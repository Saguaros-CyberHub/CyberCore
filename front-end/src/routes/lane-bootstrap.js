/**
 * ============================================================================
 * Lane bootstrap endpoint — UNAUTHENTICATED but source-IP gated
 * ============================================================================
 * Lane gateways (LXC clones of 1694) call this on first boot to fetch their
 * one-shot config payload (currently Tailscale auth key + tags + hostname).
 *
 * Auth model:
 *   - Caller is identified by request source IP.
 *   - Request must hit a row in lane_bootstrap_tokens whose wan_ip matches
 *     the source IP, is unconsumed, and not expired.
 *   - On match, payload is returned and the row is marked consumed (one-shot).
 *
 * Why no bearer token?
 *   - Lane gateway has no credentials before bootstrap (chicken/egg).
 *   - Source IP is enforced at insert time (the deploy path writes the lane's
 *     ALLOCATED WAN address — see utils/lane-wan-allocator.js. It used to be
 *     derived, which is why the IP-gated branch below needs a uniqueness guard
 *     for gateways deployed before that changed).
 *   - Token is single-use: even if a lab-network adversary spoofs source IP
 *     and races to consume, the gateway's subsequent fetch fails noisily —
 *     and the consumed key is one-shot Tailscale-side anyway.
 *   - For higher-trust deployments, layer in a hostname-embedded random
 *     bootstrap secret validated server-side (separate follow-up).
 *
 * Endpoint behavior:
 *   GET /api/lane-bootstrap
 *     200 + JSON payload   → success, row marked consumed
 *     404 + {error:"..."}  → no matching row, expired, or already consumed
 *     500                  → DB error
 * ============================================================================
 */

const express = require('express');
const router = express.Router();
const { cybercoreQuery } = require('../utils/cybercore-db');

// Source IP resolution. We use Express's req.ip, which honors X-Forwarded-For
// only when the request comes from a `trust proxy` CIDR (configured in
// server.js — defaults to loopback/linklocal/uniquelocal, which covers Docker
// bridge networks like 172.18.0.0/16 where the Node app commonly runs behind
// a reverse proxy on the host).
//
// Security model: the X-Forwarded-For header is only trusted when set by a
// proxy in the trust list. An attacker on the lab network cannot inject a
// forged header that bypasses the source-IP check, because Express drops
// X-Forwarded-For from untrusted hops. If the orchestrator is exposed
// directly (no proxy), req.ip equals the socket peer, same as before.
function rawSourceIp(req) {
  const ra = req.ip || req.socket?.remoteAddress || req.connection?.remoteAddress || '';
  // Strip the IPv4-mapped-IPv6 prefix if present (::ffff:10.39.16.1 → 10.39.16.1)
  return ra.replace(/^::ffff:/, '');
}

router.get('/', async (req, res) => {
  const sourceIp = rawSourceIp(req);
  // The secret comes from the gateway: it greps a `b<16hex>` suffix out of its
  // own LXC hostname (set per-lane at clone time) and passes it as ?secret=…
  // — see configureLaneTailscale + the bake script firstboot. Validate shape
  // strictly so a garbage querystring can't be expensive to look up.
  const secretRaw = String(req.query.secret || '').trim();
  const secret = /^[a-f0-9]{16}$/.test(secretRaw) ? secretRaw : null;

  if (!secret && !sourceIp) {
    return res.status(400).json({ error: 'could not determine source ip' });
  }

  try {
    // Single atomic UPDATE…RETURNING claims the token only if fresh. Two match
    // modes:
    //   - secret-gated (preferred): match payload->>'_claim_secret' (set per
    //     lane in configureLaneTailscale). Works even when the source IP is
    //     rewritten by the Docker bridge / proxy chain.
    //   - IP-gated (legacy):        match host(wan_ip) = source IP. Kept so
    //     gateways baked before this change keep working until they re-bake.
    // wan_ip is still recorded in consumed_by for audit either way.
    let result;
    if (secret) {
      result = await cybercoreQuery(
        `UPDATE lane_bootstrap_tokens
            SET consumed_at = NOW(),
                consumed_by = $2::inet
          WHERE payload->>'_claim_secret' = $1
            AND consumed_at IS NULL
            AND expires_at > NOW()
          RETURNING vxlan_id, payload`,
        [secret, sourceIp || '0.0.0.0']
      );
    } else {
      // The ambiguity guard is load-bearing. Before lane WAN addresses were
      // allocated, two live lanes could share one — and then this UPDATE matched
      // two unconsumed rows with different vxlan_ids and claimed an ARBITRARY
      // one, so gateway A could consume gateway B's Tailscale auth key. Refuse
      // when the match is not unique rather than picking.
      //
      // `wan_ip = $1::inet` rather than `host(wan_ip) = $1`: the text form cannot
      // use idx_lane_bootstrap_tokens_wan_ip, the inet form can.
      result = await cybercoreQuery(
        `UPDATE lane_bootstrap_tokens t
            SET consumed_at = NOW(),
                consumed_by = $1::inet
          WHERE t.wan_ip = $1::inet
            AND t.consumed_at IS NULL
            AND t.expires_at > NOW()
            AND (SELECT COUNT(*) FROM lane_bootstrap_tokens u
                  WHERE u.wan_ip = t.wan_ip
                    AND u.consumed_at IS NULL
                    AND u.expires_at > NOW()) = 1
          RETURNING vxlan_id, payload`,
        [sourceIp]
      );
    }

    if (result.rows.length === 0) {
      if (!secret) {
        // Distinguish "nothing to claim" from "more than one lane claims this
        // address" — the second is a WAN collision and needs an operator, not a
        // retry.
        const ambiguous = await cybercoreQuery(
          `SELECT COUNT(*)::int AS n, STRING_AGG(vxlan_id::text, ', ') AS vxlans
             FROM lane_bootstrap_tokens
            WHERE wan_ip = $1::inet AND consumed_at IS NULL AND expires_at > NOW()`,
          [sourceIp]
        ).catch(() => null);
        if (ambiguous && ambiguous.rows[0]?.n > 1) {
          console.error(
            `[LaneBootstrap] REFUSED: ${ambiguous.rows[0].n} unconsumed tokens claim ${sourceIp} ` +
            `(vxlan ${ambiguous.rows[0].vxlans}). Two lanes share this WAN transit address, so ` +
            `handing one of them the other's Tailscale key is a coin flip. ` +
            `GET /api/admin/wan-conflicts, then redeploy the newer lane.`
          );
          return res.status(409).json({ error: 'ambiguous bootstrap claim: this WAN address is shared by more than one lane' });
        }
      }
      console.warn(`[LaneBootstrap] No claimable token (mode=${secret ? 'secret' : 'ip'}, src=${sourceIp})`);
      return res.status(404).json({ error: 'no bootstrap token for this request' });
    }

    const { vxlan_id, payload } = result.rows[0];
    // Strip the internal claim secret — the gateway already has it, no need
    // to echo it back, and it doesn't belong in any log/leak surface.
    if (payload && typeof payload === 'object') delete payload._claim_secret;
    console.log(`[LaneBootstrap] Delivered payload for vxlan ${vxlan_id} via ${secret ? 'secret' : 'ip'} match (src=${sourceIp})`);
    res.json(payload);
  } catch (err) {
    console.error(`[LaneBootstrap] Error serving (src=${sourceIp}): ${err.message}`);
    res.status(500).json({ error: 'internal error' });
  }
});

module.exports = router;
