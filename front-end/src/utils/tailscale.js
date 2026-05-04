/*
 * ============================================================================
 * Tailscale BYOAB helper
 * ============================================================================
 * Mints per-lane auth keys for v2 lane gateways and pushes them in. Used by
 * admin.js's lane-deploy paths when subnet_scheme='v2' and Tailscale is
 * configured. v1 deploys ignore this module entirely.
 *
 * --- Setup (one-time, on the Tailscale admin UI) ----------------------------
 * 1. Create an OAuth client at:
 *      https://login.tailscale.com/admin/settings/oauth
 *    Required scopes:
 *      - Keys → Auth Keys: Write    (mints per-lane keys)
 *      - Devices → Core: Write      (deletes devices on lane teardown)
 *    Required tags (page asks because Auth Keys: Write is enabled):
 *      - tag:lane                   (the single fixed tag every lane gw gets)
 *
 * 2. Define the lane tag in your tailnet ACL (one-time):
 *      {
 *        "tagOwners": {
 *          "tag:lane": []           // empty = only OAuth client + admins apply
 *        },
 *        "acls": [
 *          // start permissive for testing — refine later
 *          { "action": "accept", "src": ["autogroup:admin"], "dst": ["*:*"] }
 *        ]
 *      }
 *
 * 3. Set these env vars on the orchestrator (the host running this Node app):
 *      TAILSCALE_OAUTH_CLIENT_ID
 *      TAILSCALE_OAUTH_CLIENT_SECRET
 *      TAILSCALE_TAILNET            (e.g., "your-org.github" or "-")
 *      TAILSCALE_LANE_TAG           (optional override; default "tag:lane")
 *
 * If any of the first three are missing, isEnabled() returns false and
 * admin.js skips Tailscale entirely — v2 lanes still deploy, just without
 * BYOAB.
 *
 * --- Per-lane identity ------------------------------------------------------
 * Every lane gateway gets the same `tag:lane`. Individual lanes are
 * identified by device hostname: `lane-<vxlanId>-<lane-name-slug>`.
 * Per-lane ACLs target hostnames, not tags:
 *
 *      { "action": "accept",
 *        "src":    ["alice@example.com"],
 *        "dst":    ["lane-10000-*:*"] }
 * ============================================================================
 */

const TAILSCALE_API = 'https://api.tailscale.com';

// ---- Token cache (Tailscale OAuth tokens last 1h) --------------------------
let tokenCache = { token: null, expires: 0 };

function isEnabled() {
  return !!(process.env.TAILSCALE_OAUTH_CLIENT_ID
         && process.env.TAILSCALE_OAUTH_CLIENT_SECRET
         && process.env.TAILSCALE_TAILNET);
}

async function getAccessToken() {
  if (tokenCache.token && Date.now() < tokenCache.expires - 60_000) {
    return tokenCache.token;
  }
  const clientId = process.env.TAILSCALE_OAUTH_CLIENT_ID;
  const clientSecret = process.env.TAILSCALE_OAUTH_CLIENT_SECRET;
  if (!clientId || !clientSecret) {
    throw new Error('TAILSCALE_OAUTH_CLIENT_ID/_SECRET not set');
  }

  const body = new URLSearchParams({
    client_id: clientId,
    client_secret: clientSecret,
    grant_type: 'client_credentials'
  }).toString();

  const r = await fetch(`${TAILSCALE_API}/api/v2/oauth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body
  });
  if (!r.ok) {
    const text = await r.text();
    throw new Error(`Tailscale OAuth token failed (${r.status}): ${text}`);
  }
  const data = await r.json();
  tokenCache = {
    token: data.access_token,
    expires: Date.now() + (data.expires_in || 3600) * 1000
  };
  return data.access_token;
}

/**
 * Mint a single-use, ephemeral, pre-approved, tagged auth key for one lane.
 *
 * Behavior of the issued key:
 *   - reusable=false   → consumed by the first `tailscale up`. Replays fail.
 *   - ephemeral=true   → device auto-removes from tailnet when offline
 *                        (no orphan tailnet devices when lane is destroyed).
 *   - preauthorized=true → no human approval click needed.
 *   - tags=[<TAILSCALE_LANE_TAG>, ...extraTags] → ACLs gate access by tag.
 *
 * Tag strategy (why only one fixed tag): Tailscale's tagOwners doesn't
 * support wildcards, so per-vxlan tags would require pre-declaring every
 * possible tag in the ACL. We instead use ONE fixed tag ('tag:lane' by
 * default) and identify individual lanes by device hostname. Per-lane
 * ACL grants then target devices by name pattern, not by tag.
 *
 * Override the base tag with TAILSCALE_LANE_TAG env var if you want a
 * different convention (e.g., 'tag:crucible-lane').
 *
 * @param {object} opts
 * @param {number} opts.vxlanId      — used in extraTags + the device description
 * @param {number} [opts.expirySeconds=600] — key dies if not used (default 10 min)
 * @param {string[]} [opts.extraTags] — additional tags (e.g., 'tag:cohort-fall26').
 *                                      Each must be in the OAuth client's allowed
 *                                      tag list and have a tagOwner in the ACL.
 * @returns {Promise<{key: string, tags: string[]}>}
 */
async function mintLaneAuthKey({ vxlanId, expirySeconds = 600, extraTags = [] }) {
  const tailnet = process.env.TAILSCALE_TAILNET || '-';
  const baseTag = process.env.TAILSCALE_LANE_TAG || 'tag:lane';
  const token = await getAccessToken();

  const tags = [baseTag, ...extraTags];
  const body = {
    capabilities: {
      devices: {
        create: {
          reusable: false,
          ephemeral: true,
          preauthorized: true,
          tags
        }
      }
    },
    expirySeconds,
    // Tailscale rejects descriptions with spaces, parens, or punctuation —
    // alphanumeric + hyphens/underscores only.
    description: `cybercore-lane-${vxlanId}`
  };

  const r = await fetch(`${TAILSCALE_API}/api/v2/tailnet/${encodeURIComponent(tailnet)}/keys`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(body)
  });
  if (!r.ok) {
    const text = await r.text();
    throw new Error(`Tailscale mintLaneAuthKey failed (${r.status}): ${text}`);
  }
  const data = await r.json();
  return { key: data.key, tags };
}

/**
 * Store the bootstrap payload in cybercore_db for the lane gateway to fetch
 * on first boot via GET /api/lane-bootstrap. Replaces the earlier SSH-based
 * pctPushFromString approach — keeps the orchestrator off the Proxmox node.
 *
 * Single row per vxlan_id (PK). Re-deploys overwrite the row, which is fine:
 * the previous lane was torn down (or its key already consumed).
 *
 * @param {object} opts
 * @param {Function} opts.cybercoreQuery — DB helper from utils/cybercore-db
 * @param {number}   opts.vxlanId
 * @param {string}   opts.wanIp           — IP the orchestrator expects this lane gw to call from
 * @param {object}   opts.payload         — JSON returned to the gateway: { tailscale_authkey, tailscale_tags, tailscale_hostname }
 * @param {number}   [opts.ttlSeconds=600]
 */
async function storeLaneBootstrap({ cybercoreQuery, vxlanId, wanIp, payload, ttlSeconds = 600 }) {
  await cybercoreQuery(
    `INSERT INTO lane_bootstrap_tokens (vxlan_id, wan_ip, payload, expires_at)
     VALUES ($1, $2, $3::jsonb, NOW() + ($4 || ' seconds')::interval)
     ON CONFLICT (vxlan_id) DO UPDATE SET
       wan_ip      = EXCLUDED.wan_ip,
       payload     = EXCLUDED.payload,
       created_at  = NOW(),
       expires_at  = EXCLUDED.expires_at,
       consumed_at = NULL,
       consumed_by = NULL`,
    [vxlanId, wanIp, JSON.stringify(payload), String(ttlSeconds)]
  );
}

/**
 * Best-effort device cleanup on lane teardown. Ephemeral keys auto-remove
 * the device when it goes offline, so this is mostly aesthetic. We look up
 * devices by hostname prefix (`lane-<vxlanId>-`) and delete them. Failures
 * are logged but never thrown (a leaked tailnet device is annoying, not
 * breaking).
 *
 * Hostname-based lookup beats tag-based here: with the simplified single-tag
 * scheme (`tag:lane`), filtering by tag would catch every lane gateway in
 * the tailnet. Hostname disambiguates by vxlan_id.
 */
async function deleteLaneDevices({ vxlanId, logger = console }) {
  if (!isEnabled()) return;
  const tailnet = process.env.TAILSCALE_TAILNET || '-';
  const hostnamePrefix = `lane-${vxlanId}`;
  try {
    const token = await getAccessToken();
    const listResp = await fetch(
      `${TAILSCALE_API}/api/v2/tailnet/${encodeURIComponent(tailnet)}/devices`,
      { headers: { 'Authorization': `Bearer ${token}` } }
    );
    if (!listResp.ok) {
      logger.warn?.(`[Tailscale] device list failed (${listResp.status}); skipping cleanup`);
      return;
    }
    const { devices = [] } = await listResp.json();
    const matches = devices.filter(d =>
      typeof d.hostname === 'string' &&
      (d.hostname === hostnamePrefix || d.hostname.startsWith(`${hostnamePrefix}-`))
    );
    for (const d of matches) {
      try {
        const delResp = await fetch(`${TAILSCALE_API}/api/v2/device/${d.id}`, {
          method: 'DELETE',
          headers: { 'Authorization': `Bearer ${token}` }
        });
        if (delResp.ok) {
          logger.log?.(`[Tailscale] deleted device ${d.hostname || d.id}`);
        } else {
          logger.warn?.(`[Tailscale] delete device ${d.id} returned ${delResp.status}`);
        }
      } catch (e) {
        logger.warn?.(`[Tailscale] delete device ${d.id} threw: ${e.message}`);
      }
    }
  } catch (e) {
    logger.warn?.(`[Tailscale] deleteLaneDevices failed (best-effort): ${e.message}`);
  }
}

module.exports = {
  isEnabled,
  mintLaneAuthKey,
  storeLaneBootstrap,
  deleteLaneDevices
};
