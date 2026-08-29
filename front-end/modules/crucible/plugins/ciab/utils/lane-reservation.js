/**
 * lane-reservation.js — one CIAB engagement's VXLAN reservation, and the
 * teardown that releases it.
 * ============================================================================
 * Extracted intact from lane-deploy.js in Track A7, which deleted that file's
 * other half: a private fourth copy of the clone-and-wire sequence that the
 * shared deployer already owns. Nothing here was rewritten — the reservation
 * logic, its legacy-key adoption path and its zone backfill are the A1 code
 * verbatim, because they are the parts that were already correct.
 *
 * What a reservation IS: one crucible_challenge row in cybercore_db per
 * (profile, engagement), whose spec.vxlan_block sizes the SDN zone and VNets.
 * Deploying lanes from it is challenge-lane-deployer's job, reached through
 * ./lane-provision.js — this file never clones anything.
 *
 * KEYED BY (profile, engagement), NOT BY PROFILE ALONE. One client profile can
 * be the subject of several engagements — "internal, here are the credentials"
 * and "external, here is the website" are different labs against the same
 * company — and a profile-only key would alias them onto one reservation, so
 * tearing one down would destroy the other's live lanes.
 */

const { query } = require('./db');
const { cybercoreQuery } = require('../../../../../src/utils/cybercore-db');
const { proxmoxAPI } = require('../../../../../src/utils/proxmox');
const {
  sanitizeZoneAbbrev,
  reserveLabNetwork,
  teardownLabNetwork,
  V3_INTERNAL_TAG_OFFSET,
  // Aliased: CIAB used to export a function of the same name with a different
  // signature, and both spellings still appear in this file's history.
  ensureSdnZoneAndVnets: provisionSdnZoneAndVnets,
} = require('../../../../../src/utils/lab-network-provision');
const laneDeployer = require('../../../../../src/utils/lane-deployer');

// VXLAN bounds reported to the admin UI, and the ceiling the shared allocator
// is held to.
//
// _MIN is informational only now. CIAB used to run its own first-free-gap search
// inside this window; allocation is the shared allocateVxlanBlock's job, and it
// packs each new block immediately above the global maximum end (never below
// 10000), so nothing here selects a start address any more.
//
// _MAX is load-bearing: a v2/v3 lane's LAN is 10.<vxlan>>8>.<vxlan & 255>.0/24,
// so an id above 65535 wraps those two bytes and silently puts two lanes on one
// subnet. Passed to reserveLabNetwork as maxVxlanId so the reservation fails
// loudly instead.
const VXLAN_SEARCH_MIN = parseInt(process.env.CIAB_VXLAN_SEARCH_MIN, 10) || 10100;
const VXLAN_SEARCH_MAX = parseInt(process.env.CIAB_VXLAN_SEARCH_MAX, 10) || 65535;

// ─── Per-profile crucible_challenge reservation ────────────────────────────
/**
 * A CIAB engagement that has been deployed owns ONE crucible_challenge row in
 * cybercore_db. The challenge's spec.vxlan_block IS the reservation, sized
 * exactly to max_students. Identical mechanism to how crucible challenge
 * templates work — no parallel reservation system.
 *
 * The block, the SDN zone and the VNets are all provisioned by the SHARED
 * primitive in src/utils/lab-network-provision.js. CIAB used to carry its own
 * copy of that, and the copy had drifted into two cluster-affecting bugs: it
 * POSTed zones with peer addresses invented from each node's INDEX in the
 * /nodes response (`n.ip || 100.100.10.<10+i>` — /nodes never returns `ip`),
 * and it set ipam:'pve', which writes per-VNet dnsmasq config on every node and
 * has crashed the cluster at reboot. Both are documented at length in the
 * shared module, which is the only thing that should ever create a zone.
 *
 * KEYED BY (profile, engagement), NOT BY PROFILE ALONE
 * One client profile can be the subject of several engagements — "internal,
 * here are the credentials" and "external, here is the website" are different
 * labs against the same company, with different address plans and different
 * live lanes. Keying on the profile alone aliased them onto a single
 * reservation, so deploying the second silently adopted the first's block and
 * tearing either one down destroyed the other's lanes.
 */

// EVERY CIAB VNet on the cluster is already in this one Proxmox SDN zone, and
// it must stay that way: the old code derived the zone from the challenge key
// via sanitizeZoneAbbrev, which truncates to 8 characters — so
// 'ciab-profile-<anything>' has always collapsed to 'ciabprof' regardless of
// which profile it was. Deriving it explicitly, rather than from a key whose
// format this change is altering, is what keeps existing VNets findable.
// ciab-reservation.test.js pins the equality.
const CIAB_ZONE_ABBREV = sanitizeZoneAbbrev('ciab-profile');

// The engagement a reservation belongs to. Track B replaces this with rows in
// ciab_engagement; until then every deploy that does not name one lands here,
// which is also the value pre-existing (profile-keyed) reservations adopt.
const DEFAULT_ENGAGEMENT_TYPE = 'default';

// Which VNet tags a teardown must sweep for a CIAB block.
//
// teardownLabNetwork otherwise reads crucible_challenge.subnet_scheme, which is
// written once at reservation time and never updated — while the scheme a lane
// is BUILT at is chosen per deploy (profile-deploy.js reads subnet_scheme off
// the request body, and the admin UI offers v2/v3 on every deploy). Reserve a
// block at v2, later deploy it at v3, and ensureLaneVnets creates the internal
// VNets at tag+V3_INTERNAL_TAG_OFFSET while the row still says v2 — so the
// sweep skips them, the zone-empty check then sees them and keeps the zone, and
// deleting the challenge row leaves nothing that can ever name them again.
//
// 'v3' means "sweep both ranges", which is exactly what CIAB's own teardown did
// before A1 (unconditionally, with no scheme test). For a genuinely v2 block the
// internal range is empty and the extra pass costs one filter.
const TEARDOWN_SWEEP_SCHEME = 'v3';

/** Coerce arbitrary caller input into a key-safe engagement slug. */
function sanitizeEngagementType(raw) {
  const s = String(raw == null ? '' : raw).trim().toLowerCase().replace(/[^a-z0-9_-]/g, '');
  return s ? s.slice(0, 32) : DEFAULT_ENGAGEMENT_TYPE;
}

/** The reservation key for one engagement against one profile. */
function profileChallengeKey(profileId, engagementType) {
  const engagementSlug = sanitizeEngagementType(engagementType);
  return `ciab-profile-${String(profileId).slice(0, 8)}-${engagementSlug}`;
}

/**
 * The pre-engagement key format. Deliberately built by concatenation rather
 * than as a template literal: ciab-deploy-parity.test.js scans for a
 * `ciab-profile-${...}` template and requires the first one it finds to name the
 * engagement, and a legacy-key template appearing above would satisfy that scan
 * while meaning the opposite of what it checks for.
 */
function legacyProfileChallengeKey(profileId) {
  return 'ciab-profile-' + String(profileId).slice(0, 8);
}

function parseSpec(raw) {
  if (typeof raw === 'string') { try { return JSON.parse(raw); } catch (_) { return {}; } }
  return raw || {};
}

async function loadChallengeByKey(challengeKey) {
  const res = await cybercoreQuery(
    `SELECT challenge_id, challenge_key, created_at, spec
       FROM crucible_challenge WHERE challenge_key = $1`,
    [challengeKey]
  );
  return res.rows[0] || null;
}

/** Normalize a crucible_challenge row into the reservation shape callers read. */
function reservationFromRow(row) {
  const spec = parseSpec(row.spec);
  const block = spec.vxlan_block || {};
  const hasBlock = Number.isFinite(block.start) && Number.isFinite(block.end);
  return {
    challenge_id: row.challenge_id,
    challenge_key: row.challenge_key,
    created_at: row.created_at,
    vxlan_block: { start: hasBlock ? block.start : null, end: hasBlock ? block.end : null },
    max_students: hasBlock ? (block.end - block.start + 1) : null,
    zone_abbrev: (spec.zone && spec.zone.abbrev) || null,
    spec
  };
}

/**
 * Lazy zone-abbrev backfill.
 *
 * teardownLabNetwork deletes the zone named by spec.zone.abbrev; rows CIAB
 * created before this change have no such key, because CIAB re-derived the zone
 * from the challenge key at teardown time instead of storing it. Stamping it
 * here — on the read path, once, in place — is what lets the shared teardown
 * find the same zone the old deploy created. A .sql file would not run:
 * front-end/migrations/ has no runner, and a plugins/ciab/migrations/ file
 * cannot reach cybercore_db.
 *
 * Written as one merging UPDATE rather than read-modify-write so it cannot
 * clobber a concurrent spec write — profile-deploy.js adopts a fresh spec onto
 * the same row moments later.
 */
async function backfillZoneAbbrev(row) {
  const spec = parseSpec(row.spec);
  if (spec.zone && spec.zone.abbrev) return spec;
  const res = await cybercoreQuery(
    // jsonb_typeof guard: `object || scalar` is an error in Postgres, and the
    // IS NULL predicate does not exclude it (`->>'abbrev'` on a jsonb string is
    // NULL, not an error). These are exactly the rows this backfill exists for —
    // written before the current invariants — so a malformed zone must degrade
    // to "overwrite it" rather than throw a 500 out of a deploy.
    `UPDATE crucible_challenge
        SET spec = COALESCE(spec, '{}'::jsonb)
                || jsonb_build_object('zone',
                     COALESCE(CASE WHEN jsonb_typeof(spec->'zone') = 'object' THEN spec->'zone' END,
                              '{}'::jsonb)
                     || jsonb_build_object('abbrev', $2::text))
      WHERE challenge_id = $1
        AND (spec->'zone'->>'abbrev') IS NULL
      RETURNING spec`,
    [row.challenge_id, CIAB_ZONE_ABBREV]
  );
  if (res.rows.length > 0) {
    console.log(`[CIAB Reservation] Stamped zone '${CIAB_ZONE_ABBREV}' on ${row.challenge_key}`);
    row.spec = res.rows[0].spec;
    return parseSpec(row.spec);
  }
  // Someone stamped it between the read and the update — re-read rather than
  // reporting a value we never wrote.
  const fresh = await loadChallengeByKey(row.challenge_key);
  if (fresh) row.spec = fresh.spec;
  return parseSpec(row.spec);
}

/**
 * Adopt a pre-engagement reservation into the new key format.
 *
 * Renaming, rather than creating a second row, is the only safe move: the
 * profile's live lanes hold vxlan_ids inside that block and point at that
 * challenge_id, and nothing anywhere joins on challenge_key — cybercore_lane
 * and ciab_profile_lane_groups both carry the UUID. The Proxmox zone is
 * unaffected because both key formats sanitize to the same 8 characters.
 *
 * The UPDATE is a compare-and-swap on the old key so two concurrent adopters
 * cannot both claim it, and a 23505 means the new key already exists — in which
 * case that row wins and the legacy row is left alone rather than merged.
 */
async function adoptLegacyProfileChallenge(profileId, newKey) {
  const legacyKey = legacyProfileChallengeKey(profileId);
  const legacy = await loadChallengeByKey(legacyKey);
  if (!legacy) return null;

  try {
    const res = await cybercoreQuery(
      `UPDATE crucible_challenge SET challenge_key = $1
        WHERE challenge_id = $2 AND challenge_key = $3
        RETURNING challenge_id, challenge_key, created_at, spec`,
      [newKey, legacy.challenge_id, legacyKey]
    );
    if (res.rows.length > 0) {
      console.log(`[CIAB Reservation] Adopted legacy reservation ${legacyKey} → ${newKey}`);
      return res.rows[0];
    }
  } catch (err) {
    if (err.code !== '23505') throw err;
    console.warn(`[CIAB Reservation] ${newKey} already exists; leaving legacy ${legacyKey} in place`);
  }
  return loadChallengeByKey(newKey);
}

/**
 * Idempotent get-or-create for one engagement's reservation.
 *
 * @param {object} args
 * @param {string} args.profileId
 * @param {string} [args.engagementType]   defaults to DEFAULT_ENGAGEMENT_TYPE
 * @param {number} args.requestedMax       max_students, when creating or resizing
 * @param {string} args.companyName        display name only
 * @param {object} args.spec               used only when CREATING; an existing
 *                                         reservation keeps its stored spec
 * @param {string} args.subnetScheme
 * @returns {Promise<{challenge_id, challenge_key, engagement_type, vxlan_block,
 *                    max_students, was_existing, spec}>}
 */
async function getOrCreateProfileChallenge({
  profileId, engagementType, requestedMax, companyName, spec, subnetScheme = 'v2'
}) {
  if (!profileId) throw new Error('getOrCreateProfileChallenge: profileId required');
  const engagement = sanitizeEngagementType(engagementType);
  const challengeKey = profileChallengeKey(profileId, engagement);
  const logTag = `[CIAB Reservation ${String(profileId).slice(0, 8)}/${engagement}]`;

  let row = await loadChallengeByKey(challengeKey);
  if (!row && engagement === DEFAULT_ENGAGEMENT_TYPE) {
    row = await adoptLegacyProfileChallenge(profileId, challengeKey);
  }

  if (row) {
    await backfillZoneAbbrev(row);
    const existing = reservationFromRow(row);
    const wantsResize = Number.isFinite(requestedMax)
      && existing.max_students != null
      && requestedMax !== existing.max_students;

    if (!wantsResize) {
      return { ...existing, engagement_type: engagement, was_existing: true };
    }

    // Recovery path for the common case: a previous attempt failed before any
    // lane deployed, locking the reservation at the wrong size. teardownLabNetwork
    // makes "is it empty?" the shared definition (claimsSql, so pending and
    // suspended lanes count too) and refuses with .status 400 when it is not —
    // and unlike the bare DELETE this replaces, it also frees the block's VNets
    // instead of orphaning them in Proxmox.
    try {
      await teardownLabNetwork(existing.challenge_id, {
        force: false,
        subnetScheme: TEARDOWN_SWEEP_SCHEME,
        log: (m) => console.log(`${logTag} ${m}`)
      });
      console.log(`${logTag} resized empty reservation ${existing.max_students}→${requestedMax}`);
      row = null;
    } catch (err) {
      if (err.status === 400) {
        console.log(`${logTag} lanes are live — keeping the ${existing.max_students}-slot reservation`);
        return { ...existing, engagement_type: engagement, was_existing: true };
      }
      // 404: something deleted the row between our read and the teardown. That is
      // the state we were trying to reach, so carry on and create a fresh one
      // rather than failing the deploy on a race we won.
      if (err.status !== 404) throw err;
      console.warn(`${logTag} reservation vanished mid-resize — creating a fresh one`);
      row = null;
    }
  }

  if (!Number.isFinite(requestedMax) || requestedMax < 1) {
    throw new Error(`requestedMax must be >= 1 (got ${requestedMax})`);
  }

  // reserveLabNetwork pre-creates every VNet in the block and waits for the
  // bridges, so the per-batch ensureLaneVnets below is a no-op on the happy
  // path. It also rolls the challenge row back when SDN provisioning fails,
  // which is why this propagates rather than warning: unlike the code it
  // replaces there is no half-made reservation left behind to retry against.
  try {
    const reservation = await reserveLabNetwork({
      challengeKey,
      name: `CIAB Profile: ${companyName || String(profileId).slice(0, 8)}`,
      description: `CIAB profile-derived challenge (auto-managed). Profile ID: ${profileId}, engagement: ${engagement}`,
      difficulty: 3,
      challengeType: 'multi_vm',
      moduleKey: 'crucible',
      subnetScheme,
      maxLanes: requestedMax,
      spec: { ...(spec || {}) },
      zoneAbbrev: CIAB_ZONE_ABBREV,
      maxVxlanId: VXLAN_SEARCH_MAX,
      log: (m) => console.log(`${logTag} ${m}`)
    });
    console.log(`${logTag} → challenge ${reservation.challenge_id.slice(0, 8)} (${challengeKey}), VXLAN ${reservation.vxlan_block.start}-${reservation.vxlan_block.end} (${requestedMax} slots)`);
    return {
      challenge_id: reservation.challenge_id,
      challenge_key: reservation.challenge_key,
      engagement_type: engagement,
      vxlan_block: reservation.vxlan_block,
      max_students: requestedMax,
      zone_abbrev: reservation.zone,
      was_existing: false,
      spec: {
        ...(spec || {}),
        zone: { abbrev: reservation.zone },
        vxlan_block: reservation.vxlan_block
      }
    };
  } catch (err) {
    // A concurrent request won the race for this key. Its block is as good as
    // ours would have been, so adopt it rather than failing the deploy.
    if (err.code === '23505') {
      const winner = await loadChallengeByKey(challengeKey);
      if (winner) {
        console.warn(`${logTag} lost the create race — using the concurrently created reservation`);
        return { ...reservationFromRow(winner), engagement_type: engagement, was_existing: true };
      }
    }
    throw err;
  }
}

/**
 * Every reservation a profile owns, across all engagements, including one still
 * carrying the pre-engagement key.
 */
async function listProfileChallenges(profileId) {
  // The prefix is 'ciab-profile-' plus 8 hex characters of a UUID, so it can
  // carry no LIKE metacharacter.
  const legacyKey = legacyProfileChallengeKey(profileId);
  const res = await cybercoreQuery(
    `SELECT challenge_id, challenge_key, created_at, spec
       FROM crucible_challenge
      WHERE challenge_key = $1 OR challenge_key LIKE $1 || '-%'
      ORDER BY challenge_key`,
    [legacyKey]
  );
  return res.rows;
}

/**
 * Release a profile's reservations. With no engagementType this releases ALL of
 * them, which is what deleting the profile means — a profile-scoped delete that
 * freed only one engagement would leak every other engagement's VXLAN block and
 * VNets permanently.
 *
 * force: true matches the behaviour this replaces (the old code never refused).
 * The caller is deleting the profile; refusing here would strand the block
 * rather than protect anything.
 */
async function deleteProfileChallenge(profileId, { engagementType = null } = {}) {
  const rows = engagementType
    ? [await loadChallengeByKey(profileChallengeKey(profileId, engagementType))].filter(Boolean)
    : await listProfileChallenges(profileId);

  if (rows.length === 0) return { deleted: false, reason: 'no_challenge', released: [] };

  const released = [];
  for (const row of rows) {
    // Without the stamp the shared teardown has no zone to remove.
    await backfillZoneAbbrev(row).catch(() => {});
    try {
      const res = await teardownLabNetwork(row.challenge_id, {
        force: true,
        subnetScheme: TEARDOWN_SWEEP_SCHEME,
        log: (m) => console.log(`[CIAB Reservation] ${m}`)
      });
      released.push({
        challenge_id: row.challenge_id, challenge_key: row.challenge_key,
        vnets_removed: res.vnets_removed, zone_removed: res.zone_removed
      });
    } catch (err) {
      console.warn(`[CIAB Reservation] Release of ${row.challenge_key} failed: ${err.message}`);
      released.push({ challenge_id: row.challenge_id, challenge_key: row.challenge_key, error: err.message });
    }
  }

  return {
    deleted: released.some(r => !r.error),
    challenge_id: rows[0].challenge_id,
    released,
    vnets_removed: released.reduce((n, r) => n + (r.vnets_removed || 0), 0),
    zone_removed: released.some(r => r.zone_removed)
  };
}

/**
 * Read-only lookup for one engagement's reservation. Falls back to the
 * pre-engagement key for the default engagement WITHOUT adopting it — a GET
 * must not rename anything; getOrCreateProfileChallenge does that on deploy.
 */
async function findProfileChallenge(profileId, engagementType = DEFAULT_ENGAGEMENT_TYPE) {
  const engagement = sanitizeEngagementType(engagementType);
  let row = await loadChallengeByKey(profileChallengeKey(profileId, engagement));
  if (!row && engagement === DEFAULT_ENGAGEMENT_TYPE) {
    row = await loadChallengeByKey(legacyProfileChallengeKey(profileId));
  }
  return row ? { ...reservationFromRow(row), engagement_type: engagement } : null;
}

/**
 * Look a reservation up by the id a deploy group already stores
 * (ciab_profile_lane_groups.ephemeral_challenge_id). Add-lanes and retry must
 * use this rather than re-deriving a key: the group knows exactly which
 * reservation its lanes came from, and once one profile can own several,
 * re-deriving is a guess.
 */
async function getProfileChallengeById(challengeId) {
  if (!challengeId) return null;
  const res = await cybercoreQuery(
    `SELECT challenge_id, challenge_key, created_at, spec
       FROM crucible_challenge WHERE challenge_id = $1`,
    [challengeId]
  );
  return res.rows[0] ? reservationFromRow(res.rows[0]) : null;
}


// ─── Ensure the VNets a batch needs are present ───────────────────────────
/**
 * A safety net, not a provisioner.
 *
 * getOrCreateProfileChallenge pre-creates every VNet in the reservation block,
 * so on the happy path this finds nothing missing and returns after one GET.
 * It exists for the case where SDN lost a VNet between reservation and deploy
 * (or an operator removed one), because the per-lane resolveVnets below is a
 * plain lookup that throws rather than repairs.
 *
 * The missing-tag check comes FIRST and short-circuits deliberately: the shared
 * provisioner ends with PUT /cluster/sdn, and an SDN apply commits every pending
 * SDN change on the cluster, not just this lab's. That is the right price for
 * creating VNets and the wrong one to pay on every batch deploy that needed
 * nothing.
 *
 * Zone creation belongs to the shared provisioner alone — see the note on
 * CIAB_ZONE_ABBREV above for what CIAB's own copy got wrong.
 */
async function ensureLaneVnets({ vxlanIds, subnetScheme, logTag }) {
  const tag = logTag || 'CIAB Deploy';
  const ids = [...new Set((vxlanIds || []).filter(Number.isFinite))].sort((a, b) => a - b);
  if (ids.length === 0) return { missing: 0, repaired: false };

  const requiredTags = new Set();
  for (const id of ids) {
    requiredTags.add(id);
    if (subnetScheme === 'v3') requiredTags.add(id + V3_INTERNAL_TAG_OFFSET);
  }

  const vnets = await proxmoxAPI('GET', '/api2/json/cluster/sdn/vnets');
  const present = new Set((vnets || []).map(v => v.tag));
  const missing = [...requiredTags].filter(t => !present.has(t));
  if (missing.length === 0) return { missing: 0, repaired: false };

  // The shared provisioner takes a contiguous external range and derives the v3
  // internal tags itself. Spanning min..max of this batch can only re-assert
  // VNets that already exist inside the same reservation block, which it treats
  // as success.
  console.warn(`[${tag}] ${missing.length} VNet(s) missing from the reservation — repairing`);
  await provisionSdnZoneAndVnets({
    zone: CIAB_ZONE_ABBREV,
    vxlanStart: ids[0],
    vxlanEnd: ids[ids.length - 1],
    subnetScheme,
    log: (m) => console.log(`[${tag}] ${m}`)
  });
  return { missing: missing.length, repaired: true };
}


// ─── Teardown a single lane (used by group DELETE + per-lane retry cleanup) ──
/**
 * Delegates to the ONE canonical teardown in src/utils/lane-deployer.js.
 *
 * What this used to do, and why none of it survived:
 *   - ignored forceDestroyVM's return value entirely, so a VM that refused to
 *     die never reached `errors` and the caller reported a clean teardown
 *   - deleted the cybercore_lane row unconditionally AND swallowed the delete's
 *     own failure with .catch(() => {}) — orphaning any survivor permanently and
 *     releasing its vxlan_id for the next deploy to clone a gateway on top of
 *   - had no contested-VXLAN check, so a recycled id meant it destroyed the LIVE
 *     lane's machines
 *   - no Guacamole cleanup, no Tailscale cleanup, no disk sweep, no retry rounds
 *
 * vm_ids from ciab_profile_lane_jobs are still honoured: they are passed as
 * extraVmIds, because a lane whose config write never landed has them recorded
 * nowhere else. They go through the same contested and ownership checks.
 *
 * @param {{laneId: string, vmIds?: Array<number>}} a
 * @returns {Promise<{errors: Array<string>, keptForRetry: boolean, result: object}>}
 */
async function teardownLane({ laneId, vmIds }) {
  const result = await laneDeployer.teardownLanes([laneId], {
    extraVmIds: Array.isArray(vmIds) ? vmIds : [],
    purgeJanitors: true,
  });

  // The job row is this plugin's own bookkeeping, in its own pool, so it is
  // cleaned here rather than inside teardownLanes. Only once the lane row is
  // actually gone: while the lane is kept for retry, vm_ids is the record of
  // what is still out there.
  if ((result.lanes_kept_for_retry || 0) === 0) {
    await query(`DELETE FROM ciab_profile_lane_jobs WHERE lane_id = $1`, [laneId])
      .catch(e => result.errors.push(`Profile lane job cleanup: ${e.message}`));
  }

  return {
    errors: result.errors,
    keptForRetry: (result.lanes_kept_for_retry || 0) > 0,
    result,
  };
}


module.exports = {
  // Reservation lifecycle.
  getOrCreateProfileChallenge,
  deleteProfileChallenge,
  findProfileChallenge,
  getProfileChallengeById,
  listProfileChallenges,
  // Repairs a reservation whose VNets drifted. Not a provisioner — see its own
  // note. Kept with the reservation because it repairs the reservation.
  ensureLaneVnets,
  // Lane teardown — delegates to the ONE canonical implementation.
  teardownLane,
  // Exported for ciab-reservation.test.js, which pins the key format and the
  // zone continuity that the legacy-adoption path depends on.
  CIAB_ZONE_ABBREV,
  DEFAULT_ENGAGEMENT_TYPE,
  sanitizeEngagementType,
  profileChallengeKey,
  legacyProfileChallengeKey,
  VXLAN_SEARCH_MIN,
  VXLAN_SEARCH_MAX,
};
