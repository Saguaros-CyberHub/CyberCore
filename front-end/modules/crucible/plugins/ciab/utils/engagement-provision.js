/**
 * ============================================================================
 * engagement-provision.js — Track A8: carve the VXLAN block BEFORE deploy day
 * ----------------------------------------------------------------------------
 * Reserving a block is slow and its cost is mostly unavoidable:
 *
 *   - 25-50 SERIAL VNet POSTs, rate-limited 500ms every 10
 *   - `PUT /cluster/sdn` — the ONLY supported commit, and it is CLUSTER-WIDE.
 *     There is no per-node SDN apply, and an apply commits EVERY pending SDN
 *     change on the cluster, not just ours.
 *   - up to three reconcile passes, each with ANOTHER cluster-wide apply
 *   - then a wait for the bridges to materialize on the nodes
 *
 * So the lever is FREQUENCY, not speed: do it once, ahead of time, for a whole
 * block — and never on the deploy path. This module owns that moment.
 *
 * The shape is CLE's (cle/routes/courses.js provisionCourseLab + the
 * cle_course.provision_status column), because it is the pattern already proven
 * here. What it deliberately does NOT copy from CLE:
 *
 *   - CLE has no re-provision action; a failed course can only be deleted and
 *     recreated. This module has one (A8b).
 *   - CLE has no boot recovery, so a restart mid-provision strands the row in
 *     'provisioning' forever and the only exit is deleting the course. This
 *     module has recoverStrandedEngagements(), modelled on
 *     src/server.js recoverStrandedLanes.
 *   - CLE has no concurrency guard. This module refuses a second concurrent
 *     provision for the same engagement.
 *   - CLE gives each course its OWN SDN zone. CIAB deliberately shares one zone
 *     ('ciabprof') across every profile and engagement — see CIAB_ZONE_ABBREV in
 *     lane-reservation.js. Do not introduce per-engagement zones here.
 * ============================================================================
 */

const { query } = require('./db');
const {
  getOrCreateProfileChallenge,
  findProfileChallenge,
  sanitizeEngagementType,
  DEFAULT_ENGAGEMENT_TYPE,
} = require('./lane-reservation');
const {
  verifyBridgesOnAllNodes, getLabReadiness, V3_INTERNAL_TAG_OFFSET,
} = require('../../../../../src/utils/lab-network-provision');

const LOG = '[CIAB Engagement]';

/**
 * Engagements currently being provisioned in THIS process.
 *
 * The DB status is not sufficient on its own: two requests can both read
 * 'provisioning' before either writes, and the reservation underneath is not
 * idempotent in the way that matters — allocateVxlanBlock always carves ABOVE
 * the global maximum and never re-uses, so a double provision permanently burns
 * a second block. One Node process, so a Set is a real mutex here (same
 * reasoning as the progress registry in lane-provision.js).
 */
const _inFlight = new Set();

// ─── Reads ──────────────────────────────────────────────────────────────────

function rowToEngagement(row) {
  if (!row) return null;
  return {
    engagement_id: row.engagement_id,
    profile_id: row.profile_id,
    engagement_type: row.engagement_type,
    subnet_scheme: row.subnet_scheme,
    max_students: row.max_students,
    challenge_id: row.challenge_id,
    challenge_key: row.challenge_key,
    provision_status: row.provision_status,
    provision_error: row.provision_error,
    provisioned_at: row.provisioned_at,
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

/**
 * Attach the reservation's bridge readiness, which lives in cybercore_db because
 * it belongs to the reservation rather than to either plugin. Cross-DB, so it is
 * a second round trip rather than a join — and best-effort, because an
 * engagement that exists must still render if the readiness row does not.
 */
async function withReadiness(engagement) {
  if (!engagement || !engagement.challenge_id) return engagement;
  const r = await getLabReadiness(engagement.challenge_id);
  return {
    ...engagement,
    bridges_ready: r ? r.bridges_ready : null,
    bridge_report: r ? r.report : null,
  };
}

async function getEngagement(profileId, engagementType = DEFAULT_ENGAGEMENT_TYPE) {
  const res = await query(
    `SELECT * FROM ciab_engagement WHERE profile_id = $1 AND engagement_type = $2`,
    [profileId, sanitizeEngagementType(engagementType)]
  );
  return withReadiness(rowToEngagement(res.rows[0]));
}

async function getEngagementById(engagementId) {
  const res = await query(`SELECT * FROM ciab_engagement WHERE engagement_id = $1`, [engagementId]);
  return rowToEngagement(res.rows[0]);
}

async function listEngagements(profileId) {
  const res = await query(
    `SELECT * FROM ciab_engagement WHERE profile_id = $1 ORDER BY engagement_type`,
    [profileId]
  );
  return Promise.all(res.rows.map(r => withReadiness(rowToEngagement(r))));
}

/**
 * Adopt a reservation that predates this table.
 *
 * A migration cannot do this: the evidence is a crucible_challenge row in
 * cybercore_db, and a CIAB migration runs against clinic_db only. So it happens
 * lazily on read, the same way lane-reservation.js adopts pre-engagement
 * challenge keys and backfills a missing zone abbrev.
 *
 * Adopted rows land as 'ready' with NO readiness record — the block genuinely
 * exists (lanes may be running on it), but nothing ever verified its bridges on
 * every node, and writing one would be inventing evidence. withReadiness()
 * therefore reports bridges_ready as null, which the UI renders as unverified
 * rather than as failed.
 */
async function adoptExistingReservation(profileId, engagementType) {
  const engagement = sanitizeEngagementType(engagementType);
  const reservation = await findProfileChallenge(profileId, engagement).catch(() => null);
  if (!reservation) return null;

  const size = reservation.vxlan_block && reservation.vxlan_block.end != null
    ? reservation.vxlan_block.end - reservation.vxlan_block.start + 1
    : null;

  const res = await query(
    `INSERT INTO ciab_engagement
       (profile_id, engagement_type, subnet_scheme, max_students,
        challenge_id, challenge_key, provision_status, provisioned_at)
     VALUES ($1, $2, $3, $4, $5, $6, 'ready', now())
     ON CONFLICT (profile_id, engagement_type) DO UPDATE
       SET challenge_id = EXCLUDED.challenge_id,
           challenge_key = EXCLUDED.challenge_key,
           updated_at = now()
     RETURNING *`,
    [
      profileId, engagement,
      reservation.subnet_scheme || 'v2',
      size && size >= 1 && size <= 200 ? size : 1,
      reservation.challenge_id, reservation.challenge_key,
    ]
  );
  console.log(`${LOG} Adopted pre-existing reservation for ${profileId.slice(0, 8)}/${engagement}`);
  return rowToEngagement(res.rows[0]);
}

/**
 * The engagement for (profile, type), adopting a pre-A8 reservation if one
 * exists. Returns null when there is genuinely nothing reserved.
 */
async function resolveEngagement(profileId, engagementType = DEFAULT_ENGAGEMENT_TYPE) {
  return (await getEngagement(profileId, engagementType))
      || (await adoptExistingReservation(profileId, engagementType));
}

// ─── The deploy gate ────────────────────────────────────────────────────────

/**
 * Refuse a deploy whose network is not actually ready.
 *
 * DELIBERATELY HAS NO INLINE FALLBACK. Reserving here "just this once" is how
 * the cost became invisible in the first place: it would work, so nobody would
 * notice the instructor waiting several minutes with no explanation. A 409 that
 * names the state and the remedy is the whole point of the phase.
 *
 * `bridges_ready === false` is a WARNING, not a block. An adopted pre-A8
 * reservation legitimately has lanes running on it and no bridge evidence, and
 * refusing those would break every existing profile.
 *
 * @throws {Error & {status:409}}
 */
function assertEngagementDeployable(engagement, { profileId, engagementType }) {
  if (!engagement) {
    const err = new Error(
      `No network reserved for this client's '${engagementType}' engagement yet. ` +
      `Reserve it first — carving the VXLAN block takes a few minutes and is done ` +
      `ahead of time so deploy day is fast.`
    );
    err.status = 409;
    err.code = 'ENGAGEMENT_NOT_RESERVED';
    throw err;
  }
  if (engagement.provision_status === 'provisioning') {
    const err = new Error(
      `This engagement's network is still being reserved. Creating the SDN zone and ` +
      `${engagement.max_students} VNets, then waiting for the bridges on every node, ` +
      `takes a few minutes. Watch the reservation panel and deploy when it reads Ready.`
    );
    err.status = 409;
    err.code = 'ENGAGEMENT_PROVISIONING';
    throw err;
  }
  if (engagement.provision_status === 'failed') {
    const err = new Error(
      `This engagement's network failed to reserve: ${engagement.provision_error || 'no reason recorded'}. ` +
      `Use Re-provision on the reservation panel — a failed reservation self-cleans, so retrying is safe.`
    );
    err.status = 409;
    err.code = 'ENGAGEMENT_FAILED';
    throw err;
  }
  if (!engagement.challenge_id) {
    const err = new Error(
      `This engagement is marked ready but has no reservation recorded, which should be ` +
      `impossible. Re-provision it before deploying.`
    );
    err.status = 409;
    err.code = 'ENGAGEMENT_INCONSISTENT';
    throw err;
  }
  return engagement;
}

// ─── Provisioning ───────────────────────────────────────────────────────────

/** Every VXLAN tag whose bridge must exist for this block, v3 internals included. */
function expectedTagsFor(vxlanBlock, subnetScheme) {
  const tags = [];
  for (let id = vxlanBlock.start; id <= vxlanBlock.end; id++) {
    tags.push(id);
    if (subnetScheme === 'v3') tags.push(id + V3_INTERNAL_TAG_OFFSET);
  }
  return tags;
}

/**
 * Carve the block for one engagement, then verify it, then flip the status.
 *
 * DETACHED BY THE CALLER — nothing awaits this. It must therefore never throw
 * out of its own top level, or the rejection lands on an unhandled-rejection
 * handler instead of in the row where an operator can see it.
 */
async function provisionEngagementNetwork(engagement, { companyName = null } = {}) {
  const id = engagement.engagement_id;
  if (_inFlight.has(id)) {
    console.warn(`${LOG} provision already in flight for ${id} — ignoring duplicate`);
    return;
  }
  _inFlight.add(id);

  try {
    await query(
      `UPDATE ciab_engagement
          SET provision_status = 'provisioning', provision_error = NULL,
              provision_started_at = now(), updated_at = now()
        WHERE engagement_id = $1`,
      [id]
    );

    const reservation = await getOrCreateProfileChallenge({
      profileId: engagement.profile_id,
      engagementType: engagement.engagement_type,
      requestedMax: engagement.max_students,
      companyName,
      // The spec is deliberately an empty stub. The real one is synthesized at
      // deploy time from the current asset selection, and profile-deploy's
      // adopt logic keys on `spec.vms` being absent to know it must write one.
      spec: {},
      subnetScheme: engagement.subnet_scheme,
    });

    // A8c: the block is not ready because the config was written — it is ready
    // when the bridges exist on every node a lane could be placed on.
    const readiness = await verifyBridgesOnAllNodes({
      tags: expectedTagsFor(reservation.vxlan_block, engagement.subnet_scheme),
      log: (m) => console.log(`${LOG} ${m}`),
    });

    // Readiness is recorded against the RESERVATION by reserveLabNetwork, in
    // cybercore_db, so it is not written here — CLE reads the same row.
    await query(
      `UPDATE ciab_engagement
          SET challenge_id = $2, challenge_key = $3, provision_status = 'ready',
              provisioned_at = now(), provision_error = NULL, updated_at = now()
        WHERE engagement_id = $1`,
      [id, reservation.challenge_id, reservation.challenge_key]
    );

    if (readiness.ready) {
      console.log(`${LOG} ${engagement.engagement_type} ready for ${engagement.profile_id.slice(0, 8)} ` +
        `(VXLAN ${reservation.vxlan_block.start}-${reservation.vxlan_block.end}, bridges on ${readiness.nodesReady.length} node(s))`);
    } else {
      // Deliberately still 'ready': the block exists and lanes can deploy onto
      // the nodes that DID come up. Blocking here would strand a whole class
      // over one node that is down for unrelated reasons. The warning is
      // surfaced in the UI so it is a decision, not a surprise.
      console.warn(`${LOG} ${engagement.engagement_type} reserved but bridges unconfirmed on ` +
        `${readiness.nodesPending.concat(readiness.nodesUnreachable).join(', ')} — lanes placed there will fail to cable`);
    }
  } catch (err) {
    console.error(`${LOG} provision failed for ${id}: ${err.message}`);
    await query(
      `UPDATE ciab_engagement
          SET provision_status = 'failed', provision_error = $2, updated_at = now()
        WHERE engagement_id = $1`,
      [id, String(err.message).slice(0, 2000)]
    ).catch(e => console.error(`${LOG} could not record failure for ${id}: ${e.message}`));
  } finally {
    _inFlight.delete(id);
  }
}

/**
 * Create an engagement and start carving its network in the background.
 *
 * Returns as soon as the row exists — the caller responds immediately and the
 * UI polls. Nothing awaits the provision.
 */
async function createEngagement({
  profileId, engagementType = DEFAULT_ENGAGEMENT_TYPE, subnetScheme = 'v2',
  maxStudents, companyName = null, actingUserId = null,
}) {
  if (!profileId) throw Object.assign(new Error('profile_id required'), { status: 400 });
  const engagement = sanitizeEngagementType(engagementType);
  const max = parseInt(maxStudents, 10);
  if (!Number.isFinite(max) || max < 1 || max > 200) {
    throw Object.assign(new Error('max_students must be between 1 and 200'), { status: 400 });
  }
  if (!['v1', 'v2', 'v3'].includes(subnetScheme)) {
    throw Object.assign(new Error('subnet_scheme must be v1|v2|v3'), { status: 400 });
  }

  const existing = await resolveEngagement(profileId, engagement);
  if (existing) {
    throw Object.assign(
      new Error(`This client already has a '${engagement}' engagement (${existing.provision_status}).`),
      { status: 409 }
    );
  }

  const res = await query(
    `INSERT INTO ciab_engagement
       (profile_id, engagement_type, subnet_scheme, max_students, created_by, provision_status)
     VALUES ($1, $2, $3, $4, $5, 'provisioning')
     RETURNING *`,
    [profileId, engagement, subnetScheme, max, actingUserId]
  );
  const row = rowToEngagement(res.rows[0]);

  // Detached, exactly as CLE does it. The bare .catch() is the last line of
  // defence: provisionEngagementNetwork records its own failures, so this only
  // fires if the failure UPDATE itself threw.
  provisionEngagementNetwork(row, { companyName })
    .catch(err => console.error(`${LOG} background provision crashed: ${err.message}`));

  return row;
}

/**
 * Re-run a failed engagement's reservation.
 *
 * Safe to retry because getOrCreateProfileChallenge is idempotent on the
 * challenge key and self-heals a wrong-sized EMPTY reservation, and because the
 * resize path it uses calls teardownLabNetwork with force:false — which counts
 * live lanes through the shared claim predicate and refuses rather than
 * destroying a block that is in use.
 *
 * Refused while a provision is in flight, and refused for an engagement that is
 * already ready — re-provisioning a healthy block would carve a NEW one (the
 * allocator only ever climbs) and permanently burn range.
 */
async function reprovisionEngagement(engagementId, { companyName = null, force = false } = {}) {
  const engagement = await getEngagementById(engagementId);
  if (!engagement) throw Object.assign(new Error('Engagement not found'), { status: 404 });

  if (_inFlight.has(engagementId) || engagement.provision_status === 'provisioning') {
    throw Object.assign(
      new Error('This engagement is already being provisioned. Wait for it to finish.'),
      { status: 409 }
    );
  }
  if (engagement.provision_status === 'ready' && !force) {
    throw Object.assign(
      new Error(
        'This engagement is already reserved. Re-provisioning a healthy block would carve a ' +
        'second one — VXLAN blocks are only ever allocated above the highest in use, never reused.'
      ),
      { status: 409 }
    );
  }

  provisionEngagementNetwork(engagement, { companyName })
    .catch(err => console.error(`${LOG} re-provision crashed: ${err.message}`));
  return engagement;
}

/**
 * Boot sweep for engagements stranded mid-provision.
 *
 * A provision is fire-and-forget async work inside THIS process. A restart kills
 * it with no resume, so any row still 'provisioning' at boot is by definition
 * abandoned — CLE has no equivalent, and the result there is a course that spins
 * "Initializing" forever with deletion as the only exit.
 *
 * Marks them 'failed' rather than silently retrying: the half-built block may
 * hold a challenge row, and an operator pressing Re-provision is a decision,
 * where an automatic retry at every boot is a loop.
 */
async function recoverStrandedEngagements() {
  try {
    const res = await query(
      `UPDATE ciab_engagement
          SET provision_status = 'failed',
              provision_error = 'Interrupted by a server restart while reserving. Re-provision to retry.',
              updated_at = now()
        WHERE provision_status = 'provisioning'
        RETURNING engagement_id, profile_id, engagement_type`
    );
    if (res.rows.length > 0) {
      console.warn(`${LOG} Marked ${res.rows.length} engagement(s) failed — stranded mid-provision by a restart: `
        + res.rows.map(r => `${String(r.profile_id).slice(0, 8)}/${r.engagement_type}`).join(', '));
    }
    return res.rows.length;
  } catch (err) {
    // The table may not exist yet on a first boot after deploy — the migration
    // runs in the same startup, but ordering across plugins is not guaranteed.
    console.warn(`${LOG} stranded-engagement sweep skipped: ${err.message}`);
    return 0;
  }
}

module.exports = {
  getEngagement,
  getEngagementById,
  listEngagements,
  resolveEngagement,
  adoptExistingReservation,
  createEngagement,
  provisionEngagementNetwork,
  reprovisionEngagement,
  recoverStrandedEngagements,
  assertEngagementDeployable,
  // Pure, so it is testable without a cluster.
  expectedTagsFor,
};
