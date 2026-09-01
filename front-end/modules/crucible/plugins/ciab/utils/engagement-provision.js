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
// ─── Track B0: the engagement MODEL ─────────────────────────────────────────
// engagement-model.js has ZERO requires of its own — that is its contract, and
// the new test file asserts it with a source scan. It matters here: this module
// is loaded on a stubbed require.cache by test/ciab-engagement-provision.test.js
// (:173-174, which stubs only site-config and proxmox), so a new impure
// transitive require would fail that suite with an error naming the wrong file.
//
// engagement-plan.js is deliberately NOT required here. It pulls in
// profile-to-spec.js and the shared ipv4 helper, none of which this path needs;
// the compile is a caller's concern, not a projection's.
const {
  engagementModelFromRow, validateEngagementPlan, describeEngagementType,
  MODEL_FIELDS, JSONB_MODEL_FIELDS, AUTHORABLE_FIELDS, BAKE_TYPE_KEY,
} = require('./engagement-model');
// ─── B3: the staging engagement cannot be pulled out from under a bake ───────
// TWO NAMES ONLY — the status vocabulary and the per-client read — from the
// module that OWNS ciab_profile_bake. Not a second SELECT spelled here: this
// file would then hold its own copy of another module's table name and its own
// idea of which statuses are finished, and the day a status is added the copy
// would quietly start calling a running bake finished.
//
// LOAD-SAFE, and checked rather than assumed: bake-orchestrator.js's only
// top-level require is './db', the same handle this file already holds, so it
// adds no cluster call, no site-config read and no new failure mode to the
// stubbed module caches that load this file (test/ciab-engagement-provision.test.js
// and test/ciab-engagement-model.test.js). It does not require this module
// back, so there is no cycle.
const {
  listBakes, TERMINAL_STATUSES: BAKE_TERMINAL_STATUSES,
} = require('./bake-orchestrator');
// ─── R1: the default scheme has exactly ONE spelling ────────────────────────
// It used to have six — a bare 'v2' literal in each of routes/engagements.js,
// routes/profile-deploy.js and this file — which is precisely why flipping
// profile-to-spec.js's DEFAULT_SUBNET_SCHEME to 'v3' changed nothing: that
// constant only fires when a caller OMITS the option, and every live caller
// passed a literal. So the constant is IMPORTED here rather than re-declared;
// a second declaration is the same drift wearing a different name.
//
// LOAD-SAFE, and that is not an accident. profile-to-spec.js's own header
// records that it imports nothing which needs a cluster or a database: its
// heaviest edge is src/utils/vm-template-resolver.js -> site-config.js, whose
// getConfig() reads config/site.json LAZILY, on call, not at require time. So
// this adds no new failure mode to the stubbed module caches that load this
// file (test/ciab-engagement-provision.test.js:36-46 and
// test/ciab-engagement-model.test.js:141-156, which stub site-config only).
const { DEFAULT_SUBNET_SCHEME } = require('./profile-to-spec');

const LOG = '[CIAB Engagement]';

/**
 * The scheme an ADOPTED pre-A8 reservation is recorded as — 'v2', and
 * deliberately NOT DEFAULT_SUBNET_SCHEME.
 *
 * This is not a stale literal that R1 missed; it is the same rule migration
 * 016 refuses to break with a backfill, applied on the read path.
 *
 * adoptExistingReservation writes a ciab_engagement row for a VXLAN block that
 * was ALREADY CARVED, before this table existed — by the inline path in
 * routes/profile-deploy.js, which defaulted to v2 and carved ONE VNet per lane.
 * subnet_scheme on such a row is therefore not a preference to be defaulted; it
 * is a DESCRIPTION of what is in Proxmox. Recording 'v3' would claim an internal
 * VNet at tag + V3_INTERNAL_TAG_OFFSET that nothing ever created, and the next
 * deploy would cable its lanes onto bridges that do not exist on any node —
 * while expectedTagsFor() below would start demanding those same tags and call
 * a perfectly healthy block unready.
 *
 * reservationFromRow (lane-reservation.js:145-158) does not project a
 * subnet_scheme at all, so `reservation.subnet_scheme` is always undefined here
 * and this value is always the one written. Stated as a named constant so that
 * is a decision on the record rather than a fallback nobody re-read.
 */
const ADOPTED_SUBNET_SCHEME = 'v2';

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
    // ── Track B0: the engagement MODEL. ─────────────────────────────────────
    // Via engagementModelFromRow rather than fifteen more hand-written lines,
    // so a column added later cannot be silently dropped on every read path
    // while SELECT * keeps returning it. This map is a WHITELIST — it already
    // drops provision_started_at and created_by, which is the standing proof
    // that a column absent from here is invisible to every caller, no matter
    // what the database holds.
    //
    // engagementModelFromRow returns the migration's DEFAULTs for a row that
    // carries none of these columns, so on a database where the model
    // migration has not yet run the added keys read as null/[]/{} and no
    // existing key changes value.
    //
    // test/ciab-engagement-model.test.js parses the migration's ADD COLUMN
    // list and diffs it against this function's output, so the omission fails
    // a test rather than a demo.
    ...engagementModelFromRow(row),
    retired_at: row.retired_at,
    updated_by: row.updated_by,
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
      // NOT the default — see ADOPTED_SUBNET_SCHEME. An adopted row describes a
      // carve that already happened; it does not get to choose one.
      reservation.subnet_scheme || ADOPTED_SUBNET_SCHEME,
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

// ─── The model writer ───────────────────────────────────────────────────────

/**
 * Update the engagement MODEL — the display name, the perspective, what is in
 * and out of scope, the rules of engagement, the accounts the client agreed to
 * hand over, where each host sits relative to the perimeter, the objectives and
 * the brief.
 *
 * This is the writer B1's PATCH route will call. B0 ships no route, so today its
 * only caller is a test. It lives here rather than in the route because the
 * validate-then-write pair must not be splittable — see the next paragraph.
 *
 * THE JS VALIDATOR RUNS FIRST, ALWAYS. The CHECK constraints on this table are
 * backstops for a writer that is NOT this function (a psql session, a future
 * import script) — they are not the guarantee. An off-vocabulary value that
 * reaches Postgres raises 23514, and a pg error carries neither `status` nor
 * `statusCode`, so every engagement endpoint's renderer
 * (routes/profile-deploy.js:699, :733, :761 — `res.status(err.status || 500)`)
 * turns it into an unhandled 500 naming a constraint, in place of the 400 the
 * route already knows how to produce. So validateEngagementPlan refuses it here
 * and the field-level report rides on the error, in the same shape
 * createEngagement already throws (:498-505 below).
 *
 * PARTIAL PATCH SEMANTICS. validateEngagementPlan returns only the keys the
 * caller actually sent, and the SET list below is built from exactly those, so
 * an unmentioned column is never blanked. That is load-bearing: this model is
 * authored across several screens over several sittings, and a PATCH that
 * silently reset the fields it did not mention would lose an instructor's work.
 *
 * NOT A RETIREMENT PATH. retired_at is not a member of MODEL_FIELDS, so nothing
 * here can hand a VXLAN block back; that decision needs its own action with its
 * own confirmation, and B0 writes the column nowhere.
 *
 * @param {string}   engagementId
 * @param {object}   patch                  a PARTIAL model; unknown keys ignored
 * @param {object}   [opts]
 * @param {?string}  [opts.actingUserId]    cybercore_user.user_id — cross-DB, no FK,
 *                                          same pattern as created_by
 * @param {boolean}  [opts.markAuthored]    record the touched AUTHORABLE fields as
 *                                          human-authored. A patch carrying none of
 *                                          them never rewrites authored_fields, so a
 *                                          machine writer that forgets to opt out
 *                                          cannot lock B2's refresh path out of a
 *                                          field nobody edited.
 * @returns {Promise<object>} the rowToEngagement projection of the updated row
 * @throws {Error & {status:404}}
 * @throws {Error & {status:400, code:'ENGAGEMENT_PLAN_INVALID', errors, warnings}}
 */
async function updateEngagementModel(engagementId, patch, {
  actingUserId = null, markAuthored = true,
} = {}) {
  const current = await getEngagementById(engagementId);
  if (!current) throw Object.assign(new Error('Engagement not found'), { status: 404 });

  // knownVmNames is deliberately NOT passed. This path has no synthesized spec
  // in hand, and building one here would be a fourth derivation of the host list
  // — the exact duplication B0 exists to avoid. Every check that needs real
  // hosts is a WARNING in the validator, so their absence costs a hint and never
  // a guarantee; the compile (engagement-plan.js) is where a stored model is
  // measured against the machines that actually deploy, because that is the only
  // place those machines exist.
  // subnetScheme comes from the ROW, not from the caller. This function already
  // holds the engagement, and the scheme is the fact that decides whether a
  // placement is real: on v1/v2 there is one flat lan0 (lane-networking.js
  // resolveVmSegments), so an 'internal' or 'pivot' placement is a fiction and
  // validateEngagementPlan raises EXPOSURE_REQUIRES_V3. Without this argument
  // that warning could never fire on the authoring path — the only path an
  // instructor uses — and the divergence would surface at deploy instead.
  // A WARNING, never an error: the model is legitimately authored before the
  // environment's scheme is settled.
  const { errors, warnings, value } = validateEngagementPlan(patch, {
    engagementType: current.engagement_type,
    subnetScheme: current.subnet_scheme || null,
  });
  if (errors.length > 0) {
    const more = errors.length > 1 ? ` (+${errors.length - 1} more)` : '';
    throw Object.assign(new Error(`${errors[0].message}${more}`), {
      status: 400, code: 'ENGAGEMENT_PLAN_INVALID', errors, warnings,
    });
  }

  // Keyed BY COLUMN so a field can be assigned at most once. authored_fields is
  // both an ordinary model column and the thing markAuthored maintains, and
  // Postgres refuses two assignments to the same column in one UPDATE — a map
  // makes that collision structurally impossible rather than a thing to
  // remember.
  const assignments = {};
  for (const field of MODEL_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(value, field)) assignments[field] = value[field];
  }

  // NOTHING AUTHORABLE IN THE PATCH MEANS NOTHING WAS AUTHORED. markAuthored
  // defaults to true because the human writer (B1's PATCH route) is the common
  // caller, but the flag must never be able to mark a field nobody edited: a
  // field listed here is one B2's refresh-from-the-client-file path will refuse
  // to overwrite forever, and "which fields a human edited" is unrecoverable
  // retroactively. So a patch that carries no authorable field — an empty
  // patch, or one that only stamps updated_by, or one that only sets
  // synthesis_meta — leaves authored_fields untouched rather than rewriting it
  // to its own sorted self.
  //
  // A patch whose ONLY key is authored_fields still writes: that value was
  // already assigned above from MODEL_FIELDS, so the caller's prune stands on
  // its own without the union running.
  const touched = Object.keys(value).filter(k => AUTHORABLE_FIELDS.includes(k));

  if (markAuthored && touched.length > 0) {
    // A UNION, never a replacement. A later "refresh from the client file"
    // action fills everything NOT named here and leaves everything that is, so
    // dropping an entry silently re-opens an authored field to being clobbered
    // — and which fields a human edited is unrecoverable retroactively.
    //
    // An explicit authored_fields in the patch is the BASE of the union rather
    // than a competitor, which keeps markAuthored purely additive and keeps the
    // caller able to prune the list in the same request.
    const base = Array.isArray(assignments.authored_fields)
      ? assignments.authored_fields
      : (Array.isArray(current.authored_fields) ? current.authored_fields : []);
    assignments.authored_fields = Array.from(new Set([...base, ...touched])).sort();
  }

  // The column names interpolated below come from MODEL_FIELDS — a frozen module
  // constant — and never from the caller: `value`'s keys were intersected with
  // it above, so nothing a request body carries can reach the SQL TEXT. Only
  // values are parameters.
  //
  // Every jsonb column is JSON.stringify'd and cast on FIRST reference. There is
  // deliberately no `$n IS NULL` construction anywhere in this file: Postgres
  // fixes a parameter's type at its first reference, so an uncast NULL test is a
  // real parse failure, not a style preference — test/sql-param-typing.test.js
  // scans every .js under src/ and modules/ for it.
  const params = [engagementId];
  const sets = [];
  for (const field of MODEL_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(assignments, field)) continue;
    const raw = assignments[field];
    if (JSONB_MODEL_FIELDS.has(field)) {
      params.push(JSON.stringify(raw === undefined ? null : raw));
      sets.push(`${field} = $${params.length}::jsonb`);
    } else {
      params.push(raw === undefined ? null : raw);
      sets.push(`${field} = $${params.length}`);
    }
  }

  // Set by hand: this schema has no triggers anywhere, and every other UPDATE in
  // this file does the same. Appended last so that even a patch which sets no
  // model column still records who touched the engagement and when.
  params.push(actingUserId);
  sets.push(`updated_by = $${params.length}`);
  sets.push('updated_at = now()');

  const res = await query(
    `UPDATE ciab_engagement
        SET ${sets.join(', ')}
      WHERE engagement_id = $1
      RETURNING *`,
    params
  );
  // Deleted between the read and the write. Rare, but returning null here would
  // hand the caller an "updated" engagement that does not exist.
  if (res.rows.length === 0) {
    throw Object.assign(new Error('Engagement not found'), { status: 404 });
  }
  return rowToEngagement(res.rows[0]);
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
  profileId, engagementType = DEFAULT_ENGAGEMENT_TYPE,
  // R1: the ONE default, imported. A caller that names a scheme still wins —
  // this fires only when the field is absent or empty, which is what makes an
  // explicit 'v2' a first-class choice rather than a legacy value.
  subnetScheme = DEFAULT_SUBNET_SCHEME,
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

  // ── THE POSTURE IS WRITTEN AT INSERT, NOT LEFT TO THE COLUMN DEFAULTS ─────
  //
  // 011 declares perspective and credential_posture NOT NULL DEFAULT
  // 'internal' / 'none' — the conservative pair every pre-B0 row already holds.
  // A DEFAULT is the right answer for the 'default' type and the WRONG one for
  // 'external_blackbox', and because the columns are NOT NULL the wrong answer
  // is always a LEGAL value: nothing downstream can distinguish it from an
  // authored choice, and a read-time registry fallback can never fire, because
  // there is no null to fall back FROM. An engagement created as external would
  // be stored as internal permanently, and every consumer of 'external' —
  // exposure, scope, the brief, B1's per-perspective filter — would silently
  // take the internal branch.
  //
  // describeEngagementType is TOTAL (engagement-model.js): a registry key gives
  // its declared posture, and an unknown slug gives exactly the (internal,
  // none) pair the DEFAULTs already assign. So this changes nothing for a
  // custom slug and fixes the one case that matters. Both values satisfy 012's
  // CHECK vocabularies by construction — the registry and the constraint are
  // the same two lists.
  //
  // NOT a substitute for the model writer: updateEngagementModel remains the
  // only way to change a posture afterwards (a custom slug declaring itself
  // external), and it validates the pair against the registry first.
  //
  // adoptExistingReservation deliberately does NOT do this. It is on the READ
  // path, its INSERT stays a fixed 8-column list, and it must never write a
  // model column an instructor may have authored.
  const posture = describeEngagementType(engagement);

  const res = await query(
    `INSERT INTO ciab_engagement
       (profile_id, engagement_type, subnet_scheme, max_students, created_by,
        provision_status, perspective, credential_posture)
     VALUES ($1, $2, $3, $4, $5, 'provisioning', $6, $7)
     RETURNING *`,
    [profileId, engagement, subnetScheme, max, actingUserId,
      posture.perspective, posture.credential_posture]
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

/**
 * B3: refuse to retire the staging engagement out from under a running bake.
 *
 * WHAT GOES WRONG WITHOUT IT. A bake borrows a DEDICATED one-slot engagement —
 * routes/profile-deploy.js's BAKE_ENGAGEMENT_TYPE, and its header explains at
 * length why a one-id block is the only shape that makes the staging lane's
 * VXLAN id, and therefore the pair of /24 bases the golden templates write into
 * their own DNS zone, their SYSVOL referrals and every SPN, knowable before the
 * lane exists. That row is the system's whole record of which block those
 * templates were built against. Retiring it is one confirmed click in a list
 * that, until this phase, showed it as an ordinary engagement — and the bake it
 * strands reports nothing at all, because nothing in a ninety-minute ansible run
 * reads this table.
 *
 * THE SHAPE IS assertEngagementDeployable's, deliberately: a 409 with a
 * SCREAMING_SNAKE code, naming the state it found and the remedy, and NO INLINE
 * FALLBACK. There is nothing sensible to do on behalf of the operator here —
 * pausing the bake is not a thing this system can do, and retiring anyway is the
 * failure — so the only honest answer is to refuse and say what to do instead.
 *
 * NOT RESTRICTED TO A ROUTE. It lives on retireEngagement because that is the
 * one function every retirement path goes through; a guard in the handler would
 * be bypassed by the next caller, and the whole finding is that a second caller
 * appeared without anyone noticing.
 *
 * TERMINAL IS THE BAKE MODULE'S WORD, not a list copied here — ready, failed and
 * superseded are the three states nothing will move on its own. 'pending' is
 * NOT terminal: it has allocated nothing yet, but it is a bake about to start on
 * exactly this block, and retiring underneath it strands it just as thoroughly.
 *
 * A READ THAT CANNOT RUN IS NOT AN ABSENT BAKE. If ciab_profile_bake is missing
 * or unreadable this throws the pg error, the route renders it (42P01 becomes a
 * 503 naming the migration), and the retirement does not happen. Refusing on
 * "could not check" is the safe direction: the cost of a wrong refusal is one
 * operator re-reading a message, and the cost of a wrong retirement is a
 * ninety-minute build with no evidence of what broke it.
 *
 * @param {object} engagement  a rowToEngagement projection, or a bare row —
 *                             only engagement_type and profile_id are read
 * @returns {Promise<void>}
 * @throws {Error & {status:409, code:'ENGAGEMENT_BAKE_IN_FLIGHT'}}
 */
async function assertBakeEngagementRetirable(engagement) {
  // Every other type keeps exactly the behaviour it had: no second read, no new
  // failure mode, no new refusal. This guard is about ONE slug.
  if (!engagement || engagement.engagement_type !== BAKE_TYPE_KEY) return;

  const bakes = await listBakes(engagement.profile_id);
  const live = bakes.filter(b => !BAKE_TERMINAL_STATUSES.includes(b.status));
  if (live.length === 0) return;

  // listBakes orders created_at DESC, so this is the newest live one. The count
  // is named too: an operator who clears one and is refused again should not
  // have to guess that there was a second.
  const bake = live[0];
  const also = live.length > 1 ? ` (and ${live.length - 1} more still running)` : '';
  const err = new Error(
    `Bake ${bake.lab_name} is still running on this staging network — it reads ` +
    `'${bake.status}': ${bake.phase_detail || 'no progress recorded yet'}${also}. Retiring the ` +
    `'${BAKE_TYPE_KEY}' engagement now would end the record of the one-slot block that bake's golden ` +
    `templates are being built against, and nothing in the build would report the cause. Wait for it ` +
    `to finish — a bake ends as ${BAKE_TERMINAL_STATUSES.join(', ')} — or, if no process is still ` +
    `running it, restart the server: the boot sweep marks an abandoned bake failed and tears its ` +
    `staging lane down. Then retire.`
  );
  err.status = 409;
  err.code = 'ENGAGEMENT_BAKE_IN_FLIGHT';
  err.bake = { bake_id: bake.bake_id, lab_name: bake.lab_name, status: bake.status };
  throw err;
}

/**
 * Track B1: retirement.
 *
 * DELIBERATELY NOT PART OF updateEngagementModel. retired_at sits OUTSIDE
 * MODEL_FIELDS on purpose (see that function's "NOT A RETIREMENT PATH" note),
 * and test/ciab-engagement-model.test.js parses 011's ADD COLUMN list and pins
 * `declared \ MODEL_FIELDS` to exactly ['retired_at','updated_by'] — so moving it
 * into MODEL_FIELDS fails a test immediately, and for the right reason. Ending
 * an engagement is an ACTION with its own confirmation, not a field somebody
 * sets in passing while editing a scope rule.
 *
 * RETIRING DOES NOT RELEASE CAPACITY. It marks the row; the carved VXLAN block
 * stays carved. Nothing anywhere in this tree hands a block back — the only
 * teardown path is deleting the whole profile. The route's confirmation copy is
 * the ONLY thing standing between an instructor and the belief that retiring
 * frees a slot, so do not soften it.
 *
 * WHY A CONDITIONAL UPDATE RATHER THAN READ-THEN-WRITE. `AND retired_at IS NULL`
 * makes a second retire a zero-row UPDATE instead of a silent second write that
 * moves the timestamp — when an engagement ended is evidence, and a double click
 * must not rewrite it. The two failure cases are told apart afterwards, on the
 * cold path, so the hot path stays one statement. (`retired_at IS NULL` is a
 * COLUMN null test, not a `$n IS NULL` parameter one — the construction
 * test/sql-param-typing.test.js scans this file for.)
 *
 * @param {string}  engagementId
 * @param {object}  [opts]
 * @param {?string} [opts.actingUserId]  cybercore_user.user_id — cross-DB, no FK,
 *                                       the same pattern as created_by/updated_by
 * @returns {Promise<object>} the rowToEngagement projection of the retired row
 * @throws {Error & {status:404}} no such engagement
 * @throws {Error & {status:409}} already retired
 */
async function retireEngagement(engagementId, { actingUserId = null } = {}) {
  // B3: ONE extra SELECT, and only far enough to learn the type — the guard
  // itself reads nothing more for any engagement that is not the staging one.
  // The conditional UPDATE below stays exactly as it was, including its zero-row
  // 404/409 split: a missing row falls straight through here (there is no type
  // to guard) and is still told apart on the cold path.
  //
  // Retirement is a confirmed, admin-only action taken a handful of times in an
  // environment's life, so a second round trip on it is not a cost worth
  // trading against a stranded ninety-minute build.
  const before = await query(
    `SELECT engagement_id, profile_id, engagement_type FROM ciab_engagement WHERE engagement_id = $1`,
    [engagementId]
  );
  await assertBakeEngagementRetirable(before.rows[0]);

  const res = await query(
    `UPDATE ciab_engagement
        SET retired_at = now(), updated_by = $2, updated_at = now()
      WHERE engagement_id = $1 AND retired_at IS NULL
      RETURNING *`,
    [engagementId, actingUserId]
  );
  if (res.rows.length === 0) {
    // Zero rows means one of two things, and the caller must be able to tell
    // them apart: a 404 is a bad id, a 409 is a button pressed twice. One extra
    // round trip, only on a path that has already failed.
    const existing = await getEngagementById(engagementId);
    if (!existing) throw Object.assign(new Error('Engagement not found'), { status: 404 });
    throw Object.assign(new Error('This engagement is already retired.'), { status: 409 });
  }
  return rowToEngagement(res.rows[0]);
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
  // Track B1: ends an engagement without pretending it hands the block back.
  retireEngagement,
  // B3: exported so a caller — and a test — can ask the question without
  // performing the retirement, and so the refusal has exactly one author.
  assertBakeEngagementRetirable,
  assertEngagementDeployable,
  // Track B0: the model writer B1's PATCH route calls.
  updateEngagementModel,
  // Exported so a test can assert it projects every column the migration adds —
  // SELECT * hides the omission, because the database really does return them.
  rowToEngagement,
  // Pure, so it is testable without a cluster.
  expectedTagsFor,
  // ─── R1 ───────────────────────────────────────────────────────────────────
  // Re-exported, NOT re-declared: profile-to-spec.js owns the only literal, and
  // this is the same binding. It is here so that the module which WRITES
  // ciab_engagement.subnet_scheme can also state what that column defaults to,
  // and so a test can prove the two agree by identity rather than by spelling.
  DEFAULT_SUBNET_SCHEME,
  // The read-path exception, exported so a test can pin that it is NOT the
  // default and cannot quietly become it.
  ADOPTED_SUBNET_SCHEME,
};
