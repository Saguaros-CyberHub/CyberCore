/**
 * ============================================================================
 * engagements.js — Track B1a: the engagement MODEL over HTTP
 * ----------------------------------------------------------------------------
 * B0 shipped the model (migration 011 + utils/engagement-model.js), the writer
 * (utils/engagement-provision.js updateEngagementModel) and the compiler
 * (utils/engagement-plan.js compileEngagementPlan). None of it had a route. An
 * instructor could not read, author or even see an engagement, and the only
 * surface that named one at all was the admin reservation panel, which renders
 * engagements[0] and hardcodes the type. This file is the whole B1a route
 * surface: read the engagements a client holds, compile one offline into a
 * brief, edit the seven fields the compile actually reads, and — for an admin —
 * create, adopt, re-provision and retire.
 *
 * WHY ITS OWN FILE, MOUNTED FROM routes/instructor.js.
 * routes/api.js is the single shared mount block that several tracks are
 * editing at once, and it is guarded by a test that is being edited in the same
 * breath. Mounting here instead keeps routes/api.js at ZERO diff. instructor.js
 * has no route path beginning /engagements (every top-level path in it was
 * enumerated before this was written), so the sub-mount shadows nothing, and
 * the router.use() sits above every route in that file so a later /:param path
 * cannot shadow it either.
 *
 * WHY NOT UNDER /api/profile-deploy. That mount carries checkSchedule
 * (routes/api.js), which can refuse an instructor who is outside a group's
 * scheduled window. Authoring an engagement is not a lab session and must not
 * be gated on one.
 *
 * GATING. authenticateToken is applied once, at the /api/instructor mount in
 * routes/api.js:139, so it is deliberately NOT repeated here — but there is no
 * requireCiabAccess and no checkSchedule on that mount, so EVERY route below
 * carries its own requireRole. The split is not cosmetic:
 *
 *   instructorOnly  reads and authoring. Editing a scope rule or a brief costs
 *                   nothing and is the daily work of the person teaching.
 *   adminOnly       CREATE, ADOPT, RE-PROVISION, RETIRE. Creating an engagement
 *                   burns a VXLAN block permanently: 25-50 serial VNet POSTs
 *                   plus a CLUSTER-WIDE SDN apply, and the allocator only ever
 *                   climbs above the highest block in use and never re-uses
 *                   range. That is a cluster decision, not an authoring one.
 *
 * WHAT THIS FILE REFUSES TO DO.
 *   - It never calls resolveEngagement outside POST /adopt. resolveEngagement
 *     falls through to adoptExistingReservation, which INSERTs. A read that
 *     writes is not a read, and the existing admin GET does exactly that.
 *   - It has NO DELETE route, at all. ciab_module.engagement_type is a bare
 *     VARCHAR with no foreign key, so a hard delete would silently orphan every
 *     module naming that (profile_id, engagement_type) pair with nothing
 *     anywhere able to notice. Migration 011 shipped retired_at for this.
 *   - It never puts a credential, or anything derived from one, into an audit
 *     row. Names and counts only. See the PATCH handler.
 * ============================================================================
 */

const express = require('express');
const router = express.Router();
const { requireRole } = require('../../../../../src/middleware/auth');
const audit = require('../../../../../src/utils/audit');
const { query } = require('../utils/db');
const { cybercoreQuery } = require('../../../../../src/utils/cybercore-db');
const engagementProvision = require('../utils/engagement-provision');
const { compileEngagementPlan } = require('../utils/engagement-plan');
const { synthesizeSpecFromProfile } = require('../utils/profile-to-spec');
const laneReservation = require('../utils/lane-reservation');
const {
  ENGAGEMENT_TYPES, describeEngagementType, engagementDisplayName,
  resolveEngagementTypeAlias, validateEngagementPlan,
} = require('../utils/engagement-model');

const instructorOnly = requireRole('instructor', 'admin');
const adminOnly      = requireRole('admin');

// ─── Helpers ────────────────────────────────────────────────────────────────

/**
 * The ONLY error renderer in this file. JSON on every path, always.
 *
 * public/js/app.js:38 calls response.json() unconditionally on a failure, so an
 * error body that is not JSON becomes APIError('Network error', 0) and the real
 * status is lost before any handler sees it. A status-only reply with no body —
 * or an HTML error page from an uncaught throw — would present a 409 carrying a
 * named remedy to the operator as a network outage instead.
 *
 * TWO PROPERTY NAMES, BOTH READ. The two producers this file calls disagree:
 * loadProfileForDeploy throws `statusCode` (404 for a missing client, 422 for a
 * missing client file), and engagement-provision.js throws `status` (400/404/
 * 409). routes/profile-deploy.js:608 reads only `err.statusCode || 500`, which
 * is exactly why assertEngagementDeployable's 409 renders as a bare 500 there
 * today. Never copy either half alone.
 *
 * A pg error carries NEITHER, which is deliberate: an unexpected database error
 * is a 500, and turning it into anything else would hide it.
 */
function sendErr(res, err) {
  if (err && err.code === '42P01') {
    // The engagement tables come from this plugin's own migrations directory,
    // which the loader re-runs on every boot and whose failures it only
    // console.errors. A missing relation is therefore a DEPLOY state, not a bug
    // in the request — 503 with the remedy named, never a bare 500 that reads
    // as "the server is broken".
    return res.status(503).json({
      code: 'ENGAGEMENT_STORE_MISSING',
      error: 'The engagement tables are not available on this server yet '
           + `(${(err.message || 'relation missing').split('\n')[0]}). `
           + 'Restart the server and check the boot log for a line reading '
           + '"[PluginLoader]   Migration failed" against the ciab migrations.',
    });
  }
  if (err && err.code === '22P02') {
    // 22P02 is invalid_text_representation — in this file, always a malformed
    // uuid reaching a WHERE engagement_id = $1 (the :engagementId path segment)
    // or a WHERE id = $1 (a body profile_id). That is a CLIENT error, so it is
    // a 400: a bare 500 tells the operator the server broke when in fact the
    // link they followed carried a bad id, and it puts a false alarm in the
    // server log for something no server change can fix.
    //
    // The message names BOTH ids because sendErr cannot see which one the
    // handler was holding, and guessing "engagement" for what was really a
    // client id would send the operator to the wrong field.
    //
    // THE PG MESSAGE IS DELIBERATELY NOT FORWARDED. It reads `invalid input
    // syntax for type uuid: "<value>"`, which echoes the offending path segment
    // — attacker-chosen text — straight back into a response body that
    // public/js/app.js renders into a toast. Nothing about the caller's own
    // input tells them anything they did not already send, so the reply names
    // the SHAPE that was expected and stops there.
    return res.status(400).json({
      code: 'INVALID_ID',
      error: 'That id is not valid. Engagement and client ids are uuids — use '
           + 'the ones the engagement list returns.',
    });
  }
  const status = (err && (err.status || err.statusCode)) || 500;
  const body = { error: (err && err.message) || 'Request failed' };
  if (err && err.code) body.code = err.code;
  if (err && Array.isArray(err.errors)) body.errors = err.errors;
  if (err && Array.isArray(err.warnings)) body.warnings = err.warnings;
  res.status(status).json(body);
}

/** adminOnly gates the write routes; this decides what the SCREEN may offer. */
function isAdmin(req) {
  return !!(req.user && req.user.role === 'admin');
}

/**
 * ────────────────────────────────────────────────────────────────────────────
 * THE ENGAGEMENT-TYPE CONTRACT ON CREATE — and why it is a 400 with an
 * override rather than either a blanket check or nothing at all.
 * ────────────────────────────────────────────────────────────────────────────
 *
 * WHAT A TYPO COSTS. sanitizeEngagementType is a COERCER, not a validator: it
 * deletes disallowed characters and never rejects (lane-reservation.js:108-111),
 * so 'externl_blackbox' passes through untouched. describeEngagementType is
 * TOTAL by design (engagement-model.js:478-497) and answers the conservative
 * (internal, none) posture for any slug it does not know. Put those two
 * together on POST / and one transposed character used to produce a 202, a
 * PERMANENTLY BURNED VXLAN BLOCK — the allocator only ever climbs above the
 * highest block in use and never re-uses range — and an engagement stored with
 * the OPPOSITE perspective from the one that was asked for, with no error
 * anywhere. subnet_scheme and max_students on the same handler were already
 * validated by the writer, so the gap was an asymmetry, not a policy.
 *
 * WHY NOT A BLANKET ALLOWLIST. B0 built ENGAGEMENT_TYPES as a REGISTRY WITH A
 * TOTAL FALLBACK and said so at length — engagement-model.js:396-421 and
 * migrations/011_ciab_engagement_model.sql's "NO CHECK ON engagement_type —
 * HERE OR EVER". A locally defined slug must stay expressible, existing rows
 * carry slugs this registry does not name, and a database CHECK would turn an
 * off-vocabulary slug into a 23514 surfacing as an unhandled 500. So the
 * REGISTRY does not become an allowlist: this refusal lives in ONE route
 * handler — the one that spends capacity — and changes no stored contract, no
 * reader, and no other route.
 *
 * WHY THE OVERRIDE IS AN EXPLICIT PARAMETER. The thing being defended against
 * is a MISTAKE, and the only reliable way to tell a mistake from an intention
 * is to make the operator state the intention. `allow_custom_type: true` cannot
 * be typed by accident, and it turns a slug the registry does not know from a
 * silent 202 into a deliberate one. The refusal names every key it does know
 * so the fix is in the response, and resolves a DISPLAY alias into a
 * did_you_mean — 'externalblackbox' is exactly what the sanitizer makes of
 * 'External Blackbox' typed into a form, and it must NOT be silently rewritten
 * (the slug is baked into the reservation key, so rewriting orphans a carve),
 * which leaves naming the canonical spelling as the only safe help.
 *
 * WHY ONLY POST /. Not on /adopt and not on PATCH:
 *   - adopt ADOPTS AN EXISTING CARVE and allocates nothing. The slug it is
 *     given has to match a reservation key that already exists on the cluster,
 *     and pre-engagement blocks were carved with whatever slug the writer of
 *     the day emitted. Refusing an unknown slug there would make exactly the
 *     legacy blocks adopt exists to rescue unadoptable.
 *   - engagement_type is not in B1_EDITABLE_FIELDS, so PATCH cannot reach it.
 */
function classifyEngagementTypeSlug(slug) {
  const descriptor = describeEngagementType(slug);
  if (descriptor.known) return { known: true, refusal: null };

  const aliasOf = resolveEngagementTypeAlias(slug);
  return {
    known: false,
    refusal: {
      code: 'UNKNOWN_ENGAGEMENT_TYPE',
      error: `"${slug}" is not one of the known engagement types. Creating an `
           + 'engagement carves a network block permanently and nothing in this '
           + 'system hands one back, so an unrecognised type is refused rather '
           + 'than created with a default posture. Pick a known type, or resend '
           + 'with allow_custom_type: true to define a new one deliberately.'
           + (aliasOf ? ` Did you mean "${aliasOf}"?` : ''),
      // The refusal carries the vocabulary, so the caller never has to guess
      // and never has to make a second request to GET /types to recover.
      known_types: Object.keys(ENGAGEMENT_TYPES),
      did_you_mean: aliasOf || undefined,
    },
  };
}

/**
 * B1a EDITS EXACTLY SEVEN FIELDS. Every one of them is read by
 * compileEngagementPlan, so every edit is visible in the compiled brief. A
 * field an instructor can change but nothing consumes is worse than no editor
 * at all — it looks like it worked.
 *
 * allowed_techniques is DELIBERATELY ABSENT. plan.techniques is ALWAYS
 * buildTechniques(perspective, credentialPosture) (engagement-plan.js:2613);
 * the stored column has no reader anywhere in the compile. Offering an editor
 * would persist an edit with zero effect AND stamp the field into
 * authored_fields, which locks a later refresh-from-the-client-file path out of
 * it forever. Whether the compile starts reading it, or the column leaves
 * AUTHORABLE_FIELDS, is a B2 decision.
 *
 * asset_selection is DELIBERATELY ABSENT. It changes what actually deploys
 * (profile-to-spec.js:83-90) and belongs with B2's spec writeback, not with an
 * authoring form that has no deploy consequence anywhere else in it.
 *
 * The allowlist also means the request body is never spread: an unknown key can
 * never reach the writer, and markAuthored can only ever stamp a field this
 * file actually offers.
 */
const B1_EDITABLE_FIELDS = Object.freeze([
  'display_name', 'scope_in', 'scope_out', 'objectives',
  'brief', 'issued_credentials', 'exposure_plan',
]);

/**
 * Project a rowToEngagement result for the browser.
 *
 * The browser cannot load engagement-model.js — it has zero requires and no
 * window shim, and manifest.json's staticDir is "public", so utils/ is never
 * served. So the display label and the type descriptor are resolved HERE, once,
 * rather than by a second vocabulary invented in the page.
 *
 * challenge_key and challenge_id are STRIPPED. rowToEngagement really does
 * carry both (utils/engagement-provision.js:76-111), they are reservation
 * identifiers with no meaning to an instructor, and the admin reservation panel
 * renders one today — which is how a word that must never appear in
 * instructor-facing copy gets onto a screen. Deleting them here means the page
 * cannot render one even by accident.
 *
 * `can` is ADVICE FOR THE SCREEN, never the gate. The gate is the requireRole
 * on each route below; this only decides which buttons are worth drawing.
 */
function project(row, admin) {
  const out = { ...row };
  delete out.challenge_key;
  delete out.challenge_id;
  out.display_label   = engagementDisplayName(row);
  out.type_descriptor = describeEngagementType(row.engagement_type);
  out.can = {
    create: admin, adopt: admin, reprovision: admin, retire: admin,
    edit: true,
  };
  return out;
}

/**
 * Compile one engagement's plan OFFLINE — no Proxmox call, no deploy, no
 * reservation required.
 *
 * THE SPEC IS SYNTHESIZED FRESH, NOT READ OFF THE RESERVATION.
 * provisionEngagementNetwork stores `spec: {}` on purpose
 * (utils/engagement-provision.js:465-469) — the real one is written at deploy
 * time — so reading it back would compile every freshly created engagement to
 * one SPEC_EMPTY problem and an empty plan.
 *
 * options.vxlanBlock is omitted DELIBERATELY. profile-to-spec.js:254 defaults it
 * to {start:10000,end:10009} and only ever writes it to spec.vxlan_block, which
 * the compile never reads. That is what lets a plan compile for an engagement
 * that has never deployed and holds no block at all.
 */
async function compilePlanFor(engagement) {
  // LAZY require, inside the call rather than at module load: profile-deploy.js
  // pulls the batch deployer and the vuln-app generator behind it, and this
  // file is required from routes/instructor.js at boot. Keeping it here means
  // mounting the router costs nothing.
  const { loadProfileForDeploy, defaultAssetSelection } = require('./profile-deploy');

  const { profile, assets } = await loadProfileForDeploy(engagement.profile_id);

  // The VM template catalog lives in cybercore_db, the vuln scripts in
  // clinic_db — two pools, so two round trips, run together.
  const [vmCat, vulnCat] = await Promise.all([
    cybercoreQuery(`SELECT id, os_family, os_version, os_name, template_vmid, node, role_hints, is_active, preferred, created_at
                    FROM cybercore_template_catalog WHERE is_active = true AND template_type = 'os_template'`),
    query(`SELECT id, slug, name, os_target, category, script_type, services_exposed, is_active FROM vuln_scripts WHERE is_active = true`),
  ]);

  const assetSelection = Array.isArray(engagement.asset_selection) && engagement.asset_selection.length
    ? engagement.asset_selection
    : defaultAssetSelection(assets);

  const { spec } = synthesizeSpecFromProfile({
    profile: { ...profile, assets },
    assetSelection,
    vmTemplateCatalog: vmCat.rows,
    vulnScriptCatalog: vulnCat.rows,
    vulnApp: null,
    options: { subnetScheme: engagement.subnet_scheme || 'v2', attackBoxes: true },
  });

  return compileEngagementPlan({
    engagement,
    spec,
    profile: { ...profile, assets },
  });
}

// ─── Routes ─────────────────────────────────────────────────────────────────
//
// REGISTRATION ORDER IS LOAD-BEARING. '/types' and '/adopt' are registered
// before '/:engagementId', or Express binds engagementId = 'types' and the
// registry read becomes a 404 for an engagement nobody asked for.

/**
 * GET /api/instructor/engagements/types
 *
 * The engagement-type registry, projected. This is what stops the create form
 * from hardcoding 'default' the way the admin reservation panel does at
 * public/js/admin-profile-lanes.js:411 — the vocabulary has ONE definition and
 * every screen reads it from here.
 *
 * The registry is deep-frozen, so each entry is copied: a caller that mutates
 * its own copy must not throw in strict mode.
 */
router.get('/types', instructorOnly, (req, res) => {
  try {
    res.json({ types: Object.values(ENGAGEMENT_TYPES).map(t => ({ ...t })) });
  } catch (err) {
    sendErr(res, err);
  }
});

/**
 * POST /api/instructor/engagements/adopt   { profile_id, engagement_type }
 *
 * The ONLY route in this file permitted to call resolveEngagement, and it
 * exists so that the write which today happens invisibly on somebody else's GET
 * becomes an explicit, audited, admin-confirmed action.
 *
 * ADOPTING CONSUMES NO CAPACITY. It takes over a block that was already carved
 * before this table existed and carves nothing new — adoptExistingReservation
 * returns null immediately when there is no reservation to find, so it can only
 * ever adopt, never allocate. The screen copy has to say so: an admin who
 * believes otherwise presses Create instead and burns a second block that
 * nothing in this tree can ever hand back.
 */
router.post('/adopt', adminOnly, async (req, res) => {
  try {
    const body = req.body || {};
    if (!body.profile_id) return res.status(400).json({ error: 'profile_id is required' });

    // Through sanitizeEngagementType, always. The slug is baked into the
    // reservation key, and the canonical identity of an ENVIRONMENT is exactly
    // the pair (profile_id, sanitizeEngagementType(engagement_type)) — so a raw
    // slug written here produces a row that the environment surface can never
    // join to, with nothing anywhere able to notice.
    const engagementType = laneReservation.sanitizeEngagementType(body.engagement_type);

    const engagement = await engagementProvision.resolveEngagement(body.profile_id, engagementType);
    if (!engagement) {
      return res.status(404).json({ error: 'No existing reservation to adopt' });
    }

    audit.log({
      req,
      action: 'profile_engagement.adopted',
      source: 'ciab',
      target: {
        type: 'engagement', id: engagement.engagement_id,
        label: engagementDisplayName(engagement),
      },
      metadata: {
        profile_id: engagement.profile_id,
        engagement_type: engagement.engagement_type,
        provision_status: engagement.provision_status,
      },
    });

    res.json({ engagement: project(engagement, isAdmin(req)) });
  } catch (err) {
    sendErr(res, err);
  }
});

/**
 * GET /api/instructor/engagements?profile_id=<uuid>
 *
 * EVERY engagement the client holds, not the first one. The admin reservation
 * panel reads engagements[0] (public/js/admin-profile-lanes.js:336), which is
 * why a second engagement against one client is invisible there and its VXLAN
 * block looks like a leak.
 *
 * listEngagements ONLY — never resolveEngagement. See the file header.
 *
 * unadopted_reservation is CAPACITY-CRITICAL. Without it the screen cannot tell
 * "nothing is reserved" from "a block was carved before this table existed and
 * no row names it yet", and an instructor pressing Create in the second case
 * carves a SECOND block the allocator can never release. findProfileChallenge
 * is a pure SELECT — it is the read half of the adopt path, with no INSERT — so
 * probing costs nothing and changes nothing.
 *
 * THREE ANSWERS, NOT TWO. unadopted_probe distinguishes "the probe ran" from
 * "the probe could not run", because collapsing the second into null asserts
 * that nothing is reserved on exactly the evidence that nothing is known — and
 * that assertion is what carves a duplicate block. See the handler.
 */
router.get('/', instructorOnly, async (req, res) => {
  try {
    const profileId = req.query.profile_id;
    if (!profileId) return res.status(400).json({ error: 'profile_id is required' });

    const rows = await engagementProvision.listEngagements(profileId);
    const admin = isAdmin(req);

    // THE PROBE RUNS ON EVERY LIST, NOT ONLY ON AN EMPTY ONE.
    //
    // It used to be gated on rows.length === 0, which made a pre-engagement
    // block PERMANENTLY INVISIBLE the moment any engagement row existed against
    // that client — and "a client holds a second, different engagement" is the
    // normal case this whole table was added for. That is the exact state the
    // comment above says must never be indistinguishable from "nothing is
    // reserved", and the consequence is an admin pressing Create and carving a
    // SECOND block the allocator can never hand back. Capacity is a hard
    // ceiling, so one indexed SELECT per list is the right price.
    //
    // findProfileChallenge is a pure SELECT — the read half of the adopt path,
    // with no INSERT — so probing costs nothing and changes nothing.
    const probeType = laneReservation.DEFAULT_ENGAGEMENT_TYPE;
    let unadopted = null;
    let probeStatus = 'ok';
    let reservation = null;
    try {
      reservation = await laneReservation.findProfileChallenge(profileId, probeType);
    } catch (probeErr) {
      // A FAILED PROBE IS NOT AN ABSENT RESERVATION, and reporting it as one is
      // how a cybercore_db outage turns into a second carved block: the empty
      // state would offer Create where it should offer Adopt. So the failure is
      // NAMED — unadopted_probe: 'unavailable' — and the screen can say "could
      // not check" instead of asserting something it does not know. It is still
      // not a 500: the engagement list itself came back fine and is worth
      // rendering.
      probeStatus = 'unavailable';
      console.warn(`[CIAB Engagement] reservation probe failed for profile ${profileId}: ${probeErr.message}`);
    }

    if (reservation) {
      // A reservation that an engagement row ALREADY names is adopted, not
      // unadopted — offering Adopt for it would be its own wrong answer. The
      // comparison is between sanitized slugs on both sides because the stored
      // identity of an environment is the pair (profile_id, sanitized type).
      const adopted = rows.some(
        r => laneReservation.sanitizeEngagementType(r.engagement_type) === probeType
      );
      if (!adopted) {
        // The engagement type ONLY. The reservation record also carries its key
        // and its stored spec, neither of which an instructor has any use for.
        unadopted = {
          engagement_type: laneReservation.sanitizeEngagementType(reservation.engagement_type),
        };
      }
    }

    res.json({
      engagements: rows.map(r => project(r, admin)),
      unadopted_reservation: unadopted,
      // 'ok'          — the probe ran; unadopted_reservation is the answer.
      // 'unavailable' — the probe could not run. unadopted_reservation is null
      //                 because nothing is known, NOT because nothing exists.
      unadopted_probe: probeStatus,
      // The SAME advice project() puts on each row, hoisted to the top level,
      // because the branch that needs it most has no rows to read it from: an
      // empty list is exactly where the screen offers Create and Adopt. Without
      // it an admin visiting a client with no engagement sees prose where the
      // button belongs — and an instructor would see a button whose 403 writes
      // an access.denied audit row against the screen's primary user. Advice for
      // drawing buttons only; the gate is the requireRole on every route here.
      can: {
        create: admin, adopt: admin, reprovision: admin,
        retire: admin, edit: true,
      },
    });
  } catch (err) {
    sendErr(res, err);
  }
});

/**
 * POST /api/instructor/engagements
 *   { profile_id, engagement_type, subnet_scheme, max_students, display_name? }
 *
 * adminOnly: CAPACITY. One of these burns a VXLAN block permanently.
 *
 * 202, not 200 — the row exists, the network does not yet. The screen polls the
 * list route.
 *
 * CREATE-THEN-PATCH, and the failure of the second half is not an error.
 * createEngagement's signature accepts no model field at all, so naming an
 * engagement is a second call. If that call fails the engagement EXISTS and has
 * ALREADY BURNED A BLOCK; answering with an error would invite the operator to
 * press Create again and burn another. So the name is best-effort and the
 * response is still 202 — engagementDisplayName falls back through the registry
 * to a readable label, so an unnamed engagement renders correctly rather than
 * as a broken one.
 */
router.post('/', adminOnly, async (req, res) => {
  try {
    const body = req.body || {};
    const engagementType = laneReservation.sanitizeEngagementType(body.engagement_type);

    // BEFORE THE PROFILE LOOKUP, AND BEFORE ANY WRITE. See
    // classifyEngagementTypeSlug: this is the only thing standing between a
    // one-character typo and a permanently carved VXLAN block stored under the
    // wrong perspective. It is pure and synchronous, so refusing here costs
    // nothing and touches no database.
    const typeCheck = classifyEngagementTypeSlug(engagementType);
    const customTypeAllowed = body.allow_custom_type === true;
    if (!typeCheck.known && !customTypeAllowed) {
      return res.status(400).json(typeCheck.refusal);
    }

    // The client must exist, and its name is needed for the reservation key.
    const profRes = await query(
      `SELECT id, company_name FROM profiles WHERE id = $1`,
      [body.profile_id]
    );
    if (profRes.rows.length === 0) return res.status(404).json({ error: 'Profile not found' });

    let engagement = await engagementProvision.createEngagement({
      profileId: body.profile_id,
      engagementType,
      subnetScheme: body.subnet_scheme || 'v2',
      maxStudents: body.max_students,
      companyName: profRes.rows[0].company_name,
      actingUserId: req.user.userId,
    });

    const wantedName = typeof body.display_name === 'string' ? body.display_name.trim() : '';
    let named = false;
    if (wantedName) {
      try {
        engagement = await engagementProvision.updateEngagementModel(
          engagement.engagement_id, { display_name: wantedName },
          { actingUserId: req.user.userId, markAuthored: true }
        );
        named = true;
      } catch (nameErr) {
        // Swallowed on purpose — see the header note. The block is already
        // carved; the name can be set from the edit form afterwards.
        console.warn(`[CIAB Engagement] created ${engagement.engagement_id} but could not name it: ${nameErr.message}`);
      }
    }

    audit.log({
      req,
      action: 'profile_engagement.created',
      source: 'ciab',
      target: {
        type: 'engagement', id: engagement.engagement_id,
        label: engagementDisplayName(engagement),
      },
      metadata: {
        profile_id: engagement.profile_id,
        engagement_type: engagement.engagement_type,
        subnet_scheme: engagement.subnet_scheme,
        max_students: engagement.max_students,
        perspective: engagement.perspective,
        named,
        // Recorded because it is the one path that spends capacity on a slug
        // the registry does not name — an operator who used the override left a
        // row saying so, and a run of these is how a missing registry entry
        // becomes visible instead of accumulating silently.
        custom_type: !typeCheck.known,
      },
    });

    res.status(202).json({ success: true, engagement: project(engagement, isAdmin(req)) });
  } catch (err) {
    sendErr(res, err);
  }
});

/**
 * GET /api/instructor/engagements/:engagementId
 *
 * The engagement plus its COMPILED PLAN — the brief, the scope, the exposure,
 * the objectives, and every problem the compile found. Offline: three awaits
 * and one synchronous call, no cluster contact.
 *
 * bridges_ready is null ON PURPOSE and must render as UNVERIFIED, NOT FAILED.
 * getEngagementById attaches no readiness, unlike getEngagement and
 * listEngagements — and an adopted pre-existing block genuinely has lanes
 * running on it with no bridge evidence anywhere, so inventing `false` here
 * would report a healthy environment as broken.
 */
router.get('/:engagementId', instructorOnly, async (req, res) => {
  try {
    const engagement = await engagementProvision.getEngagementById(req.params.engagementId);
    if (!engagement) return res.status(404).json({ error: 'Engagement not found' });

    const plan = await compilePlanFor(engagement);

    res.json({
      engagement: project(engagement, isAdmin(req)),
      plan,
      bridges_ready: null,
    });
  } catch (err) {
    sendErr(res, err);
  }
});

/**
 * PATCH /api/instructor/engagements/:engagementId
 *
 * Authoring. instructorOnly: editing a scope rule or a brief costs nothing and
 * is the daily work of the person teaching.
 *
 * THE WARNINGS ARE RE-RUN, AND THAT IS THE POINT.
 * updateEngagementModel destructures `warnings` but references them only inside
 * the error throw (utils/engagement-provision.js:270-272); its success return
 * discards them. So EXPOSURE_REQUIRES_V3 — the warning that tells an instructor
 * their pivot placement is a fiction on a v1/v2 lane, because those schemes have
 * one flat lan0 — can never reach the only path an instructor uses.
 *
 * validateEngagementPlan is pure, synchronous and total, so re-running it with
 * the SAME arguments the writer used reproduces them exactly. subnetScheme and
 * engagementType come from the ROW, never from the request, exactly as the
 * writer does — and neither is editable here, so the returned row carries the
 * same values the writer read. This is why B1 makes ZERO edits to that
 * function: the fix is a second call, not a changed contract.
 */
router.patch('/:engagementId', instructorOnly, async (req, res) => {
  try {
    const body = req.body || {};

    // NEVER a spread of the body. Only the seven fields, and only when actually
    // present — an absent key must stay absent, because the writer's partial
    // semantics turn "present and undefined" into a blanked column.
    const patch = {};
    for (const f of B1_EDITABLE_FIELDS) {
      if (body[f] !== undefined) patch[f] = body[f];
    }
    if (Object.keys(patch).length === 0) {
      return res.status(400).json({ error: 'Nothing to update' });
    }

    const updated = await engagementProvision.updateEngagementModel(
      req.params.engagementId, patch,
      { actingUserId: req.user.userId, markAuthored: true }
    );

    const { warnings } = validateEngagementPlan(patch, {
      engagementType: updated.engagement_type,
      subnetScheme:   updated.subnet_scheme || null,
    });

    // AUDIT: NAMES AND COUNTS ONLY, and the last thing before the response.
    //
    // Never metadata: {...patch} and never changes: { after: req.body }.
    // test/audit-hygiene.test.js is a source-literal check over eleven
    // identifiers and CANNOT SEE A SPREAD, so a spread is not caught, it is
    // merely unnoticed. The writer's runtime redact() blanks issued_credentials
    // wholesale because the key matches /cred/ — which makes the row useless
    // rather than safe — while a FLATTENED credential entry keeps username,
    // target_vm, privilege and above all note, none of which redact() matches,
    // in a plaintext table that is published on adminer.
    //
    // WHICH IS ALSO WHY THE COUNT IS NOT CALLED credential_slots.
    // audit.js:114 tests SECRET_KEY_RE — which contains a bare `cred` — against
    // the KEY, not the value, so `credential_slots: 2` was being STORED as the
    // string "[redacted]": the one number here that is safe by construction was
    // the one number the row lost. The fix is the key name, never the redactor:
    // that regex is shared core, it is on CLE's path, and every other key it
    // catches it catches correctly. issued_account_slots says the same thing —
    // migration 011 calls these "accounts the client agreed to hand over" — and
    // matches nothing in SECRET_KEY_RE, so the count survives.
    //
    // Counts, not contents, for a second reason: audit.js:115 caps a serialized
    // metadata object at 16KB and DISCARDS IT WHOLE when it is bigger, so
    // dumping a model here would lose profile_id along with it.
    audit.log({
      req,
      action: 'profile_engagement.model_updated',
      source: 'ciab',
      target: {
        type: 'engagement', id: req.params.engagementId,
        label: engagementDisplayName(updated),
      },
      metadata: {
        profile_id: updated.profile_id,
        engagement_type: updated.engagement_type,
        perspective: updated.perspective,
        fields: Object.keys(patch).sort(),
        issued_account_slots: (updated.issued_credentials || []).length,
        scope_in_rules:   (updated.scope_in  || []).length,
        scope_out_rules:  (updated.scope_out || []).length,
        exposure_entries: (updated.exposure_plan || []).length,
        objectives:       (updated.objectives || []).length,
        brief_chars: typeof updated.brief === 'string' ? updated.brief.length : 0,
        warnings: warnings.map(w => w.code),
      },
    });

    res.json({ engagement: project(updated, isAdmin(req)), warnings });
  } catch (err) {
    sendErr(res, err);
  }
});

/**
 * POST /api/instructor/engagements/:engagementId/reprovision   { force?: true }
 *
 * adminOnly: CAPACITY. Re-provisioning a HEALTHY block carves a second one,
 * because the allocator only ever climbs. reprovisionEngagement refuses a
 * 'ready' engagement with a 409 unless force is set, and the screen offers this
 * only in the failed state and sends force only behind a second confirmation.
 *
 * 202: the row is unchanged, the carve runs detached and records its own
 * outcome. The screen polls the list route.
 */
router.post('/:engagementId/reprovision', adminOnly, async (req, res) => {
  try {
    const existing = await engagementProvision.getEngagementById(req.params.engagementId);
    if (!existing) return res.status(404).json({ error: 'Engagement not found' });

    const profRes = await query(
      `SELECT company_name FROM profiles WHERE id = $1`,
      [existing.profile_id]
    );

    const forced = (req.body || {}).force === true;
    const engagement = await engagementProvision.reprovisionEngagement(req.params.engagementId, {
      companyName: profRes.rows[0] && profRes.rows[0].company_name,
      force: forced,
    });

    audit.log({
      req,
      action: 'profile_engagement.reprovisioned',
      source: 'ciab',
      target: {
        type: 'engagement', id: req.params.engagementId,
        label: engagementDisplayName(existing),
      },
      metadata: {
        profile_id: existing.profile_id,
        engagement_type: existing.engagement_type,
        previous_status: existing.provision_status,
        forced,
      },
    });

    res.status(202).json({ success: true, engagement: project(engagement, isAdmin(req)) });
  } catch (err) {
    sendErr(res, err);
  }
});

/**
 * POST /api/instructor/engagements/:engagementId/retire   { confirm: true }
 *
 * adminOnly, and there is deliberately NO DELETE anywhere in this file.
 *
 * RETIRING DOES NOT RELEASE CAPACITY. The row is marked; the carved VXLAN block
 * stays carved. Nothing in this tree hands a block back — the only teardown is
 * deleting the whole client. The confirmation copy on the screen is the only
 * thing preventing an instructor from retiring in the belief that a slot comes
 * back, and then hitting the ceiling anyway.
 *
 * `confirm: true` is required in the body rather than inferred from the method,
 * so an accidental replay of a POST cannot end an engagement.
 */
router.post('/:engagementId/retire', adminOnly, async (req, res) => {
  try {
    if ((req.body || {}).confirm !== true) {
      return res.status(400).json({
        code: 'CONFIRM_REQUIRED',
        error: 'Retiring an engagement needs confirm: true. Retiring marks the '
             + 'engagement as ended — it does NOT hand its reserved network back, '
             + 'and the slots it holds stay held.',
      });
    }

    const engagement = await engagementProvision.retireEngagement(req.params.engagementId, {
      actingUserId: req.user.userId,
    });

    audit.log({
      req,
      action: 'profile_engagement.retired',
      source: 'ciab',
      target: {
        type: 'engagement', id: engagement.engagement_id,
        label: engagementDisplayName(engagement),
      },
      metadata: {
        profile_id: engagement.profile_id,
        engagement_type: engagement.engagement_type,
        perspective: engagement.perspective,
        max_students: engagement.max_students,
        // Stated explicitly so the audit row itself records the fact the copy
        // above exists to defend: nothing was released.
        capacity_released: false,
      },
    });

    res.json({ engagement: project(engagement, isAdmin(req)) });
  } catch (err) {
    sendErr(res, err);
  }
});

module.exports = router;
