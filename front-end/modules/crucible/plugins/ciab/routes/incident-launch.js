/**
 * CIAB Plugin — Incident LAUNCHER
 * Mounted INSIDE routes/incidents.js, so every path below is reached as
 *   /api/engagements/:engagementId/incidents/...
 * ============================================================================
 * The CiAB twin of cle/routes/attacks.js. Same engine (src/incident/runner.js),
 * same catalog, same dispatch mutex, same response shapes — addressed by
 * ENGAGEMENT instead of by course, so the front-end module that already
 * understands the CLE console understands this one without a second dialect.
 *
 * Vocabulary: Section / Module / Client / Engagement / Environment / Incident.
 * No course, no cohort, no CYBR, and no "lane" in anything a person reads. The
 * `lane_id` KEYS in the resolver's output are a different matter: they are the
 * shared engine's column names, not copy, and renaming them here would fork the
 * payload the shared console renders.
 *
 * ── WHY THIS IS ITS OWN FILE AND NOT MORE OF routes/incidents.js ────────────
 * Two independent reasons, and either alone would be enough.
 *
 *  1. THE ANSWER KEY IS WRITTEN HERE. POST / compiles the graded truth into the
 *     run INSERT, which means this file NAMES the `answer_key` column.
 *     test/incident-answer-key-leak.test.js (E5-L1) forbids that string in
 *     every STUDENT-FACING incident file, and routes/incidents.js is one:
 *     students read boards and bank findings through it. That gate is worth
 *     keeping blunt — it is what stops a later handler in that file selecting
 *     the key by accident — so the writer moves out rather than the gate being
 *     softened.
 *
 *  2. IT IS THE SHAPE CLE ALREADY HAS. Over there the board is
 *     cle/routes/incidents.js and the launcher is cle/routes/attacks.js: one
 *     file every student touches, one file only staff can. This is that split,
 *     with the same reasoning and the same blast radius.
 *
 * It is MOUNTED FROM routes/incidents.js rather than from routes/api.js so the
 * URL surface does not change and api.js stays at zero diff — see the comment
 * at the mount for why the ORDER of that mount is load-bearing.
 *
 * ── SCENARIO MODE: COMPILE FIRST, THEN INSERT ONCE (E7) ─────────────────────
 * The CiAB-native mode. An incident compiled out of the CLIENT's own threat
 * profile — their machines, their people, their addresses — rather than picked
 * out of the MITRE catalog. Three rules hold it together and every one of them
 * is about the same failure:
 *
 *  1. THE COMPILE HAPPENS BEFORE ANYTHING IS WRITTEN. A scenario that cannot
 *     produce a runnable incident is a 400 with a sentence in it. A run row
 *     written and then abandoned sits at 'scheduling', which is one of the two
 *     statuses the per-engagement dispatch mutex is partial on, so it would
 *     hold the whole engagement until something swept it.
 *
 *  2. THE PLAYBOOK AND THE KEY GO IN THE SAME STATEMENT. They are two halves of
 *     one compilation against one seed — and the seed IS the run id, which is
 *     why the uuid is minted here rather than left to the column default. A row
 *     with the attack and no key is an ungradable incident; a row with the key
 *     and no attack can never be retried into the same one.
 *
 *  3. THE CHOICE IS RECORDED ON THE ENGAGEMENT. The benign floor on every
 *     sensor was compiled from a scenario at DEPLOY time; the attack is
 *     compiled at LAUNCH time. The attack's pools are a clone of the floor's by
 *     construction, which is what makes "no closed-vocabulary field separates
 *     the incident from ordinary traffic" true — and that only holds if both
 *     name the same scenario. See launchInBackground.
 *
 * ── 404, NOT 403, FOR AN ENGAGEMENT OR A RUN THAT IS NOT YOURS ──────────────
 * Inherited from routes/incidents.js and restated because it is easy to lose:
 * "no such engagement", "not your engagement" and "no such run" are ONE answer.
 * Engagement ids are UUIDs in a URL, and a distinguishable refusal turns this
 * into an enumeration oracle for how many clinics are running. The 403s below
 * are role refusals only — "you are not staff" — which reveal nothing about
 * which engagements exist.
 * ============================================================================
 */

'use strict';

const crypto = require('crypto');
const express = require('express');
const router = express.Router({ mergeParams: true });

const { requireRole } = require('../../../../../src/middleware/auth');
const audit = require('../../../../../src/utils/audit');
const { cybercoreQuery } = require('../../../../../src/utils/cybercore-db');
const { query } = require('../utils/db');

// Core, from a plugin: the allowed direction. test/incident-engine-locality.js
// forbids the reverse, and nothing under src/incident/ knows this file exists.
const runner = require('../../../../../src/incident/runner');
const catalogModule = require('../../../../../src/incident/catalog');
const engines = require('../../../../../src/incident/engines');

const enrollment = require('../utils/enrollment');
const { engagementDisplayName, isEngagementLive } = require('../utils/engagement-model');

/**
 * E7. The ONE door to a compiled scenario — see utils/scenario-source.js.
 *
 * Required eagerly, unlike engagement-provision below: it reaches
 * src/incident/scenario-compiler.js and this plugin's `query`, neither of which
 * reads config/site.json at module scope, so the trap that forces the lazy
 * require below does not apply here.
 */
const scenarioSource = require('../utils/scenario-source');

/**
 * ATTACK AUTHORING. Both halves come from core, and the split between them is
 * deliberate:
 *
 *   routes/caldera-authoring.js  owns WHERE the authoring instance is (the same
 *                                value Caddy substitutes into its reverse_proxy)
 *                                and the public path it is served on. It holds
 *                                no credential and never will.
 *   incident/caldera/authoring.js owns the API key, the client, the fact-source
 *                                sync and the adversary list.
 *
 * Requiring the route module for two constants is not a layering violation: a
 * plugin requiring core is the allowed direction, and the alternative — a second
 * resolver for the upstream address in this file — is exactly the drift
 * test/caldera-authoring-access.test.js exists to prevent between the app and
 * the Caddyfile.
 *
 * NEITHER OF THESE CAN DISPATCH. See src/incident/caldera/authoring.js's header:
 * the client it builds calls the source and adversary endpoints and nothing
 * else, engineFor('caldera') still throws, and POST / below refuses a body that
 * names an authored adversary.
 */
const authoring = require('../../../../../src/incident/caldera/authoring');
const {
  authoringConfig,
  PUBLIC_PATH: AUTHORING_PATH,
} = require('../../../../../src/routes/caldera-authoring');

/**
 * engagement-provision.js is LAZILY required, and this is not style.
 *
 * Its dependency graph reaches src/utils/batch-deployer.js, which reads
 * config/site.json AT MODULE SCOPE — a gitignored file that is absent in a
 * plain checkout. Requiring it from here at load time makes this whole router
 * unimportable outside a deployed environment, which takes routes/incidents.js
 * (the student board) down with it and breaks every test that mounts either.
 * engines/synthetic.js defers requiring runner.js for exactly this reason and
 * documents the same trap. Deferring costs one cached lookup per request.
 */
let _provision = null;
function provision() {
  if (!_provision) _provision = require('../utils/engagement-provision');
  return _provision;
}

const instructorOnly = requireRole('instructor', 'admin');

/**
 * The engine every incident this route launches runs on.
 *
 * Spelled ONCE and bound as a parameter into the INSERT rather than written as
 * a SQL literal, so the value the adapter is looked up by and the value stored
 * on the row cannot drift apart. 'caldera' is already legal in the column's
 * CHECK (src/incident/schema.js) and deliberately has no adapter until E9;
 * engineFor() refuses it loudly rather than dispatching it with the wrong
 * semantics, which is exactly why nothing here defaults.
 */
const INCIDENT_ENGINE = 'synthetic';

/** Runs are addressed by this pair everywhere. Never scope_id alone. */
const SCOPE_TYPE = 'engagement';
const scopeOf = (engagementId) => ({ scopeType: SCOPE_TYPE, scopeId: String(engagementId) });

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Engagement id arrives via mergeParams; the res.locals shim in api.js backs it up. */
function engagementIdOf(req, res) {
  return req.params.engagementId || res.locals.engagementId;
}

/** One 404 body, so every "not found" answer is byte-identical. See the header. */
const notFound = (res) => res.status(404).json({ error: 'Not found' });

/**
 * One error renderer, reading BOTH `status` and `statusCode`.
 *
 * Deliberately a copy of routes/incidents.js's fail() rather than an import:
 * that file is the student-facing half and this one must not start requiring
 * into it, or the split in the header stops being a split. Same behaviour, same
 * reasons — JSON on every path, because public/js/app.js calls response.json()
 * unconditionally on a failure and a non-JSON body becomes APIError(0).
 */
function fail(res, err, where) {
  const status = err && (err.status || err.statusCode);
  if (status && status >= 400 && status < 500) {
    return res.status(status).json({ error: err.message, code: err.code || null });
  }
  // 22P02 is invalid_text_representation — a malformed uuid, a CLIENT error.
  // pg quotes the offending value verbatim, so it is NOT echoed back: that
  // would put an attacker-chosen path segment into a toast.
  if (err && err.code === '22P02') {
    return res.status(400).json({ error: 'Malformed identifier', code: 'BAD_UUID' });
  }
  console.error(`[CIAB incident-launch] ${where}: ${err && err.message}`);
  return res.status(500).json({ error: (err && err.message) || 'Internal error' });
}

// ---------------------------------------------------------------------------
// Authorization: which engagement, and may this instructor drive it
// ---------------------------------------------------------------------------

/**
 * Every section whose curriculum binds this engagement.
 *
 * ciab_module is the ONLY link between a section and an engagement that exists:
 * ciab_engagement hangs off a CLIENT (profiles), and a module names the pair
 * (profile_id, engagement_type) — the same pair ciab_engagement is UNIQUE on.
 * There is no section_id on the engagement row and there cannot usefully be
 * one, because two sections may run the same client.
 *
 * Returns [] rather than throwing when the table is not there (migration 014
 * warned on this deployment). A missing binding table means "nothing claims
 * this engagement", which is the same answer as an unbound engagement and is
 * handled identically below — see canManageEngagement.
 */
async function sectionsBinding(engagement) {
  try {
    const r = await query(
      `SELECT DISTINCT m.section_id
         FROM ciab_module m
        WHERE m.profile_id = $1 AND m.engagement_type = $2`,
      [engagement.profile_id, engagement.engagement_type]
    );
    return r.rows.map((row) => row.section_id).filter(Boolean);
  } catch (err) {
    console.warn(`[CIAB incident-launch] section binding unavailable: ${err.message}`);
    return [];
  }
}

/**
 * May this staff member launch into this engagement?
 *
 * THE UNBOUND CASE IS AN ALLOW, ON PURPOSE, and it is the part worth reading.
 *
 *   admin                      always. Reserving and driving blocks is theirs.
 *   engagement bound to a
 *   section they manage        yes — that is the ownership claim.
 *   engagement bound to
 *   NOBODY's section           yes. An engagement created straight from the
 *                              admin reservation panel is bound to no module at
 *                              all, which is the common case today. Refusing
 *                              every instructor there would make the launcher
 *                              unusable on exactly the environments it exists
 *                              for, and there is no one to exclude: nothing
 *                              claims the engagement.
 *   bound only to sections
 *   they do NOT manage         no. Somebody else's clinic. 404.
 *
 * This is STRICTLY TIGHTER than the reads beside it: routes/incidents.js gives
 * any staff member the staff board — answer key included — on any engagement,
 * because `isStaff(req.user)` is the whole test there. Tightening the write
 * side first is the right direction to move; widening the read side to match
 * would be a separate, deliberate change.
 */
async function canManageEngagement(engagement, user) {
  if (!user) return false;
  if (user.role === 'admin') return true;
  const sections = await sectionsBinding(engagement);
  if (sections.length === 0) return true;
  for (const sectionId of sections) {
    // canManageSection answers "does it exist AND may you touch it" in one call,
    // so a route cannot accidentally answer the first without the second.
    if (await enrollment.canManageSection(sectionId, user)) return true;
  }
  return false;
}

/**
 * The engagement in the URL, if it exists, is live, and the caller may drive
 * it. null otherwise — the caller 404s, and never distinguishes the three.
 *
 * getEngagementById, NOT resolveEngagement. The brief for this phase named
 * resolveEngagement, but it falls through to adoptExistingReservation(), which
 * INSERTs a row: a read that writes is not a read, and routes/engagements.js
 * documents refusing it outside POST /adopt for exactly this reason. It also
 * takes (profile_id, engagement_type) and this route only ever holds an
 * engagement_id, so it could not be called here without a lookup first anyway.
 */
async function loadEngagement(req, res) {
  const engagementId = engagementIdOf(req, res);
  if (!UUID_RE.test(String(engagementId || ''))) return null;
  const engagement = await provision().getEngagementById(engagementId);
  if (!engagement) return null;
  // A retired engagement handed its VXLAN block back. Anything launched into it
  // would target environments that no longer have a network to run on, and the
  // failure would surface a dispatch at a time as "the guest is unreachable".
  if (!isEngagementLive(engagement)) return null;
  if (!(await canManageEngagement(engagement, req.user))) return null;
  return engagement;
}

/**
 * Load a run, but only if it belongs to the engagement in the URL.
 *
 * scope_type is IN THE PREDICATE, not assumed. A course id and an engagement id
 * are both UUIDs drawn from the same space, so matching on scope_id alone would
 * eventually let a CiAB instructor abort a CYBR 400 run that happened to carry
 * a colliding id — the same collision the dispatch mutex is keyed against.
 *
 * It is a SQL LITERAL here and in the INSERT, matching SCOPE_TYPE and matching
 * cle/routes/attacks.js's `scope_type = 'course'`. A literal is greppable,
 * cannot be reached by a caller-supplied value, and reads identically to a
 * human comparing this statement against the column's CHECK. SCOPE_TYPE stays
 * the single spelling for the JS half, where the engine is handed a scope
 * object rather than a statement.
 *
 * The column list is explicit. `SELECT *` here would pull the compiled attack
 * and the graded truth back out of Postgres on a path that has no use for
 * either, and the only thing between them and a response would be whichever
 * handler remembered not to spread the row.
 */
async function getRunForEngagement(runId, engagementId) {
  if (!UUID_RE.test(String(runId || ''))) return null;
  const r = await cybercoreQuery(
    `SELECT run_id, scope_type, scope_id, scope_label, engine, status,
            mode, technique_id, tactic_id, chain_key, scenario_id,
            duration_seconds, speed,
            catalog_version, created_at, finished_at
       FROM cybercore_incident_run
      WHERE run_id = $1 AND scope_type = 'engagement' AND scope_id = $2`,
    [runId, engagementId]
  );
  return r.rows[0] || null;
}

/**
 * The same row, PLUS the compiled attack. Used by retry and by nothing else.
 *
 * Kept as a second reader rather than widening the one above, because the
 * playbook is the intrusion verbatim and every other handler here has no use
 * for it. A column that is only selected where it is needed cannot be spread
 * into a response by a handler that never asked for it — the same discipline
 * board.js's two column lists follow.
 *
 * WHY RETRY NEEDS IT AT ALL. A retry rebuilds the selection from the STORED row
 * so it means what the original launch meant. For a scenario that selection IS
 * the playbook: there is no catalog entry to look the incident up from, because
 * it was compiled for this client, this scenario and this run. Recompiling
 * instead would produce a DIFFERENT intrusion — the seed is the run id, so the
 * entity draws and the timeline would land elsewhere — and the students would be
 * graded against a key describing the first one.
 *
 * The answer key is deliberately NOT read back. Retry never recompiles it: the
 * stored key is what the board grades against, and it stays where it is.
 */
async function getRunForRetry(runId, engagementId) {
  if (!UUID_RE.test(String(runId || ''))) return null;
  const r = await cybercoreQuery(
    `SELECT run_id, scope_type, scope_id, engine, status,
            mode, technique_id, tactic_id, chain_key, scenario_id,
            duration_seconds, speed, playbook
       FROM cybercore_incident_run
      WHERE run_id = $1 AND scope_type = 'engagement' AND scope_id = $2`,
    [runId, engagementId]
  );
  return r.rows[0] || null;
}

// ---------------------------------------------------------------------------
// GET /catalog — what an instructor can choose from
// ---------------------------------------------------------------------------
/**
 * Static for the life of the process, and PRIVATE.
 *
 * catalog_version names the exact log-generator build the images run, which is
 * why src/incident/projection.js keeps it off every student payload: a student
 * who can read it can diff two runs and learn what changed between them. A
 * shared cache would hand it to whatever proxy sits in front of this.
 */
router.get('/catalog', instructorOnly, async (req, res) => {
  try {
    if (!(await loadEngagement(req, res))) return notFound(res);
    res.set('Cache-Control', 'private, max-age=300');
    return res.json(catalogModule.catalog());
  } catch (error) {
    return fail(res, error, 'GET /catalog');
  }
});

// ---------------------------------------------------------------------------
// GET /scenarios — this client's own incidents
// ---------------------------------------------------------------------------
/**
 * The scenario picker's source, and the reason it is not "read the profile".
 *
 * A client profile is a large document of client prose, and the launcher needs
 * five fields per scenario. Handing the whole thing to a browser to be filtered
 * there would ship `detection_opportunity` — the answer key, per step, in
 * plain text — to a page an instructor might have open beside a student. So the
 * projection happens SERVER SIDE, in scenario-source.summarizeScenario(), which
 * names the fields it emits rather than deleting the ones it does not.
 *
 * `chosen` is what the engagement has already committed to
 * (telemetry_plan.scenario_id, migration 017). It matters more than it looks:
 * the benign floor on every sensor in this engagement was compiled from THAT
 * scenario at deploy time, so launching a different one is a real choice with a
 * real consequence, and the picker can only say so if it knows.
 *
 * An engagement whose client has no scenarios answers 200 with an empty list,
 * not a 404. "There are none" is an answer; the UI renders it as a sentence and
 * leaves the other three modes selectable.
 */
router.get('/scenarios', instructorOnly, async (req, res) => {
  try {
    const engagement = await loadEngagement(req, res);
    if (!engagement) return notFound(res);

    const ctx = await scenarioSource.loadEngagementScenarioContext(engagement.engagement_id);
    if (!ctx) return notFound(res);

    // PRIVATE, and for the same reason /catalog is: this names one client's
    // threat model, and a shared cache would hand it to whatever proxy sits in
    // front of this. Short, because a regenerated profile should show up in the
    // picker within a class rather than within a deploy.
    res.set('Cache-Control', 'private, max-age=60');
    return res.json({
      scenarios: ctx.scenarios.map(scenarioSource.summarizeScenario),
      chosen: ctx.planScenarioId,
      client_name: ctx.companyName || null,
      assets_known: ctx.assets.length,
    });
  } catch (error) {
    return fail(res, error, 'GET /scenarios');
  }
});

// ---------------------------------------------------------------------------
// GET /targets — the environment picker
// ---------------------------------------------------------------------------
router.get('/targets', instructorOnly, async (req, res) => {
  try {
    const engagement = await loadEngagement(req, res);
    if (!engagement) return notFound(res);

    // NO GUEST PROBE. This runs on every tab open, and rung 4 of the resolver
    // costs a guest exec per candidate VM — acceptable when launching, far too
    // expensive for a page load. An environment only resolvable by probe
    // therefore shows as unresolved in the picker and is resolved for real at
    // launch. Identical to cle/routes/attacks.js's /targets, deliberately: this
    // is a READ, and a read that takes a minute is a read nobody waits for.
    const targets = await runner.resolveScopeTargets(scopeOf(engagement.engagement_id));
    return res.json({
      targets,
      resolvable: targets.filter((t) => t.resolvable).length,
      total: targets.length,
    });
  } catch (error) {
    return fail(res, error, 'GET /targets');
  }
});

// ---------------------------------------------------------------------------
// Attack authoring — prepare this Engagement, THEN hand over the link
// ---------------------------------------------------------------------------
/**
 * WHAT THIS IS. One standalone Caldera "authoring" instance lives outside every
 * Environment, with no agents and no implants. An instructor builds adversaries
 * in its own web UI; CyberCore reads them back out. Nothing inside an
 * Environment ever talks to it, and nothing here launches anything.
 *
 * WHY THESE TWO ROUTES ARE REGISTERED ABOVE POST /:runId/abort AND /retry.
 * Express matches in REGISTRATION ORDER, and `/authoring/fact-source` would be
 * read as a run id by any :runId route declared first. Neither of those two
 * would actually match a second segment of 'fact-source' — but that is a
 * property of the current path names and not of the design, and the same
 * accident already cost this file's mount its own comment in routes/incidents.js.
 * Registered first, it cannot happen.
 *
 * THE ROLE GATE IS instructorOnly, LIKE EVERY OTHER WRITE HERE. Caldera itself
 * has no per-user and no per-object ownership — its users are credentials in a
 * 'red' or 'blue' GROUP, which is a role and not tenancy — so CYBERCORE OWNS ALL
 * SCOPING, exactly as it does for the launcher: loadEngagement() decides whether
 * this staff member may drive this Engagement at all, and a student never gets
 * past requireRole.
 */

/**
 * The authoring instance for this deployment, or the reason there isn't one.
 *
 * WHERE the box is comes from routes/caldera-authoring.js — the same value
 * Caddy proxies to. The CREDENTIAL comes from incident/caldera/authoring.js,
 * because that route file deliberately holds none and says so at length. The
 * decision itself lives in core, so the CLE twin cannot answer it differently.
 */
const authoringTarget = () => authoring.resolveTarget(authoringConfig());

/**
 * POST /authoring/fact-source — the "Author attacks" click.
 *
 * THE ORDER IS THE POINT AND IT IS WHY THIS IS A REQUEST AT ALL, rather than a
 * link the browser could simply follow. The fact source Caldera seeds an
 * operation from is REFRESHED FROM THE DEPLOYED SPEC HERE, and the console_path
 * this answers with is only present once that refresh has been accepted by the
 * server. An instructor who reaches the authoring UI before the refresh is
 * authoring against the machines the PREVIOUS environment had: every ability
 * they aim at one of them produces a link that can never run, the operation
 * completes in seconds having done nothing, and the run row says it succeeded.
 *
 * A POST rather than a GET because it WRITES — it creates or replaces a row on a
 * shared server. The same request is safe to repeat: syncFactSource() matches
 * the class's deterministic id first and its name second, so re-pressing the
 * button updates one row rather than accumulating thirty.
 *
 * ANSWERS 200 EVEN WHEN IT CANNOT BE DONE. `ready` is the discriminant, and the
 * reasons are codes this route turns into nothing at all: the CONSOLE writes the
 * sentences, because CiAB and CLE do not share copy. A 4xx here would reach
 * public/js/app.js as an APIError and become a red toast reading "Internal
 * error", which is precisely the dead end this endpoint exists to replace.
 */
router.post('/authoring/fact-source', instructorOnly, async (req, res) => {
  try {
    const engagement = await loadEngagement(req, res);
    if (!engagement) return notFound(res);
    const engagementId = engagement.engagement_id;

    // The Client's own document, for the company name and the asset list. A
    // failure here is NOT fatal: assets are ENRICHMENT ONLY (an OS string for a
    // machine whose spec row carries none) and the label falls back to the
    // Engagement's own display name. Blanking the whole card because a profile
    // moved would take away authoring that would otherwise work.
    let ctx = null;
    try {
      ctx = await scenarioSource.loadEngagementScenarioContext(engagementId);
    } catch (err) {
      console.warn(`[CIAB incident-launch] authoring context unavailable: ${err.message}`);
    }

    // THE DEPLOYED SPEC, never the profile. A profile describes an estate on
    // paper and the Environment deploys a subset of it; seeding the authoring UI
    // from the paper makes every machine that was never built look targetable.
    const { spec, lanes } = await authoring.loadScopeSpec(scopeOf(engagementId));

    const target = authoringTarget();
    const label = [ctx && ctx.companyName, engagementDisplayName(engagement)]
      .filter(Boolean).join(' — ');

    const result = await authoring.prepareAuthoring({
      client: target.client,
      unavailable: target.unavailable,
      // The scope KEY is the engagement id and the LABEL is for humans. Two
      // Engagements a human called the same thing are two scopes; the id is what
      // keeps their fact sources apart on a server with no ownership.
      scopeKey: engagementId,
      scopeLabel: label || engagementDisplayName(engagement),
      spec,
      assets: ctx ? ctx.assets : null,
    });

    if (result.ready) {
      // Audited ONCE per click, unlike the forward_auth probe next door which
      // fires per subrequest and is deliberately not audited on the allow side.
      // This one is a staff action that writes to a server every instructor
      // shares, so it is worth a row. Names and counts only — the host list
      // describes a Client's estate and does not belong in an audit metadata
      // blob that admins browse.
      audit.log({
        req,
        action: 'incident.authoring_prepared',
        source: 'ciab',
        target: {
          type: 'engagement',
          id: engagementId,
          label: engagementDisplayName(engagement),
        },
        metadata: {
          fact_source: result.fact_source.name,
          action: result.fact_source.action,
          windows: result.platforms.windows,
          linux: result.platforms.linux,
          other: result.platforms.other,
        },
      }).catch(() => {});
    }

    return res.json({
      ...result,
      // The link, and ONLY on the ready path. This is the ordering rule made
      // structural: there is no branch in which a console can render a link
      // without having rendered the platform summary that came back with it.
      console_path: result.ready ? `${AUTHORING_PATH}/` : null,
      upstream: target.upstream,
      environments: lanes,
      // Travels with every answer so a console renders the gate from the
      // SERVER's word rather than a constant of its own that could drift open.
      execution: authoring.EXECUTION_GATE,
    });
  } catch (error) {
    return fail(res, error, 'POST /authoring/fact-source');
  }
});

/**
 * GET /authoring/adversaries — what the authoring instance holds.
 *
 * A READ of a content store. Caldera has no per-object ownership, so this is
 * every adversary on the box and not "this Engagement's" — there is no such
 * concept over there, and pretending otherwise in the payload would invent a
 * boundary the server does not enforce.
 *
 * PICKING ONE CANNOT LAUNCH IT. There is no endpoint in this router, or in the
 * CLE twin, that accepts an adversary id and dispatches it: POST / refuses a
 * body naming one outright, INCIDENT_ENGINE is the literal 'synthetic', and
 * engineFor('caldera') throws underneath all of that. `execution` says so in the
 * payload so the console can explain the gate rather than silently disabling a
 * button.
 */
router.get('/authoring/adversaries', instructorOnly, async (req, res) => {
  try {
    if (!(await loadEngagement(req, res))) return notFound(res);
    const target = authoringTarget();
    const result = await authoring.listAdversaryProfiles(target.client, {
      unavailable: target.unavailable,
    });
    // PRIVATE and uncached. The list names one department's authored intrusions
    // and changes the moment an instructor saves in Caldera's UI; a stale picker
    // is how somebody launches last week's adversary.
    res.set('Cache-Control', 'no-store');
    return res.json({ ...result, upstream: target.upstream });
  } catch (error) {
    return fail(res, error, 'GET /authoring/adversaries');
  }
});

// ---------------------------------------------------------------------------
// POST / — launch
// ---------------------------------------------------------------------------

router.post('/', instructorOnly, async (req, res) => {
  try {
    const engagement = await loadEngagement(req, res);
    if (!engagement) return notFound(res);
    const engagementId = engagement.engagement_id;
    const body = req.body || {};

    // ── EXECUTION IS SHUT, AND THIS IS WHERE THAT IS ENFORCED ─────────────
    // An adversary authored in the attack-authoring console is PREPARED, never
    // dispatchable: src/incident/engines/index.js does not register the caldera
    // adapter, engineFor('caldera') throws, and INCIDENT_ENGINE below is the
    // literal 'synthetic'. So a body naming one could only ever be ignored —
    // and an ignored field is how an instructor comes to believe they launched
    // the intrusion they authored while the class hunts a different one.
    // Refused by name instead, with the reason in it.
    if (body.adversary_id || body.adversary) {
      return res.status(400).json({
        error: 'An adversary from the attack-authoring console cannot be launched yet. '
             + 'Authoring is available now; execution is enabled after the cluster gate '
             + 'passes. Launch a scenario, a technique, a tactic or an attack chain.',
        code: 'AUTHORED_ADVERSARY_NOT_DISPATCHABLE',
      });
    }

    const engine = engines.engineFor(INCIDENT_ENGINE);

    // ── The mode gate, BEFORE a run row exists ────────────────────────────
    // An unsupported (engine, mode) pair must never reach 'scheduling': the
    // dispatch mutex is partial on exactly that status, so a row written and
    // then abandoned would hold the whole engagement until something swept it.
    const mode = String(body.mode || '');
    if (!engine.supportsMode(mode)) {
      return res.status(400).json({
        error: `Unsupported incident mode ${JSON.stringify(mode)}. `
             + 'Choose a scenario, a technique, a tactic or an attack chain.',
        code: 'UNSUPPORTED_MODE',
      });
    }

    // ── THE SEED IS THE RUN ID, so the id is minted HERE ──────────────────
    // engines/synthetic.js: compileAnswerKey "MUST BE CALLED IN THE SAME
    // STATEMENT AS THE RUN INSERT, because the seed IS the run id". The column
    // defaults to gen_random_uuid(), so the only way to satisfy that literally
    // is to mint the uuid before the statement and bind it. Compiling
    // afterwards would leave a window in which a completed run has no key and
    // the board grades every correct answer as a false positive.
    //
    // Minted BEFORE the compile as well, because a scenario is compiled from
    // this same seed: scenario-compiler.js refuses a missing runId outright for
    // the reason it states — a playbook compiled from '' describes an intrusion
    // no lane runs, and every symptom shows up in a grade rather than a log.
    const runId = crypto.randomUUID();

    // ── The scenario arm ──────────────────────────────────────────────────
    // Compiled HERE, before anything is written, so a client profile that
    // cannot produce a runnable incident is a 400 with a sentence in it rather
    // than a run row holding the engagement's dispatch mutex.
    let compiled = null;
    if (mode === 'scenario') {
      try {
        compiled = await scenarioSource.compileEngagementScenario({
          engagementId,
          scenarioId: body.scenario_id,
          runId,
          requestedSeconds: body.duration_seconds,
        });
      } catch (err) {
        // Every refusal below the compiler carries a `status` and a `code`:
        // UNKNOWN_SCENARIO, NO_SCENARIOS, SCENARIO_NOT_CHOSEN,
        // SCENARIO_UNCOMPILABLE. fail() renders all four as the 400 they are.
        return fail(res, err, 'POST / (scenario)');
      }
    }

    // Throws on anything the catalog does not offer. This is what makes a bad
    // technique id a 400 rather than a string interpolated into a root shell
    // inside a student's environment — resolveSelection REJECTS, it never
    // sanitizes. For a scenario it validates the compiler's own output on the
    // same terms, and refuses a playbook with no steps.
    let selection;
    try {
      selection = engine.resolveSelection({
        mode,
        technique_id: body.technique_id,
        tactic_id: body.tactic_id,
        chain_key: body.chain_key,
        scenario_id: compiled ? compiled.scenario.scenario_id : null,
        playbook: compiled ? compiled.attack : null,
        scenarioLabel: compiled ? compiled.scenario.name : null,
        answerKey: compiled ? compiled.answerKey : null,
        duration_seconds: body.duration_seconds,
        speed: body.speed,
      });
    } catch (err) {
      return res.status(400).json({ error: err.message, code: 'INVALID_SELECTION' });
    }
    // Enforced by cc_incident_run_duration_matches_mode too, but a 400 explains
    // it and a constraint violation does not.
    if (selection.mode === 'chain' && body.duration_seconds != null) {
      return res.status(400).json({
        error: 'Attack chains run for their own scripted length; a duration cannot be applied to them.',
        code: 'INVALID_SELECTION',
      });
    }

    // It returns {} for TACTIC mode and that is not an error: a tactic is a
    // dozen unrelated behaviours with no single honest story to script, so
    // there is no event list to predict. scoring.js reads an empty key as "not
    // auto-graded" and marks every claim 'unscored', which is honest where a
    // guessed key would mis-grade silently. For a scenario it READS the key the
    // compiler produced beside the playbook, rather than deriving a second one.
    const compiledKey = engine.compileAnswerKey(
      { run_id: runId, duration_seconds: selection.durationSeconds }, selection
    );

    let run;
    try {
      const ins = await cybercoreQuery(
        // scope_label is a SNAPSHOT of the engagement's name at launch, not a
        // join. There is no FK to ciab_engagement and there cannot be one —
        // that table lives in clinic_db and this one in cybercore_db — so a run
        // has to stay readable after the engagement it names is renamed or
        // retired. Same reasoning as cybercore_ticket.course_name.
        //
        // RETURNING is a THREE-COLUMN LIST, not *. The row now carries the
        // graded truth AND the compiled attack; pulling either back out to read
        // run_id off it would be a disclosure waiting for the first handler
        // that spreads the result.
        //
        // THE PLAYBOOK AND THE KEY GO IN THE SAME STATEMENT, and that is the
        // whole point of compiling before the INSERT. They are two halves of
        // one compilation against one seed: a row that carried the attack and
        // not the key would be an ungradable incident, and a row that carried
        // the key and not the attack could never be retried into the same one.
        //
        // scenario_ref is a SNAPSHOT, on the same terms scope_label is. Profiles
        // are editable and regenerable; a graded run must not change meaning
        // because someone reworded a threat scenario next semester.
        `INSERT INTO cybercore_incident_run
           (run_id, scope_type, scope_id, scope_label, engine, launched_by, mode,
            technique_id, tactic_id, chain_key, scenario_id, scenario_ref, playbook,
            duration_seconds, speed, catalog_version, answer_key, status)
         VALUES ($1,'engagement',$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12::jsonb,
                 $13,$14,$15,$16::jsonb,'scheduling')
         RETURNING run_id, status, created_at`,
        [
          runId, engagementId,
          engagementDisplayName(engagement) || engagement.engagement_type || null,
          INCIDENT_ENGINE, req.user.userId, selection.mode,
          selection.mode === 'technique' ? selection.arg : null,
          selection.mode === 'tactic' ? selection.arg : null,
          selection.mode === 'chain' ? selection.arg : null,
          selection.mode === 'scenario' ? selection.arg : null,
          compiled ? JSON.stringify({
            profile_id: engagement.profile_id || null,
            engagement_id: engagementId,
            scenario_id: compiled.scenario.scenario_id,
            name: compiled.scenario.name || null,
            type: compiled.scenario.type || null,
            // The instructor's own record of what the compiler could not
            // represent — an unknown target host, a phase ceded to the host
            // agent. Codes and details only; scenario-compiler.js has already
            // refused to let any detection_opportunity prose into either half.
            warnings: compiled.warnings || [],
          }) : null,
          compiled ? JSON.stringify(compiled.attack) : null,
          selection.durationSeconds,
          selection.mode === 'chain' ? selection.speed : null,
          catalogModule.CATALOG_VERSION,
          JSON.stringify(compiledKey || {}),
        ]
      );
      run = ins.rows[0];
    } catch (err) {
      // ux_cc_incident_run_dispatching, the per-scope dispatch mutex — a UNIQUE
      // index on the PAIR (scope_type, scope_id) WHERE status IN
      // ('scheduling','dispatching'). It is a CONSTRAINT VIOLATION, so without
      // this branch a second instructor pressing Launch gets a 500 naming an
      // index. It survives a restart, unlike an in-memory registry, so the
      // message says how to clear it rather than implying it expires.
      if (err && err.code === '23505') {
        return res.status(409).json({
          error: 'An incident is already being dispatched for this engagement. '
               + 'Wait for it to finish, or abort it first.',
          code: 'INCIDENT_IN_FLIGHT',
        });
      }
      throw err;
    }

    res.status(202).json({
      run_id: run.run_id,
      status: 'scheduling',
      label: selection.label,
      // The /status suffix is load-bearing: src/server.js exempts GETs matching
      // /\/status$/ from the global API rate limiter, and the console polls at
      // 2s. Instructors are not admins, so a class-length exercise would
      // otherwise exhaust their bucket and start 429ing mid-incident.
      status_url: `/api/engagements/${engagementId}/incidents/${run.run_id}/status`,
    });

    // Detached from here, exactly as cle/routes/attacks.js is. The tables are
    // the record, not this closure.
    launchInBackground({ req, run, engagement, engagementId, selection, compiled }).catch((err) => {
      console.error(`[CIAB incident-launch] run ${run.run_id} dispatch failed: ${err.message}`);
    });
    return undefined;
  } catch (error) {
    if (!res.headersSent) return fail(res, error, 'POST /');
    return undefined;
  }
});

/**
 * Resolve, record and dispatch.
 *
 * Runs AFTER the 202, so nothing here may throw into a response — every failure
 * lands on the run row instead, where the console can show it. A throw that
 * escaped would also leave the run at 'scheduling' forever, which is the one
 * status the dispatch mutex holds the engagement on.
 */
async function launchInBackground({ req, run, engagement, engagementId, selection, compiled }) {
  try {
    // ── Commit the engagement to this scenario ─────────────────────────────
    //
    // AFTER the 202 and BEFORE the dispatch, and best-effort in both
    // directions: recordTelemetryScenario never throws, it returns a reason.
    // The incident is already going out; a bookkeeping write must not be able
    // to abort a live exercise.
    //
    // WHAT IT BUYS. The benign floor on every sensor here is compiled from a
    // scenario at DEPLOY time and the intrusion from one at LAUNCH time. The
    // attack's pools are a clone of the floor's by construction — that is what
    // makes the vocabulary contract hold — so the two must name the same
    // scenario or the estate's vocabulary silently forks and one terms
    // aggregation on loggen.source.host ends the hunt. Writing the choice down
    // is what makes the NEXT deploy, add-lanes or lane retry rebuild the floor
    // this incident was written for.
    if (selection.mode === 'scenario' && compiled) {
      const recorded = await provision().recordTelemetryScenario(
        engagementId, compiled.scenario.scenario_id, { actingUserId: req.user && req.user.userId }
      );
      if (!recorded.written && recorded.reason === 'no-plan') {
        console.warn(
          `[CIAB incident-launch] engagement ${engagementId} has no telemetry plan, so scenario `
          + `${compiled.scenario.scenario_id} was not recorded; its environments keep the generic `
          + 'benign floor and the incident will name machines ordinary traffic never mentions'
        );
      }
    }

    const exclude = new Set(((req.body && req.body.exclude_lane_ids) || []).map(String));

    // The probe rung IS used here, unlike /targets: at launch a few extra guest
    // execs are worth resolving an environment that would otherwise be skipped.
    const all = await runner.resolveScopeTargets(
      scopeOf(engagementId), { probe: runner.makeGuestProbe() }
    );
    // OPT-OUT, not opt-in. An environment deployed between the instructor
    // opening the tab and pressing Launch is then included by default rather
    // than silently left out of the exercise.
    const targets = all.filter((t) => !exclude.has(String(t.lane_id)));

    for (const t of targets) {
      await cybercoreQuery(
        `INSERT INTO cybercore_incident_target
           (run_id, lane_id, user_id, student_email, node, vmid, vm_name,
            resolved_by, status, skip_reason)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
         ON CONFLICT (run_id, lane_id) DO NOTHING`,
        [run.run_id, t.lane_id, t.user_id, t.student_email, t.node, t.vmid,
          t.vm_name, t.resolved_by, t.resolvable ? 'pending' : 'skipped', t.skip_reason]
      );
    }

    // One summary row plus one per environment, sharing an event_group_id, so
    // "which students did this instructor attack" stays answerable by
    // target_user_id. Ids, names and counts only — never a credential, and
    // never the selection's compiled key.
    const eventGroupId = await audit.batch({
      req,
      action: 'incident.launched',
      source: 'ciab',
      target: { type: 'engagement', id: engagementId, label: engagementDisplayName(engagement) },
      metadata: {
        run_id: run.run_id,
        mode: selection.mode,
        selection: selection.arg,
        label: selection.label,
        duration_seconds: selection.durationSeconds,
        catalog_version: catalogModule.CATALOG_VERSION,
        loggen_ref: catalogModule.LOGGEN_REF,
        environments_targeted: targets.filter((t) => t.resolvable).length,
        environments_skipped: targets.filter((t) => !t.resolvable).length,
      },
      targetAction: 'incident.launched_environment',
      targets: targets.map((t) => ({
        id: t.user_id,
        label: t.student_email,
        status: t.resolvable ? 'success' : 'denied',
        reason: t.skip_reason || null,
        metadata: { run_id: run.run_id, lane_id: t.lane_id, vmid: t.vmid },
      })),
    }).catch(() => null);

    if (eventGroupId) {
      await cybercoreQuery(
        `UPDATE cybercore_incident_run SET event_group_id = $2 WHERE run_id = $1`,
        [run.run_id, eventGroupId]
      );
    }

    await runner.dispatchRun({ runId: run.run_id, selection, targets });
  } catch (err) {
    await cybercoreQuery(
      `UPDATE cybercore_incident_run
          SET status = 'failed', error = $2, finished_at = NOW()
        WHERE run_id = $1`,
      [run.run_id, String((err && err.message) || err).slice(0, 500)]
    ).catch(() => {});
    throw err;
  }
}

// ---------------------------------------------------------------------------
// POST /:runId/abort
// ---------------------------------------------------------------------------
router.post('/:runId/abort', instructorOnly, async (req, res) => {
  try {
    const engagement = await loadEngagement(req, res);
    if (!engagement) return notFound(res);
    const run = await getRunForEngagement(req.params.runId, engagement.engagement_id);
    if (!run) return notFound(res);

    res.status(202).json({ run_id: run.run_id, status: 'aborting' });

    // Detached, like launch: abort touches every live guest over the agent and
    // an instructor pressing Stop must not watch a request hang while it does.
    runner.abortRun(run.run_id)
      .then((r) => audit.log({
        req,
        action: 'incident.aborted',
        source: 'ciab',
        target: {
          type: 'engagement',
          id: engagement.engagement_id,
          label: engagementDisplayName(engagement),
        },
        metadata: { run_id: run.run_id, environments_signalled: r && r.aborted },
      }).catch(() => {}))
      .catch((err) => console.error(
        `[CIAB incident-launch] abort ${run.run_id} failed: ${err.message}`
      ));
    return undefined;
  } catch (error) {
    if (!res.headersSent) return fail(res, error, 'POST /:runId/abort');
    return undefined;
  }
});

// ---------------------------------------------------------------------------
// POST /:runId/retry — re-fire the environments that missed, at a fresh start
// ---------------------------------------------------------------------------
router.post('/:runId/retry', instructorOnly, async (req, res) => {
  try {
    const engagement = await loadEngagement(req, res);
    if (!engagement) return notFound(res);
    // The one reader that pulls the compiled attack back, because a scenario
    // retry has nothing else to rebuild the incident from. See its header.
    const run = await getRunForRetry(req.params.runId, engagement.engagement_id);
    if (!run) return notFound(res);

    // Rebuilt from the STORED row, not from the request: a retry must mean what
    // the original launch meant, and the body carries no selection at all.
    let selection;
    try {
      selection = engines.engineFor(run.engine || INCIDENT_ENGINE).resolveSelection(run);
    } catch (err) {
      // The catalog changed under a stored run, or the row names an engine this
      // build does not implement. Either way re-firing it would not reproduce
      // the incident the students were graded against.
      return res.status(409).json({
        error: `This incident can no longer be reproduced: ${err.message}`,
        code: 'RUN_NOT_REPRODUCIBLE',
      });
    }

    // Filtered to real uuids rather than trusted: lane_ids reaches
    // `lane_id = ANY($2::uuid[])`, and one bad element fails the whole
    // statement with a 22P02 that the caller cannot act on.
    const laneIds = Array.isArray(req.body && req.body.lane_ids) && req.body.lane_ids.length
      ? req.body.lane_ids.filter((id) => UUID_RE.test(String(id)))
      : null;

    res.status(202).json({ run_id: run.run_id, status: 'retrying' });

    runner.retryTargets({ runId: run.run_id, laneIds, selection })
      .then((r) => audit.log({
        req,
        action: 'incident.retried',
        source: 'ciab',
        target: {
          type: 'engagement',
          id: engagement.engagement_id,
          label: engagementDisplayName(engagement),
        },
        metadata: { run_id: run.run_id, environments_retried: r && r.retried },
      }).catch(() => {}))
      .catch((err) => console.error(
        `[CIAB incident-launch] retry ${run.run_id} failed: ${err.message}`
      ));
    return undefined;
  } catch (error) {
    if (!res.headersSent) return fail(res, error, 'POST /:runId/retry');
    return undefined;
  }
});

module.exports = router;
// Named export for the tests, which pin the engine key directly rather than by
// matching on a string the copy may legitimately change. Attaching it to the
// router is the house pattern — cle/routes/attacks.js does exactly this for
// recoverLegacyAttackRuns.
//
// SCENARIO_REFUSAL used to sit beside it and is gone with E7: the mode is
// implemented, so there is no refusal to pin. What replaced it is a set of
// NAMED refusals for the ways a scenario can fail to compile —
// UNKNOWN_SCENARIO, NO_SCENARIOS, SCENARIO_NOT_CHOSEN, SCENARIO_UNCOMPILABLE —
// each raised by utils/scenario-source.js with its own sentence.
module.exports.INCIDENT_ENGINE = INCIDENT_ENGINE;
