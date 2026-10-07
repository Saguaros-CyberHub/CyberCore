/**
 * scenario-source.js — Track E, phase E7: where a compiled incident comes from
 * ============================================================================
 * ONE function answers "what does this engagement's incident look like", and
 * both halves of the exercise call it:
 *
 *   the LAUNCHER   modules/crucible/plugins/ciab/routes/incident-launch.js
 *                  takes `attack` + `answerKey` and writes them onto the run row
 *   the DEPLOYER   utils/lane-provision.js takes `floor` and publishes it onto
 *                  every sensor through blueteam-postdeploy.makeFloorSwapPostDeploy
 *
 * ── WHY THAT MATTERS MORE THAN IT LOOKS ────────────────────────────────────
 * The floor and the attack are not two features, they are two halves of one
 * claim: that no closed-vocabulary field separates the incident from ordinary
 * traffic. src/incident/scenario-compiler.js makes that true BY CONSTRUCTION —
 * the attack playbook's `pools` are a clone of the floor's, so every host,
 * account and address the intrusion can draw is one the floor also draws.
 *
 * That construction only holds if the two were compiled TOGETHER. Compile the
 * floor at deploy time from one scenario and the attack at launch time from
 * another, and the estate's vocabulary silently forks: the attack names
 * machines the floor's pools never mention, one terms aggregation on
 * `loggen.source.host` ends the hunt, and every part of it reviews as working.
 *
 * So the scenario choice is PERSISTED — `ciab_engagement.telemetry_plan.
 * scenario_id`, migration 017's column — and both callers read it from there
 * rather than each picking for themselves.
 *
 * ── WHY THE DEPLOY-TIME SEED IS THE ENGAGEMENT ID AND THAT IS FINE ─────────
 * compileScenario() requires `options.runId` because it is the seed, and at
 * deploy time no run exists. The FLOOR half does not use it: buildFloor() takes
 * no rng at all — buckets are a stable sort of the profile's own asset order,
 * accounts come from the stakeholder list, addresses from the assets' own IPs.
 * The seed only reaches the ATTACK half (entity draws and planTimeline). So a
 * floor compiled at deploy time under the engagement id is byte-identical to
 * the floor any later run compiles under its own run id, for the same scenario
 * and the same profile. Passing a stable, already-existing id is honest here in
 * a way that inventing a uuid per deploy would not be.
 *
 * ── PROFILE LAYOUTS ────────────────────────────────────────────────────────
 * Four of them reach this codebase and all four are live. The reader below is
 * the same tolerant walk utils/engagement-plan.js readClientFacts() and
 * routes/profile-deploy.js loadProfileForDeploy() already do, narrowed to the
 * three things a compile needs: assets, stakeholders, scenarios. It NEVER
 * throws on a shape it does not recognise — it returns empty lists, and the
 * caller turns that into a named refusal with a sentence in it.
 * ============================================================================
 */

'use strict';

const fs = require('fs');
const path = require('path');

const { query } = require('./db');

// Core, from a plugin: the allowed direction. Nothing under src/incident/ knows
// this file exists, and test/incident-engine-locality.test.js is the gate.
const { compileScenario } = require('../../../../../src/incident/scenario-compiler');

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const unwrap = (v) => (Array.isArray(v) ? v[0] : v);

// ---------------------------------------------------------------------------
// Reading a profile
// ---------------------------------------------------------------------------

/**
 * The `threats` bag, wherever this profile keeps it.
 *
 * canonical / real_intake  json.student_view.raw.threats.{network, threat_profile, …}
 * legacy_split             json.student_view.raw.{network, threat_profile, …}
 * flat                     the json object itself
 */
function threatsBag(json) {
  const root = isObj(unwrap(json)) ? unwrap(json) : {};
  const sv = isObj(root.student_view) ? root.student_view : {};
  const raw = isObj(sv.raw) ? sv.raw : {};
  const threats = isObj(raw.threats) ? raw.threats : {};
  if (isObj(threats.threat_profile) || isObj(threats.network) || isObj(threats.organization)) {
    return { root, sv, bag: threats };
  }
  if (isObj(raw.threat_profile) || isObj(raw.network)) return { root, sv, bag: raw };
  return { root, sv, bag: root };
}

/**
 * Every threat scenario this client's profile declares, in profile order.
 *
 * Filtered to entries that could actually be compiled — an object with an
 * `attack_path` array — because the picker this feeds must not offer a row that
 * compileScenario() would then refuse. An entry with no scenario_id is dropped
 * rather than given a generated one: the id is what gets persisted onto the
 * engagement and written to the run row, and inventing one means the same
 * scenario answers to a different name after the profile is next regenerated.
 */
function readScenarios(json) {
  const { bag } = threatsBag(json);
  const tp = isObj(bag.threat_profile) ? bag.threat_profile : {};
  const list = Array.isArray(tp.scenarios) ? tp.scenarios : [];
  return list.filter((s) => isObj(s) && s.scenario_id && Array.isArray(s.attack_path));
}

/** The estate. Same two places loadProfileForDeploy() looks, in the same order. */
function readAssets(json) {
  const { root, bag } = threatsBag(json);
  const net = isObj(bag.network) ? bag.network : {};
  if (Array.isArray(net.assets)) return net.assets;
  return Array.isArray(root.assets) ? root.assets : [];
}

/**
 * The roster.
 *
 * The same three-way fallback loadProfileForDeploy(), engagement-plan.js and
 * answer-key-risk-assessment.js already use. Three readers of one fact must not
 * disagree about where the fact lives — and here it decides the `users` pool,
 * so disagreeing means an intrusion whose account nobody in the estate has.
 */
function readStakeholders(json) {
  const { root, sv, bag } = threatsBag(json);
  const roster = (Array.isArray(sv.stakeholders) && sv.stakeholders)
    || (Array.isArray(bag.stakeholders) && bag.stakeholders)
    || (Array.isArray(root.stakeholders) && root.stakeholders)
    || [];
  return roster;
}

/**
 * What a picker needs, and NOT ONE FIELD MORE.
 *
 * `detection_opportunity` and `action` are the answer key — scenario-compiler.js
 * refuses to let either reach a playbook for exactly that reason — so they are
 * not in this projection either. This response is instructor-gated today, but
 * the shape is what keeps it safe if it is ever mounted anywhere else.
 */
function summarizeScenario(scenario) {
  const s = isObj(scenario) ? scenario : {};
  const steps = Array.isArray(s.attack_path) ? s.attack_path : [];
  const techniques = new Set();
  for (const step of steps) {
    if (isObj(step) && step.technique) techniques.add(String(step.technique).trim().toUpperCase());
  }
  return {
    scenario_id: s.scenario_id || null,
    name: s.name || null,
    type: s.type || null,
    threat_actor: s.threat_actor || null,
    initial_vector: s.initial_vector || null,
    technique_count: techniques.size,
    step_count: steps.length,
    impacted_assets: Array.isArray(s.impacted_assets) ? s.impacted_assets.slice(0, 12) : [],
  };
}

/**
 * Load one client profile's JSON off disk.
 *
 * Narrow SELECT, not `SELECT *`: this reads a table full of client prose on a
 * path that needs three fields, and a star select is how the rest of it ends up
 * in a response somebody later spreads.
 *
 * Returns null rather than throwing for every "there is nothing here" case — no
 * such profile, no json_file_path, the file is gone, the file is not JSON. The
 * caller renders a named refusal; a throw here would surface as a 500 on a
 * picker load.
 */
async function loadProfileJson(profileId) {
  if (!profileId) return null;
  let rows;
  try {
    const r = await query(
      `SELECT id, company_name, json_file_path FROM profiles WHERE id = $1`,
      [profileId]
    );
    rows = r.rows;
  } catch (err) {
    console.warn(`[CIAB ScenarioSource] profile ${profileId} unreadable: ${err.message}`);
    return null;
  }
  const row = rows[0];
  if (!row || !row.json_file_path) return null;

  // The same resolution loadProfileForDeploy() uses: the column holds a
  // repo-relative path with a leading slash.
  const resolved = path.join(process.cwd(), String(row.json_file_path).replace(/^\//, ''));
  try {
    const parsed = JSON.parse(fs.readFileSync(resolved, 'utf-8'));
    return { profile: row, json: unwrap(parsed) };
  } catch (err) {
    console.warn(`[CIAB ScenarioSource] profile ${profileId} JSON unreadable: ${err.message}`);
    return null;
  }
}

/**
 * Everything a compile needs for one engagement, plus the scenario the
 * engagement has already committed to.
 *
 * `plan_scenario_id` is `telemetry_plan.scenario_id` — read RAW off the column
 * rather than through telemetryPlanFromRow(), because that projector returns {}
 * for a plan whose `stack` is missing, and a scenario recorded on an engagement
 * whose stack was later cleared is still the scenario the lanes were built
 * around.
 *
 * @returns {Promise<null|{engagement, profileId, companyName, assets,
 *                         stakeholders, scenarios, planScenarioId}>}
 */
async function loadEngagementScenarioContext(engagementId) {
  if (!engagementId) return null;
  let engagement;
  try {
    const r = await query(
      `SELECT engagement_id, profile_id, engagement_type, telemetry_plan
         FROM ciab_engagement
        WHERE engagement_id = $1`,
      [engagementId]
    );
    engagement = r.rows[0];
  } catch (err) {
    console.warn(`[CIAB ScenarioSource] engagement ${engagementId} unreadable: ${err.message}`);
    return null;
  }
  if (!engagement) return null;

  const loaded = await loadProfileJson(engagement.profile_id);
  const json = loaded ? loaded.json : null;

  let plan = engagement.telemetry_plan;
  if (typeof plan === 'string') { try { plan = JSON.parse(plan); } catch (e) { plan = {}; } }

  return {
    engagement,
    profileId: engagement.profile_id,
    companyName: loaded ? loaded.profile.company_name : null,
    assets: json ? readAssets(json) : [],
    stakeholders: json ? readStakeholders(json) : [],
    scenarios: json ? readScenarios(json) : [],
    planScenarioId: isObj(plan) && plan.scenario_id ? String(plan.scenario_id) : null,
  };
}

/** The scenario with this id, matched case-insensitively. null when absent. */
function findScenario(scenarios, scenarioId) {
  const want = String(scenarioId == null ? '' : scenarioId).trim().toLowerCase();
  if (!want) return null;
  return (scenarios || []).find((s) => String(s.scenario_id).trim().toLowerCase() === want) || null;
}

// ---------------------------------------------------------------------------
// Compiling
// ---------------------------------------------------------------------------

/**
 * Compile ONE engagement's scenario into {attack, floor, answerKey}.
 *
 * The single door both callers go through, so the options can never diverge —
 * see this file's header for why a forked floor is a silent failure rather than
 * a visible one.
 *
 * THROWS with `status` set, so a route can render the refusal as a 4xx without
 * a second lookup table:
 *   404  the engagement, its client, or that client's profile JSON is gone
 *   400  the profile declares no scenarios, or none with this id
 *   400  whatever compileScenario() itself refuses (a scenario with no usable
 *        MITRE step, a duration shorter than the burst it has to hold)
 *
 * @param {object}  a
 * @param {string}  a.engagementId
 * @param {string} [a.scenarioId]        defaults to the engagement's stored one
 * @param {string}  a.runId              THE SEED; the engagement id at deploy time
 * @param {number} [a.requestedSeconds]  the instructor's duration
 * @param {object} [a.context]           a pre-loaded context, to avoid a re-read
 */
async function compileEngagementScenario({
  engagementId, scenarioId = null, runId, requestedSeconds = null, context = null,
}) {
  const ctx = context || await loadEngagementScenarioContext(engagementId);
  if (!ctx) {
    throw Object.assign(new Error('Not found'), { status: 404, code: 'NO_SUCH_ENGAGEMENT' });
  }

  const wanted = scenarioId || ctx.planScenarioId;
  if (!ctx.scenarios.length) {
    throw Object.assign(
      new Error(
        "This client's profile declares no threat scenarios, so there is nothing to compile an "
        + 'incident from. Choose a technique, a tactic or an attack chain instead, or regenerate '
        + "the client's threat profile."
      ),
      { status: 400, code: 'NO_SCENARIOS' }
    );
  }
  if (!wanted) {
    throw Object.assign(
      new Error('No scenario was chosen, and this engagement has none recorded.'),
      { status: 400, code: 'SCENARIO_NOT_CHOSEN' }
    );
  }

  const scenario = findScenario(ctx.scenarios, wanted);
  if (!scenario) {
    // NAMED, and it lists what does exist. A scenario id that matches nothing
    // must never become a run: the alternative is a row at 'scheduling' holding
    // the engagement's dispatch mutex while it dispatches an empty playbook.
    throw Object.assign(
      new Error(
        `No threat scenario ${JSON.stringify(String(wanted))} on this client. `
        + `This profile declares: ${ctx.scenarios.map((s) => s.scenario_id).join(', ')}.`
      ),
      { status: 400, code: 'UNKNOWN_SCENARIO' }
    );
  }

  let compiled;
  try {
    compiled = compileScenario({
      scenario,
      assets: ctx.assets,
      options: {
        runId,
        requestedSeconds: requestedSeconds || undefined,
        stakeholders: ctx.stakeholders,
      },
    });
  } catch (err) {
    // compileScenario's refusals are all instructor-actionable sentences — "this
    // scenario needs at least 900s of burst time", "has no attack_path step with
    // a usable MITRE technique". A 500 would bury them.
    throw Object.assign(err, { status: err.status || 400, code: err.code || 'SCENARIO_UNCOMPILABLE' });
  }

  return { scenario, context: ctx, ...compiled };
}

/**
 * The compiled benign FLOOR for an engagement, for the deploy-time swap.
 *
 * Best-effort BY DESIGN, and this is the one place in the chain where that is
 * the right call. Every reason a floor cannot be compiled — an offensive
 * engagement with no telemetry plan, a client whose profile has no scenarios, an
 * engagement whose scenario has not been chosen yet — is an ordinary state, not
 * a fault, and none of them should fail a deploy. Returning null composes to
 * "no floor-swap hook" (makeFloorSwapPostDeploy returns null without one), which
 * leaves the lane on the baked generic floor exactly as it was before E7.
 *
 * A floor that WAS compiled and then fails to publish is a different matter, and
 * makeFloorSwapPostDeploy throws for it — a lane keeping the generic floor when
 * the client's own was available is an exercise a single terms aggregation ends.
 *
 * @returns {Promise<{floor: object, scenarioId: string}|null>}
 */
async function floorForEngagement(engagementId, { logTag = '[CIAB ScenarioSource]' } = {}) {
  if (!engagementId) return null;
  try {
    const ctx = await loadEngagementScenarioContext(engagementId);
    if (!ctx || !ctx.planScenarioId || !ctx.scenarios.length) return null;

    const { floor, scenario, warnings } = await compileEngagementScenario({
      engagementId,
      scenarioId: ctx.planScenarioId,
      // See the header: the floor half takes no rng, so a stable existing id is
      // the honest seed here rather than a uuid invented per deploy.
      runId: String(engagementId),
      context: ctx,
    });

    for (const w of warnings || []) {
      console.warn(`${logTag} floor for ${scenario.scenario_id}: ${w.code} — ${w.detail}`);
    }
    return { floor, scenarioId: String(scenario.scenario_id) };
  } catch (err) {
    console.warn(`${logTag} no client floor for engagement ${engagementId}: ${err.message}`);
    return null;
  }
}

module.exports = {
  // Pure readers, exported so a test can hold each layout to its contract
  // without a database.
  readScenarios,
  readAssets,
  readStakeholders,
  summarizeScenario,
  findScenario,
  // The two doors.
  loadEngagementScenarioContext,
  compileEngagementScenario,
  floorForEngagement,
};
