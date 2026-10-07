/**
 * blueteam-templates.js — Track E, phase E3: which images a defensive lane uses
 * ============================================================================
 * A `defensive_monitoring` engagement stands up up to three machines that are
 * not in the client's asset list at all: the synthetic-telemetry sensor, an
 * Elastic SIEM, and a Wazuh SIEM. None of them can be resolved by
 * src/utils/vm-template-resolver.js, because that resolver answers "which image
 * runs this OS?" and the question here is "which image IS the SIEM?" — an
 * identity, not a capability.
 *
 * The identity lives on the catalog row, as a `role_hints` tag. That is the
 * same mechanism CYBR 400 already uses to find its sensor
 * (cle/utils/attack-target.js loadLoggenTemplate), and this file mirrors it
 * deliberately rather than inventing a second scheme: a tag travels WITH the
 * template, so it cannot drift from the image the way a config file naming a
 * vmid can.
 *
 * ── WHY EVERY MISS IS A NAMED 400, AND NEVER A NULL ────────────────────────
 *
 * `role_hints` is a TEXT[] with no admin UI behind it — nothing in
 * public/admin.html or any route writes it, so on a fresh site it is empty on
 * every row and STAYS empty until somebody runs one UPDATE. That makes "no
 * tagged row" the NORMAL first-time state, not an exotic failure.
 *
 * If this file returned null on a miss, appendTelemetryMachines would append no
 * SIEM, the lane would deploy, every machine would come up, the console would
 * open, and the environment would be reported active — with nowhere for the
 * telemetry to go. The instructor would discover it in class. So a miss throws
 * an Error carrying `status: 400` and the exact SQL that fixes it; the deploy
 * route renders `err.statusCode || err.status` and the instructor sees the
 * remedy before a single clone happens.
 *
 * ── WHY THE PREDICATES ARE NOT ALL THE SAME ────────────────────────────────
 *
 * The sensor query is loadLoggenTemplate's, character for character in intent:
 * `'loggen' = ANY(role_hints) AND is_active`, honouring the SAME environment
 * override, CYBR400_LOGGEN_TEMPLATE_KEY. Two different queries for one image
 * would let CiAB and CYBR 400 deploy different sensors from one catalog, and
 * the incident engine's target ladder would then resolve one and probe the
 * other.
 *
 * The two SIEM queries are stricter — `template_type = 'workstation'`,
 * `status = 'active'`, `template_vmid IS NOT NULL` — because unlike the sensor
 * these machines are cloned directly by this plugin and a row missing a
 * template_vmid produces a clone of nothing, hours into a batch. The `status`
 * column has its own CHECK ('draft' | 'active' | 'retired'), so a half-registered
 * draft row is a real state a site passes through and one this must not pick up.
 * ============================================================================
 */

const { cybercoreQuery } = require('../../../../../src/utils/cybercore-db');
const { TELEMETRY_STACKS } = require('./engagement-model');

const LOG = '[CIAB BlueTeam]';

/**
 * The three roles, their env overrides, and the words a refusal uses.
 *
 * DATA, NOT THREE FUNCTIONS. The failure this file exists to prevent is one of
 * the three silently behaving differently from the others, and three copies of
 * one query is how that happens. `extraPredicate` is the only thing that
 * differs, and it is stated once per role where a reader can compare them.
 *
 * Nothing in `sql` is interpolated from a caller — every string here is a
 * module constant, and the only parameter is the env-supplied template_key.
 */
const TELEMETRY_ROLES = Object.freeze({
  sensor: Object.freeze({
    hint: 'loggen',
    // The SAME variable CYBR 400 reads. Not a new CIAB_-prefixed one: a site
    // that has already pinned its sensor must not have to pin it twice, and two
    // variables that disagree is a lane whose sensor is not the one the
    // incident engine will aim at.
    envKey: 'CYBR400_LOGGEN_TEMPLATE_KEY',
    extraPredicate: '',
    label: 'telemetry sensor',
    why: 'It runs the synthetic emitter that gives the environment its background '
       + 'volume, and the incident engine aims every run at it.',
  }),
  elk: Object.freeze({
    hint: 'elk',
    envKey: 'CIAB_ELK_TEMPLATE_KEY',
    extraPredicate: "AND template_type = 'workstation' AND status = 'active' AND template_vmid IS NOT NULL",
    label: 'Elastic SIEM',
    why: 'It is where the students actually do the work — without it the environment '
       + 'has telemetry and nothing to read it in.',
  }),
  wazuh: Object.freeze({
    hint: 'wazuh',
    envKey: 'CIAB_WAZUH_TEMPLATE_KEY',
    extraPredicate: "AND template_type = 'workstation' AND status = 'active' AND template_vmid IS NOT NULL",
    label: 'Wazuh SIEM',
    why: 'It is where the students actually do the work — without it the environment '
       + 'has telemetry and nothing to read it in.',
  }),
});

/** Trim a catalog row down to what a spec machine needs, and nothing else. */
function projectRow(row) {
  if (!row) return null;
  return {
    template_vmid: Number(row.template_vmid),
    template_node: row.node || null,
    template_key: row.template_key || null,
    os_name: row.os_name || null,
  };
}

/**
 * Build the refusal for a role with no usable catalog row.
 *
 * IT CARRIES THE FIX. An operator reading "no ELK template" has to go and find
 * out what tagging even means; an operator reading the UPDATE statement runs it.
 * `role_hints` has no admin UI, so the SQL genuinely is the remedy rather than
 * a lazy substitute for one.
 */
function missingTemplateError(roleKey, { envKeyWasSet }) {
  const role = TELEMETRY_ROLES[roleKey];
  const err = new Error(
    `This engagement needs the ${role.label}, and no template in the catalog is tagged as one. ` +
    role.why + ' ' +
    (envKeyWasSet
      ? `${role.envKey} is set, but no catalog row has that template_key` +
        (role.extraPredicate ? ', or the row it names is not an active workstation template with a VMID' : '') +
        '. Point it at a registered template, or clear it and tag the row instead: '
      : 'Tag the registered image once — role_hints is not editable from any screen, so this is a ' +
        'one-time SQL statement against cybercore_db: ') +
    `UPDATE cybercore_template_catalog SET role_hints = array_append(role_hints, '${role.hint}') ` +
    `WHERE template_key = '<the image>' AND NOT ('${role.hint}' = ANY(role_hints));`
  );
  err.status = 400;
  err.statusCode = 400;
  err.code = `TELEMETRY_TEMPLATE_MISSING_${roleKey.toUpperCase()}`;
  return err;
}

/**
 * Resolve ONE role's catalog row, or throw the named 400.
 *
 * @param {'sensor'|'elk'|'wazuh'} roleKey
 * @param {string|null} [overrideKey]  a template_key recorded on the engagement's
 *   telemetry_plan, which beats the env variable — so a lane redeployed months
 *   later lands on the image it was built against rather than on whatever is
 *   tagged today.
 */
async function loadTelemetryTemplate(roleKey, overrideKey = null) {
  const role = TELEMETRY_ROLES[roleKey];
  if (!role) throw new Error(`loadTelemetryTemplate: unknown role '${roleKey}'`);

  const key = (overrideKey && String(overrideKey).trim()) || process.env[role.envKey] || null;

  // Two shapes, one column list. The keyed query deliberately does NOT also
  // require the tag: an operator who pins a key has already made the choice
  // this file would otherwise be making for them, and forcing them to do both
  // turns an override into a second thing that can be half-done.
  const res = await cybercoreQuery(
    key
      ? `SELECT id, template_vmid, template_key, node, os_name
           FROM cybercore_template_catalog
          WHERE template_key = $1 ${role.extraPredicate}
          LIMIT 1`
      : `SELECT id, template_vmid, template_key, node, os_name
           FROM cybercore_template_catalog
          WHERE '${role.hint}' = ANY(role_hints) AND is_active ${role.extraPredicate}
          ORDER BY preferred DESC, updated_at DESC
          LIMIT 1`,
    key ? [key] : []
  );

  const row = res.rows[0] || null;
  if (!row || !Number.isFinite(Number(row.template_vmid))) {
    throw missingTemplateError(roleKey, { envKeyWasSet: !!key });
  }
  return projectRow(row);
}

/**
 * Turn an engagement's stored telemetry_plan into the `options.telemetry`
 * object profile-to-spec.js consumes.
 *
 * RESOLVES ONLY WHAT THE PLAN ASKS FOR. A 'wazuh' engagement never touches the
 * elk row, so a site running Wazuh-only lanes is never asked to tag an image it
 * does not have. That is also why the refusals are per-role rather than one
 * combined check: the message names the ONE thing that is missing.
 *
 * `sensor` is read off the plan, not re-derived, because engagement-model.js
 * validateTelemetryPlan is the single authority on that derivation and
 * telemetryPlanFromRow re-applies it on every read. A plan that reached here
 * with `sensor: true` on a wazuh stack could only have come from a caller that
 * bypassed both, and resolving one anyway would hide that.
 *
 * @param {object} plan  ciab_engagement.telemetry_plan, already projected
 * @returns {Promise<object|null>} null when the engagement carries no telemetry
 * @throws {Error & {status:400}}  when a required catalog row is missing
 */
async function resolveTelemetryTemplates(plan) {
  const stack = plan && typeof plan.stack === 'string' ? plan.stack.trim().toLowerCase() : '';
  if (!TELEMETRY_STACKS.includes(stack)) return null;

  const out = { stack, sensor: null, elk: null, wazuh: null };

  if (plan.sensor) {
    out.sensor = await loadTelemetryTemplate('sensor', plan.sensor_template_key);
  }
  if (stack === 'elastic' || stack === 'both') {
    out.elk = await loadTelemetryTemplate('elk', plan.elk_template_key);
  }
  if (stack === 'wazuh' || stack === 'both') {
    out.wazuh = await loadTelemetryTemplate('wazuh', plan.wazuh_template_key);
  }

  const placed = [['sensor', out.sensor], ['elk', out.elk], ['wazuh', out.wazuh]]
    .filter(([, v]) => v)
    .map(([k, v]) => `${k}=${v.template_vmid}`)
    .join(' ');
  console.log(`${LOG} telemetry stack '${stack}': ${placed || 'no machines'}`);

  return out;
}

module.exports = {
  TELEMETRY_ROLES,
  loadTelemetryTemplate,
  resolveTelemetryTemplates,
  // Exported so a test can assert the refusal carries the remedy without
  // needing a database to produce one.
  missingTemplateError,
};
