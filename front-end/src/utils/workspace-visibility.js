/**
 * ============================================================================
 * WORKSPACE VISIBILITY — which lane VMs a student is not supposed to see
 * ============================================================================
 * A lane is not always "the student's machine". Since lane-deployer.js grew
 * multiple slots, a single lane can hold a machine the student works ON (slot 0
 * — Windows, ELK, Kali) and a machine the exercise merely NEEDS: the CYBR 400
 * synthetic-telemetry sensor, which runs log-generator and is the thing the
 * incident engine aims every attack run at.
 *
 * Both are registered identically by registerWorkspaceVm (vm_category
 * 'lane_vm', an allocation to the student), so both land on the student's home
 * page as a card with an Open Console button. Students click it — it is right
 * there next to their real workstation, and its name only differs by a `-ws1`
 * suffix — and then either log in and disturb the emitter that their whole
 * detection exercise depends on, or sit on a console that was never meant for
 * them wondering why nothing looks like the lab handout.
 *
 * ── WHAT DECIDES IT ────────────────────────────────────────────────────────
 *
 * Three inputs, checked in this order:
 *
 *   1. `cybercore_resource.metadata.student_hidden` — a per-VM override, the
 *      string 'true' or 'false'. An instructor's explicit answer for ONE
 *      machine, and it wins in both directions.
 *   2. the deployed template's `role_hints`, via
 *      `cybercore_resource.metadata.catalog_template_id` → the catalog row.
 *      Anything tagged with a hint in HIDDEN_ROLE_HINTS is infrastructure.
 *   3. the template_key named by CYBR400_LOGGEN_TEMPLATE_KEY, if that is set.
 *
 * Rules 2 and 3 key on the SAME two things src/incident/target.js
 * loadLoggenTemplate keys on, in the same order, because the question is
 * identical: "which image is the sensor?". Hiding by hostname suffix (`-ws1`)
 * or by slot number would be a third, independent answer to that question, free
 * to drift from the two that already agree — and slot order is not fixed
 * anyway.
 *
 * Rule 3 is not redundant. `role_hints` has NO admin UI: nothing in
 * public/admin.html or any route writes it, so on a site that has never run the
 * tagging UPDATE it is empty on every row (blueteam-templates.js says so at
 * length). Such a site pins its sensor with the env var instead — and would
 * then have a perfectly identified sensor that this file could not see.
 *
 * ── WHAT THIS IS AND IS NOT ────────────────────────────────────────────────
 *
 * It is an AUTHORIZATION predicate, not a UI preference. The same expression
 * filters the workspace list (routes/guac-sessions.js GET /vms), the console
 * launch (POST /vms/:vmId/guac-session) and the credential read
 * (utils/lane-credentials.js). Filtering only the list would leave a student
 * who kept a vmId — from a bookmark, or from before this landed — able to open
 * the console anyway, which is not hiding, it is decluttering.
 *
 * It is NOT a claim that the machine is unreachable. The sensor still sits on
 * the lane LAN, and a student on their own workstation can still reach it by
 * IP; that is the exercise. This governs the platform's own doors.
 *
 * Instructors and admins are never filtered — they own these machines and have
 * to be able to open one when the emitter stops. GET /vms hands them a
 * `studentHidden` flag per card instead, so the UI can say so out loud.
 *
 * NO QUERIES HERE. This is the vocabulary — two SQL fragments and a list —
 * shared by the route and the credential reader so the three doors cannot
 * disagree about which machines are behind them.
 * ============================================================================
 */

'use strict';

/** The metadata key carrying a per-VM override. Values: 'true' | 'false'. */
const HIDDEN_METADATA_KEY = 'student_hidden';

/**
 * Template role hints that mark a deployed machine as lab infrastructure.
 *
 * Default: the CYBR 400 / CiAB telemetry sensor, the machine this module was
 * written for. NOT the SIEMs — 'elk' and 'wazuh' are where students do the
 * work, and hiding those would hide the lab itself.
 *
 * Override with WORKSPACE_HIDDEN_ROLE_HINTS (comma-separated). Setting it to an
 * empty string turns the automatic rule off entirely and leaves only the
 * per-VM metadata override, which is the escape hatch for a site that tags its
 * catalog differently.
 */
const HIDDEN_ROLE_HINTS = Object.freeze(
  process.env.WORKSPACE_HIDDEN_ROLE_HINTS === undefined
    ? ['loggen']
    : process.env.WORKSPACE_HIDDEN_ROLE_HINTS
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean)
);

/**
 * Template keys that mark a deployed machine as lab infrastructure, for a site
 * that pins its sensor by name rather than by tag.
 *
 * The variable is CYBR400_LOGGEN_TEMPLATE_KEY, not a new one, and that is the
 * point: it is what src/incident/target.js and ciab/utils/blueteam-templates.js
 * already read. A second variable meaning almost the same thing is how the
 * incident engine ends up aiming at one image while this file hides another.
 */
const HIDDEN_TEMPLATE_KEYS = Object.freeze(
  [process.env.CYBR400_LOGGEN_TEMPLATE_KEY].map((s) => (s || '').trim()).filter(Boolean)
);

/**
 * The two binds studentHiddenSql consumes, in the order it consumes them.
 *
 * Callers spread this at the tail of their parameter list rather than naming
 * the arrays themselves — the expression uses two consecutive placeholders, and
 * a caller passing one value for two `$n`s is a runtime bind error on a path
 * that only students take.
 */
function hiddenBindValues() {
  return [HIDDEN_ROLE_HINTS, HIDDEN_TEMPLATE_KEYS];
}

/**
 * The same decision as studentHiddenSql's rules 2 and 3, in JavaScript, over a
 * catalog row that is already in hand.
 *
 * The deploy path needs this BEFORE any resource row exists, to decide whether
 * to grant the owner READ on the machine's Guacamole connection. Withholding
 * that grant is not belt-and-braces: the console-launch route hands the browser
 * a scoped per-user Guacamole token, and a student holding one can open /guac
 * directly and see every connection their Guac account has READ on. Filtering
 * CyberCore's three doors while leaving the grant in place hides the machine
 * from the app and not from the student.
 *
 * Rule 1 (the per-VM metadata override) is deliberately absent: it lives on a
 * resource row that does not exist yet, and an operator setting it later is
 * changing what CyberCore shows, not re-running the deploy.
 *
 * @param {{role_hints?: string[], template_key?: string}|null} row a
 *   cybercore_template_catalog row, or anything shaped like one. A row with no
 *   `role_hints` field answers FALSE — callers that cannot see the column must
 *   look it up rather than trusting the absence (see lane-deployer.js).
 */
function isHiddenTemplateRow(row) {
  if (!row) return false;
  const hints = Array.isArray(row.role_hints) ? row.role_hints : [];
  if (hints.some((h) => HIDDEN_ROLE_HINTS.includes(h))) return true;
  return !!row.template_key && HIDDEN_TEMPLATE_KEYS.includes(row.template_key);
}

/** Reject anything that is not a plain SQL identifier before interpolating it. */
function checkAlias(alias, what) {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(String(alias))) {
    throw new Error(`workspace-visibility: refusing to build SQL from ${what} ${JSON.stringify(alias)}`);
  }
  return alias;
}

/**
 * The LEFT JOIN that rule 2 needs, for a query that does not already have one.
 *
 * LEFT, never INNER: `catalog_template_id` is absent on rows written by
 * utils/challenge-lane-deployer.js and on anything deployed before that field
 * existed, and an INNER JOIN would drop those machines out of the student's
 * list altogether — hiding far more than intended, silently.
 *
 * routes/guac-sessions.js GET /vms already joins the catalog as `tc` for its
 * OS tagging (DISPLAY_JOINS); that query passes the existing alias to
 * studentHiddenSql rather than joining the table twice.
 */
function catalogJoinSql({ resource = 'r', catalog = 'tc' } = {}) {
  checkAlias(resource, 'resource alias');
  checkAlias(catalog, 'catalog alias');
  return `LEFT JOIN cybercore_template_catalog ${catalog}
    ON ${catalog}.id::text = ${resource}.metadata->>'catalog_template_id'`;
}

/**
 * A boolean expression: TRUE when this VM must not be shown to its student.
 *
 * @param {object}        opts
 * @param {number|string} opts.param    1-based index of the FIRST of the two
 *                                      consecutive placeholders this consumes:
 *                                      $n is the role-hint text[], $n+1 the
 *                                      template-key text[]. REQUIRED — neither
 *                                      list is ever interpolated. Bind them
 *                                      with hiddenBindValues().
 * @param {string}        [opts.resource='r']  alias of cybercore_resource
 * @param {string}        [opts.catalog='tc']  alias of cybercore_template_catalog
 *
 * The metadata override is compared as TEXT rather than cast to boolean:
 * `(metadata->>'student_hidden')::boolean` throws 22P02 on any value that is
 * not boolean-ish, and metadata is free-form JSONB that nothing validates. One
 * hand-edited row reading "yes" would turn every workspace list on the site
 * into a 500. An unrecognised value falls through to the role-hint rule, which
 * is the behaviour of a row that never set the key at all.
 *
 * COALESCE around the overlap is required by the LEFT JOIN above: `NULL && ...`
 * is NULL, `NOT NULL` is NULL, and a WHERE that is NULL drops the row — so
 * without it every VM whose catalog row is missing would vanish from the
 * student's list, which is the exact opposite of failing open.
 */
function studentHiddenSql({ param, resource = 'r', catalog = 'tc' } = {}) {
  checkAlias(resource, 'resource alias');
  checkAlias(catalog, 'catalog alias');
  const idx = String(param).replace(/^\$/, '');
  if (!/^[1-9][0-9]*$/.test(idx)) {
    throw new Error(`workspace-visibility: bad bind index ${JSON.stringify(param)} for the role-hint list`);
  }
  const keyIdx = Number(idx) + 1;
  return `(CASE
    WHEN ${resource}.metadata->>'${HIDDEN_METADATA_KEY}' = 'true'  THEN TRUE
    WHEN ${resource}.metadata->>'${HIDDEN_METADATA_KEY}' = 'false' THEN FALSE
    ELSE COALESCE(${catalog}.role_hints && $${idx}::text[], FALSE)
      OR COALESCE(${catalog}.template_key = ANY($${keyIdx}::text[]), FALSE)
  END)`;
}

module.exports = {
  HIDDEN_METADATA_KEY,
  HIDDEN_ROLE_HINTS,
  HIDDEN_TEMPLATE_KEYS,
  hiddenBindValues,
  isHiddenTemplateRow,
  catalogJoinSql,
  studentHiddenSql,
};
