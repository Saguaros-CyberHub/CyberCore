/**
 * ============================================================================
 * GOAD SIEM AGENT SCRIPTS — the vuln_scripts rows behind the two agent slugs
 * ----------------------------------------------------------------------------
 * The other half of the contract described at the top of goad-agent-attach.js.
 * That module decides WHICH MACHINES get an agent; this one makes sure the two
 * slugs it names actually EXIST as rows the deployer can select.
 *
 *   goad-agent-attach.js   elk ticked  -> every Windows roster host carries
 *                          'goad-elk-agent'; wazuh likewise.
 *   THIS FILE              'goad-elk-agent' and 'goad-wazuh-agent' are rows in
 *                          vuln_scripts, is_active, os_target 'windows', with
 *                          the PowerShell body from vuln-scripts/<slug>.ps1.
 *
 * Miss this half and the failure is silent in the exact way the whole feature
 * exists to avoid: runVulnScripts selects
 * `WHERE slug = ANY($1) AND is_active = true`, so an unseeded slug returns no
 * row, installs nothing, and logs nothing. Green deploy, empty Kibana.
 *
 * ── WHY A BOOT HOOK AND NOT A MIGRATION ─────────────────────────────────────
 *
 * front-end/migrations/ HAS NO RUNNER. A .sql file dropped there is INERT —
 * 012_seed_vuln_scripts.sql is exactly that shape and exactly that inert, and
 * it is the file whose ROW SHAPE the table below reproduces. (The plugin
 * directory modules/crucible/plugins/ciab/migrations/ *is* run, by
 * src/module-loader.js, but a plugin migration is a static .sql file too: it
 * cannot read a 185 KB PowerShell body off disk, and re-seeding an edited
 * script would mean editing SQL that already ran.)
 *
 * So this follows the ensureTicketTables() precedent (src/utils/tickets.js,
 * called from src/server.js): idempotent, run at boot, and it NEVER THROWS. A
 * DDL/DML permission problem must produce a server with no seeded agent
 * scripts, not no server. The warning is the operator's cue.
 *
 * ── WHICH DATABASE ──────────────────────────────────────────────────────────
 *
 * clinic_db, via `query` from utils/db.js — NOT cybercoreQuery. That is not a
 * preference, it is the only correct answer: challenge-lane-deployer.js reads
 * `SELECT slug, script_content, os_target, depends_on, script_args FROM
 * vuln_scripts` through that same `query`, so seeding anywhere else produces
 * rows nothing will ever read. The table itself is created by the CiAB plugin
 * migration 001_ciab_schema.sql (and by front-end/migrations/011 on older
 * hand-migrated deployments), both against clinic_db.
 *
 * ── THE BODIES LIVE IN vuln-scripts/, NOT IN THIS FILE ──────────────────────
 *
 * goad-elk-agent.ps1 is ~185 KB, most of it the base64-embedded
 * SwiftOnSecurity Sysmon config. Inlining that as a JS string literal would
 * make this module unreadable and would put PowerShell inside JS escaping
 * rules for no gain. They stay as .ps1 files, which also keeps them lintable,
 * diffable and openable in an editor that knows the language.
 *
 * OPERATIONAL CAVEAT, worth knowing before you edit one: docker-compose bind-
 * mounts ./front-end/src and ./front-end/public over the image, but NOT
 * ./front-end/vuln-scripts — that directory arrives via the Dockerfile's
 * `COPY . .`. So editing a .ps1 needs a REBUILD, not just a restart:
 *     docker compose build app && docker compose up -d app
 * Editing this file alone needs only `docker compose restart app`.
 *
 * ── WHAT AN UPSERT MAY AND MAY NOT OVERWRITE ────────────────────────────────
 *
 *   script_content etc.  OVERWRITTEN every boot. The repo file is the source of
 *                        truth; that is the whole point of "changing the script
 *                        changes the next lane".
 *   script_args          FORCED BACK TO ''. script-executor.js interpolates it
 *                        UNQUOTED into `& '<path>' <args>`, so a value there is
 *                        a command injection into every lane host that runs the
 *                        script. These installs take no arguments at all, so
 *                        the boot hook actively re-empties the field rather
 *                        than merely declining to set it.
 *   is_active            SET ON INSERT, LEFT ALONE ON CONFLICT. Re-asserting
 *                        `true` every boot would make an admin's deliberate
 *                        deactivation impossible to keep. The cost is that a
 *                        deactivated agent script installs nothing quietly —
 *                        which is a decision someone made, rather than a bug.
 *
 * ── COLUMNS ARE PROBED, NOT ASSUMED ─────────────────────────────────────────
 *
 * vuln_scripts has two definitions in this repo that do not agree: the CiAB
 * plugin schema declares script_type inline, while front-end/migrations/011
 * predates it and 014 adds it afterwards. A deployment sitting between the two
 * has no script_type column, and naming it unconditionally would turn the
 * whole seed into an error. So the insert is built from the columns the table
 * ACTUALLY has (information_schema), and anything missing is simply not set.
 * ============================================================================
 */

const fs = require('fs');
const path = require('path');
const { query } = require('./db');

/** Where the PowerShell bodies live: <repo>/front-end/vuln-scripts/. */
const SCRIPT_DIR = path.join(__dirname, '..', '..', 'vuln-scripts');

/**
 * The rows, in the shape of migrations/012_seed_vuln_scripts.sql.
 *
 * `slug` is THE CONTRACT with goad-agent-attach.js's GOAD_AGENT_SLUGS. The two
 * are pinned to each other by a source-text gate in
 * test/goad-agent-attach.test.js rather than by a require, so that renaming this
 * module can never make the shared lane deployer fail to LOAD.
 *
 * Field notes, each of which is load-bearing:
 *
 *   os_target 'windows'    routes executeScriptsOnVM to executePowerShellViaFile
 *                          (script-executor.js:683 — anything but 'linux' is
 *                          PowerShell). goad-agent-attach.js already guarantees
 *                          these slugs only reach Windows roster hosts.
 *   services_exposed []    NOT decoration. vuln-script-resolver's scoreRow
 *                          returns 0 for any row whose services_exposed does
 *                          not contain the wanted service, so an empty list is
 *                          what makes these rows unreachable by the real-client
 *                          intake synthesizer's auto-pick. An agent must be
 *                          attached deliberately by a SIEM tick, never guessed
 *                          at from a client's asset list.
 *   script_type 'baseline' They install monitoring; they inject no weakness,
 *                          and 014's backfill puts exactly this class of script
 *                          in 'baseline'. Safe despite 'baseline' being the
 *                          synthesizer's preferred type, because the empty
 *                          services_exposed above already zeroes their score.
 *   depends_on {}          DELIBERATELY EMPTY, and the reasoning is written out
 *                          in goad-agent-attach.js: the two agents are disjoint
 *                          installers with disjoint services and destinations.
 *                          sortByDependencies is a topological sort over this
 *                          field only, so an invented edge between them would
 *                          not create meaningful ordering — it would just make
 *                          one agent's failure block the other's install.
 *   script_args ''         see the header. Never anything else.
 */
const GOAD_AGENT_SCRIPT_ROWS = Object.freeze([
  Object.freeze({
    slug: 'goad-elk-agent',
    file: 'goad-elk-agent.ps1',
    name: 'GOAD ELK Agent (Sysmon + Winlogbeat)',
    description:
      'Installs Sysmon with the SwiftOnSecurity configuration (embedded, byte-identical to '
      + "GOAD's logs_windows role) and Winlogbeat 7.17.6, shipping every event channel the "
      + 'upstream template collects to elk.cybercore.lan:9200. Deliberately does not run '
      + '`winlogbeat setup` and does not reboot: the sealed ELK template already carries the '
      + 'index templates, ILM policy and dashboards. Installed per lane rather than baked into '
      + 'the shared Windows templates.',
    category: 'SIEM Agents',
    script_type: 'baseline',
    os_target: 'windows',
    difficulty: 'intermediate',
    services_exposed: [],
    depends_on: [],
    // Two downloads (Sysmon ~3 MB from Microsoft, Winlogbeat ~30 MB from
    // artifacts.elastic.co) plus two service installs. Advisory only — nothing
    // enforces it — but it should not read as though this is instant.
    estimated_runtime_sec: 420,
    script_args: '',
  }),
  Object.freeze({
    slug: 'goad-wazuh-agent',
    file: 'goad-wazuh-agent.ps1',
    name: 'GOAD Wazuh Agent',
    description:
      'Installs the Wazuh 4.8.2 agent MSI with WAZUH_MANAGER and WAZUH_REGISTRATION_SERVER set '
      + 'to wazuh.cybercore.lan, then starts WazuhSvc so the agent enrols itself. A fresh '
      + 'in-lane install is the point: an agent snapshotted after registration would bake one '
      + 'agent identity into every clone and the manager would see it flapping across every '
      + 'lane at once.',
    category: 'SIEM Agents',
    script_type: 'baseline',
    os_target: 'windows',
    difficulty: 'intermediate',
    services_exposed: [],
    depends_on: [],
    estimated_runtime_sec: 240,
    script_args: '',
  }),
]);

/**
 * Every column this hook would like to write, with the cast its value needs.
 *
 * `slug` is not here: it is always $1, it is the ON CONFLICT target, and it is
 * the one column that must never be filtered out by the probe.
 */
const CANDIDATE_COLUMNS = Object.freeze([
  { col: 'name',                  cast: '',         get: r => r.name },
  { col: 'description',           cast: '',         get: r => r.description },
  { col: 'category',              cast: '',         get: r => r.category },
  { col: 'script_type',           cast: '',         get: r => r.script_type },
  { col: 'os_target',             cast: '',         get: r => r.os_target },
  { col: 'difficulty',            cast: '',         get: r => r.difficulty },
  { col: 'script_content',        cast: '',         get: r => r.script_content },
  { col: 'services_exposed',      cast: '::jsonb',  get: r => JSON.stringify(r.services_exposed || []) },
  { col: 'depends_on',            cast: '::text[]', get: r => r.depends_on || [] },
  { col: 'estimated_runtime_sec', cast: '',         get: r => r.estimated_runtime_sec },
  { col: 'script_args',           cast: '',         get: r => r.script_args },
]);

/**
 * Read one PowerShell body off disk.
 *
 * Normalised to LF and BOM-stripped on the way in. Not cosmetic: the payload is
 * re-line-ended to CRLF by guestWriteLargeText when it is staged on the guest,
 * and a BOM would survive the round trip into a `.ps1` whose first token is
 * then not `<#`. Storing the canonical LF form means the DB row is byte-stable
 * no matter what checked the file out — a Windows clone with autocrlf on
 * produces the same row as a Linux CI box, so the UPSERT is not a no-op change
 * that rewrites both rows on every boot.
 *
 * @returns {string|null} null (with a warning) when the file is unreadable, so
 *          one missing body cannot take the other row down with it.
 */
function readScriptBody(fileName) {
  const full = path.join(SCRIPT_DIR, fileName);
  try {
    const body = fs.readFileSync(full, 'utf8')
      .replace(/^\uFEFF/, '')
      .replace(/\r\n/g, '\n');
    if (!body.trim()) {
      console.warn(`⚠️  GOAD agent script ${fileName} is empty — not seeding it`);
      return null;
    }
    return body;
  } catch (err) {
    console.warn(`⚠️  Could not read GOAD agent script ${full}: ${err.message}`);
    return null;
  }
}

/**
 * Which of CANDIDATE_COLUMNS this deployment's vuln_scripts actually has.
 *
 * @returns {Set<string>|null} null when the table is not there at all, which is
 *          a different and more actionable condition than a missing column.
 */
async function probeColumns() {
  const res = await query(
    `SELECT column_name FROM information_schema.columns
      WHERE table_name = 'vuln_scripts' AND table_schema = ANY(current_schemas(false))`
  );
  if (res.rows.length === 0) return null;
  return new Set(res.rows.map(r => r.column_name));
}

/**
 * Seed (or re-seed) the two SIEM agent scripts. Idempotent; never throws.
 *
 * Called from src/server.js alongside ensureTicketTables() and friends, and it
 * must land before any lane can deploy — a lane that deploys against an
 * unseeded slug installs no agent and says nothing about it.
 *
 * @returns {Promise<{seeded: string[], skipped: string[]}>} for callers/tests
 *          that want to assert on the outcome. Never rejects.
 */
async function ensureGoadAgentScripts() {
  const seeded = [];
  const skipped = [];
  try {
    const columns = await probeColumns();
    if (columns === null) {
      console.warn(
        '⚠️  vuln_scripts does not exist in clinic_db — GOAD SIEM agent scripts not seeded. '
        + 'A lane that ticks elk or wazuh will deploy its SIEM server with no agents reporting '
        + 'to it. Run the CiAB plugin migrations (modules/crucible/plugins/ciab/migrations/'
        + '001_ciab_schema.sql) or front-end/migrations/011_challenge_templates.sql.'
      );
      return { seeded, skipped: GOAD_AGENT_SCRIPT_ROWS.map(r => r.slug) };
    }

    const cols = CANDIDATE_COLUMNS.filter(c => columns.has(c.col));
    const missing = CANDIDATE_COLUMNS.filter(c => !columns.has(c.col)).map(c => c.col);
    if (missing.length) {
      console.warn(`⚠️  vuln_scripts is missing column(s) ${missing.join(', ')} — seeding without them`);
    }

    // is_active only on INSERT: see the header. Written as a plain literal in
    // the column list rather than as a parameter, and pointedly absent from the
    // DO UPDATE SET clause.
    const hasIsActive = columns.has('is_active');
    const insertCols = ['slug', ...cols.map(c => c.col), ...(hasIsActive ? ['is_active'] : [])];
    const insertVals = ['$1', ...cols.map((c, i) => `$${i + 2}${c.cast}`), ...(hasIsActive ? ['true'] : [])];
    const updateSet = cols.map(c => `${c.col} = EXCLUDED.${c.col}`).join(', ');

    const sql =
      `INSERT INTO vuln_scripts (${insertCols.join(', ')})\n` +
      `     VALUES (${insertVals.join(', ')})\n` +
      `ON CONFLICT (slug) DO UPDATE SET ${updateSet}`;

    for (const row of GOAD_AGENT_SCRIPT_ROWS) {
      // Per-row try/catch: one bad row must not cost the other. An elk lane and
      // a wazuh lane are independent, and so are their seeds.
      try {
        const scriptContent = readScriptBody(row.file);
        if (scriptContent === null) { skipped.push(row.slug); continue; }
        const withBody = { ...row, script_content: scriptContent };
        await query(sql, [row.slug, ...cols.map(c => c.get(withBody))]);
        seeded.push(row.slug);
      } catch (err) {
        skipped.push(row.slug);
        console.warn(`⚠️  Could not seed vuln_scripts row '${row.slug}': ${err.message}`);
      }
    }

    if (seeded.length) console.log(`✅ GOAD SIEM agent scripts ensured (${seeded.join(', ')})`);
    if (skipped.length) {
      console.warn(
        `⚠️  GOAD SIEM agent script(s) NOT seeded: ${skipped.join(', ')}. `
        + 'Any lane ticking that extension gets a SIEM with nothing reporting to it.'
      );
    }
  } catch (err) {
    // The outer net. Same terms as ensureTicketTables: a database problem here
    // must degrade to "no seeded agent scripts", never to "no server".
    console.warn('⚠️  Could not ensure GOAD SIEM agent scripts:', err.message);
  }
  return { seeded, skipped };
}

module.exports = {
  ensureGoadAgentScripts,
  GOAD_AGENT_SCRIPT_ROWS,
  SCRIPT_DIR,
};
