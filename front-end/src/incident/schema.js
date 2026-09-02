/**
 * ============================================================================
 * INCIDENT ENGINE — shared schema (cybercore_db)
 * ============================================================================
 * One incident engine, two callers. CYBR 400 (a CLE course) and CiAB (a clinic
 * engagement) launch the same intrusion machinery at the same kind of lane, and
 * the only thing that ever differed was WHICH ROW OWNS THE RUN.
 *
 * WHY THESE TABLES ARE HERE AND NOT IN A PLUGIN
 * ----------------------------------------------------------------------------
 * The predecessor is `cle_attack_run` in cle_db, whose `course_id` is a NOT NULL
 * FK to `cle_course`. That single column is what makes the table unusable for
 * CiAB: a CiAB instructor never creates a CLE course, so there is no row to
 * point at and no honest value to write. Two incident tables — one per plugin —
 * is the wrong answer, because then the student board, the worker sweep, the
 * dispatch mutex and the answer-key projection all have to exist twice and
 * diverge once.
 *
 * So: ONE scope-polymorphic table, in cybercore_db, which both plugins can
 * already reach (the CLE plugin owns cle_db, CiAB owns clinic_db, and neither
 * can see the other's).
 *
 * WHY THERE IS NO FOREIGN KEY ON THE SCOPE
 * ----------------------------------------------------------------------------
 * There is none TO BE HAD. `course_id` lives in cle_db and `engagement_id` in
 * clinic_db; this table is in cybercore_db. Postgres has no cross-database
 * references, so the pair (scope_type, scope_id) is a snapshot by construction —
 * exactly the shape `cle_attack_run.launched_by` already has, and exactly the
 * shape utils/tickets.js documents at length for its course columns.
 *
 * A run whose course or engagement is later deleted keeps its history, which is
 * the behaviour you want: "this intrusion really happened, in this lane, on this
 * date" outlives the container it was launched from.
 *
 * WHY front-end/migrations/ IS NOT WHERE THIS LIVES
 * ----------------------------------------------------------------------------
 * `front-end/migrations/` HAS NO RUNNER. A .sql file there is an operator's
 * paper trail, nothing more — see the header of utils/tickets.js, and
 * ensureTicketTables() at :165, which is the precedent this file copies
 * structurally. Plugin migrations DO run on every boot, but a plugin migration
 * runs against THAT PLUGIN'S OWN DATABASE, so a CiAB migration physically
 * cannot create a cybercore_db table.
 *
 * That leaves an idempotent boot hook, called from src/server.js. Same rules as
 * ensureAuditLog() and ensureTicketTables(): one try/catch around the lot,
 * console.warn rather than throw. A DDL-permission problem must produce a server
 * with NO INCIDENT ENGINE, not NO SERVER.
 * ============================================================================
 */

'use strict';

const { cybercoreQuery } = require('../utils/cybercore-db');

/**
 * The run's lifecycle states, written out as a literal rather than built from a
 * constant, for the same reason STATUS_CHECK in utils/tickets.js is: a literal
 * is greppable, cannot be reached by a caller-supplied value, and reads
 * identically to a human comparing it against cle_attack_run's CHECK.
 *
 * Carried over unchanged from migration 006 so a CLE run re-pointed at this
 * table in E2 keeps every status string its console already renders.
 */
const RUN_STATUS_CHECK =
  `CHECK (status IN ('scheduling','dispatching','running','completed','partial','failed','aborted'))`;

const RUN_TABLE_SQL = `
  CREATE TABLE IF NOT EXISTS cybercore_incident_run (
    run_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Scope polymorphism. No FK in EITHER direction: course_id lives in cle_db
    -- and engagement_id in clinic_db, so there is no cross-database reference to
    -- be had. See the header. 'course' and 'engagement' are the only two shapes
    -- that own lanes today; a third would be a code change anyway.
    scope_type   VARCHAR(16) NOT NULL CHECK (scope_type IN ('course','engagement')),
    scope_id     UUID NOT NULL,
    -- Snapshot, e.g. 'CYBR400-01'. Keeps the history readable after the course
    -- or engagement it names is renamed or deleted — the same reasoning as
    -- cybercore_ticket.course_name.
    scope_label  TEXT,

    -- Selects an adapter under src/incident/engines/. 'caldera' is in the CHECK
    -- FROM DAY ONE deliberately: this is a CREATE TABLE IF NOT EXISTS in a
    -- boot-rerun path, so widening a CHECK later means an ALTER ... DROP
    -- CONSTRAINT / ADD CONSTRAINT pair that has to be safe to run on every boot
    -- against a table that may or may not already carry it. Declaring the value
    -- now costs nothing and means E9 does no DDL at all.
    engine       VARCHAR(16) NOT NULL DEFAULT 'synthetic'
                 CHECK (engine IN ('synthetic','caldera')),

    -- cybercore_user.user_id. No FK: the instructor who launched a run may be
    -- deactivated later, and a run whose launcher is gone is still a real run.
    launched_by  UUID NOT NULL,

    -- 'scenario' is the CiAB arm: an incident compiled from a client profile's
    -- own threat scenarios rather than picked out of the MITRE catalog. It is in
    -- the CHECK from day one for the same reason 'caldera' is.
    mode         VARCHAR(16) NOT NULL CHECK (mode IN ('technique','tactic','chain','scenario')),
    technique_id VARCHAR(16),
    tactic_id    VARCHAR(16),
    chain_key    VARCHAR(64),
    scenario_id  VARCHAR(64),
    -- {profile_id, engagement_id, scenario_id, name} — what the scenario was
    -- WHEN IT RAN. Profiles are editable; a graded run must not change meaning
    -- because someone reworded a threat scenario afterwards.
    scenario_ref JSONB,

    -- Compiled playbook, scenario mode only. STAFF ONLY — it is the attack,
    -- verbatim, and handing it to a student ends the exercise.
    playbook     JSONB,
    -- STAFF ONLY on the same terms; the student-facing projection is what routes
    -- serve. NOT NULL DEFAULT '{}' so a reader never has to null-check it.
    answer_key   JSONB NOT NULL DEFAULT '{}'::jsonb,

    -- Bounds copied from migration 006: 30s is shorter than any offered run and
    -- 28800s is eight hours, past which a forgotten run is a burning lane.
    duration_seconds INTEGER CHECK (duration_seconds IS NULL OR duration_seconds BETWEEN 30 AND 28800),
    speed        NUMERIC(4,2) CHECK (speed IS NULL OR speed BETWEEN 0.1 AND 20),

    -- Names the log-generator build the run was produced by. Private: it is a
    -- version string, and a student who can read it can diff two runs.
    catalog_version VARCHAR(64) NOT NULL DEFAULT 'unknown',

    -- Synchronized start. Every target is told the same absolute epoch so a
    -- class of 20 lanes sees the same incident at the same wall-clock minute.
    lead_seconds INTEGER,
    scheduled_start_at TIMESTAMPTZ,

    status       VARCHAR(16) NOT NULL DEFAULT 'scheduling'
                 ${RUN_STATUS_CHECK},

    event_group_id UUID,
    error          TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at  TIMESTAMPTZ,

    -- Migration 006's four correlated CHECKs, restated with the fourth mode.
    -- Same semantics, and the second one is the non-obvious one: a CHAIN runs its
    -- own native length, so it is the only mode that FORBIDS a duration rather
    -- than requiring one. Getting that backwards produces a chain that is cut
    -- short at an arbitrary boundary, which looks like a crashed attack.
    CONSTRAINT cc_incident_run_chain_matches_mode     CHECK ((mode='chain')     = (chain_key IS NOT NULL)),
    CONSTRAINT cc_incident_run_duration_matches_mode  CHECK ((mode='chain')     = (duration_seconds IS NULL)),
    CONSTRAINT cc_incident_run_technique_matches_mode CHECK ((mode='technique') = (technique_id IS NOT NULL)),
    CONSTRAINT cc_incident_run_tactic_matches_mode    CHECK ((mode='tactic')    = (tactic_id IS NOT NULL)),
    CONSTRAINT cc_incident_run_scenario_matches_mode  CHECK ((mode='scenario')  = (scenario_id IS NOT NULL))
  )
`;

const TARGET_TABLE_SQL = `
  CREATE TABLE IF NOT EXISTS cybercore_incident_target (
    target_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id    UUID NOT NULL REFERENCES cybercore_incident_run(run_id) ON DELETE CASCADE,

    -- lane_id and user_id ARE in this database, and they still have no FK —
    -- deliberately, and for a different reason than the scope columns above.
    -- teardownLanes() deletes cybercore_lane rows as routine housekeeping, and a
    -- CASCADE from there would erase the record of a run that really happened.
    -- A RESTRICT would be worse: it would block teardown, a hot path.
    -- So: snapshots, exactly like cybercore_ticket.lane_id, with student_email
    -- carrying the part that stays meaningful once the lane is gone.
    lane_id UUID NOT NULL,
    user_id UUID NOT NULL,
    student_email TEXT,

    node VARCHAR(64),
    vmid INTEGER,
    vm_name TEXT,
    -- Which rung of the resolution ladder answered. Diagnostic: a lane resolving
    -- by 'probe' every run means the cheap rungs are silently missing.
    resolved_by VARCHAR(24),        -- cache|template|spec_role|sole_linux|probe|postdeploy

    status VARCHAR(24) NOT NULL DEFAULT 'pending'
      CHECK (status IN ('pending','skipped','dispatching','scheduled','running',
                        'completed','failed','aborted','unknown')),
    skip_reason TEXT,
    guest_state TEXT,
    exit_code   INTEGER,
    event_count INTEGER,
    -- Proxmox only syncs a guest's RTC on resume, so a cloned lane's clock can
    -- be hours out. Recorded rather than corrected: it is the first thing to
    -- check when a run generated events nobody can find.
    clock_skew_s INTEGER,
    late BOOLEAN NOT NULL DEFAULT FALSE,
    attempt INTEGER NOT NULL DEFAULT 1,
    error TEXT,

    -- Caldera operation and agent ids. NULL for the synthetic engine. Present
    -- from day one so E9 adds an adapter file and nothing else — no DDL, no
    -- migration, no boot-rerun risk.
    engine_ref JSONB,

    dispatched_at      TIMESTAMPTZ,
    started_at         TIMESTAMPTZ,
    expected_finish_at TIMESTAMPTZ,
    finished_at        TIMESTAMPTZ,
    last_checked_at    TIMESTAMPTZ,
    check_failures INTEGER NOT NULL DEFAULT 0,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )
`;

const INCIDENT_INDEX_SQL = [
  // The console's history list: "runs for this scope, newest first".
  `CREATE INDEX IF NOT EXISTS idx_cc_incident_run_scope
     ON cybercore_incident_run (scope_type, scope_id, created_at DESC)`,

  // THE DISPATCH MUTEX. Widened from ux_cle_attack_run_dispatching's bare
  // (course_id), and the widening is not cosmetic:
  //
  //   It MUST be the PAIR (scope_type, scope_id), never scope_id alone. A course
  //   id and an engagement id are both UUIDs drawn from the same space, and an
  //   index keyed on the bare value would eventually — rarely, unreproducibly —
  //   refuse an engagement's dispatch because some unrelated course happened to
  //   be mid-dispatch under a colliding id. That is a bug nobody would ever
  //   diagnose from the symptom ("launch button did nothing, once, in March").
  //
  // Partial on the two non-terminal pre-run states, so a scope may hold any
  // number of completed runs and at most one in flight.
  `CREATE UNIQUE INDEX IF NOT EXISTS ux_cc_incident_run_dispatching
     ON cybercore_incident_run (scope_type, scope_id)
   WHERE status IN ('scheduling','dispatching')`,

  // One target row per lane per run. This is what makes a retry an UPDATE
  // rather than a second row racing the first.
  `CREATE UNIQUE INDEX IF NOT EXISTS ux_cc_incident_target_run_lane
     ON cybercore_incident_target (run_id, lane_id)`,

  // The worker's claim query. NULLS FIRST because a never-checked target is the
  // most urgent one, and partial so the index stays the size of the in-flight
  // set rather than of all history.
  `CREATE INDEX IF NOT EXISTS idx_cc_incident_target_sweep
     ON cybercore_incident_target (last_checked_at NULLS FIRST)
   WHERE status IN ('dispatching','scheduled','running')`,
];

/**
 * Idempotent boot DDL. Structurally a copy of ensureTicketTables()
 * (utils/tickets.js:165), which is itself a copy of ensureAuditLog().
 *
 * ONE try/catch around the lot, warning rather than throwing. If the app role
 * cannot run DDL the right outcome is a server that starts with no incident
 * engine, not a server that will not start — the Attack Console degrades, every
 * other page is unaffected, and the warning is the operator's cue.
 *
 * Every statement is natively re-runnable (CREATE ... IF NOT EXISTS), so boot 2
 * is silent. Nothing here ALTERs, on purpose: an ALTER in a boot-rerun path is
 * the one genuinely unsafe operation available, because it has to be correct
 * against both the pre-change and post-change shape forever.
 */
async function ensureIncidentTables() {
  try {
    await cybercoreQuery(RUN_TABLE_SQL);
    await cybercoreQuery(TARGET_TABLE_SQL);
    for (const sql of INCIDENT_INDEX_SQL) await cybercoreQuery(sql);
    console.log('✅ Incident engine tables ensured');
  } catch (err) {
    console.warn('⚠️  Could not ensure incident engine tables:', err.message);
  }
}

module.exports = {
  ensureIncidentTables,
  // Exported for the schema tests, which pin the CHECK lists and the mutex key
  // so a later edit cannot quietly narrow either.
  RUN_TABLE_SQL,
  TARGET_TABLE_SQL,
  INCIDENT_INDEX_SQL,
  RUN_STATUS_CHECK,
};
