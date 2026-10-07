-- ============================================================================
-- 006_cle_attack_console.sql
-- ----------------------------------------------------------------------------
-- Durable record of instructor-launched log-generator attack runs (CYBR 400).
--
-- An attack chain runs up to 45 minutes and the guest keeps generating whether
-- or not this app is alive. Nothing else in CyberCore models work that outlives
-- the process: deploys are fire-and-forget IIFEs whose only state is the
-- in-memory global._batchDeployProgress, which evicts after an hour and is lost
-- on restart. So this is a real table, one row per lane, and the sweeper in
-- utils/attack-worker.js reconciles it against the guests.
--
-- One row per lane rather than a JSONB array is deliberate. The JSONB shape is
-- what src/utils/script-executor.js updateScriptStatus() uses, and it is a
-- read-modify-write with no locking -- concurrent per-VM writers silently lose
-- each other's updates. A fan-out to 30 lanes is exactly the workload that hits
-- that bug, so this schema does not repeat it.
--
-- WHY HERE AND NOT front-end/migrations/: that directory has no runner. Only
-- manifest.database.migrations dirs execute (src/module-loader.js:207). A
-- 033_*.sql over there would be inert and the tables would never exist.
--
-- THIS DIRECTORY RE-RUNS ON EVERY BOOT (src/module-loader.js), and failures are
-- only warned about. Every statement here must be IF NOT EXISTS.
--
-- Postgres has no ADD CONSTRAINT IF NOT EXISTS, so the inline CHECKs below are
-- applied ONLY when the table is first created. NEVER edit this file in place
-- once it has run anywhere -- add 007 instead, or existing deployments silently
-- keep the old constraints while this file claims otherwise.
-- ============================================================================

-- One instructor click. Fans out to N cle_attack_target rows.
CREATE TABLE IF NOT EXISTS cle_attack_run (
  run_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  course_id          UUID NOT NULL REFERENCES cle_course(course_id) ON DELETE CASCADE,
  -- Cross-DB reference to cybercore_user; no FK is possible (separate database),
  -- matching how cle_course.instructor_id and cle_roster_import.actor_id work.
  launched_by        UUID NOT NULL,

  -- technique -> generate --mitre-technique T####
  -- tactic    -> generate --mitre-tactic TA####   (broader match, higher yield)
  -- chain     -> attack-chains:execute <key>      (native length, no --duration)
  mode               VARCHAR(16) NOT NULL CHECK (mode IN ('technique','tactic','chain')),
  technique_id       VARCHAR(16),
  tactic_id          VARCHAR(16),
  chain_key          VARCHAR(64),

  duration_seconds   INTEGER CHECK (duration_seconds IS NULL OR duration_seconds BETWEEN 30 AND 28800),
  speed              NUMERIC(4,2) CHECK (speed IS NULL OR speed BETWEEN 0.1 AND 20),

  -- Which loggen-catalog.js revision the instructor chose from. If the guest
  -- image is later re-baked at a different log-generator SHA, an old run still
  -- explains itself.
  catalog_version    VARCHAR(64) NOT NULL DEFAULT 'unknown',

  -- Lead time granted for dispatch before the synchronized start fires.
  lead_seconds       INTEGER,
  scheduled_start_at TIMESTAMPTZ,

  status             VARCHAR(16) NOT NULL DEFAULT 'scheduling'
    CHECK (status IN ('scheduling','dispatching','running','completed','partial','failed','aborted')),

  -- Ties back to the cybercore_audit_log rows written by audit.batch().
  event_group_id     UUID,
  error              TEXT,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  finished_at        TIMESTAMPTZ,

  -- Chain mode carries a chain_key and nothing else; technique/tactic modes
  -- never do. Encoding the product rule here means a future caller cannot
  -- quietly reintroduce "a chain, but for 10 minutes".
  CONSTRAINT cle_attack_run_chain_matches_mode
    CHECK ((mode = 'chain') = (chain_key IS NOT NULL)),
  -- Chains run their native length -- a duration is meaningless for them.
  CONSTRAINT cle_attack_run_duration_matches_mode
    CHECK ((mode = 'chain') = (duration_seconds IS NULL)),
  CONSTRAINT cle_attack_run_technique_matches_mode
    CHECK ((mode = 'technique') = (technique_id IS NOT NULL)),
  CONSTRAINT cle_attack_run_tactic_matches_mode
    CHECK ((mode = 'tactic') = (tactic_id IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS idx_cle_attack_run_course
  ON cle_attack_run (course_id, created_at DESC);

-- Durable mutex over the DISPATCH phase only.
--
-- Two dispatches at once would fight for the same guest-exec channels and blow
-- each other's synchronized-start window. Two RUNNING attacks are a legitimate
-- thing to want (layering a technique over a chain), so 'running' is excluded.
--
-- Stronger than assertNoConflictingLabOperation() in utils/vuln-lab-provision.js,
-- which guards an in-memory registry and so forgets everything on restart.
CREATE UNIQUE INDEX IF NOT EXISTS ux_cle_attack_run_dispatching
  ON cle_attack_run (course_id)
  WHERE status IN ('scheduling','dispatching');

-- One lane's copy of the run.
CREATE TABLE IF NOT EXISTS cle_attack_target (
  target_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  run_id             UUID NOT NULL REFERENCES cle_attack_run(run_id) ON DELETE CASCADE,
  -- Cross-DB: cybercore_lane.lane_id / cybercore_user.user_id.
  lane_id            UUID NOT NULL,
  user_id            UUID NOT NULL,
  -- Snapshot, not a join. A student dropped from the roster mid-semester must
  -- still render in the history of a run they were part of.
  student_email      TEXT,

  -- Resolved ONCE at dispatch and never re-derived. The sweeper and the abort
  -- path read only these, so a lane rebuilt mid-run cannot make us poke a
  -- different machine than the one we started on.
  node               VARCHAR(64),
  vmid               INTEGER,
  vm_name            TEXT,
  resolved_by        VARCHAR(24),   -- cache|template|spec_role|sole_linux|probe

  status             VARCHAR(24) NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending','skipped','dispatching','scheduled','running',
                      'completed','failed','aborted','unknown')),
  skip_reason        TEXT,

  -- Last raw line the guest wrapper wrote to its state file.
  guest_state        TEXT,
  exit_code          INTEGER,
  -- wc -l of this run's output. Turns "did anything actually happen?" into a
  -- number, which matters because --mitre-technique FILTERS the generated log
  -- stream rather than executing an attack, and some techniques yield little.
  event_count        INTEGER,
  -- Guest clock minus scheduler clock, in seconds. Surfaced per lane so a
  -- drifting box is legible instead of mysterious.
  clock_skew_s       INTEGER,
  -- True when this lane could not make the common start: slow dispatch, or a
  -- retry fired after the fact.
  late               BOOLEAN NOT NULL DEFAULT FALSE,
  attempt            INTEGER NOT NULL DEFAULT 1,
  error              TEXT,

  dispatched_at      TIMESTAMPTZ,
  started_at         TIMESTAMPTZ,
  expected_finish_at TIMESTAMPTZ,
  finished_at        TIMESTAMPTZ,
  last_checked_at    TIMESTAMPTZ,
  check_failures     INTEGER NOT NULL DEFAULT 0,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_cle_attack_target_run_lane
  ON cle_attack_target (run_id, lane_id);

-- Drives the sweeper's claim order. Partial so it stays small: terminal rows
-- are the overwhelming majority once a course has run a few attacks.
CREATE INDEX IF NOT EXISTS idx_cle_attack_target_sweep
  ON cle_attack_target (last_checked_at NULLS FIRST)
  WHERE status IN ('dispatching','scheduled','running');

CREATE INDEX IF NOT EXISTS idx_cle_attack_target_run
  ON cle_attack_target (run_id);
