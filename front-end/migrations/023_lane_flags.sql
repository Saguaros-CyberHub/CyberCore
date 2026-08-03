-- ============================================================================
-- Migration 023: HTB-style capture flags (cybercore_db)
-- ============================================================================
-- Every target VM in a student lane carries two flags: user (readable once
-- the student has any shell as the low-priv account) and `root` (readable only
-- after privilege escalation). Values are generated in Node with
-- crypto.randomBytes(16) and written to the guest afterwards — the guest never
-- generates anything, so the database is always authoritative and a re-run of
-- the planting step can never desync disk from DB.
--
-- Flag values are stored in plaintext because instructors must be able to see
-- the correct value for a given student lane. Submission comparison still
-- goes through crypto.timingSafeEqual. Anyone with read access to cybercore_db
-- can read every flag — acceptable for a course range, not for a public CTF.
--
-- Cleanup: cybercore_lane_flag CASCADEs off cybercore_lane, which BOTH teardown
-- paths hard-delete (routes/admin/lanes.js DELETE and lane-deployer.js
-- teardownLanes), so flags are removed for free. cybercore_flag_submission
-- deliberately has NO foreign key — the gradebook has to outlive the lanes.
--
-- Run against the CyberCore database:
--   psql -h <host> -U cactus-admin -d <cybercore_db> -f migrations/023_lane_flags.sql
-- ============================================================================

CREATE TABLE IF NOT EXISTS cybercore_lane_flag (
  flag_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  lane_id      UUID NOT NULL REFERENCES cybercore_lane(lane_id) ON DELETE CASCADE,
  user_id      UUID NOT NULL,
  vm_name      TEXT NOT NULL,
  flag_type    TEXT NOT NULL CHECK (flag_type IN ('user', 'root')),
  flag_value   TEXT NOT NULL,
  plant_status TEXT NOT NULL DEFAULT 'pending'
               CHECK (plant_status IN ('pending', 'planted', 'failed')),
  plant_error  TEXT,
  planted_at   TIMESTAMPTZ,
  captured_at  TIMESTAMPTZ,
  points       INTEGER NOT NULL DEFAULT 0,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (lane_id, vm_name, flag_type)
);

-- Globally unique so a submission can be resolved to exactly one flag row.
-- This is what lets the submit endpoint tell "wrong value" apart from
-- "right value, wrong student" without trusting the client.
CREATE UNIQUE INDEX IF NOT EXISTS ux_cybercore_lane_flag_value
  ON cybercore_lane_flag(flag_value);

CREATE INDEX IF NOT EXISTS idx_cybercore_lane_flag_user
  ON cybercore_lane_flag(user_id);

CREATE INDEX IF NOT EXISTS idx_cybercore_lane_flag_lane
  ON cybercore_lane_flag(lane_id);

COMMENT ON TABLE cybercore_lane_flag IS
  'Per-lane, per-VM user/root capture flags. One row per (lane, vm, type).';
COMMENT ON COLUMN cybercore_lane_flag.plant_status IS
  'Whether the value was successfully written into the guest. failed => the student cannot possibly capture it; surfaced on the instructor dashboard.';
COMMENT ON COLUMN cybercore_lane_flag.captured_at IS
  'First correct submission by the owning student. NULL = not yet captured.';


-- ============================================================================
-- Submission audit log
-- ============================================================================
-- Every attempt, right or wrong. `foreign_lane` means the submitted value is a
-- real flag belonging to a DIFFERENT student lane. The submitting student
-- still sees a plain "Incorrect Flag", but the instructor sees the sharing.
--
-- No FK to cybercore_lane or cybercore_lane_flag: tearing down a class must not
-- erase the record of who captured what.
CREATE TABLE IF NOT EXISTS cybercore_flag_submission (
  submission_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         UUID NOT NULL,
  lane_id         UUID,
  submitted_value TEXT NOT NULL,
  result          TEXT NOT NULL
                  CHECK (result IN ('correct', 'incorrect', 'foreign_lane', 'duplicate')),
  vm_name         TEXT,
  flag_type       TEXT,
  ip_address      INET,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cybercore_flag_submission_user
  ON cybercore_flag_submission(user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_cybercore_flag_submission_result
  ON cybercore_flag_submission(result)
  WHERE result = 'foreign_lane';

COMMENT ON TABLE cybercore_flag_submission IS
  'Append-only audit of every flag submission attempt. Survives lane teardown by design.';
COMMENT ON COLUMN cybercore_flag_submission.result IS
  'correct | duplicate (own flag, already captured) | foreign_lane (another student''s real flag) | incorrect. foreign_lane and incorrect are indistinguishable to the student.';
