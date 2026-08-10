-- ============================================================================
-- 005_cle_roster_import.sql
-- ----------------------------------------------------------------------------
-- Audit trail for roster imports and cohort generation.
--
-- An import creates accounts and sends mail on an instructor's behalf. When a
-- student later says "I never got an invitation", the only way to answer is a
-- record of what the run actually decided, row by row.
--
-- ⚠ THIS DIRECTORY RE-RUNS ON EVERY BOOT (src/module-loader.js), and failures
-- are only warned about. Every statement here must be IF NOT EXISTS.
-- ============================================================================

CREATE TABLE IF NOT EXISTS cle_roster_import (
  import_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  course_id      UUID NOT NULL REFERENCES cle_course(course_id) ON DELETE CASCADE,
  -- Cross-DB reference to cybercore_user; no FK is possible (separate database),
  -- matching how cle_course.instructor_id already works.
  actor_id       UUID NOT NULL,
  source         VARCHAR(16) NOT NULL CHECK (source IN ('csv','cohort')),
  total_rows     INTEGER NOT NULL DEFAULT 0,
  created_count  INTEGER NOT NULL DEFAULT 0,
  enrolled_count INTEGER NOT NULL DEFAULT 0,
  skipped_count  INTEGER NOT NULL DEFAULT 0,
  failed_count   INTEGER NOT NULL DEFAULT 0,
  notify         BOOLEAN NOT NULL DEFAULT TRUE,
  -- Per-row outcome: { line, email, action, elevated, reason }.
  -- NEVER a password and NEVER an activation token. The point of this column is
  -- to explain a run, and neither of those explains anything.
  results        JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_cle_roster_import_course
  ON cle_roster_import(course_id);

-- Provenance mirror on the enrollment, so rendering a roster doesn't need a
-- second cross-database hop per student just to show a badge.
--
-- ⚠ DISPLAY ONLY. Authorization MUST read cybercore_user.provisioned_via /
-- provisioned_ref instead — these columns are written by the same
-- instructor-facing routes that would be doing the asking, so an enrollment row
-- is not authority over an account. See assertCourseProvisionedStudent() in
-- src/utils/account-provisioning.js.
ALTER TABLE cle_course_enrollment
  ADD COLUMN IF NOT EXISTS provisioned_via       VARCHAR(16),
  ADD COLUMN IF NOT EXISTS provisioned_import_id UUID;
