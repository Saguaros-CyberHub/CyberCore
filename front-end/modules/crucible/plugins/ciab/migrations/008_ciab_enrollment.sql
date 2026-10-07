-- ============================================================================
-- 008_ciab_enrollment.sql — CIAB owns its own roster
-- ----------------------------------------------------------------------------
-- Clinic-in-a-Box was open to every authenticated user: no enrollment, no
-- cohort membership, no entitlement of any kind. A valid JWT was full student
-- access to the generator, the workspace, the interview simulator and the risk
-- assessment. These tables make CIAB a course you are put on.
--
-- WHY NOT REUSE cle_course_enrollment
--   It lives in cle_db and belongs to a different plugin. Sharing it would mean
--   every CIAB instructor must also own a CLE course, and deactivating the CLE
--   plugin would revoke CIAB access for everyone. The roster machinery is
--   copied (utils/section-roster.js mirrors cle/utils/roster.js); the STORAGE
--   is ours.
--
-- THIS FILE RE-RUNS ON EVERY BOOT (src/module-loader.js:220) and the loader
--   sends it as ONE dbPool.query(sql) -- simple query protocol, so the whole
--   file is a single implicit transaction. A single failing statement rolls
--   back EVERY table here, and the loader only console.warn()s. Every statement
--   must be IF NOT EXISTS / ON CONFLICT safe, and the data backfill is guarded
--   by a marker row so it runs exactly once.
--
--   Corollary: do NOT reference a table created by 003 or later without an
--   IF to_regclass(...) IS NOT NULL guard. An unguarded reference to a table
--   that does not exist yet takes this whole migration down with it.
--
-- NO FKs TO USERS. cybercore_user is a different database; user_id columns are
-- plain UUIDs, exactly as 001_ciab_schema.sql:3-4 established.
--
-- TO RE-RUN THE BACKFILL DELIBERATELY:
--   DELETE FROM ciab_meta WHERE key = 'backfill_008';   then restart.
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- One-shot markers for data migrations in this plugin.
--
-- Without this the backfill below would resurrect, on every single restart,
-- every enrollment an instructor has since dropped -- because the evidence it
-- infers enrollment from (a profiles row, an assessment_progress row) never
-- goes away.
CREATE TABLE IF NOT EXISTS ciab_meta (
  key        TEXT PRIMARY KEY,
  value      JSONB       NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- === Sections ===============================================================
-- A section is a class: "CYBR 480 Fall 2026". Students are enrolled onto it,
-- and an active enrollment is what grants CIAB access.
--
-- instructor_id is the OWNER and is NULLABLE. NULL means platform-owned,
-- manageable by admins only -- which is what the grandfather section below
-- needs, without inventing a sentinel UUID.
CREATE TABLE IF NOT EXISTS ciab_section (
  section_id    UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name          VARCHAR(255) NOT NULL,
  code          VARCHAR(64),
  term          VARCHAR(64),
  description   TEXT,
  instructor_id UUID,
  max_students  INTEGER CHECK (max_students IS NULL OR max_students >= 1),
  status        VARCHAR(16) NOT NULL DEFAULT 'active'
                  CHECK (status IN ('active','archived')),
  -- How this row came to exist. backfill_* rows were inferred by this
  -- migration rather than created by a person, which the UI flags so an
  -- instructor knows to check them.
  source        VARCHAR(24) NOT NULL DEFAULT 'manual'
                  CHECK (source IN ('manual','backfill_group','backfill_legacy','cle_course')),
  source_ref    TEXT,
  created_by    UUID,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ciab_section_instructor ON ciab_section(instructor_id);
CREATE INDEX IF NOT EXISTS idx_ciab_section_status     ON ciab_section(status);

-- code feeds cohort usernames (cybr-480-student7). Two ACTIVE sections sharing
-- a code would generate colliding account names, and planCohort()'s
-- skip-existing logic would walk straight into the other section's accounts and
-- report them as "already provisioned".
CREATE UNIQUE INDEX IF NOT EXISTS ux_ciab_section_code
  ON ciab_section (lower(code)) WHERE code IS NOT NULL AND status = 'active';

-- Idempotent identity for the backfill, so a re-run cannot duplicate sections.
CREATE UNIQUE INDEX IF NOT EXISTS ux_ciab_section_source
  ON ciab_section (source, source_ref) WHERE source_ref IS NOT NULL;

-- === Co-instructors and TAs =================================================
-- CIAB's existing de-facto model is already many-to-many: deployed_groups.config
-- carries an instructors[] ARRAY, and getInstructorStudentIds() unions across
-- every group you appear in. A single-owner section would silently strip the
-- second instructor of a co-taught class on day one.
--
-- The owner is ALSO inserted here, so "sections I can manage" is one predicate
-- rather than an OR across two shapes.
CREATE TABLE IF NOT EXISTS ciab_section_instructor (
  section_id    UUID NOT NULL REFERENCES ciab_section(section_id) ON DELETE CASCADE,
  instructor_id UUID NOT NULL,
  staff_role    VARCHAR(16) NOT NULL DEFAULT 'instructor'
                  CHECK (staff_role IN ('instructor','ta')),
  added_by      UUID,
  added_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (section_id, instructor_id)
);

CREATE INDEX IF NOT EXISTS idx_ciab_section_staff_user
  ON ciab_section_instructor(instructor_id);

-- === Enrollments ============================================================
-- ONLY status = 'active' grants access. 'completed' is an end-of-term
-- bookkeeping state an instructor sets deliberately; if it also granted rights
-- it would be indistinguishable from 'active' and the distinction would be
-- decorative. Reinstating is one click.
CREATE TABLE IF NOT EXISTS ciab_enrollment (
  enrollment_id   UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  section_id      UUID NOT NULL REFERENCES ciab_section(section_id) ON DELETE CASCADE,
  user_id         UUID NOT NULL,
  enrollment_role VARCHAR(16) NOT NULL DEFAULT 'student'
                    CHECK (enrollment_role IN ('student','ta','guest','observer')),
  status          VARCHAR(16) NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active','completed','dropped','pending','suspended')),
  enrolled_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at    TIMESTAMPTZ,
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- DISPLAY ONLY, both of them. Authorization for credential actions MUST read
  -- cybercore_user.provisioned_via / provisioned_ref through
  -- account-provisioning.assertCourseProvisionedStudent(). These columns are
  -- written by the very instructor-facing routes that would be doing the
  -- asking, so trusting them would be circular. Same warning, same reason, as
  -- cle/migrations/005_cle_roster_import.sql:40-44.
  provisioned_via       VARCHAR(16),
  provisioned_import_id UUID,
  UNIQUE (user_id, section_id)
);

CREATE INDEX IF NOT EXISTS idx_ciab_enrollment_user    ON ciab_enrollment(user_id);
CREATE INDEX IF NOT EXISTS idx_ciab_enrollment_section ON ciab_enrollment(section_id);
CREATE INDEX IF NOT EXISTS idx_ciab_enrollment_status  ON ciab_enrollment(status);

-- The access gate's hot path is exactly "does this user have ANY active
-- enrollment", run on every /ciab page load and every /api/* call.
CREATE INDEX IF NOT EXISTS idx_ciab_enrollment_active_user
  ON ciab_enrollment(user_id) WHERE status = 'active';

-- === Roster import audit ====================================================
CREATE TABLE IF NOT EXISTS ciab_roster_import (
  import_id      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  section_id     UUID NOT NULL REFERENCES ciab_section(section_id) ON DELETE CASCADE,
  actor_id       UUID NOT NULL,
  source         VARCHAR(16) NOT NULL CHECK (source IN ('csv','cohort','cle_course')),
  total_rows     INTEGER NOT NULL DEFAULT 0,
  created_count  INTEGER NOT NULL DEFAULT 0,
  enrolled_count INTEGER NOT NULL DEFAULT 0,
  skipped_count  INTEGER NOT NULL DEFAULT 0,
  failed_count   INTEGER NOT NULL DEFAULT 0,
  notify         BOOLEAN NOT NULL DEFAULT TRUE,
  -- { line, email, action, elevated, reason } per row.
  -- NEVER a password. NEVER an activation token.
  results        JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ciab_roster_import_section
  ON ciab_roster_import(section_id);

-- ============================================================================
-- BACKFILL — runs exactly once, guarded by ciab_meta.
-- ----------------------------------------------------------------------------
-- Shipping the access gate against an empty roster locks out every existing
-- user on the next restart. This infers the roster that was already implied by
-- the data, so nobody loses access on the day enrollment ships.
--
-- It deliberately OVER-enrolls. Instructors can prune in one click; the
-- opposite failure -- locking a live class out mid-term -- is far worse.
--
-- Every id is filtered through a UUID regex before casting. deployed_groups
-- .config is free-form JSONB written by an admin route, and a single malformed
-- entry would raise 22P02 and roll back this entire migration file.
-- ============================================================================
DO $backfill$
DECLARE
  uuid_re CONSTANT text :=
    '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$';
  legacy_id UUID;
BEGIN
  IF EXISTS (SELECT 1 FROM ciab_meta WHERE key = 'backfill_008') THEN
    RETURN;
  END IF;

  -- ---- 1. One section per deployed group that actually has students --------
  -- Owner is the group's first listed instructor, falling back to whoever
  -- created it. Groups with no students are skipped: an empty section would be
  -- clutter an instructor has to archive, not a roster they lost.
  INSERT INTO ciab_section (name, instructor_id, source, source_ref, created_by, created_at)
  SELECT g.group_name, g.owner_txt::uuid, 'backfill_group', g.id::text, g.created_by, g.created_at
  FROM (
    SELECT dg.id, dg.group_name, dg.created_by, dg.created_at,
           COALESCE(NULLIF(dg.config->'instructors'->0->>'id', ''),
                    dg.created_by::text) AS owner_txt
    FROM deployed_groups dg
    WHERE jsonb_typeof(dg.config->'students') = 'array'
      AND jsonb_array_length(dg.config->'students') > 0
  ) g
  WHERE g.owner_txt ~ uuid_re
  ON CONFLICT DO NOTHING;

  -- ---- 2. Every instructor named on the group becomes section staff --------
  INSERT INTO ciab_section_instructor (section_id, instructor_id, staff_role, added_at)
  SELECT s.section_id, (e.j->>'id')::uuid, 'instructor', s.created_at
  FROM ciab_section s
  JOIN deployed_groups dg ON dg.id::text = s.source_ref
  CROSS JOIN LATERAL jsonb_array_elements(COALESCE(dg.config->'instructors', '[]'::jsonb)) AS e(j)
  WHERE s.source = 'backfill_group' AND (e.j->>'id') ~ uuid_re
  ON CONFLICT DO NOTHING;

  -- The owner too, so "sections I manage" is a single predicate over this table.
  INSERT INTO ciab_section_instructor (section_id, instructor_id, staff_role, added_at)
  SELECT s.section_id, s.instructor_id, 'instructor', s.created_at
  FROM ciab_section s
  WHERE s.source = 'backfill_group' AND s.instructor_id IS NOT NULL
  ON CONFLICT DO NOTHING;

  -- ---- 3. Group students become active enrollments -------------------------
  INSERT INTO ciab_enrollment (section_id, user_id, enrollment_role, status, enrolled_at, provisioned_via)
  SELECT s.section_id, (e.j->>'id')::uuid, 'student', 'active', s.created_at, 'group_deploy'
  FROM ciab_section s
  JOIN deployed_groups dg ON dg.id::text = s.source_ref
  CROSS JOIN LATERAL jsonb_array_elements(COALESCE(dg.config->'students', '[]'::jsonb)) AS e(j)
  WHERE s.source = 'backfill_group' AND (e.j->>'id') ~ uuid_re
  ON CONFLICT (user_id, section_id) DO NOTHING;

  -- ---- 4. Grandfather section: anyone who has ALREADY used CIAB -----------
  -- Step 1 only reaches students in a deployed_groups row, and that table is
  -- written by core's admin Group Deploy (src/routes/admin/groups.js) -- NOT by
  -- CIAB's own profile-deploy.js, which writes ciab_profile_lane_groups and
  -- never touches it. So every student minted by a CIAB profile-lane deploy,
  -- and every self-service user, is in no group at all. Without this step,
  -- turning the gate on locks out most of the existing user base.
  --
  -- instructor_id NULL => admin-managed. Admins should triage this section into
  -- real ones and archive it; the name says so.
  INSERT INTO ciab_section (name, description, instructor_id, source, source_ref, created_at)
  VALUES (
    'Existing CIAB users (pre-enrollment)',
    'Created by migration 008 so nobody who was already using Clinic-in-a-Box lost '
    || 'access the day enrollment shipped. Move these students into real sections '
    || 'and archive this one.',
    NULL, 'backfill_legacy', 'legacy_grandfather', now()
  )
  ON CONFLICT DO NOTHING;

  SELECT section_id INTO legacy_id
  FROM ciab_section
  WHERE source = 'backfill_legacy' AND source_ref = 'legacy_grandfather';

  -- Every table below is created by 001 or 002, both of which run earlier in
  -- this same boot. Adding a source from 003+ needs an
  -- IF to_regclass('public.<t>') IS NOT NULL guard -- an unguarded reference to
  -- a missing table would roll back this whole file.
  IF legacy_id IS NOT NULL THEN
    INSERT INTO ciab_enrollment (section_id, user_id, enrollment_role, status, enrolled_at)
    SELECT legacy_id, u.user_id, 'student', 'active', now()
    FROM (
      SELECT DISTINCT user_id       FROM profiles                WHERE user_id     IS NOT NULL
      UNION SELECT DISTINCT user_id      FROM assessment_progress     WHERE user_id     IS NOT NULL
      UNION SELECT DISTINCT user_id      FROM intake_form_responses   WHERE user_id     IS NOT NULL
      UNION SELECT DISTINCT user_id      FROM interview_sessions      WHERE user_id     IS NOT NULL
      UNION SELECT DISTINCT user_id      FROM nice_progress           WHERE user_id     IS NOT NULL
      UNION SELECT DISTINCT student_id   FROM instructor_assignments  WHERE student_id  IS NOT NULL
      UNION SELECT DISTINCT student_id   FROM instructor_working_sets WHERE student_id  IS NOT NULL
      UNION SELECT DISTINCT uploaded_by  FROM real_client_intakes     WHERE uploaded_by IS NOT NULL
    ) u
    ON CONFLICT (user_id, section_id) DO NOTHING;
  END IF;

  INSERT INTO ciab_meta (key, value)
  VALUES ('backfill_008', jsonb_build_object(
    'ran_at',      now(),
    'sections',    (SELECT count(*) FROM ciab_section),
    'enrollments', (SELECT count(*) FROM ciab_enrollment)
  ))
  ON CONFLICT (key) DO NOTHING;
END
$backfill$;
