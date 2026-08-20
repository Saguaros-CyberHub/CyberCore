-- ============================================================================
-- 007_cle_course_features.sql
-- ----------------------------------------------------------------------------
-- Per-course tab visibility. Until now the course detail page rendered all six
-- tabs for every course, and the two that are course-specific said so only in a
-- comment: courses.html labels the pane "CYBR 400 Attack Console" while showing
-- it to CYBR 480 as well, where it can only ever render "No active lanes found
-- for this course."
--
-- WHY ONE JSONB COLUMN RATHER THAN A BOOLEAN PER FEATURE
--   cle_course has grown a scalar at a time (max_students, subnet_scheme,
--   provision_status). A boolean per tab makes feature #3 another migration,
--   another PATCH field and another audit entry. One blob makes it a single
--   entry in utils/course-features.js.
--
--   The read-modify-write hazard called out in 006 does NOT apply here: this
--   column is written whole, by one instructor at a time, from a form. It is
--   not fan-out state.
--
-- WHY NULLABLE WITH NO DEFAULT
--   The backfill below finds its work with WHERE features IS NULL. Given
--   DEFAULT '{}', the ALTER would fill every existing row at once, that guard
--   would match nothing, and the code-derived backfill would never run at all.
--
--   Resolution is PER KEY (utils/course-features.js): any key a row does not
--   carry falls back to that feature's code-derived default, so NULL and '{}'
--   behave alike, and a feature added later lands on existing courses with the
--   default it was designed to have rather than forced off.
--
--   Because the resolver derives from the code anyway, the app behaves
--   identically whether or not this file has run. The backfill is an
--   optimisation and a paper trail, not a correctness dependency.
--
-- THIS DIRECTORY RE-RUNS ON EVERY BOOT (src/module-loader.js:207) and failures
-- are only warned about. Every statement must be IF NOT EXISTS or otherwise
-- idempotent. NEVER edit this file in place once it has run anywhere -- add
-- 008 instead.
--
-- NOT A SECURITY BOUNDARY. Flags are still generated and planted on lane VMs by
-- the deploy path regardless of this setting, and POST /api/flags/submit
-- (src/routes/flags.js) is core, not CLE, and is not course-scoped at all. This
-- governs which tabs an instructor sees and which boards a student is offered.
-- ============================================================================

ALTER TABLE cle_course ADD COLUMN IF NOT EXISTS features JSONB;

COMMENT ON COLUMN cle_course.features IS
  'Per-course optional-tab visibility, e.g. {"flags": true, "attack_console": false}. Keys are the optional entries of COURSE_FEATURES in modules/crucible/plugins/cle/utils/course-features.js. NULL = never configured; resolveFeatures() falls back to the per-code defaults.';

-- One-time backfill from the course code, which is where this knowledge lived
-- before this column existed. Guarded on IS NULL so the every-boot re-run is a
-- no-op afterwards and can never re-enable a feature an instructor turned off.
-- Punctuation is stripped before matching so 'CYBR-480-7W1-1', 'CYBR480-1' and
-- 'cybr 480' all land the same way. utils/course-features.js normalises the
-- code identically -- these two rules MUST agree, because the resolver applies
-- the JS one to any row this backfill has not reached.
UPDATE cle_course
   SET features = jsonb_build_object(
         'flags',          regexp_replace(COALESCE(code, ''), '[^a-zA-Z0-9]', '', 'g') ILIKE 'CYBR480%',
         'attack_console', regexp_replace(COALESCE(code, ''), '[^a-zA-Z0-9]', '', 'g') ILIKE 'CYBR400%')
 WHERE features IS NULL;
