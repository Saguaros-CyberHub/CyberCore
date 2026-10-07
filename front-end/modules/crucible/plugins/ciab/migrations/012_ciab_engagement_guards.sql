-- 012_ciab_engagement_guards.sql — Track B, phase B0: database backstops.
--
-- Every rule here is ALSO enforced in JavaScript by
-- utils/engagement-model.validateEngagementPlan, which returns a field-level
-- report the route turns into a 400. These constraints exist because the JS
-- validator is on one write path and the table will outlive it: a psql session,
-- a future route, or an import script must not be able to store an object where
-- a list belongs, or an off-vocabulary perspective.
--
-- THE JS VALIDATOR MUST RUN FIRST, ALWAYS. An off-vocabulary value that reaches
-- Postgres raises 23514, which routes/profile-deploy.js:585-591 renders as
-- `err.statusCode || 500` — an unhandled 500 instead of the 400 the route
-- already knows how to produce.
--
-- WHY THIS IS ITS OWN FILE. src/plugin-loader.js:134-147 sends each migration
-- file as ONE pool.query() — a single implicit transaction — and catches the
-- failure with nothing but console.error. If a constraint expression here is
-- wrong, only the backstops are lost; 011_ciab_engagement_model.sql's columns,
-- which B1-B6 actually need, are already committed.
--
-- WHY EVERY ADD IS GUARDED BY NAME. Postgres has no ADD CONSTRAINT IF NOT
-- EXISTS. The guard is 002_real_client_intake.sql:43-51's: check pg_constraint
-- for the constraint NAME first, so the validating table scan happens exactly
-- once and every later boot is a single catalog lookup. Do NOT copy
-- front-end/migrations/005_policy_documents.sql:8-13 or
-- 021_subnet_scheme_v3.sql:19-30, which DROP then unconditionally ADD — that
-- directory has no runner (src/server.js:623-626) and those files are
-- hand-applied once. Here that pattern would re-validate the table under ACCESS
-- EXCLUSIVE on every restart and, the first time any row disagreed, take every
-- other statement with it.
--
-- AND WHY EVERY GUARD IS SCOPED BY conrelid. A constraint name is unique per
-- TABLE, not per database: pg_constraint holds one row per constraint per
-- relation, and nothing stops a future table -- in this schema or another one
-- on the search_path -- from carrying a same-named check. An unscoped
-- `conname = '...'` lookup satisfied by that stranger would skip the ADD here
-- SILENTLY and FOREVER, leaving the column with no backstop at all and no error
-- and no log line to say so. 014_ciab_modules.sql:631-635 documents the same
-- hazard for its FK guard and scopes it the same way. The cast is safe in this
-- position: the to_regclass guard at the top of this block has already returned
-- if ciab_engagement is absent, and PL/pgSQL plans each statement lazily, so
-- 'ciab_engagement'::regclass is never resolved on a database that lacks it.
--
-- There is deliberately NO DROP CONSTRAINT in this file, NO constraint on
-- engagement_type (see 011's header), and NO lifecycle enum (011 uses a
-- nullable retired_at precisely so no future phase needs constraint surgery).
--
-- ─── ALSO DELIBERATELY ABSENT: ANYTHING THAT WOULD HAVE TO COUNT ────────────
--
-- exposure_plan carries at most ONE entry with placement 'pivot', because the
-- deployer defines exactly one dual-homed address — .240 on each segment
-- (challenge-lane-deployer.js:758-772) — so a second pivot has nowhere to land.
-- That invariant is NOT expressible here and no attempt is made to fake it:
-- counting the array elements that match a predicate requires
-- jsonb_array_elements, which is set-returning, and a CHECK constraint may not
-- contain a subquery. A containment expression that pretended to count would be
-- wrong rather than merely absent.
--
-- The same goes for "a pivot may not also be the student console" — the
-- console's identity is not in this table at all — and for "an internal
-- engagement should not place anything on the external segment", which is an
-- opinion rather than an invariant and would need exactly the DROP CONSTRAINT
-- this file forbids in order to undo. All three live in
-- engagement-model.validateExposurePlan and engagement-plan.compileEngagementPlan.
-- The JS validator can decide; the database only checks SHAPE.
--
-- There is likewise no reserved-port constraint, because there is no port.
-- Track B publishes nothing at the perimeter: the external exercise is Kali on
-- the external segment reaching a dual-homed host that is also on the internal
-- one. See 011's exposure_plan comment.
--
-- Every predicate below is satisfied by the column DEFAULTs 011 assigned, so
-- the validation pass against existing rows cannot fail.

DO $b0guards$
BEGIN
  -- 008's corollary: never reference a table a later migration created without
  -- a guard, or one missing object rolls the whole file back.
  IF to_regclass('ciab_engagement') IS NULL THEN
    RAISE NOTICE '012: ciab_engagement not present — skipping guards';
    RETURN;
  END IF;

  -- 011_ciab_engagement_model.sql sorts before this file, so on a healthy boot
  -- its columns are already there. If it failed, every statement below would
  -- reference a column that does not exist and take the whole file down; this
  -- turns that into one NOTICE and a clean retry on the next boot.
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
     WHERE table_name = 'ciab_engagement' AND column_name = 'exposure_plan'
  ) THEN
    RAISE NOTICE '012: 011 columns not present — skipping guards';
    RETURN;
  END IF;

  -- ── vocabulary ──────────────────────────────────────────────────────────
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'ciab_engagement_perspective_ck'
       AND conrelid = 'ciab_engagement'::regclass
  ) THEN
    ALTER TABLE ciab_engagement
      ADD CONSTRAINT ciab_engagement_perspective_ck
      CHECK (perspective IN ('internal','external'));
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'ciab_engagement_credential_posture_ck'
       AND conrelid = 'ciab_engagement'::regclass
  ) THEN
    ALTER TABLE ciab_engagement
      ADD CONSTRAINT ciab_engagement_credential_posture_ck
      CHECK (credential_posture IN ('none','credentialed'));
  END IF;

  -- ── document shape ──────────────────────────────────────────────────────
  -- Every list field is a JSON array and synthesis_meta is a JSON object. This
  -- is what makes a later jsonb_array_elements() read safe: a scalar or an
  -- object where an array is expected raises 22023 at READ time, in a route,
  -- rather than at write time. jsonb_typeof is immutable, so it is legal here.
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'ciab_engagement_model_shape_ck'
       AND conrelid = 'ciab_engagement'::regclass
  ) THEN
    ALTER TABLE ciab_engagement
      ADD CONSTRAINT ciab_engagement_model_shape_ck
      CHECK (
            jsonb_typeof(asset_selection)    = 'array'
        AND jsonb_typeof(scope_in)           = 'array'
        AND jsonb_typeof(scope_out)          = 'array'
        AND jsonb_typeof(allowed_techniques) = 'array'
        AND jsonb_typeof(issued_credentials) = 'array'
        AND jsonb_typeof(exposure_plan)      = 'array'
        AND jsonb_typeof(objectives)         = 'array'
        AND jsonb_typeof(authored_fields)    = 'array'
        AND jsonb_typeof(synthesis_meta)     = 'object'
      );
  END IF;

  RAISE NOTICE '012: engagement model guards present';
END
$b0guards$;
