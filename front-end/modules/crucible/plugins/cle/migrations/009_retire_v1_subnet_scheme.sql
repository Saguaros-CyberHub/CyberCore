-- 009_retire_v1_subnet_scheme.sql — v1 is gone; drop it from cle_course's vocabulary.
--
-- WHAT CHANGES: the CHECK on cle_course.subnet_scheme, declared inline on the
-- ADD COLUMN in 002_cle_course_lab.sql:19-20 as
--   CHECK (subnet_scheme IN ('v1','v2','v3'))
-- becomes
--   CHECK (subnet_scheme IN ('v2','v3'))
--
-- WHY IT NEEDS ITS OWN FILE. 002 declares the constraint as part of an
-- ADD COLUMN IF NOT EXISTS. On any database where the column already exists that
-- whole clause is skipped, so editing 002 in place would change nothing for every
-- install that matters — and would silently diverge from what those databases
-- actually hold. The vocabulary has to be narrowed by an explicit ALTER.
--
-- WHY NARROWING IS SAFE HERE. cle_course rows are course DEFINITIONS: the row
-- records the scheme a course's lanes will be CUT at, not a description of
-- infrastructure that already exists (that lives on cybercore_lane). The column
-- has defaulted to 'v2' since it was introduced and no CLE code path ever wrote
-- 'v1' — v1 predates this plugin — so the UPDATE below is expected to touch zero
-- rows. It is here so the constraint cannot fail on a hand-edited database.
--
-- v1 was: gateway VMID 1691/1692/1693 chosen by module, one flat 192.18.0.0/24
-- shared by every lane, wan0 off a per-module transit /16. Retired across the
-- product; see front-end/migrations/038_retire_v1_subnet_scheme.sql.
--
-- Idempotent. Re-run by the module loader on EVERY server start, so the
-- constraint swap is guarded on the current definition rather than done
-- unconditionally — a bare DROP/ADD would re-validate the table under
-- ACCESS EXCLUSIVE on every boot.

BEGIN;

UPDATE cle_course SET subnet_scheme = 'v2' WHERE subnet_scheme = 'v1';

DO $$
DECLARE
  cname       TEXT;
  current_def TEXT;
BEGIN
  IF to_regclass('cle_course') IS NULL THEN
    RETURN;
  END IF;

  -- The inline CHECK from 002 is auto-named by Postgres, so find it by what it
  -- constrains rather than by a name this file cannot predict. conrelid scopes
  -- the lookup to this table: there is no ADD CONSTRAINT IF NOT EXISTS, and an
  -- unscoped conname match can be satisfied by another table's constraint.
  SELECT conname, pg_get_constraintdef(oid)
    INTO cname, current_def
    FROM pg_constraint
   WHERE conrelid = to_regclass('cle_course')
     AND contype = 'c'
     AND pg_get_constraintdef(oid) ILIKE '%subnet_scheme%'
   LIMIT 1;

  IF cname IS NULL THEN
    ALTER TABLE cle_course
      ADD CONSTRAINT cle_course_subnet_scheme_check
      CHECK (subnet_scheme IN ('v2', 'v3'));
    RAISE NOTICE 'cle_course: subnet_scheme CHECK was missing; added (v2,v3).';
  ELSIF position('''v1''' IN current_def) > 0 THEN
    EXECUTE format('ALTER TABLE cle_course DROP CONSTRAINT %I', cname);
    ALTER TABLE cle_course
      ADD CONSTRAINT cle_course_subnet_scheme_check
      CHECK (subnet_scheme IN ('v2', 'v3'));
    RAISE NOTICE 'cle_course: subnet_scheme CHECK narrowed to (v2,v3).';
  END IF;
  -- else: already narrowed. Touch nothing, so a restart costs no table lock.
END$$;

COMMIT;
