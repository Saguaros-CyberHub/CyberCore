-- 018_retire_v1_subnet_scheme.sql — v1 is gone; drop it from the CIAB vocabulary.
--
-- WHAT CHANGES: the CHECK constraint on two subnet_scheme columns —
--   ciab_engagement.subnet_scheme          (010_ciab_engagements.sql:46)
--   ciab_profile_lane_groups.subnet_scheme (006_profile_lane_deploys.sql:31)
-- Both were declared CHECK (subnet_scheme IN ('v1','v2','v3')). Both become
-- CHECK (subnet_scheme IN ('v2','v3')).
--
-- WHY. v1 was the original lane topology: gateway VMID 1691/1692/1693 chosen by
-- module, one flat 192.18.0.0/24 shared by EVERY lane, and wan0 off a per-module
-- transit /16 instead of the shared VLAN-60 transit v2 and v3 use. Nothing
-- deploys it, the application no longer carries code paths for it, and
-- front-end/migrations/038_retire_v1_subnet_scheme.sql removes it from
-- crucible_challenge. Leaving it in these two CHECKs would let a psql session or
-- a CSV import write a value the deploy path will refuse.
--
-- Neither column ever DEFAULTED to v1 — 006 and 010 both declared DEFAULT 'v2',
-- and 016 moved both to DEFAULT 'v3' — so this narrows a vocabulary that was
-- almost certainly never used, rather than taking away something in service.
--
-- ════════════════════════════════════════════════════════════════════════════
-- THIS FILE REFUSES RATHER THAN REWRITES, FOR THE REASON 016 SPELLS OUT.
-- ════════════════════════════════════════════════════════════════════════════
--
-- 016_ciab_v3_default.sql explains at length why no migration may quietly
-- UPDATE subnet_scheme on an existing row here: on THESE two tables the column
-- is not a preference, it is a description of a VXLAN block already carved in
-- Proxmox. v2 carves one VNet per lane; v3 carves two. Rewriting the value does
-- not create or remove a VNet — it only makes the row lie about what exists, and
-- the next deploy cables lanes onto bridges no node has.
--
-- The same argument applies to v1 -> v2, so this file does NOT convert anything.
-- If a v1 row somehow exists it is real, deployed topology, and an operator has
-- to decide what to do with it. The guard below aborts with the ids rather than
-- guessing. That is the difference between this file and
-- front-end/migrations/038: crucible_challenge holds challenge DEFINITIONS,
-- where an upgrade is only a statement about the next deploy, and these two
-- tables hold live reservations.
--
-- Idempotent: safe to run more than once. Auto-applied by the module loader.

BEGIN;

-- Refuse loudly if either table still describes a v1 lane. Rewriting it here
-- would desynchronise the row from the VNets actually carved in Proxmox.
DO $$
DECLARE
  eng_ids  TEXT;
  grp_ids  TEXT;
BEGIN
  SELECT string_agg(engagement_id::text, ', ') INTO eng_ids
    FROM ciab_engagement WHERE subnet_scheme = 'v1';

  SELECT string_agg(id::text, ', ') INTO grp_ids
    FROM ciab_profile_lane_groups WHERE subnet_scheme = 'v1';

  IF eng_ids IS NOT NULL OR grp_ids IS NOT NULL THEN
    RAISE EXCEPTION
      'Cannot retire v1: rows still describe v1 lanes. ciab_engagement: [%]. ciab_profile_lane_groups: [%]. '
      'These are carved VXLAN reservations, not preferences — tear the lanes down (which releases the VNets) '
      'and redeploy them as v2/v3, then re-run this migration. Do NOT UPDATE the column by hand: see the '
      'header of 016_ciab_v3_default.sql for what that breaks.',
      COALESCE(eng_ids, 'none'), COALESCE(grp_ids, 'none');
  END IF;
END$$;

-- Narrow both CHECKs, ONLY IF they still mention v1.
--
-- The "only if" is load-bearing here in a way it is not in front-end/migrations/.
-- The module loader re-runs every plugin migration on EVERY server start, and a
-- bare DROP-then-ADD would re-validate the whole table under ACCESS EXCLUSIVE on
-- each boot — 012_ciab_engagement_guards.sql calls this out by name as the
-- core-migration pattern that must not be copied into a plugin. Reading the
-- existing definition out of pg_get_constraintdef makes the second and every
-- subsequent run a no-op, and also makes the file safe on a database that
-- already has the narrowed form.
--
-- conrelid is matched as well as conname, for the reason 012 gives: Postgres has
-- no ADD CONSTRAINT IF NOT EXISTS, and an unscoped conname lookup can be
-- satisfied by a same-named constraint on a different table.
DO $$
DECLARE
  t          TEXT;
  cname      TEXT;
  current_def TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY['ciab_engagement', 'ciab_profile_lane_groups'] LOOP
    IF to_regclass(t) IS NULL THEN
      RAISE NOTICE '%: table absent, nothing to narrow.', t;
      CONTINUE;
    END IF;

    cname := t || '_subnet_scheme_check';

    SELECT pg_get_constraintdef(oid) INTO current_def
      FROM pg_constraint
     WHERE conname = cname AND conrelid = to_regclass(t);

    IF current_def IS NULL THEN
      -- No constraint at all (a hand-altered database). Add the narrow one.
      EXECUTE format('ALTER TABLE %I ADD CONSTRAINT %I CHECK (subnet_scheme IN (%L, %L))',
                     t, cname, 'v2', 'v3');
      RAISE NOTICE '%: subnet_scheme CHECK was missing; added ((v2,v3)).', t;
    ELSIF position('''v1''' IN current_def) > 0 THEN
      EXECUTE format('ALTER TABLE %I DROP CONSTRAINT %I', t, cname);
      EXECUTE format('ALTER TABLE %I ADD CONSTRAINT %I CHECK (subnet_scheme IN (%L, %L))',
                     t, cname, 'v2', 'v3');
      RAISE NOTICE '%: subnet_scheme CHECK narrowed to (v2,v3).', t;
    END IF;
    -- else: already narrowed. Touch nothing, so a restart costs no table lock.
  END LOOP;
END$$;

COMMIT;
