-- ============================================================================
-- Migration 038: Retire subnet_scheme = 'v1' on crucible_challenge (cybercore_db)
-- ============================================================================
-- v1 is the original lane topology and it is gone. Nothing deploys it any more,
-- and the application no longer has code paths for it.
--
-- WHAT v1 WAS, so a reader of this file in a year knows what was removed:
--   - Gateway clone source: VMID 1691/1692/1693, chosen by MODULE
--     (cyberlabs/crucible/forge) rather than by scheme.
--   - One flat 192.18.0.0/24 lane subnet SHARED BY EVERY LANE, gateway .1.
--     Isolation between students was a firewall concern, not a topology one.
--   - wan0 came off a per-module transit /16 (cluster.networking.module_networks
--     in site.json), not the shared VLAN-60 transit every v2/v3 lane uses.
--
-- It was superseded by:
--   - v2 (migration 015, VMID 1694): a per-lane /24 on lan0, one transit VLAN.
--   - v3 (migration 021, VMID 1695): segmented ext0/int0 for DMZ topologies.
--
-- WHAT THIS MIGRATION DOES
--   1. Upgrades any remaining v1 challenge rows to v2.
--   2. Changes the column DEFAULT from 'v1' to 'v2'.
--   3. Narrows the CHECK from ('v1','v2','v3') to ('v2','v3').
--
-- WHY UPGRADING THE ROWS IS SAFE. crucible_challenge holds challenge
-- DEFINITIONS, not deployed lanes — nothing in this table describes running
-- infrastructure. Flipping a row to v2 changes which gateway template the NEXT
-- deploy of that challenge clones (1692 -> 1694) and moves its lane off the
-- shared 192.18.0.0/24 onto its own /24. Deployed lanes carry their own
-- topology in cybercore_lane.config and are not touched by this file.
--
-- A challenge whose spec hardcodes a 192.18.0.x address will need that address
-- corrected by hand — the query at the bottom finds them. Nothing here rewrites
-- a spec, because guessing at someone's lab addressing is worse than a clear
-- error at deploy time.
--
-- HAND-RUN. front-end/migrations/ has no runner:
--
--   docker compose exec -T postgres psql -U cybercore -d cybercore_db \
--     -f - < front-end/migrations/038_retire_v1_subnet_scheme.sql
--
-- Idempotent: safe to run more than once.
-- ============================================================================

-- 1 + 2 + 3, in one transaction: the CHECK must not be narrowed while a v1 row
-- still exists, and the rows must not be upgraded without the default following
-- them, or the next INSERT re-creates the problem.
BEGIN;

-- 1. Upgrade the rows FIRST. Narrowing the CHECK ahead of this would abort.
--
-- Deployed lanes are NOT affected by this UPDATE and do not need to be: a lane
-- carries its own topology at cybercore_lane.config->>'subnet_scheme', and every
-- rebuild/teardown path reads it from there, not from the challenge. Flipping
-- this column changes what the NEXT deploy of the challenge builds. The notice
-- below reports any live v1 lane anyway, because that is a real thing an
-- operator has to deal with and no constraint can see inside JSONB.
DO $$
DECLARE
  upgraded INTEGER;
  stragglers INTEGER;
BEGIN
  UPDATE crucible_challenge SET subnet_scheme = 'v2' WHERE subnet_scheme = 'v1';
  GET DIAGNOSTICS upgraded = ROW_COUNT;
  RAISE NOTICE 'crucible_challenge: % v1 challenge row(s) upgraded to v2.', upgraded;

  SELECT count(*) INTO stragglers
    FROM cybercore_lane
   WHERE config->>'subnet_scheme' = 'v1'
     AND status NOT IN ('deleted', 'error');

  IF stragglers > 0 THEN
    RAISE WARNING
      'There are still % live lane(s) whose config says subnet_scheme=v1. They are NOT touched by this '
      'migration and the application no longer has code paths for them: tear them down and redeploy. '
      'List them with the query at the bottom of this file.', stragglers;
  END IF;
END$$;

-- 2. New rows are v2 unless they say otherwise.
ALTER TABLE crucible_challenge
  ALTER COLUMN subnet_scheme SET DEFAULT 'v2';

-- 3. Narrow the vocabulary so v1 cannot come back through an API that forgot.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'crucible_challenge_subnet_scheme_check') THEN
    ALTER TABLE crucible_challenge
      DROP CONSTRAINT crucible_challenge_subnet_scheme_check;
  END IF;

  ALTER TABLE crucible_challenge
    ADD CONSTRAINT crucible_challenge_subnet_scheme_check
    CHECK (subnet_scheme IN ('v2', 'v3'));
END$$;

COMMIT;

-- ============================================================================
-- POST-RUN CHECKS — two things this file deliberately does not fix for you.
--
-- 1. LIVE v1 LANES. cybercore_lane keeps its topology in JSONB, so no CHECK can
--    reach it and nothing above rewrites it. A lane listed here was cut on the
--    shared 192.18.0.0/24 against a 1691/1692/1693 gateway; the application can
--    no longer rebuild or attach to it. Tear it down and redeploy it as v2/v3.
--
--      SELECT lane_id, user_id, status, vxlan_id, config->>'subnet_scheme' AS scheme
--        FROM cybercore_lane
--       WHERE config->>'subnet_scheme' = 'v1'
--         AND status NOT IN ('deleted', 'error')
--       ORDER BY created_at;
--
-- 2. SPECS THAT HARDCODE THE OLD SHARED SUBNET. Challenge definitions that named
--    a 192.18.0.x address explicitly (a pinned host, a DNS record, a scripted
--    target). Their row is v2 now, so the lane comes up on its own /24 and those
--    literals point at nothing. Guessing at someone's lab addressing is worse
--    than a clear failure, so edit each spec by hand.
--
--      SELECT challenge_id, challenge_key, name
--        FROM crucible_challenge
--       WHERE spec::text LIKE '%192.18.0%'
--       ORDER BY challenge_key;
-- ============================================================================
