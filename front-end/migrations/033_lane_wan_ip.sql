-- ============================================================================
-- Migration 033: cybercore_lane.gateway_wan_ip + uniqueness + lease history
-- ============================================================================
-- Until now a lane's WAN transit address lived only in config->>'gateway_wan_ip',
-- and only lane-deployer.js ever wrote it (challenge-lane-deployer and the CIAB
-- profile-deploy path never did, so roughly half the live lanes have no recorded
-- address at all). It was DERIVED as base + 10 + (vxlan_id % 240) -- 240 slots
-- against monotonically climbing VXLAN ids, so two live lanes 240 apart share one
-- address on the lab broadcast domain AND one Guacamole console host:port.
--
-- SAFE TO RUN ON A TABLE THAT ALREADY CONTAINS DUPLICATES -- it does today.
-- A plain unique index would abort and you would learn nothing. Instead every
-- lane that is currently part of a duplicate group is flagged and carved out of
-- the index predicate. The constraint is live for every NEW lane from this
-- moment; the pre-existing offenders are exempt, listed in the output below, and
-- drop out of the exemption on their own as they are torn down. Nothing but this
-- migration ever sets the flag, so the exemption can only shrink.
--
-- Run by hand:
--   psql -h <host> -U <user> -d cybercore_db -f 033_lane_wan_ip.sql
-- front-end/migrations/ has NO automatic runner -- module-loader.js only walks
-- manifest.database.migrations inside modules/ and plugins/.
--
-- ORDER MATTERS: apply this BEFORE deploying the code that writes the column,
-- or every insertLane fails with 'column "gateway_wan_ip" does not exist'.
-- (server.js also carries an idempotent ensureLaneWanColumns() belt-and-braces
-- for the two ADD COLUMNs, but not for the backfill or the index -- those are
-- one-time and need operator eyes on the collision report at the end.)
--
-- PLAIN SQL ONLY -- no psql meta-commands (\set, \echo), so this runs unchanged
-- in Adminer, DBeaver, pgAdmin or psql. In psql, pass -v ON_ERROR_STOP=1 on the
-- command line if you want it to halt on the first error; everything is inside
-- one transaction either way, so a failure rolls the whole thing back.
--
-- IDEMPOTENT: safe to re-run. Columns and indexes use IF NOT EXISTS, both
-- backfills only touch rows that are still NULL, and the lease seed is skipped
-- once the table has any rows.
-- ============================================================================

BEGIN;

-- 1. Columns ---------------------------------------------------------------
ALTER TABLE cybercore_lane
  ADD COLUMN IF NOT EXISTS gateway_wan_ip       INET,
  ADD COLUMN IF NOT EXISTS wan_ip_grandfathered BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN cybercore_lane.gateway_wan_ip IS
  'Lane gateway wan0 transit address, ALLOCATED (not derived) by src/utils/lane-wan-allocator.js. Authoritative; config->>''gateway_wan_ip'' is a legacy mirror.';
COMMENT ON COLUMN cybercore_lane.wan_ip_grandfathered IS
  'TRUE only for lanes that already shared a WAN address when migration 033 ran. Exempt from ux_cybercore_lane_wan_ip_active. Set once, by 033, never by application code.';

-- 2. Backfill from config, where a value was recorded ----------------------
UPDATE cybercore_lane
   SET gateway_wan_ip = (config->>'gateway_wan_ip')::inet
 WHERE gateway_wan_ip IS NULL
   AND config->>'gateway_wan_ip' ~ '^[0-9]{1,3}(\.[0-9]{1,3}){3}$';

-- 3. Backfill the rest from the legacy derivation ---------------------------
--    Most rows land here. Same formula the running gateways were actually
--    configured with, so the backfill matches what is on the wire. v1 lanes are
--    excluded: they use the per-module transit /16, not this pool.
UPDATE cybercore_lane
   -- '100.100.60.0' is the pre-allocator base. Change it here ONLY if this
   -- site's cluster.networking.v2_lab_network.subnet_base was ever something
   -- other than the code default in src/utils/site-config.js.
   SET gateway_wan_ip = '100.100.60.0'::inet + 10 + (vxlan_id % 240)
 WHERE gateway_wan_ip IS NULL
   AND vxlan_id IS NOT NULL
   AND status NOT IN ('error', 'deleted')
   AND COALESCE(config->>'subnet_scheme', 'v2') <> 'v1';

-- 4. Flag the pre-existing duplicates --------------------------------------
WITH dups AS (
  SELECT gateway_wan_ip
    FROM cybercore_lane
   WHERE gateway_wan_ip IS NOT NULL
     AND status NOT IN ('error', 'deleted')
   GROUP BY gateway_wan_ip
  HAVING COUNT(*) > 1
)
UPDATE cybercore_lane l
   SET wan_ip_grandfathered = TRUE
  FROM dups d
 WHERE l.gateway_wan_ip = d.gateway_wan_ip
   AND l.status NOT IN ('error', 'deleted');

-- 5. The constraint --------------------------------------------------------
--    Mirrors ux_cybercore_lane_vxlan_active (migration 016): error and deleted
--    lanes release their address for retry.
CREATE UNIQUE INDEX IF NOT EXISTS ux_cybercore_lane_wan_ip_active
  ON cybercore_lane(gateway_wan_ip)
  WHERE gateway_wan_ip IS NOT NULL
    AND status NOT IN ('error', 'deleted')
    AND wan_ip_grandfathered = FALSE;

-- 6. Lease history ----------------------------------------------------------
--    cybercore_lane rows are HARD-deleted on teardown, so the lane table cannot
--    say when an address was last in use. The allocator orders candidates by
--    longest-since-handed-out, which needs this.
--    DELIBERATELY NO FOREIGN KEY to cybercore_lane: ON DELETE CASCADE would erase
--    exactly the history this exists to keep, and RESTRICT would break every
--    teardown path.
CREATE TABLE IF NOT EXISTS cybercore_lane_wan_lease (
  lease_id     BIGSERIAL PRIMARY KEY,
  wan_ip       INET NOT NULL,
  lane_id      UUID,
  vxlan_id     INTEGER,
  allocated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_lane_wan_lease_ip
  ON cybercore_lane_wan_lease(wan_ip, allocated_at DESC);

-- Seed from what exists now, so the first allocations after this migration have
-- cooldown ordering rather than marching from the bottom of the pool over live
-- lanes.
--
-- Guarded on the table being empty so a re-run of this file does not stack a
-- second copy of the seed. (Harmless to the allocator, which only reads MAX,
-- but a lease table that doubles every time someone re-runs the migration is
-- the kind of thing that gets debugged at an unhelpful moment.) The boot hook
-- ensureLaneWanColumns() may have created the table already; it never seeds it.
INSERT INTO cybercore_lane_wan_lease (wan_ip, lane_id, vxlan_id, allocated_at)
SELECT gateway_wan_ip, lane_id, vxlan_id, created_at
  FROM cybercore_lane
 WHERE gateway_wan_ip IS NOT NULL
   AND NOT EXISTS (SELECT 1 FROM cybercore_lane_wan_lease);

COMMIT;

-- ============================================================================
-- 7. THE REPORT -- read this. Returned as a RESULT SET rather than RAISE
--    WARNING, because Adminer, pgAdmin and DBeaver all swallow server notices
--    and this is the one part of the migration an operator has to actually see.
--
--    Every row is an address two or more LIVE lanes are sharing today: both
--    owners' Guacamole consoles resolve to the same host:port, and both
--    gateways answer ARP for it on the lab VLAN. They are exempt from the new
--    unique index so this migration could complete; nothing is repaired
--    automatically.
--
--    To fix one: redeploy the NEWER lane of the pair (it picks up a freshly
--    allocated address); the older lane keeps its working setup. The exemption
--    clears itself as they go.
--
--    NO ROWS = no pre-existing collisions. Nothing was grandfathered.
-- ============================================================================
SELECT host(l.gateway_wan_ip)                              AS wan_ip,
       COUNT(*)                                            AS live_lanes,
       STRING_AGG(l.vxlan_id::text, ', ' ORDER BY l.created_at) AS vxlan_ids,
       STRING_AGG(COALESCE(u.email, '(no owner)'), ', ' ORDER BY l.created_at) AS owners,
       STRING_AGG(COALESCE(l.name, '?'), ', ' ORDER BY l.created_at)           AS lane_names,
       MAX(l.created_at)                                   AS newest_lane
  FROM cybercore_lane l
  LEFT JOIN cybercore_user u ON u.user_id = l.user_id
 WHERE l.wan_ip_grandfathered
   AND l.status NOT IN ('error', 'deleted')
 GROUP BY l.gateway_wan_ip
 ORDER BY COUNT(*) DESC, l.gateway_wan_ip;

-- To clear a stale grandfather flag once a lane is no longer colliding:
--   UPDATE cybercore_lane l SET wan_ip_grandfathered = FALSE
--    WHERE l.wan_ip_grandfathered
--      AND NOT EXISTS (SELECT 1 FROM cybercore_lane o
--                       WHERE o.gateway_wan_ip = l.gateway_wan_ip
--                         AND o.lane_id <> l.lane_id
--                         AND o.status NOT IN ('error','deleted'));
