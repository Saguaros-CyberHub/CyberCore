-- ============================================================================
-- Migration 016: Make ux_cybercore_lane_vxlan a partial unique index
-- ============================================================================
-- The existing full unique index covers every row, but the available-VXLAN
-- SELECT in admin.js excludes lanes with status IN ('error', 'deleted') from
-- the "used" set — so a previously-failed lane's vxlan_id is reported as
-- available, then the INSERT collides with the orphan row.
--
-- This partial index aligns the on-disk constraint with the SELECT's intent:
-- only active/deploying/pending/suspended lanes reserve their vxlan_id;
-- error and deleted lanes free theirs for retry.
--
-- Safe to run on a populated table — partial indexes can replace full
-- indexes without data movement.
-- ============================================================================

DROP INDEX IF EXISTS ux_cybercore_lane_vxlan;

CREATE UNIQUE INDEX ux_cybercore_lane_vxlan_active
  ON cybercore_lane(vxlan_id)
  WHERE vxlan_id IS NOT NULL
    AND status NOT IN ('error', 'deleted');
