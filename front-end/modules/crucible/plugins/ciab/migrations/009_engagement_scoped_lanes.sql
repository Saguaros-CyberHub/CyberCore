-- 009_engagement_scoped_lanes.sql — Track A, phase A1.
--
-- One client profile can be the subject of several engagements. "Internal, here
-- are the credentials" and "external, here is the website" are different labs
-- against the same company, with different address plans and different live
-- lanes, and the VXLAN reservation in cybercore_db is now keyed on
-- (profile, engagement) rather than on the profile alone. This column records
-- which engagement a deploy group was for, so a group can be traced back to the
-- reservation it drew from.
--
-- The reservation itself lives in cybercore_db.crucible_challenge, which a CIAB
-- migration cannot reach (this file runs against clinic_db). Nothing is created
-- there: getOrCreateProfileChallenge stamps and adopts pre-existing rows lazily
-- on the read path.
--
-- Every plugin migration re-runs on every boot, so this must stay idempotent.

ALTER TABLE ciab_profile_lane_groups
  ADD COLUMN IF NOT EXISTS engagement_type VARCHAR(32) NOT NULL DEFAULT 'default';

-- Groups deployed before this column existed all belong to the default
-- engagement, which is exactly what the DEFAULT backfills them to. No UPDATE
-- needed; the value is deliberately not constrained to a vocabulary because
-- Track B is what defines one (ciab_engagement).

CREATE INDEX IF NOT EXISTS idx_ciab_pllg_engagement
  ON ciab_profile_lane_groups(profile_id, engagement_type);
