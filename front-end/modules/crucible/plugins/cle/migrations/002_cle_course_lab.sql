/*
 * ============================================================================
 * CLE Migration 002 — Course → reserved lab linkage
 * ----------------------------------------------------------------------------
 * Each CLE course owns one reserved lab: a crucible_challenge row (in
 * cybercore_db) whose spec.vxlan_block sizes the SDN zone + VNets created once
 * at course creation. Student workstations are then deployed as cybercore_lane
 * rows drawn from that block — no per-provision SDN reload.
 *
 * Cross-DB note: crucible_challenge / cybercore_lane live in cybercore_db. The
 * CLE plugin DB cannot FK into them, so challenge_id is stored as a plain UUID
 * (same cross-DB pattern used elsewhere for user_id / lane_id references).
 * ============================================================================
 */

ALTER TABLE cle_course
  ADD COLUMN IF NOT EXISTS challenge_id   UUID,
  ADD COLUMN IF NOT EXISTS challenge_key  TEXT,
  ADD COLUMN IF NOT EXISTS subnet_scheme  VARCHAR(8) NOT NULL DEFAULT 'v2'
    CHECK (subnet_scheme IN ('v1', 'v2', 'v3')),
  ADD COLUMN IF NOT EXISTS max_students   INTEGER NOT NULL DEFAULT 30
    CHECK (max_students >= 1);

CREATE INDEX IF NOT EXISTS idx_cle_course_challenge ON cle_course(challenge_id);
