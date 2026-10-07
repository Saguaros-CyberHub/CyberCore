-- ============================================================================
-- 006 — PROFILE-DRIVEN LANE DEPLOYMENTS (CIAB-only)
-- ----------------------------------------------------------------------------
-- Admins can deploy N independent cybercore lanes from a single AI-generated
-- profile (classroom mode). Only assets tagged role='server' (or explicitly
-- ticked) become real VMs; workstations/mobile/iot remain phantom in the
-- profile. Real deployed IPs get written back per-lane so the profile reflects
-- what's live where.
--
-- Cross-DB note: cybercore_lane / crucible_challenge live in cybercore_db.
-- CIAB cannot ALTER them from this migration — we keep the linkage tables
-- locally in clinic_db and store lane_id / ephemeral_challenge_id as plain
-- UUIDs (mirrors the existing user_id pattern in profiles).
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- One row per profile-driven batch deploy (a "lane group").
CREATE TABLE IF NOT EXISTS ciab_profile_lane_groups (
  id                     UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  profile_id             UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  group_name             VARCHAR(128) NOT NULL,
  created_by             UUID NOT NULL,                              -- cybercore_user.user_id (cross-DB, no FK)
  num_lanes              INTEGER NOT NULL CHECK (num_lanes > 0),
  asset_selection        JSONB NOT NULL,                             -- [{hostname, included, role, os}]
  service_gaps           JSONB NOT NULL DEFAULT '[]'::jsonb,         -- [{vm, service, port, reason}]
  template_misses        JSONB NOT NULL DEFAULT '[]'::jsonb,         -- [{hostname, os, reason}]
  profile_snapshot       JSONB NOT NULL,                             -- frozen network.assets at deploy time
  lane_ip_writeback      JSONB NOT NULL DEFAULT '{}'::jsonb,         -- { hostname: { lane_id: ip, ... } }
  ephemeral_challenge_id UUID,                                       -- crucible_challenge row CIAB synthesized (cross-DB)
  subnet_scheme          VARCHAR(8) NOT NULL DEFAULT 'v2'
                         CHECK (subnet_scheme IN ('v1','v2','v3')),
  attack_boxes           BOOLEAN NOT NULL DEFAULT TRUE,
  vuln_app_id            UUID,                                       -- ciab_profile_vuln_apps.id, nullable
  status                 VARCHAR(32) NOT NULL DEFAULT 'deploying'
                         CHECK (status IN ('deploying','partial','active','error','deleted')),
  created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ciab_pllg_profile ON ciab_profile_lane_groups(profile_id);
CREATE INDEX IF NOT EXISTS idx_ciab_pllg_creator ON ciab_profile_lane_groups(created_by);
CREATE INDEX IF NOT EXISTS idx_ciab_pllg_status  ON ciab_profile_lane_groups(status);

-- One row per lane in a group. Tracks per-lane lifecycle so the UI can show
-- "lane 7 of 25 failed", and so retry knows which VMIDs to forcibly destroy
-- before re-running deployOneLaneFromSpec().
CREATE TABLE IF NOT EXISTS ciab_profile_lane_jobs (
  id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  group_id     UUID NOT NULL REFERENCES ciab_profile_lane_groups(id) ON DELETE CASCADE,
  lane_id      UUID NOT NULL,                                        -- cybercore_lane.lane_id (cross-DB)
  vxlan_id     INTEGER NOT NULL,
  lane_index   INTEGER NOT NULL CHECK (lane_index > 0),              -- 1..N (display only)
  status       VARCHAR(32) NOT NULL DEFAULT 'pending'
               CHECK (status IN ('pending','cloning','firstboot','active','error')),
  phase_detail TEXT,
  error_msg    TEXT,
  vm_ids       INTEGER[],                                            -- expected Proxmox VMIDs, for retry cleanup
  target_node  VARCHAR(64),
  started_at   TIMESTAMPTZ,
  finished_at  TIMESTAMPTZ,
  UNIQUE (group_id, lane_index)
);

CREATE INDEX IF NOT EXISTS idx_ciab_pllj_group ON ciab_profile_lane_jobs(group_id);
CREATE INDEX IF NOT EXISTS idx_ciab_pllj_lane  ON ciab_profile_lane_jobs(lane_id);

-- AI-generated vulnerable web app per profile. Re-used across deploys of the
-- same profile so we don't pay the LLM cost on every batch.
CREATE TABLE IF NOT EXISTS ciab_profile_vuln_apps (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  profile_id      UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  target_hostname VARCHAR(128),                                      -- web-server asset hostname, or NULL = dedicated VM
  delivery_mode   VARCHAR(16) NOT NULL
                  CHECK (delivery_mode IN ('docker','apache_vhost','standalone_vm')),
  dockerfile      TEXT,
  source_tree     JSONB,                                             -- { 'path/to/file.php': '<?php ...' }
  install_script  TEXT,                                              -- shell script run on the target VM
  llm_model       VARCHAR(64),
  generation_meta JSONB,                                             -- {industry, vulns_picked, prompt_hash, ...}
  generated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ciab_cpva_profile ON ciab_profile_vuln_apps(profile_id);
