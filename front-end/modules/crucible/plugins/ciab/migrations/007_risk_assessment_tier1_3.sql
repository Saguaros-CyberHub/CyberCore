-- ============================================================================
-- 007 — RISK ASSESSMENT TIER 1-3 FEATURES
-- ============================================================================
-- Adds the schema needed for:
--   * Asset register with criticality + data classification (Tier 1)
--   * Threat scenario library + instantiate-from-library (Tier 1)
--   * Owner / due date / evidence / discovery method on findings (Tier 1)
--   * POA&M view + Insurance readiness + Snapshot comparison (Tier 2)
--   * OWASP decomposed L×I + FAIR-lite quantification (Tier 3)
--   * NIST 800-30 threat source category dropdown
--
-- All tables scoped by (profile_id, user_id) so instructor answer-keys +
-- student work don't collide. Same pattern as existing risk_findings.
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ─── Asset Register ─────────────────────────────────────────────────────
-- Each row is one enumerable asset in scope of the engagement. Risks tie
-- back to assets via risk_findings.affected_asset_ids (jsonb array of UUIDs).
CREATE TABLE IF NOT EXISTS risk_assets (
  id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id             UUID NOT NULL,
  profile_id          UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  name                VARCHAR(200) NOT NULL,
  asset_type          VARCHAR(40),                     -- 'workstation' | 'server' | 'network_device' | 'saas' | 'data_store' | 'mobile' | 'iot' | 'process' | 'people'
  owner_role          VARCHAR(100),                    -- 'IT Manager', 'Finance Lead', etc.
  custodian           VARCHAR(100),                    -- who operates it day-to-day
  -- CIA ratings 1 (Low) – 3 (High)
  confidentiality     SMALLINT CHECK (confidentiality BETWEEN 1 AND 3),
  integrity           SMALLINT CHECK (integrity       BETWEEN 1 AND 3),
  availability        SMALLINT CHECK (availability    BETWEEN 1 AND 3),
  -- Tiered criticality (Tier 1 = mission-critical / crown jewel)
  criticality_tier    SMALLINT CHECK (criticality_tier BETWEEN 1 AND 3),
  -- Data classification: Public / Internal / Confidential / Restricted
  data_classification VARCHAR(20) CHECK (data_classification IN ('Public','Internal','Confidential','Restricted','Unknown')),
  -- Optional: data category tags (PII / PHI / PCI / IP / Financial / etc.)
  data_categories     JSONB NOT NULL DEFAULT '[]'::jsonb,
  ip_address          VARCHAR(45),
  hostname            VARCHAR(255),
  description         TEXT,
  -- OCTAVE Allegro container concept (technical / physical / people)
  containers          JSONB NOT NULL DEFAULT '[]'::jsonb,
  ai_generated        BOOLEAN NOT NULL DEFAULT FALSE,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_risk_assets_profile     ON risk_assets(profile_id);
CREATE INDEX IF NOT EXISTS idx_risk_assets_user        ON risk_assets(user_id);
CREATE INDEX IF NOT EXISTS idx_risk_assets_criticality ON risk_assets(profile_id, criticality_tier);

-- ─── Findings — extend with Tier 1-3 fields ─────────────────────────────
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='risk_findings' AND column_name='owner_role') THEN
    ALTER TABLE risk_findings ADD COLUMN owner_role VARCHAR(100);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='risk_findings' AND column_name='owner_name') THEN
    ALTER TABLE risk_findings ADD COLUMN owner_name VARCHAR(150);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='risk_findings' AND column_name='reviewer') THEN
    ALTER TABLE risk_findings ADD COLUMN reviewer VARCHAR(150);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='risk_findings' AND column_name='target_completion_date') THEN
    ALTER TABLE risk_findings ADD COLUMN target_completion_date DATE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='risk_findings' AND column_name='evidence_observed') THEN
    ALTER TABLE risk_findings ADD COLUMN evidence_observed TEXT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='risk_findings' AND column_name='discovery_method') THEN
    ALTER TABLE risk_findings ADD COLUMN discovery_method VARCHAR(40);  -- 'interview' | 'document_review' | 'technical_scan' | 'observation' | 'self_attestation'
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='risk_findings' AND column_name='threat_source') THEN
    ALTER TABLE risk_findings ADD COLUMN threat_source VARCHAR(20);     -- NIST 800-30: 'adversarial' | 'accidental' | 'structural' | 'environmental'
  END IF;
  -- Asset linkage (JSONB array of risk_assets.id UUIDs)
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='risk_findings' AND column_name='affected_asset_ids') THEN
    ALTER TABLE risk_findings ADD COLUMN affected_asset_ids JSONB NOT NULL DEFAULT '[]'::jsonb;
  END IF;
  -- OWASP decomposed scoring (8 likelihood factors + 8 impact factors, each 0-9)
  -- Stored as one jsonb blob: {skill:5, motive:3, ..., conf:7, integ:5, ...}
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='risk_findings' AND column_name='owasp_factors') THEN
    ALTER TABLE risk_findings ADD COLUMN owasp_factors JSONB;
  END IF;
  -- FAIR-lite quantification: triangular distribution inputs + ALE result
  -- {lef:{min,mode,max}, lm:{min,mode,max}, ale_mean, ale_p10, ale_p90, lec_data}
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='risk_findings' AND column_name='fair_quant') THEN
    ALTER TABLE risk_findings ADD COLUMN fair_quant JSONB;
  END IF;
  -- Scenario library link — when the finding was instantiated from a library
  -- template, this records which template (so updates to the library can
  -- optionally cascade to derived findings).
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='risk_findings' AND column_name='scenario_library_key') THEN
    ALTER TABLE risk_findings ADD COLUMN scenario_library_key VARCHAR(80);
  END IF;
END $$;

-- ─── Threat Scenario Library ────────────────────────────────────────────
-- Canonical starter scenarios students "instantiate" into per-profile
-- findings. Decoupled from any profile (system-wide library). Seeded
-- by ai/scenario-library/seed.js at app startup if rowcount = 0.
CREATE TABLE IF NOT EXISTS threat_scenario_library (
  key                 VARCHAR(80) PRIMARY KEY,         -- e.g. 'ransomware-via-phishing'
  title               VARCHAR(200) NOT NULL,
  category            VARCHAR(40),                     -- 'people' | 'process' | 'technical' | 'physical'
  threat_source       VARCHAR(20),                     -- NIST 800-30 source category
  description         TEXT,                            -- 2-3 paragraph problem statement
  recommendation_template TEXT,                        -- skeleton recommendation
  default_likelihood  SMALLINT,                        -- 1-5 starting point
  default_impact      SMALLINT,                        -- 1-5
  default_residual_likelihood SMALLINT,
  default_residual_impact     SMALLINT,
  control_refs        JSONB NOT NULL DEFAULT '[]'::jsonb,
  applicable_industries JSONB NOT NULL DEFAULT '[]'::jsonb,   -- ['all'] or ['healthcare','finance']
  applicable_sizes    JSONB NOT NULL DEFAULT '[]'::jsonb,     -- ['SMB','MidMarket','Enterprise']
  tags                JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_threat_scenarios_category ON threat_scenario_library(category);

-- ─── Snapshots (baseline / re-assessment comparison) ────────────────────
-- A point-in-time snapshot of an engagement's full state. Students hit
-- "Snapshot" before implementing recommendations, then re-assess and see
-- the dashboard arrows. Schema: one row per snapshot per (profile, user).
CREATE TABLE IF NOT EXISTS risk_snapshots (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id       UUID NOT NULL,
  profile_id    UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  label         VARCHAR(120) NOT NULL,
  -- Frozen counts + scores for fast delta calculation
  findings_total      SMALLINT,
  findings_critical   SMALLINT,
  findings_high       SMALLINT,
  findings_medium     SMALLINT,
  findings_low        SMALLINT,
  ig1_coverage_pct    SMALLINT,
  ig1_yes             SMALLINT,
  ig1_partial         SMALLINT,
  ig1_no              SMALLINT,
  csf_scores          JSONB NOT NULL DEFAULT '{}'::jsonb,
  total_inherent_risk INTEGER,
  total_residual_risk INTEGER,
  -- Full frozen state for detailed comparison
  findings_snapshot   JSONB,
  notes               TEXT,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_risk_snapshots_profile ON risk_snapshots(profile_id, user_id, created_at DESC);

-- ─── Insurance Readiness Scoring ────────────────────────────────────────
-- One row per (profile, user). Stores the 12-item readiness scorecard.
-- Each control is yes / partial / no, mapped to the Coalition/At-Bay/
-- Cowbell underwriting questionnaire.
CREATE TABLE IF NOT EXISTS insurance_readiness (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id     UUID NOT NULL,
  profile_id  UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  -- 12 control flags (yes / partial / no / unknown)
  mfa_email           VARCHAR(10),
  mfa_remote          VARCHAR(10),
  mfa_privileged      VARCHAR(10),
  mfa_cloud           VARCHAR(10),
  edr_coverage_pct    SMALLINT,
  immutable_backups   VARCHAR(10),
  tested_restore_12mo VARCHAR(10),
  ir_plan_written     VARCHAR(10),
  tabletop_12mo       VARCHAR(10),
  pam_in_place        VARCHAR(10),
  security_training   VARCHAR(10),
  vuln_scanning       VARCHAR(10),
  -- Computed score (server-side) — lets the dashboard show the gauge
  readiness_score     SMALLINT,                       -- 0-100
  readiness_tier      VARCHAR(20),                    -- 'Insurable' | 'Conditional' | 'Restricted' | 'Uninsurable'
  notes               TEXT,
  ai_generated        BOOLEAN NOT NULL DEFAULT FALSE,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (profile_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_insurance_readiness_profile ON insurance_readiness(profile_id);

-- ─── Report deliverable — extend with Deloitte exec-summary structure ──
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='report_deliverables' AND column_name='exec_current_posture') THEN
    ALTER TABLE report_deliverables ADD COLUMN exec_current_posture TEXT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='report_deliverables' AND column_name='exec_top_risks') THEN
    ALTER TABLE report_deliverables ADD COLUMN exec_top_risks TEXT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='report_deliverables' AND column_name='exec_progress') THEN
    ALTER TABLE report_deliverables ADD COLUMN exec_progress TEXT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='report_deliverables' AND column_name='exec_decisions_needed') THEN
    ALTER TABLE report_deliverables ADD COLUMN exec_decisions_needed TEXT;
  END IF;
END $$;
