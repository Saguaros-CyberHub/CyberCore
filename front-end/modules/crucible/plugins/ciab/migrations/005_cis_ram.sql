-- ============================================================================
-- 005 — CIS RAM v2.1 IG1 WORKBOOK (Phase 2)
-- ----------------------------------------------------------------------------
-- Mirrors the published CIS RAM v2.1 IG1 workbook in the database. Each profile
-- gets one assessment envelope (acceptable_risk_score, impact criteria notes)
-- and 56 safeguard rows (one per IG1 safeguard) lazily created on first read
-- of the workbook tab.
--
-- Risk math (CIS RAM tri-factor):
--   inherent_risk_score  = likelihood          * GREATEST(mission_impact,           obligations_impact)            -- 1..9
--   residual_risk_score  = treatment_likelihood* GREATEST(treatment_mission_impact, treatment_obligations_impact)  -- 1..9
--   "Reasonable?" = (residual_risk_score <= acceptable_risk_score) — computed at read-time, not stored.
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- One row per profile. Holds engagement-level settings the workbook calls
-- "Impact Criteria". Lazily inserted by the API on first GET.
CREATE TABLE IF NOT EXISTS cis_ram_assessments (
  id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  profile_id              UUID NOT NULL UNIQUE REFERENCES profiles(id) ON DELETE CASCADE,
  user_id                 UUID NOT NULL,
  acceptable_risk_score   SMALLINT NOT NULL DEFAULT 6
                          CHECK (acceptable_risk_score BETWEEN 1 AND 9),
  -- Per-engagement criteria notes — free-form per workbook. Shape:
  --   { mission_definition, obligations_definition, dollar_thresholds, notes }
  impact_criteria         JSONB NOT NULL DEFAULT '{}'::jsonb,
  status                  VARCHAR(20) NOT NULL DEFAULT 'in_progress'
                          CHECK (status IN ('in_progress','complete')),
  created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at            TIMESTAMPTZ
);

-- One row per (profile × IG1 safeguard). 56 rows pre-populated on first GET.
-- safeguard_num joins back to data/frameworks/cis-ig1.json safeguards[].num.
CREATE TABLE IF NOT EXISTS cis_ram_safeguards (
  id                              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  profile_id                      UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  user_id                         UUID NOT NULL,
  safeguard_num                   VARCHAR(10) NOT NULL,        -- "1.1", "4.3", ...
  asset_class                     VARCHAR(80),                 -- 'Workstations' | 'Servers' | 'Data' | ...

  -- Inherent risk (1–3 each per CIS RAM)
  mission_impact                  SMALLINT CHECK (mission_impact     BETWEEN 1 AND 3),
  obligations_impact              SMALLINT CHECK (obligations_impact BETWEEN 1 AND 3),
  likelihood                      SMALLINT CHECK (likelihood         BETWEEN 1 AND 3),
  inherent_risk_score             SMALLINT GENERATED ALWAYS AS
                                    (likelihood * GREATEST(mission_impact, obligations_impact)) STORED,

  -- Treatment plan (1–3 each per CIS RAM)
  treatment_safeguard             VARCHAR(10),                  -- usually equals safeguard_num
  treatment_title                 VARCHAR(300),
  treatment_description           TEXT,
  treatment_mission_impact        SMALLINT CHECK (treatment_mission_impact     BETWEEN 1 AND 3),
  treatment_obligations_impact    SMALLINT CHECK (treatment_obligations_impact BETWEEN 1 AND 3),
  treatment_likelihood            SMALLINT CHECK (treatment_likelihood         BETWEEN 1 AND 3),
  treatment_cost                  VARCHAR(40),                  -- free-text per workbook ("Low", "$5k", etc.)
  residual_risk_score             SMALLINT GENERATED ALWAYS AS
                                    (treatment_likelihood * GREATEST(treatment_mission_impact, treatment_obligations_impact)) STORED,

  implementation_year             SMALLINT,
  last_completed_date             DATE,
  notes                           TEXT,
  status                          VARCHAR(20) NOT NULL DEFAULT 'open'
                                  CHECK (status IN ('open','accepted','mitigated','transferred','not_applicable')),
  created_at                      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at                      TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (profile_id, safeguard_num)
);

CREATE INDEX IF NOT EXISTS idx_cis_ram_safeguards_profile  ON cis_ram_safeguards(profile_id);
CREATE INDEX IF NOT EXISTS idx_cis_ram_safeguards_inherent ON cis_ram_safeguards(profile_id, inherent_risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_cis_ram_safeguards_status   ON cis_ram_safeguards(profile_id, status);
