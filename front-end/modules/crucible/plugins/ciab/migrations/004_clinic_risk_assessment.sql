-- ============================================================================
-- 004 — CLINIC RISK ASSESSMENT (Phase 1)
-- ----------------------------------------------------------------------------
-- Adds the data model for the Clinic Risk Assessment deliverable: a register
-- of risk findings (likelihood × impact + control mappings) and per-profile
-- report drafts (exec summary, branding, cached chart PNGs, generated PDF).
--
-- Reads from the unified `intakes` table (Phase 0). One report per profile.
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- === Risk Findings ===
-- One row per finding. Likelihood and impact are 1–5; inherent_risk is the
-- product, generated as a stored column so heat-map ordering is index-friendly.
CREATE TABLE IF NOT EXISTS risk_findings (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id         UUID NOT NULL,
  profile_id      UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  finding_code    VARCHAR(20),                  -- "F-001", assessor-assigned
  title           VARCHAR(300) NOT NULL,
  description     TEXT,
  category        VARCHAR(50),                  -- technical | process | people | physical
  likelihood      SMALLINT CHECK (likelihood BETWEEN 1 AND 5),
  impact          SMALLINT CHECK (impact     BETWEEN 1 AND 5),
  inherent_risk   SMALLINT GENERATED ALWAYS AS (likelihood * impact) STORED,
  residual_likelihood SMALLINT CHECK (residual_likelihood BETWEEN 1 AND 5),
  residual_impact     SMALLINT CHECK (residual_impact     BETWEEN 1 AND 5),
  status          VARCHAR(20) NOT NULL DEFAULT 'open'
                  CHECK (status IN ('open','accepted','mitigated','transferred')),
  recommendation  TEXT,
  control_refs    JSONB NOT NULL DEFAULT '[]'::jsonb,  -- [{framework:'CIS_IG1', id:'4.1'}, ...]
  evidence_refs   JSONB NOT NULL DEFAULT '[]'::jsonb,
  ai_generated    BOOLEAN NOT NULL DEFAULT FALSE,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (profile_id, finding_code)
);

CREATE INDEX IF NOT EXISTS idx_risk_findings_profile ON risk_findings(profile_id);
CREATE INDEX IF NOT EXISTS idx_risk_findings_inherent ON risk_findings(profile_id, inherent_risk DESC);
CREATE INDEX IF NOT EXISTS idx_risk_findings_status   ON risk_findings(profile_id, status);

-- === Report Deliverables ===
-- Holds the assessor-curated narrative and the cached chart PNGs the client
-- POSTs at export time. One profile may eventually have many versioned drafts;
-- Phase 1 just keeps the latest.
CREATE TABLE IF NOT EXISTS report_deliverables (
  id                 UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  profile_id         UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  version            INT  NOT NULL DEFAULT 1,
  status             VARCHAR(20) NOT NULL DEFAULT 'draft'
                     CHECK (status IN ('draft','final')),
  exec_summary       TEXT,
  branding           JSONB NOT NULL DEFAULT '{}'::jsonb,  -- {logo_path, accent_color, prepared_by}
  csf_scores         JSONB NOT NULL DEFAULT '{}'::jsonb,  -- {identify:3, protect:4, ...}
  charts_cache       JSONB NOT NULL DEFAULT '{}'::jsonb,  -- {heatmap_png, radar_png, cis_png, csf_png}
  generated_pdf_path TEXT,
  created_by         UUID,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  finalized_at       TIMESTAMPTZ,
  UNIQUE (profile_id, version)
);

CREATE INDEX IF NOT EXISTS idx_report_deliverables_profile ON report_deliverables(profile_id);
