-- ============================================================================
-- REAL-CLIENT INTAKE — PARALLEL FLOW TO ASSESSMENT INTAKE
-- Stores anonymized intake payloads uploaded from the standalone HTML form.
-- Decoupled from intake_form_responses (which is bound to assessment profiles).
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- === Real-Client Intakes ===
CREATE TABLE IF NOT EXISTS real_client_intakes (
  id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  uploaded_by         UUID         NOT NULL,                  -- cross-DB ref to cybercore_user.users.id
  uploaded_role       VARCHAR(20)  NOT NULL
                      CHECK (uploaded_role IN ('student','instructor','admin')),
  cover_name          VARCHAR(200) NOT NULL,
  schema_version      VARCHAR(20)  NOT NULL,
  payload             JSONB        NOT NULL,                  -- full exported JSON from the HTML form
  raw_preview         TEXT,                                   -- first 4KB of raw upload for audit
  raw_format          VARCHAR(10)  NOT NULL DEFAULT 'json'
                      CHECK (raw_format IN ('json','html')),
  linked_profile_id   UUID         REFERENCES profiles(id) ON DELETE SET NULL,
  linked_challenge_id UUID,                                    -- crucible_challenge.challenge_id (cross-DB; no FK)
  status              VARCHAR(20)  NOT NULL DEFAULT 'uploaded'
                      CHECK (status IN ('uploaded','linked','archived')),
  created_at          TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at          TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_rci_uploader    ON real_client_intakes(uploaded_by);
CREATE INDEX IF NOT EXISTS idx_rci_profile     ON real_client_intakes(linked_profile_id);
CREATE INDEX IF NOT EXISTS idx_rci_challenge   ON real_client_intakes(linked_challenge_id);
CREATE INDEX IF NOT EXISTS idx_rci_status      ON real_client_intakes(status);
CREATE INDEX IF NOT EXISTS idx_rci_created_at  ON real_client_intakes(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_rci_cover_name  ON real_client_intakes(cover_name);

-- === Profiles: tag real-client-sourced profiles + hold admin filler selections ===
ALTER TABLE profiles
  ADD COLUMN IF NOT EXISTS profile_source    VARCHAR(20) NOT NULL DEFAULT 'ai_simulated',
  ADD COLUMN IF NOT EXISTS source_intake_id  UUID,
  ADD COLUMN IF NOT EXISTS filler_assets     JSONB NOT NULL DEFAULT '{}'::jsonb;

-- Add constraint separately so re-running is safe (ADD COLUMN IF NOT EXISTS won't re-check constraints)
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'profiles_profile_source_check'
  ) THEN
    ALTER TABLE profiles
      ADD CONSTRAINT profiles_profile_source_check
      CHECK (profile_source IN ('ai_simulated','real_intake'));
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'profiles_source_intake_fk'
  ) THEN
    ALTER TABLE profiles
      ADD CONSTRAINT profiles_source_intake_fk
      FOREIGN KEY (source_intake_id) REFERENCES real_client_intakes(id) ON DELETE SET NULL;
  END IF;
END$$;

CREATE INDEX IF NOT EXISTS idx_profiles_source            ON profiles(profile_source);
CREATE INDEX IF NOT EXISTS idx_profiles_source_intake_id  ON profiles(source_intake_id);
