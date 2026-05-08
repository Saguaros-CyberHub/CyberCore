CREATE EXTENSION IF NOT EXISTS "uuid-ossp";


CREATE TABLE IF NOT EXISTS intakes (
  id                    UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id               UUID NOT NULL,
  profile_id            UUID REFERENCES profiles(id) ON DELETE CASCADE,
  source                VARCHAR(20) NOT NULL
                        CHECK (source IN ('ai_simulated','real_client')),
  schema_version        VARCHAR(10) NOT NULL DEFAULT '1.1',
  cover_name            VARCHAR(200),
  payload               JSONB       NOT NULL DEFAULT '{}'::jsonb,
  completion_percentage SMALLINT    NOT NULL DEFAULT 0
                        CHECK (completion_percentage BETWEEN 0 AND 100),
  status                VARCHAR(20) NOT NULL DEFAULT 'in_progress'
                        CHECK (status IN ('in_progress','complete')),
  raw_format            VARCHAR(10) CHECK (raw_format IN ('json','html')),
  raw_preview           TEXT,
  legacy_source_table   VARCHAR(40),  -- 'intake_form_responses' | 'real_client_intakes' (audit)
  legacy_source_id      UUID,         -- id from old table, for traceability
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at          TIMESTAMPTZ
);


CREATE UNIQUE INDEX IF NOT EXISTS idx_intakes_profile_unique
  ON intakes(profile_id) WHERE profile_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_intakes_user_status ON intakes(user_id, status);
CREATE INDEX IF NOT EXISTS idx_intakes_source      ON intakes(source);
CREATE INDEX IF NOT EXISTS idx_intakes_created_at  ON intakes(created_at DESC);

-- === Backfill: real_client_intakes are already canonical v1.1 — direct copy.
-- Skip rows that have already been migrated (idempotent re-run safety).
INSERT INTO intakes (
  id, user_id, profile_id, source, schema_version, cover_name, payload,
  completion_percentage, status, raw_format, raw_preview,
  legacy_source_table, legacy_source_id, created_at, updated_at, completed_at
)
SELECT
  uuid_generate_v4(),
  rci.uploaded_by,
  rci.linked_profile_id,
  'real_client',
  COALESCE(rci.schema_version, '1.1'),
  rci.cover_name,
  rci.payload,
  100,                              -- real-client uploads are always submitted complete
  CASE WHEN rci.status = 'archived' THEN 'in_progress' ELSE 'complete' END,
  rci.raw_format,
  rci.raw_preview,
  'real_client_intakes',
  rci.id,
  rci.created_at,
  rci.updated_at,
  rci.created_at
FROM real_client_intakes rci
WHERE NOT EXISTS (
  SELECT 1 FROM intakes i
  WHERE i.legacy_source_table = 'real_client_intakes'
    AND i.legacy_source_id    = rci.id
);

