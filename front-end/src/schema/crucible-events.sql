-- Existing core databases need the same event extension as a fresh Crucible
-- install. Keep this section aligned with config/postgres/modules/crucible.sql.
-- Existing rows retain their metadata and provenance; an unknown creator stays
-- NULL rather than being guessed from an unrelated user or participant.
ALTER TABLE cybercore_event
  ADD COLUMN IF NOT EXISTS event_type  TEXT,
  ADD COLUMN IF NOT EXISTS status      TEXT NOT NULL DEFAULT 'draft',
  ADD COLUMN IF NOT EXISTS description TEXT,
  ADD COLUMN IF NOT EXISTS max_players INTEGER,
  ADD COLUMN IF NOT EXISTS is_public   BOOLEAN NOT NULL DEFAULT true,
  ADD COLUMN IF NOT EXISTS created_by  UUID REFERENCES cybercore_user(user_id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS module_key  TEXT REFERENCES cybercore_module(key)   ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  ADD COLUMN IF NOT EXISTS updated_at  TIMESTAMPTZ NOT NULL DEFAULT now();

CREATE INDEX IF NOT EXISTS idx_cybercore_event_type   ON cybercore_event (event_type);
CREATE INDEX IF NOT EXISTS idx_cybercore_event_status ON cybercore_event (status);
CREATE INDEX IF NOT EXISTS idx_cybercore_event_module ON cybercore_event (module_key);

CREATE TABLE IF NOT EXISTS crucible_score (
  score_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id   UUID NOT NULL REFERENCES cybercore_event(event_id) ON DELETE CASCADE,
  user_id    UUID NOT NULL REFERENCES cybercore_user(user_id) ON DELETE CASCADE,
  points     INT NOT NULL DEFAULT 0,
  submitted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (event_id, user_id)
);
