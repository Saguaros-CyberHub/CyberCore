-- Durable Wazuh deregistration outbox. Deliberately no lane foreign key:
-- cleanup must survive the lane's atomic deletion, including API outages.
-- Runtime equivalent: src/utils/wazuh-agent-cleanup.js (no migrations runner).
CREATE TABLE IF NOT EXISTS cybercore_wazuh_cleanup (
  lane_id UUID PRIMARY KEY,
  registrations JSONB NOT NULL CHECK (jsonb_typeof(registrations) = 'array'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  retain_until TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '15 minutes'),
  next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  attempts INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  lease_token UUID,
  lease_until TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ix_wazuh_cleanup_due ON cybercore_wazuh_cleanup(next_attempt_at);
