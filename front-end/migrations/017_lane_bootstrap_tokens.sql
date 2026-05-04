-- ============================================================================
-- Migration 017: lane_bootstrap_tokens (cybercore_db)
-- ============================================================================
-- Backs the HTTP pull-bootstrap mechanism that replaces SSH-based config push.
--
-- When admin.js deploys a v2 lane, it mints a Tailscale auth key and inserts a
-- row here keyed by vxlan_id (PK) plus the lane gateway's expected WAN IP.
-- The lane gateway, on first boot, calls GET /api/lane-bootstrap from inside
-- the LXC. The endpoint identifies the requesting lane by source IP, returns
-- the payload, and marks the row consumed (one-shot).
--
-- Auth model:
--   * Source IP must match wan_ip of an unconsumed, non-expired row.
--   * Token is single-use: consumed_at is set on first successful fetch.
--   * Tokens have a short expiry (default 10min) — minted keys themselves
--     also have short Tailscale-side expiry, so layered protection.
--
-- Cleanup: rows with consumed_at NOT NULL or expires_at < NOW() are tombstones.
-- Easy to add a periodic janitor later; not urgent because rows are tiny.
-- ============================================================================

CREATE TABLE IF NOT EXISTS lane_bootstrap_tokens (
  vxlan_id      INTEGER PRIMARY KEY,
  wan_ip        INET    NOT NULL,
  payload       JSONB   NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at    TIMESTAMPTZ NOT NULL,
  consumed_at   TIMESTAMPTZ,
  consumed_by   INET
);

CREATE INDEX IF NOT EXISTS idx_lane_bootstrap_tokens_wan_ip
  ON lane_bootstrap_tokens(wan_ip)
  WHERE consumed_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_lane_bootstrap_tokens_expires
  ON lane_bootstrap_tokens(expires_at);

COMMENT ON TABLE lane_bootstrap_tokens IS
  'Single-use bootstrap payloads delivered to lane gateways on first boot via GET /api/lane-bootstrap. Replaces SSH-based config push.';
COMMENT ON COLUMN lane_bootstrap_tokens.payload IS
  'JSON payload returned to the lane gateway. Currently contains tailscale_authkey, tailscale_tags, tailscale_hostname.';
COMMENT ON COLUMN lane_bootstrap_tokens.wan_ip IS
  'Expected WAN IP of the lane gateway. Endpoint enforces request source IP == wan_ip.';
