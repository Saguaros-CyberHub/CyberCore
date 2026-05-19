-- ============================================================================
-- Migration: Create cybercore_site_settings table
-- Purpose: Store white label branding settings (site name, logo, favicon, etc.)
-- Database: cybercore_db
-- ============================================================================

CREATE TABLE IF NOT EXISTS cybercore_site_settings (
  key VARCHAR(255) PRIMARY KEY,
  value TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Add index on created_at/updated_at for potential future queries
CREATE INDEX IF NOT EXISTS idx_cybercore_site_settings_updated ON cybercore_site_settings(updated_at DESC);

-- Initialize default site settings
INSERT INTO cybercore_site_settings (key, value) VALUES
  ('site_name', 'CyberHub'),
  ('site_logo_url', NULL),
  ('site_favicon_url', NULL),
  ('site_description', 'A comprehensive cybersecurity training and assessment platform')
ON CONFLICT (key) DO NOTHING;

-- Grant permissions to application user
ALTER TABLE cybercore_site_settings OWNER TO "cactus-admin";
GRANT ALL PRIVILEGES ON cybercore_site_settings TO "cactus-admin";
GRANT SELECT ON cybercore_site_settings TO "cactus-admin";
