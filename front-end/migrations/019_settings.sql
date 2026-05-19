-- ============================================================================
-- Settings Table for CyberHub Configuration
-- ============================================================================
-- This table stores application-level settings as key-value pairs.
-- Used by admin.js to fetch site configuration like site_name.
-- ============================================================================

-- Create the settings table
CREATE TABLE IF NOT EXISTS settings (
  key VARCHAR(255) PRIMARY KEY,
  value TEXT,
  description TEXT,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create index for faster lookups
CREATE INDEX IF NOT EXISTS idx_settings_key ON settings(key);

-- Insert default settings if they don't exist
INSERT INTO settings (key, value, description) VALUES 
  ('site_name', 'CyberHub', 'The display name of the CyberHub instance')
ON CONFLICT (key) DO NOTHING;
