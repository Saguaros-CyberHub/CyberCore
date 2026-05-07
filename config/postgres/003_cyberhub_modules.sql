-- ============================================================================
-- CyberHub Module Metadata Migration
-- Adds display metadata columns to cybercore_module for dynamic sidebar/UI
-- ============================================================================

-- Add new columns for UI display
ALTER TABLE cybercore_module
  ADD COLUMN IF NOT EXISTS icon          TEXT,
  ADD COLUMN IF NOT EXISTS description   TEXT,
  ADD COLUMN IF NOT EXISTS entry_url     TEXT,
  ADD COLUMN IF NOT EXISTS display_order INTEGER NOT NULL DEFAULT 100,
  ADD COLUMN IF NOT EXISTS category      TEXT NOT NULL DEFAULT 'module',
  ADD COLUMN IF NOT EXISTS parent_module VARCHAR(255),
  ADD COLUMN IF NOT EXISTS color         TEXT;

-- Upsert all modules with full metadata
INSERT INTO cybercore_module (key, name, active, icon, description, entry_url, display_order, category, parent_module, color) VALUES
  ('crucible',   'The Crucible',         TRUE,  '🔥', 'CTF-style cyber warfare range with isolated lanes and scoring',          '/crucible',       10, 'module', NULL, '#ef4444'),
  ('cyberlabs',  'CyberLabs',            TRUE,  '🧪', 'Virtualization environment for student and faculty projects',             '/cyberlabs',      20, 'module', NULL, '#3b82f6'),
  ('forge',      'The Forge',            TRUE,  '🔨', 'Isolated environment for malware development and reverse engineering',    '/forge',          30, 'module', NULL, '#f59e0b'),
  ('university', 'Saguaros University',  TRUE,  '🎓', 'Moodle LMS with courses, certifications, and digital badges',            '/university',     40, 'module', NULL, '#8b5cf6'),
  ('archive',    'The Archive',          TRUE,  '📦', 'Deep archive of malware samples, research artifacts, and datasets',       '/archive',        50, 'module', NULL, '#6b7280'),
  ('cyberwiki',  'CyberWiki',            TRUE,  '📖', 'Walkthroughs, playbooks, cheat sheets, and project documentation',       '/wiki',           60, 'module', NULL, '#06b6d4'),
  ('library',    'The Library',          TRUE,  '📚', 'Indexed repository of eBooks, guides, and cybersecurity resources',       '/library',        70, 'module', NULL, '#10b981'),
  ('cyberprobe', 'CyberProbe',           TRUE,  '📡', 'Automated fuzzing and vulnerability discovery environment',              '/cyberprobe',     80, 'module', NULL, '#ec4899'),
  ('ciab',       'Clinic-in-a-Box',      TRUE,  '🏥', 'Cyber risk assessment training with AI-powered interviews and profiles', '/ciab/dashboard', 10, 'plugin', 'crucible', '#1e40af')
ON CONFLICT (key) DO UPDATE SET
  name          = EXCLUDED.name,
  icon          = EXCLUDED.icon,
  description   = EXCLUDED.description,
  entry_url     = EXCLUDED.entry_url,
  display_order = EXCLUDED.display_order,
  category      = EXCLUDED.category,
  parent_module = EXCLUDED.parent_module,
  color         = EXCLUDED.color;
