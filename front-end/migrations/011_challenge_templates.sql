-- ============================================================================
-- Migration 011: Vuln Scripts & Deployment Tracking (clinic_db only)
-- ============================================================================
-- Run against clinic_db (localhost)
--
-- Challenge definitions live in crucible_challenge (cybercore_db) — not touched here.
-- ============================================================================

-- Vulnerability script library
CREATE TABLE IF NOT EXISTS vuln_scripts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  slug VARCHAR(128) UNIQUE NOT NULL,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  category VARCHAR(100) NOT NULL,
  os_target VARCHAR(50) NOT NULL DEFAULT 'windows',
  difficulty VARCHAR(50) DEFAULT 'intermediate',
  script_content TEXT NOT NULL,
  services_exposed JSONB DEFAULT '[]',
  depends_on TEXT[] DEFAULT '{}',
  estimated_runtime_sec INTEGER DEFAULT 60,
  is_active BOOLEAN DEFAULT true,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Add script_args if table already exists (for scripts that need CLI flags like -Setup -Start)
ALTER TABLE vuln_scripts ADD COLUMN IF NOT EXISTS script_args VARCHAR(500) DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_vuln_scripts_category ON vuln_scripts(category);
CREATE INDEX IF NOT EXISTS idx_vuln_scripts_os ON vuln_scripts(os_target);

-- Per-deployment vuln selections and network state
CREATE TABLE IF NOT EXISTS deployment_vuln_selections (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  lane_id UUID NOT NULL,
  challenge_key VARCHAR(128),
  selected_scripts JSONB NOT NULL DEFAULT '[]',
  deployed_network JSONB DEFAULT '{}',
  profile_id UUID,
  status VARCHAR(50) DEFAULT 'pending',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dvs_lane ON deployment_vuln_selections(lane_id);
CREATE INDEX IF NOT EXISTS idx_dvs_status ON deployment_vuln_selections(status);

-- Add profile_type to profiles table
ALTER TABLE profiles ADD COLUMN IF NOT EXISTS profile_type VARCHAR(50) DEFAULT 'standard';
