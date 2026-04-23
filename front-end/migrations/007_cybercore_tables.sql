-- ============================================================================
-- CYBERCORE: Lane deployment tables
-- ============================================================================
-- Run against the CyberCore database (n8n_db on 100.100.20.50)
-- NOT against clinic_db!
--
-- psql -h 100.100.20.50 -U cactus-admin -d n8n_db -f migrations/007_cybercore_tables.sql
-- ============================================================================

-- Installed modules (e.g., crucible)
CREATE TABLE IF NOT EXISTS cybercore_module (
  key VARCHAR(64) PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  installed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Crucible challenges
CREATE TABLE IF NOT EXISTS crucible_challenge (
  challenge_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  challenge_key VARCHAR(128) NOT NULL UNIQUE,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  difficulty VARCHAR(32) DEFAULT 'beginner',
  spec JSONB NOT NULL DEFAULT '{}',
  status VARCHAR(32) NOT NULL DEFAULT 'active',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Lane tracking
CREATE TABLE IF NOT EXISTS cybercore_lane (
  lane_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id UUID,
  user_id UUID NOT NULL,
  name VARCHAR(255),
  status VARCHAR(32) NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'deploying', 'active', 'suspended', 'error', 'deleted')),
  vxlan_id INTEGER,
  challenge_id UUID REFERENCES crucible_challenge(challenge_id),
  config JSONB NOT NULL DEFAULT '{}',
  team_id UUID,
  lane_group_id UUID,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cybercore_lane_user ON cybercore_lane(user_id);
CREATE INDEX IF NOT EXISTS idx_cybercore_lane_status ON cybercore_lane(status);
CREATE INDEX IF NOT EXISTS idx_cybercore_lane_vxlan ON cybercore_lane(vxlan_id);

-- Seed the crucible module
INSERT INTO cybercore_module (key, name, description)
VALUES ('crucible', 'Crucible', 'CyberHub Crucible challenge module')
ON CONFLICT (key) DO NOTHING;

-- Seed the metasploitable2-basic challenge
INSERT INTO crucible_challenge (challenge_key, name, description, difficulty, spec, status)
VALUES (
  'metasploitable2-basic',
  'Metasploitable 2 - Basic',
  'Basic penetration testing challenge using Metasploitable 2 vulnerable VM',
  'beginner',
  '{
    "template_vmid": 1600,
    "gateway_vmid": 1699,
    "template_node": "cyberhub-node-5",
    "vxlan_block": { "start": 10000, "end": 10009 }
  }'::jsonb,
  'active'
)
ON CONFLICT (challenge_key) DO NOTHING;
