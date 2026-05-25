-- Crucible (CTF range) module: enabled tables + badges

INSERT INTO cybercore_module (key, name, active)
VALUES ('crucible', 'The Crucible', TRUE)
ON CONFLICT (key) DO NOTHING;

-- Module tables (enabled)

CREATE TABLE IF NOT EXISTS crucible_score (
  score_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id   UUID NOT NULL REFERENCES cybercore_event(event_id) ON DELETE CASCADE,
  user_id    UUID NOT NULL REFERENCES cybercore_user(user_id) ON DELETE CASCADE,
  points     INT NOT NULL DEFAULT 0,
  submitted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (event_id, user_id)
);


COMMENT ON TABLE crucible_score IS
  'User scores for Crucible events.';

-- =====================================================================
-- Crucible challenge catalog
-- Defines reusable challenges: single VMs, multi-VM labs, GOAD-style infra, etc.
-- =====================================================================

-- Challenge type enum (idempotent)
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_type WHERE typname = 'crucible_challenge_type'
  ) THEN
    CREATE TYPE crucible_challenge_type AS ENUM (
      'single_vm',     -- one vulnerable machine
      'multi_vm',      -- small multi-VM scenario
      'koth',          -- king-of-the-hill style target
      'red_vs_blue',   -- red-vs-blue team setup
      'other'          -- anything else
    );
  END IF;
END$$;

-- Challenge status enum (idempotent)
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_type WHERE typname = 'crucible_challenge_status'
  ) THEN
    CREATE TYPE crucible_challenge_status AS ENUM (
      'draft',         -- still being designed
      'active',        -- available for use
      'retired',       -- kept for history but not selectable
      'archived'       -- fully hidden / deprecated
    );
  END IF;
END$$;

-- Main challenge definition table
CREATE TABLE IF NOT EXISTS crucible_challenge (
  challenge_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  -- Short stable key used by code / configs (e.g. 'goad-basic-01')
  challenge_key TEXT NOT NULL UNIQUE,

  -- Human-friendly name
  name          TEXT NOT NULL,

  -- Optional longer description / briefing
  description   TEXT,

  -- What kind of range this is (single VM, GOAD, etc.)
  challenge_type crucible_challenge_type NOT NULL DEFAULT 'single_vm',

  -- Optional difficulty indicator (0–5 or 1–10; up to you how you use it)
  difficulty    INTEGER,

  -- Owning module / logical group (e.g. 'crucible', 'cyberlabs', 'forge')
  module_key    TEXT DEFAULT 'crucible',

  -- Lane gateway subnet scheme this challenge uses.
  --   v1: VMID 1692/1691/1693 lane gateway, shared 192.18.0.0/24 lane subnet,
  --       gateway WAN through per-module transit (100.102.0.0/16). Default for
  --       all pre-existing challenges.
  --   v2: VMID 1694 subnet-agnostic lane gateway, unique
  --       10.<vxlan_high>.<vxlan_low>.0/24 per lane, gateway WAN directly on
  --       lab bridge (100.100.60.<derived>/24). Required for Tailscale BYOAB.
  --   v3: VMID 1695 segmented gateway (wan0 + ext0 + int0). Two SDN VNets per
  --       lane — external (Kali/BYOD) and internal (GOAD AD) — with the gateway
  --       firewall-blocking traffic between them. Forces a DMZ-pivot attack path.
  subnet_scheme VARCHAR(8) NOT NULL DEFAULT 'v1'
                 CHECK (subnet_scheme IN ('v1', 'v2', 'v3')),

  -- JSONB spec that defines the actual infra and scoring model.
  -- Suggested structure:
  -- {
  --   "network": {
  --     "topology": "flat",
  --     "subnets": [
  --       { "cidr": "10.50.10.0/24", "role": "corp" }
  --     ]
  --   },
  --   "vms": [
  --     {
  --       "template_key": "goad-dc-01",
  --       "role": "dc",
  --       "hostname": "dc01.goad.local",
  --       "tags": ["windows", "ad", "dc"]
  --     },
  --     {
  --       "template_key": "goad-ws-01",
  --       "role": "workstation",
  --       "hostname": "ws01.goad.local",
  --       "tags": ["windows", "client"]
  --     }
  --   ],
  --   "flags": [
  --     { "key": "root_flag", "description": "Gain root on target", "points": 100 }
  --   ],
  --   "limits": {
  --     "max_runtime_minutes": 240,
  --     "max_concurrent_lanes": 10
  --   }
  -- }
  spec          JSONB NOT NULL DEFAULT '{}'::jsonb,

  -- Additional free-form metadata: tags, author info, categories, etc.
  metadata      JSONB NOT NULL DEFAULT '{}'::jsonb,

  status        crucible_challenge_status NOT NULL DEFAULT 'draft',

  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE crucible_challenge IS
  'Reusable Crucible challenges (single VM, multi-VM, GOAD-style infra, etc.).';

COMMENT ON COLUMN crucible_challenge.spec IS
  'JSONB spec describing network topology, VM templates, flags, scoring, and limits.';

COMMENT ON COLUMN crucible_challenge.metadata IS
  'Auxiliary metadata such as tags, author, categories, and display options.';

-- Helpful indexes
CREATE INDEX IF NOT EXISTS crucible_challenge_type_idx
  ON crucible_challenge (challenge_type);

CREATE INDEX IF NOT EXISTS crucible_challenge_status_idx
  ON crucible_challenge (status);

CREATE INDEX IF NOT EXISTS crucible_challenge_subnet_scheme_idx
  ON crucible_challenge (subnet_scheme);

-- Optional GIN index if you plan to search by tags in metadata/spec
CREATE INDEX IF NOT EXISTS crucible_challenge_spec_gin_idx
  ON crucible_challenge
  USING GIN (spec);

CREATE INDEX IF NOT EXISTS crucible_challenge_metadata_gin_idx
  ON crucible_challenge
  USING GIN (metadata);

----------------------------------------------------------------------------
-- Teams and lane grouping
----------------------------------------------------------------------------

-- Team that plays in an event
CREATE TABLE IF NOT EXISTS crucible_team (
  team_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id   UUID NOT NULL REFERENCES cybercore_event(event_id) ON DELETE CASCADE,
  name       TEXT NOT NULL,
  metadata   JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Users belonging to a team
CREATE TABLE IF NOT EXISTS crucible_team_member (
  team_id    UUID NOT NULL REFERENCES crucible_team(team_id) ON DELETE CASCADE,
  user_id    UUID NOT NULL REFERENCES cybercore_user(user_id)      ON DELETE CASCADE,
  role       TEXT, -- "captain", "member", etc.
  joined_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (team_id, user_id)
);

CREATE TABLE IF NOT EXISTS crucible_lane_group (
  lane_group_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id      UUID NOT NULL REFERENCES cybercore_event(event_id) ON DELETE CASCADE,
  name          TEXT,
  metadata      JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE cybercore_lane
  ADD COLUMN IF NOT EXISTS team_id UUID
    REFERENCES crucible_team(team_id)
    ON DELETE SET NULL;

ALTER TABLE cybercore_lane
  ADD COLUMN IF NOT EXISTS lane_group_id UUID
    REFERENCES crucible_lane_group(lane_group_id)
    ON DELETE SET NULL;

ALTER TABLE cybercore_lane
  ADD COLUMN IF NOT EXISTS challenge_id UUID
    REFERENCES crucible_challenge(challenge_id)
    ON DELETE SET NULL;

COMMENT ON TABLE crucible_team IS
  'Teams participating in Crucible events.';

COMMENT ON TABLE crucible_team_member IS
  'Users who are members of Crucible teams.';

COMMENT ON TABLE crucible_lane_group IS
  'Groups of lanes within a Crucible event for organizational purposes.';

COMMENT ON TABLE cybercore_lane IS
  'Crucible lanes (range instances) with optional team, group, and challenge associations.';

----------------------------------------------------------------------------
-- Module-scoped badges
----------------------------------------------------------------------------
INSERT INTO cybercore_badge (key, name, description, module_key, active) VALUES
  ('crucible_ctf_scorer', 'CTF Scorer', 'Scored in a Crucible CTF event', 'crucible', TRUE),
  ('crucible_ctf_winner', 'CTF Winner', 'Won a Crucible CTF event', 'crucible', TRUE)
ON CONFLICT (key) DO NOTHING;

CREATE OR REPLACE VIEW crucible_v_vm_state AS
WITH latest_allocations AS (
  SELECT DISTINCT ON (a.resource_id)
         a.resource_id,
         a.allocation_id,
         a.user_id,
         a.group_key,
         a.starts_at,
         a.ends_at,
         a.purpose,
         a.metadata AS allocation_metadata
  FROM cybercore_allocation a
  WHERE a.ends_at IS NULL OR a.ends_at > now()
  ORDER BY a.resource_id, a.starts_at DESC
)
SELECT
  r.resource_id,
  r.module_key,
  r.name AS resource_name,
  r.status AS resource_status,
  vi.vm_instance_id,
  vi.power_state,
  vi.provider,
  vi.provider_node,
  vi.provider_vmid,
  vi.hostname,
  vi.ip_address,
  vi.mac_address,
  vi.vlan_id,
  vi.created_at AS vm_created_at,
  vi.started_at,
  vi.last_seen_at,
  vi.last_state_change,
  vi.auto_sleep_at,
  vi.destroyed_at,
  vi.metadata AS vm_metadata,
  t.template_id,
  t.name AS template_name,
  la.allocation_id,
  la.user_id,
  u.username,
  u.email,
  la.group_key,
  la.starts_at AS allocation_starts_at,
  la.ends_at AS allocation_ends_at,
  la.purpose AS allocation_purpose
FROM cybercore_resource r
JOIN cybercore_vm_instance vi ON vi.resource_id = r.resource_id
LEFT JOIN cybercore_vm_template t ON vi.template_id = t.template_id
LEFT JOIN latest_allocations la ON la.resource_id = r.resource_id
LEFT JOIN cybercore_user u ON la.user_id = u.user_id
WHERE r.type = 'vm'
  AND r.module_key = 'crucible';

-- ============================================================================
-- Attachable lab challenge seeds
-- Consumed by POST /api/admin/lanes/:id/modules. Templates must be baked
-- on a Proxmox node before these rows can deploy. node is resolved at runtime.
-- ============================================================================

INSERT INTO crucible_challenge (challenge_key, name, description, challenge_type, difficulty, module_key, spec, status)
VALUES (
  'juice-shop-v1',
  'OWASP Juice Shop',
  'Modern vulnerable web app (Node/Angular). Covers JWT, NoSQLi, SSRF, prototype pollution, and ~95 other web bugs.',
  'single_vm', 2, 'crucible',
  '{"attachable":true,"vms":[{"name":"juice-shop","template_vmid":1701,"type":"qemu","role":"web"}]}'::jsonb,
  'active'
)
ON CONFLICT (challenge_key) DO UPDATE
  SET spec = EXCLUDED.spec, name = EXCLUDED.name, description = EXCLUDED.description,
      challenge_type = EXCLUDED.challenge_type, difficulty = EXCLUDED.difficulty,
      module_key = EXCLUDED.module_key, status = EXCLUDED.status, updated_at = now();

INSERT INTO crucible_challenge (challenge_key, name, description, challenge_type, difficulty, module_key, spec, status)
VALUES (
  'dvwa-v1',
  'DVWA + Linux PE',
  'Damn Vulnerable Web Application on Debian 13. Three shell-yielding modules with Linux privesc primitives baked in.',
  'single_vm', 1, 'crucible',
  '{"attachable":true,"vms":[{"name":"dvwa","template_vmid":1702,"type":"qemu","role":"web"}]}'::jsonb,
  'active'
)
ON CONFLICT (challenge_key) DO UPDATE
  SET spec = EXCLUDED.spec, name = EXCLUDED.name, description = EXCLUDED.description,
      challenge_type = EXCLUDED.challenge_type, difficulty = EXCLUDED.difficulty,
      module_key = EXCLUDED.module_key, status = EXCLUDED.status, updated_at = now();

INSERT INTO crucible_challenge (challenge_key, name, description, challenge_type, difficulty, module_key, spec, status)
VALUES (
  'cybersaguaros-ssrf',
  'CyberSaguaros — SSRF Research Portal',
  'Custom vulnerable web app. SSRF chain → localhost admin API → session mint → upload filter bypass → PHP webshell → Linux privesc.',
  'single_vm', 3, 'crucible',
  '{"attachable":true,"vms":[{"name":"cybersaguaros","template_vmid":1703,"type":"qemu","role":"web"}]}'::jsonb,
  'active'
)
ON CONFLICT (challenge_key) DO UPDATE
  SET spec = EXCLUDED.spec, name = EXCLUDED.name, description = EXCLUDED.description,
      challenge_type = EXCLUDED.challenge_type, difficulty = EXCLUDED.difficulty,
      module_key = EXCLUDED.module_key, status = EXCLUDED.status, updated_at = now();
