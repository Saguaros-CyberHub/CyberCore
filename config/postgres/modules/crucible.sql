-- Crucible (CTF range) module: enabled tables + badges

INSERT INTO module (key, name, active)
VALUES ('crucible', 'The Crucible', TRUE)
ON CONFLICT (key) DO NOTHING;

-- Module tables (enabled)
CREATE TABLE IF NOT EXISTS crucible_event (
  event_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name       TEXT NOT NULL,
  starts_at  TIMESTAMPTZ,
  ends_at    TIMESTAMPTZ,
  metadata   JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS crucible_score (
  score_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id   UUID NOT NULL REFERENCES crucible_event(event_id) ON DELETE CASCADE,
  user_id    UUID NOT NULL REFERENCES app_user(user_id) ON DELETE CASCADE,
  points     INT NOT NULL DEFAULT 0,
  submitted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (event_id, user_id)
);


COMMENT ON TABLE crucible_event IS
  'Crucible CTF events with start/end times and metadata.';

COMMENT ON TABLE crucible_score IS
  'User scores for Crucible events.';

-- Per-user / per-event Crucible lanes (range instances)

-- Lane status enum (idempotent)
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_type WHERE typname = 'crucible_lane_status'
  ) THEN
    CREATE TYPE crucible_lane_status AS ENUM (
      'pending',     -- created, not yet provisioning
      'deploying',   -- provisioning in progress
      'active',      -- ready for use
      'suspended',   -- temporarily disabled
      'error',       -- failed deployment
      'deleted'      -- torn down / archived
    );
  END IF;
END$$;

-- Main lane table
CREATE TABLE IF NOT EXISTS crucible_lane (
  lane_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  event_id   UUID
    REFERENCES crucible_event(event_id)
    ON DELETE CASCADE,

  user_id    UUID NOT NULL
    REFERENCES app_user(user_id)
    ON DELETE CASCADE,

  name       TEXT, -- optional human label

  status     crucible_lane_status NOT NULL DEFAULT 'pending',

  -- Deterministic VXLAN VNI for this lane
  vxlan_id   INTEGER,

  -- Flexible config for networking, VMs, access, flags, etc.
  config     JSONB NOT NULL DEFAULT '{}'::jsonb,

  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Helpful indexes
CREATE INDEX IF NOT EXISTS crucible_lane_event_idx
  ON crucible_lane (event_id);

CREATE INDEX IF NOT EXISTS crucible_lane_user_idx
  ON crucible_lane (user_id);

-- One lane per (event, user) (optional)
CREATE UNIQUE INDEX IF NOT EXISTS crucible_lane_event_user_uniq
  ON crucible_lane (event_id, user_id);

-- Enforce globally unique VXLANs (optional; remove if you don't want this)
CREATE UNIQUE INDEX IF NOT EXISTS crucible_lane_vxlan_unique_idx
  ON crucible_lane (vxlan_id)
  WHERE vxlan_id IS NOT NULL;

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
  event_id   UUID NOT NULL REFERENCES crucible_event(event_id) ON DELETE CASCADE,
  name       TEXT NOT NULL,
  metadata   JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Users belonging to a team
CREATE TABLE IF NOT EXISTS crucible_team_member (
  team_id    UUID NOT NULL REFERENCES crucible_team(team_id) ON DELETE CASCADE,
  user_id    UUID NOT NULL REFERENCES app_user(user_id)      ON DELETE CASCADE,
  role       TEXT, -- "captain", "member", etc.
  joined_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (team_id, user_id)
);

CREATE TABLE IF NOT EXISTS crucible_lane_group (
  lane_group_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id      UUID NOT NULL REFERENCES crucible_event(event_id) ON DELETE CASCADE,
  name          TEXT,
  metadata      JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE crucible_lane
  ADD COLUMN IF NOT EXISTS team_id UUID
    REFERENCES crucible_team(team_id)
    ON DELETE SET NULL;

ALTER TABLE crucible_lane
  ADD COLUMN IF NOT EXISTS lane_group_id UUID
    REFERENCES crucible_lane_group(lane_group_id)
    ON DELETE SET NULL;

ALTER TABLE crucible_lane
  ADD COLUMN IF NOT EXISTS challenge_id UUID
    REFERENCES crucible_challenge(challenge_id)
    ON DELETE SET NULL;

COMMENT ON TABLE crucible_team IS
  'Teams participating in Crucible events.';

COMMENT ON TABLE crucible_team_member IS
  'Users who are members of Crucible teams.';

COMMENT ON TABLE crucible_lane_group IS
  'Groups of lanes within a Crucible event for organizational purposes.';

COMMENT ON TABLE crucible_lane IS
  'Crucible lanes (range instances) with optional team, group, and challenge associations.';

----------------------------------------------------------------------------
-- Module-scoped badges
----------------------------------------------------------------------------
INSERT INTO badge (key, name, description, module_key, active) VALUES
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
  FROM allocation a
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
FROM resource r
JOIN vm_instance vi ON vi.resource_id = r.resource_id
LEFT JOIN vm_template t ON vi.template_id = t.template_id
LEFT JOIN latest_allocations la ON la.resource_id = r.resource_id
LEFT JOIN app_user u ON la.user_id = u.user_id
WHERE r.type = 'vm'
  AND r.module_key = 'crucible';