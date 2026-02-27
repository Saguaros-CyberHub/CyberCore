-- config/postgres/001_core_init.sql
-- Core schema + core seeds (no library/wiki)

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- === Users ===
CREATE TABLE IF NOT EXISTS cybercore_user (
  user_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username       TEXT NOT NULL UNIQUE,
  email          TEXT NOT NULL,
  first_name     TEXT,
  last_name      TEXT,
  auth_provider  TEXT NOT NULL DEFAULT 'local' CHECK (auth_provider IN ('local','keycloak')),
  password_hash  TEXT,
  password_alg   TEXT,
  status         TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','inactive','suspended','banned','deleted')),
  active         BOOLEAN NOT NULL DEFAULT TRUE,
  role           TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user','student','admin','instructor')),
  group_key      TEXT REFERENCES app_group(key) ON DELETE SET NULL,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_auth_at   TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_cybercore_user_email_lower ON cybercore_user (lower(email));

-- === Groups (text key) ===
CREATE TABLE IF NOT EXISTS cybercore_group (
  key         TEXT PRIMARY KEY,            -- 'cyberlabs','crucible','forge','university','library','wiki'
  label       TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- === User↔Group bridge ===
CREATE TABLE IF NOT EXISTS cybercore_user_group (
  user_id   UUID NOT NULL REFERENCES cybercore_user(user_id) ON DELETE CASCADE,
  group_key TEXT NOT NULL REFERENCES cybercore_group(key) ON DELETE CASCADE,
  PRIMARY KEY (user_id, group_key)
);

-- === Modules (text key) ===
CREATE TABLE IF NOT EXISTS cybercore_module (
  key     TEXT PRIMARY KEY,                -- 'cyberlabs','crucible','forge','university','library','wiki'
  name    TEXT NOT NULL,
  active  BOOLEAN NOT NULL DEFAULT TRUE
);

-- === Resources (generic infra objects) ===
CREATE TABLE IF NOT EXISTS cybercore_resource (
  resource_id  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  type         TEXT NOT NULL CHECK (type IN ('vm','network','dataset','vpn_account')),
  module_key   TEXT REFERENCES cybercore_module(key),
  name         TEXT NOT NULL,
  provider_ref TEXT,
  metadata     JSONB NOT NULL DEFAULT '{}'::jsonb,
  status       TEXT NOT NULL DEFAULT 'available' CHECK (status IN ('available','provisioning','allocated','error','retired')),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (module_key, name)
);

-- === Allocations ===
CREATE TABLE IF NOT EXISTS cybercore_allocation (
  allocation_id  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  resource_id    UUID NOT NULL REFERENCES cybercore_resource(resource_id) ON DELETE CASCADE,
  user_id        UUID REFERENCES cybercore_user(user_id) ON DELETE SET NULL,
  group_key      TEXT REFERENCES cybercore_group(key) ON DELETE SET NULL,
  starts_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  ends_at        TIMESTAMPTZ,
  purpose        TEXT,
  quota_units    INTEGER,
  metadata       JSONB NOT NULL DEFAULT '{}'::jsonb,
  CHECK (user_id IS NOT NULL OR group_key IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS idx_cybercore_allocation_user     ON cybercore_allocation(user_id);
CREATE INDEX IF NOT EXISTS idx_cybercore_allocation_group    ON cybercore_allocation(group_key);
CREATE INDEX IF NOT EXISTS idx_cybercore_allocation_resource ON cybercore_allocation(resource_id);

-- === Badges / Achievements ===
CREATE TABLE IF NOT EXISTS cybercore_badge (
  badge_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  key         TEXT NOT NULL UNIQUE,        -- e.g., 'member','onboarding_complete'
  name        TEXT NOT NULL,
  description TEXT,
  module_key  TEXT REFERENCES cybercore_module(key), -- NULL = global badge
  icon_url    TEXT,
  active      BOOLEAN NOT NULL DEFAULT TRUE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS cybercore_user_badge (
  user_id    UUID NOT NULL REFERENCES cybercore_user(user_id) ON DELETE CASCADE,
  badge_id   UUID NOT NULL REFERENCES cybercore_badge(badge_id) ON DELETE CASCADE,
  earned_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  awarded_by UUID REFERENCES cybercore_user(user_id),
  metadata   JSONB NOT NULL DEFAULT '{}'::jsonb,
  PRIMARY KEY (user_id, badge_id)
);
CREATE INDEX IF NOT EXISTS idx_cybercore_user_badge_user  ON cybercore_user_badge(user_id);
CREATE INDEX IF NOT EXISTS idx_cybercore_user_badge_badge ON cybercore_user_badge(badge_id);

-- === VM Templates (shared) ===
CREATE TABLE IF NOT EXISTS cybercore_vm_template (
  template_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  module_key           TEXT REFERENCES cybercore_module(key),
  name                 TEXT NOT NULL,
  role                 TEXT,
  default_runtime_min  INTEGER,
  metadata             JSONB NOT NULL DEFAULT '{}'::jsonb,
  active               BOOLEAN NOT NULL DEFAULT TRUE,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (module_key, name)
);

-- === VM Instances (shared) ===
CREATE TABLE IF NOT EXISTS cybercore_vm_instance (
  vm_instance_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  resource_id        UUID NOT NULL UNIQUE REFERENCES cybercore_resource(resource_id) ON DELETE CASCADE,
  template_id        UUID REFERENCES cybercore_vm_template(template_id) ON DELETE SET NULL,

  power_state        TEXT,
  provider           TEXT,
  provider_node      TEXT,
  provider_vmid      TEXT,

  hostname           TEXT,
  ip_address         INET,
  mac_address        TEXT,
  vlan_id            INTEGER,

  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  started_at         TIMESTAMPTZ,
  last_seen_at       TIMESTAMPTZ,
  last_state_change  TIMESTAMPTZ,
  auto_sleep_at      TIMESTAMPTZ,
  destroyed_at       TIMESTAMPTZ,

  metadata           JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_cybercore_vm_instance_template ON cybercore_vm_instance(template_id);
CREATE INDEX IF NOT EXISTS idx_cybercore_vm_instance_provider ON cybercore_vm_instance(provider, provider_node);

-- === CyberCore Events & Lanes ===
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_type WHERE typname = 'cybercore_lane_status'
  ) THEN
    CREATE TYPE cybercore_lane_status AS ENUM (
      'pending',     -- created, not yet provisioning
      'deploying',   -- provisioning in progress
      'active',      -- ready for use
      'suspended',   -- temporarily disabled
      'error',       -- failed deployment
      'deleted'      -- torn down / archived
    );
  END IF;
END$$;

CREATE TABLE IF NOT EXISTS cybercore_event (
  event_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name       TEXT NOT NULL,
  starts_at  TIMESTAMPTZ,
  ends_at    TIMESTAMPTZ,
  metadata   JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS cybercore_lane (
  lane_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  event_id   UUID
    REFERENCES cybercore_event(event_id)
    ON DELETE CASCADE,

  user_id    UUID NOT NULL
    REFERENCES cybercore_user(user_id)
    ON DELETE CASCADE,

  name       TEXT, -- optional human label

  status     cybercore_lane_status NOT NULL DEFAULT 'pending',

  -- Deterministic VXLAN VNI for this lane
  vxlan_id   INTEGER,

  -- Flexible config for networking, VMs, access, flags, etc.
  config     JSONB NOT NULL DEFAULT '{}'::jsonb,

  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_cybercore_lane_event ON cybercore_lane (event_id);
CREATE INDEX IF NOT EXISTS idx_cybercore_lane_user ON cybercore_lane (user_id);
CREATE UNIQUE INDEX IF NOT EXISTS ux_cybercore_lane_event_user ON cybercore_lane (event_id, user_id);
CREATE UNIQUE INDEX IF NOT EXISTS ux_cybercore_lane_vxlan ON cybercore_lane (vxlan_id) WHERE vxlan_id IS NOT NULL;

-- === Core seeds (modules, groups, global badges) ===
BEGIN;

INSERT INTO cybercore_module (key, name, active) VALUES
  ('cyberlabs',  'CyberLabs', TRUE),
  ('crucible',   'The Crucible', TRUE),
  ('forge',      'The Forge', TRUE),
  ('university', 'Saguaros University', TRUE),
  ('library',    'The Library', TRUE),
  ('cyberwiki',  'CyberWiki', TRUE)
ON CONFLICT (key) DO NOTHING;

INSERT INTO cybercore_group (key, label, created_at) VALUES
  ('cyberlabs',  'CyberLabs', now()),
  ('crucible',   'The Crucible', now()),
  ('forge',      'The Forge', now()),
  ('university', 'Saguaros University', now()),
  ('library',    'The Library', now()),
  ('cyberwiki',  'CyberWiki', now())
ON CONFLICT (key) DO NOTHING;

-- Global badges (module_key = NULL)
INSERT INTO cybercore_badge (key, name, description, module_key, icon_url, active) VALUES
  ('member', 'Club Member', 'Verified member of Cyber Saguaros / CyberHub', NULL, NULL, TRUE),
  ('onboarding_complete', 'Onboarding Complete', 'Completed initial onboarding checklist', NULL, NULL, TRUE)
ON CONFLICT (key) DO NOTHING;

COMMIT;