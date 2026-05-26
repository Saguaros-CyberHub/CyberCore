-- config/postgres/001_core_init.sql
-- Core schema + core seeds (no library/wiki)

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- === Groups (text key) — must come before users ===
CREATE TABLE IF NOT EXISTS cybercore_group (
  key         TEXT PRIMARY KEY,            -- 'cyberlabs','crucible','forge','university','library','wiki','archive'
  label       TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- === Users ===
CREATE TABLE IF NOT EXISTS cybercore_user (
  user_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username       TEXT NOT NULL UNIQUE,
  email          TEXT NOT NULL,
  first_name     TEXT,
  last_name      TEXT,
  organization   TEXT NOT NULL DEFAULT 'Independent',
  email_verified BOOLEAN NOT NULL DEFAULT FALSE,
  auth_provider  TEXT NOT NULL DEFAULT 'local' CHECK (auth_provider IN ('local','keycloak')),
  password_hash  TEXT,
  password_alg   TEXT,
  status         TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','inactive','suspended','banned','deleted')),
  active         BOOLEAN NOT NULL DEFAULT TRUE,
  role           TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user','student','admin','instructor')),
  group_key      TEXT REFERENCES cybercore_group(key) ON DELETE SET NULL,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_auth_at   TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_cybercore_user_email_lower ON cybercore_user (lower(email));

-- === User↔Group bridge ===
CREATE TABLE IF NOT EXISTS cybercore_user_group (
  user_id   UUID NOT NULL REFERENCES cybercore_user(user_id) ON DELETE CASCADE,
  group_key TEXT NOT NULL REFERENCES cybercore_group(key) ON DELETE CASCADE,
  PRIMARY KEY (user_id, group_key)
);

-- === Modules (text key) ===
CREATE TABLE IF NOT EXISTS cybercore_module (
  key            TEXT PRIMARY KEY,                -- 'cyberlabs','crucible','forge','university','library','wiki','archive'
  name           TEXT NOT NULL,
  icon           TEXT,
  description    TEXT,
  entry_url      TEXT,
  category       TEXT,
  color          TEXT,
  display_order  INTEGER NOT NULL DEFAULT 0,
  active         BOOLEAN NOT NULL DEFAULT TRUE
);

-- === Resources (generic infra objects) ===
CREATE TABLE IF NOT EXISTS cybercore_resource (
  resource_id  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  type         TEXT NOT NULL CHECK (type IN ('vm','network','dataset','vpn_account')),
  module_key   TEXT REFERENCES cybercore_module(key),
  name         TEXT NOT NULL,
  provider_ref TEXT,
  metadata     JSONB NOT NULL DEFAULT '{}'::jsonb,
  status       TEXT NOT NULL DEFAULT 'available' CHECK (status IN ('available','provisioning','allocated','deleting','error','retired')),
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
  event_id   UUID REFERENCES cybercore_event(event_id) ON DELETE CASCADE,
  user_id    UUID NOT NULL REFERENCES cybercore_user(user_id) ON DELETE CASCADE,
  module_key TEXT REFERENCES cybercore_module(key) ON DELETE RESTRICT,
  name       TEXT,
  status     cybercore_lane_status NOT NULL DEFAULT 'pending',
  vxlan_id   INTEGER,
  config     JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_cybercore_lane_event ON cybercore_lane (event_id);
CREATE INDEX IF NOT EXISTS idx_cybercore_lane_user ON cybercore_lane (user_id);
CREATE UNIQUE INDEX IF NOT EXISTS ux_cybercore_lane_event_user ON cybercore_lane (event_id, user_id);
-- Partial: error/deleted lanes release their vxlan_id so retries don't collide.
CREATE UNIQUE INDEX IF NOT EXISTS ux_cybercore_lane_vxlan_active
  ON cybercore_lane(vxlan_id)
  WHERE vxlan_id IS NOT NULL AND status NOT IN ('error', 'deleted');

-- === Core seeds (modules, groups, global badges) ===
BEGIN;

INSERT INTO cybercore_module (key, name, active) VALUES
  ('cyberlabs',  'CyberLabs', TRUE),
  ('crucible',   'The Crucible', TRUE),
  ('forge',      'The Forge', TRUE),
  ('university', 'Saguaros University', TRUE),
  ('library',    'The Library', TRUE),
  ('cyberwiki',  'CyberWiki', TRUE),
  ('archive',    'The Archive', TRUE)
ON CONFLICT (key) DO NOTHING;

INSERT INTO cybercore_group (key, label, created_at) VALUES
  ('cyberlabs',  'CyberLabs', now()),
  ('crucible',   'The Crucible', now()),
  ('forge',      'The Forge', now()),
  ('university', 'Saguaros University', now()),
  ('library',    'The Library', now()),
  ('cyberwiki',  'CyberWiki', now()),
  ('archive',    'The Archive', now())
ON CONFLICT (key) DO NOTHING;

-- Global badges (module_key = NULL)
INSERT INTO cybercore_badge (key, name, description, module_key, icon_url, active) VALUES
  ('member', 'Club Member', 'Verified member of Cyber Saguaros / CyberHub', NULL, NULL, TRUE),
  ('onboarding_complete', 'Onboarding Complete', 'Completed initial onboarding checklist', NULL, NULL, TRUE)
ON CONFLICT (key) DO NOTHING;

COMMIT;

-- === Deployed groups (admin batch-deploy tracking) ===
CREATE TABLE IF NOT EXISTS deployed_groups (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  group_name VARCHAR(255) NOT NULL,
  config     JSONB NOT NULL DEFAULT '{}',
  created_by UUID REFERENCES cybercore_user(user_id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_deployed_groups_name ON deployed_groups(group_name);

-- === Account access schedules (time-gated group accounts) ===
CREATE TABLE IF NOT EXISTS account_schedules (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  group_id       UUID NOT NULL REFERENCES deployed_groups(id) ON DELETE CASCADE,
  active_days    INTEGER[] NOT NULL DEFAULT '{1,2,3,4,5}',  -- 0=Sun … 6=Sat
  active_start   TIME NOT NULL DEFAULT '08:00',
  active_end     TIME NOT NULL DEFAULT '17:00',
  timezone       VARCHAR(50) NOT NULL DEFAULT 'America/Phoenix',
  override_active BOOLEAN DEFAULT NULL,  -- NULL=use schedule, true=force on, false=force off
  override_by    UUID REFERENCES cybercore_user(user_id),
  override_at    TIMESTAMPTZ,
  created_at     TIMESTAMPTZ DEFAULT NOW(),
  updated_at     TIMESTAMPTZ DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_account_schedules_group
  ON account_schedules(group_id);
CREATE INDEX IF NOT EXISTS idx_account_schedules_override
  ON account_schedules(override_active) WHERE override_active IS NOT NULL;

-- === Lane bootstrap tokens (v2 pull-bootstrap, one-shot) ===
CREATE TABLE IF NOT EXISTS lane_bootstrap_tokens (
  vxlan_id    INTEGER PRIMARY KEY,
  wan_ip      INET    NOT NULL,
  payload     JSONB   NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at  TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ,
  consumed_by INET
);
CREATE INDEX IF NOT EXISTS idx_lane_bootstrap_tokens_wan_ip
  ON lane_bootstrap_tokens(wan_ip) WHERE consumed_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_lane_bootstrap_tokens_expires
  ON lane_bootstrap_tokens(expires_at);
COMMENT ON TABLE lane_bootstrap_tokens IS
  'Single-use bootstrap payloads delivered to lane gateways on first boot via GET /api/lane-bootstrap.';

-- === VM Template Catalog ===
-- Unified catalog for all Proxmox VM templates. `template_type` controls which
-- menus/flows consume each row:
--   os_template    — base OS images; CiaB synthesizer auto-picks by os_family/os_version
--   workstation    — user self-provisioning via the Workstations dashboard
--   lane_networking — gateway/networking VMs used by lane deployment logic
--   challenge      — single-VM challenge templates for the Crucible
-- `node` is nullable — populated at runtime by POST /api/admin/vm-templates/sync-nodes.
CREATE TABLE IF NOT EXISTS cybercore_template_catalog (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  os_family     VARCHAR(32)  NOT NULL,   -- 'windows_server','windows_client','linux','macos','network'
  os_name       VARCHAR(128) NOT NULL,   -- display name: 'Windows Server 2022', 'Engineering Workstation', etc.
  os_version    VARCHAR(64),             -- '2022','11','22.04' — null = any version
  template_vmid INTEGER      NOT NULL,
  node          VARCHAR(64),             -- populated by sync-nodes, never seeded

  -- Type/classification
  template_type VARCHAR(32)  NOT NULL DEFAULT 'os_template',
  provider_type VARCHAR(8)   CHECK (provider_type IN ('qemu', 'lxc')),  -- auto-detected on verify; null = unknown
  template_key  TEXT,                    -- stable slug (required for workstation/lane_networking rows)
  module_key    TEXT REFERENCES cybercore_module(key) ON DELETE SET NULL,
  max_instances INTEGER      NOT NULL DEFAULT 10,
  status        TEXT         NOT NULL DEFAULT 'active'
                CHECK (status IN ('draft', 'active', 'retired')),
  description   TEXT,                    -- user-facing description
  metadata      JSONB        NOT NULL DEFAULT '{}'::jsonb,

  role_hints    TEXT[]       NOT NULL DEFAULT '{}',
  preferred     BOOLEAN      NOT NULL DEFAULT true,
  notes         TEXT,                    -- admin-facing notes / Proxmox template name
  is_active     BOOLEAN      NOT NULL DEFAULT true,
  created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_cybercore_tc_family ON cybercore_template_catalog(os_family, is_active);
CREATE INDEX IF NOT EXISTS idx_cybercore_tc_active ON cybercore_template_catalog(is_active);
CREATE INDEX IF NOT EXISTS idx_cybercore_tc_type   ON cybercore_template_catalog(template_type, is_active);
CREATE UNIQUE INDEX IF NOT EXISTS idx_cybercore_tc_key
  ON cybercore_template_catalog(template_key) WHERE template_key IS NOT NULL;

-- Seed: OS base images (template_type = 'os_template'). Node resolved at runtime via sync-nodes.
INSERT INTO cybercore_template_catalog (os_family, os_name, os_version, template_vmid, role_hints, notes, template_type) VALUES
  ('windows_server', 'Windows Server 2022', '2022', 1000, '{dc,file,web,mail,backup,print}', 'windows-server-2022-template', 'os_template'),
  ('linux',          'Rocky Linux',         NULL,   1001, '{web,file,db}',                   'rocky-linux-template',         'os_template'),
  ('windows_client', 'Windows 11',          '25H2', 1002, '{}',                              'windows-25h2-template',        'os_template'),
  ('linux',          'Ubuntu',              NULL,   1003, '{web}',                           'Ubuntu-Template',              'os_template'),
  ('linux',          'Metasploitable 2',    NULL,   1600, '{}',                              'Metasploitable-2-Template — admin-select only', 'os_template')
ON CONFLICT DO NOTHING;
UPDATE cybercore_template_catalog SET preferred = false WHERE template_vmid = 1600;