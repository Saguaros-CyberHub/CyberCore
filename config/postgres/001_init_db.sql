-- config/postgres/001_core_init.sql
-- Core schema + core seeds (no library/wiki)

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- === Groups (text key) — must come before users ===
CREATE TABLE IF NOT EXISTS cybercore_group (
  key         TEXT PRIMARY KEY,            -- 'cyberlabs','crucible','forge','university','library','cyberwiki','archive'
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
  guac_password  BYTEA,
  -- Password policy. must_change_password gates session issuance at login;
  -- temp_password_expires_at bounds a credential that was handed out rather
  -- than chosen. Also applied at runtime by ensureProvisioningColumns() in
  -- src/utils/account-provisioning.js, since this script does not re-run on
  -- an existing database. See front-end/migrations/027.
  must_change_password     BOOLEAN NOT NULL DEFAULT FALSE,
  password_changed_at      TIMESTAMPTZ,
  temp_password_expires_at TIMESTAMPTZ,
  activated_at             TIMESTAMPTZ,
  -- Provenance: who minted this account and for which course/group. This is
  -- the authorization key for instructor-scoped credential actions — an
  -- instructor may only touch accounts their own course created.
  provisioned_by   UUID,
  provisioned_via  TEXT,   -- no CHECK: the boot-time DDL re-runs every start
  provisioned_ref  TEXT,   -- course_id or group_id
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_auth_at   TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_cybercore_user_email_lower ON cybercore_user (lower(email));
-- The login lookup matches lower(email) OR lower(username); without this the
-- OR degrades to a sequential scan on every sign-in.
CREATE INDEX IF NOT EXISTS idx_cybercore_user_username_lower ON cybercore_user (lower(username));
CREATE INDEX IF NOT EXISTS idx_cybercore_user_provisioned
  ON cybercore_user (provisioned_via, provisioned_ref) WHERE provisioned_via IS NOT NULL;

-- === User↔Group bridge ===
CREATE TABLE IF NOT EXISTS cybercore_user_group (
  user_id   UUID NOT NULL REFERENCES cybercore_user(user_id) ON DELETE CASCADE,
  group_key TEXT NOT NULL REFERENCES cybercore_group(key) ON DELETE CASCADE,
  PRIMARY KEY (user_id, group_key)
);

-- === Modules (text key) ===
CREATE TABLE IF NOT EXISTS cybercore_module (
  key            TEXT PRIMARY KEY,                -- 'cyberlabs','crucible','forge','university','library','cyberwiki','archive'
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
  -- Lane gateway wan0 transit address on the shared lab VLAN. Allocated by
  -- src/utils/lane-wan-allocator.js; also the Guacamole console host for every
  -- machine in the lane, which is why two lanes must never share one.
  gateway_wan_ip       INET,
  wan_ip_grandfathered BOOLEAN NOT NULL DEFAULT FALSE,
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

-- Same rule for the gateway WAN transit address. It is ALLOCATED, not derived
-- (src/utils/lane-wan-allocator.js) — the old derivation had 240 buckets against
-- monotonically climbing vxlan ids, so two live lanes could share one address on
-- the lab VLAN and one Guacamole console host:port.
--
-- wan_ip_grandfathered exists only for migration 033, which had to bring an
-- existing table that ALREADY contained duplicates under this constraint. A
-- fresh database has none, so nothing here is ever flagged; the column and the
-- predicate clause are kept so both schemas are identical.
CREATE UNIQUE INDEX IF NOT EXISTS ux_cybercore_lane_wan_ip_active
  ON cybercore_lane(gateway_wan_ip)
  WHERE gateway_wan_ip IS NOT NULL
    AND status NOT IN ('error', 'deleted')
    AND wan_ip_grandfathered = FALSE;

-- Address history. cybercore_lane rows are hard-deleted on teardown, so this is
-- the only record of when an address was last in use — which is what lets the
-- allocator prefer the longest-idle address instead of handing a torn-down
-- lane's address straight to the next student. No FK on purpose: cascade would
-- erase exactly the history this exists to keep.
CREATE TABLE IF NOT EXISTS cybercore_lane_wan_lease (
  lease_id     BIGSERIAL PRIMARY KEY,
  wan_ip       INET NOT NULL,
  lane_id      UUID,
  vxlan_id     INTEGER,
  allocated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_lane_wan_lease_ip
  ON cybercore_lane_wan_lease(wan_ip, allocated_at DESC);

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

-- ============================================================================
-- SUPPORT TICKETS
-- ============================================================================
-- Students file these from the sidebar on any page; every active admin is
-- emailed with the course instructor Cc'd. Kept in cybercore_db rather than
-- cle_db because every hot join here is a core table and support history must
-- outlive the CLE plugin being disabled.
--
-- THIS FILE ONLY RUNS ON A FRESH DOCKER VOLUME. Existing deployments get these
-- tables from ensureTicketTables() in front-end/src/utils/tickets.js at boot.
-- Keep the status CHECK byte-identical across both, and across
-- front-end/migrations/034_support_tickets.sql —
-- front-end/test/ticket-schema.test.js asserts it.
-- ============================================================================

-- ── tickets ─────────────────────────────────────────────────────────────────
-- Course and machine are SNAPSHOTS, not references. cle_course lives in cle_db
-- so there is no foreign key to be had, and there is deliberately none to
-- cybercore_lane either: an FK would either block teardownLanes() or, with
-- ON DELETE CASCADE, delete support history when a lane is recycled.
CREATE TABLE IF NOT EXISTS cybercore_ticket (
  ticket_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ticket_number       BIGINT GENERATED ALWAYS AS IDENTITY,

  requester_user_id   UUID REFERENCES cybercore_user(user_id) ON DELETE SET NULL,
  requester_email     TEXT NOT NULL,
  requester_name      TEXT,

  subject             TEXT NOT NULL,
  body                TEXT NOT NULL,
  status              TEXT NOT NULL DEFAULT 'open'
                      CHECK (status IN ('open','in_progress','pending','resolved','closed')),

  course_id           UUID,
  course_name         TEXT,
  course_code         TEXT,
  instructor_user_id  UUID,
  instructor_email    TEXT,

  lane_id             UUID,
  machine_key         TEXT,
  machine_label       TEXT,
  machine_vmid        INTEGER,

  first_response_at   TIMESTAMPTZ,
  resolved_at         TIMESTAMPTZ,
  closed_at           TIMESTAMPTZ,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── thread ──────────────────────────────────────────────────────────────────
-- One table for status changes, staff replies, internal notes and student
-- comments, so a detail view is one ordered query. `visibility` is a separate
-- axis from `kind` on purpose: a new kind must decide its visibility, and the
-- student-facing filter is one predicate rather than a list of kinds to
-- remember.
CREATE TABLE IF NOT EXISTS cybercore_ticket_event (
  event_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ticket_id       UUID NOT NULL REFERENCES cybercore_ticket(ticket_id) ON DELETE CASCADE,

  kind            TEXT NOT NULL CHECK (kind IN ('created','reply','note','comment','status')),
  visibility      TEXT NOT NULL DEFAULT 'public' CHECK (visibility IN ('public','internal')),

  author_user_id  UUID REFERENCES cybercore_user(user_id) ON DELETE SET NULL,
  author_email    TEXT,
  author_name     TEXT,
  author_role     TEXT,

  body            TEXT,
  from_status     TEXT,
  to_status       TEXT,

  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_ticket_number
  ON cybercore_ticket (ticket_number);
CREATE INDEX IF NOT EXISTS idx_ticket_requester
  ON cybercore_ticket (requester_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ticket_instructor
  ON cybercore_ticket (instructor_user_id, created_at DESC)
  WHERE instructor_user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ticket_course
  ON cybercore_ticket (course_id, created_at DESC)
  WHERE course_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ticket_status
  ON cybercore_ticket (status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ticket_active
  ON cybercore_ticket (created_at DESC)
  WHERE status IN ('open','in_progress','pending');
CREATE INDEX IF NOT EXISTS idx_ticket_event_ticket
  ON cybercore_ticket_event (ticket_id, created_at);
CREATE INDEX IF NOT EXISTS idx_ticket_event_public
  ON cybercore_ticket_event (ticket_id, created_at)
  WHERE visibility = 'public';
