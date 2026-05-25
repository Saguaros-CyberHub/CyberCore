-- ============================================================================
-- Migration 013: VM Template Catalog → cybercore_template_catalog
-- Renames the old vm_template_catalog (if it exists) and adds all new columns
-- introduced when the table was unified into the core schema.
--
-- `node` is intentionally nullable — populated at runtime by
-- POST /api/admin/vm-templates/sync-nodes. Never hardcode a node here.
-- ============================================================================

-- Rename old table if it still exists under the old name
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'vm_template_catalog') THEN
    ALTER TABLE vm_template_catalog RENAME TO cybercore_template_catalog;
  END IF;
END$$;

-- Create fresh if neither name existed yet
CREATE TABLE IF NOT EXISTS cybercore_template_catalog (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  os_family     VARCHAR(32)  NOT NULL,
  os_name       VARCHAR(128) NOT NULL,
  os_version    VARCHAR(64),
  template_vmid INTEGER      NOT NULL,
  node          VARCHAR(64),
  template_type VARCHAR(32)  NOT NULL DEFAULT 'os_template',
  template_key  TEXT,
  module_key    TEXT,
  max_instances INTEGER      NOT NULL DEFAULT 10,
  status        TEXT         NOT NULL DEFAULT 'active'
                CHECK (status IN ('draft', 'active', 'retired')),
  description   TEXT,
  metadata      JSONB        NOT NULL DEFAULT '{}'::jsonb,
  role_hints    TEXT[]       NOT NULL DEFAULT '{}',
  preferred     BOOLEAN      NOT NULL DEFAULT true,
  notes         TEXT,
  is_active     BOOLEAN      NOT NULL DEFAULT true,
  created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Ensure node column is nullable (drop old NOT NULL / default if migrating)
ALTER TABLE cybercore_template_catalog ALTER COLUMN node DROP NOT NULL;
ALTER TABLE cybercore_template_catalog ALTER COLUMN node DROP DEFAULT;

-- Add new columns if they don't exist yet (idempotent for partial migrations)
ALTER TABLE cybercore_template_catalog ADD COLUMN IF NOT EXISTS template_type VARCHAR(32) NOT NULL DEFAULT 'os_template';
ALTER TABLE cybercore_template_catalog ADD COLUMN IF NOT EXISTS template_key  TEXT;
ALTER TABLE cybercore_template_catalog ADD COLUMN IF NOT EXISTS module_key    TEXT;
ALTER TABLE cybercore_template_catalog ADD COLUMN IF NOT EXISTS max_instances INTEGER NOT NULL DEFAULT 10;
ALTER TABLE cybercore_template_catalog ADD COLUMN IF NOT EXISTS status        TEXT NOT NULL DEFAULT 'active';
ALTER TABLE cybercore_template_catalog ADD COLUMN IF NOT EXISTS description   TEXT;
ALTER TABLE cybercore_template_catalog ADD COLUMN IF NOT EXISTS metadata      JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE cybercore_template_catalog ADD COLUMN IF NOT EXISTS updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- Drop old workstation_template if it exists (consolidated into cybercore_template_catalog)
DROP TABLE IF EXISTS workstation_template CASCADE;

-- Indexes
CREATE INDEX IF NOT EXISTS idx_cybercore_tc_family ON cybercore_template_catalog(os_family, is_active);
CREATE INDEX IF NOT EXISTS idx_cybercore_tc_active ON cybercore_template_catalog(is_active);
CREATE INDEX IF NOT EXISTS idx_cybercore_tc_type   ON cybercore_template_catalog(template_type, is_active);
CREATE UNIQUE INDEX IF NOT EXISTS idx_cybercore_tc_key
  ON cybercore_template_catalog(template_key) WHERE template_key IS NOT NULL;

-- Seed OS base images (skip if already present)
INSERT INTO cybercore_template_catalog (os_family, os_name, os_version, template_vmid, role_hints, notes, template_type) VALUES
  ('windows_server', 'Windows Server 2022', '2022', 1000, '{dc,file,web,mail,backup,print}', 'windows-server-2022-template', 'os_template'),
  ('linux',          'Rocky Linux',         NULL,   1001, '{web,file,db}',                   'rocky-linux-template',         'os_template'),
  ('windows_client', 'Windows 11',          '25H2', 1002, '{}',                              'windows-25h2-template',        'os_template'),
  ('linux',          'Ubuntu',              NULL,   1003, '{web}',                           'Ubuntu-Template',              'os_template'),
  ('linux',          'Metasploitable 2',    NULL,   1600, '{}',                              'Metasploitable-2-Template — admin-select only', 'os_template')
ON CONFLICT DO NOTHING;

UPDATE cybercore_template_catalog SET preferred = false WHERE template_vmid = 1600;
