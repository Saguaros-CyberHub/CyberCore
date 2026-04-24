-- ============================================================================
-- Migration 013: VM Template Catalog (clinic_db)
-- Maps OS strings from real-client intakes → Proxmox template_vmid so the
-- synthesizer can auto-pick templates instead of making the admin type VMIDs.
-- ============================================================================

CREATE TABLE IF NOT EXISTS vm_template_catalog (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  os_family      VARCHAR(32)  NOT NULL,                    -- 'windows_server','windows_client','linux','macos','network'
  os_name        VARCHAR(128) NOT NULL,                    -- 'Windows Server 2022','Windows 11','Ubuntu 22.04'
  os_version     VARCHAR(64),                              -- '2022','11','22.04' — null = any
  template_vmid  INTEGER      NOT NULL,
  node           VARCHAR(64)  NOT NULL DEFAULT 'cyberhub-node-5',
  role_hints     TEXT[]       NOT NULL DEFAULT '{}',       -- pre-installed roles: {dc,file,web,mail,backup}
  preferred      BOOLEAN      NOT NULL DEFAULT true,       -- tiebreaker when multiple rows match
  notes          TEXT,
  is_active      BOOLEAN      NOT NULL DEFAULT true,
  created_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_vmtc_family  ON vm_template_catalog(os_family, is_active);
CREATE INDEX IF NOT EXISTS idx_vmtc_active  ON vm_template_catalog(is_active);

-- Seed reflects the current cyberhub-node-5 template inventory. Gateway
-- templates (1691 cyberlabs, 1692 crucible, 1693 forge) and the attack box
-- (1699 kali) are infrastructure — they do NOT belong here. Only challenge
-- VM templates are catalogued.
INSERT INTO vm_template_catalog (os_family, os_name, os_version, template_vmid, node, role_hints, notes) VALUES
  ('windows_server', 'Windows Server 2022', '2022', 1000, 'cyberhub-node-5', '{dc,file,web,mail,backup,print}', 'windows-server-2022-template — all Windows server roles land here'),
  ('linux',          'Rocky Linux',         NULL,   1001, 'cyberhub-node-5', '{web,file,db}',                   'rocky-linux-template — preferred Linux server for web/file/db roles'),
  ('windows_client', 'Windows 11',          '25H2', 1002, 'cyberhub-node-5', '{}',                              'windows-25h2-template — only Windows client template'),
  ('linux',          'Ubuntu',              NULL,   1003, 'cyberhub-node-5', '{web}',                           'Ubuntu-Template — generic Ubuntu fallback'),
  ('linux',          'Metasploitable 2',    NULL,   1600, 'cyberhub-node-5', '{}',                              'Metasploitable-2-Template — intentionally vulnerable. Admin-select only; never auto-picked by synthesizer (preferred=false).')
ON CONFLICT DO NOTHING;

-- Metasploitable should never be auto-chosen for a real-client Linux — flip preferred off.
UPDATE vm_template_catalog SET preferred = false WHERE template_vmid = 1600;
