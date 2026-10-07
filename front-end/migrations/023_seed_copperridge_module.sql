-- ============================================================================
-- Migration 023: Seed the Copper Ridge FieldOps challenge as an attachable module
-- ============================================================================
-- Consumed by POST /api/admin/lanes/:id/modules. The `attachable: true` flag
-- in spec is enforced by the attach route. The VMID 1704 template is built by
-- hand from a clone of template 1004 before this row can deploy -- see
-- challenges/copperridge-fieldops/BUILD.md.
--
-- App source is bundled in the CyberCore repo at challenges/copperridge-fieldops/.
--
-- This is the range's only Windows *local* privilege escalation target. The
-- CYBV 480 chain teaches Linux PE in week 3 and then jumps straight to AD in
-- weeks 4-6; nothing else covers SeImpersonate, service DACLs, unquoted paths
-- or writable SYSTEM tasks. Deliberately NOT domain-joined -- SYSTEM here must
-- not hand a student machine-account access that short-circuits weeks 4-6.
--
-- Three spec fields are load-bearing and easy to omit:
--
--   nic_model = e1000
--     attached-modules.js buildAttachedNet0() defaults QEMU NICs to virtio
--     because every other attached module is Linux. Stock Windows has no
--     virtio-net driver, so a virtio NIC never gets a DHCP lease and the box
--     is simply unreachable.
--
--   os = windows
--     flag-manager.js plantFlagsForLane() falls back to detectGuestOs() and
--     throws "could not determine guest OS" if that comes back empty.
--
--   flags.user.path
--     The default Windows user-flag planter enumerates C:\Users for a
--     non-builtin profile and hard-fails ("no non-builtin user profile found")
--     when it finds none. This target has no interactive user -- the foothold
--     is the IIS application pool virtual account -- so the path must be
--     explicit. Public\Desktop is readable by the app pool identity once the
--     student has code execution, and is not reachable over HTTP.
--     root.txt keeps the default path; the planter strips inheritance and
--     grants only Administrators + SYSTEM, so it genuinely requires escalation.
--
-- Schema notes (crucible_challenge):
--   difficulty     -- integer 0-5 (3 = intermediate: filter bypass + Windows PE)
--   challenge_type -- crucible_challenge_type enum: single_vm | multi_vm | koth | ...
--   status         -- crucible_challenge_status enum: draft | active | retired | archived
--
-- Keep this spec byte-identical to the matching block in
-- config/postgres/modules/crucible.sql -- both upsert the same challenge_key
-- and whichever applies last wins.
--
-- Run against the CyberCore database:
--   psql -h <host> -U cactus-admin -d n8n_db -f migrations/023_seed_copperridge_module.sql
-- ============================================================================

INSERT INTO crucible_challenge (challenge_key, name, description, challenge_type, difficulty, module_key, spec, status)
VALUES (
  'copperridge-fieldops',
  'Copper Ridge — FieldOps (IIS + Windows PE)',
  'Custom vulnerable ASP.NET app on IIS 10. Directory browsing leaks web.config.bak (.bak is not in requestFiltering''s denied extensions, unlike .config) -> portal login -> case-sensitive upload filter bypass (cmd.AspX) -> webshell as the IIS application pool identity -> SYSTEM via SeImpersonate/PrintSpoofer, a weak service DACL, a writable SYSTEM scheduled task, an unquoted service path, or recovered local-admin credentials.',
  'single_vm',
  3,
  'crucible',
  '{"attachable":true,"template_node":"cyberhub-node-5","vms":[{"name":"tuc-web01","template_vmid":1704,"type":"qemu","role":"web","os":"windows","nic_model":"e1000","flags":{"user":{"path":"C:\\Users\\Public\\Desktop\\user.txt"},"root":{"path":"C:\\Users\\Administrator\\Desktop\\root.txt"}}}]}'::jsonb,
  'active'
)
ON CONFLICT (challenge_key) DO UPDATE
  SET spec = EXCLUDED.spec,
      name = EXCLUDED.name,
      description = EXCLUDED.description,
      challenge_type = EXCLUDED.challenge_type,
      difficulty = EXCLUDED.difficulty,
      module_key = EXCLUDED.module_key,
      status = EXCLUDED.status,
      updated_at = now();

-- ----------------------------------------------------------------------------
-- Template catalog row. Mirrored into the seed block of
-- migrations/013_vm_template_catalog.sql for fresh volumes.
--
-- metadata.nic_model is belt-and-braces: the attach path reads nic_model from
-- the challenge spec above, but lane-deployer.js reads metadata.nic_model if
-- this box is ever deployed as a lane workstation instead of attached.
-- ----------------------------------------------------------------------------
INSERT INTO cybercore_template_catalog
  (os_family, os_name, os_version, template_vmid, role_hints, notes, template_type, metadata)
VALUES
  ('windows_server', 'Windows Server 2019 IIS Target', '2019', 1704, '{web}',
   'copperridge-fieldops-template — challenge target, built from a clone of 1004',
   'challenge', '{"nic_model":"e1000"}'::jsonb)
ON CONFLICT DO NOTHING;

-- Not a general-purpose OS image: never auto-select it for a synthesised lab.
UPDATE cybercore_template_catalog SET preferred = false WHERE template_vmid = 1704;
