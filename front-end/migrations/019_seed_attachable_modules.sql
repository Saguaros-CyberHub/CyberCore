-- ============================================================================
-- Migration 019: Seed attachable-module challenges (DVWA, OWASP Juice Shop)
-- ============================================================================
-- These rows are consumed by POST /api/admin/lanes/:id/modules to graft
-- single-VM web targets onto an already-running lane. The `attachable: true`
-- flag in spec is enforced by the attach route; standalone deploy-lane
-- ignores it (still works if anyone wants to deploy DVWA as its own lane).
--
-- The VMID 1701 / 1702 templates are baked by:
--   - front-end/scripts/bake-juice-shop-template.sh
--   - front-end/scripts/bake-dvwa-template.sh
-- on a Proxmox node before these rows can actually be deployed.
--
-- IP octets are LEFT UNSET so the attach handler auto-allocates from the
-- attached-module range (.100+). Override per-deploy by editing the vms[]
-- entry if you want deterministic addressing.
--
-- Run against the CyberCore database (where cybercore_lane lives):
--   psql -h <host> -U cactus-admin -d n8n_db -f migrations/019_seed_attachable_modules.sql
-- ============================================================================

-- Schema notes for the columns below:
--   difficulty     — integer (0–5 scale, NULL allowed). 1=beginner, 2=intermediate.
--   challenge_type — crucible_challenge_type enum: single_vm | multi_vm | koth | red_vs_blue | other
--   status         — crucible_challenge_status enum: draft | active | retired | archived

-- OWASP Juice Shop — modern Node/Angular SPA, ~100 web challenges.
-- Single Docker container running on Debian 13. Reach at http://<ip>:80.
INSERT INTO crucible_challenge (challenge_key, name, description, challenge_type, difficulty, module_key, spec, status)
VALUES (
  'juice-shop-v1',
  'OWASP Juice Shop',
  'Modern vulnerable web app (Node/Angular). Covers JWT, NoSQLi, SSRF, prototype pollution, and ~95 other web bugs. Attach to a lane; reach from Kali at http://<lane>.<ip>:80.',
  'single_vm',
  2,
  'crucible',
  '{
    "attachable": true,
    "template_node": "cyberhub-node-5",
    "vms": [
      {
        "name": "juice-shop",
        "template_vmid": 1701,
        "type": "qemu",
        "role": "web"
      }
    ]
  }'::jsonb,
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

-- DVWA — native LAMP install with LinPE primitives planted in the image.
-- Three shell-yielding modules (Command Injection, File Upload, File
-- Inclusion) drop www-data on the box. From there: SUID find, world-writable
-- cron, sudo tar (GTFObins), and planted /opt/credentials.txt with hints
-- pointing at an AD account for later weeks.
INSERT INTO crucible_challenge (challenge_key, name, description, challenge_type, difficulty, module_key, spec, status)
VALUES (
  'dvwa-v1',
  'DVWA + Linux PE',
  'Damn Vulnerable Web Application on Debian 13. Three shell-yielding modules (cmd injection, file upload, RFI) drop www-data on the host. LinPE primitives baked in: SUID find, world-writable cron script, sudo NOPASSWD on tar (devops user). Credentials hint at an AD pivot for later weeks.',
  'single_vm',
  1,
  'crucible',
  '{
    "attachable": true,
    "template_node": "cyberhub-node-5",
    "vms": [
      {
        "name": "dvwa",
        "template_vmid": 1702,
        "type": "qemu",
        "role": "web"
      }
    ]
  }'::jsonb,
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
