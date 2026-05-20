-- ============================================================================
-- Migration 020: Seed the CyberSaguaros SSRF challenge as an attachable module
-- ============================================================================
-- Consumed by POST /api/admin/lanes/:id/modules. The `attachable: true` flag
-- in spec is enforced by the attach route. The VMID 1703 template is baked by
-- front-end/scripts/bake-cybersaguaros-template.sh before this row can deploy.
--
-- App source is bundled in the CyberCore repo at challenges/cybersaguaros/.
--
-- Schema notes (crucible_challenge):
--   difficulty     — integer 0-5 (3 = intermediate: SSRF chain + filter bypass + LinPE)
--   challenge_type — crucible_challenge_type enum: single_vm | multi_vm | koth | ...
--   status         — crucible_challenge_status enum: draft | active | retired | archived
--
-- Run against the CyberCore database:
--   psql -h <host> -U cactus-admin -d n8n_db -f migrations/020_seed_cybersaguaros_module.sql
-- ============================================================================

INSERT INTO crucible_challenge (challenge_key, name, description, challenge_type, difficulty, module_key, spec, status)
VALUES (
  'cybersaguaros-ssrf',
  'CyberSaguaros — SSRF Research Portal',
  'Custom vulnerable web app (CyberSaguaros cactus research group). SaguaroBot''s dataset integrity check is a readable SSRF -> reach the localhost-only provisioning API -> mint an admin session -> weak "Cloud Storage" upload filter -> PHP webshell RCE -> Linux privesc to root. Foreshadows the GOAD pivot.',
  'single_vm',
  3,
  'crucible',
  '{
    "attachable": true,
    "template_node": "cyberhub-node-5",
    "vms": [
      {
        "name": "cybersaguaros",
        "template_vmid": 1703,
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
