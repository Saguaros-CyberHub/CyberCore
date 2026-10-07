-- ============================================================================
-- Migration 030: Topology model in crucible_challenge.spec (cybercore_db)
-- ============================================================================
-- No table changes. `spec` is JSONB, so the topology canvas needs no DDL to
-- store what it authors — this migration exists to WRITE THE SHAPE DOWN, the
-- same way migration 009 documented spec.vms[] when multi-VM support landed.
--
-- It does add column comments, so the contract is discoverable from psql (\d+)
-- and not only from a file in the repo.
--
-- ---------------------------------------------------------------------------
-- What the canvas adds
-- ---------------------------------------------------------------------------
--
-- 1. spec.network — the segments a challenge draws on, plus canvas positions.
--
--    "network": {
--      "version": 1,
--      "segments": [
--        { "id": "ext", "role": "external", "label": "External / Attacker" },
--        { "id": "int", "role": "internal", "label": "Internal / Corp" }
--      ],
--      "layout": { "ext": {"x":120,"y":80}, "int": {"x":120,"y":420} }
--    }
--
--    Segment ids are DERIVED FROM subnet_scheme, never free-typed:
--      v1 / v2 → exactly one segment, id 'lan'
--      v3      → exactly two, id 'ext' (external) and 'int' (internal)
--    They are stored as a LIST rather than fixed keys so an N-segment gateway
--    later is an extra array entry, not a schema change.
--
--    `layout` is cosmetic. Losing it costs node positions, nothing else — the
--    renderer falls back to an automatic layout.
--
-- 2. spec.vms[].nics — explicit network attachment, in NIC order.
--
--    { "name": "web01", "template_vmid": 1601, "type": "qemu",
--      "vm_offset": 620000,
--      "nics": [ { "segment": "ext" }, { "segment": "int" } ],
--      "layout": { "x": 300, "y": 200 } }
--
--    nics[] order maps positionally to net0, net1, … — the same order the
--    dual-homed DMZ host has always used.
--
-- ---------------------------------------------------------------------------
-- Backward compatibility
-- ---------------------------------------------------------------------------
-- Both keys are OPTIONAL and every existing challenge lacks them.
--
-- utils/lane-networking.resolveVmNics is the single owner of the translation:
--   nics[] present → honoured as authored
--   nics[] absent  → the historical derivation runs unchanged
--                    (v3 + role 'dmz' + qemu → ext then int;
--                     v3 + GOAD-matched name → int;
--                     everything else → ext on v3, lan on v1/v2)
--
-- test/topology-nics.test.js asserts the derivation path emits byte-identical
-- Proxmox config to the five inline copies it replaced. So this migration is
-- safe to apply to a live database with no coordinated deploy: nothing reads
-- these keys until a challenge is opened in the canvas and saved.
--
-- The editor also writes nics[] ONLY when the authored placement differs from
-- what the derivation would produce anyway, so opening an existing challenge
-- and saving it does not rewrite every row.
--
-- ---------------------------------------------------------------------------
-- Rollback
-- ---------------------------------------------------------------------------
-- Deleting the keys reverts every challenge to derived placement:
--
--   UPDATE crucible_challenge SET spec = spec - 'network';
--   UPDATE crucible_challenge
--      SET spec = jsonb_set(spec, '{vms}', (
--            SELECT jsonb_agg((vm - 'nics') - 'layout')
--            FROM jsonb_array_elements(spec->'vms') AS vm))
--    WHERE spec ? 'vms' AND jsonb_typeof(spec->'vms') = 'array';
--
-- ============================================================================

COMMENT ON COLUMN crucible_challenge.spec IS
  'Challenge definition (JSONB). Keys: vms[] (machines; each may carry nics[] '
  'for explicit network attachment in net0..netN order, and layout for canvas '
  'position), network (segments[] + layout — see migration 030), goad, flags, '
  'phantom_assets, vxlan_block, zone, template_vmid (legacy single-VM). '
  'Attachment is resolved by utils/lane-networking.resolveVmNics: explicit '
  'nics[] win, otherwise the historical name/role derivation applies.';

COMMENT ON COLUMN crucible_challenge.subnet_scheme IS
  'v1/v2 = one lane segment (id "lan"); v3 = two (ids "ext" and "int", '
  'firewall-separated by the 1695 gateway). Determines which segment ids '
  'spec.vms[].nics[].segment may reference.';
