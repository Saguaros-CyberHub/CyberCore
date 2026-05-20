-- ============================================================================
-- Migration 021: Allow subnet_scheme = 'v3' on crucible_challenge (cybercore_db)
-- ============================================================================
-- Widens the subnet_scheme CHECK constraint (added in migration 015) to permit
-- a third scheme, 'v3' — the segmented "DMZ" lane topology.
--
-- v3 (new challenges, opt-in):
--   - Lane gateway clone source: VMID 1695 (segmented gateway, baked by
--     bake-lane-gateway-v3.sh — 3 NICs: wan0 + ext0 + int0)
--   - Two SDN VNets per lane: an external subnet (Kali + Tailscale BYOD) and an
--     internal subnet (GOAD Active Directory). The gateway NATs both to the
--     internet but firewall-DROPs traffic between them — the attacker must
--     pivot through a dual-homed DMZ host to reach the internal network.
--
-- Existing v1/v2 rows are unaffected.
-- ============================================================================

-- Drop the old constraint (whatever values it allowed) and re-add it with v3.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'crucible_challenge_subnet_scheme_check') THEN
    ALTER TABLE crucible_challenge
      DROP CONSTRAINT crucible_challenge_subnet_scheme_check;
  END IF;

  ALTER TABLE crucible_challenge
    ADD CONSTRAINT crucible_challenge_subnet_scheme_check
    CHECK (subnet_scheme IN ('v1', 'v2', 'v3'));
END$$;
