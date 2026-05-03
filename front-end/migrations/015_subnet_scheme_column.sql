-- ============================================================================
-- Migration 015: Add subnet_scheme column to crucible_challenge (cybercore_db)
-- ============================================================================
-- Lets v1 and v2 lane gateways coexist while the v2 architecture is rolled out.
--
-- v1 (default — every existing challenge):
--   - Lane gateway clone source: VMID 1692 (or module-specific 1691/1693)
--   - Lane subnet: 192.18.0.0/24 (shared across all lanes; isolated only by VXLAN)
--   - Gateway WAN: hangs off a per-module transit gateway in 100.102.0.0/16
--
-- v2 (new challenges, opt-in):
--   - Lane gateway clone source: VMID 1694 (subnet-agnostic, baked by
--     bake-lane-gateway-v2.sh — firstboot renders dnsmasq/iptables from
--     the lane's actual lan0 IP at every boot)
--   - Lane subnet: 10.<vxlan_high>.<vxlan_low>.0/24 (unique per lane,
--     globally routable — required for Tailscale BYOAB and multi-subnet labs)
--   - Gateway WAN: hangs directly off the lab network bridge (vmbr0) at
--     100.100.60.<derived>/24, no module transit hop
--
-- Existing rows default to 'v1' so in-flight classes keep working untouched.
-- ============================================================================

ALTER TABLE crucible_challenge
  ADD COLUMN IF NOT EXISTS subnet_scheme VARCHAR(8) NOT NULL DEFAULT 'v1';

-- CHECK constraint — add only if not already there so migration re-runs cleanly.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'crucible_challenge_subnet_scheme_check') THEN
    ALTER TABLE crucible_challenge
      ADD CONSTRAINT crucible_challenge_subnet_scheme_check
      CHECK (subnet_scheme IN ('v1', 'v2'));
  END IF;
END$$;

CREATE INDEX IF NOT EXISTS idx_crucible_challenge_subnet_scheme
  ON crucible_challenge(subnet_scheme);
