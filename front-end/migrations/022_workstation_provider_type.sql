-- Migration 022: Add provider_type to cybercore_template_catalog
-- Tracks whether a workstation template is a QEMU VM or LXC container.
-- NULL means not yet auto-detected; the verify endpoint populates it on first Test.
ALTER TABLE cybercore_template_catalog
  ADD COLUMN IF NOT EXISTS provider_type VARCHAR(8)
  CHECK (provider_type IN ('qemu', 'lxc'));

-- Assume existing templates are QEMU (all prior workstation templates were VMs)
UPDATE cybercore_template_catalog
  SET provider_type = 'qemu'
  WHERE template_type = 'workstation' AND provider_type IS NULL;
