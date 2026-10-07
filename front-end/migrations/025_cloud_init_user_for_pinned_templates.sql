-- Migration 025: Move bake-pinned accounts from default_rdp_user to cloud_init_user
--
-- metadata.default_rdp_user means "this image bakes its own account AND its own
-- password; use both verbatim and inject nothing" — see resolveWorkstationCredentials
-- in src/utils/lane-deployer.js. Setting it disables cloud-init credential
-- injection entirely: cipassword is never written, so Proxmox shows no password
-- after clone, and every lane from that template displays the SAME static string.
--
-- The Windows 11 base template was registered that way with the Packer build
-- credentials (winrm_username / winrm_password from the packer vars — the account
-- used to reach the image over WinRM during the bake, not a credential meant to
-- reach students). Result: the bake secret was rendered in the instructor UI for
-- every student, the password matched the guest only for as long as the bake
-- password survived on the account, and there was no per-student isolation.
--
-- The correct declaration for these images is metadata.cloud_init_user. That image's
-- cloudbase-init is pinned at BAKE time to one account (files/cloudbase-init/
-- cloudbase-init.conf carries `username=cactus-user`), and such an agent can only
-- set THAT account's password on first boot — it cannot create or rename one after
-- templating. So: keep the account name, generate a fresh password per lane, inject
-- it through cloud-init. Per-lane isolation is restored; the account name is
-- unchanged because it cannot change.
--
-- Only rows that pin BOTH a user and a password are touched, and only where
-- cloud_init_user is not already set — a template deliberately configured with a
-- baked user and no password is a different (legitimate) case and is left alone.
--
-- Existing lanes are NOT rewritten: their config still carries the old
-- workstation_user/workstation_pass, and their guests still have whatever password
-- is actually on the account. Re-provision to pick up a generated credential.

UPDATE cybercore_template_catalog
   SET metadata = (metadata - 'default_rdp_user' - 'default_rdp_pass')
                  || jsonb_build_object('cloud_init_user', metadata->>'default_rdp_user'),
       updated_at = NOW()
 WHERE template_type = 'workstation'
   AND metadata->>'default_rdp_user' IS NOT NULL
   AND metadata->>'default_rdp_pass' IS NOT NULL
   AND metadata->>'cloud_init_user' IS NULL;
