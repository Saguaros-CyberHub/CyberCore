-- Migration 026: finish what 025 started — Windows templates that pin an account
-- but NO password.
--
-- 025 moved bake-pinned accounts from default_rdp_user to cloud_init_user, but
-- only for rows that pinned BOTH a user and a password. It left "user, no
-- password" alone, reading it as a deliberate choice: an image whose password is
-- baked and handed to students out of band.
--
-- On a Windows workstation template that reading is wrong, and it fails silently.
-- default_rdp_user disables cloud-init credential injection (see
-- resolveWorkstationCredentials in src/utils/lane-deployer.js), so the deploy
-- publishes a Guacamole connection carrying a username and no password at all —
-- buildGuacParameters only spreads truthy values. The student gets an RDP
-- password prompt for an account whose password nobody has: not CyberCore, which
-- never generated one, and not the instructor, since the bake never produced one
-- to hand out. windows-11-base-template shipped in exactly this state with
-- default_rdp_user='cactus-user', which is the account name its cloudbase-init is
-- pinned to (files/cloudbase-init/cloudbase-init.conf), not a credential.
--
-- cloud_init_user is the correct declaration for that shape: keep the account
-- name the agent is fixed to, generate a fresh password per lane, inject it
-- through cloud-init.
--
-- SCOPE: Windows workstation templates only. A Linux image genuinely shipping a
-- documented static login is a real case and is left alone. If you DO have a
-- Windows template that intentionally ships a handout password, exclude it by
-- template_key before running this — after it runs, that image's account gets a
-- generated password on every lane instead.
--
-- Existing lanes are NOT rewritten: their config still carries the old
-- workstation_user and a null workstation_pass, and their guests still have
-- whatever the bake left on the account. Re-provision to pick up a generated
-- credential.

UPDATE cybercore_template_catalog
   SET metadata = (metadata - 'default_rdp_user' - 'default_rdp_pass')
                  || jsonb_build_object('cloud_init_user', metadata->>'default_rdp_user'),
       updated_at = NOW()
 WHERE template_type = 'workstation'
   AND os_family LIKE 'windows%'
   AND metadata->>'default_rdp_user' IS NOT NULL
   AND metadata->>'default_rdp_pass' IS NULL
   AND metadata->>'cloud_init_user' IS NULL;
