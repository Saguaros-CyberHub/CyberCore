-- ============================================================================
-- Migration 024: Declare guest OS + flag targets on existing challenge specs
-- ============================================================================
-- flag-manager.plantFlagsForLane reads spec.vms[].os to decide whether to talk
-- PowerShell or /bin/sh to a guest, and spec.vms[].flags to override where the
-- files land. Newer seeds (023_seed_copperridge_module.sql) already declare
-- both inline. This migration backfills the specs that predate the flag system.
--
-- STRICTLY ADDITIVE. Every statement only fills in keys that are ABSENT, so:
--   * re-running it is a no-op,
--   * it never overwrites a hand-tuned path, nic_model, or template_vmid,
--   * a spec already carrying `os`/`flags` (Copper Ridge) is left untouched.
-- This matters because challenge specs are edited by hand in parallel with
-- these migrations; a wholesale array replacement here would silently revert
-- that work.
--
-- Two things below are deliberate and must not be "simplified":
--
--   jsonb_exists(vm, KEY) rather than the equivalent question-mark operator.
--   Adminer, JDBC and most driver-level clients treat a question mark as a
--   bind-parameter placeholder and rewrite it before Postgres sees it,
--   producing a syntax error. The function form has no such ambiguity.
--
--   WITH ORDINALITY + ORDER BY, because jsonb_agg has no guaranteed input
--   order. spec.vms order is load-bearing: routes/admin/groups.js falls back to
--   the first entry of deployedVMs when a script selection names no VM, so
--   silently reordering the array would retarget scripts at the wrong host.
--
-- Run against the CyberCore database:
--   psql -h <host> -U cactus-admin -d <cybercore_db> -f migrations/024_challenge_flag_targets.sql
-- ============================================================================


-- ----------------------------------------------------------------------------
-- CyberSaguaros — Linux web target.
--
-- The user flag deliberately lives in the hrivera home dir, NOT saguarobot:
-- webshell lands as saguarobot, and the intended chain is a lateral move to
-- hrivera via the world-readable passphrase-protected deploy key before the
-- user flag is reachable. Planting it as saguarobot would hand the student the
-- flag at RCE and skip that whole step.
--
-- root.txt keeps the default /root/root.txt; the planter writes it 0600
-- root:root, so it genuinely requires the SUID/cron escalation.
-- ----------------------------------------------------------------------------
UPDATE crucible_challenge c
   SET spec = jsonb_set(
         c.spec,
         '{vms}',
         (
           SELECT jsonb_agg(
                    CASE WHEN t.vm->>'name' = 'cybersaguaros'
                         THEN t.vm
                              || CASE WHEN jsonb_exists(t.vm, 'os') THEN '{}'::jsonb
                                      ELSE '{"os":"linux"}'::jsonb END
                              || CASE WHEN jsonb_exists(t.vm, 'flags') THEN '{}'::jsonb
                                      ELSE '{"flags":{"user":{"path":"/home/hrivera/user.txt"},"root":{"path":"/root/root.txt"}}}'::jsonb END
                         ELSE t.vm
                    END
                    ORDER BY t.ord
                  )
             FROM jsonb_array_elements(c.spec->'vms') WITH ORDINALITY AS t(vm, ord)
         ),
         true
       ),
       updated_at = now()
 WHERE c.challenge_key = 'cybersaguaros-ssrf'
   AND jsonb_typeof(c.spec->'vms') = 'array'
   AND jsonb_array_length(c.spec->'vms') > 0;


-- ----------------------------------------------------------------------------
-- Every other challenge VM: tag Windows explicitly where the spec omits it.
-- Every template in the catalog today is Windows except CyberSaguaros, so this
-- is the correct default. A future Linux target must declare "os":"linux" in
-- its own spec (or rely on the get-osinfo probe, which costs a round-trip and
-- returns nothing if the guest agent is not fully up yet).
--
-- VMs that already declare os (Copper Ridge tuc-web01) pass through
-- unchanged.
-- ----------------------------------------------------------------------------
UPDATE crucible_challenge c
   SET spec = jsonb_set(
         c.spec,
         '{vms}',
         (
           SELECT jsonb_agg(
                    CASE WHEN jsonb_exists(t.vm, 'os') THEN t.vm
                         ELSE t.vm || '{"os":"windows"}'::jsonb
                    END
                    ORDER BY t.ord
                  )
             FROM jsonb_array_elements(c.spec->'vms') WITH ORDINALITY AS t(vm, ord)
         ),
         true
       ),
       updated_at = now()
 WHERE c.challenge_key <> 'cybersaguaros-ssrf'
   AND jsonb_typeof(c.spec->'vms') = 'array'
   AND jsonb_array_length(c.spec->'vms') > 0
   -- Skip rows where every VM already declares os, so re-runs touch nothing.
   AND EXISTS (
     SELECT 1 FROM jsonb_array_elements(c.spec->'vms') AS vm
      WHERE NOT jsonb_exists(vm, 'os')
   );


-- ----------------------------------------------------------------------------
-- Verify. Runs as part of the migration so the result set is the confirmation:
-- every challenge VM should report an os, and the two flag-bearing targets
-- should report their explicit paths.
--
-- The jsonb_typeof guard is required, not decorative. Older challenge specs
-- describe a single VM with bare template_vmid/gateway_vmid keys and carry no
-- vms array at all (metasploitable2-basic, and the per-course lab rows created
-- by lab-network-provision.js). jsonb_array_elements raises "cannot extract
-- elements from a scalar/object" the moment it meets one of those, which aborts
-- the whole script.
-- ----------------------------------------------------------------------------
SELECT c.challenge_key,
       t.vm->>'name'              AS vm_name,
       t.vm->>'os'                AS os,
       t.vm#>>'{flags,user,path}' AS user_flag_path,
       t.vm#>>'{flags,root,path}' AS root_flag_path
  FROM crucible_challenge c
  CROSS JOIN LATERAL jsonb_array_elements(c.spec->'vms') AS t(vm)
 WHERE jsonb_typeof(c.spec->'vms') = 'array'
 ORDER BY c.challenge_key, t.vm->>'name';
