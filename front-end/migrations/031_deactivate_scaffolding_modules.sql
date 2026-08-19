-- 031_deactivate_scaffolding_modules.sql
-- Hide the scaffolding modules that only ever served module-placeholder.html.
--
-- Their manifests now ship "active": false, but registerModule() no longer
-- overwrites `active` on conflict (so an admin's toggle survives a restart),
-- which means the manifest value only applies on a first INSERT. Existing
-- deployments already have these rows at active = true, so flip them here.
--
-- Re-enable any of these from Admin -> Settings -> Modules; the change now
-- persists across restarts.
UPDATE cybercore_module
   SET active = FALSE
 WHERE key IN ('cyberlabs', 'forge', 'university', 'archive', 'library', 'cyberwiki');
