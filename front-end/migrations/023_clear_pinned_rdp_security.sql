-- Migration 023: Drop the 'tls' RDP security mode pinned onto workstation templates
--
-- The admin template form used to write metadata.rdp_security on EVERY save, with
-- 'tls' as the first (default-selected) option. So any template ever saved through
-- that form carries rdp_security='tls' whether or not anyone chose it — including
-- templates registered before the field meant anything.
--
-- That pinned value beats lane-deployer's own default of 'any' in
-- buildGuacParameters, and 'tls' fails outright against xrdp and against NLA-only
-- Windows: the Guacamole console never completes its handshake. Removing the key
-- (rather than rewriting it to 'any') restores "unset means negotiate", so the
-- deployer's default governs and a future change to that default is not silently
-- overridden by stale rows.
--
-- Only 'tls' is cleared. A template explicitly set to nla/rdp/any is left alone:
-- those are deliberate overrides, and this migration cannot tell an intentional
-- 'tls' from the form's default — but an intentional one can be re-selected in
-- the form, whereas a broken console is not self-diagnosing.

UPDATE cybercore_template_catalog
   SET metadata   = metadata - 'rdp_security',
       updated_at = NOW()
 WHERE template_type = 'workstation'
   AND metadata->>'rdp_security' = 'tls';
