-- ============================================================================
-- Migration 014: Separate baseline vs vulnerable scripts (clinic_db)
-- Adds a script_type column so admins + the synthesizer can distinguish
-- "just make the VM realistic" (baseline) from "inject weaknesses"
-- (vulnerable). For real-client intake → challenge synthesis, we prefer
-- baseline scripts since the goal is to mirror the client's actual stack.
-- ============================================================================

ALTER TABLE vuln_scripts
  ADD COLUMN IF NOT EXISTS script_type VARCHAR(16) NOT NULL DEFAULT 'vulnerable';

-- CHECK constraint — add only if not already there so migration re-runs cleanly.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'vuln_scripts_script_type_check') THEN
    ALTER TABLE vuln_scripts
      ADD CONSTRAINT vuln_scripts_script_type_check
      CHECK (script_type IN ('baseline','vulnerable'));
  END IF;
END$$;

CREATE INDEX IF NOT EXISTS idx_vuln_scripts_type ON vuln_scripts(script_type, is_active);

-- Backfill: bootstrap + realism + "deploy a service" scripts are baseline.
-- Everything that injects weaknesses (null sessions, weak perms, plaintext
-- creds, NLA off, xp_cmdshell, etc.) stays 'vulnerable' (the default).
--
-- Baseline candidates reflecting both the original placeholders from 012
-- and the production 'win-*' slugs currently in clinic_db.
UPDATE vuln_scripts SET script_type = 'baseline'
WHERE slug IN (
  -- Original 012 placeholders
  'init-setup',
  'life-artifacts',
  -- Production 'win-*' slugs
  'win-life-artifacts',    -- user+artifact simulation, no vuln injection
  'win-start-ssh',         -- description explicitly says "no vulnerabilities built in"
  'win-owasp-setup',       -- deploys OWASP training apps (vuln lives in the app, not the script)
  'win-owasp-start'
);

-- Explicitly tag the MedAlliance tier-1 lab as vulnerable (it hardcodes SA
-- password, enables xp_cmdshell, anonymous FTP, guest SMB, etc.) so it's
-- never auto-picked by the intake synthesizer.
UPDATE vuln_scripts SET script_type = 'vulnerable'
WHERE slug IN ('win-install-480-services');
