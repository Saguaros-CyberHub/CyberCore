-- 015_ciab_profile_bake.sql — Track G, phase G5: one immutable, versioned bake
-- per (client, compiled environment).
--
-- ON THE FILE NUMBER: src/plugin-loader.js:135-137 runs this directory
-- `.sort()`ed by FILENAME, so the three digits ARE the ordering and two files
-- sharing them both run, in an order nothing promises. This was drafted as 011,
-- which 011_ciab_engagement_model.sql already holds; test/ciab-module-spine.test.js
-- pins prefix uniqueness across the directory, and its comment records that the
-- module spine migration was renumbered to 014 for exactly this reason. Hence 015.
--
-- ----------------------------------------------------------------------------
-- WHY A BAKE IS A ROW AT ALL
-- ----------------------------------------------------------------------------
-- A GOAD environment is not built by one command. It is 16 separate
-- ansible-playbook invocations chained by playbooks.yml, and nothing in
-- vulnerabilities.yml — the last link — is so much as PARSED until roughly 95%
-- of a ~90-minute run has already been paid for. Today the only durable trace of
-- all of that is a single terminal write, up to two hours after it started, so a
-- bake that is working and a bake that is hung are the same row.
--
-- Worse, the failure mode this whole pipeline exists to handle is SILENCE. An
-- audit of the vendored role library found 20 sites where a task reports SUCCESS
-- and did nothing at all — three of them shipped vulnerabilities that simply are
-- not present on the finished machine (vulns/adcs_esc7's module guard is
-- inverted, move_to_ou swallows its own lookup into `> $null`, no_ldap_signing
-- writes a registry path Windows does not read). Tree-wide, `changed_when`
-- appears TWICE and `error_action: stop` six times, so neither "changed" nor the
-- exit code carries information. A green run is not evidence.
--
-- So a bake needs three things a fire-and-forget script cannot have:
--
--   1. DURABLE PROGRESS. status + phase_detail are written as each phase starts
--      and as it reports, so an operator can tell minute 70 from a hang. The
--      column is deliberately named phase_detail to match
--      ciab_profile_lane_jobs.phase_detail (migration 006), which the admin UI
--      already polls and renders — a second status channel would mean a second
--      renderer and a second thing to keep true.
--
--   2. A VERSION IDENTITY. lab_hash is the content hash of the compiled IR, and
--      it — not a timestamp, not the row's own id — is what "this environment"
--      means. UNIQUE (profile_id, lab_hash) is therefore the whole point of the
--      table: re-baking identical content is a NO-OP that finds the existing
--      row, and editing the profile produces a DIFFERENT hash and therefore a
--      NEW row. That is what makes "immutable versioned bakes" true rather than
--      aspirational, and it is what drift detection is measured against
--      (assertBakeDeployable in utils/bake-orchestrator.js).
--
--   3. EVIDENCE THAT SOMEONE LOOKED. The three gate_* columns and their
--      approval stamp are the human counterweight to a toolchain that reports
--      green while planting nothing.
--
-- ----------------------------------------------------------------------------
-- CROSS-DB, as everywhere else in this plugin
-- ----------------------------------------------------------------------------
-- staging_lane_id points at cybercore_db.cybercore_lane, which this migration
-- cannot reach (it runs against clinic_db). Bare UUID, no foreign key — the same
-- pattern ciab_profile_lane_groups uses for lane_id and ciab_engagement uses for
-- challenge_id. created_by / gates_approved_by are cybercore_user.user_id for the
-- same reason.
--
-- Every plugin migration re-runs on every boot as ONE implicit transaction per
-- file, so everything here must stay idempotent.

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS ciab_profile_bake (
  bake_id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  profile_id       UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,

  -- THE VERSION IDENTITY. A content hash of the compiled IR, lowercase hex.
  --
  -- The alphabet is constrained rather than left as free TEXT because the hash
  -- does not stay in this column: lab_name below is 'CIAB-' plus its first eight
  -- characters, and that string becomes a DIRECTORY NAME under ad/ on the
  -- controller AND a key in playbooks.yml. Hex is the only alphabet that is safe
  -- in both by construction — a base64 digest would carry '/' and '+', and the
  -- failure would land ninety minutes into a bake as a path that does not exist
  -- rather than here.
  lab_hash         TEXT NOT NULL CHECK (lab_hash ~ '^[0-9a-f]{8,64}$'),

  -- 'CIAB-<first 8 of lab_hash>'. DERIVED, never authored — labNameForHash() in
  -- utils/bake-orchestrator.js is the single derivation. It is STORED rather
  -- than recomputed on read so that a later change to the naming rule cannot
  -- retroactively rename a directory that already exists on a controller.
  lab_name         TEXT NOT NULL,

  -- The pinned GOAD commit this environment was built from, as a full 40-char
  -- SHA. Without it the bake is not reproducible, and a branch name here would
  -- defeat the entire point of pinning — see the header of
  -- test/ciab-goad-role-manifest.test.js, which pins the same property on the
  -- vendored manifest and on the controller bake script.
  goad_ref         TEXT NOT NULL CHECK (goad_ref ~ '^[0-9a-f]{40}$'),

  -- The vendored role manifest the compiled lab was validated against. A bake
  -- validated against one role library and run against another is the exact
  -- shape of failure the manifest exists to prevent, and it fails QUIETLY.
  manifest_sha     TEXT NOT NULL,

  -- The compiled IR the lanes will clone with: spec.goad.lab, the fixed subnet
  -- the golden templates were built on, and the subnet scheme. Stored whole,
  -- because a lane cloned from these templates has to be addressed exactly as
  -- the templates were baked.
  spec             JSONB NOT NULL CHECK (jsonb_typeof(spec) = 'object'),

  -- The staging lane the bake runs on, so recovery can FIND it. Written the
  -- moment they are known, never at the end: a bake that dies mid-provision with
  -- these unwritten has leaked a whole lane plus a controller VM that nothing in
  -- this system can enumerate afterwards.
  staging_lane_id  UUID,
  staging_vxlan_id INTEGER,
  controller_vmid  INTEGER,

  status           VARCHAR(24) NOT NULL DEFAULT 'pending'
                     CHECK (status IN ('pending','compiling','pushing','provisioning',
                                       'verifying','capturing','ready','failed','superseded')),

  -- Durable progress. Same name and same job as ciab_profile_lane_jobs.phase_detail
  -- (migration 006) — the admin UI already polls and renders that field.
  phase_detail     TEXT,
  error            TEXT,

  -- What the verifier actually found on the built machines, and the BloodHound
  -- collection it walked. These are the answer to "did one of the twenty silent
  -- no-ops happen to us this time", so they are kept whole rather than reduced
  -- to a boolean.
  verify_report    JSONB,
  bh_report        JSONB,

  -- ── THE GATES ─────────────────────────────────────────────────────────────
  -- DELIBERATELY NULLABLE, with no default. Three states, all distinct:
  --   NULL   nobody has reviewed this yet
  --   FALSE  someone reviewed it and it did NOT pass
  --   TRUE   someone reviewed it and it passed
  -- A `NOT NULL DEFAULT FALSE` would collapse the first two, and "reviewed and
  -- rejected" is evidence worth keeping distinct from "never looked at" when the
  -- question is why an environment was never approved.
  --
  -- gates_approved_at is stamped only when all three are TRUE; it is the single
  -- fact assertBakeDeployable treats as sign-off.
  gate_solvable      BOOLEAN,
  gate_paper         BOOLEAN,
  gate_no_unintended BOOLEAN,
  gates_approved_by  UUID,
  gates_approved_at  TIMESTAMPTZ,

  -- The captured template VMIDs, so teardown can find them. A half-captured set
  -- on a failed bake is otherwise a permanent, invisible storage leak.
  golden_vmids     JSONB,

  started_at       TIMESTAMPTZ,
  finished_at      TIMESTAMPTZ,
  created_by       UUID,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),

  -- THE CONSTRAINT THE WHOLE DESIGN RESTS ON. One row per (client, content).
  -- Re-baking identical content is a no-op; a profile EDIT changes the hash and
  -- therefore gets its own row, with its own gates and its own golden templates.
  UNIQUE (profile_id, lab_hash)
);

CREATE INDEX IF NOT EXISTS idx_ciab_profile_bake_profile
  ON ciab_profile_bake(profile_id);

-- The boot sweep's query: rows a restart abandoned mid-flight. Same shape as
-- idx_ciab_engagement_status (010) and for the same reason.
--
-- 'pending' is deliberately NOT in this predicate. A pending row has allocated
-- nothing and leaks nothing — it is swept by its own cheap statement in
-- recoverStrandedBakes, with its own message. This index is for the five
-- statuses that mean a lane and a controller VM are out there somewhere.
CREATE INDEX IF NOT EXISTS idx_ciab_profile_bake_status
  ON ciab_profile_bake(status)
  WHERE status IN ('compiling','pushing','provisioning','verifying','capturing');

-- "Which bake does this client deploy from?" — the deploy gate's read, and it
-- runs on every deploy.
CREATE INDEX IF NOT EXISTS idx_ciab_profile_bake_ready
  ON ciab_profile_bake(profile_id)
  WHERE status = 'ready';
