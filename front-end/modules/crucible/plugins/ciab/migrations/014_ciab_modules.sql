-- ============================================================================
-- 014_ciab_modules.sql — Track D, phase D1: the module spine
-- ----------------------------------------------------------------------------
-- A SECTION is a class (migration 008). An ENGAGEMENT is a reserved VXLAN block
-- against one client (migration 010). Nothing yet says WHAT a class does, in
-- WHAT ORDER, or WHEN each piece opens. These three tables are that spine:
--
--     Section -> Module -> Client -> Engagement -> Environment
--                ^^^^^^
--
-- A MODULE is one unit of work an instructor sequences: a title, a brief, a
-- client to run it against, an engagement against that client, and a rule for
-- when it opens. Two modules in one section may name the SAME client -- that
-- repetition, the same shape against a different profile, is the pedagogical
-- point of the whole program -- so nothing here is keyed on the client, and
-- there is deliberately NO UNIQUE constraint mentioning profile_id.
--
-- NO CLE VOCABULARY APPEARS IN ANY NAME A PERSON READS. No "course", no
-- "material", no "challenge", no "assignment". An instructor must never have to
-- tell CiAB and CLE apart.
--
-- ----------------------------------------------------------------------------
-- WHY A MODULE IS A FIRST-CLASS ROW
-- ----------------------------------------------------------------------------
-- Because the alternative has already been measured, next door. The other
-- plugin resolves a unit of work with
--
--     SELECT material_id FROM cle_course_material
--      WHERE course_id = $1 AND template_id = $2 ... LIMIT 1
--
-- so a course plus a target COLLAPSES TO ONE ROW, on purpose. Every lane it
-- deploys is stamped with that row's id, and its scoped teardown hard-DELETEs
-- every lane carrying the stamp. Sequence two units of work against ONE client
-- there and the second deploy skips students who already hold the first one's
-- lanes, and closing the second DESTROYS the first's machines -- silently,
-- with no error, because from the schema's point of view they were one thing.
--
-- ciab_module has its own primary key. Two modules against one client are two
-- rows. That is the entire fix, and it is why this table exists at all rather
-- than a column being bolted onto something that already exists.
--
-- ----------------------------------------------------------------------------
-- WHAT ciab_module_student DELIBERATELY DOES NOT STORE
-- ----------------------------------------------------------------------------
-- It is NOT a fourth progress tracker. Three already exist, in two databases,
-- and every one of them keeps its job:
--
--   assessment_progress   (this database, UNIQUE (user_id, profile_id,
--                          part_number)) owns deliverable content, submission,
--                          feedback, score and rubric.
--   cybercore_lane_flag   (cybercore_db) owns objective capture. captured_at is
--                          written by exactly one function and read through
--                          getFlagStateForUsers / getUserFlagRows.
--   the other plugin's submission table -- off limits entirely: different
--                          database, different plugin (008's header records the
--                          decision that CiAB owns its own storage).
--
-- So this table carries NO content, NO score, NO feedback, NO rubric, NO
-- evidence, NO flag, NO points, and no per-task anything. It carries exactly
-- TWO facts, and both are facts nothing else in either database can hold,
-- because nothing else knows what a module is:
--
--   1. completion  -- is this student cleared to move on FROM THIS MODULE?
--   2. release_override -- may this ONE student in, or not, against what the
--                          module's own release rules say?
--
-- completion DEFAULTS TO 'auto', which stores nothing and defers to the tracker
-- that already owns the answer: for a module bound to an assessment part, the
-- resolver DERIVES completion from that student's own assessment_progress row.
-- The stored values are an instructor's OVERRIDE of that verdict, including the
-- explicit rejection 'incomplete'. The ordinary case writes no row at all.
--
-- ROWS ARE SPARSE. Nothing pre-creates them; a student with no row is in the
-- default state and the resolver treats it that way. The alternative is what
-- the other plugin does -- insert an empty submission row per student at deploy
-- time as an assignment marker, whose submitted_at DEFAULTs to now() -- after
-- which "has this student finished" is unanswerable from the schema.
--
-- IF YOU ARE ABOUT TO ADD A COLUMN HERE, check first whether one of the three
-- trackers above already owns that fact.
--
-- ----------------------------------------------------------------------------
-- WHAT IS DELIBERATELY ABSENT FROM ciab_module, AND HOW TO ADD IT LATER
-- ----------------------------------------------------------------------------
-- The rule this file follows: a column is admitted before it has a reader ONLY
-- if the fact it records is DESTROYED by not having it. Everything else waits
-- for the phase that reads it, because ALTER TABLE ... ADD COLUMN IF NOT EXISTS
-- is fully idempotent and is exactly what migration 009 already is:
--
--     ALTER TABLE ciab_module
--       ADD COLUMN IF NOT EXISTS <name> <type> NOT NULL DEFAULT <default>;
--
-- (Do NOT confuse that with CREATE TABLE IF NOT EXISTS, which does NOT
-- converge -- see the warning at the bottom.)
--
--   NO environment_policy. D5 (deploy-on-open / teardown-on-close) is not
--     designed and is blocked on an unresolved capacity decision. Declaring its
--     vocabulary now would freeze a CHECK that D5 may need to widen, and a
--     CHECK is the one thing that genuinely cannot be fixed cheaply here. D5
--     adds the column with the values D5 actually needs.
--
--   NO lane_group_id / lane_id / challenge_id / challenge_key. One module owns
--     MANY lane groups over a term (open, close, reopen, per-lane retry), so a
--     single pointer on the module is the wrong cardinality and the second
--     deploy silently overwrites it -- leaving the first group's lanes holding
--     a VXLAN id and a WAN address with nothing pointing at them. D5 records
--     the link on the group, where the cardinality is right:
--       ALTER TABLE ciab_profile_lane_groups
--         ADD COLUMN IF NOT EXISTS module_id UUID;
--     And a lane_id here would be a dangling pointer BY DESIGN: teardown
--     hard-deletes cybercore_lane rows -- that is what frees the vxlan id.
--
--   NO prereq_policy ('enforce'/'advise'). An instructor who wants a merely
--     advisory ordering does not create the edge. One fewer frozen vocabulary.
--
--   NO first_opened_at. D4 writes it; D4 adds it.
--
--   cloned_from_module_id IS present, with no D1 reader, and it is the ONE
--     exception to the rule above -- because it is the one fact an ALTER cannot
--     recover. D2 ships clone-a-module (the repetition mechanism the whole
--     program is built on) long before D9's growth view reads the lineage; every
--     module cloned in between would lose its provenance permanently. One
--     nullable self-reference, no vocabulary, no risk.
--
-- ----------------------------------------------------------------------------
-- FOREIGN KEYS, AND WHICH ONES CANNOT EXIST
-- ----------------------------------------------------------------------------
-- REAL FKs -- every target is in clinic_db, this same database:
--   ciab_module.section_id             -> ciab_section(section_id)   CASCADE
--                                         (attached by the guarded DO block at
--                                          the bottom, NOT inline -- see below)
--   ciab_module.profile_id             -> profiles(id)               SET NULL
--   ciab_module.cloned_from_module_id  -> ciab_module(module_id)     SET NULL
--   ciab_module_prereq (both edges)    -> ciab_module(section_id, module_id)
--                                         ON UPDATE CASCADE ON DELETE CASCADE
--   ciab_module_student.module_id      -> ciab_module(module_id)     CASCADE
--
-- BARE UUIDs, NO FK POSSIBLE. cybercore_user lives in cybercore_db, on a
-- different HOST (src/utils/cybercore-db.js), so a cross-database FK is not
-- merely unsupported -- it cannot be expressed:
--   ciab_module.created_by, ciab_module.updated_by
--   ciab_module_prereq.created_by
--   ciab_module_student.user_id, .completed_by, .override_by
-- This is the convention 001_ciab_schema.sql:3-4 established and 006, 008 and
-- 010 all restate.
--
-- NOT A REFERENCE AT ALL: engagement_type. It is the slug half of
--   ciab_engagement's UNIQUE (profile_id, engagement_type), and the same value
--   ciab_profile_lane_groups.engagement_type already carries (migration 009).
--   There is deliberately NO engagement_id column. Two reasons. First, it is one
--   fact with two writers and two ways to disagree -- the argument 010's own
--   header makes about bridge readiness. Second, and decisively: the engagement
--   row for a client reserved before Track A8 DOES NOT EXIST until something
--   READS it -- engagement-provision.adoptExistingReservation() INSERTs it
--   lazily on the read path -- so a module authored before the reservation
--   exists could not name an id at all, and every legacy client would be
--   unbindable. Resolve through
--   engagement-provision.resolveEngagement(profile_id, engagement_type), never a
--   bare SELECT, and write engagement_type only through
--   lane-reservation.sanitizeEngagementType() (lowercase, strip to [a-z0-9_-],
--   cap 32, empty -> 'default') or the value can never match that unique key.
--   Do not cache ciab_engagement.provision_status anywhere: the boot sweep flips
--   every 'provisioning' row to 'failed' on every restart, so it is volatile by
--   construction and must be read live.
--
-- profile_id IS 'ON DELETE SET NULL', NOT CASCADE.
--   DELETE /api/profiles/:id is owner-scoped -- the DELETE itself carries
--   `AND user_id = $2`. CASCADE would let the owner tidying their client list
--   silently destroy a sequenced, graded module belonging to someone else's
--   section, along with every per-student record under it. SET NULL leaves the
--   module standing with its client removed, which the resolver reports rather
--   than 500s on. Precedent: instructor_assignments.profile_id,
--   real_client_intakes.linked_profile_id.
--   BE AWARE, and do not "fix" it here: that same route calls
--   deleteProfileChallenge(id) with no engagement type -- releasing EVERY
--   engagement's VXLAN block and VNets for the client -- BEFORE the ownership-
--   scoped DELETE runs. An admin calling it on someone else's profile therefore
--   frees all the reservations and then deletes zero rows. That is a
--   pre-existing bug in that route; D1 does not touch it, and no D1 code may
--   assume a profiles row implies a live reservation.
--
-- section_id IS 'ON DELETE CASCADE', matching ciab_enrollment,
--   ciab_section_instructor and ciab_roster_import. RESTRICT would turn
--   routes/sections.js's deliberate, friendly 409 ("This section still has
--   enrollments. Archive it instead...") into a raw 23503 and a 500.
--   REQUIREMENT FOR D2/D3, WRITTEN HERE SO IT IS NOT LOST: that 409 currently
--   counts ONLY ciab_enrollment rows. A hard delete of a section that has
--   modules but no enrollments -- one built ahead of the term, or one whose
--   roster was already dropped -- will silently destroy every module, every
--   prereq edge and every per-student completion record, and answer 200. The
--   route must be extended to count ciab_module rows in the same refusal.
--
-- ciab_module_prereq CASCADEs on BOTH ends. Deleting module A therefore removes
--   the edge gating module B, and B silently becomes available. That is the
--   friendlier of the two failure modes -- RESTRICT turns a delete into an
--   unhandled 23503 -- but it is a real surprise, so D2's delete route MUST warn
--   ("2 modules require this one") first. idx_ciab_module_prereq_requires makes
--   that warning one cheap query.
--
-- ----------------------------------------------------------------------------
-- WHY THE PREREQ EDGE CARRIES section_id AND BOTH FKs ARE COMPOSITE
-- ----------------------------------------------------------------------------
-- D2's clone-a-module copies prerequisite structure through an old-id -> new-id
-- map. Get that map wrong and you write an edge whose two endpoints are in
-- different sections. With plain single-column FKs that INSERT succeeds, and the
-- damage surfaces months later as a module that is permanently locked for
-- everyone, for no visible reason, in a section that looks correct.
--
-- Carrying section_id on the edge and pointing both FKs at
-- ciab_module(section_id, module_id) -- which is why the deliberately redundant
-- UNIQUE (section_id, module_id) exists on ciab_module -- makes that INSERT a
-- 23503 at write time. The database refuses the corrupt clone; no review comment
-- required.
--
-- SIDE EFFECT, KNOWN AND ACCEPTED: a module cannot be moved between sections
-- while it is an endpoint of any edge. ON UPDATE CASCADE propagates the new
-- section_id onto the edge, at which point the edge's OTHER endpoint no longer
-- matches and the UPDATE fails with 23503. There is no "move a module" feature;
-- there is clone-and-delete, which is what D2 offers anyway.
--
-- CYCLES CANNOT BE PREVENTED BY A CONSTRAINT. The CHECK below stops a self-edge
-- and the composite FKs stop a cross-section edge; nothing in SQL stops
-- A -> B -> C -> A. Detection is application-level, in utils/module-spine.js:
-- every module inside a cycle resolves to LOCKED, never OPEN, and the instructor
-- view raises it as an error-severity issue. An entry that leads to a refusal is
-- worse than no entry.
--
-- ----------------------------------------------------------------------------
-- ORDERING: THERE IS DELIBERATELY NO UNIQUE (section_id, position)
-- ----------------------------------------------------------------------------
-- A drag-reorder that swaps two modules writes position 2 onto the row holding
-- 1 while another row still holds 2. PostgreSQL checks a NON-DEFERRABLE unique
-- constraint per ROW, so that swap fails mid-statement with 23505 and the
-- reorder half-applies.
--
-- DEFERRABLE INITIALLY DEFERRED would in fact work for a single-statement
-- renumber -- a deferred constraint is checked at end of transaction, and an
-- implicit single-statement transaction ends after every row is written. It is
-- still rejected, for a simpler reason: there is not one DEFERRABLE constraint
-- anywhere in this repository to copy, and nothing in this plugin ever calls
-- pool.connect(), so any multi-statement reorder someone writes later would be
-- silently unprotected. (Do not repeat the folk claim that a deferred constraint
-- is "checked immediately anyway" -- it is not, and a header that re-runs on
-- every boot should not teach the next author something untrue about Postgres.)
--
-- The order is therefore (position, created_at, module_id), resolved by
-- module-spine.sortModules() and matched exactly by every ORDER BY in that file.
-- module_id is a UUID, so the order is TOTAL and stable even when two clones tie
-- -- and a duplicate position is cosmetic (surfaced as an instructor warning)
-- rather than a correctness bug.
--
-- THE REORDER STATEMENT D2 SHOULD WRITE -- one statement, atomic without a
-- transaction, scoped to the section so it cannot renumber anyone else's:
--
--     UPDATE ciab_module m
--        SET position = v.pos, updated_at = now()
--       FROM (VALUES ($2::uuid, 1), ($3::uuid, 2), ...) AS v(module_id, pos)
--      WHERE m.module_id = v.module_id
--        AND m.section_id = $1;
--
-- ----------------------------------------------------------------------------
-- THE IDEMPOTENCY CONTRACT
-- ----------------------------------------------------------------------------
-- THIS FILE RE-RUNS ON EVERY BOOT. src/module-loader.js reads this directory in
-- plain .sort() order and sends each file as ONE dbPool.query(sql) -- simple
-- query protocol, so THE WHOLE FILE IS A SINGLE IMPLICIT TRANSACTION. One
-- failing statement rolls back EVERY table here, and the loader only
-- console.warn()s before injecting the pool anyway -- so the server boots,
-- mounts every route, reports healthy, and throws 42P01 at the first request,
-- with one line of boot log as the only evidence. THERE IS NO MIGRATION LEDGER.
--
--   * Every statement must be IF NOT EXISTS / guarded.
--   * NEVER write BEGIN or COMMIT. No plugin migration has them, and an explicit
--     COMMIT mid-file destroys the all-or-nothing property every header relies
--     on, leaving half a spine behind after a later failure.
--   * NEVER write CREATE INDEX CONCURRENTLY, VACUUM, REINDEX, CREATE DATABASE or
--     ALTER SYSTEM. They cannot run inside a transaction block and fail the
--     ENTIRE file with SQLSTATE 25001. They read as harmless hygiene.
--   * NO TRIGGERS, NO FUNCTIONS. There is not one CREATE TRIGGER or CREATE OR
--     REPLACE FUNCTION in any plugin migration in this tree, and a bare CREATE
--     TRIGGER is not idempotent. updated_at is maintained by the writing code,
--     exactly as 010 does.
--   * The pool's statement_timeout is 120s and is a budget for the WHOLE FILE.
--
-- 008's corollary: do NOT reference a table created by migration 003 or later
-- without an IF to_regclass(...) IS NOT NULL guard. ciab_section is created by
-- 008, so the section FK is attached by the guarded DO block at the bottom
-- rather than declared inline -- otherwise a deployment where 008 warned would
-- lose the ENTIRE D1 spine on top, which helps nobody. profiles is created by
-- 001, which every migration from 004 to 010 references inline; that FK is
-- inline here too.
--
-- NO BACKFILL, AND THEREFORE NO ciab_meta MARKER -- do not go looking for one.
-- Nothing in this database is a module today (`ciab_module` matched zero files
-- in src/ and modules/ before this migration), so there is nothing to infer.
-- instructor_assignments is the nearest existing shape and is deliberately NOT
-- migrated and NOT deleted: it is a due-date sticky note with no section, no
-- order, no release and no state, its existing instructor UI still reads it, and
-- inferring modules from it would manufacture a sequence nobody chose. If a
-- LATER file backfills anything, guard it with a ciab_meta marker (008's
-- backfill_008 pattern) or it will resurrect, on every restart, every module an
-- instructor has since deleted.
--
-- ----------------------------------------------------------------------------
-- WARNING TO THE NEXT AUTHOR: CREATE TABLE IF NOT EXISTS DOES NOT CONVERGE
-- ----------------------------------------------------------------------------
-- Once this file has run on a deployment, editing a CREATE TABLE body below --
-- to add a column, to add a value to a CHECK, to add a UNIQUE clause -- is a
-- SILENT NO-OP there, while looking perfectly correct in review and working
-- perfectly on a fresh database.
--
--   * A new COLUMN needs its own ALTER TABLE ... ADD COLUMN IF NOT EXISTS
--     (migration 009 is exactly that, and it is cheap).
--   * A new CONSTRAINT, or a widened CHECK, needs a DO block guarded on
--     pg_constraint -- and widening means DROP CONSTRAINT then ADD, for which
--     there is NO precedent anywhere in this tree to copy.
--
-- That asymmetry is why every CHECK below is NAMED (so a future guarded
-- DROP/ADD is deterministic instead of relying on PostgreSQL's auto-generated
-- name, which is only conventional and gets a numeric suffix on collision), and
-- why the vocabularies below are deliberately generous: this is the one commit
-- in which they are free. GET THEM RIGHT NOW.
--
-- The vocabularies are mirrored in utils/module-states.js and a test asserts the
-- two agree in both directions. If you change a CHECK here, change that file.
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- === Modules ================================================================
-- One unit of work an instructor sequences inside a section.
--
-- The PEDAGOGICAL half (title, brief, assessment_part, release rules) is
-- separable from the BINDING half (profile_id, engagement_type) because D2's
-- clone copies the first and re-points the second.
CREATE TABLE IF NOT EXISTS ciab_module (
  module_id   UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

  -- The FK is attached by the guarded DO block at the bottom of this file, NOT
  -- inline: ciab_section comes from migration 008, and an unguarded reference
  -- takes this whole file down on any deployment where 008 warned.
  section_id  UUID NOT NULL,

  -- Display order. NOT unique -- see the ORDERING section of the header. Ties
  -- break on (created_at, module_id) in the resolver, so the order is total and
  -- stable even while a reorder is half-written.
  position    INTEGER NOT NULL DEFAULT 0,

  title       VARCHAR(255) NOT NULL,

  -- STUDENT-FACING. The engagement brief D4 renders. The resolver NULLs it
  -- unless the module is open or closed for that student, so a locked module
  -- cannot leak next week's brief through the network tab. That filtering
  -- happens SERVER-SIDE, in module-spine.studentModuleView().
  brief       TEXT,

  -- STAFF ONLY, and it exists partly so the student projection has something
  -- real to exclude: the projection test asserts this key never appears in a
  -- student response. "Swap the client next term, the SMB share is too easy."
  instructor_notes TEXT,

  -- === The client binding ===================================================
  -- Nullable: an instructor sequences the term before choosing every client,
  -- and a deleted profile must leave the module standing (SET NULL).
  profile_id  UUID REFERENCES profiles(id) ON DELETE SET NULL,

  -- The slug half of ciab_engagement's UNIQUE (profile_id, engagement_type).
  -- Deliberately unconstrained to a vocabulary, matching 009 and 010, because
  -- Track B is what defines one. ALWAYS write it through
  -- lane-reservation.sanitizeEngagementType().
  engagement_type VARCHAR(32) NOT NULL DEFAULT 'default',

  -- === The deliverable binding ==============================================
  -- Which part of the 8-part assessment this module's deliverable is, if any.
  -- Maps to assessment_progress.part_number. It is the ONLY link into that
  -- table, and it is what lets completion be DERIVED for the ordinary case
  -- instead of stored.
  --
  -- No upper bound, on purpose: the part list lives in utils/part-definitions.js
  -- where TOTAL_PARTS is DERIVED from the key count, so a ninth part must not
  -- require a DROP CONSTRAINT that has no precedent here.
  --
  -- NEVER store the part NAME. assessment_progress.part_name already drifted
  -- from the definitions once, which is why routes/progress.js re-derives it on
  -- every read; module-spine does the same via getPartName().
  assessment_part INTEGER
    CONSTRAINT ciab_module_assessment_part_chk
      CHECK (assessment_part IS NULL OR assessment_part >= 1),

  -- === Release: instructor INTENT. The effective phase is DERIVED. ==========
  --   draft     invisible to students; the default, so a half-written module
  --             cannot leak
  --   scheduled published; opens at release_at. A NULL release_at means it never
  --             opens, and is reported to the instructor as a configuration
  --             error rather than silently treated as "now"
  --   open      available now (the manual "Open it" button)
  --   closed    was available, now shut; students keep read access to the brief
  --             and their own state. This is the transition D5 will hang
  --             teardown-on-close from
  --   archived  retired from the sequence but NOT deleted. Invisible to
  --             students; every ciab_module_student row survives. This is the
  --             ONLY way to remove a module without cascading away the record
  --             the grading phase reads, and it must be distinguishable from
  --             'draft' or a term rollover looks like a half-built section
  --
  -- Nothing about availability is STORED. "Is this open" is computed from
  -- (release_state, release_at, close_at, now) by a pure function over an
  -- INJECTED clock. A stored is_open boolean would need a scheduled job to flip
  -- it, one missed tick leaves a module shut on the morning it was meant to
  -- open, and the result is indistinguishable from a module the instructor
  -- deliberately closed.
  release_state VARCHAR(16) NOT NULL DEFAULT 'draft'
    CONSTRAINT ciab_module_release_state_chk
      CHECK (release_state IN ('draft','scheduled','open','closed','archived')),
  release_at  TIMESTAMPTZ,
  close_at    TIMESTAMPTZ,

  -- There is deliberately NO CHECK that close_at > release_at. A UI that PATCHes
  -- close_at before release_at, or an instructor correcting an inverted window
  -- in two steps, would get a raw 23514 surfaced as a 500. An inverted window is
  -- reported as an instructor ISSUE instead, and the resolver still fails closed
  -- because it tests close_at before release_at.

  -- Provenance for D2's clone-a-module. See the header: the one column admitted
  -- before it has a reader, because it is the one fact an ALTER cannot recover.
  -- SET NULL so deleting the original does not delete its clones.
  cloned_from_module_id UUID REFERENCES ciab_module(module_id) ON DELETE SET NULL,

  created_by  UUID,            -- cybercore_user.user_id (cross-DB, no FK)
  updated_by  UUID,            -- cybercore_user.user_id (cross-DB, no FK)
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

  -- Redundant against the primary key, and REQUIRED: it is the target of the two
  -- composite foreign keys on ciab_module_prereq, which is what makes a
  -- cross-section prereq edge impossible to insert. DO NOT REMOVE IT.
  CONSTRAINT ciab_module_section_module_key UNIQUE (section_id, module_id)
);

-- The list query, in exactly the resolver's order.
CREATE INDEX IF NOT EXISTS idx_ciab_module_section_position
  ON ciab_module(section_id, position, created_at);

-- "Which modules use this client's EXTERNAL engagement?" -- D3's environments
-- tab, the shared-environment refcount D5 needs before it tears anything down,
-- and the dependency warning a profile delete ought to show. Both columns,
-- matching ciab_engagement's unique key and idx_ciab_pllg_engagement (009):
-- Track B's headline case is one client running internal and external at once.
CREATE INDEX IF NOT EXISTS idx_ciab_module_engagement
  ON ciab_module(profile_id, engagement_type)
  WHERE profile_id IS NOT NULL;

-- D9's repetition view walks this backwards.
CREATE INDEX IF NOT EXISTS idx_ciab_module_clone_src
  ON ciab_module(cloned_from_module_id)
  WHERE cloned_from_module_id IS NOT NULL;

-- === Prerequisites ==========================================================
-- A GRAPH, not a chain. A single self-referencing prereq_module_id column on
-- ciab_module would allow one prerequisite per module and could not express
-- "finish the external AND the internal recon before writing the report" -- and
-- converting a column into this table later needs a backfill plus a column drop,
-- a shape this tree has no precedent for.
--
-- See the header for why section_id is on the edge and why both FKs are
-- composite. Cycles are detected in the resolver and lock every module on them.
CREATE TABLE IF NOT EXISTS ciab_module_prereq (
  section_id         UUID NOT NULL,
  module_id          UUID NOT NULL,   -- the module that is gated
  prereq_module_id   UUID NOT NULL,   -- the module that must be complete first
  created_by         UUID,            -- cybercore_user.user_id (cross-DB, no FK)
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),

  -- One edge per pair; a duplicate insert is a no-op via ON CONFLICT.
  PRIMARY KEY (module_id, prereq_module_id),

  -- The only cycle SQL can catch. A -> B -> A and longer are the resolver's job.
  CONSTRAINT ciab_module_prereq_self_chk CHECK (module_id <> prereq_module_id),

  CONSTRAINT ciab_module_prereq_module_fk
    FOREIGN KEY (section_id, module_id)
    REFERENCES ciab_module (section_id, module_id)
    ON UPDATE CASCADE ON DELETE CASCADE,

  CONSTRAINT ciab_module_prereq_requires_fk
    FOREIGN KEY (section_id, prereq_module_id)
    REFERENCES ciab_module (section_id, module_id)
    ON UPDATE CASCADE ON DELETE CASCADE
);

-- "Load every edge in this section" -- one query, then the graph work is pure.
CREATE INDEX IF NOT EXISTS idx_ciab_module_prereq_section
  ON ciab_module_prereq(section_id);

-- "What depends on this module?" -- the delete warning D2 must show.
CREATE INDEX IF NOT EXISTS idx_ciab_module_prereq_requires
  ON ciab_module_prereq(prereq_module_id);

-- The two composite FKs above are the referencing side of an ON DELETE CASCADE.
-- Without these, every DELETE of a ciab_module row falls back to a section-prefix
-- scan plus filter for each of the two lookups. Harmless at 20 modules; an
-- unstated regression at 200, and PostgreSQL will not warn about it.
CREATE INDEX IF NOT EXISTS idx_ciab_module_prereq_edge_module
  ON ciab_module_prereq(section_id, module_id);
CREATE INDEX IF NOT EXISTS idx_ciab_module_prereq_edge_requires
  ON ciab_module_prereq(section_id, prereq_module_id);

-- === Per-student module state ===============================================
-- READ "WHAT ciab_module_student DELIBERATELY DOES NOT STORE" IN THE HEADER
-- BEFORE ADDING A COLUMN HERE. This is an OVERRIDE table, and the defaults are
-- chosen so that a student with NO ROW AT ALL is in a complete, correct, fully
-- described state.
--
-- Keyed on (module_id, user_id) and on nothing else. NOT on profile_id:
-- risk_findings, cis_ram_assessments, cis_ram_safeguards and risk_assets all
-- carry a user_id while constraining on profile_id alone, which is why two
-- students on one client silently share rows there.
--
-- user_id has NO foreign key -- cybercore_user is a different database -- and
-- deliberately no FK to ciab_enrollment(enrollment_id) either, even though that
-- would be legal here: drops are SOFT (routes/sections.js sets status='dropped',
-- with a reinstate route) and state must survive a drop and reinstate. Note also
-- that two DISJOINT populations can appear in this column: enrolled roster
-- members, and the <slug>-studentN@clinic.local accounts a profile deploy MINTS,
-- which are never enrolled. Do not assume a matching ciab_enrollment row exists.
--
-- The PRIMARY KEY is the ON CONFLICT target for every upsert in
-- utils/module-spine.js. A primary key cannot be missing from a table that
-- exists, which an inline UNIQUE(...) added in a later edit could be -- if you
-- ever need ANOTHER uniqueness rule here, add it as a standalone
-- CREATE UNIQUE INDEX IF NOT EXISTS ux_..., never as an in-table UNIQUE, because
-- CREATE TABLE IF NOT EXISTS is a no-op on any deployment that already ran this
-- file and the constraint would be invisible to ON CONFLICT there.
CREATE TABLE IF NOT EXISTS ciab_module_student (
  module_id UUID NOT NULL REFERENCES ciab_module(module_id) ON DELETE CASCADE,
  user_id   UUID NOT NULL,   -- cybercore_user.user_id (cross-DB, no FK)

  -- FACT 1: is this student cleared to move on from THIS MODULE? Module grain,
  -- which no existing tracker is -- assessment_progress is (user, client, part),
  -- cybercore_lane_flag is (lane, vm, flag_type), and neither knows what a
  -- module is.
  --
  --   'auto'       DEFAULT, and the state of every student with no row. Defer to
  --                the tracker that already owns the answer: for a module with
  --                an assessment_part and a profile_id, the resolver derives
  --                completion from THAT STUDENT'S OWN assessment_progress row
  --                (status 'submitted' or 'reviewed'). 'submitted' is
  --                deliberately enough -- a student must not wait on grading to
  --                start the next module. Stores nothing.
  --   'complete'   an explicit decision. Satisfies a prerequisite.
  --   'waived'     excused -- a late joiner, an accommodation. ALSO satisfies a
  --                prerequisite, but is counted separately so a waiver is never
  --                reported as work done.
  --   'incomplete' an explicit REJECTION, which beats a derived submission. This
  --                is what makes 'auto' safe to default to: an instructor can
  --                always say no.
  --
  -- There is no 'in_progress' and no 'submitted' here: those are
  -- assessment_progress.status, and restating them is the fourth tracker this
  -- file exists to avoid.
  completion   VARCHAR(16) NOT NULL DEFAULT 'auto'
    CONSTRAINT ciab_module_student_completion_chk
      CHECK (completion IN ('auto','incomplete','complete','waived')),
  completed_at TIMESTAMPTZ,
  completed_by UUID,         -- cybercore_user.user_id (cross-DB, no FK).
                             -- NULL alongside a non-auto completion means the
                             -- student marked it themselves.

  -- FACT 2: this ONE student's gate, against what the module's release says.
  --   'unlock' an extension, a make-up, an accommodation. Beats a pending
  --            release AND an unmet prerequisite AND a closed module, because an
  --            instructor's explicit grant is an authority the resolver must not
  --            second-guess. It cannot beat 'draft' or 'archived' -- you cannot
  --            grant access to something that has not been written -- and it
  --            cannot beat an archived section, because the enrollment gate
  --            would refuse the request the UI would then be offering.
  --   'lock'   an integrity hold. Checked before every open path, so an
  --            instructor lock always wins.
  -- NULL means "follow the module". Nothing else in either database records
  -- this; without it an instructor can only reopen a module for the whole class.
  release_override VARCHAR(16)
    CONSTRAINT ciab_module_student_override_chk
      CHECK (release_override IS NULL OR release_override IN ('unlock','lock')),
  -- Shown to the student verbatim when it is a lock, so write it for them.
  override_reason  TEXT,
  override_by      UUID,     -- cybercore_user.user_id (cross-DB, no FK)
  override_at      TIMESTAMPTZ,

  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

  PRIMARY KEY (module_id, user_id)
);

-- The primary key leads with module_id, so "everything this student has, across
-- every section" needs its own index -- the student's own dashboard (D4).
CREATE INDEX IF NOT EXISTS idx_ciab_module_student_user
  ON ciab_module_student(user_id);

-- "Which students on this module has somebody overridden?" -- the exceptions
-- list, which is the interesting one and is almost always tiny.
CREATE INDEX IF NOT EXISTS idx_ciab_module_student_override
  ON ciab_module_student(module_id)
  WHERE release_override IS NOT NULL OR completion <> 'auto';

-- ============================================================================
-- THE ciab_section FOREIGN KEY — added separately, and guarded three ways.
-- ----------------------------------------------------------------------------
-- 1. to_regclass('public.ciab_section') -- ciab_section is created by migration
--    008, and each migration file is independently failure-tolerant, so 008 may
--    have warned and left the table absent. Declaring this FK inline would take
--    THIS ENTIRE FILE down on precisely the deployment that is already degraded.
--    to_regclass takes TEXT and returns NULL for a missing relation, so naming
--    it this way does not require the relation to exist at parse time.
--
--    EVERYTHING ELSE IN THIS CONDITION MUST ALSO BE PARSE-SAFE. PL/pgSQL
--    prepares an IF expression as ONE SPI query, and parse analysis resolves
--    every relation name in it BEFORE the executor can short-circuit the AND --
--    so a second conjunct that SELECTs FROM ciab_section would raise 42P01 and
--    roll back this whole file, in exactly the case the guard exists for. The
--    condition below names only pg_constraint and a regclass cast of
--    ciab_module, which this same file created moments ago. The reference to
--    ciab_section lives in the THEN body, where PL/pgSQL plans it lazily.
--
--    In particular: do NOT add a "no existing row would violate it" pre-check.
--    Besides being parse-unsafe, an orphan row can only exist BECAUSE the FK is
--    absent -- so once one exists the constraint would be silently never added,
--    on every boot, forever, with no error and no log line. Let ADD CONSTRAINT
--    fail loudly instead.
--
-- 2. pg_constraint, SCOPED BY conrelid -- ALTER TABLE ADD CONSTRAINT is not
--    idempotent and this file re-runs on every boot. A constraint name is unique
--    per TABLE, not per database, so an unscoped conname lookup could be
--    permanently satisfied by a same-named constraint elsewhere and leave
--    section_id with no referential integrity, silently.
--
-- 3. An EXCEPTION subtransaction around the ALTER itself, catching EXACTLY the
--    two transient contention conditions and nothing else. ADD FOREIGN KEY takes
--    SHARE ROW EXCLUSIVE on ciab_section and this pool sets lock_timeout to 30s.
--    A concurrent writer (a second app instance, an operator's psql session)
--    would make the ALTER raise 55P03 lock_not_available, or 40P01
--    deadlock_detected against a writer taking the same locks in the other
--    order; without this wrapper either one rolls back the three CREATE TABLEs
--    above it and leaves the deployment with no D1 schema for that boot. Both
--    clear on their own, so retrying next boot is the right answer and the FK
--    add is genuinely non-fatal.
--
--    IT IS DELIBERATELY NOT "WHEN OTHERS". That would also swallow 23503
--    (an orphan section_id already exists) and 42501 (the migration role may not
--    ALTER this table) -- neither of which ever clears by waiting. The ALTER
--    would then fail on every boot, forever, be swallowed every time, and leave
--    section_id carrying no referential integrity while the server reported
--    healthy: verbatim the state guard 1 above refuses to allow. The 23503 path
--    is reachable, not hypothetical, because routes/sections.js hard-deletes a
--    ciab_section row behind a 409 that counts only ciab_enrollment rows, so
--    with this FK absent nothing cascades and that section's module rows survive
--    with a dangling section_id. An integrity or permission failure is therefore
--    FATAL to this file's boot pass on purpose: plugin-loader console.warn()s a
--    named error line, and rolling back costs nothing, because on a first boot
--    ciab_module was created empty moments ago and on any later boot every
--    statement in this file is already a no-op.
--
--    statement_timeout (120s, set by the same pool) raises 57014 query_canceled,
--    which PL/pgSQL's OTHERS does not catch either, by design -- and neither
--    would any handler worth writing here. That 120s is the budget for the WHOLE
--    file, since each migration is sent as one query, so no wrapper can extend
--    it and the file's own size remains the real ceiling.
--
--    (The WARNING reaches the client as a notice node-postgres does not log, so
--    it is not a monitoring signal -- its job is only to keep the tables.)
--
-- Named dollar tag ($section_fk$, not $$): a bare $$ is terminated early by any
-- dollar-quoted string appearing inside, and the resulting syntax error rolls
-- back the whole file.
-- ============================================================================
DO $section_fk$
BEGIN
  IF to_regclass('public.ciab_section') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
        WHERE conname  = 'ciab_module_section_fk'
          AND conrelid = 'public.ciab_module'::regclass
     )
  THEN
    BEGIN
      ALTER TABLE ciab_module
        ADD CONSTRAINT ciab_module_section_fk
        FOREIGN KEY (section_id) REFERENCES ciab_section(section_id)
        ON DELETE CASCADE;
    EXCEPTION WHEN lock_not_available OR deadlock_detected THEN
      RAISE WARNING '014_ciab_modules: ciab_module_section_fk not attached (%); retrying next boot', SQLERRM;
    END;
  END IF;
END
$section_fk$;
