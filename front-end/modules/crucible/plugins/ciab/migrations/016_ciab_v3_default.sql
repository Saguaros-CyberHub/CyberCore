-- 016_ciab_v3_default.sql — Track R1: v3 becomes the default, and ONLY the default.
--
-- WHAT CHANGES: the column DEFAULT on two subnet_scheme columns —
--   ciab_engagement.subnet_scheme          (010_ciab_engagements.sql:46)
--   ciab_profile_lane_groups.subnet_scheme (006_profile_lane_deploys.sql:31)
-- Both were declared DEFAULT 'v2'. Both become DEFAULT 'v3'.
--
-- WHY. v2 is one flat segment: Kali, the company web host and the domain
-- controller share a broadcast domain, so "pivot through the web server to
-- reach AD" is a CONVENTION a student can simply decline to follow — nmap the
-- /24, find the DC, attack it directly, and the exercise the engagement was
-- built around never happens. v3 is two segments behind one gateway (ext0/int0)
-- with ext0<->int0 DROPped in FORWARD, the web host dual-homed at .240, and
-- everything else internal — so the network ENFORCES the pivot instead of the
-- worksheet asking for it. utils/profile-to-spec.js's DEFAULT_SUBNET_SCHEME is
-- the JavaScript half of the same decision; these two DEFAULTs are the half
-- that governs a writer which is not this application (a psql session, a CSV
-- import, a future route that omits the column).
--
-- ════════════════════════════════════════════════════════════════════════════
-- THERE IS NO BACKFILL HERE, AND ADDING ONE WOULD BREAK RUNNING LANES.
-- ════════════════════════════════════════════════════════════════════════════
--
-- Do NOT "helpfully" append an UPDATE that rewrites existing rows to 'v3'.
-- A DEFAULT governs rows that do not exist yet. subnet_scheme on a row that
-- ALREADY EXISTS is not a preference — it is a description of a VXLAN block
-- that has already been carved in Proxmox:
--
--   * v2 carves ONE VNet per lane, at the block's own tag.
--   * v3 carves TWO — the external tag AND an internal one at
--     tag + V3_INTERNAL_TAG_OFFSET (src/utils/lab-network-provision.js).
--
-- Rewriting a v2 reservation's scheme to 'v3' does not create the second VNet;
-- it only makes the row LIE about what was carved. The next deploy then cables
-- its lanes onto int-segment bridges that do not exist on any node, and the
-- environment comes up unreachable — while utils/engagement-provision.js's
-- expectedTagsFor() starts demanding internal tags that were never created, so
-- the readiness check calls a healthy block broken. The reverse is no better:
-- an unnamed internal VNet is one the teardown sweep can never name again, and
-- the allocator only ever climbs, so the range is burned permanently
-- (utils/lane-reservation.js:91-105 has the full account).
--
-- The engagement row and the carve must agree. The only safe way to move a
-- live engagement to v3 is to reserve a NEW block at v3 — which is what
-- creating a new engagement already does.
--
-- ════════════════════════════════════════════════════════════════════════════
-- CAPACITY: THIS DOUBLES VNet TAG CONSUMPTION PER ENGAGEMENT. FLAGGED, NOT SOLVED.
-- ════════════════════════════════════════════════════════════════════════════
--
-- A v3 lane consumes TWO VNet tags where a v2 lane consumed one. Defaulting to
-- v3 therefore doubles the tag spend of every engagement created from here on:
-- a 25-slot engagement that cost 25 VNets now costs 50, and reserveLabNetwork
-- creates every one of them up front. The allocator never re-uses a released
-- block (it only ever climbs above the highest block in use), so this halves
-- the effective ceiling of the VXLAN search window
-- (lane-reservation.js VXLAN_SEARCH_MIN/MAX) at the same creation rate.
--
-- That is a real capacity decision and it is deliberately NOT addressed here.
-- Nothing in this file changes the window, the block size or the allocator.
-- An operator who is close to the ceiling should size max_students to the class
-- rather than to the wish, and should retire engagements that are finished. If
-- the window itself needs widening, that belongs with the allocator, not with
-- a column default.
--
-- ════════════════════════════════════════════════════════════════════════════
-- IDEMPOTENCE
-- ════════════════════════════════════════════════════════════════════════════
--
-- src/plugin-loader.js:134-147 sends EVERY migration file in this directory to
-- pool.query() on EVERY boot, as one implicit transaction per file, and catches
-- failure with nothing but console.error. So this file must be safe to apply an
-- unbounded number of times and must reference nothing it has not first proved
-- exists — one missing object rolls back the whole file, exactly as 008's
-- corollary and 012's header describe.
--
-- ALTER COLUMN ... SET DEFAULT is already idempotent: it rewrites one pg_attrdef
-- row and performs NO table rewrite and NO validation scan, unlike the ADD
-- CONSTRAINT that 012 has to guard by name. The catalog read below is therefore
-- not needed for correctness — it is here so that every boot after the first
-- takes no lock at all. SET DEFAULT still needs ACCESS EXCLUSIVE for the
-- instant it runs, and taking that on two live tables on every restart, behind
-- the pool's 30s lock_timeout, is a cost with no benefit.
--
-- The default expression comes back from pg_get_expr as 'v3'::character varying,
-- so the comparison is a prefix test rather than equality — the cast text is a
-- rendering detail of the column type and is not worth depending on.
--
-- NOT TOUCHED, deliberately: the CHECK (subnet_scheme IN ('v1','v2','v3')) that
-- 006 and 010 declare. v2 stays fully selectable — an explicit subnet_scheme
-- must always win over the default — and narrowing that vocabulary would make
-- every existing v1/v2 row illegal.

DO $v3default$
DECLARE
  tbl     TEXT;
  cur_def TEXT;
BEGIN
  FOREACH tbl IN ARRAY ARRAY['ciab_engagement', 'ciab_profile_lane_groups'] LOOP
    -- 008's corollary: never reference a table another migration created
    -- without a guard. A fresh database runs 006 and 010 before this file, but
    -- either may have failed, and their failure must not become this one's.
    IF to_regclass(tbl) IS NULL THEN
      RAISE NOTICE '016: % not present — skipping', tbl;
      CONTINUE;
    END IF;

    -- The column is guarded separately from the table for the same reason 012
    -- guards 011's columns separately from 011's table: a table that exists in
    -- an older shape is the case a bare ALTER turns into a rolled-back file.
    IF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
       WHERE table_name = tbl AND column_name = 'subnet_scheme'
    ) THEN
      RAISE NOTICE '016: %.subnet_scheme not present — skipping', tbl;
      CONTINUE;
    END IF;

    SELECT pg_get_expr(d.adbin, d.adrelid) INTO cur_def
      FROM pg_attrdef d
      JOIN pg_attribute a ON a.attrelid = d.adrelid AND a.attnum = d.adnum
     WHERE d.adrelid = to_regclass(tbl)
       AND a.attname = 'subnet_scheme';

    -- Already v3 — every boot after the first ends here, having taken nothing
    -- but a catalog read.
    IF cur_def IS NOT NULL AND cur_def LIKE '''v3''%' THEN
      CONTINUE;
    END IF;

    EXECUTE format('ALTER TABLE %I ALTER COLUMN subnet_scheme SET DEFAULT %L', tbl, 'v3');
    RAISE NOTICE '016: %.subnet_scheme DEFAULT is now v3 (existing rows untouched)', tbl;
  END LOOP;
END
$v3default$;
