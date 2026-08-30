-- 010_ciab_engagements.sql — Track A8, phase A8a.
--
-- Carving a VXLAN block is slow: 25-50 serial VNet POSTs (rate-limited), then a
-- CLUSTER-WIDE `PUT /cluster/sdn` apply, then up to three reconcile passes each
-- with another apply, then a wait for the bridges to materialize on every node.
-- Until now that ran INSIDE the first profile deploy, so an instructor waited
-- through all of it before a single lane started cloning.
--
-- This table moves the reservation to its own moment. An engagement is created
-- (usually days before it deploys), the reservation runs detached, and
-- provision_status carries the answer. The deploy then REFUSES to start unless
-- the status is 'ready' — it never silently falls back to doing the slow thing
-- inline, because a fallback is how the cost becomes invisible again.
--
-- Same shape as cle_course.provision_status (cle/migrations/004), for the same
-- reason its header gives: the work takes "longer than the edge proxy will hold
-- the create request open".
--
-- CROSS-DB. challenge_id / challenge_key point at cybercore_db.crucible_challenge,
-- which this migration cannot reach (it runs against clinic_db). They are bare
-- values with no foreign key — the same pattern cle_course uses for the same
-- reason, and the same one ciab_profile_lane_groups already uses for lane_id.
--
-- DEFAULT IS 'provisioning', NOT 'ready'. cle_course defaulted to 'ready'
-- because it was ADDING a column to rows whose labs were already reserved.
-- This is a NEW table, so every row it will ever hold is created by the code
-- that also starts the provision. Reservations that predate the table are
-- adopted lazily on read as 'ready' (see adoptExistingReservation in
-- utils/engagement-provision.js) — a migration cannot do it, because the
-- evidence lives in the other database.
--
-- Every plugin migration re-runs on every boot as ONE implicit transaction per
-- file, so this must stay idempotent.

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS ciab_engagement (
  engagement_id    UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  profile_id       UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,

  -- Matches ciab_profile_lane_groups.engagement_type (migration 009) and the
  -- reservation key format 'ciab-profile-<id8>-<engagement>'. Deliberately not
  -- constrained to a vocabulary: Track B is what defines one.
  engagement_type  VARCHAR(32) NOT NULL DEFAULT 'default',

  subnet_scheme    VARCHAR(8) NOT NULL DEFAULT 'v2'
                     CHECK (subnet_scheme IN ('v1','v2','v3')),
  -- The block size. Locks once lanes exist, exactly as it does today.
  max_students     INTEGER NOT NULL CHECK (max_students BETWEEN 1 AND 200),

  challenge_id     UUID,
  challenge_key    TEXT,

  provision_status VARCHAR(16) NOT NULL DEFAULT 'provisioning'
                     CHECK (provision_status IN ('provisioning','ready','failed')),
  provision_error  TEXT,

  -- NOTE: bridge readiness deliberately does NOT live here. "Were this block's
  -- bridges verified, when, and on which nodes?" is a fact about the RESERVATION
  -- (the crucible_challenge row), not about a CIAB engagement — and CLE reserves
  -- through the same shared provisioner. Storing it per-plugin means one fact
  -- written twice, by two writers, in two databases that cannot join. It lives
  -- in cybercore_db.cybercore_lab_readiness, written by reserveLabNetwork and
  -- read through getLabReadiness(challenge_id).

  provision_started_at TIMESTAMPTZ,
  provisioned_at   TIMESTAMPTZ,
  created_by       UUID,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),

  -- One reservation per (client, engagement) — the same key the challenge uses.
  UNIQUE (profile_id, engagement_type)
);

CREATE INDEX IF NOT EXISTS idx_ciab_engagement_profile
  ON ciab_engagement(profile_id);

-- The boot sweep's query: find rows stranded mid-provision by a restart.
CREATE INDEX IF NOT EXISTS idx_ciab_engagement_status
  ON ciab_engagement(provision_status)
  WHERE provision_status = 'provisioning';
