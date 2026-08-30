/*
 * ============================================================================
 * CLE Migration 008 — recover course labs stranded mid-provision
 * ----------------------------------------------------------------------------
 * Track A8 replaced the SDN readiness check in the SHARED provisioner
 * (src/utils/lab-network-provision.js). It used to poll exactly ONE node —
 * whichever Proxmox listed first, with no online filter — and swallow every
 * error into a log line, so an offline or wedged first node silently produced a
 * negative result with no indication why. It now checks every ONLINE node
 * concurrently, because a lane's node is chosen at DEPLOY time over whatever is
 * online and above the memory floor.
 *
 * CLE reserves through that same function, so it inherits the better check with
 * no change here.
 *
 * WHAT THIS FILE DELIBERATELY DOES NOT ADD. The readiness answer itself is a
 * fact about the RESERVATION — the crucible_challenge row — not about a course.
 * CIAB reserves through the same provisioner, so a per-plugin copy would be one
 * fact written twice, by two writers, in two databases that cannot join. It
 * lives in cybercore_db.cybercore_lab_readiness, written once by
 * reserveLabNetwork and read by both plugins through getLabReadiness().
 * Neither plugin's migration could have created it anyway: plugin migrations
 * only ever run against that plugin's own database, which is why it is a boot
 * hook in src/server.js alongside ensureLaneWanColumns.
 *
 * So all that is left here is the index the new boot sweep needs.
 *
 * Every plugin migration re-runs on every boot as ONE implicit transaction per
 * file, so this must stay idempotent.
 * ============================================================================
 */

-- recoverStrandedCourseLabs() runs at boot and marks these 'failed'.
-- Reserving is fire-and-forget async work inside one process with no resume, so
-- a course still 'provisioning' at boot was abandoned by a previous one. Before
-- Track A8 there was no sweep at all: such a course spun "Initializing" forever,
-- its deploy stayed blocked on a null challenge_id, and the only exit was
-- deleting the course and losing its roster with it.
CREATE INDEX IF NOT EXISTS idx_cle_course_provisioning
  ON cle_course(provision_status)
  WHERE provision_status = 'provisioning';
