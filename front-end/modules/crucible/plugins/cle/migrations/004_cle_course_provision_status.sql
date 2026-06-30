/*
 * ============================================================================
 * CLE Migration 004 — Course lab provisioning status
 * ----------------------------------------------------------------------------
 * Reserving a course's lab network (SDN zone + VNets + bridge-readiness wait)
 * takes tens of seconds to minutes — longer than the edge proxy will hold the
 * create request open. Course creation therefore returns immediately and the
 * reservation runs in the background, flipping this column from 'provisioning'
 * to 'ready' (or 'failed') when it finishes. The UI shows an "Initializing"
 * label while a course is still 'provisioning'.
 *
 * Existing courses predate background provisioning and already have their lab
 * reserved, so the column defaults to 'ready' for them.
 * ============================================================================
 */

ALTER TABLE cle_course
  ADD COLUMN IF NOT EXISTS provision_status VARCHAR(16) NOT NULL DEFAULT 'ready'
    CHECK (provision_status IN ('provisioning', 'ready', 'failed'));
