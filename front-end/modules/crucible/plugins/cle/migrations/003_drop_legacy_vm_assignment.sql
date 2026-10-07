/*
 * ============================================================================
 * CLE Migration 003 — Drop legacy VM-assignment tables
 * ----------------------------------------------------------------------------
 * CLE provisioning is now lane-native: each student's workstation is a
 * cybercore_lane row (source of truth). The old per-VM assignment tables are no
 * longer written or read by any code — VM/lane counts are derived from
 * cybercore_lane (config.course_id). Drop the dead tables.
 * ============================================================================
 */

DROP TABLE IF EXISTS cle_user_vm_assignment;
DROP TABLE IF EXISTS cle_course_vm_assignment;
