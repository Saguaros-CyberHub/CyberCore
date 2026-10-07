-- ============================================================================
-- Migration 008: Account Access Schedules
-- Adds time-based access windows for group student accounts
-- ============================================================================

CREATE TABLE IF NOT EXISTS account_schedules (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  group_id UUID NOT NULL REFERENCES deployed_groups(id) ON DELETE CASCADE,
  active_days INTEGER[] NOT NULL DEFAULT '{1,2,3,4,5}',  -- 0=Sun, 1=Mon, 2=Tue, 3=Wed, 4=Thu, 5=Fri, 6=Sat
  active_start TIME NOT NULL DEFAULT '08:00',
  active_end TIME NOT NULL DEFAULT '17:00',
  timezone VARCHAR(50) NOT NULL DEFAULT 'America/Chicago',
  override_active BOOLEAN DEFAULT NULL,  -- NULL=use schedule, true=force on, false=force off
  override_by UUID REFERENCES users(id),
  override_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- One schedule per group
CREATE UNIQUE INDEX IF NOT EXISTS idx_account_schedules_group
  ON account_schedules(group_id);

-- Index for fast lookup during auth
CREATE INDEX IF NOT EXISTS idx_account_schedules_override
  ON account_schedules(override_active) WHERE override_active IS NOT NULL;
