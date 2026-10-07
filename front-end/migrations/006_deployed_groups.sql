-- ============================================================================
-- CLINIC-IN-A-BOX: Deployed Groups tracking table
-- ============================================================================
-- Tracks batch-deployed user groups for the CyberHub Admin Dashboard
-- so they can be torn down as a single unit.
-- ============================================================================

CREATE TABLE IF NOT EXISTS deployed_groups (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  group_name VARCHAR(255) NOT NULL,
  config JSONB NOT NULL DEFAULT '{}',
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_deployed_groups_name ON deployed_groups(group_name);
