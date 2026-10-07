-- ============================================================================
-- Migration 010: Ensure instructor_working_sets table exists
-- (May already exist from initial schema — uses IF NOT EXISTS)
-- ============================================================================

CREATE TABLE IF NOT EXISTS instructor_working_sets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  instructor_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  student_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  is_active BOOLEAN DEFAULT true,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(instructor_id, student_id)
);

CREATE INDEX IF NOT EXISTS idx_working_sets_instructor ON instructor_working_sets(instructor_id);
CREATE INDEX IF NOT EXISTS idx_working_sets_student ON instructor_working_sets(student_id);
