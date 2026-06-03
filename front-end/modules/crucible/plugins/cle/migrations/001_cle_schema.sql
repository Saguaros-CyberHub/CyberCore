/*
 * ============================================================================
 * CLE (Cyber Learning Environment) Schema
 * Allows instructors to manage students/faculty access to courses and VMs
 * 
 * References:
 * - cybercore_user from cybercore_db (users table)
 * - cybercore_vm_instance from cybercore_db (VM instances)
 * - cybercore_resource from cybercore_db (resource allocation)
 * - Only creates CLE-specific tables for courses, enrollments, assignments, materials
 * ============================================================================
 */


-- ============================================================================
-- CLE COURSES TABLE
-- ============================================================================
-- Represents a course managed by an instructor
-- Instructor is a reference to cybercore_user with role 'instructor'
CREATE TABLE IF NOT EXISTS cle_course (
  course_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  course_key VARCHAR(100) UNIQUE,
  course_name VARCHAR(255) NOT NULL,
  code VARCHAR(50),
  description TEXT,
  instructor_id UUID NOT NULL,
  start_date DATE,
  end_date DATE,
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_cle_course_instructor ON cle_course(instructor_id);
CREATE INDEX IF NOT EXISTS idx_cle_course_key ON cle_course(course_key);


-- ============================================================================
-- CLE COURSE ENROLLMENTS TABLE
-- ============================================================================
-- Many-to-many: Students/faculty enrolled in courses
-- References cybercore_user for enrolled students/faculty
CREATE TABLE IF NOT EXISTS cle_course_enrollment (
  enrollment_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  course_id UUID NOT NULL REFERENCES cle_course(course_id) ON DELETE CASCADE,
  enrollment_role VARCHAR(50) DEFAULT 'student' CHECK (enrollment_role IN ('student', 'ta', 'guest', 'lab_assistant')),
  enrolled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  completion_date TIMESTAMP,
  status VARCHAR(50) DEFAULT 'active' CHECK (status IN ('active', 'completed', 'dropped', 'pending', 'suspended')),
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id, course_id)
);

CREATE INDEX IF NOT EXISTS idx_cle_enrollment_user ON cle_course_enrollment(user_id);
CREATE INDEX IF NOT EXISTS idx_cle_enrollment_course ON cle_course_enrollment(course_id);
CREATE INDEX IF NOT EXISTS idx_cle_enrollment_status ON cle_course_enrollment(status);


-- ============================================================================
-- CLE COURSE MATERIALS TABLE
-- ============================================================================
-- Course materials: lectures, labs, assignments, quizzes, resources, rubrics
-- References cybercore_user for the instructor who created it
-- References cybercore_challenge_template for vulnerable lab deployments
CREATE TABLE IF NOT EXISTS cle_course_material (
  material_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  course_id UUID NOT NULL REFERENCES cle_course(course_id) ON DELETE CASCADE,
  template_id UUID,
  title VARCHAR(255) NOT NULL,
  description TEXT,
  type VARCHAR(50) DEFAULT 'lecture' CHECK (type IN ('lecture', 'lab', 'assignment', 'quiz', 'resource', 'rubric', 'vulnerable_lab')),
  content TEXT,
  file_path VARCHAR(500),
  file_size BIGINT,
  created_by UUID NOT NULL,
  is_published BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_cle_material_course ON cle_course_material(course_id);
CREATE INDEX IF NOT EXISTS idx_cle_material_type ON cle_course_material(type);
CREATE INDEX IF NOT EXISTS idx_cle_material_creator ON cle_course_material(created_by);
CREATE INDEX IF NOT EXISTS idx_cle_material_template ON cle_course_material(template_id);


-- ============================================================================
-- CLE ACTIVITY LOG TABLE
-- ============================================================================
-- Track user actions for audit and analytics
-- References cybercore_user for activity tracking
CREATE TABLE IF NOT EXISTS cle_activity_log (
  activity_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID,
  action_type VARCHAR(50) CHECK (action_type IN ('login', 'logout', 'vm_start', 'vm_stop', 'assignment_submit', 'material_view', 'course_access', 'enrollment_change', 'guac_session')),
  entity_type VARCHAR(50),
  entity_id UUID,
  metadata JSONB,
  ip_address INET,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_cle_activity_user ON cle_activity_log(user_id);
CREATE INDEX IF NOT EXISTS idx_cle_activity_action ON cle_activity_log(action_type);
CREATE INDEX IF NOT EXISTS idx_cle_activity_timestamp ON cle_activity_log(created_at);


-- ============================================================================
-- CLE STUDENT SUBMISSION TABLE
-- ============================================================================
-- Track student submissions for assignments
-- References cybercore_user for submitting student and grading instructor
CREATE TABLE IF NOT EXISTS cle_student_submission (
  submission_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  material_id UUID NOT NULL REFERENCES cle_course_material(material_id) ON DELETE CASCADE,
  user_id UUID NOT NULL,
  submission_content TEXT,
  submission_file_path VARCHAR(500),
  submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  feedback TEXT,
  grade DECIMAL(5, 2),
  graded_by UUID,
  graded_at TIMESTAMP,
  UNIQUE(material_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_cle_submission_user ON cle_student_submission(user_id);
CREATE INDEX IF NOT EXISTS idx_cle_submission_material ON cle_student_submission(material_id);
CREATE INDEX IF NOT EXISTS idx_cle_submission_graded ON cle_student_submission(graded_by);
