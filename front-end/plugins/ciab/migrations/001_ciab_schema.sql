-- ============================================================================
-- CLINIC-IN-A-BOX PLUGIN — FULL SCHEMA
-- All CIAB tables for clinic_db. NO users table (users live in cybercore_user).
-- user_id columns store UUIDs without FK constraints (cross-DB reference).
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- === Profiles ===
CREATE TABLE IF NOT EXISTS profiles (
  id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id                 UUID NOT NULL,
  run_id                  VARCHAR(100) NOT NULL UNIQUE,
  client_type             VARCHAR(50) NOT NULL,
  client_type_name        VARCHAR(100),
  industry                VARCHAR(255),
  difficulty              VARCHAR(50),
  maturity_level          VARCHAR(50),
  delivery_mode           VARCHAR(100),
  company_name            VARCHAR(255),
  hq_city                 VARCHAR(100),
  employee_count          INTEGER,
  stakeholder_count       INTEGER,
  endpoint_count          INTEGER,
  compliance_frameworks   JSONB,
  key_risks               JSONB,
  critical_systems        JSONB,
  html_filename           VARCHAR(255),
  json_filename           VARCHAR(255),
  html_file_path          VARCHAR(500),
  json_file_path          VARCHAR(500),
  generation_status       VARCHAR(50) DEFAULT 'pending',
  generation_time_seconds NUMERIC,
  file_size_bytes         INTEGER,
  scaffolding_level       VARCHAR(20) DEFAULT 'intermediate',
  nice_alignment          JSONB DEFAULT '{}'::jsonb,
  instructor_materials    JSONB DEFAULT '{}'::jsonb,
  student_worksheets      JSONB DEFAULT '{}'::jsonb,
  artifacts               JSONB DEFAULT '{}'::jsonb,
  learning_objectives     JSONB DEFAULT '{}'::jsonb,
  grading_rubric          JSONB DEFAULT '{}'::jsonb,
  difficulty_settings     JSONB DEFAULT '{}'::jsonb,
  profile_type            VARCHAR(50) DEFAULT 'standard',
  created_at              TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
  updated_at              TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_profiles_user_id      ON profiles(user_id);
CREATE INDEX IF NOT EXISTS idx_profiles_client_type   ON profiles(client_type);
CREATE INDEX IF NOT EXISTS idx_profiles_company_name  ON profiles(company_name);
CREATE INDEX IF NOT EXISTS idx_profiles_industry      ON profiles(industry);
CREATE INDEX IF NOT EXISTS idx_profiles_status        ON profiles(generation_status);
CREATE INDEX IF NOT EXISTS idx_profiles_scaffolding   ON profiles(scaffolding_level);
CREATE INDEX IF NOT EXISTS idx_profiles_created_at    ON profiles(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_profiles_search        ON profiles USING gin(
  to_tsvector('english', COALESCE(company_name,'') || ' ' || COALESCE(industry,'') || ' ' || COALESCE(hq_city,''))
);

-- === Assessment Progress ===
CREATE TABLE IF NOT EXISTS assessment_progress (
  id                 UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id            UUID NOT NULL,
  profile_id         UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  part_number        INTEGER NOT NULL,
  part_name          VARCHAR(100) NOT NULL,
  output_option      VARCHAR(500),
  output_option_name VARCHAR(200),
  status             VARCHAR(20) NOT NULL DEFAULT 'not_started',
  content            TEXT,
  content_format     VARCHAR(20) DEFAULT 'markdown',
  evidence_files     JSONB DEFAULT '[]'::jsonb,
  submitted_at       TIMESTAMPTZ,
  revision_count     INTEGER DEFAULT 0,
  reviewed_at        TIMESTAMPTZ,
  reviewer_id        UUID,
  feedback           TEXT,
  score              NUMERIC,
  rubric_scores      JSONB,
  created_at         TIMESTAMPTZ DEFAULT now(),
  updated_at         TIMESTAMPTZ DEFAULT now(),
  UNIQUE(user_id, profile_id, part_number)
);

CREATE INDEX IF NOT EXISTS idx_progress_user_profile ON assessment_progress(user_id, profile_id);
CREATE INDEX IF NOT EXISTS idx_progress_status       ON assessment_progress(status);
CREATE INDEX IF NOT EXISTS idx_progress_reviewer     ON assessment_progress(reviewer_id) WHERE reviewer_id IS NOT NULL;

-- === Activity Log ===
CREATE TABLE IF NOT EXISTS activity_log (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id     UUID,
  action_type VARCHAR(50) NOT NULL,
  entity_type VARCHAR(50),
  entity_id   UUID,
  metadata    JSONB DEFAULT '{}'::jsonb,
  ip_address  INET,
  user_agent  TEXT,
  created_at  TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_activity_log_user    ON activity_log(user_id);
CREATE INDEX IF NOT EXISTS idx_activity_log_action  ON activity_log(action_type);
CREATE INDEX IF NOT EXISTS idx_activity_log_entity  ON activity_log(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_activity_log_created ON activity_log(created_at);

-- === Sessions ===
CREATE TABLE IF NOT EXISTS sessions (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id       UUID NOT NULL,
  token         VARCHAR(500) NOT NULL UNIQUE,
  ip_address    INET,
  user_agent    TEXT,
  is_valid      BOOLEAN DEFAULT true,
  expires_at    TIMESTAMPTZ NOT NULL,
  created_at    TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
  last_activity TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token   ON sessions(token);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

-- === Tags ===
CREATE TABLE IF NOT EXISTS tags (
  id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name       VARCHAR(100) NOT NULL UNIQUE,
  color      VARCHAR(7) DEFAULT '#6B7280',
  created_by UUID,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- === Profile Tags ===
CREATE TABLE IF NOT EXISTS profile_tags (
  profile_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  tag_id     UUID NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
  PRIMARY KEY (profile_id, tag_id)
);

-- === Profile Files ===
CREATE TABLE IF NOT EXISTS profile_files (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  profile_id      UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  file_type       VARCHAR(50) NOT NULL,
  filename        VARCHAR(255) NOT NULL,
  file_path       VARCHAR(500) NOT NULL,
  file_size_bytes INTEGER,
  mime_type       VARCHAR(100),
  checksum        VARCHAR(64),
  ftp_uploaded    BOOLEAN DEFAULT false,
  ftp_upload_time TIMESTAMPTZ,
  created_at      TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_profile_files_profile_id ON profile_files(profile_id);
CREATE INDEX IF NOT EXISTS idx_profile_files_type       ON profile_files(file_type);

-- === Favorites ===
CREATE TABLE IF NOT EXISTS favorites (
  user_id    UUID NOT NULL,
  profile_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (user_id, profile_id)
);

-- === Generated Documents ===
CREATE TABLE IF NOT EXISTS generated_documents (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  profile_id    UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  document_type VARCHAR(20) NOT NULL CHECK (document_type IN ('nessus','zap','nmap','combined','policies')),
  filename      VARCHAR(255) NOT NULL,
  content       TEXT,
  file_path     TEXT,
  file_size     INTEGER,
  metadata      JSONB DEFAULT '{}'::jsonb,
  generated_by  UUID,
  generated_at  TIMESTAMPTZ DEFAULT now(),
  UNIQUE(profile_id, document_type)
);

CREATE INDEX IF NOT EXISTS idx_generated_docs_profile ON generated_documents(profile_id);

-- === Security Documents ===
CREATE TABLE IF NOT EXISTS security_documents (
  id                   UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  profile_id           UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  generated_by         UUID NOT NULL,
  document_type        VARCHAR(50) NOT NULL,
  file_name            VARCHAR(255) NOT NULL,
  file_path            VARCHAR(500) NOT NULL,
  file_size_bytes      INTEGER,
  content_summary      JSONB,
  vulnerability_count  INTEGER,
  critical_count       INTEGER,
  high_count           INTEGER,
  medium_count         INTEGER,
  low_count            INTEGER,
  is_public            BOOLEAN DEFAULT false,
  shared_with_students TEXT[],
  generation_params    JSONB,
  generated_at         TIMESTAMPTZ DEFAULT now(),
  created_at           TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_security_docs_profile    ON security_documents(profile_id);
CREATE INDEX IF NOT EXISTS idx_security_docs_instructor ON security_documents(generated_by);
CREATE INDEX IF NOT EXISTS idx_security_docs_type       ON security_documents(document_type);

-- === Document Access Log ===
CREATE TABLE IF NOT EXISTS document_access_log (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  document_id UUID NOT NULL,
  user_id     UUID NOT NULL,
  access_type VARCHAR(20) DEFAULT 'view',
  accessed_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_doc_access_document ON document_access_log(document_id);
CREATE INDEX IF NOT EXISTS idx_doc_access_user     ON document_access_log(user_id);
CREATE INDEX IF NOT EXISTS idx_doc_access_time     ON document_access_log(accessed_at);

-- === Interview Sessions ===
CREATE TABLE IF NOT EXISTS interview_sessions (
  id                   UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id              UUID NOT NULL,
  profile_id           UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  stakeholder_id       VARCHAR(50) NOT NULL,
  stakeholder_name     VARCHAR(100) NOT NULL,
  stakeholder_role     VARCHAR(100),
  transcript           JSONB NOT NULL DEFAULT '[]'::jsonb,
  questions_asked      INTEGER DEFAULT 0,
  information_gathered JSONB DEFAULT '[]'::jsonb,
  quality_score        NUMERIC,
  status               VARCHAR(20) DEFAULT 'active',
  started_at           TIMESTAMPTZ DEFAULT now(),
  ended_at             TIMESTAMPTZ,
  duration_seconds     INTEGER,
  created_at           TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_interview_user_profile  ON interview_sessions(user_id, profile_id);
CREATE INDEX IF NOT EXISTS idx_interview_stakeholder   ON interview_sessions(profile_id, stakeholder_id);

-- === Intake Form Responses ===
CREATE TABLE IF NOT EXISTS intake_form_responses (
  id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id                 UUID NOT NULL,
  profile_id              UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  organization_info       JSONB DEFAULT '{}'::jsonb,
  technical_environment   JSONB DEFAULT '{}'::jsonb,
  security_current_state  JSONB DEFAULT '{}'::jsonb,
  compliance_requirements JSONB DEFAULT '{}'::jsonb,
  risk_concerns           JSONB DEFAULT '{}'::jsonb,
  additional_notes        TEXT,
  status                  VARCHAR(20) DEFAULT 'not_started',
  completion_percentage   INTEGER DEFAULT 0,
  interview_session_id    UUID,
  started_at              TIMESTAMPTZ,
  completed_at            TIMESTAMPTZ,
  last_saved_at           TIMESTAMPTZ,
  created_at              TIMESTAMPTZ DEFAULT now(),
  updated_at              TIMESTAMPTZ DEFAULT now(),
  company_info            JSONB DEFAULT '{}'::jsonb,
  security_policies       JSONB DEFAULT '{}'::jsonb,
  data_management         JSONB DEFAULT '{}'::jsonb,
  network_security        JSONB DEFAULT '{}'::jsonb,
  wireless                JSONB DEFAULT '{}'::jsonb,
  endpoint_security       JSONB DEFAULT '{}'::jsonb,
  compliance              JSONB DEFAULT '{}'::jsonb,
  software_assets         JSONB DEFAULT '{}'::jsonb,
  vuln_management         JSONB DEFAULT '{}'::jsonb,
  admin_privileges        JSONB DEFAULT '{}'::jsonb,
  secure_config           JSONB DEFAULT '{}'::jsonb,
  email_web               JSONB DEFAULT '{}'::jsonb,
  network_ports           JSONB DEFAULT '{}'::jsonb,
  network_devices         JSONB DEFAULT '{}'::jsonb,
  pentesting              JSONB DEFAULT '{}'::jsonb,
  UNIQUE(user_id, profile_id)
);

CREATE INDEX IF NOT EXISTS idx_intake_user_profile ON intake_form_responses(user_id, profile_id);
CREATE INDEX IF NOT EXISTS idx_intake_status       ON intake_form_responses(status);

-- === NICE Framework Reference ===
CREATE TABLE IF NOT EXISTS nice_framework_reference (
  id               VARCHAR(20) PRIMARY KEY,
  type             VARCHAR(20) NOT NULL,
  name             VARCHAR(200) NOT NULL,
  description      TEXT,
  work_roles       TEXT[],
  assessment_parts INTEGER[],
  created_at       TIMESTAMPTZ DEFAULT now()
);

-- === NICE Progress ===
CREATE TABLE IF NOT EXISTS nice_progress (
  id                       UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id                  UUID NOT NULL,
  work_role                VARCHAR(100) NOT NULL,
  work_role_id             VARCHAR(20),
  competency_type          VARCHAR(20) NOT NULL,
  competency_id            VARCHAR(20) NOT NULL,
  competency_description   TEXT,
  demonstrated_at          TIMESTAMPTZ DEFAULT now(),
  evidence_type            VARCHAR(50),
  evidence_link            UUID,
  profile_id               UUID,
  part_number              INTEGER,
  created_at               TIMESTAMPTZ DEFAULT now(),
  UNIQUE(user_id, work_role_id, competency_type, competency_id)
);

CREATE INDEX IF NOT EXISTS idx_nice_user       ON nice_progress(user_id);
CREATE INDEX IF NOT EXISTS idx_nice_work_role  ON nice_progress(work_role_id);
CREATE INDEX IF NOT EXISTS idx_nice_competency ON nice_progress(competency_type, competency_id);

-- === Peer Reviews ===
CREATE TABLE IF NOT EXISTS peer_reviews (
  id                 UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  submission_id      UUID NOT NULL REFERENCES assessment_progress(id) ON DELETE CASCADE,
  reviewer_id        UUID NOT NULL,
  feedback           TEXT NOT NULL,
  rubric_scores      JSONB,
  overall_rating     INTEGER,
  helpfulness_rating INTEGER,
  status             VARCHAR(20) DEFAULT 'submitted',
  created_at         TIMESTAMPTZ DEFAULT now(),
  updated_at         TIMESTAMPTZ DEFAULT now(),
  UNIQUE(submission_id, reviewer_id)
);

CREATE INDEX IF NOT EXISTS idx_peer_reviews_submission ON peer_reviews(submission_id);
CREATE INDEX IF NOT EXISTS idx_peer_reviews_reviewer   ON peer_reviews(reviewer_id);

-- === Deployed Groups ===
CREATE TABLE IF NOT EXISTS deployed_groups (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  group_name VARCHAR(255) NOT NULL,
  config     JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_by UUID,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_deployed_groups_name ON deployed_groups(group_name);

-- === Account Schedules ===
CREATE TABLE IF NOT EXISTS account_schedules (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  group_id        UUID NOT NULL REFERENCES deployed_groups(id) ON DELETE CASCADE,
  active_days     INTEGER[] NOT NULL DEFAULT '{1,2,3,4,5}',
  active_start    TIME NOT NULL DEFAULT '08:00',
  active_end      TIME NOT NULL DEFAULT '17:00',
  timezone        VARCHAR(50) NOT NULL DEFAULT 'America/Chicago',
  override_active BOOLEAN,
  override_by     UUID,
  override_at     TIMESTAMPTZ,
  created_at      TIMESTAMPTZ DEFAULT now(),
  updated_at      TIMESTAMPTZ DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_account_schedules_group    ON account_schedules(group_id);
CREATE INDEX IF NOT EXISTS idx_account_schedules_override ON account_schedules(override_active) WHERE override_active IS NOT NULL;

-- === Instructor Assignments ===
CREATE TABLE IF NOT EXISTS instructor_assignments (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  instructor_id UUID NOT NULL,
  student_id    UUID NOT NULL,
  profile_id    UUID REFERENCES profiles(id) ON DELETE SET NULL,
  assigned_at   TIMESTAMPTZ DEFAULT now(),
  due_date      TIMESTAMPTZ,
  notes         TEXT,
  created_at    TIMESTAMPTZ DEFAULT now(),
  UNIQUE(instructor_id, student_id, profile_id)
);

CREATE INDEX IF NOT EXISTS idx_instructor_assignments_instructor ON instructor_assignments(instructor_id);
CREATE INDEX IF NOT EXISTS idx_instructor_assignments_student    ON instructor_assignments(student_id);

-- === Instructor Working Sets ===
CREATE TABLE IF NOT EXISTS instructor_working_sets (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  instructor_id UUID NOT NULL,
  student_id    UUID NOT NULL,
  set_name      VARCHAR(100) DEFAULT 'My Students',
  notes         TEXT,
  color_tag     VARCHAR(20),
  is_active     BOOLEAN DEFAULT true,
  added_at      TIMESTAMPTZ DEFAULT now(),
  removed_at    TIMESTAMPTZ,
  UNIQUE(instructor_id, student_id)
);

CREATE INDEX IF NOT EXISTS idx_working_sets_instructor ON instructor_working_sets(instructor_id);
CREATE INDEX IF NOT EXISTS idx_working_sets_student    ON instructor_working_sets(student_id);
CREATE INDEX IF NOT EXISTS idx_working_sets_active     ON instructor_working_sets(instructor_id, is_active) WHERE is_active = true;

-- === Challenge Templates ===
CREATE TABLE IF NOT EXISTS challenge_templates (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name           VARCHAR(255) NOT NULL,
  description    TEXT,
  difficulty     VARCHAR(50) DEFAULT 'intermediate',
  created_by     UUID,
  vm_specs       JSONB NOT NULL DEFAULT '[]'::jsonb,
  phantom_assets JSONB DEFAULT '[]'::jsonb,
  metadata       JSONB DEFAULT '{}'::jsonb,
  is_active      BOOLEAN DEFAULT true,
  created_at     TIMESTAMPTZ DEFAULT now(),
  updated_at     TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_challenge_templates_active ON challenge_templates(is_active) WHERE is_active = true;

-- === Vulnerability Scripts ===
CREATE TABLE IF NOT EXISTS vuln_scripts (
  id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  slug                 VARCHAR(128) NOT NULL UNIQUE,
  name                 VARCHAR(255) NOT NULL,
  description          TEXT,
  category             VARCHAR(100) NOT NULL,
  os_target            VARCHAR(50) NOT NULL DEFAULT 'windows',
  difficulty           VARCHAR(50) DEFAULT 'intermediate',
  script_content       TEXT NOT NULL,
  services_exposed     JSONB DEFAULT '[]'::jsonb,
  depends_on           TEXT[] DEFAULT '{}',
  estimated_runtime_sec INTEGER DEFAULT 60,
  is_active            BOOLEAN DEFAULT true,
  created_at           TIMESTAMPTZ DEFAULT now(),
  script_args          VARCHAR(500) DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_vuln_scripts_category ON vuln_scripts(category);
CREATE INDEX IF NOT EXISTS idx_vuln_scripts_os       ON vuln_scripts(os_target);
CREATE INDEX IF NOT EXISTS idx_vuln_scripts_active   ON vuln_scripts(is_active) WHERE is_active = true;

-- === Deployment Vulnerability Selections ===
CREATE TABLE IF NOT EXISTS deployment_vuln_selections (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  lane_id          UUID NOT NULL,
  template_id      UUID,
  selected_scripts JSONB NOT NULL DEFAULT '[]'::jsonb,
  deployed_network JSONB DEFAULT '{}'::jsonb,
  profile_id       UUID,
  status           VARCHAR(50) DEFAULT 'pending',
  created_at       TIMESTAMPTZ DEFAULT now(),
  updated_at       TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_dvs_lane     ON deployment_vuln_selections(lane_id);
CREATE INDEX IF NOT EXISTS idx_dvs_status   ON deployment_vuln_selections(status);
CREATE INDEX IF NOT EXISTS idx_dvs_template ON deployment_vuln_selections(template_id);

-- ============================================================================
-- VIEWS
-- ============================================================================

-- Profile listing view (joins with cybercore_user via app-level, not DB-level)
CREATE OR REPLACE VIEW profile_listing AS
SELECT
  p.id, p.run_id, p.client_type, p.client_type_name, p.industry,
  p.difficulty, p.company_name, p.hq_city, p.employee_count,
  p.generation_status, p.html_file_path, p.json_file_path,
  p.created_at, p.user_id,
  NULL::VARCHAR(255) AS user_email,
  NULL::VARCHAR(100) AS first_name,
  NULL::VARCHAR(100) AS last_name,
  NULL::TEXT AS full_name
FROM profiles p;

-- Interview summary view
CREATE OR REPLACE VIEW v_interview_summary AS
SELECT
  i.user_id, i.profile_id,
  COUNT(*) AS total_interviews,
  SUM(i.questions_asked) AS total_questions,
  ROUND(AVG(i.quality_score), 1) AS avg_quality,
  COUNT(*) FILTER (WHERE i.status = 'completed') AS completed_interviews,
  jsonb_agg(DISTINCT jsonb_build_object('id', i.stakeholder_id, 'name', i.stakeholder_name)) AS stakeholders_interviewed
FROM interview_sessions i
GROUP BY i.user_id, i.profile_id;

-- Student progress summary view
CREATE OR REPLACE VIEW v_student_progress_summary AS
SELECT
  p.user_id,
  NULL::VARCHAR(255) AS email,
  NULL::VARCHAR(50) AS role,
  p.id AS profile_id,
  p.company_name AS profile_name,
  p.scaffolding_level,
  COUNT(ap.id) FILTER (WHERE ap.status != 'not_started') AS parts_started,
  COUNT(ap.id) FILTER (WHERE ap.status = 'submitted' OR ap.status = 'reviewed') AS parts_submitted,
  COUNT(ap.id) FILTER (WHERE ap.status = 'reviewed') AS parts_reviewed,
  ROUND(AVG(ap.score), 1) AS avg_score,
  MAX(ap.updated_at) AS last_activity
FROM profiles p
LEFT JOIN assessment_progress ap ON ap.profile_id = p.id
GROUP BY p.user_id, p.id, p.company_name, p.scaffolding_level;
