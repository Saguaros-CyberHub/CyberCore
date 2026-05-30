/*
 * ============================================================================
 * Instructor Routes - Dashboard and Grading
 * ============================================================================
 */

const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');
const PDFDocument = require('pdfkit');
const { query, pool } = require('../utils/db');
const jwt = require('jsonwebtoken');
const { authenticateToken, requireRole } = require('../../../../../src/middleware/auth');
const { renderIntakePdf } = require('./intake-form');
const { cybercoreQuery } = require('../../../../../src/utils/cybercore-db');
const { proxmoxAPI } = require('../../../../../src/utils/proxmox');
const { guacAPI, getGuacToken, GUAC_URL, GUAC_DS } = require('../../../../../src/utils/guacamole');

const instructorOnly = requireRole('instructor', 'admin');

// ─── In-memory generation job tracker ────────────────────────────────────────
// Tracks active example generation jobs so the frontend can check status on
// page load/refresh and prevent duplicate generation requests.
const activeGenerationJobs = new Map(); // key: `${userId}:${profileId}` → { status, startedAt, model }

function getJobKey(userId, profileId) { return `${userId}:${profileId}`; }

function setJobActive(userId, profileId, model) {
  activeGenerationJobs.set(getJobKey(userId, profileId), {
    status: 'generating',
    startedAt: new Date().toISOString(),
    model: model || 'default'
  });
}

function setJobComplete(userId, profileId) {
  activeGenerationJobs.delete(getJobKey(userId, profileId));
}

function getJobStatus(userId, profileId) {
  const job = activeGenerationJobs.get(getJobKey(userId, profileId));
  if (!job) return null;
  // Auto-expire stale jobs after 20 minutes (safety net)
  const elapsed = Date.now() - new Date(job.startedAt).getTime();
  if (elapsed > 20 * 60 * 1000) {
    activeGenerationJobs.delete(getJobKey(userId, profileId));
    return null;
  }
  return job;
}

// GET /api/instructor/generation-status/:profileId — check if generation is in progress
router.get('/generation-status/:profileId', authenticateToken, instructorOnly, (req, res) => {
  const job = getJobStatus(req.user.userId, req.params.profileId);
  if (job) {
    res.json({ generating: true, ...job });
  } else {
    res.json({ generating: false });
  }
});

// POST /api/instructor/store-example — DEPRECATED.
// Previously called by N8N's E4 node to write generated answer-key parts back.
// As of the N8N removal, ai/examples writes directly to assessment_progress.
// Kept callable for one release in case any external integration still posts here.
router.post('/store-example', authenticateToken, async (req, res) => {
  try {
    const { user_id, profile_id, part_number, part_name, content, output_option } = req.body;

    if (!user_id || !profile_id || !part_number) {
      return res.status(400).json({ error: 'Missing required fields: user_id, profile_id, part_number' });
    }

    // Parse output_option to build output_option_name
    let optionNames = null;
    try {
      const keys = JSON.parse(output_option || '[]');
      if (Array.isArray(keys)) {
        optionNames = keys.join(', ');
      }
    } catch (_) {}

    await query(`
      INSERT INTO assessment_progress
        (user_id, profile_id, part_number, part_name, content, output_option, output_option_name, status)
      VALUES ($1, $2, $3, $4, $5, $6, $7, 'reviewed')
      ON CONFLICT (user_id, profile_id, part_number)
      DO UPDATE SET
        content = EXCLUDED.content,
        output_option = EXCLUDED.output_option,
        output_option_name = EXCLUDED.output_option_name,
        status = 'reviewed',
        updated_at = NOW()
    `, [user_id, profile_id, part_number, part_name, content, output_option, optionNames]);

    console.log(`[StoreExample] Stored part ${part_number} for profile ${profile_id}`);
    res.json({ success: true, part_number });
  } catch (error) {
    console.error('[StoreExample] Error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// Simple test endpoint
router.get('/test', authenticateToken, async (req, res) => {
  try {
    res.json({
      success: true,
      user: req.user,
      message: 'Instructor routes working'
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ─── Vuln-app cheat sheet (answer key for instructors + admins) ────────────
// Returns the attack chain, instructor notes, seed credentials, and per-file
// vuln annotations for a profile's most recently generated vuln-app. Surfaced
// in the instructor dashboard's "Documents & Answer Keys" tab so instructors
// can see exactly what students are expected to find, with copy-pasteable
// flags and login credentials — without grep'ing source_tree JSONB by hand.
//
// Gated to instructor + admin roles. Page-level auth already restricts the
// dashboard to those two roles, so this matches that boundary.
router.get('/vuln-cheat-sheet/:profileId', authenticateToken, instructorOnly, async (req, res) => {
  try {
    const { profileId } = req.params;
    // Latest vuln-app row for this profile (regeneration creates a new row).
    const r = await query(`
      SELECT profile_id, generation_meta, delivery_mode, created_at
      FROM ciab_profile_vuln_apps
      WHERE profile_id = $1
      ORDER BY created_at DESC
      LIMIT 1
    `, [profileId]);

    if (!r.rows.length) {
      return res.status(404).json({
        error: 'No vuln-app generated for this profile yet — run a deploy first.',
        profile_id: profileId
      });
    }

    const row = r.rows[0];
    const meta = row.generation_meta || {};
    // Shape into a payload the frontend can render directly. Defensively pull
    // every field that might be present — older rows may be missing
    // file_annotations or seed_data, and that's fine, the UI handles nulls.
    res.json({
      profile_id: row.profile_id,
      generated_at: row.created_at,
      delivery_mode: row.delivery_mode,
      difficulty: meta.difficulty || null,
      title: meta.title || null,
      theme_summary: meta.theme_summary || null,
      tech_stack: meta.tech_stack || null,
      primary_language: meta.primary_language || null,
      instructor_notes: meta.instructor_notes || null,
      post_install_notes: meta.post_install_notes || null,
      attack_chain: Array.isArray(meta.attack_chain) ? meta.attack_chain : [],
      seed_data: meta.seed_data || null,
      file_annotations: meta.file_annotations || {},
      page_count: meta.page_count || null,
      page_errors: meta.page_errors || []
    });
  } catch (error) {
    console.error('[VulnCheatSheet] Error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// GET /api/instructor/dashboard - Get instructor dashboard data
router.get('/dashboard', authenticateToken, instructorOnly, async (req, res) => {
  try {
    const instructorId = req.user.userId;
    
    let students = [];
    let pendingSubmissions = [];

    // Get ALL students from cybercore_db (users live in cybercore_user, not in clinic_db)
    try {
      const usersResult = await cybercoreQuery(`
        SELECT
          user_id AS student_id,
          email AS student_email,
          CONCAT(first_name, ' ', last_name) AS student_name,
          first_name,
          last_name,
          created_at AS student_joined,
          role,
          organization
        FROM cybercore_user
        WHERE role = 'student' OR role IS NULL
        ORDER BY last_name ASC NULLS LAST, first_name ASC NULLS LAST, email ASC
      `);
      const userRows = usersResult.rows;

      // Build a lookup map of all users (so we can resolve instructor names for assignments/watching)
      const allUsersResult = await cybercoreQuery(`
        SELECT user_id AS id, email, first_name, last_name FROM cybercore_user
      `);
      const userMap = {};
      allUsersResult.rows.forEach(u => { userMap[u.id] = u; });

      const studentIds = userRows.map(u => u.student_id);
      const profilesByUser = {};
      const assignmentsByStudent = {};
      const watchingByStudent = {};
      const reviewCountsByUser = {};

      if (studentIds.length > 0) {
        const placeholders = studentIds.map((_, i) => `$${i + 1}`).join(',');

        // Fetch profiles per student (clinic_db)
        const profilesResult = await query(
          `SELECT id AS profile_id, user_id, company_name, industry, difficulty, created_at
           FROM profiles
           WHERE user_id::text IN (${placeholders})`,
          studentIds
        );
        profilesResult.rows.forEach(p => {
          if (!profilesByUser[p.user_id]) profilesByUser[p.user_id] = [];
          profilesByUser[p.user_id].push(p);
        });

        // Fetch instructor assignments per student
        const assignmentsResult = await query(
          `SELECT student_id, profile_id, instructor_id, due_date, assigned_at
           FROM instructor_assignments
           WHERE student_id::text IN (${placeholders})`,
          studentIds
        );
        assignmentsResult.rows.forEach(a => {
          if (!assignmentsByStudent[a.student_id]) assignmentsByStudent[a.student_id] = [];
          const inst = userMap[a.instructor_id] || {};
          assignmentsByStudent[a.student_id].push({
            profile_id: a.profile_id,
            instructor_id: a.instructor_id,
            instructor_email: inst.email || null,
            instructor_name: inst.first_name ? `${inst.first_name} ${inst.last_name}` : null,
            due_date: a.due_date,
            assigned_at: a.assigned_at
          });
        });

        // Fetch instructors watching each student
        const watchingResult = await query(
          `SELECT DISTINCT student_id, instructor_id
           FROM instructor_working_sets
           WHERE student_id::text IN (${placeholders})`,
          studentIds
        );
        watchingResult.rows.forEach(w => {
          if (!watchingByStudent[w.student_id]) watchingByStudent[w.student_id] = [];
          const inst = userMap[w.instructor_id] || {};
          watchingByStudent[w.student_id].push({
            instructor_id: w.instructor_id,
            instructor_email: inst.email || null,
            instructor_name: inst.first_name ? `${inst.first_name} ${inst.last_name}` : null
          });
        });

        // Fetch progress counts (pending_reviews, completed_reviews, parts_started)
        const progressResult = await query(
          `SELECT user_id,
                  COUNT(*) FILTER (WHERE status = 'submitted') AS pending_reviews,
                  COUNT(*) FILTER (WHERE status = 'reviewed') AS completed_reviews,
                  COUNT(DISTINCT part_number) AS parts_started
           FROM assessment_progress
           WHERE user_id::text IN (${placeholders})
           GROUP BY user_id`,
          studentIds
        );
        progressResult.rows.forEach(r => {
          reviewCountsByUser[r.user_id] = r;
        });
      }

      // Merge everything per student
      students = userRows.map(u => ({
        ...u,
        generated_profiles: profilesByUser[u.student_id] || null,
        assignments: assignmentsByStudent[u.student_id] || null,
        watching_instructors: watchingByStudent[u.student_id] || null,
        pending_reviews: reviewCountsByUser[u.student_id]?.pending_reviews || 0,
        completed_reviews: reviewCountsByUser[u.student_id]?.completed_reviews || 0,
        parts_started: reviewCountsByUser[u.student_id]?.parts_started || 0
      }));
    } catch (studentError) {
      console.error('Error fetching students:', studentError.message);
    }

    // Enrich students with instructor info from deployed_groups
    // (students are linked to instructors via group config, not just working_sets)
    try {
      const groupsResult = await query(`SELECT id, group_name, config FROM deployed_groups`);
      const groups = groupsResult.rows;

      // Build a map: student_id -> [{instructor_id, instructor_name, instructor_email, group_name}]
      const groupInstructorMap = {}; // student_id -> instructors[]

      for (const g of groups) {
        const cfg = typeof g.config === 'string' ? JSON.parse(g.config) : g.config;
        const groupInstructors = cfg.instructors || [];
        const groupStudents = cfg.students || [];

        for (const student of groupStudents) {
          if (!groupInstructorMap[student.id]) groupInstructorMap[student.id] = [];
          for (const inst of groupInstructors) {
            // Avoid duplicates
            if (!groupInstructorMap[student.id].some(i => i.instructor_id === inst.id)) {
              groupInstructorMap[student.id].push({
                instructor_id: inst.id,
                instructor_name: inst.name || inst.email,
                instructor_email: inst.email,
                source: 'group',
                group_name: g.group_name
              });
            }
          }
        }
      }

      // Merge group instructors into each student's watching_instructors
      for (const student of students) {
        const groupInstructors = groupInstructorMap[student.student_id] || [];
        const existing = student.watching_instructors || [];

        // Combine, deduplicating by instructor_id
        const merged = [...existing];
        for (const gi of groupInstructors) {
          if (!merged.some(e => e.instructor_id === gi.instructor_id)) {
            merged.push(gi);
          }
        }
        student.watching_instructors = merged.length > 0 ? merged : null;
      }
    } catch (groupError) {
      console.error('Error enriching students with group instructors:', groupError.message);
    }

    // Get pending submissions (merge with cybercore_user data after)
    try {
      const pendingResult = await query(`
        SELECT
          ap.id,
          ap.user_id,
          ap.profile_id,
          ap.part_number,
          ap.status,
          ap.content,
          ap.created_at,
          ap.updated_at,
          p.company_name AS profile_name
        FROM assessment_progress ap
        LEFT JOIN profiles p ON ap.profile_id = p.id
        WHERE ap.status = 'submitted'
        ORDER BY ap.updated_at DESC
        LIMIT 50
      `);

      pendingSubmissions = pendingResult.rows;

      // Enrich with student email/name from cybercore_db
      const userIds = [...new Set(pendingSubmissions.map(p => p.user_id).filter(Boolean))];
      if (userIds.length > 0) {
        const placeholders = userIds.map((_, i) => `$${i + 1}`).join(',');
        const usersResult = await cybercoreQuery(
          `SELECT user_id, email, first_name, last_name FROM cybercore_user WHERE user_id::text IN (${placeholders})`,
          userIds
        );
        const map = {};
        usersResult.rows.forEach(u => {
          map[u.user_id] = {
            email: u.email,
            name: `${u.first_name || ''} ${u.last_name || ''}`.trim()
          };
        });
        pendingSubmissions.forEach(p => {
          const info = map[p.user_id] || {};
          p.student_email = info.email || null;
          p.student_name = info.name || null;
        });
      }
    } catch (pendingError) {
      console.error('Error fetching pending submissions:', pendingError.message);
    }
    
    res.json({
      success: true,
      dashboard: {
        total_students: students.length,
        pending_reviews: pendingSubmissions.length,
        students: students,
        pending_submissions: pendingSubmissions
      }
    });
    
  } catch (error) {
    console.error('Error fetching instructor dashboard:', error);
    res.status(500).json({ error: 'Failed to fetch dashboard: ' + error.message });
  }
});

// GET /api/instructor/student/:studentId/progress - Get a student's progress details
router.get('/student/:studentId/progress', authenticateToken, instructorOnly, async (req, res) => {
  try {
    const { studentId } = req.params;
    
    // Get student info (from cybercore_user in cybercore_db)
    const studentResult = await cybercoreQuery(`
      SELECT user_id AS id, email, first_name, last_name, organization, created_at
      FROM cybercore_user WHERE user_id = $1
    `, [studentId]);
    
    if (studentResult.rows.length === 0) {
      return res.status(404).json({ error: 'Student not found' });
    }
    
    const student = studentResult.rows[0];
    
    // Get student's profiles
    const profilesResult = await query(`
      SELECT id, company_name, industry, difficulty, client_type_name, created_at
      FROM profiles WHERE user_id = $1
      ORDER BY created_at DESC
    `, [studentId]);
    
    // Get all assessment progress for this student
    const progressResult = await query(`
      SELECT 
        ap.id,
        ap.profile_id,
        ap.part_number,
        ap.status,
        ap.content,
        ap.feedback,
        ap.score,
        ap.created_at,
        ap.updated_at,
        p.company_name AS profile_name
      FROM assessment_progress ap
      LEFT JOIN profiles p ON ap.profile_id = p.id
      WHERE ap.user_id = $1
      ORDER BY ap.profile_id, ap.part_number
    `, [studentId]);
    
    // Get intake form responses
    let intakeResponses = [];
    try {
      const intakeResult = await query(`
        SELECT ifr.*, p.company_name AS profile_name
        FROM intake_form_responses ifr
        LEFT JOIN profiles p ON ifr.profile_id = p.id
        WHERE ifr.user_id = $1
        ORDER BY ifr.updated_at DESC
      `, [studentId]);
      intakeResponses = intakeResult.rows;
    } catch (e) {
      // Table may not exist
    }
    
    // Group progress by profile
    const progressByProfile = {};
    for (const row of progressResult.rows) {
      if (!progressByProfile[row.profile_id]) {
        progressByProfile[row.profile_id] = {
          profile_id: row.profile_id,
          profile_name: row.profile_name,
          parts: {}
        };
      }
      progressByProfile[row.profile_id].parts[row.part_number] = {
        id: row.id,
        status: row.status,
        score: row.score,
        feedback: row.feedback,
        updated_at: row.updated_at
      };
    }
    
    res.json({
      success: true,
      student: {
        id: student.id,
        email: student.email,
        name: `${student.first_name || ''} ${student.last_name || ''}`.trim() || null,
        first_name: student.first_name,
        last_name: student.last_name,
        organization: student.organization,
        joined: student.created_at
      },
      profiles: profilesResult.rows,
      progress: Object.values(progressByProfile),
      intake_responses: intakeResponses
    });
    
  } catch (error) {
    console.error('Error fetching student progress:', error);
    res.status(500).json({ error: 'Failed to fetch student progress: ' + error.message });
  }
});

// POST /api/instructor/review/:progressId - Submit review feedback
router.post('/review/:progressId', authenticateToken, instructorOnly, async (req, res) => {
  try {
    const instructorId = req.user.userId;
    const { progressId } = req.params;
    const { feedback, score, rubric_scores, status } = req.body;
    
    // Check if assessment_progress table exists
    const tableCheck = await query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_schema = 'public' 
        AND table_name = 'assessment_progress'
      )
    `);
    
    if (!tableCheck.rows[0]?.exists) {
      return res.status(400).json({ error: 'Assessment progress table not found. Please run database migrations.' });
    }
    
    // Check if the progress record exists
    const progressCheck = await query('SELECT * FROM assessment_progress WHERE id = $1', [progressId]);
    
    if (progressCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Submission not found' });
    }
    
    // Update the progress record with review
    const result = await query(`
      UPDATE assessment_progress
      SET status = $1, 
          feedback = $2, 
          score = $3, 
          rubric_scores = $4, 
          reviewer_id = $5, 
          reviewed_at = NOW(),
          updated_at = NOW()
      WHERE id = $6
      RETURNING *
    `, [status || 'reviewed', feedback, score, JSON.stringify(rubric_scores || {}), instructorId, progressId]);
    
    res.json({ success: true, review: result.rows[0] });
    
  } catch (error) {
    console.error('Error submitting review:', error);
    res.status(500).json({ error: 'Failed to submit review: ' + error.message });
  }
});

// POST /api/instructor/assign - Assign a profile to a student
router.post('/assign', authenticateToken, instructorOnly, async (req, res) => {
  try {
    const instructorId = req.user.userId;
    const { student_id, student_email, profile_id, due_date, notes } = req.body;
    
    // Check if instructor_assignments table exists
    const tableCheck = await query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_schema = 'public' 
        AND table_name = 'instructor_assignments'
      )
    `);
    
    if (!tableCheck.rows[0]?.exists) {
      // Create the table if it doesn't exist
      await query(`
        CREATE TABLE IF NOT EXISTS instructor_assignments (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          instructor_id UUID NOT NULL,
          student_id UUID NOT NULL,
          profile_id UUID,
          assigned_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          due_date TIMESTAMP WITH TIME ZONE,
          notes TEXT,
          created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          UNIQUE(instructor_id, student_id, profile_id)
        )
      `);
    }
    
    let studentId = student_id;
    
    // If student_email provided, look up the student (from cybercore_user)
    if (student_email && !student_id) {
      const userResult = await cybercoreQuery(
        'SELECT user_id AS id FROM cybercore_user WHERE email = $1',
        [student_email]
      );
      
      if (userResult.rows.length === 0) {
        return res.status(404).json({ error: 'Student not found with that email' });
      }
      
      studentId = userResult.rows[0].id;
    }
    
    if (!studentId) {
      return res.status(400).json({ error: 'Student ID or email required' });
    }
    
    const result = await query(`
      INSERT INTO instructor_assignments (instructor_id, student_id, profile_id, due_date, notes)
      VALUES ($1, $2, $3, $4, $5)
      ON CONFLICT (instructor_id, student_id, profile_id)
      DO UPDATE SET due_date = EXCLUDED.due_date, notes = EXCLUDED.notes
      RETURNING *
    `, [instructorId, studentId, profile_id || null, due_date || null, notes || null]);
    
    res.json({ success: true, assignment: result.rows[0] });
    
  } catch (error) {
    console.error('Error creating assignment:', error);
    res.status(500).json({ error: 'Failed to create assignment: ' + error.message });
  }
});

// REMOVED DUPLICATE - Real handler is below at line ~600

// GET /api/instructor/rubric/:profileId - Get grading rubric for profile
router.get('/rubric/:profileId', authenticateToken, instructorOnly, async (req, res) => {
  try {
    const { profileId } = req.params;
    
    const result = await query(
      'SELECT grading_rubric, scaffolding_level FROM profiles WHERE id = $1',
      [profileId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Profile not found' });
    }
    
    let rubric = result.rows[0].grading_rubric;
    if (!rubric || Object.keys(rubric).length === 0) {
      rubric = getDefaultRubric();
    }
    
    res.json({ success: true, rubric, scaffolding_level: result.rows[0].scaffolding_level });
    
  } catch (error) {
    console.error('Error fetching rubric:', error);
    res.status(500).json({ error: 'Failed to fetch rubric' });
  }
});

function getDefaultRubric() {
  return {
    part2_scoping: { name: 'Scoping and Context', points: 15, criteria: [
      { item: 'Correctly identifies organizational mission', points: 3 },
      { item: 'Lists key assets and systems', points: 3 },
      { item: 'Documents assumptions clearly', points: 3 },
      { item: 'Identifies appropriate scope boundaries', points: 3 },
      { item: 'Includes relevant clarification questions', points: 3 }
    ]},
    part3_threats: { name: 'Threat Identification', points: 20, criteria: [
      { item: 'Identifies sector-relevant threats', points: 5 },
      { item: 'Maps threats to organizational context', points: 5 },
      { item: 'Develops realistic threat scenarios', points: 5 },
      { item: 'Prioritizes threats appropriately', points: 5 }
    ]},
    part4_vulnerabilities: { name: 'Vulnerability Assessment', points: 20, criteria: [
      { item: 'Identifies technical vulnerabilities', points: 5 },
      { item: 'Identifies process/policy gaps', points: 5 },
      { item: 'Maps vulnerabilities to assets', points: 5 },
      { item: 'Prioritizes by risk', points: 5 }
    ]},
    part5_risk_analysis: { name: 'Risk Analysis', points: 20, criteria: [
      { item: 'Applies appropriate methodology', points: 5 },
      { item: 'Justifies likelihood ratings', points: 5 },
      { item: 'Justifies impact ratings', points: 5 },
      { item: 'Creates comprehensive risk register', points: 5 }
    ]},
    part6_controls: { name: 'Control Recommendations', points: 15, criteria: [
      { item: 'Maps to recognized framework', points: 3 },
      { item: 'Recommendations are actionable', points: 3 },
      { item: 'Prioritization is justified', points: 3 },
      { item: 'Considers cost/effort', points: 3 },
      { item: 'Implementation roadmap is realistic', points: 3 }
    ]},
    part7_reporting: { name: 'Reporting', points: 10, criteria: [
      { item: 'Executive summary is clear', points: 2 },
      { item: 'Technical details are accurate', points: 2 },
      { item: 'Appropriate for audience', points: 2 },
      { item: 'Professional formatting', points: 2 },
      { item: 'Actionable recommendations', points: 2 }
    ]}
  };
}


// POST /api/instructor/generate-documents - Generate security scan documents (NMAP/NESSUS/ZAP)
// Uses ai/scan-documents — deterministic, profile-driven, no LLM call.
router.post('/generate-documents', authenticateToken, instructorOnly, async (req, res) => {
  try {
    const { profile_id, documents = ['nessus', 'zap', 'nmap'] } = req.body;
    const instructorId = req.user.userId;

    if (!profile_id) {
      return res.status(400).json({ success: false, error: 'Missing profile_id' });
    }

    console.log('📄 Generate documents request:', { profile_id, documents, instructorId });

    // Get profile data including JSON file path
    const profileResult = await query(
      `SELECT
        id, company_name, industry, client_type, client_type_name, difficulty,
        maturity_level, delivery_mode, hq_city, employee_count, stakeholder_count,
        endpoint_count, compliance_frameworks, key_risks, critical_systems,
        scaffolding_level, nice_alignment, json_file_path, run_id
      FROM profiles WHERE id = $1`,
      [profile_id]
    );

    if (profileResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Profile not found' });
    }

    const profile = profileResult.rows[0];
    const companyName = profile.company_name || 'Unknown Company';

    // Load full profile JSON from file for detailed network/IT data
    let fullProfileData = null;
    try {
      let jsonPath = profile.json_file_path;
      if (jsonPath) {
        // Always resolve relative to project root (DB stores paths like /profiles/...)
        const resolvedPath = path.join(process.cwd(), jsonPath.replace(/^\//, ''));
        if (fs.existsSync(resolvedPath)) {
          const jsonContent = fs.readFileSync(resolvedPath, 'utf-8');
          const parsed = JSON.parse(jsonContent);
          fullProfileData = Array.isArray(parsed) ? parsed[0] : parsed;
          console.log('📂 Loaded full profile JSON from:', resolvedPath);
        } else {
          console.warn('⚠️ json_file_path not found:', resolvedPath);
        }
      }
      // Fallback: try to find by run_id in profiles directory
      if (!fullProfileData && profile.run_id) {
        const profilesDir = path.join(process.cwd(), 'profiles');
        if (fs.existsSync(profilesDir)) {
          const files = fs.readdirSync(profilesDir);
          const matchFile = files.find(f => f.includes(profile.run_id) && f.endsWith('.json'));
          if (matchFile) {
            const jsonContent = fs.readFileSync(path.join(profilesDir, matchFile), 'utf-8');
            const parsed = JSON.parse(jsonContent);
            fullProfileData = Array.isArray(parsed) ? parsed[0] : parsed;
            console.log('📂 Loaded full profile JSON by run_id:', matchFile);
          }
        }
      }
    } catch (jsonError) {
      console.warn('⚠️ Could not load full profile JSON:', jsonError.message);
    }

    // Extract detailed data from full profile JSON
    // Data may be properly split (raw.network, raw.it, raw.threats) OR
    // all merged into raw.threats (depends on N8N workflow execution)
    const studentView = fullProfileData?.student_view?.raw || {};
    const threatsData = studentView?.threats || {};
    const networkData = studentView?.network || threatsData?.network || {};
    const itEnvironment = studentView?.it?.it_environment || threatsData?.it_environment || {};
    const threatProfile = studentView?.threat_profile || threatsData?.threat_profile || {};
    const orgData = threatsData?.organization || {};
    const deliberateWeaknesses = [
      ...(itEnvironment?.deliberate_weaknesses || []),
      ...(networkData?.deliberate_weaknesses || []),
      ...(threatsData?.threat_profile?.deliberate_weaknesses || [])
    ].filter((v, i, a) => a.indexOf(v) === i);

    // Build profile data object with full context
    const profileData = {
      id: profile.id,
      company_name: profile.company_name,
      industry: profile.industry,
      client_type: profile.client_type,
      client_type_name: profile.client_type_name,
      difficulty: profile.difficulty,
      maturity_level: profile.maturity_level,
      delivery_mode: profile.delivery_mode,
      hq_city: profile.hq_city,
      employee_count: profile.employee_count,
      stakeholder_count: profile.stakeholder_count,
      endpoint_count: profile.endpoint_count,
      compliance_frameworks: profile.compliance_frameworks,
      key_risks: profile.key_risks,
      critical_systems: profile.critical_systems,
      scaffolding_level: profile.scaffolding_level,
      nice_alignment: profile.nice_alignment,
      // Full profile data for realistic document generation
      network: networkData,
      it_environment: itEnvironment,
      threat_profile: threatProfile,
      organization: orgData,
      deliberate_weaknesses: deliberateWeaknesses
    };

    console.log('📊 Profile data summary:', {
      company: companyName,
      hasFullData: !!fullProfileData,
      dataSource: studentView?.network ? 'split branches' : (threatsData?.network ? 'merged in threats' : 'none'),
      assets: networkData.assets?.length || 0,
      subnets: networkData.subnets?.length || 0,
      servers: itEnvironment.servers?.length || 0,
      saas: itEnvironment.saas?.length || 0,
      threats: threatProfile.scenarios?.length || 0,
      weaknesses: deliberateWeaknesses.length || 0
    });

    // Generate documents inline (profile-driven; replaces N8N webhook).
    // Output traces back to profile.assets[].services so real `nmap` against
    // the deployed lane matches the fake scan exactly.
    const { generateScanDocuments } = require('../ai/scan-documents');
    const domain = orgData?.domain_public || profile.industry?.toLowerCase()?.replace(/\s+/g, '') + '.local' || 'corp.local';
    const scanProfileData = {
      ...profileData,
      assets: networkData.assets || []
    };
    const generated = generateScanDocuments({
      profileData: scanProfileData,
      companyName,
      domain,
      types: documents
    });

    console.log(`📄 Generated ${generated.length} scan documents inline:`, generated.map(d => `${d.type} (${d.content.length}b)`).join(', '));

    // Store the generated documents in database
    const generatedDocs = [];

    {
      console.log(`📝 Processing ${generated.length} documents...`);
      for (const doc of generated) {
        console.log(`  → Saving ${doc.type} document: ${doc.filename} (${doc.content?.length || 0} bytes)`);
        try {
          await query(`
            INSERT INTO generated_documents (profile_id, document_type, filename, content, metadata, generated_by)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (profile_id, document_type)
            DO UPDATE SET
              filename = EXCLUDED.filename,
              content = EXCLUDED.content,
              metadata = EXCLUDED.metadata,
              generated_by = EXCLUDED.generated_by,
              generated_at = NOW()
          `, [
            profile_id,
            doc.type,
            doc.filename,
            doc.content || '',
            JSON.stringify({
              company: companyName,
              n8n_generated: true,
              size: doc.content?.length || 0
            }),
            instructorId
          ]);

          generatedDocs.push({
            type: doc.type,
            filename: doc.filename,
            size: doc.content?.length || 0,
            url: `/api/instructor/download/${profile_id}/${doc.type}`
          });
          console.log(`  ✅ Successfully saved ${doc.type} to database`);
        } catch (dbError) {
          console.error(`  ❌ Failed to save ${doc.type} document:`, dbError.message);
          console.error(`     Error details:`, dbError);
        }
      }
    }

    console.log('✅ Documents generated and stored:', generatedDocs.map(d => d.type).join(', '));

    res.json({
      success: true,
      documents: generatedDocs,
      generated_at: new Date().toISOString(),
      source: 'inline'
    });

  } catch (error) {
    console.error('❌ Error generating documents:', error);
    res.status(500).json({ success: false, error: 'Failed to generate documents: ' + error.message });
  }
});

// GET /api/instructor/download/:profileId/:docType - Download a generated document
router.get('/download/:profileId/:docType', authenticateToken, async (req, res) => {
  try {
    const { profileId, docType } = req.params;
    
    const result = await query(`
      SELECT filename, content, document_type 
      FROM generated_documents 
      WHERE profile_id = $1 AND document_type = $2
    `, [profileId, docType]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Document not found' });
    }
    
    const doc = result.rows[0];
    
    // Set appropriate content type based on document type
    let contentType = 'application/octet-stream';
    if (docType === 'zap') contentType = 'text/html';
    else if (docType === 'nessus') contentType = 'application/xml';
    else if (docType === 'nmap') contentType = 'text/markdown';
    else if (docType === 'policies') contentType = 'application/json';
    
    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Disposition', `attachment; filename="${doc.filename}"`);
    res.send(doc.content);
    
  } catch (error) {
    console.error('Error downloading document:', error);
    res.status(500).json({ error: 'Failed to download document' });
  }
});

// GET /api/instructor/documents/:profileId - Get generated documents for a profile
router.get('/documents/:profileId', authenticateToken, instructorOnly, async (req, res) => {
  try {
    const { profileId } = req.params;
    
    const result = await query(`
      SELECT gd.*, p.company_name
      FROM generated_documents gd
      JOIN profiles p ON gd.profile_id = p.id
      WHERE gd.profile_id = $1
      ORDER BY gd.generated_at DESC
    `, [profileId]);

    // Add download URLs to each document
    const documents = result.rows.map(doc => ({
      type: doc.document_type,
      filename: doc.filename,
      size: doc.content?.length || 0,
      url: `/api/instructor/download/${profileId}/${doc.document_type}`,
      generated_at: doc.generated_at,
      generated_by: doc.generated_by
    }));

    res.json({
      success: true,
      documents: documents
    });
    
  } catch (error) {
    console.error('Error fetching documents:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================================================
// EXAMPLE / ANSWER KEY GENERATION
// ============================================================================

// Part definitions for example generation (mirrors PART_OPTIONS from workspace.js)
const PART_DEFINITIONS = {
  1: { name: 'Clinic Orientation', options: [
    { key: 'p1_participation_agreement', name: 'Clinic Participation Agreement', deliverables: ['Signed participation agreement or code of conduct document'] },
    { key: 'p1_reflection', name: 'Short Reflection on Cybersecurity Clinics', deliverables: ['Reflection addressing: purpose of cybersecurity clinics, benefits to under-resourced organizations, workforce preparation, professional standards'] }
  ]},
  2: { name: 'Organizational Understanding', options: [
    { key: 'p2_org_brief', name: 'Initial Organizational Understanding Brief', deliverables: ['Organization mission and core services', 'High-level description of systems, data, and users', 'Summary of scoping activities performed', 'Initial cybersecurity posture observations', 'Explicit assumptions and client clarification questions'] },
    { key: 'p2_scoping_matrix', name: 'Scoping and Assumptions Matrix', deliverables: ['Table: Category, Known Information, Assumptions Made, Impact if Incorrect, Clarification Needed'] },
    { key: 'p2_asset_inventory', name: 'Preliminary Asset and Impact Inventory', deliverables: ['Key assets list (data, systems, processes)', 'Asset owner (if known)', 'Importance to mission (High/Medium/Low)', 'Potential impact of compromise'] },
    { key: 'p2_risk_hypothesis', name: 'Initial Risk Hypothesis Statement', deliverables: ['3-5 hypothesized high-risk areas', 'Rationale for each hypothesis', 'Evidence observed so far', 'Additional information needed to confirm or refute'] },
    { key: 'p2_question_log', name: 'Client Question and Information Request Log', deliverables: ['Structured question log: Topic Area, Question, Reason, Priority, Requested Evidence'] },
    { key: 'p2_scope_diagram', name: 'Visual Scope Diagram or System Context Map', deliverables: ['Systems and data flows (high-level)', 'External connections (vendors, cloud)', 'In-scope vs. out-of-scope elements', 'Unknown components highlighted'] }
  ]},
  3: { name: 'Threat Identification', options: [
    { key: 'p3_sector_brief', name: 'Sector-Based Threat Research Brief', deliverables: ['1-2 page threat research brief', 'List of top sector-specific threats', 'Rationale for relevance to the organization'] },
    { key: 'p3_actor_profiles', name: 'Threat Actor Profile Development', deliverables: ['Threat actor profile sheets', 'Actor motivation, capability, and access analysis', 'Asset-actor mapping table'] },
    { key: 'p3_case_study', name: 'Case Study-Driven Threat Mapping', deliverables: ['Case study summary', 'Threat comparison table (Case vs. Client)', 'Lessons learned and applicability analysis'] },
    { key: 'p3_threat_model', name: 'Threat Modeling Workshop', deliverables: ['Threat scenario list', 'High-level threat model diagram', 'Narrative explanation of key threat paths'] },
    { key: 'p3_emerging_threats', name: 'Emerging Threat Research Snapshot', deliverables: ['Emerging threat summary', 'Relevance assessment (High/Medium/Low)', 'Justification for inclusion or exclusion'] },
    { key: 'p3_insider_threats', name: 'Insider and Non-Technical Threat Analysis', deliverables: ['Insider threat scenarios', 'Human and process-based threat list', 'Mitigation considerations (high-level)'] }
  ]},
  4: { name: 'Vulnerability Discovery', options: [
    { key: 'p4_policy_review', name: 'Policy and Procedure Vulnerability Review', deliverables: ['Policy gap analysis document', 'List of administrative vulnerabilities', 'Assumptions and evidence references'] },
    { key: 'p4_vuln_scanning', name: 'Hands-On Vulnerability Scanning', deliverables: ['Scan configuration summary', 'Raw scan output (sanitized)', 'Identified vulnerabilities with descriptions'] },
    { key: 'p4_scan_analysis', name: 'Vulnerability Scan Results Analysis', deliverables: ['Validated vulnerability list', 'False positive justification notes', 'Severity reassessment based on context'] },
    { key: 'p4_config_assessment', name: 'Configuration-Based Assessment', deliverables: ['Configuration review checklist', 'Observational vulnerability notes', 'Interview-derived findings summary'] },
    { key: 'p4_vuln_asset_map', name: 'Vulnerability-to-Asset Mapping Table', deliverables: ['Vulnerability-asset mapping table', 'Impact notes and assumptions', 'Confidence ratings'] }
  ]},
  5: { name: 'Risk Analysis', options: [
    { key: 'p5_scoring_justification', name: 'Risk Scoring Methodology Justification', deliverables: ['Risk scoring methodology memo', 'Comparison table of alternative models', 'Justification tied to organizational context'] },
    { key: 'p5_likelihood_impact', name: 'Likelihood and Impact Research Briefs', deliverables: ['Likelihood research brief', 'Impact justification narrative', 'Annotated references'] },
    { key: 'p5_risk_narrative', name: 'Risk Narrative Development', deliverables: ['Risk narratives', 'Supporting evidence citations', 'Audience-specific language adaptation'] },
    { key: 'p5_final_package', name: 'Final Risk Prioritization Package', deliverables: ['Final prioritized risk register', 'Executive summary', 'Research appendix'] }
  ]},
  6: { name: 'Controls and Mitigations', options: [
    { key: 'p6_framework_selection', name: 'Framework Selection and Justification', deliverables: ['Framework selection memorandum', 'Comparison table of candidate frameworks', 'Justification narrative'] },
    { key: 'p6_risk_control_map', name: 'Risk-to-Control Mapping', deliverables: ['Risk-control mapping table', 'Narrative justification per control', 'Citation list linking to framework docs'] },
    { key: 'p6_feasibility', name: 'Control Feasibility and Resource Analysis', deliverables: ['Control feasibility matrix', 'Cost/benefit narrative', 'Resource assumptions and constraints'] },
    { key: 'p6_roadmap', name: 'Prioritized Mitigation Roadmap', deliverables: ['Mitigation roadmap', 'Timeline with dependencies', 'Sequencing justification'] },
    { key: 'p6_client_package', name: 'Client-Ready Mitigation Package', deliverables: ['Final mitigation recommendations', 'Executive summary', 'Reference appendix'] }
  ]},
  7: { name: 'Reporting and Communication', options: [
    { key: 'p7_full_report', name: 'Comprehensive Risk Assessment Report', deliverables: ['Formal report: executive summary, org overview, methodology, key risks, controls, limitations, next steps', 'Proper citations and references', 'Technical appendices'] },
    { key: 'p7_executive_summary', name: 'Executive Summary and Leadership Brief', deliverables: ['1-2 page executive summary', 'Top 3-5 risks with business impact', 'High-level mitigation priorities (jargon-free)'] },
    { key: 'p7_presentation', name: 'Oral Briefing or Presentation', deliverables: ['Slide deck (8-12 slides)', 'Speaker notes', 'Q&A reflection summary'] },
    { key: 'p7_handoff', name: 'Client Handoff and Next Steps Package', deliverables: ['Priority action checklist', 'Recommended timelines', 'Suggested future assessments'] }
  ]},
  8: { name: 'Reflection and Workforce Alignment', options: [
    { key: 'p8_reflection_paper', name: 'Structured Reflection Paper', deliverables: ['Reflection paper (1-3 pages): what you learned, how understanding changed, challenges, what you\'d do differently'] },
    { key: 'p8_self_assessment', name: 'Skills and Competency Self-Assessment', deliverables: ['Skills self-assessment matrix (before/after)', 'Narrative growth summary', 'Skills gap analysis'] },
    { key: 'p8_workforce_alignment', name: 'Workforce Framework Alignment Map', deliverables: ['Workforce alignment table', 'Role interest reflection', 'Evidence supporting alignment claims'] },
    { key: 'p8_career_plan', name: 'Career Pathway and Professional Development Plan', deliverables: ['Individual career roadmap', 'Short- and long-term professional goals', 'Certification or education plan'] }
  ]}
};

// ============================================================================
// INTAKE FORM AUTO-GENERATOR FROM PROFILE DATA
// ============================================================================

function generateIntakeFormFromProfile(profile, fullProfileData) {
  const sv = fullProfileData?.student_view?.raw || {};
  const t = sv.threats || {};
  const org = t.organization || {};
  const it = t.it_environment || {};
  const net = t.network || sv.network || {};
  const gov = t.profiles?.governance_and_policy || {};
  const stakeholders = t.stakeholders || [];

  const pc = stakeholders[0] || {};
  const sc = stakeholders[1] || {};
  const servers = it.servers || [];
  const saas = it.saas || [];
  const remote = it.remote_access || {};
  const backups = it.backups || {};
  const ep = it.endpoint_protection || {};
  const fw = net.firewall || {};
  const policiesPresent = gov.policies_present || [];
  const complianceFocus = t.profiles?.compliance_focus || [];
  const endpoints = it.endpoints || {};
  const vendorDeps = it.vendor_dependencies || [];
  const delivery = (it.delivery || '').toLowerCase();
  const companyName = org.company_name || profile.company_name || 'Organization';
  const industry = org.industry || profile.industry || 'General';
  const city = org.hq_city || profile.hq_city || '';
  const domain = org.domain_public || '';
  const empCount = org.employees_total || profile.employee_count || 50;

  // Maturity-based scoring: low=beginner, med=intermediate, hi=advanced
  const isLow = profile.difficulty === 'beginner' || gov.framework === 'Ad-hoc';
  const isHigh = profile.difficulty === 'advanced';

  const hasPolicy = (kw) => policiesPresent.some(p => p.toLowerCase().includes(kw));
  const hasComp = (kw) => complianceFocus.some(c => c.toLowerCase().includes(kw));

  // Generate a realistic street address from city
  const streetNums = [100, 250, 500, 750, 1200, 2300, 4500, 8100];
  const streets = ['Main St', 'Commerce Blvd', 'Industrial Pkwy', 'Oak Ave', 'Technology Dr', 'Business Loop', 'Market St', 'Enterprise Way'];
  const suites = ['Suite 100', 'Suite 200', 'Bldg A', 'Floor 2', 'Suite 310', ''];
  const sIdx = Math.abs((companyName.charCodeAt(0) || 0) + (city.charCodeAt(0) || 0)) % streets.length;
  const addr = city ? `${streetNums[sIdx]} ${streets[sIdx]}${suites[sIdx] ? ', ' + suites[sIdx] : ''}, ${city}` : '';

  // Build server detail text
  const serverLines = servers.map(s => `${s.hostname} (${s.os || 'Unknown OS'}) - ${s.role || 'General Server'}`);
  const saasList = saas.map(s => typeof s === 'string' ? s : s.name || s.app || '').filter(Boolean);

  // Build realistic services/products description
  const critServices = org.critical_services || [];
  const productsText = critServices.length > 0
    ? critServices.join(', ')
    : org.business_model
      ? org.business_model.substring(0, 200)
      : `Core ${industry.toLowerCase()} services and operations`;

  // Past incidents
  const incidents = (org.past_incidents || []).map(i =>
    typeof i === 'string' ? i : [i.type, i.description, i.incident].filter(Boolean).join(' - ')
  ).filter(Boolean);

  // Ongoing concerns from key_risks
  const concerns = Array.isArray(profile.key_risks) ? profile.key_risks.join('; ') : '';

  // Goals based on maturity
  const goals = isLow
    ? `Establish a baseline cybersecurity program, identify critical vulnerabilities, and develop foundational security policies for ${companyName}`
    : isHigh
      ? `Enhance existing security controls, achieve compliance with ${complianceFocus[0] || 'industry standards'}, and implement continuous monitoring capabilities`
      : `Improve cybersecurity posture, address known gaps in security controls, and prepare for compliance requirements`;

  // Generate realistic training scores (0-4) based on maturity
  const tScore = (base) => isLow ? Math.min(base, 1) : isHigh ? Math.min(base + 1, 4) : base;

  // ---- V8 intake form field mapping (10 sections + IG1) ----

  // Employee count band
  const empBand = empCount <= 10 ? '1-10' : empCount <= 50 ? '11-50' : empCount <= 100 ? '51-100'
    : empCount <= 250 ? '101-250' : empCount <= 500 ? '251-500' : empCount <= 1000 ? '501-1000'
    : empCount <= 5000 ? '1001-5000' : '5000+';

  // Endpoint counts from profile
  const desktops = (endpoints.windows_desktops || 0) + (endpoints.shared_kiosks || 0);
  const laptops = endpoints.windows_laptops || 0;
  const serverCount = servers.length || 0;
  const winServers = servers.filter(s => /windows server/i.test(s.os || '')).length;
  const winClients = desktops + laptops;
  const linuxCount = servers.filter(s => /linux|ubuntu|centos|rhel/i.test(s.os || '')).length;
  const macCount = endpoints.macos || 0;

  // Determine wifi encryption level based on maturity
  const wifiEnc = isLow ? 'WPA2' : isHigh ? 'WPA3' : 'WPA2';

  // Determine AV vendor from profile
  const avVendor = ep.product
    ? (['CrowdStrike Falcon','SentinelOne','Sophos','Bitdefender','Trend Micro','McAfee / Trellix','Microsoft Defender for Endpoint','Microsoft Defender (built-in)','Symantec / Broadcom','Webroot']
        .find(v => (ep.product || '').toLowerCase().includes(v.split(' ')[0].toLowerCase())) || ep.product)
    : (isLow ? 'Microsoft Defender (built-in)' : 'Unknown');

  // Email provider detection
  const emailProvider = saasList.some(s => /office 365|microsoft 365|o365|exchange online/i.test(s)) ? 'Microsoft 365'
    : saasList.some(s => /google workspace|gmail/i.test(s)) ? 'Google Workspace'
    : servers.some(s => /mail|exchange/i.test(s.role || '')) ? 'On-prem Exchange'
    : 'Unknown';

  // Domain mode detection
  const domainMode = servers.some(s => /domain controller|dc/i.test(s.role || ''))
    ? (delivery.includes('cloud') || saasList.some(s => /azure|entra/i.test(s)) ? 'hybrid' : 'ad')
    : (delivery.includes('cloud') ? 'cloud_only' : 'workgroup');

  // Network segments from profile
  const vlans = (net.vlans || net.segments || []).map(v => ({
    vlan: v.vlan_id || v.id || '',
    cidr: v.cidr || v.subnet || '',
    purpose: v.purpose || v.name || v.description || ''
  }));

  // Build server role mappings
  const hasServerRole = (kw) => servers.some(s => new RegExp(kw, 'i').test(s.role || '') || new RegExp(kw, 'i').test(s.hostname || ''));
  const serverVersion = (kw) => {
    const s = servers.find(sv => new RegExp(kw, 'i').test(sv.role || '') || new RegExp(kw, 'i').test(sv.hostname || ''));
    return s ? `${s.hostname} (${s.os || 'Unknown'})` : '';
  };

  // Build IG1 safeguard responses based on maturity
  const ig1Nums = ['1.1','1.2','2.1','2.2','2.3','3.1','3.2','3.3','3.4','3.5','3.6',
    '4.1','4.2','4.3','4.4','4.5','4.6','4.7','5.1','5.2','5.3','5.4',
    '6.1','6.2','6.3','6.4','6.5','7.1','7.2','7.3','7.4','8.1','8.2','8.3',
    '9.1','9.2','10.1','10.2','10.3','11.1','11.2','11.3','11.4','12.1',
    '14.1','14.2','14.3','14.4','14.5','14.6','14.7','14.8','15.1','17.1','17.2','17.3'];
  const ig1Responses = {};
  ig1Nums.forEach(num => {
    // Vary responses based on maturity: low=mostly no/unknown, med=mixed, high=mostly yes/partial
    const rand = Math.abs((companyName.charCodeAt(0) + parseFloat(num) * 17) % 10);
    if (isLow) {
      ig1Responses[`ig1_${num}`] = rand < 2 ? 'yes' : rand < 4 ? 'partial' : rand < 7 ? 'no' : 'unknown';
    } else if (isHigh) {
      ig1Responses[`ig1_${num}`] = rand < 6 ? 'yes' : rand < 8 ? 'partial' : 'no';
    } else {
      ig1Responses[`ig1_${num}`] = rand < 3 ? 'yes' : rand < 6 ? 'partial' : rand < 8 ? 'no' : 'unknown';
    }
  });

  return {
    // Section 1: Organization Profile
    company_info: {
      company_name: companyName,
      industry: industry,
      employees_band: empBand,
      revenue_band: isLow ? '< $1M' : isHigh ? '$50M-$250M' : '$1M-$10M',
      business_address: addr,
      locations: city ? `${city} (Headquarters)${empCount > 200 ? ', Remote employees' : ''}` : '',
      website: domain ? `https://${domain}` : '',
      primary_contact_name: pc.name || '',
      primary_contact_title: pc.role || pc.title || '',
      primary_contact_email: pc.email || (pc.name ? pc.name.toLowerCase().replace(/\s+/g, '.') + '@' + (domain || 'company.com') : ''),
      primary_contact_phone: pc.phone || '',
      secondary_contact_name: sc.name || '',
      secondary_contact_title: sc.role || sc.title || '',
      secondary_contact_email: sc.email || (sc.name ? sc.name.toLowerCase().replace(/\s+/g, '.') + '@' + (domain || 'company.com') : ''),
      secondary_contact_phone: sc.phone || '',
      social_linkedin: domain ? `linkedin.com/company/${companyName.toLowerCase().replace(/[^a-z0-9]+/g, '-')}` : '',
      social_instagram: '', social_x: '', social_facebook: '', social_tiktok: '', social_other: '',
      // Regulatory frameworks (now in company_info with fw_ prefix)
      fw_hipaa: hasComp('hipaa'),
      fw_pci: hasComp('pci'),
      fw_cmmc: hasComp('cmmc'),
      fw_sox: hasComp('sox'),
      fw_glba: hasComp('glba'),
      fw_gdpr: hasComp('gdpr'),
      fw_ferpa: hasComp('ferpa'),
      fw_nist: hasComp('nist'),
      fw_none: complianceFocus.length === 0,
      products_services: productsText,
      service_risk_assessment: true,
      service_training: true,
      service_vuln_assessment: !isLow,
      service_osint: isHigh,
      recent_incidents: incidents.length > 0 ? incidents.join('; ') : 'No significant incidents reported in the past 12 months',
      ongoing_concerns: concerns || `General concerns about ${isLow ? 'lack of visibility into threats and outdated systems' : 'maintaining security posture as the organization grows'}`,
      primary_goals: goals,
      ai_usage: saasList.some(s => s.toLowerCase().includes('ai') || s.toLowerCase().includes('copilot')) ? 'used' : 'unsure',
      ai_has_policy: false, ai_no_policy: !isHigh,
      ai_interest_training: true, ai_interest_risks: true,
      ai_interest_opportunities: false, ai_interest_policy: false,
    },

    // Section 2: Network Topology
    network_security: {
      workstation_count: String(desktops),
      laptop_count: String(laptops),
      server_count: String(serverCount),
      os_win_server: String(winServers),
      os_win_client: String(winClients),
      os_linux: String(linuxCount),
      os_macos: String(macCount),
      os_other: String(endpoints.mobile || 0),
      // Server roles (select values: yes/no/unknown)
      role_dc: hasServerRole('domain controller|dc') ? 'yes' : 'unknown',
      role_dc_version: serverVersion('domain controller|dc'),
      role_file: hasServerRole('file') ? 'yes' : (servers.length > 0 ? 'yes' : 'unknown'),
      role_file_version: serverVersion('file'),
      role_mail: hasServerRole('mail|exchange') ? 'yes' : (emailProvider.includes('On-prem') ? 'yes' : 'no'),
      role_mail_version: serverVersion('mail|exchange'),
      role_web: hasServerRole('web|app') ? 'yes' : 'no',
      role_web_version: serverVersion('web|app'),
      role_db: hasServerRole('db|database|sql') ? 'yes' : 'no',
      role_db_version: serverVersion('db|database|sql'),
      role_backup: hasServerRole('backup') ? 'yes' : (backups.method ? 'yes' : 'unknown'),
      role_backup_version: serverVersion('backup') || (backups.method || ''),
      role_print: 'unknown',
      role_print_version: '',
      role_other: servers.some(s => /erp|crm|wms/i.test(s.role || '')) ? 'yes' : 'no',
      role_other_version: servers.filter(s => /erp|crm|wms/i.test(s.role || '')).map(s => `${s.hostname} (${s.role})`).join(', '),
      role_other_notes: serverLines.join('\n'),
      // Exposed services (checkboxes)
      svc_smb: true,
      svc_smb_version: '',
      svc_rdp: true,
      svc_rdp_version: '',
      svc_ssh: linuxCount > 0,
      svc_ssh_version: '',
      svc_http: hasServerRole('web') || saasList.length > 0,
      svc_http_version: '',
      svc_sql: hasServerRole('db|database|sql'),
      svc_sql_version: '',
      svc_ftp: isLow,
      svc_ftp_version: '',
      svc_dns: true,
      svc_dns_version: '',
      svc_ldap: domainMode === 'ad' || domainMode === 'hybrid',
      svc_ldap_version: '',
      svc_vpn: !!remote.vpn,
      svc_vpn_version: remote.vpn || '',
      // Domain & network
      domain_mode: domainMode,
      domain_name: domain || `${companyName.toLowerCase().replace(/[^a-z0-9]+/g, '')}.local`,
      // Segments
      segments: vlans.length > 0 ? vlans : [
        { vlan: '10', cidr: '10.10.10.0/28', purpose: 'Management' },
        { vlan: '20', cidr: '10.10.20.0/24', purpose: 'Servers' },
        { vlan: '30', cidr: '10.10.30.0/24', purpose: 'Workstations' },
        { vlan: '99', cidr: '10.10.99.0/24', purpose: 'Guest' },
      ],
    },

    // Section 3: Wireless
    wireless: {
      ssid_count: String(Math.max(1, Math.min(4, Math.floor(empCount / 40) + 1))),
      wifi_encryption: wifiEnc,
      guest_wifi: 'Yes',
      guest_isolated: isLow ? 'No' : 'Yes',
    },

    // Section 4: Endpoint Security
    endpoint_security: {
      av_vendor: avVendor,
      disk_encryption: isLow ? 'No' : (isHigh ? 'Yes, all' : 'Some'),
      usb_policy: isLow ? 'Allowed, no restrictions' : (isHigh ? 'Blocked entirely' : 'Allowed with encryption'),
      patch_cadence: isLow ? 'Ad hoc / as needed' : (isHigh ? 'Automated, weekly or faster' : 'Automated, monthly'),
    },

    // Section 5: Email & Web
    email_web: {
      email_provider: emailProvider,
      web_filtering: isLow ? 'No' : (isHigh ? 'Yes' : 'Partial'),
      spf: isLow ? 'Unknown' : 'Yes',
      dkim: isLow ? 'Unknown' : (isHigh ? 'Yes' : 'No'),
      dmarc: isLow ? 'Unknown' : (isHigh ? 'Yes, enforcing' : 'No'),
    },

    // Section 6: Account & Access
    admin_privileges: {
      mfa_coverage: isLow ? 'None' : (isHigh ? 'All users, all systems' : 'Admin accounts + email'),
      priv_count_band: empCount <= 20 ? '1-2' : empCount <= 100 ? '3-5' : empCount <= 250 ? '6-10' : '11-25',
      password_manager: isLow ? 'No' : (isHigh ? 'Yes, company-wide' : 'Some users'),
      lockout_policy: isLow ? 'No' : 'Yes',
      dormant_cleanup: isLow ? 'Never' : (isHigh ? 'Automated' : 'Ad hoc'),
    },

    // Section 7: Data Protection
    data_management: {
      backup_cadence: backups.frequency === 'daily' ? 'Daily' : (isLow ? 'Weekly' : 'Daily'),
      offsite_backup: isLow ? 'No' : 'Yes',
      offline_backup: isLow ? 'No' : (isHigh ? 'Yes' : 'No'),
      encryption_at_rest: isLow ? 'No' : (isHigh ? 'Yes' : 'Partial'),
      dlp: isLow ? 'No' : (isHigh ? 'Yes' : 'No'),
      restore_test: isLow ? 'No' : (isHigh ? 'Yes' : 'No'),
    },

    // Section 8: Vulnerability & Audit
    vuln_management: {
      vuln_scanning: isLow ? 'None' : (isHigh ? 'Continuous / automated' : 'Quarterly'),
      logging_coverage: isLow ? 'None / unknown' : (isHigh ? 'Centralized, everything' : 'Local only, some systems'),
      siem: isLow ? 'No' : (isHigh ? 'Yes' : 'No'),
      audit_retention: isLow ? 'Unknown' : (isHigh ? '1-3 years' : '30-90 days'),
    },

    // Section 9: CIS IG1 Safeguards (stored in compliance column)
    compliance: ig1Responses,

    // Legacy sections (kept for DB compatibility, empty for V8 forms)
    security_policies: {},
    software_assets: {},
    secure_config: {},
    network_ports: {},
    network_devices: {},

    // Section 10: Additional Notes (stored in pentesting column)
    pentesting: {
      free_text: [
        `${companyName} is a ${industry.toLowerCase()} organization with ${empCount} employees.`,
        concerns ? `Key concerns: ${concerns}.` : '',
        incidents.length > 0 ? `Recent incidents: ${incidents.join('; ')}.` : '',
        `Security maturity: ${isLow ? 'Low' : isHigh ? 'High' : 'Intermediate'}.`,
        gov.framework ? `Governance framework: ${gov.framework}.` : '',
        vendorDeps.length > 0 ? `Key vendor dependencies: ${vendorDeps.map(v => typeof v === 'string' ? v : v.name || '').filter(Boolean).join(', ')}.` : '',
      ].filter(Boolean).join(' '),
    },
  };
}

// POST /api/instructor/generate-examples - Generate answer key for all parts
// Responds immediately and runs generation in background so the user can leave the page.
router.post('/generate-examples', authenticateToken, instructorOnly, async (req, res) => {
  try {
    const { profile_id, parts, model } = req.body;
    const instructorId = req.user.userId;

    if (!profile_id) {
      return res.status(400).json({ success: false, error: 'Missing profile_id' });
    }

    console.log('[Examples] Generate request:', { profile_id, instructorId, model: model || 'default' });

    // Load profile data (validate before responding)
    const profileResult = await query(
      `SELECT id, company_name, industry, client_type, client_type_name, difficulty,
        maturity_level, employee_count, endpoint_count, compliance_frameworks,
        key_risks, critical_systems, json_file_path, run_id, hq_city
      FROM profiles WHERE id = $1`, [profile_id]
    );

    if (profileResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Profile not found' });
    }

    const profile = profileResult.rows[0];

    // Load full profile JSON
    let fullProfileData = null;
    try {
      let jsonPath = profile.json_file_path;
      if (jsonPath) {
        const resolvedPath = path.join(process.cwd(), jsonPath.replace(/^\//, ''));
        if (fs.existsSync(resolvedPath)) {
          const parsed = JSON.parse(fs.readFileSync(resolvedPath, 'utf-8'));
          fullProfileData = Array.isArray(parsed) ? parsed[0] : parsed;
        }
      }
      if (!fullProfileData && profile.run_id) {
        const profilesDir = path.join(process.cwd(), 'profiles');
        if (fs.existsSync(profilesDir)) {
          const files = fs.readdirSync(profilesDir);
          const matchFile = files.find(f => f.includes(profile.run_id) && f.endsWith('.json'));
          if (matchFile) {
            const parsed = JSON.parse(fs.readFileSync(path.join(profilesDir, matchFile), 'utf-8'));
            fullProfileData = Array.isArray(parsed) ? parsed[0] : parsed;
          }
        }
      }
    } catch (e) {
      console.warn('[Examples] Could not load profile JSON:', e.message);
    }

    const studentView = fullProfileData?.student_view?.raw || {};
    const threatsData = studentView?.threats || {};
    const networkData = studentView?.network || threatsData?.network || {};
    const itEnvironment = studentView?.it?.it_environment || threatsData?.it_environment || {};
    const threatProfile = studentView?.threat_profile || threatsData?.threat_profile || {};

    const profileContext = {
      company_name: profile.company_name,
      industry: profile.industry,
      client_type: profile.client_type_name || profile.client_type,
      difficulty: profile.difficulty,
      maturity_level: profile.maturity_level,
      hq_city: profile.hq_city,
      employee_count: profile.employee_count,
      endpoint_count: profile.endpoint_count,
      compliance_frameworks: profile.compliance_frameworks,
      key_risks: profile.key_risks,
      critical_systems: profile.critical_systems,
      network: networkData,
      it_environment: itEnvironment,
      threat_profile: threatProfile
    };

    const partsToGenerate = parts || [1, 2, 3, 4, 5, 6, 7, 8];

    // ─── Delete old answer key rows, then fire N8N and respond immediately ───
    try {
      const deleted = await query(
        `DELETE FROM assessment_progress WHERE user_id = $1 AND profile_id = $2`,
        [instructorId, profile_id]
      );
      console.log(`[Examples] Deleted ${deleted.rowCount} old answer key rows for profile ${profile_id}`);
    } catch (delErr) {
      console.error('[Examples] Failed to delete old rows:', delErr.message);
    }

    setJobActive(instructorId, profile_id, model);

    // Inline generation (background, fire-and-forget).
    const { generateExamples } = require('../ai/examples');
    console.log(`[Examples] Starting inline generation for ${partsToGenerate.length} parts (background)`);

    setImmediate(async () => {
      try {
        await generateExamples({
          profileId: profile_id,
          userId: instructorId,
          profileContext,
          parts: partsToGenerate,
          partDefinitions: PART_DEFINITIONS,
          model
        });
        // Also generate intake form locally (fast, no LLM needed)
        try {
          const intakeData = generateIntakeFormFromProfile(profile, fullProfileData);
          const V72_SECTIONS = [
            'company_info', 'security_policies', 'data_management', 'network_security',
            'wireless', 'endpoint_security', 'compliance', 'software_assets',
            'vuln_management', 'admin_privileges', 'secure_config', 'email_web',
            'network_ports', 'network_devices', 'pentesting'
          ];
          await query(`
            INSERT INTO intake_form_responses
              (user_id, profile_id, status, completion_percentage,
               company_info, security_policies, data_management, network_security,
               wireless, endpoint_security, compliance, software_assets,
               vuln_management, admin_privileges, secure_config, email_web,
               network_ports, network_devices, pentesting, started_at, completed_at)
            VALUES ($1, $2, 'complete', 100,
               $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, NOW(), NOW())
            ON CONFLICT (user_id, profile_id)
            DO UPDATE SET
               status = 'complete', completion_percentage = 100,
               company_info = EXCLUDED.company_info, security_policies = EXCLUDED.security_policies,
               data_management = EXCLUDED.data_management, network_security = EXCLUDED.network_security,
               wireless = EXCLUDED.wireless, endpoint_security = EXCLUDED.endpoint_security,
               compliance = EXCLUDED.compliance, software_assets = EXCLUDED.software_assets,
               vuln_management = EXCLUDED.vuln_management, admin_privileges = EXCLUDED.admin_privileges,
               secure_config = EXCLUDED.secure_config, email_web = EXCLUDED.email_web,
               network_ports = EXCLUDED.network_ports, network_devices = EXCLUDED.network_devices,
               pentesting = EXCLUDED.pentesting, completed_at = NOW(), updated_at = NOW()
          `, [instructorId, profile_id, ...V72_SECTIONS.map(s => JSON.stringify(intakeData[s] || {}))]);
          console.log('[Examples] Intake form generated and stored');
        } catch (intakeErr) {
          console.error('[Examples] Failed to store intake form:', intakeErr.message);
        }

        // Auto-complete the Clinic Risk Assessment so the instructor has
        // a true answer key (findings + CIS RAM scoring + exec summary +
        // CSF maturity) to compare against students' work.
        try {
          const { pool } = require('../utils/db');
          // The unified intakes row is what the CRA tool reads from. It was
          // seeded at profile-generation time (see ciab/ai/profile/index.js).
          // We load it here to get the IG1 answers + posture archetype.
          const intakeQ = await pool.query(
            `SELECT payload FROM intakes WHERE profile_id = $1 ORDER BY created_at DESC LIMIT 1`,
            [profile_id]
          );
          const intakePayload = intakeQ.rows[0]?.payload;
          if (!intakePayload || !intakePayload.sections?.ig1) {
            console.warn('[Examples] Skipping answer-key risk assessment — no v11 intake found for profile', profile_id);
          } else {
            const { generateInstructorAnswerKeyRiskAssessment } = require('../utils/answer-key-risk-assessment');
            const r = await generateInstructorAnswerKeyRiskAssessment({
              profileId: profile_id,
              userId: instructorId,
              profileData: fullProfileData,
              intakePayload,
              pool
            });
            console.log(`[Examples] Answer-key risk assessment populated for instructor: ${r.findings_inserted} findings, ${r.cis_ram_rows_inserted} CIS RAM rows, CSF avg ${(Object.values(r.csf_scores).reduce((s,v)=>s+v,0)/6).toFixed(1)}/5, posture: ${r.posture?.name || 'unknown'}`);
          }
        } catch (raErr) {
          console.error('[Examples] Failed to populate answer-key risk assessment:', raErr.message);
        }
      } catch (err) {
        console.error('[Examples] Background generation failed:', err.message);
      } finally {
        setJobComplete(instructorId, profile_id);
      }
    });

    res.json({
      success: true,
      status: 'generating',
      profile_id,
      message: `Answer key generation started for ${partsToGenerate.length} parts (inline Claude, no N8N). You can leave this page.`
    });

  } catch (error) {
    console.error('[Examples] Error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET /api/instructor/examples/:profileId - Get generated examples for a profile
router.get('/examples/:profileId', authenticateToken, instructorOnly, async (req, res) => {
  try {
    const { profileId } = req.params;
    const instructorId = req.user.userId;

    const result = await query(`
      SELECT part_number, part_name, content, output_option, status, updated_at
      FROM assessment_progress
      WHERE user_id = $1 AND profile_id = $2
      ORDER BY part_number
    `, [instructorId, profileId]);

    const examples = result.rows.filter(r => {
      try {
        const c = JSON.parse(r.content || '{}');
        return c.is_example === true;
      } catch { return false; }
    });

    res.json({ success: true, examples });
  } catch (error) {
    console.error('[Examples] Fetch error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================================================
// INSTRUCTOR PACKET PDF — Examples + Intake Form
// ============================================================================

// ============================================================================
// HTML-to-PDF structured renderer: preserves headings, bullets, tables, paragraphs
// ============================================================================

function decodeEntities(text) {
  return (text || '')
    .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&nbsp;/g, ' ')
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(n));
}

function stripTags(html) {
  return decodeEntities((html || '').replace(/<[^>]+>/g, '').trim());
}

/**
 * Render HTML content into a PDFKit document with proper structure.
 * Handles: h1-h4, p, ul/ol/li, tables, br, strong/b, and plain text.
 */
function renderHtmlToPdf(doc, html, pageWidth, leftMargin) {
  if (!html) return;
  const text = String(html);

  // Parse into structural blocks
  const blocks = [];
  // Split on block-level elements
  const blockRegex = /<(h[1-4]|p|ul|ol|table|div|blockquote)[^>]*>([\s\S]*?)<\/\1>/gi;
  let lastIndex = 0;
  let match;

  while ((match = blockRegex.exec(text)) !== null) {
    // Capture any text between blocks
    if (match.index > lastIndex) {
      const between = text.substring(lastIndex, match.index).trim();
      if (between && stripTags(between)) {
        blocks.push({ type: 'text', content: between });
      }
    }
    blocks.push({ type: match[1].toLowerCase(), content: match[2] });
    lastIndex = match.index + match[0].length;
  }
  // Trailing text
  if (lastIndex < text.length) {
    const trailing = text.substring(lastIndex).trim();
    if (trailing && stripTags(trailing)) {
      blocks.push({ type: 'text', content: trailing });
    }
  }

  // If no block elements found, treat entire content as text
  if (blocks.length === 0 && stripTags(text)) {
    blocks.push({ type: 'text', content: text });
  }

  function ensureSpace(needed) {
    if (doc.y + needed > doc.page.height - 60) doc.addPage();
  }

  for (const block of blocks) {
    const clean = stripTags(block.content);
    if (!clean && block.type !== 'table' && block.type !== 'ul' && block.type !== 'ol') continue;

    switch (block.type) {
      case 'h1':
        ensureSpace(30);
        doc.fontSize(13).font('Helvetica-Bold').fillColor('#1a365d')
          .text(clean, leftMargin, doc.y, { width: pageWidth });
        doc.moveDown(0.3);
        break;

      case 'h2':
        ensureSpace(26);
        doc.fontSize(11.5).font('Helvetica-Bold').fillColor('#2c5282')
          .text(clean, leftMargin, doc.y, { width: pageWidth });
        doc.moveDown(0.25);
        break;

      case 'h3':
        ensureSpace(22);
        doc.fontSize(10.5).font('Helvetica-Bold').fillColor('#2d3748')
          .text(clean, leftMargin, doc.y, { width: pageWidth });
        doc.moveDown(0.2);
        break;

      case 'h4':
        ensureSpace(20);
        doc.fontSize(10).font('Helvetica-Bold').fillColor('#4a5568')
          .text(clean, leftMargin, doc.y, { width: pageWidth });
        doc.moveDown(0.15);
        break;

      case 'ul':
      case 'ol': {
        const items = block.content.match(/<li[^>]*>([\s\S]*?)<\/li>/gi) || [];
        items.forEach((li, idx) => {
          const itemText = stripTags(li);
          if (!itemText) return;
          ensureSpace(14);
          const bullet = block.type === 'ol' ? `${idx + 1}. ` : ' - ';
          doc.fontSize(9.5).font('Helvetica').fillColor('#1e293b')
            .text(`${bullet}${itemText}`, leftMargin + 10, doc.y, { width: pageWidth - 20, lineGap: 1.5 });
          doc.moveDown(0.1);
        });
        doc.moveDown(0.3);
        break;
      }

      case 'table': {
        // Extract headers and rows
        const headers = [];
        const headerMatch = block.content.match(/<thead[^>]*>([\s\S]*?)<\/thead>/i);
        if (headerMatch) {
          const ths = headerMatch[1].match(/<th[^>]*>([\s\S]*?)<\/th>/gi) || [];
          ths.forEach(th => headers.push(stripTags(th)));
        }
        // If no thead, check first row for th elements
        if (headers.length === 0) {
          const firstRow = block.content.match(/<tr[^>]*>([\s\S]*?)<\/tr>/i);
          if (firstRow && /<th[^>]*>/i.test(firstRow[1])) {
            const ths = firstRow[1].match(/<th[^>]*>([\s\S]*?)<\/th>/gi) || [];
            ths.forEach(th => headers.push(stripTags(th)));
          }
        }

        const rows = [];
        const rowMatches = block.content.match(/<tr[^>]*>([\s\S]*?)<\/tr>/gi) || [];
        for (const row of rowMatches) {
          if (/<th[^>]*>/i.test(row) && !/<td[^>]*>/i.test(row)) continue;
          const cells = [];
          const tds = row.match(/<td[^>]*>([\s\S]*?)<\/td>/gi) || [];
          tds.forEach(td => cells.push(stripTags(td)));
          if (cells.length > 0) rows.push(cells);
        }

        if (rows.length === 0) break;

        // Render table with header row highlighted
        const colCount = Math.max(headers.length, rows[0]?.length || 1);
        const colWidth = (pageWidth - 4) / colCount;

        // Header row
        if (headers.length > 0) {
          ensureSpace(18);
          const headerY = doc.y;
          doc.rect(leftMargin, headerY, pageWidth, 16).fill('#e2e8f0');
          headers.forEach((h, i) => {
            doc.fontSize(8).font('Helvetica-Bold').fillColor('#1a365d')
              .text(h, leftMargin + 4 + i * colWidth, headerY + 3, { width: colWidth - 8 });
          });
          doc.y = headerY + 18;
        }

        // Data rows
        rows.forEach((cells, rowIdx) => {
          const cellTexts = cells.map(c => c.substring(0, 120)); // Truncate long cells
          const rowHeight = Math.max(14, ...cellTexts.map(c =>
            doc.heightOfString(c, { width: colWidth - 8, fontSize: 8 }) + 6
          ));
          ensureSpace(rowHeight);

          const rowY = doc.y;
          if (rowIdx % 2 === 0) doc.rect(leftMargin, rowY, pageWidth, rowHeight).fill('#f7fafc');

          cellTexts.forEach((cell, i) => {
            doc.fontSize(8).font('Helvetica').fillColor('#2d3748')
              .text(cell, leftMargin + 4 + i * colWidth, rowY + 3, { width: colWidth - 8 });
          });
          doc.y = rowY + rowHeight;
        });

        // Bottom border
        doc.moveTo(leftMargin, doc.y).lineTo(leftMargin + pageWidth, doc.y)
          .lineWidth(0.5).strokeColor('#cbd5e1').stroke();
        doc.moveDown(0.4);
        break;
      }

      case 'p':
      case 'div':
      case 'blockquote':
      case 'text':
      default: {
        ensureSpace(14);
        // Handle inline bold/strong
        const plainText = block.content
          .replace(/<br\s*\/?>/gi, '\n')
          .replace(/<strong[^>]*>|<b[^>]*>/gi, '')
          .replace(/<\/strong>|<\/b>/gi, '')
          .replace(/<[^>]+>/g, '')
          .trim();
        const decoded = decodeEntities(plainText);
        if (decoded) {
          doc.fontSize(9.5).font('Helvetica').fillColor('#1e293b')
            .text(decoded, leftMargin, doc.y, { width: pageWidth, lineGap: 2 });
          doc.moveDown(0.3);
        }
        break;
      }
    }
  }
}

// Legacy plain-text fallback
function stripHtml(html) {
  if (!html) return '';
  let text = String(html);
  return text
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/p>/gi, '\n')
    .replace(/<\/li>/gi, '\n')
    .replace(/<\/tr>/gi, '\n')
    .replace(/<\/h[1-6]>/gi, '\n')
    .replace(/<li>/gi, '  - ')
    .replace(/<[^>]+>/g, '')
    .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"').replace(/&#39;/g, "'")
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

// GET /api/instructor/packet/:profileId/pdf - Download instructor packet as PDF
router.get('/packet/:profileId/pdf', authenticateToken, instructorOnly, async (req, res) => {
  try {
    const { profileId } = req.params;
    const instructorId = req.user.userId;

    const profileResult = await query(
      `SELECT company_name, industry, difficulty FROM profiles WHERE id = $1`, [profileId]
    );
    if (profileResult.rows.length === 0) {
      return res.status(404).json({ error: 'Profile not found' });
    }
    const profile = profileResult.rows[0];
    const companyName = profile.company_name || 'Unknown';

    const examplesResult = await query(`
      SELECT part_number, part_name, content, output_option
      FROM assessment_progress
      WHERE user_id = $1 AND profile_id = $2
      ORDER BY part_number
    `, [instructorId, profileId]);

    const examples = examplesResult.rows.filter(r => {
      try { return JSON.parse(r.content || '{}').is_example === true; } catch { return false; }
    });

    const intakeResult = await pool.query(
      `SELECT * FROM intake_form_responses WHERE user_id = $1 AND profile_id = $2`,
      [instructorId, profileId]
    );
    const intakeForm = intakeResult.rows[0] || null;

    if (examples.length === 0 && !intakeForm) {
      return res.status(404).json({ error: 'No answer key found. Generate one first.' });
    }

    // Build PDF — NO bufferPages to avoid blank page duplication
    const doc = new PDFDocument({ margin: 50, size: 'letter' });
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="instructor-packet-${companyName.replace(/[^a-zA-Z0-9]/g, '-')}.pdf"`);
    doc.pipe(res);

    const pageWidth = doc.page.width - 100;
    const leftMargin = 50;

    // ---- COVER PAGE ----
    doc.rect(0, 0, doc.page.width, doc.page.height).fill('#1a365d');
    doc.fillColor('#ffffff');
    doc.fontSize(32).font('Helvetica-Bold')
      .text('INSTRUCTOR PACKET', leftMargin, 180, { width: pageWidth, align: 'center' });
    doc.fontSize(14).font('Helvetica')
      .text('Answer Key & Completed Intake Form', leftMargin, 230, { width: pageWidth, align: 'center' });
    doc.fontSize(20).font('Helvetica-Bold')
      .text(companyName, leftMargin, 300, { width: pageWidth, align: 'center' });
    doc.fontSize(12).font('Helvetica')
      .text(`${profile.industry || ''} | ${(profile.difficulty || 'intermediate').charAt(0).toUpperCase() + (profile.difficulty || 'intermediate').slice(1)}`, leftMargin, 330, { width: pageWidth, align: 'center' });
    doc.fontSize(10)
      .text(`Generated: ${new Date().toLocaleDateString()}`, leftMargin, 380, { width: pageWidth, align: 'center' });
    doc.fontSize(9).fillColor('#a0aec0')
      .text('CONFIDENTIAL - For Instructor Use Only', leftMargin, 420, { width: pageWidth, align: 'center' });

    // ---- TABLE OF CONTENTS ----
    doc.addPage();
    doc.fillColor('#1a365d').fontSize(18).font('Helvetica-Bold')
      .text('Table of Contents', leftMargin, 50);
    doc.moveDown(0.5);
    doc.moveTo(leftMargin, doc.y).lineTo(leftMargin + pageWidth, doc.y).lineWidth(1).strokeColor('#cbd5e1').stroke();
    doc.moveDown(0.8);

    doc.fillColor('#2d3748').fontSize(11).font('Helvetica');
    let tocIndex = 1;
    for (const ex of examples) {
      doc.text(`${tocIndex}. Part ${ex.part_number}: ${ex.part_name}`, leftMargin + 10);
      doc.moveDown(0.4);
      tocIndex++;
    }
    if (intakeForm) {
      doc.text(`${tocIndex}. Completed Client Intake Form`, leftMargin + 10);
      doc.moveDown(0.4);
    }

    // ---- EXAMPLES ----
    function ensureSpace(needed) {
      if (doc.y + needed > doc.page.height - 60) doc.addPage();
    }

    for (const ex of examples) {
      doc.addPage();
      doc.rect(leftMargin, 50, pageWidth, 36).fill('#1a365d');
      doc.fillColor('#ffffff').fontSize(14).font('Helvetica-Bold')
        .text(`Part ${ex.part_number}: ${ex.part_name}`, leftMargin + 12, 58, { width: pageWidth - 24 });
      doc.y = 100;

      let parsed;
      try { parsed = JSON.parse(ex.content || '{}'); } catch { continue; }
      const deliverables = parsed.deliverables || {};

      for (const [optKey, delArr] of Object.entries(deliverables)) {
        ensureSpace(40);
        const optName = optKey.replace(/^p\d+_/, '').replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
        doc.fillColor('#2c5282').fontSize(12).font('Helvetica-Bold')
          .text(optName, leftMargin, doc.y);
        doc.moveDown(0.3);
        doc.moveTo(leftMargin, doc.y).lineTo(leftMargin + pageWidth, doc.y).lineWidth(0.5).strokeColor('#e2e8f0').stroke();
        doc.moveDown(0.4);

        const items = Array.isArray(delArr) ? delArr : [delArr];
        items.forEach((html, i) => {
          ensureSpace(30);
          // Deliverable label with accent bar
          const labelY = doc.y;
          doc.rect(leftMargin, labelY, 3, 12).fill('#2c5282');
          doc.fillColor('#718096').fontSize(8).font('Helvetica-Bold')
            .text(`DELIVERABLE ${i + 1}`, leftMargin + 8, labelY + 1);
          doc.y = labelY + 16;
          // Render HTML with structure preserved
          renderHtmlToPdf(doc, html, pageWidth, leftMargin);
          doc.moveDown(0.4);
        });
        doc.moveDown(0.3);
      }
    }

    // ---- INTAKE FORM — reuse the professional renderer from intake-form.js ----
    if (intakeForm) {
      doc.addPage();
      renderIntakePdf(doc, intakeForm, companyName);
    }

    doc.end();

  } catch (error) {
    console.error('[Packet] PDF error:', error);
    if (!res.headersSent) res.status(500).json({ error: 'Failed to generate packet PDF' });
  }
});

// ============================================================================
// LAB ENVIRONMENTS — Instructor VM Visibility & Access
// ============================================================================

/**
 * Helper: Get all student IDs this instructor can see
 * (students in instructor's groups + manually watched students)
 */
async function getInstructorStudentIds(userId) {
  // Get groups where this instructor is listed
  const groupResult = await query(
    `SELECT id, group_name, config FROM deployed_groups`
  );
  const studentIds = new Set();

  for (const g of groupResult.rows) {
    const cfg = typeof g.config === 'string' ? JSON.parse(g.config) : g.config;
    if ((cfg.instructors || []).some(i => i.id === userId)) {
      (cfg.students || []).forEach(s => studentIds.add(s.id));
    }
  }

  // Also include manually watched students from instructor_working_sets
  try {
    const wsResult = await query(
      `SELECT student_id FROM instructor_working_sets WHERE instructor_id = $1`,
      [userId]
    );
    wsResult.rows.forEach(r => studentIds.add(r.student_id));
  } catch (e) {
    // Table may not exist or have different schema — non-blocking
  }

  return Array.from(studentIds);
}

// GET /api/instructor/lanes — list lanes for instructor's students
router.get('/lanes', authenticateToken, instructorOnly, async (req, res) => {
  try {
    const studentIds = await getInstructorStudentIds(req.user.userId);

    if (studentIds.length === 0) {
      return res.json([]);
    }

    // Query cybercore_lane for these students
    const placeholders = studentIds.map((_, i) => `$${i + 1}`).join(',');
    const lanesResult = await cybercoreQuery(
      `SELECT l.lane_id, l.user_id, l.vxlan_id, l.name, l.status, l.config, l.created_at
       FROM cybercore_lane l
       WHERE l.user_id::text IN (${placeholders})
       ORDER BY l.created_at DESC`,
      studentIds
    );

    // Enrich with student email from cybercore_db
    const userPlaceholders = studentIds.map((_, i) => `$${i + 1}`).join(',');
    const usersResult = await cybercoreQuery(
      `SELECT user_id AS id, email, first_name, last_name FROM cybercore_user WHERE user_id::text IN (${userPlaceholders})`,
      studentIds
    );
    const userMap = {};
    usersResult.rows.forEach(u => { userMap[u.id] = u; });

    const lanes = lanesResult.rows.map(l => ({
      ...l,
      config: typeof l.config === 'string' ? JSON.parse(l.config) : l.config,
      student_email: userMap[l.user_id]?.email || 'unknown',
      student_name: userMap[l.user_id] ? `${userMap[l.user_id].first_name} ${userMap[l.user_id].last_name}` : 'Unknown'
    }));

    res.json(lanes);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/instructor/lanes/:id/ips — fetch live IP addresses for a lane's VMs
router.get('/lanes/:id/ips', authenticateToken, instructorOnly, async (req, res) => {
  try {
    const laneResult = await cybercoreQuery(
      `SELECT lane_id, vxlan_id, config, status FROM cybercore_lane WHERE lane_id = $1`,
      [req.params.id]
    );
    if (laneResult.rows.length === 0) {
      return res.status(404).json({ error: 'Lane not found' });
    }

    const lane = laneResult.rows[0];
    const config = typeof lane.config === 'string' ? JSON.parse(lane.config) : lane.config;
    const vxlanId = lane.vxlan_id;
    const node = config?.node;

    if (!node || lane.status !== 'active') {
      return res.json({ lane_id: lane.lane_id, status: lane.status, ips: {} });
    }

    const ips = {};

    // Try to get IPs from Proxmox guest agent for each VM
    const challengeVmId = config.challenge_vm_id || (600000 + vxlanId);
    const gatewayVmId = config.gateway_vm_id || (100000 + vxlanId);
    const attackBoxVmId = config.attack_box_vm_id || null;

    // Challenge VM (QEMU - guest agent)
    try {
      const agentData = await proxmoxAPI('GET', `/api2/json/nodes/${node}/qemu/${challengeVmId}/agent/network-get-interfaces`);
      if (agentData?.result) {
        for (const iface of agentData.result) {
          if (iface.name === 'lo') continue;
          const ipv4 = (iface['ip-addresses'] || []).find(a => a['ip-address-type'] === 'ipv4');
          if (ipv4) {
            ips.challenge_vm = ipv4['ip-address'];
            break;
          }
        }
      }
    } catch (e) { ips.challenge_vm = null; }

    // Gateway LXC (interfaces endpoint)
    try {
      const gwInterfaces = await proxmoxAPI('GET', `/api2/json/nodes/${node}/lxc/${gatewayVmId}/interfaces`);
      if (Array.isArray(gwInterfaces)) {
        for (const iface of gwInterfaces) {
          if (iface.name === 'lo') continue;
          if (iface.inet) {
            ips[`gateway_${iface.name}`] = iface.inet.split('/')[0];
          }
        }
      }
    } catch (e) { ips.gateway = null; }

    // Attack box if present
    if (attackBoxVmId) {
      try {
        const agentData = await proxmoxAPI('GET', `/api2/json/nodes/${node}/qemu/${attackBoxVmId}/agent/network-get-interfaces`);
        if (agentData?.result) {
          for (const iface of agentData.result) {
            if (iface.name === 'lo') continue;
            const ipv4 = (iface['ip-addresses'] || []).find(a => a['ip-address-type'] === 'ipv4');
            if (ipv4) {
              ips.attack_box = ipv4['ip-address'];
              break;
            }
          }
        }
      } catch (e) { ips.attack_box = null; }
    }

    res.json({
      lane_id: lane.lane_id,
      vxlan_id: vxlanId,
      node,
      vm_ids: { challenge: challengeVmId, gateway: gatewayVmId, attack_box: attackBoxVmId },
      ips
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/instructor/lanes/:id/connect — get Guacamole connection URL for a student's VM
router.get('/lanes/:id/connect', authenticateToken, instructorOnly, async (req, res) => {
  try {
    const laneResult = await cybercoreQuery(
      `SELECT lane_id, user_id, vxlan_id, config, status FROM cybercore_lane WHERE lane_id = $1`,
      [req.params.id]
    );
    if (laneResult.rows.length === 0) {
      return res.status(404).json({ error: 'Lane not found' });
    }

    const lane = laneResult.rows[0];

    // Verify this instructor has access to this student
    const studentIds = await getInstructorStudentIds(req.user.userId);
    if (!studentIds.includes(lane.user_id)) {
      return res.status(403).json({ error: 'You do not have access to this student\'s lane' });
    }

    if (lane.status !== 'active') {
      return res.status(400).json({ error: `Lane is not active (status: ${lane.status})` });
    }

    const config = typeof lane.config === 'string' ? JSON.parse(lane.config) : lane.config;

    // Look for an existing Guacamole connection for this lane's attack box
    // The connection is typically named "{group} - {student} - Kali"
    if (config.guac_connection_id) {
      // Direct connection ID stored in config
      const connId = config.guac_connection_id;
      const guacUrl = `${GUAC_URL}/#/client/${btoa(`${connId}\0c\0postgresql`)}`;
      return res.json({ guac_url: guacUrl, connection_id: connId });
    }

    // Try to find connection by searching Guacamole
    try {
      const tree = await guacAPI('GET', '/connectionGroups/ROOT/tree');
      const connections = findAllConnections(tree);

      // Look for a connection that matches this lane's VMs
      const vxlanId = lane.vxlan_id;
      const attackBoxVmId = config.attack_box_vm_id || (700000 + vxlanId);

      // Search by name pattern or by the hostname matching an IP we know
      const matchingConn = connections.find(c =>
        c.name && c.name.includes(`${vxlanId}`) ||
        c.identifier && config.guac_connection_id === c.identifier
      );

      if (matchingConn) {
        const guacUrl = `${GUAC_URL}/#/client/${btoa(`${matchingConn.identifier}\0c\0postgresql`)}`;
        return res.json({ guac_url: guacUrl, connection_id: matchingConn.identifier, connection_name: matchingConn.name });
      }
    } catch (e) {
      // Guacamole unreachable
    }

    // No connection found — return the Guacamole dashboard URL
    res.json({
      guac_url: `${GUAC_URL}/#/`,
      connection_id: null,
      message: 'No specific connection found for this lane. Opening Guacamole dashboard.'
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Helper: recursively find all connections in a Guacamole tree
function findAllConnections(node) {
  let conns = [];
  if (node.childConnections) {
    conns.push(...node.childConnections);
  }
  if (node.childConnectionGroups) {
    for (const group of node.childConnectionGroups) {
      conns.push(...findAllConnections(group));
    }
  }
  return conns;
}

// GET /api/instructor/students/search — search students outside instructor's group
router.get('/students/search', authenticateToken, instructorOnly, async (req, res) => {
  try {
    const q = req.query.q;
    if (!q || q.length < 2) {
      return res.json([]);
    }

    const myStudentIds = await getInstructorStudentIds(req.user.userId);

    const result = await cybercoreQuery(
      `SELECT user_id AS id, email, first_name, last_name, organization
       FROM cybercore_user
       WHERE role = 'student'
         AND (email ILIKE $1 OR first_name ILIKE $1 OR last_name ILIKE $1)
       ORDER BY email
       LIMIT 20`,
      [`%${q}%`]
    );

    // Mark which ones are already in the instructor's view
    const students = result.rows.map(s => ({
      ...s,
      already_watching: myStudentIds.includes(s.id)
    }));

    res.json(students);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/instructor/students/watch — add a student to instructor's view
router.post('/students/watch', authenticateToken, instructorOnly, async (req, res) => {
  try {
    const { student_id } = req.body;
    if (!student_id) {
      return res.status(400).json({ error: 'student_id required' });
    }

    // Verify student exists (cybercore_user)
    const studentResult = await cybercoreQuery(`SELECT user_id AS id, email FROM cybercore_user WHERE user_id = $1 AND role = 'student'`, [student_id]);
    if (studentResult.rows.length === 0) {
      return res.status(404).json({ error: 'Student not found' });
    }

    // Add to instructor_working_sets (may need to handle schema differences)
    try {
      await query(
        `INSERT INTO instructor_working_sets (instructor_id, student_id, created_at)
         VALUES ($1, $2, NOW())
         ON CONFLICT DO NOTHING`,
        [req.user.userId, student_id]
      );
    } catch (e) {
      // If table schema is different, try alternative approach
      return res.status(500).json({ error: `Could not add student: ${e.message}` });
    }

    res.json({ success: true, student: studentResult.rows[0] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// PATCH /api/instructor/lanes/:id/internet — toggle internet access on a lane
router.patch('/lanes/:id/internet', authenticateToken, instructorOnly, async (req, res) => {
  try {
    const { enabled } = req.body;
    if (typeof enabled !== 'boolean') {
      return res.status(400).json({ error: 'enabled (boolean) required' });
    }

    const laneResult = await cybercoreQuery(
      `SELECT lane_id, user_id, vxlan_id, config, status FROM cybercore_lane WHERE lane_id = $1`,
      [req.params.id]
    );
    if (laneResult.rows.length === 0) {
      return res.status(404).json({ error: 'Lane not found' });
    }

    const lane = laneResult.rows[0];

    // Verify access
    const studentIds = await getInstructorStudentIds(req.user.userId);
    if (!studentIds.includes(lane.user_id)) {
      return res.status(403).json({ error: 'You do not have access to this student\'s lane' });
    }

    if (lane.status !== 'active') {
      return res.status(400).json({ error: `Lane must be active (current: ${lane.status})` });
    }

    const config = typeof lane.config === 'string' ? JSON.parse(lane.config) : lane.config;
    const node = config?.node;
    const gatewayVmId = config?.gateway_vm_id || (100000 + lane.vxlan_id);

    if (!node) {
      return res.status(400).json({ error: 'Lane config missing node info' });
    }

    // Execute iptables commands on the gateway LXC
    const cmd = enabled
      ? 'iptables -t nat -C POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE; iptables -C FORWARD -i net1 -o eth0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i net1 -o eth0 -j ACCEPT; echo 1 > /proc/sys/net/ipv4/ip_forward'
      : 'iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null; iptables -D FORWARD -i net1 -o eth0 -j ACCEPT 2>/dev/null; echo 0 > /proc/sys/net/ipv4/ip_forward';

    try {
      await proxmoxAPI('POST', `/api2/json/nodes/${node}/lxc/${gatewayVmId}/exec`, {
        command: JSON.stringify(['sh', '-c', cmd])
      });
    } catch (execErr) {
      // Proxmox exec API may not be available — return error but still update config
      console.error(`[Internet Toggle] Exec failed on gateway ${gatewayVmId}:`, execErr.message);
      return res.status(502).json({
        error: `Could not execute command on gateway: ${execErr.message}`,
        hint: 'The Proxmox exec API may not be available. Try SSH to the gateway manually.'
      });
    }

    // Update lane config with internet status
    const updatedConfig = { ...config, internet_enabled: enabled };
    await cybercoreQuery(
      `UPDATE cybercore_lane SET config = $1, updated_at = NOW() WHERE lane_id = $2`,
      [JSON.stringify(updatedConfig), lane.lane_id]
    );

    res.json({
      success: true,
      lane_id: lane.lane_id,
      internet_enabled: enabled
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// ============================================================================
// ACCOUNT SCHEDULE MANAGEMENT (Instructor can manage their own group)
// ============================================================================

/**
 * Helper: Find groups where this instructor is listed in config.instructors
 */
async function getInstructorGroups(userId) {
  const result = await query(
    `SELECT id, group_name, config FROM deployed_groups`
  );
  return result.rows.filter(g => {
    const cfg = typeof g.config === 'string' ? JSON.parse(g.config) : g.config;
    return (cfg.instructors || []).some(i => i.id === userId);
  });
}

// GET /api/instructor/my-groups — list groups this instructor belongs to
router.get('/my-groups', authenticateToken, instructorOnly, async (req, res) => {
  try {
    const groups = await getInstructorGroups(req.user.userId);
    res.json(groups.map(g => ({
      id: g.id,
      group_name: g.group_name,
      students: (typeof g.config === 'string' ? JSON.parse(g.config) : g.config).students?.length || 0
    })));
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/instructor/all-groups — list all deployed groups (for join)
router.get('/all-groups', authenticateToken, instructorOnly, async (req, res) => {
  try {
    const result = await query(`SELECT id, group_name, config, created_at FROM deployed_groups ORDER BY created_at DESC`);
    const myGroups = await getInstructorGroups(req.user.userId);
    const myGroupIds = new Set(myGroups.map(g => g.id));

    res.json(result.rows.map(g => {
      const cfg = typeof g.config === 'string' ? JSON.parse(g.config) : g.config;
      return {
        id: g.id,
        group_name: g.group_name,
        instructors: (cfg.instructors || []).length,
        students: (cfg.students || []).length,
        is_member: myGroupIds.has(g.id),
        created_at: g.created_at
      };
    }));
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/instructor/join-group — add self to a deployed group
router.post('/join-group', authenticateToken, instructorOnly, async (req, res) => {
  try {
    const { group_id } = req.body;
    if (!group_id) return res.status(400).json({ error: 'group_id required' });

    const result = await query(`SELECT * FROM deployed_groups WHERE id = $1`, [group_id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Group not found' });

    const group = result.rows[0];
    const config = typeof group.config === 'string' ? JSON.parse(group.config) : group.config;

    // Check if already a member
    if ((config.instructors || []).some(i => i.id === req.user.userId)) {
      return res.status(400).json({ error: 'Already a member of this group' });
    }

    // Get instructor's user info (cybercore_user)
    const userResult = await cybercoreQuery(`SELECT user_id AS id, email, first_name, last_name FROM cybercore_user WHERE user_id = $1`, [req.user.userId]);
    if (userResult.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    const user = userResult.rows[0];

    // Add instructor to the group config
    config.instructors = config.instructors || [];
    config.instructors.push({
      id: user.id,
      email: user.email,
      name: `${user.first_name} ${user.last_name}`
    });

    await query(
      `UPDATE deployed_groups SET config = $1 WHERE id = $2`,
      [JSON.stringify(config), group_id]
    );

    res.json({ success: true, group_name: group.group_name });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/instructor/claim-student — add a student to instructor's working set
router.post('/claim-student', authenticateToken, instructorOnly, async (req, res) => {
  try {
    const { student_id } = req.body;
    if (!student_id) return res.status(400).json({ error: 'student_id required' });

    // Verify student exists (cybercore_user)
    const studentResult = await cybercoreQuery(`SELECT user_id AS id, email, first_name, last_name FROM cybercore_user WHERE user_id = $1 AND role = 'student'`, [student_id]);
    if (studentResult.rows.length === 0) return res.status(404).json({ error: 'Student not found' });

    // Add to working sets
    await query(
      `INSERT INTO instructor_working_sets (instructor_id, student_id, created_at)
       VALUES ($1, $2, NOW())
       ON CONFLICT DO NOTHING`,
      [req.user.userId, student_id]
    );

    res.json({ success: true, student: studentResult.rows[0] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// DELETE /api/instructor/release-student/:studentId — remove student from working set
router.delete('/release-student/:studentId', authenticateToken, instructorOnly, async (req, res) => {
  try {
    await query(
      `DELETE FROM instructor_working_sets WHERE instructor_id = $1 AND student_id = $2`,
      [req.user.userId, req.params.studentId]
    );
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/instructor/groups/:id/schedule — get schedule for instructor's group
router.get('/groups/:id/schedule', authenticateToken, instructorOnly, async (req, res) => {
  try {
    // Verify instructor belongs to this group
    const groups = await getInstructorGroups(req.user.userId);
    if (!groups.some(g => g.id === req.params.id)) {
      return res.status(403).json({ error: 'You are not an instructor for this group' });
    }

    const result = await query(
      `SELECT * FROM account_schedules WHERE group_id = $1`,
      [req.params.id]
    );
    if (result.rows.length === 0) {
      return res.json({ group_id: req.params.id, schedule: null });
    }
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// PUT /api/instructor/groups/:id/schedule — set class time window
router.put('/groups/:id/schedule', authenticateToken, instructorOnly, async (req, res) => {
  try {
    const groups = await getInstructorGroups(req.user.userId);
    if (!groups.some(g => g.id === req.params.id)) {
      return res.status(403).json({ error: 'You are not an instructor for this group' });
    }

    const { active_days, active_start, active_end, timezone } = req.body;

    if (!Array.isArray(active_days) || active_days.some(d => d < 0 || d > 6)) {
      return res.status(400).json({ error: 'active_days must be array of 0-6 (Sun-Sat)' });
    }
    if (!active_start || !active_end) {
      return res.status(400).json({ error: 'active_start and active_end required (HH:MM format)' });
    }

    const result = await query(
      `INSERT INTO account_schedules (group_id, active_days, active_start, active_end, timezone)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (group_id) DO UPDATE SET
         active_days = EXCLUDED.active_days,
         active_start = EXCLUDED.active_start,
         active_end = EXCLUDED.active_end,
         timezone = COALESCE(EXCLUDED.timezone, account_schedules.timezone),
         updated_at = NOW()
       RETURNING *`,
      [req.params.id, active_days, active_start, active_end, timezone || 'America/Chicago']
    );

    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// PATCH /api/instructor/groups/:id/schedule/override — force accounts active/inactive
router.patch('/groups/:id/schedule/override', authenticateToken, instructorOnly, async (req, res) => {
  try {
    const groups = await getInstructorGroups(req.user.userId);
    if (!groups.some(g => g.id === req.params.id)) {
      return res.status(403).json({ error: 'You are not an instructor for this group' });
    }

    const { override_active } = req.body;
    if (override_active !== true && override_active !== false && override_active !== null) {
      return res.status(400).json({ error: 'override_active must be true, false, or null' });
    }

    const result = await query(
      `UPDATE account_schedules
       SET override_active = $1,
           override_by = $2,
           override_at = NOW(),
           updated_at = NOW()
       WHERE group_id = $3
       RETURNING *`,
      [override_active, req.user.userId, req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'No schedule found for this group. Create one first.' });
    }

    // Sync Guacamole accounts: disable when forced off, enable when forced on
    // Stop or start VMs for all student lanes
    if (override_active === true || override_active === false) {
      const group = groups.find(g => g.id === req.params.id);
      const cfg = typeof group.config === 'string' ? JSON.parse(group.config) : group.config;
      const students = cfg.students || [];

      for (const student of students) {
        try {
          const lanesResult = await cybercoreQuery(
            `SELECT lane_id, vxlan_id, config, status FROM cybercore_lane
             WHERE user_id = $1 AND status IN ('active', 'suspended')`,
            [student.id]
          );

          for (const lane of lanesResult.rows) {
            const lc = typeof lane.config === 'string' ? JSON.parse(lane.config) : (lane.config || {});
            const node = lc.node;
            if (!node) continue;

            // Collect all VM IDs
            const vms = [];
            if (Array.isArray(lc.vms)) {
              for (const vm of lc.vms) vms.push({ vmid: vm.vm_id, type: vm.type || 'qemu' });
            } else if (lc.challenge_vm_id) {
              vms.push({ vmid: lc.challenge_vm_id, type: 'qemu' });
            }
            const gwId = lc.gateway_vm_id || lc.lane_gateway_vm_id;
            if (gwId) vms.push({ vmid: gwId, type: 'lxc' });
            if (lc.attack_box_vm_id) vms.push({ vmid: lc.attack_box_vm_id, type: 'qemu' });

            if (!override_active) {
              // Stop all VMs, mark lane suspended
              for (const vm of vms) {
                try { await proxmoxAPI('POST', `/api2/json/nodes/${node}/${vm.type}/${vm.vmid}/status/stop`); } catch (_) {}
              }
              await cybercoreQuery(`UPDATE cybercore_lane SET status = 'suspended', updated_at = NOW() WHERE lane_id = $1`, [lane.lane_id]);
            } else {
              // Start gateway first, then others
              const gw = vms.find(v => v.type === 'lxc');
              const others = vms.filter(v => v !== gw);
              if (gw) {
                try { await proxmoxAPI('POST', `/api2/json/nodes/${node}/${gw.type}/${gw.vmid}/status/start`); } catch (_) {}
                await new Promise(r => setTimeout(r, 3000));
              }
              for (const vm of others) {
                try { await proxmoxAPI('POST', `/api2/json/nodes/${node}/${vm.type}/${vm.vmid}/status/start`); } catch (_) {}
              }
              await cybercoreQuery(`UPDATE cybercore_lane SET status = 'active', updated_at = NOW() WHERE lane_id = $1`, [lane.lane_id]);
            }
          }
        } catch (_) {}
      }

      // Kill Guacamole sessions if disabling
      if (!override_active) {
        try {
          const studentEmails = students.map(s => s.email);
          const activeSessions = await guacAPI('GET', '/activeConnections');
          const toKill = Object.entries(activeSessions || {})
            .filter(([, s]) => studentEmails.includes(s.username))
            .map(([id]) => ({ op: 'remove', path: `/${id}` }));
          if (toKill.length > 0) {
            const token = await getGuacToken();
            await fetch(`${GUAC_URL}/api/session/data/${GUAC_DS}/activeConnections?token=${token}`, {
              method: 'PATCH',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(toKill)
            });
          }
        } catch (_) {}
      }
    }

    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


module.exports = router;
