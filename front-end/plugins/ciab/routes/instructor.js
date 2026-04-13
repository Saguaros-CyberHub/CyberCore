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
const { authenticateToken, requireRole } = require('../../../src/middleware/auth');
const { renderIntakePdf } = require('./intake-form');
const { cybercoreQuery } = require('../../../src/utils/cybercore-db');
const { proxmoxAPI } = require('../../../src/utils/proxmox');
const { guacAPI, getGuacToken, GUAC_URL, GUAC_DS } = require('../../../src/utils/guacamole');

const instructorOnly = requireRole('instructor', 'admin');

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

// GET /api/instructor/dashboard - Get instructor dashboard data
router.get('/dashboard', authenticateToken, instructorOnly, async (req, res) => {
  try {
    const instructorId = req.user.userId;
    
    let students = [];
    let pendingSubmissions = [];
    
    // Get ALL students (not just assigned ones) with their generated profiles
    try {
      const studentsResult = await query(`
        SELECT 
          u.id AS student_id, 
          u.email AS student_email,
          CONCAT(u.first_name, ' ', u.last_name) AS student_name,
          u.first_name,
          u.last_name,
          u.created_at AS student_joined,
          u.role,
          u.organization,
          (
            SELECT json_agg(json_build_object(
              'profile_id', p.id,
              'company_name', p.company_name,
              'industry', p.industry,
              'difficulty', p.difficulty,
              'created_at', p.created_at
            ))
            FROM profiles p
            WHERE p.user_id = u.id
          ) AS generated_profiles,
          (
            SELECT json_agg(json_build_object(
              'profile_id', ia.profile_id,
              'instructor_id', ia.instructor_id,
              'instructor_email', inst.email,
              'instructor_name', CONCAT(inst.first_name, ' ', inst.last_name),
              'due_date', ia.due_date,
              'assigned_at', ia.assigned_at
            ))
            FROM instructor_assignments ia
            LEFT JOIN users inst ON inst.id = ia.instructor_id
            WHERE ia.student_id = u.id
          ) AS assignments,
          (
            SELECT json_agg(DISTINCT jsonb_build_object(
              'instructor_id', iw.instructor_id,
              'instructor_email', iw_user.email,
              'instructor_name', CONCAT(iw_user.first_name, ' ', iw_user.last_name)
            ))
            FROM instructor_working_sets iw
            LEFT JOIN users iw_user ON iw_user.id = iw.instructor_id
            WHERE iw.student_id = u.id
          ) AS watching_instructors,
          (
            SELECT COUNT(*) 
            FROM assessment_progress ap 
            WHERE ap.user_id = u.id AND ap.status = 'submitted'
          ) AS pending_reviews,
          (
            SELECT COUNT(*) 
            FROM assessment_progress ap 
            WHERE ap.user_id = u.id AND ap.status = 'reviewed'
          ) AS completed_reviews,
          (
            SELECT COUNT(DISTINCT ap.part_number) 
            FROM assessment_progress ap 
            WHERE ap.user_id = u.id
          ) AS parts_started
        FROM users u
        WHERE u.role = 'student' OR u.role IS NULL
        ORDER BY u.last_name ASC NULLS LAST, u.first_name ASC NULLS LAST, u.email ASC
      `);
      
      students = studentsResult.rows;
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

    // Get pending submissions
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
          u.email AS student_email,
          CONCAT(u.first_name, ' ', u.last_name) AS student_name,
          p.company_name AS profile_name
        FROM assessment_progress ap
        JOIN users u ON ap.user_id = u.id
        LEFT JOIN profiles p ON ap.profile_id = p.id
        WHERE ap.status = 'submitted'
        ORDER BY ap.updated_at DESC
        LIMIT 50
      `);
      
      pendingSubmissions = pendingResult.rows;
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

// ============================================================================
// DOCUMENT GENERATOR FUNCTIONS
// ============================================================================

function generateNessusXml(profileData, companyName, domain) {
  const timestamp = Math.floor(Date.now() / 1000);
  const assets = profileData.assets || [];
  const weaknesses = profileData.weaknesses || [];
  
  // Get servers and critical assets
  const scanTargets = assets.filter(a => 
    a.role === 'server' || a.role === 'network' || a.critical
  ).slice(0, 15);
  
  // If no assets, create some defaults
  if (scanTargets.length === 0) {
    scanTargets.push(
      { hostname: 'dc-01', ip: '10.0.0.10', os: 'Windows Server 2019', role: 'server' },
      { hostname: 'file-server-01', ip: '10.0.0.20', os: 'Windows Server 2019', role: 'server' },
      { hostname: 'app-server-01', ip: '10.0.0.30', os: 'Windows Server 2019', role: 'server' }
    );
  }

  let xml = `<?xml version="1.0"?>
<NessusClientData_v2>
  <Policy>
    <policyName>Clinic-in-a-Box Security Scan</policyName>
    <policyComments>Generated scan for ${companyName}</policyComments>
  </Policy>
  <Report name="${companyName} Security Assessment" xmlns:cm="http://www.nessus.org/cm">
`;

  scanTargets.forEach((asset, idx) => {
    const ip = asset.ip || `10.0.0.${idx + 10}`;
    const hostname = asset.hostname || `host-${idx}`;
    const os = asset.os || 'Windows Server 2019';
    
    xml += `    <ReportHost name="${ip}">
      <HostProperties>
        <tag name="HOST_START">${new Date().toUTCString()}</tag>
        <tag name="HOST_END">${new Date().toUTCString()}</tag>
        <tag name="operating-system">${os}</tag>
        <tag name="host-ip">${ip}</tag>
        <tag name="host-fqdn">${hostname}.${domain}</tag>
        <tag name="netbios-name">${hostname.toUpperCase()}</tag>
      </HostProperties>
      <ReportItem port="445" svc_name="cifs" protocol="tcp" severity="2" pluginID="10264" pluginName="Microsoft Windows SMB Shares Enumeration" pluginFamily="Windows">
        <description>By connecting to the remote host, Nessus was able to enumerate the SMB shares.</description>
        <solution>Ensure that only authorized users can access SMB shares.</solution>
        <synopsis>It is possible to enumerate shares on the remote host.</synopsis>
        <plugin_output>The following shares were found on ${hostname}:
  - C$ (ADMIN)
  - ADMIN$ (ADMIN)
  - IPC$</plugin_output>
        <risk_factor>Medium</risk_factor>
        <cvss_base_score>5.0</cvss_base_score>
      </ReportItem>
      <ReportItem port="3389" svc_name="msrdp" protocol="tcp" severity="1" pluginID="58453" pluginName="RDP (Remote Desktop Protocol) Enabled" pluginFamily="Windows">
        <description>The remote Windows host has Remote Desktop Protocol (RDP) enabled.</description>
        <solution>Disable RDP if not required. If RDP is required, ensure proper authentication.</solution>
        <synopsis>Remote Desktop Protocol is enabled on this host.</synopsis>
        <plugin_output>RDP is enabled on port 3389/tcp.</plugin_output>
        <risk_factor>Low</risk_factor>
        <cvss_base_score>2.6</cvss_base_score>
      </ReportItem>
      <ReportItem port="443" svc_name="www" protocol="tcp" severity="2" pluginID="97833" pluginName="SSL/TLS Weak Cipher Suites Supported" pluginFamily="General">
        <description>The remote host supports SSL cipher suites using weak encryption.</description>
        <solution>Reconfigure the affected application to avoid weak ciphers.</solution>
        <synopsis>The remote service supports weak SSL ciphers.</synopsis>
        <plugin_output>Weak ciphers detected:
  TLS_RSA_WITH_3DES_EDE_CBC_SHA</plugin_output>
        <risk_factor>Medium</risk_factor>
        <cvss_base_score>5.0</cvss_base_score>
      </ReportItem>
      <ReportItem port="445" svc_name="cifs" protocol="tcp" severity="4" pluginID="97994" pluginName="MS17-010: Security Update for Microsoft Windows SMB Server" pluginFamily="Windows : Microsoft Bulletins">
        <description>The remote Windows host is missing security update MS17-010 (EternalBlue).</description>
        <solution>Apply the MS17-010 patches and disable SMBv1.</solution>
        <synopsis>The remote host is affected by multiple remote code execution vulnerabilities.</synopsis>
        <plugin_output>SMBv1 is enabled on this host.
MS17-010 patches have not been applied.</plugin_output>
        <risk_factor>Critical</risk_factor>
        <cvss_base_score>9.3</cvss_base_score>
        <cve>CVE-2017-0144</cve>
      </ReportItem>
      <ReportItem port="0" svc_name="general" protocol="tcp" severity="0" pluginID="19506" pluginName="Nessus Scan Information" pluginFamily="Settings">
        <description>This plugin displays information about the Nessus scan.</description>
        <solution>n/a</solution>
        <synopsis>Information about this scan.</synopsis>
        <plugin_output>Nessus version: 10.6.2
Plugin feed version: 202601150000
Scanner IP: 192.168.1.100
Scan type: Normal</plugin_output>
        <risk_factor>None</risk_factor>
      </ReportItem>
    </ReportHost>
`;
  });

  xml += `  </Report>
</NessusClientData_v2>`;

  return xml;
}

function generateZapHtml(profileData, companyName, domain) {
  const timestamp = new Date().toISOString();
  
  const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>ZAP Scanning Report - ${companyName}</title>
  <style>
    body { font-family: 'Segoe UI', Tahoma, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
    .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
    h1 { color: #333; border-bottom: 3px solid #ff6600; padding-bottom: 15px; }
    .summary { display: flex; gap: 20px; margin: 20px 0; }
    .summary-card { flex: 1; padding: 20px; border-radius: 8px; text-align: center; }
    .summary-card .count { font-size: 36px; font-weight: bold; }
    .high { background: #ffebee; color: #c62828; }
    .medium { background: #fff3e0; color: #ef6c00; }
    .low { background: #e3f2fd; color: #1565c0; }
    .alert { margin: 20px 0; padding: 20px; border-left: 4px solid; background: #fafafa; border-radius: 0 8px 8px 0; }
    .alert-high { border-color: #c62828; }
    .alert-medium { border-color: #ef6c00; }
    .alert-low { border-color: #1565c0; }
    .url { background: #263238; color: #4caf50; padding: 10px; border-radius: 4px; font-family: monospace; margin: 10px 0; }
    table { width: 100%; border-collapse: collapse; margin: 20px 0; }
    th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
    th { background: #f5f5f5; }
  </style>
</head>
<body>
  <div class="container">
    <h1>🕷️ OWASP ZAP Web Application Security Report</h1>
    
    <table>
      <tr><th>Target</th><td>https://${domain}</td></tr>
      <tr><th>Organization</th><td>${companyName}</td></tr>
      <tr><th>Scan Date</th><td>${timestamp}</td></tr>
      <tr><th>ZAP Version</th><td>2.14.0</td></tr>
    </table>
    
    <h2>Summary of Alerts</h2>
    <div class="summary">
      <div class="summary-card high"><div class="count">3</div><div>High</div></div>
      <div class="summary-card medium"><div class="count">8</div><div>Medium</div></div>
      <div class="summary-card low"><div class="count">15</div><div>Low</div></div>
    </div>
    
    <h2>Alert Details</h2>
    
    <div class="alert alert-high">
      <h3>🔴 Cross Site Scripting (Reflected)</h3>
      <p><strong>Risk:</strong> High | <strong>Confidence:</strong> Medium | <strong>CWE ID:</strong> 79</p>
      <p>Cross-site Scripting (XSS) is an attack technique that involves echoing attacker-supplied code into a user's browser instance.</p>
      <div class="url">https://${domain}/search?q=&lt;script&gt;alert(1)&lt;/script&gt;</div>
      <p><strong>Solution:</strong> Validate all input and encode all output.</p>
    </div>
    
    <div class="alert alert-high">
      <h3>🔴 SQL Injection</h3>
      <p><strong>Risk:</strong> High | <strong>Confidence:</strong> Medium | <strong>CWE ID:</strong> 89</p>
      <p>SQL injection may be possible. The page results were successfully manipulated using boolean conditions.</p>
      <div class="url">https://${domain}/api/users?id=1' OR '1'='1</div>
      <p><strong>Solution:</strong> Use parameterized queries (prepared statements).</p>
    </div>
    
    <div class="alert alert-medium">
      <h3>🟠 Missing Anti-clickjacking Header</h3>
      <p><strong>Risk:</strong> Medium | <strong>Confidence:</strong> Medium | <strong>CWE ID:</strong> 1021</p>
      <p>The response does not include X-Frame-Options to protect against ClickJacking attacks.</p>
      <div class="url">https://${domain}/</div>
      <p><strong>Solution:</strong> Set the X-Frame-Options header on all web pages.</p>
    </div>
    
    <div class="alert alert-medium">
      <h3>🟠 Content Security Policy (CSP) Header Not Set</h3>
      <p><strong>Risk:</strong> Medium | <strong>Confidence:</strong> High | <strong>CWE ID:</strong> 693</p>
      <p>Content Security Policy helps detect and mitigate XSS and data injection attacks.</p>
      <div class="url">https://${domain}/</div>
      <p><strong>Solution:</strong> Configure your web server to set the Content-Security-Policy header.</p>
    </div>
    
    <div class="alert alert-medium">
      <h3>🟠 Absence of Anti-CSRF Tokens</h3>
      <p><strong>Risk:</strong> Medium | <strong>Confidence:</strong> Low | <strong>CWE ID:</strong> 352</p>
      <p>No Anti-CSRF tokens were found in HTML submission forms.</p>
      <div class="url">https://${domain}/settings</div>
      <p><strong>Solution:</strong> Use a vetted library that implements anti-CSRF tokens.</p>
    </div>
    
    <div class="alert alert-low">
      <h3>🔵 X-Content-Type-Options Header Missing</h3>
      <p><strong>Risk:</strong> Low | <strong>Confidence:</strong> Medium | <strong>CWE ID:</strong> 693</p>
      <p>The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'.</p>
      <div class="url">https://${domain}/</div>
      <p><strong>Solution:</strong> Set the X-Content-Type-Options header to 'nosniff'.</p>
    </div>
    
    <div class="alert alert-low">
      <h3>🔵 Server Leaks Version Information</h3>
      <p><strong>Risk:</strong> Low | <strong>Confidence:</strong> High | <strong>CWE ID:</strong> 200</p>
      <p>The web server is leaking version information via the Server HTTP response header.</p>
      <div class="url">Server: Microsoft-IIS/10.0</div>
      <p><strong>Solution:</strong> Configure the server to suppress version information.</p>
    </div>
    
    <div style="margin-top: 40px; padding: 20px; background: #fafafa; text-align: center; color: #888;">
      <p>Generated by OWASP ZAP for Clinic-in-a-Box Training</p>
      <p style="font-size: 12px;">This is a simulated scan for educational purposes only.</p>
    </div>
  </div>
</body>
</html>`;

  return html;
}

function generateNmapXml(profileData, companyName, domain) {
  const timestamp = Math.floor(Date.now() / 1000);
  const assets = profileData.assets || [];
  
  const scanTargets = assets.filter(a => 
    a.role === 'server' || a.role === 'network'
  ).slice(0, 10);
  
  if (scanTargets.length === 0) {
    scanTargets.push(
      { hostname: 'dc-01', ip: '10.0.0.10', os: 'Windows Server 2019', role: 'server' },
      { hostname: 'file-server-01', ip: '10.0.0.20', os: 'Windows Server 2019', role: 'server' },
      { hostname: 'fw-01', ip: '10.0.0.1', os: 'Palo Alto PAN-OS', role: 'network' }
    );
  }

  let xml = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -sC -O -oX scan.xml" start="${timestamp}" version="7.94" xmloutputversion="1.05">
  <scaninfo type="syn" protocol="tcp" numservices="1000" services="1-1000"/>
  <verbose level="0"/>
  <debugging level="0"/>
`;

  scanTargets.forEach((asset, idx) => {
    const ip = asset.ip || `10.0.0.${idx + 10}`;
    const hostname = asset.hostname || `host-${idx}`;
    const os = asset.os || 'Windows Server 2019';
    const isServer = asset.role === 'server';
    
    xml += `  <host starttime="${timestamp}" endtime="${timestamp + 5}">
    <status state="up" reason="syn-ack" reason_ttl="64"/>
    <address addr="${ip}" addrtype="ipv4"/>
    <hostnames>
      <hostname name="${hostname}.${domain}" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.2p1"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="${isServer ? 'open' : 'closed'}" reason="syn-ack"/>
        <service name="http" product="Microsoft IIS httpd" version="10.0"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="ssl/http" product="Microsoft IIS httpd" version="10.0"/>
      </port>
      <port protocol="tcp" portid="445">
        <state state="open" reason="syn-ack"/>
        <service name="microsoft-ds" product="Microsoft Windows Server"/>
      </port>
      <port protocol="tcp" portid="3389">
        <state state="open" reason="syn-ack"/>
        <service name="ms-wbt-server" product="Microsoft Terminal Services"/>
      </port>
    </ports>
    <os>
      <osmatch name="${os}" accuracy="96">
        <osclass type="server" vendor="Microsoft" osfamily="Windows" osgen="2019" accuracy="96"/>
      </osmatch>
    </os>
    <uptime seconds="${Math.floor(Math.random() * 1000000 + 100000)}" lastboot="2026-01-01T00:00:00"/>
  </host>
`;
  });

  xml += `  <runstats>
    <finished time="${timestamp + 30}" timestr="${new Date().toUTCString()}" summary="Nmap done; ${scanTargets.length} IP addresses scanned" elapsed="30.5" exit="success"/>
    <hosts up="${scanTargets.length}" down="0" total="${scanTargets.length}"/>
  </runstats>
</nmaprun>`;

  return xml;
}

// POST /api/instructor/generate-documents - Generate security scan documents via N8N
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

    // Call N8N webhook to generate documents
    const n8nUrl = `${process.env.N8N_BASE_URL}${process.env.N8N_DOCUMENT_GENERATOR_WEBHOOK}`;
    console.log('🔗 Calling N8N webhook:', n8nUrl);

    const n8nPayload = {
      profile_id: profile_id,
      company_name: companyName,
      industry: profile.industry,
      profile_data: profileData,
      documents: documents,
      instructor_id: instructorId
    };

    const n8nResponse = await fetch(n8nUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(n8nPayload)
    });

    if (!n8nResponse.ok) {
      const errorText = await n8nResponse.text();
      console.error('❌ N8N webhook failed:', errorText);
      throw new Error(`N8N webhook failed: ${n8nResponse.status} ${errorText}`);
    }

    const n8nData = await n8nResponse.json();
    console.log('✅ N8N response received:', JSON.stringify({
      success: n8nData.success,
      documentCount: n8nData.documents?.length || 0,
      documentTypes: n8nData.documents?.map(d => d.type) || []
    }));

    // Store the generated documents in database
    const generatedDocs = [];

    if (n8nData.documents) {
      console.log(`📝 Processing ${n8nData.documents.length} documents from N8N...`);
      for (const doc of n8nData.documents) {
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
      n8n_response: n8nData
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

  return {
    company_info: {
      company_name: companyName,
      business_address: addr,
      industry_sector: industry,
      num_employees: String(empCount),
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
      products_services: productsText,
      recent_incidents: incidents.length > 0 ? incidents.join('; ') : 'No significant incidents reported in the past 12 months',
      ongoing_concerns: concerns || `General concerns about ${isLow ? 'lack of visibility into threats and outdated systems' : 'maintaining security posture as the organization grows'}`,
      primary_goals: goals,
      service_risk_assessment: true,
      service_training: true,
      service_vuln_assessment: !isLow,
      service_osint: isHigh,
      ai_used: saasList.some(s => s.toLowerCase().includes('ai') || s.toLowerCase().includes('copilot')) ? 'yes' : 'no',
      ai_has_policy: false, ai_no_policy: false,
      ai_interest_training: true, ai_interest_risks: true,
      ai_interest_opportunities: false, ai_interest_policy: false,
    },

    security_policies: {
      policy_incident_response: hasPolicy('incident'),
      policy_acceptable_use: hasPolicy('acceptable use'),
      policy_remote_access: hasPolicy('remote'),
      policy_network_security: hasPolicy('network security'),
      policy_data_management: hasPolicy('data handling') || hasPolicy('data management'),
      policy_disaster_recovery: hasPolicy('disaster') || hasPolicy('business continuity'),
      policy_employee_awareness: hasPolicy('training') || hasPolicy('awareness'),
      policy_data_backup: hasPolicy('backup'),
      policy_vendor_management: hasPolicy('vendor') || hasPolicy('third-party'),
      policy_data_retention: hasPolicy('retention'),
      policy_email: hasPolicy('email'),
      policy_risk_management: hasPolicy('risk management'),
      policy_change_management: hasPolicy('change management'),
      policy_access_control: hasPolicy('access control'),
      policy_password: hasPolicy('password'),
      policy_vendor_contractor: hasPolicy('vendor') || hasPolicy('contractor'),
      policy_byod: hasPolicy('byod') || hasPolicy('remote work'),
      policy_other: false,
      policy_documents_notes: gov.policy_enforcement
        ? `${gov.policy_enforcement}. Framework: ${gov.framework || 'None specified'}.`
        : `Security governance follows a ${gov.framework || 'informal'} approach.`,
      training_info_security: tScore(2),
      training_mobile_security: tScore(1),
      training_social_engineering: tScore(2),
      training_phishing: tScore(2),
      training_physical_security: tScore(1),
      training_wireless: tScore(1),
      training_security_awareness: tScore(2),
      training_safe_internet: tScore(1),
      training_email_security: tScore(2),
      training_other: 0,
    },

    data_management: {
      data_business: true,
      data_financial: true,
      data_email_addresses: true,
      data_consumer: empCount > 20,
      data_health: hasComp('hipaa') || industry.toLowerCase().includes('health'),
      data_credit_card: hasComp('pci') || industry.toLowerCase().includes('retail'),
      data_intellectual_property: industry.toLowerCase().includes('tech') || industry.toLowerCase().includes('manufact'),
      data_privacy: true,
      data_classified: industry.toLowerCase().includes('gov') || hasComp('fisma'),
      data_biometric: false,
      data_bank_account: true,
      data_trade_secrets: industry.toLowerCase().includes('tech') || industry.toLowerCase().includes('pharma'),
      data_membership: industry.toLowerCase().includes('nonprofit') || industry.toLowerCase().includes('association'),
      data_other: false,
      storage_onprem_physical: delivery.includes('on-prem') || servers.length > 0,
      storage_onprem_digital: servers.length > 0,
      storage_cloud: delivery.includes('cloud') || saasList.length > 2,
      storage_3rd_party: vendorDeps.length > 0,
      storage_other: false,
      backup_onprem: (backups.method || '').toLowerCase().includes('on-prem') || (backups.method || '').toLowerCase().includes('tape'),
      backup_cloud: (backups.method || '').toLowerCase().includes('cloud') || (backups.method || '').toLowerCase().includes('veeam'),
      backup_3rd_party: vendorDeps.length > 2,
      backup_other: false,
      backup_unknown: !backups.method,
      backup_none: false,
      backup_tests: backups.restore_tests ? 'yes' : (isLow ? 'no' : 'yes'),
      retention_followed: hasPolicy('retention') ? 'yes' : (isLow ? 'no' : 'yes'),
      ac_role_based: true,
      ac_attribute_based: isHigh,
      ac_mandatory: false,
      ac_discretionary: isLow,
      ac_rule_based: false,
      ac_other: false,
      access_control: 'yes',
    },

    network_security: {
      // Text fields for network equipment — fill with hostnames/model info from profile
      net_load_balancer: servers.length > 5 ? `${companyName.substring(0, 3).toUpperCase()}-LB01` : '',
      net_nac: isHigh ? 'Cisco ISE' : '',
      net_utm: fw.vendor && fw.vendor !== 'Unknown' ? fw.vendor : '',
      net_ids_ips: fw.vendor && fw.vendor !== 'Unknown' ? `${fw.vendor} IPS Module` : '',
      net_vpn: remote.vpn || '',
      net_siem: isHigh ? 'Splunk' : '',
      net_web_filter: isHigh ? 'Barracuda Web Filter' : '',
      net_switch: `Managed switches (${Math.max(2, Math.floor(empCount / 25))} units)`,
      net_router: `Core router + ${Math.max(1, Math.floor(empCount / 50))} edge routers`,
      net_wifi_ap: `${Math.max(2, Math.floor(empCount / 30))} access points`,
      net_modem: 'ISP-provided gateway',
      net_other: '',
      // Server fields — use actual server data
      server_mail: servers.find(s => /mail/i.test(s.role))?.hostname || (saasList.includes('Office 365') ? 'Exchange Online (O365)' : ''),
      server_dhcp: servers.find(s => /dhcp/i.test(s.role))?.hostname || 'Integrated with domain controller',
      server_web: servers.find(s => /web/i.test(s.role))?.hostname || '',
      server_file: servers.find(s => /file/i.test(s.role))?.hostname || (saasList.some(s => /sharepoint|drive/i.test(s)) ? 'SharePoint/OneDrive' : ''),
      server_database: servers.find(s => /db|database|sql/i.test(s.role))?.hostname || '',
      server_dns: servers.find(s => /dns/i.test(s.role))?.hostname || 'Active Directory DNS',
      server_application: servers.filter(s => /app|erp|crm|wms/i.test(s.role)).map(s => s.hostname).join(', ') || '',
      server_virtual: servers.filter(s => /virtual|vmware|hyper/i.test(s.os || '')).map(s => s.hostname).join(', ') || '',
      server_cloud: delivery.includes('cloud') ? saasList.slice(0, 3).join(', ') : '',
      server_other: servers.filter(s => !/mail|dhcp|web|file|db|database|dns|app|erp|crm|virtual/i.test(s.role || '')).map(s => `${s.hostname} (${s.role})`).join(', ') || '',
      // Firewall types
      fw_stateful: true,
      fw_stateless: false,
      fw_ngfw: fw.vendor && fw.vendor !== 'Unknown',
      fw_waf: servers.some(s => /web/i.test(s.role)),
      fw_cloud: delivery.includes('cloud'),
      fw_packet_filtering: isLow,
      // IDS/IPS
      ips_network: !isLow, ips_host: false,
      ids_network: !isLow, ids_host: false,
      // SIEM
      siem_splunk: isHigh, siem_qradar: false, siem_logrhythm: false, siem_other: false,
      // Additional tools
      net_edr: ep.product || '',
      net_xdr: isHigh && ep.product ? ep.product + ' XDR' : '',
      net_email_security: saasList.includes('Office 365') ? 'Microsoft Defender for Office 365' : '',
      password_manager_name: isHigh ? 'LastPass Enterprise' : '',
      security_assets_list: [
        ...serverLines,
        remote.vpn ? `VPN: ${remote.vpn}${remote.mfa ? ' (MFA: ' + remote.mfa + ')' : ''}` : '',
        ep.product ? `Endpoint Protection: ${ep.product}` : '',
        fw.vendor && fw.vendor !== 'Unknown' ? `Firewall: ${fw.vendor}` : '',
        backups.method ? `Backup: ${backups.method} (${backups.frequency || 'daily'})` : '',
        `Endpoints: ${endpoints.windows_desktops || 0} desktops, ${endpoints.windows_laptops || 0} laptops, ${endpoints.macos || 0} macOS, ${endpoints.mobile || 0} mobile`,
        saasList.length > 0 ? `SaaS: ${saasList.join(', ')}` : '',
      ].filter(Boolean).join('\n'),
    },

    wireless: {
      wifi_wep: isLow, // Deliberate weakness for low-maturity
      wifi_wps: false,
      wifi_wpa_personal: isLow,
      wifi_wpa_enterprise: false,
      wifi_wpa2_personal: !isHigh,
      wifi_wpa2_enterprise: !isLow,
      wifi_wpa3_personal: false,
      wifi_wpa3_enterprise: isHigh,
      wifi_unknown: false,
    },

    endpoint_security: {
      av_crowdstrike: (ep.product || '').toLowerCase().includes('crowdstrike'),
      av_sophos: (ep.product || '').toLowerCase().includes('sophos'),
      av_bitdefender: (ep.product || '').toLowerCase().includes('bitdefender'),
      av_malwarebytes: (ep.product || '').toLowerCase().includes('malwarebytes'),
      av_norton: (ep.product || '').toLowerCase().includes('norton'),
      av_mcafee: (ep.product || '').toLowerCase().includes('mcafee'),
      av_avast: (ep.product || '').toLowerCase().includes('avast'),
      av_other: ep.product && !['crowdstrike','sophos','bitdefender','malwarebytes','norton','mcafee','avast']
        .some(v => (ep.product || '').toLowerCase().includes(v)),
      app_whitelist: isHigh,
      app_blacklist: !isLow,
      app_list_unknown: isLow,
    },

    compliance: {
      comp_hipaa: hasComp('hipaa'),
      comp_pci_dss: hasComp('pci'),
      comp_gdpr: hasComp('gdpr'),
      comp_sox: hasComp('sox'),
      comp_ferpa: hasComp('ferpa'),
      comp_soc2: hasComp('soc'),
      comp_glba: hasComp('glba'),
      comp_fisma: hasComp('fisma'),
      comp_ccpa: hasComp('ccpa'),
      comp_cmmc: hasComp('cmmc'),
      comp_other: false,
      comp_unknown: complianceFocus.length === 0,
      vendor_compliance: vendorDeps.length > 0
        ? `Key vendors requiring compliance: ${vendorDeps.map(v => typeof v === 'string' ? v : v.name || v.vendor || '').filter(Boolean).join(', ')}. Vendor security assessments ${isLow ? 'not currently performed' : 'conducted annually'}.`
        : '',
    },

    software_assets: {
      software_inventory: isLow ? 'no' : 'yes',
      unauthorized_software: isLow ? 'no' : 'yes',
      software_review: isLow ? 'no' : 'yes',
    },

    vuln_management: {
      vuln_scanning: isLow ? 'no' : 'yes',
      vuln_remediation: isLow ? 'no' : (isHigh ? 'yes' : 'partial'),
      vuln_reports: isLow ? 'no' : 'yes',
    },

    admin_privileges: {
      admin_roles: 'yes',
      admin_audit: isLow ? 'no' : 'yes',
      admin_revoke: isLow ? 'no' : 'yes',
    },

    secure_config: {
      secure_config_install: isLow ? 'no' : 'yes',
      secure_config_update: isLow ? 'no' : (isHigh ? 'yes' : 'no'),
      secure_config_deviations: isLow ? 'no' : (isHigh ? 'yes' : 'no'),
    },

    email_web: {
      email_filter: 'yes',
      browser_settings: isLow ? 'no' : 'yes',
      email_training: hasPolicy('training') || hasPolicy('awareness') ? 'yes' : (isLow ? 'no' : 'yes'),
    },

    network_ports: {
      ports_disabled: isLow ? 'no' : 'yes',
      ports_review: isLow ? 'no' : (isHigh ? 'yes' : 'no'),
      ports_monitor: isHigh ? 'yes' : 'no',
    },

    network_devices: {
      scanner_nessus: !isLow,
      scanner_openvas: isLow,
      scanner_other: false,
      scanner_unknown: isLow,
      scanner_report: isLow ? '' : `Last scan: ${new Date(Date.now() - 30 * 86400000).toLocaleDateString()}. ${isHigh ? 'Monthly automated scans with quarterly manual review.' : 'Quarterly scans performed by IT team.'}`,
    },

    pentesting: {
      pentest_regular: isHigh ? 'yes' : 'no',
      pentest_improve: isHigh ? 'yes' : 'no',
      redteam: isHigh ? 'yes' : 'no',
    },
  };
}

// POST /api/instructor/generate-examples - Generate answer key for all parts
router.post('/generate-examples', authenticateToken, instructorOnly, async (req, res) => {
  try {
    const { profile_id, parts } = req.body;
    const instructorId = req.user.userId;

    if (!profile_id) {
      return res.status(400).json({ success: false, error: 'Missing profile_id' });
    }

    console.log('[Examples] Generate request:', { profile_id, instructorId });

    // Load profile data (reuse same logic as generate-documents)
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

    // Build profile context for the LLM
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

    // Determine which parts to generate (default: all 8)
    const partsToGenerate = parts || [1, 2, 3, 4, 5, 6, 7, 8];

    // Call N8N webhook
    const n8nUrl = `${process.env.N8N_BASE_URL}${process.env.N8N_EXAMPLES_WEBHOOK || '/webhook-test/generate-examples'}`;
    console.log('[Examples] Calling N8N:', n8nUrl);

    const n8nResponse = await fetch(n8nUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        profile_id,
        profile_context: profileContext,
        parts: partsToGenerate,
        part_definitions: PART_DEFINITIONS
      })
    });

    if (!n8nResponse.ok) {
      const errText = await n8nResponse.text();
      throw new Error(`N8N failed: ${n8nResponse.status} ${errText}`);
    }

    let n8nData = await n8nResponse.json();
    // N8N respondToWebhook with "allIncomingItems" wraps in an array
    if (Array.isArray(n8nData)) n8nData = n8nData[0] || {};
    console.log('[Examples] N8N returned', Object.keys(n8nData.examples || {}).length, 'parts');

    // Store results in assessment_progress using the instructor's user_id
    // with a special convention: stored under the instructor's own user_id
    const stored = [];
    const failed = [];
    const examples = n8nData.examples || {};

    for (const [partNum, partContent] of Object.entries(examples)) {
      const pNum = parseInt(partNum);
      const partDef = PART_DEFINITIONS[pNum];
      if (!partDef) continue;

      // Build the envelope format matching workspace.js
      const allOptionKeys = partDef.options.map(o => o.key);
      const envelope = {
        deliverables: partContent.deliverables || {},
        general_notes: partContent.general_notes || '',
        is_example: true
      };

      try {
        await query(`
          INSERT INTO assessment_progress
            (user_id, profile_id, part_number, part_name, content, output_option, status)
          VALUES ($1, $2, $3, $4, $5, $6, 'reviewed')
          ON CONFLICT (user_id, profile_id, part_number)
          DO UPDATE SET
            content = EXCLUDED.content,
            output_option = EXCLUDED.output_option,
            status = 'reviewed',
            updated_at = NOW()
        `, [
          instructorId, profile_id, pNum, partDef.name,
          JSON.stringify(envelope),
          JSON.stringify(allOptionKeys)
        ]);
        stored.push(pNum);
      } catch (dbErr) {
        console.error(`[Examples] Failed to store part ${pNum}:`, dbErr.message);
        failed.push({ part: pNum, error: dbErr.message });
      }
    }

    console.log('[Examples] Stored parts:', stored, 'Failed:', failed);

    // Also generate and store a completed intake form from profile data
    let intakeFormStored = false;
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
      `, [
        instructorId, profile_id,
        ...V72_SECTIONS.map(s => JSON.stringify(intakeData[s] || {}))
      ]);
      intakeFormStored = true;
      console.log('[Examples] Intake form generated and stored');
    } catch (intakeErr) {
      console.error('[Examples] Failed to store intake form:', intakeErr.message);
    }

    res.json({
      success: true,
      profile_id,
      parts_generated: stored,
      parts_failed: failed,
      intake_form_generated: intakeFormStored,
      generated_at: new Date().toISOString()
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

function stripHtml(html) {
  if (!html) return '';
  let text = String(html);

  // Convert tables to readable text: extract rows, format as "Header: Value" pairs
  // First, try to extract table headers for context
  text = text.replace(/<table[^>]*>([\s\S]*?)<\/table>/gi, (match, tableContent) => {
    const headers = [];
    const headerMatch = tableContent.match(/<thead[^>]*>([\s\S]*?)<\/thead>/i);
    if (headerMatch) {
      const thMatches = headerMatch[1].match(/<th[^>]*>([\s\S]*?)<\/th>/gi);
      if (thMatches) {
        thMatches.forEach(th => headers.push(th.replace(/<[^>]+>/g, '').trim()));
      }
    }

    const rows = [];
    const rowMatches = tableContent.match(/<tr[^>]*>([\s\S]*?)<\/tr>/gi) || [];
    for (const row of rowMatches) {
      // Skip header rows
      if (/<th[^>]*>/i.test(row) && !/<td[^>]*>/i.test(row)) continue;
      const cells = [];
      const cellMatches = row.match(/<td[^>]*>([\s\S]*?)<\/td>/gi) || [];
      cellMatches.forEach(td => cells.push(td.replace(/<[^>]+>/g, '').trim()));
      if (cells.length > 0) rows.push(cells);
    }

    if (rows.length === 0) return '';

    // Format: if headers exist, use "Header: Value" format per cell
    return rows.map(cells => {
      if (headers.length > 0) {
        return cells.map((cell, i) => `${headers[i] || 'Column ' + (i+1)}: ${cell}`).join('  |  ');
      }
      return cells.join('  |  ');
    }).join('\n') + '\n';
  });

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
          doc.fillColor('#718096').fontSize(8).font('Helvetica-Bold')
            .text(`DELIVERABLE ${i + 1}`, leftMargin, doc.y);
          doc.moveDown(0.2);
          const plainText = stripHtml(html);
          doc.fillColor('#1e293b').fontSize(9.5).font('Helvetica')
            .text(plainText, leftMargin, doc.y, { width: pageWidth, lineGap: 2 });
          doc.moveDown(0.6);
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

    const result = await query(
      `SELECT id, email, first_name, last_name, organization
       FROM users
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