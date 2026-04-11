/*
 * ============================================================================
 * Progress Routes - Student Assessment Progress Tracking
 * ============================================================================
 */

const express = require('express');
const router = express.Router();
<<<<<<<< HEAD:front-end/plugins/ciab/routes/progress.js
const { query } = require('../utils/db');
const { authenticateToken } = require('../../../src/middleware/auth');
========
const { query } = require('../core/utils/db');
const { authenticateToken } = require('../core/middleware/auth');
>>>>>>>> 92070e5ce56df726143f2b62c2e9027f2d3f335b:cyberhub-web-interface/src/routes/progress.js

// GET /api/progress/:profileId - Get all progress for a profile
router.get('/:profileId', authenticateToken, async (req, res) => {
  try {
    const { profileId } = req.params;
    const userId = req.user.userId;
    
    const result = await query(`
      SELECT ap.*, u_reviewer.email AS reviewer_email
      FROM assessment_progress ap
      LEFT JOIN users u_reviewer ON ap.reviewer_id = u_reviewer.id
      WHERE ap.user_id = $1 AND ap.profile_id = $2
      ORDER BY ap.part_number
    `, [userId, profileId]);
    
    // Build progress map for all 8 parts
    const progressMap = {};
    for (let i = 1; i <= 8; i++) {
      progressMap[i] = {
        part_number: i,
        part_name: getPartName(i),
        status: 'not_started',
        content: null,
        evidence_files: [],
        score: null,
        feedback: null
      };
    }
    
    // Overlay actual progress
    for (const row of result.rows) {
      progressMap[row.part_number] = { ...progressMap[row.part_number], ...row };
    }
    
    res.json({
      success: true,
      profile_id: profileId,
      progress: Object.values(progressMap),
      summary: {
        total_parts: 8,
        started: result.rows.length,
        submitted: result.rows.filter(r => ['submitted', 'reviewed'].includes(r.status)).length,
        reviewed: result.rows.filter(r => r.status === 'reviewed').length,
        avg_score: calculateAvgScore(result.rows)
      }
    });
    
  } catch (error) {
    console.error('Error fetching progress:', error);
    res.status(500).json({ error: 'Failed to fetch progress' });
  }
});

// PUT /api/progress/:profileId/:partNumber - Update progress for a part
router.put('/:profileId/:partNumber', authenticateToken, async (req, res) => {
  try {
    const { profileId, partNumber } = req.params;
    const userId = req.user.userId;
    const { content, output_option, evidence_files, status } = req.body;
    
    const partNum = parseInt(partNumber);
    if (partNum < 1 || partNum > 8) {
      return res.status(400).json({ error: 'Invalid part number' });
    }
    
    const result = await query(`
      INSERT INTO assessment_progress 
        (user_id, profile_id, part_number, part_name, content, output_option, evidence_files, status)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      ON CONFLICT (user_id, profile_id, part_number) 
      DO UPDATE SET
        content = COALESCE(EXCLUDED.content, assessment_progress.content),
        output_option = COALESCE(EXCLUDED.output_option, assessment_progress.output_option),
        evidence_files = COALESCE(EXCLUDED.evidence_files, assessment_progress.evidence_files),
        status = COALESCE(EXCLUDED.status, assessment_progress.status),
        updated_at = NOW()
      RETURNING *
    `, [userId, profileId, partNum, getPartName(partNum), content, output_option, 
        JSON.stringify(evidence_files || []), status || 'in_progress']);
    
    res.json({ success: true, progress: result.rows[0] });
    
  } catch (error) {
    console.error('Error updating progress:', error);
    res.status(500).json({ error: 'Failed to update progress' });
  }
});

// POST /api/progress/:profileId/:partNumber/submit - Submit for review
router.post('/:profileId/:partNumber/submit', authenticateToken, async (req, res) => {
  try {
    const { profileId, partNumber } = req.params;
    const userId = req.user.userId;
    
    const result = await query(`
      UPDATE assessment_progress
      SET status = 'submitted', submitted_at = NOW(), revision_count = revision_count + 1
      WHERE user_id = $1 AND profile_id = $2 AND part_number = $3
      RETURNING *
    `, [userId, profileId, parseInt(partNumber)]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Progress record not found' });
    }
    
    res.json({ success: true, message: 'Submitted for review', progress: result.rows[0] });
    
  } catch (error) {
    console.error('Error submitting progress:', error);
    res.status(500).json({ error: 'Failed to submit' });
  }
});

// Helper functions
function getPartName(partNumber) {
  const names = {
    1: 'Introduction to Risk Assessment', 2: 'Scoping and Context',
    3: 'Threat Identification', 4: 'Vulnerability Assessment',
    5: 'Risk Analysis', 6: 'Control Recommendations',
    7: 'Reporting', 8: 'Presentation'
  };
  return names[partNumber] || `Part ${partNumber}`;
}

function calculateAvgScore(rows) {
  const scored = rows.filter(r => r.score !== null);
  if (scored.length === 0) return null;
  return scored.reduce((sum, r) => sum + parseFloat(r.score), 0) / scored.length;
}

module.exports = router;
