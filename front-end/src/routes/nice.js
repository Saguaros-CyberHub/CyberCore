/*
 * ============================================================================
 * NICE Framework Routes - Competency Progress Tracking
 * ============================================================================
 */

const express = require('express');
const router = express.Router();
const { query } = require('../utils/db');
const { authenticateToken } = require('../middleware/auth');

// GET /api/nice/progress - Get user's NICE framework progress
router.get('/progress', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    
    const progressResult = await query(`
      SELECT np.*, nfr.name AS competency_name, nfr.description AS competency_description
      FROM nice_progress np
      LEFT JOIN nice_framework_reference nfr ON np.competency_id = nfr.id
      WHERE np.user_id = $1
      ORDER BY np.demonstrated_at DESC
    `, [userId]);
    
    const totalsResult = await query(`
      SELECT type, COUNT(*) as total
      FROM nice_framework_reference
      WHERE type IN ('task', 'knowledge', 'skill')
      GROUP BY type
    `);
    
    const totals = {};
    for (const row of totalsResult.rows) {
      totals[row.type] = parseInt(row.total);
    }
    
    // Calculate progress by work role
    const workRoleProgress = {};
    for (const row of progressResult.rows) {
      const roleId = row.work_role_id || 'general';
      if (!workRoleProgress[roleId]) {
        workRoleProgress[roleId] = {
          work_role: row.work_role, work_role_id: roleId,
          tasks: new Set(), knowledge: new Set(), skills: new Set()
        };
      }
      workRoleProgress[roleId][row.competency_type + 's'].add(row.competency_id);
    }
    
    const workRoles = Object.values(workRoleProgress).map(wr => ({
      work_role: wr.work_role, work_role_id: wr.work_role_id,
      tasks_completed: wr.tasks.size, knowledge_demonstrated: wr.knowledge.size,
      skills_demonstrated: wr.skills.size,
      tasks_total: totals.task || 0, knowledge_total: totals.knowledge || 0, skills_total: totals.skill || 0
    }));
    
    res.json({
      success: true,
      progress: {
        work_roles: workRoles,
        total_tasks: totals.task || 0, total_knowledge: totals.knowledge || 0, total_skills: totals.skill || 0,
        completed_tasks: new Set(progressResult.rows.filter(r => r.competency_type === 'task').map(r => r.competency_id)).size,
        completed_knowledge: new Set(progressResult.rows.filter(r => r.competency_type === 'knowledge').map(r => r.competency_id)).size,
        completed_skills: new Set(progressResult.rows.filter(r => r.competency_type === 'skill').map(r => r.competency_id)).size
      },
      history: progressResult.rows
    });
    
  } catch (error) {
    console.error('Error fetching NICE progress:', error);
    res.status(500).json({ error: 'Failed to fetch NICE progress' });
  }
});

// POST /api/nice/progress - Record a competency demonstration
router.post('/progress', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { work_role, work_role_id, competency_type, competency_id, evidence_link, profile_id, part_number } = req.body;
    
    if (!['task', 'knowledge', 'skill'].includes(competency_type)) {
      return res.status(400).json({ error: 'Invalid competency type' });
    }
    
    const refResult = await query(
      'SELECT name, description FROM nice_framework_reference WHERE id = $1',
      [competency_id]
    );
    
    const result = await query(`
      INSERT INTO nice_progress 
        (user_id, work_role, work_role_id, competency_type, competency_id, 
         competency_description, evidence_link, profile_id, part_number)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      ON CONFLICT (user_id, work_role_id, competency_type, competency_id)
      DO UPDATE SET demonstrated_at = NOW(), evidence_link = COALESCE(EXCLUDED.evidence_link, nice_progress.evidence_link)
      RETURNING *
    `, [userId, work_role, work_role_id, competency_type, competency_id,
        refResult.rows[0]?.description || null, evidence_link, profile_id, part_number]);
    
    res.json({ success: true, recorded: result.rows[0] });
    
  } catch (error) {
    console.error('Error recording NICE progress:', error);
    res.status(500).json({ error: 'Failed to record progress' });
  }
});

// GET /api/nice/reference - Get NICE Framework reference data
router.get('/reference', async (req, res) => {
  try {
    const result = await query('SELECT * FROM nice_framework_reference ORDER BY type, id');
    
    const grouped = { work_roles: [], tasks: [], knowledge: [], skills: [] };
    for (const row of result.rows) {
      switch (row.type) {
        case 'work_role': grouped.work_roles.push(row); break;
        case 'task': grouped.tasks.push(row); break;
        case 'knowledge': grouped.knowledge.push(row); break;
        case 'skill': grouped.skills.push(row); break;
      }
    }
    
    res.json({ success: true, reference: grouped });
    
  } catch (error) {
    console.error('Error fetching NICE reference:', error);
    res.status(500).json({ error: 'Failed to fetch reference data' });
  }
});

// GET /api/nice/export - Export progress for portfolio
router.get('/export', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    
    const result = await query(`
      SELECT np.*, nfr.name AS competency_name, nfr.description AS competency_description,
             p.company_name AS profile_name, ap.part_name
      FROM nice_progress np
      LEFT JOIN nice_framework_reference nfr ON np.competency_id = nfr.id
      LEFT JOIN profiles p ON np.profile_id = p.id
      LEFT JOIN assessment_progress ap ON np.evidence_link = ap.id
      WHERE np.user_id = $1
      ORDER BY np.work_role, np.competency_type, np.demonstrated_at
    `, [userId]);
    
    res.json({
      success: true,
      export: {
        generated_at: new Date().toISOString(),
        user_id: userId,
        summary: {
          total_competencies: result.rows.length,
          tasks: result.rows.filter(r => r.competency_type === 'task').length,
          knowledge: result.rows.filter(r => r.competency_type === 'knowledge').length,
          skills: result.rows.filter(r => r.competency_type === 'skill').length
        },
        competencies: result.rows.map(r => ({
          competency_id: r.competency_id, competency_name: r.competency_name,
          type: r.competency_type, work_role: r.work_role, demonstrated_at: r.demonstrated_at,
          evidence_context: r.profile_name ? `${r.profile_name} - ${r.part_name}` : null
        }))
      }
    });
    
  } catch (error) {
    console.error('Error exporting NICE progress:', error);
    res.status(500).json({ error: 'Failed to export progress' });
  }
});

module.exports = router;
