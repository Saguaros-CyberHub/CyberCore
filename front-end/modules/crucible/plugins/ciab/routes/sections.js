/**
 * CIAB Plugin — Sections and rosters
 * ----------------------------------------------------------------------------
 * A section is a class. An ACTIVE enrollment on an ACTIVE section is what grants
 * a student access to Clinic-in-a-Box (utils/enrollment.js); everything in this
 * file exists so an instructor can put people there as easily as they can in the
 * CLE plugin.
 *
 * Split from the 2,509-line routes/instructor.js on purpose, mirroring CLE's
 * courses.js / course-students.js / course-roster.js split. The BULK surface
 * (CSV import, cohort generation, credentials) lives in section-roster.js as a
 * sibling mount, so its verbs never contend with the /:userId routes here --
 * the reason cle/routes/api.js:41-47 gives for mounting /roster first.
 *
 * AUTHORISATION, twice, deliberately:
 *   requireRole('instructor','admin')  are you staff at all
 *   getManagedSection(...)             may you touch THIS section
 * The second is admin-aware and answers "does it exist" and "may you" in one
 * call, so a route cannot accidentally answer the first without the second.
 */

const express = require('express');
const router = express.Router();

const { query } = require('../utils/db');
const { cybercoreQuery } = require('../../../../../src/utils/cybercore-db');
const { requireRole } = require('../../../../../src/middleware/auth');
const prov = require('../../../../../src/utils/account-provisioning');
const activation = require('../../../../../src/utils/activation');
const enrollment = require('../utils/enrollment');
const roster = require('../utils/section-roster');

const instructorOnly = requireRole('instructor', 'admin');

/** Mounted at /api/instructor/sections; :sectionId also arrives via res.locals. */
const sectionIdOf = (req, res) => res.locals.sectionId || req.params.sectionId;

/** 403 and a null return, so callers can `if (!section) return;`. */
async function mustManage(req, res, columns = 'section_id, name, code, status, max_students, instructor_id') {
  const section = await enrollment.getManagedSection(sectionIdOf(req, res), req.user, columns);
  if (!section) {
    res.status(403).json({ error: 'Section not found or access denied' });
    return null;
  }
  return section;
}

// ---------------------------------------------------------------------------
// Sections
// ---------------------------------------------------------------------------

// GET /api/instructor/sections?status=active|archived|all
router.get('/', instructorOnly, async (req, res) => {
  try {
    const status = ['active', 'archived', 'all'].includes(req.query.status) ? req.query.status : 'active';
    const sections = await enrollment.sectionsManagedBy(req.user, { status });
    if (!sections.length) return res.json({ sections: [] });

    const ids = sections.map((s) => s.section_id);
    const counts = await query(
      `SELECT section_id,
              COUNT(*) FILTER (WHERE status = 'active')  ::int AS active_count,
              COUNT(*) FILTER (WHERE status = 'dropped') ::int AS dropped_count
         FROM ciab_enrollment WHERE section_id = ANY($1::uuid[]) GROUP BY section_id`,
      [ids]
    );
    const byId = new Map(counts.rows.map((r) => [r.section_id, r]));

    const staff = await query(
      `SELECT section_id, instructor_id, staff_role
         FROM ciab_section_instructor WHERE section_id = ANY($1::uuid[])`,
      [ids]
    );
    const staffBySection = new Map();
    for (const row of staff.rows) {
      if (!staffBySection.has(row.section_id)) staffBySection.set(row.section_id, []);
      staffBySection.get(row.section_id).push(row);
    }

    res.json({
      sections: sections.map((s) => ({
        ...s,
        // Ownership decides who may rename, archive or change staff. Computed
        // here rather than compared client-side against a user id the page
        // would have to be trusted to hold.
        is_owner: s.instructor_id === req.user.userId || req.user.role === 'admin',
        staff: staffBySection.get(s.section_id) || [],
        active_count: (byId.get(s.section_id) || {}).active_count || 0,
        dropped_count: (byId.get(s.section_id) || {}).dropped_count || 0,
      })),
    });
  } catch (error) {
    console.error('[CIAB] list sections:', error.message);
    res.status(500).json({ error: 'Failed to load sections' });
  }
});

// POST /api/instructor/sections
router.post('/', instructorOnly, express.json(), async (req, res) => {
  try {
    const name = String(req.body.name || '').trim();
    if (!name) return res.status(400).json({ error: 'A section name is required' });

    const code = String(req.body.code || '').trim() || null;
    const maxStudents = req.body.max_students == null || req.body.max_students === ''
      ? null : Number(req.body.max_students);
    if (maxStudents != null && (!Number.isInteger(maxStudents) || maxStudents < 1)) {
      return res.status(400).json({ error: 'Seat limit must be a whole number of 1 or more' });
    }

    const inserted = await query(
      `INSERT INTO ciab_section (name, code, term, description, instructor_id, max_students, source, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, 'manual', $5)
       RETURNING *`,
      [
        name, code,
        String(req.body.term || '').trim() || null,
        String(req.body.description || '').trim() || null,
        req.user.userId,
        maxStudents,
      ]
    );
    const section = inserted.rows[0];

    // The owner is also a staff row, so "sections I manage" stays one predicate.
    await query(
      `INSERT INTO ciab_section_instructor (section_id, instructor_id, staff_role, added_by)
       VALUES ($1, $2, 'instructor', $2) ON CONFLICT DO NOTHING`,
      [section.section_id, req.user.userId]
    );

    roster.logRosterActivity({
      actorId: req.user.userId, sectionId: section.section_id,
      action: 'section_created', detail: { name, code },
    });
    res.status(201).json({ section });
  } catch (error) {
    // ux_ciab_section_code: two ACTIVE sections sharing a code would generate
    // colliding cohort usernames, and planCohort() would report the other
    // section's accounts as "already provisioned".
    if (error.code === '23505') {
      return res.status(409).json({
        error: 'Another active section already uses that code. Codes must be unique '
             + 'because they generate cohort account names.',
      });
    }
    console.error('[CIAB] create section:', error.message);
    res.status(500).json({ error: 'Failed to create section' });
  }
});

// GET /api/instructor/sections/:sectionId
router.get('/:sectionId', instructorOnly, async (req, res) => {
  try {
    const section = await mustManage(req, res, '*');
    if (!section) return;

    const counts = await query(
      `SELECT status, COUNT(*)::int AS n FROM ciab_enrollment
        WHERE section_id = $1 GROUP BY status`,
      [section.section_id]
    );
    const staff = await query(
      `SELECT instructor_id, staff_role, added_at FROM ciab_section_instructor
        WHERE section_id = $1`,
      [section.section_id]
    );

    let staffUsers = [];
    if (staff.rows.length) {
      const u = await cybercoreQuery(
        `SELECT user_id, email, first_name, last_name, role FROM cybercore_user
          WHERE user_id = ANY($1::uuid[])`,
        [staff.rows.map((r) => r.instructor_id)]
      ).catch(() => ({ rows: [] }));
      const byId = new Map(u.rows.map((r) => [r.user_id, r]));
      staffUsers = staff.rows.map((r) => ({ ...r, ...(byId.get(r.instructor_id) || {}) }));
    }

    res.json({
      section: { ...section, is_owner: section.instructor_id === req.user.userId || req.user.role === 'admin' },
      staff: staffUsers,
      counts: Object.fromEntries(counts.rows.map((r) => [r.status, r.n])),
    });
  } catch (error) {
    console.error('[CIAB] read section:', error.message);
    res.status(500).json({ error: 'Failed to load section' });
  }
});

// PATCH /api/instructor/sections/:sectionId
router.patch('/:sectionId', instructorOnly, express.json(), async (req, res) => {
  try {
    const section = await mustManage(req, res, 'section_id, instructor_id, status');
    if (!section) return;

    const sets = [];
    const params = [];
    const set = (col, val) => { params.push(val); sets.push(`${col} = $${params.length}`); };

    if (req.body.name !== undefined) {
      const name = String(req.body.name).trim();
      if (!name) return res.status(400).json({ error: 'A section name is required' });
      set('name', name);
    }
    if (req.body.code !== undefined) set('code', String(req.body.code).trim() || null);
    if (req.body.term !== undefined) set('term', String(req.body.term).trim() || null);
    if (req.body.description !== undefined) set('description', String(req.body.description).trim() || null);
    if (req.body.max_students !== undefined) {
      const n = req.body.max_students === null || req.body.max_students === '' ? null : Number(req.body.max_students);
      if (n != null && (!Number.isInteger(n) || n < 1)) {
        return res.status(400).json({ error: 'Seat limit must be a whole number of 1 or more' });
      }
      set('max_students', n);
    }
    if (req.body.status !== undefined) {
      if (!['active', 'archived'].includes(req.body.status)) {
        return res.status(400).json({ error: 'status must be active or archived' });
      }
      set('status', req.body.status);
    }
    if (!sets.length) return res.status(400).json({ error: 'Nothing to update' });

    set('updated_at', new Date());
    params.push(section.section_id);

    const updated = await query(
      `UPDATE ciab_section SET ${sets.join(', ')} WHERE section_id = $${params.length} RETURNING *`,
      params
    );

    // Archiving revokes access for every student enrolled only here, so the
    // cached "yes" they are holding has to go immediately rather than at the
    // end of its TTL.
    if (req.body.status !== undefined && req.body.status !== section.status) {
      enrollment.invalidateAll();
    }

    roster.logRosterActivity({
      actorId: req.user.userId, sectionId: section.section_id,
      action: 'section_updated', detail: { fields: sets.map((s) => s.split(' ')[0]) },
    });
    res.json({ section: updated.rows[0] });
  } catch (error) {
    if (error.code === '23505') {
      return res.status(409).json({ error: 'Another active section already uses that code.' });
    }
    console.error('[CIAB] update section:', error.message);
    res.status(500).json({ error: 'Failed to update section' });
  }
});

// DELETE /api/instructor/sections/:sectionId   (soft: archive; ?hard=1 admin)
router.delete('/:sectionId', instructorOnly, async (req, res) => {
  try {
    const section = await mustManage(req, res, 'section_id, instructor_id, name');
    if (!section) return;

    // How many students lose access outright — i.e. are on no OTHER active
    // section. The UI warns with this number before archiving; "3 students will
    // lose access" is a different decision from "0 will".
    const exposed = await query(
      `SELECT COUNT(*)::int AS n FROM ciab_enrollment e
        WHERE e.section_id = $1 AND e.status = 'active'
          AND NOT EXISTS (
            SELECT 1 FROM ciab_enrollment o
              JOIN ciab_section s ON s.section_id = o.section_id
             WHERE o.user_id = e.user_id AND o.status = 'active'
               AND s.status = 'active' AND o.section_id <> $1)`,
      [section.section_id]
    );

    const hard = req.query.hard === '1' || req.query.hard === 'true';
    if (hard) {
      if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Only an administrator can delete a section outright' });
      }
      const any = await query(
        `SELECT 1 FROM ciab_enrollment WHERE section_id = $1 LIMIT 1`, [section.section_id]
      );
      if (any.rowCount) {
        return res.status(409).json({
          error: 'This section still has enrollments. Archive it instead, or drop everyone first.',
        });
      }
      await query(`DELETE FROM ciab_section WHERE section_id = $1`, [section.section_id]);
    } else {
      await query(
        `UPDATE ciab_section SET status = 'archived', updated_at = NOW() WHERE section_id = $1`,
        [section.section_id]
      );
    }

    enrollment.invalidateAll();
    roster.logRosterActivity({
      actorId: req.user.userId, sectionId: section.section_id,
      action: hard ? 'section_deleted' : 'section_archived',
      detail: { name: section.name, revoked_access_for: exposed.rows[0].n },
    });
    res.json({ success: true, archived: !hard, revoked_access_for: exposed.rows[0].n });
  } catch (error) {
    console.error('[CIAB] archive section:', error.message);
    res.status(500).json({ error: 'Failed to archive section' });
  }
});

// ---------------------------------------------------------------------------
// Co-instructors and TAs
// ---------------------------------------------------------------------------

/** Only the owner (or an admin) changes who else can teach a section. */
async function mustOwn(req, res) {
  const section = await mustManage(req, res, 'section_id, instructor_id');
  if (!section) return null;
  if (req.user.role !== 'admin' && section.instructor_id !== req.user.userId) {
    res.status(403).json({ error: 'Only the section owner can change its staff' });
    return null;
  }
  return section;
}

// POST /api/instructor/sections/:sectionId/instructors
router.post('/:sectionId/instructors', instructorOnly, express.json(), async (req, res) => {
  try {
    const section = await mustOwn(req, res);
    if (!section) return;

    const staffRole = req.body.staff_role === 'ta' ? 'ta' : 'instructor';
    let userId = req.body.user_id || null;
    if (!userId) {
      const email = prov.normalizeEmail(String(req.body.email || ''));
      if (!email) return res.status(400).json({ error: 'An email address or user id is required' });
      const user = await prov.findUserByEmail(email);
      if (!user) return res.status(404).json({ error: `No account exists for ${email}` });
      // Staff, not students: this route grants section-management rights, and
      // handing them to a student account would be a quiet privilege grant.
      if (!['instructor', 'admin'].includes(String(user.role))) {
        return res.status(400).json({
          error: `${email} is a ${user.role} account. Only instructors can be added as section staff — `
               + 'enroll them as a student instead.',
        });
      }
      userId = user.user_id;
    }

    await query(
      `INSERT INTO ciab_section_instructor (section_id, instructor_id, staff_role, added_by)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (section_id, instructor_id) DO UPDATE SET staff_role = EXCLUDED.staff_role`,
      [section.section_id, userId, staffRole, req.user.userId]
    );
    roster.logRosterActivity({
      actorId: req.user.userId, sectionId: section.section_id,
      action: 'staff_added', detail: { instructor_id: userId, staff_role: staffRole },
    });
    res.status(201).json({ success: true });
  } catch (error) {
    console.error('[CIAB] add section staff:', error.message);
    res.status(500).json({ error: 'Failed to add staff' });
  }
});

// DELETE /api/instructor/sections/:sectionId/instructors/:userId
router.delete('/:sectionId/instructors/:userId', instructorOnly, async (req, res) => {
  try {
    const section = await mustOwn(req, res);
    if (!section) return;

    // Removing the owner would leave a section only an admin could manage,
    // which looks identical to a bug. Transfer ownership first.
    if (section.instructor_id === req.params.userId) {
      return res.status(409).json({
        error: 'That is the section owner. Transfer ownership before removing them.',
      });
    }

    const r = await query(
      `DELETE FROM ciab_section_instructor WHERE section_id = $1 AND instructor_id = $2`,
      [section.section_id, req.params.userId]
    );
    if (!r.rowCount) return res.status(404).json({ error: 'That person is not staff on this section' });

    roster.logRosterActivity({
      actorId: req.user.userId, sectionId: section.section_id,
      action: 'staff_removed', detail: { instructor_id: req.params.userId },
    });
    res.json({ success: true });
  } catch (error) {
    console.error('[CIAB] remove section staff:', error.message);
    res.status(500).json({ error: 'Failed to remove staff' });
  }
});

// ---------------------------------------------------------------------------
// Roster
// ---------------------------------------------------------------------------

// GET /api/instructor/sections/:sectionId/students?status=active|dropped|all&q=
router.get('/:sectionId/students', instructorOnly, async (req, res) => {
  try {
    const section = await mustManage(req, res);
    if (!section) return;

    const status = ['active', 'dropped', 'all'].includes(req.query.status) ? req.query.status : 'active';
    const params = [section.section_id];
    let statusClause = '';
    if (status !== 'all') { params.push(status); statusClause = `AND e.status = $${params.length}`; }

    const enrollments = await query(
      `SELECT e.user_id, e.enrollment_role, e.status, e.enrolled_at, e.provisioned_via
         FROM ciab_enrollment e
        WHERE e.section_id = $1 ${statusClause}
        ORDER BY e.enrolled_at DESC`,
      params
    );
    if (!enrollments.rows.length) return res.json({ students: [] });

    const userIds = enrollments.rows.map((r) => r.user_id);

    // role / auth_provider / mfa / provenance are selected so the per-row
    // credential controls are decided SERVER-SIDE. The UI must never infer
    // them, or it would offer buttons the API refuses.
    const users = await cybercoreQuery(
      `SELECT user_id, email, username, first_name, last_name, role,
              auth_provider, mfa_enabled, provisioned_via, provisioned_ref, activated_at
         FROM cybercore_user WHERE user_id = ANY($1::uuid[])`,
      [userIds]
    ).catch(() => ({ rows: [] }));
    const userMap = new Map(users.rows.map((u) => [u.user_id, u]));

    // "Invited but hasn't set a password yet" — otherwise an instructor cannot
    // tell that apart from "the invitation never arrived".
    const pending = await activation.pendingActivationFor(userIds).catch(() => ({}));

    // Progress, so the roster is worth looking at rather than a list of names.
    const progress = await query(
      `SELECT user_id,
              COUNT(*) FILTER (WHERE status = 'submitted')::int AS pending_reviews,
              COUNT(*) FILTER (WHERE status = 'reviewed') ::int AS completed_reviews,
              COUNT(DISTINCT part_number)::int                 AS parts_started
         FROM assessment_progress WHERE user_id = ANY($1::uuid[]) GROUP BY user_id`,
      [userIds]
    ).catch(() => ({ rows: [] }));
    const progressMap = new Map(progress.rows.map((r) => [r.user_id, r]));

    const q = String(req.query.q || '').trim().toLowerCase();

    const students = enrollments.rows.map((e) => {
      const u = userMap.get(e.user_id) || {};
      const p = progressMap.get(e.user_id) || {};
      return {
        user_id: e.user_id,
        email: u.email || 'unknown',
        username: u.username || null,
        first_name: u.first_name || '',
        last_name: u.last_name || '',
        role: u.role || 'student',
        enrollment_role: e.enrollment_role,
        status: e.status,
        enrolled_at: e.enrolled_at,
        provisioned_via: e.provisioned_via,
        elevated: prov.isElevatedAccount(u),
        // The whole reason the columns above are selected.
        can_regenerate: u.user_id ? prov.canManageAccount(u, req.user, section.section_id) : false,
        pending_activation: !!pending[e.user_id],
        pending_reviews: p.pending_reviews || 0,
        completed_reviews: p.completed_reviews || 0,
        parts_started: p.parts_started || 0,
      };
    }).filter((s) => !q
      || s.email.toLowerCase().includes(q)
      || `${s.first_name} ${s.last_name}`.toLowerCase().includes(q)
      || String(s.username || '').toLowerCase().includes(q));

    res.json({ students });
  } catch (error) {
    console.error('[CIAB] read roster:', error.message);
    res.status(500).json({ error: 'Failed to load the roster' });
  }
});

// GET /api/instructor/sections/:sectionId/students/available?q=
// Feeds the Add Student dropdown: accounts that are not already actively
// enrolled here. Mirrors GET /api/cle/students/available/:courseId.
router.get('/:sectionId/students/available', instructorOnly, async (req, res) => {
  try {
    const section = await mustManage(req, res);
    if (!section) return;

    const already = await query(
      `SELECT user_id FROM ciab_enrollment WHERE section_id = $1 AND status = 'active'`,
      [section.section_id]
    );
    const taken = new Set(already.rows.map((r) => r.user_id));

    const q = String(req.query.q || '').trim();
    const params = [];
    let search = '';
    if (q) {
      params.push(`%${q}%`);
      search = `AND (email ILIKE $${params.length} OR username ILIKE $${params.length}
                     OR (COALESCE(first_name,'') || ' ' || COALESCE(last_name,'')) ILIKE $${params.length})`;
    }

    const users = await cybercoreQuery(
      `SELECT user_id, email, username, first_name, last_name, role
         FROM cybercore_user
        WHERE role IN ('student','user') AND active = TRUE ${search}
        ORDER BY last_name NULLS LAST, first_name NULLS LAST, email
        LIMIT 500`,
      params
    );

    res.json({ students: users.rows.filter((u) => !taken.has(u.user_id)) });
  } catch (error) {
    console.error('[CIAB] available students:', error.message);
    res.status(500).json({ error: 'Failed to load available students' });
  }
});

// POST /api/instructor/sections/:sectionId/students   { user_email | user_id }
router.post('/:sectionId/students', instructorOnly, express.json(), async (req, res) => {
  try {
    const section = await mustManage(req, res);
    if (!section) return;

    let userId = req.body.user_id || null;
    let user = null;
    if (!userId) {
      const email = prov.normalizeEmail(String(req.body.user_email || req.body.email || ''));
      if (!email) return res.status(400).json({ error: 'An email address is required' });
      user = await prov.findUserByEmail(email);
      if (!user) {
        // The single-add path deliberately does NOT mint accounts: creating one
        // silently from a typo'd address is worse than saying so. Import Roster
        // is the path that creates, and it previews first.
        return res.status(404).json({
          error: `No account exists for ${email}. Use Import Roster to create accounts, `
               + 'or check the address.',
        });
      }
      userId = user.user_id;
    }

    // Seat cap, if the instructor set one.
    const max = Number(section.max_students) || 0;
    if (max > 0) {
      const used = await roster.seatsUsed(section.section_id);
      const existing = await query(
        `SELECT status FROM ciab_enrollment WHERE section_id = $1 AND user_id = $2`,
        [section.section_id, userId]
      );
      const alreadyActive = existing.rows[0] && existing.rows[0].status === 'active';
      if (!alreadyActive && used + 1 > max) {
        return res.status(409).json({
          error: `This section is full (${used} of ${max} seats). Raise the seat limit in the `
               + 'section settings, or drop someone first.',
        });
      }
    }

    const role = ['student', 'ta', 'guest', 'observer'].includes(req.body.enrollment_role)
      ? req.body.enrollment_role : 'student';
    const row = await roster.enroll(userId, section.section_id, { role });

    // Grants are never stale: without this the student waits out the cache TTL
    // before Clinic-in-a-Box appears for them.
    enrollment.invalidate(userId);

    roster.logRosterActivity({
      actorId: req.user.userId, sectionId: section.section_id,
      action: 'student_enrolled', detail: { user_id: userId, enrollment_role: role },
    });
    res.status(201).json({ success: true, enrollment: row });
  } catch (error) {
    console.error('[CIAB] enroll student:', error.message);
    res.status(500).json({ error: 'Failed to enroll that student' });
  }
});

// DELETE /api/instructor/sections/:sectionId/students/:userId  (soft: dropped)
router.delete('/:sectionId/students/:userId', instructorOnly, async (req, res) => {
  try {
    const section = await mustManage(req, res);
    if (!section) return;

    // Soft, never a DELETE. A dropped student's profiles, submissions and
    // feedback all key off user_id and must survive the drop -- and a
    // mis-click has to be undoable from the same screen.
    const r = await query(
      `UPDATE ciab_enrollment
          SET status = 'dropped', updated_at = NOW()
        WHERE section_id = $1 AND user_id = $2 AND status <> 'dropped'
        RETURNING enrollment_id`,
      [section.section_id, req.params.userId]
    );
    if (!r.rowCount) return res.status(404).json({ error: 'That student is not on this roster' });

    enrollment.invalidate(req.params.userId);
    roster.logRosterActivity({
      actorId: req.user.userId, sectionId: section.section_id,
      action: 'student_dropped', detail: { user_id: req.params.userId },
    });
    res.json({ success: true });
  } catch (error) {
    console.error('[CIAB] drop student:', error.message);
    res.status(500).json({ error: 'Failed to drop that student' });
  }
});

// POST /api/instructor/sections/:sectionId/students/:userId/reinstate
router.post('/:sectionId/students/:userId/reinstate', instructorOnly, async (req, res) => {
  try {
    const section = await mustManage(req, res);
    if (!section) return;

    const r = await query(
      `UPDATE ciab_enrollment
          SET status = 'active', completed_at = NULL, updated_at = NOW()
        WHERE section_id = $1 AND user_id = $2
        RETURNING enrollment_id`,
      [section.section_id, req.params.userId]
    );
    if (!r.rowCount) return res.status(404).json({ error: 'That student is not on this roster' });

    enrollment.invalidate(req.params.userId);
    roster.logRosterActivity({
      actorId: req.user.userId, sectionId: section.section_id,
      action: 'student_reinstated', detail: { user_id: req.params.userId },
    });
    res.json({ success: true });
  } catch (error) {
    console.error('[CIAB] reinstate student:', error.message);
    res.status(500).json({ error: 'Failed to reinstate that student' });
  }
});

module.exports = router;
