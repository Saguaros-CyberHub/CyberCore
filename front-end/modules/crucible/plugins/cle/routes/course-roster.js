/**
 * ============================================================================
 * CLE Plugin — Course Roster Routes
 * ============================================================================
 * Mounted at /api/cle/courses/:courseId/roster
 *
 * Bulk paths for populating a course roster, so an instructor no longer needs
 * an admin to create accounts and then enroll them one at a time:
 *
 *   POST /import   — a CSV roster of real students. Creates accounts that don't
 *                    exist yet (invited by single-use activation link), enrolls
 *                    ones that do.
 *   POST /cohort   — generated lab accounts named off the course code, for when
 *                    students shouldn't need real email addresses at all.
 *
 * Both are preview-then-confirm, mirroring the Group Deploy flow in
 * routes/admin/groups.js: a request without `confirm` changes nothing and
 * returns what WOULD happen, so an instructor sees the seat maths and the
 * problem rows before 200 accounts exist.
 *
 * A separate namespace from course-students.js on purpose — that file owns
 * DELETE /:studentId, and a sibling mount keeps this surface from colliding
 * with future /:studentId verbs.
 */

const express = require('express');
const router = express.Router({ mergeParams: true });

const { requireRole } = require('../../../../../src/middleware/auth');
const { cybercoreQuery } = require('../../../../../src/utils/cybercore-db');
const prov = require('../../../../../src/utils/account-provisioning');
const activation = require('../../../../../src/utils/activation');
const mailer = require('../../../../../src/utils/mailer');
const templates = require('../../../../../src/utils/email-templates');

const { query } = require('../utils/db');
const { getManagedCourse } = require('../utils/course-access');
const roster = require('../utils/roster');

const instructorOnly = requireRole('instructor', 'admin');

const COURSE_COLUMNS = 'course_id, course_name, code, max_students, provision_status, instructor_id';

// Bounds a credential that was handed to a human instead of emailed. Mirrors
// ACTIVATION_TTL_HOURS, which bounds the link that would otherwise have gone
// out — the same exposure, delivered a different way.
const TEMP_PASSWORD_TTL_HOURS = Number(process.env.TEMP_PASSWORD_TTL_HOURS) > 0
  ? Number(process.env.TEMP_PASSWORD_TTL_HOURS) : 72;

// ============================================================================
// HELPERS
// ============================================================================

/**
 * Can an invitation actually reach this address?
 *
 * Every policy reason enqueue() suppresses for is knowable before the account
 * exists: mail disabled, no key to encrypt the body with, or a recipient the
 * policy blocks. Deciding up front is what lets a fallback account be
 * provisioned *correctly* — rotate on first use, bounded lifetime — instead of
 * discovering after the INSERT that nobody could be told.
 */
function canInvite(email) {
  return mailer.mailEnabled() && !!mailer.mailKey() && mailer.checkRecipient(email).ok;
}

/** courseId comes from the parent mount via res.locals (see routes/api.js). */
function courseIdOf(req, res) {
  return req.params.courseId || res.locals.courseId;
}

/**
 * Load the course this caller may manage, or send the 403 and return null.
 * Admins match any course; instructors only their own.
 */
async function loadCourse(req, res) {
  const courseId = courseIdOf(req, res);
  const course = await getManagedCourse(courseId, req.user, COURSE_COLUMNS);
  if (!course) {
    res.status(403).json({ error: 'Course not found or access denied' });
    return null;
  }
  return course;
}

/** Branding + the acting instructor's name, for the emails a run sends. */
async function mailContext(actorId) {
  let siteName = 'CyberHub';
  try {
    const s = await cybercoreQuery(`SELECT value FROM cybercore_site_settings WHERE key = 'site_name'`);
    if (s.rows[0]?.value) siteName = s.rows[0].value;
  } catch { /* branding is cosmetic — never block an import on it */ }

  let instructorName = null;
  try {
    const r = await cybercoreQuery(
      'SELECT first_name, last_name FROM cybercore_user WHERE user_id = $1', [actorId]
    );
    const u = r.rows[0];
    if (u) instructorName = [u.first_name, u.last_name].filter(Boolean).join(' ') || null;
  } catch { /* ditto */ }

  return { siteName, instructorName, publicUrl: mailer.publicUrl() };
}

/**
 * Mint an activation link and queue the invitation for a newly created account.
 *
 * Failure here is deliberately non-fatal. The account already exists and is
 * already enrolled; losing the invitation is recoverable with one click on
 * "Resend", whereas throwing would abandon the rest of the roster mid-run.
 */
async function inviteNewAccount(user, { course, ctx, actorId, importId }) {
  try {
    const { token, expiresAt } = await activation.issueActivationToken(user.user_id, {
      createdBy: actorId,
      context: { course_id: course.course_id, import_id: importId || null },
    });

    const body = templates.activation({
      siteName: ctx.siteName,
      firstName: user.first_name,
      username: user.username,
      activationUrl: activation.activationUrl(token, ctx.publicUrl),
      courseName: course.course_name,
      courseCode: course.code,
      instructorName: ctx.instructorName,
      expiresAt,
    });

    const queued = await mailer.enqueue({
      to: user.email,
      toUserId: user.user_id,
      templateKey: 'activation',
      subject: body.subject,
      text: body.text,
      html: body.html,
      context: { course_id: course.course_id, import_id: importId || null },
      requestedBy: actorId,
    });

    return { status: queued.status, reason: queued.reason || null };
  } catch (err) {
    console.warn(`[CLE] Could not invite ${user.email}:`, err.message);
    return { status: 'suppressed', reason: `invitation could not be prepared: ${err.message}` };
  }
}

/** Queue the "you've been added to X" notice for an account that already existed. */
async function notifyExisting(user, { course, ctx, actorId, importId }) {
  try {
    const body = templates.courseAdded({
      siteName: ctx.siteName,
      publicUrl: ctx.publicUrl,
      firstName: user.first_name,
      courseName: course.course_name,
      courseCode: course.code,
      instructorName: ctx.instructorName,
    });
    const queued = await mailer.enqueue({
      to: user.email,
      toUserId: user.user_id,
      templateKey: 'courseAdded',
      subject: body.subject,
      text: body.text,
      html: body.html,
      context: { course_id: course.course_id, import_id: importId || null },
      requestedBy: actorId,
    });
    return { status: queued.status, reason: queued.reason || null };
  } catch (err) {
    console.warn(`[CLE] Could not notify ${user.email}:`, err.message);
    return { status: 'suppressed', reason: err.message };
  }
}

/**
 * Queue the "a temporary password has been set for you" notice after staff
 * regenerated a credential.
 *
 * Unlike an invitation this really does put a working password in a mailbox,
 * which is why setPassword() pairs it with mustChange and an expiry: the window
 * in which the copy in the mailbox is worth anything closes on first sign-in.
 */
async function notifyCredentials(user, { password, expiresAt, course, ctx, actorId }) {
  try {
    const body = templates.credentialsIssued({
      siteName: ctx.siteName,
      publicUrl: ctx.publicUrl,
      firstName: user.first_name,
      username: user.username,
      password,
      expiresAt,
      courseName: course && course.course_name,
      courseCode: course && course.code,
    });
    const queued = await mailer.enqueue({
      to: user.email,
      toUserId: user.user_id,
      templateKey: 'credentialsIssued',
      subject: body.subject,
      text: body.text,
      html: body.html,
      context: { course_id: course ? course.course_id : null },
      requestedBy: actorId,
    });
    return { status: queued.status, reason: queued.reason || null };
  } catch (err) {
    console.warn(`[CLE] Could not send credentials to ${user.email}:`, err.message);
    return { status: 'suppressed', reason: err.message };
  }
}

// ============================================================================
// POST /import — CSV roster
// ============================================================================

router.post('/import', instructorOnly, async (req, res) => {
  try {
    const course = await loadCourse(req, res);
    if (!course) return;

    const { rows, confirm, notify_existing: notifyExistingFlag = true, enrollment_role } = req.body || {};

    if (!Array.isArray(rows) || rows.length === 0) {
      return res.status(400).json({ error: 'rows must be a non-empty array' });
    }
    if (rows.length > roster.MAX_ROWS) {
      return res.status(400).json({
        error: `A roster is limited to ${roster.MAX_ROWS} rows at a time. Split the file and import it in parts.`,
      });
    }

    const enrollmentRole = ['student', 'ta', 'guest', 'lab_assistant'].includes(enrollment_role)
      ? enrollment_role : 'student';

    const normalized = roster.normalizeRows(rows);
    const classified = await roster.classifyRows(normalized, course.course_id, req.user);
    const used = await roster.seatsUsed(course.course_id);
    const { errors, warnings } = roster.assessRun(classified, course, used);

    const willEnroll = roster.willEnrollCount(classified);
    const willCreate = classified.filter(r => r.action === roster.ACTIONS.CREATE).length;
    const emailsToSend = willCreate +
      (notifyExistingFlag !== false
        ? classified.filter(r => r.action === roster.ACTIONS.ENROLL_EXISTING || r.action === roster.ACTIONS.REACTIVATE).length
        : 0);

    const summary = {
      total: classified.length,
      will_create: willCreate,
      will_enroll_existing: classified.filter(r => r.action === roster.ACTIONS.ENROLL_EXISTING).length,
      will_reactivate: classified.filter(r => r.action === roster.ACTIONS.REACTIVATE).length,
      already_enrolled: classified.filter(r => r.action === roster.ACTIONS.ALREADY_ENROLLED).length,
      duplicates: classified.filter(r => r.action === roster.ACTIONS.SKIP).length,
      invalid: classified.filter(r => r.action === roster.ACTIONS.INVALID).length,
      seats_used: used,
      seats_after: used + willEnroll,
      max_students: course.max_students,
      emails_to_send: emailsToSend,
      email_enabled: mailer.mailEnabled(),
    };

    // ── Dry run ───────────────────────────────────────────────────────────
    if (!confirm) {
      // Two different misconfigurations produce the same outcome for the
      // instructor — no invitation arrives — so both have to say so here. Mail
      // switched on without MAIL_ENCRYPT_KEY is the more dangerous one, because
      // the settings look configured.
      const mailWarning = !mailer.mailEnabled()
        ? 'Email is not configured on this server. Accounts will still be created, and you will be shown temporary passwords to distribute yourself.'
        : !mailer.mailKey()
          ? 'Email is switched on but MAIL_ENCRYPT_KEY is not set, so no invitation can be stored or sent. Accounts will still be created, and you will be shown temporary passwords to distribute yourself.'
          : null;

      return res.json({
        preview: true,
        canProceed: errors.length === 0,
        summary,
        rows: classified,
        errors,
        warnings: mailWarning ? [...warnings, mailWarning] : warnings,
      });
    }

    // Refuse the same conditions that blocked the preview. A client that skips
    // straight to confirm must not get further than one that previewed.
    if (errors.length > 0) {
      return res.status(409).json({ error: errors[0], errors, summary });
    }

    // ── Execute ───────────────────────────────────────────────────────────
    const ctx = await mailContext(req.user.userId);
    const created = [];
    const enrolled = [];
    const failed = [];
    const results = [];
    let emailsQueued = 0;
    let emailsSuppressed = 0;

    const takenUsernames = new Set();

    for (const row of classified) {
      if (row.action === roster.ACTIONS.INVALID || row.action === roster.ACTIONS.SKIP) {
        failed.push({ line: row.line, email: row.email, error: row.reason });
        results.push({ line: row.line, email: row.email, action: row.action, reason: row.reason });
        continue;
      }

      // Per-row isolation: one bad row must never abort a run that has already
      // created accounts. Same shape as POST /api/admin/users/batch.
      try {
        let user;
        let wasCreated = false;
        let generatedPassword = null;

        if (row.action === roster.ACTIONS.CREATE) {
          // An invited account discloses nothing: the activation link is the
          // credential, single-use and expiring, and no password ever leaves
          // the server. When the invitation cannot be delivered the instructor
          // has to hand the credential over in person instead — so it becomes a
          // temporary password, and must therefore rotate on first use and
          // expire on its own rather than living forever.
          const invitable = canInvite(row.email);
          const outcome = await prov.provisionAccount({
            email: row.email,
            firstName: row.first_name,
            lastName: row.last_name,
            role: 'student',
            organization: course.code || course.course_name,
            mustChangePassword: !invitable,
            ...(invitable ? {} : { tempPasswordTtlHours: TEMP_PASSWORD_TTL_HOURS }),
            provenance: { by: req.user.userId, via: 'cle_import', ref: course.course_id },
            takenUsernames,
          });
          user = outcome.user;
          wasCreated = outcome.created;
          generatedPassword = outcome.password;
        } else {
          user = await prov.findUserByEmail(row.email);
          if (!user) throw new Error('account disappeared between preview and confirm');
        }

        if (row.action !== roster.ACTIONS.ALREADY_ENROLLED) {
          await roster.enroll(user.user_id, course.course_id, {
            role: enrollmentRole,
            via: wasCreated ? 'cle_import' : null,
          });
        }

        let mail = null;
        if (wasCreated) {
          mail = await inviteNewAccount(user, { course, ctx, actorId: req.user.userId });
          created.push({
            line: row.line,
            user_id: user.user_id,
            email: user.email,
            username: user.username,
            activation_sent: mail.status === 'queued',
            // Disclosed only when the invitation did not go out, which is what
            // the preview promises the instructor. A credential that reached a
            // mailbox must not also be echoed to the screen — two copies of one
            // secret is strictly worse than one.
            ...(mail.status !== 'queued' && generatedPassword
              ? { temp_password: generatedPassword }
              : {}),
            ...(mail.status !== 'queued' ? { email_note: mail.reason } : {}),
          });
        } else if (row.action !== roster.ACTIONS.ALREADY_ENROLLED && notifyExistingFlag !== false) {
          mail = await notifyExisting(user, { course, ctx, actorId: req.user.userId });
        }

        if (mail) {
          if (mail.status === 'queued') emailsQueued++; else emailsSuppressed++;
        }

        if (!wasCreated) {
          enrolled.push({
            line: row.line,
            user_id: user.user_id,
            email: user.email,
            was_existing: true,
            elevated: !!row.elevated,
            can_regenerate: !!row.can_regenerate,
            already_enrolled: row.action === roster.ACTIONS.ALREADY_ENROLLED,
            ...(mail && mail.status !== 'queued' ? { email_note: mail.reason } : {}),
          });
        }

        results.push({
          line: row.line, email: row.email, action: row.action,
          elevated: !!row.elevated, created: wasCreated,
        });
      } catch (err) {
        failed.push({ line: row.line, email: row.email, error: err.message });
        results.push({ line: row.line, email: row.email, action: 'failed', reason: err.message });
      }
    }

    const finalSummary = {
      total: classified.length,
      created: created.length,
      enrolled: created.length + enrolled.filter(e => !e.already_enrolled).length,
      skipped: classified.filter(r => r.action === roster.ACTIONS.SKIP || r.action === roster.ACTIONS.ALREADY_ENROLLED).length,
      failed: failed.length,
      emails_queued: emailsQueued,
      emails_suppressed: emailsSuppressed,
    };

    const record = await roster.recordImport({
      courseId: course.course_id,
      actorId: req.user.userId,
      source: 'csv',
      notify: notifyExistingFlag !== false,
      summary: finalSummary,
      results,
    });

    // Every row that matched a pre-existing account is logged with the target's
    // role. An instructor systematically importing staff addresses is permitted
    // — and visible.
    roster.logRosterActivity({
      actorId: req.user.userId,
      courseId: course.course_id,
      action: 'roster_import',
      detail: {
        import_id: record.import_id,
        ...finalSummary,
        matched_existing: classified
          .filter(r => r.user_id)
          .map(r => ({ email: r.email, elevated: !!r.elevated })),
      },
    });

    const runWarnings = [];
    if (!mailer.mailEnabled() && created.length > 0) {
      runWarnings.push(
        'Email is not configured on this server, so no invitations were sent. Use "Resend invitation" on each ' +
        'student once mail is configured, or regenerate a password to hand out directly.'
      );
    }
    if (emailsSuppressed > 0) {
      runWarnings.push(`${emailsSuppressed} message${emailsSuppressed === 1 ? ' was' : 's were'} not sent — see the delivery report for the reason.`);
    }

    res.json({
      import_id: record.import_id,
      summary: finalSummary,
      created,
      enrolled,
      failed,
      warnings: runWarnings,
    });
  } catch (error) {
    if (error.status) return res.status(error.status).json({ error: error.message });
    console.error('[CLE] Roster import error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// ============================================================================
// POST /cohort — generated lab accounts
// ============================================================================
//
// The Group Deploy shape, minus the VMs: accounts named off the course code
// (cybr-480-7w1-1-student1…N) with random passwords, for exercises where
// students should not need — or should not use — a real identity.
//
// No email is involved. The addresses are synthetic and hard-suppressed by the
// mailer, and the credentials come back once, here, for the instructor to
// print or hand out.
// ============================================================================

router.post('/cohort', instructorOnly, async (req, res) => {
  try {
    const course = await loadCourse(req, res);
    if (!course) return;

    const {
      count, start_index: startIndexRaw, confirm,
      enrollment_role, require_password_change: requirePasswordChange = false,
    } = req.body || {};

    const n = Number(count);
    if (!Number.isInteger(n) || n < 1) {
      return res.status(400).json({ error: 'count must be a whole number of at least 1' });
    }
    if (n > roster.MAX_ROWS) {
      return res.status(400).json({ error: `Generate at most ${roster.MAX_ROWS} accounts at a time.` });
    }

    const startIndex = Number.isInteger(Number(startIndexRaw)) && Number(startIndexRaw) > 0
      ? Number(startIndexRaw) : 1;

    const enrollmentRole = ['student', 'ta', 'guest', 'lab_assistant'].includes(enrollment_role)
      ? enrollment_role : 'student';

    const plan = await roster.planCohort(course, { count: n, startIndex });
    const used = await roster.seatsUsed(course.course_id);

    // Reuse the same seat assessment the CSV path uses, so both refuse at the
    // same boundary and for the same stated reason.
    const asIfRows = plan.planned.map(() => ({ action: roster.ACTIONS.CREATE }));
    const { errors, warnings } = roster.assessRun(asIfRows, course, used);

    if (!plan.slug) {
      warnings.push('This course has no code, so accounts are named student1, student2, … Set a course code for names like cybr-480-7w1-1-student1.');
    }
    if (plan.skipped.length > 0) {
      warnings.push(`${plan.skipped.length} name${plan.skipped.length === 1 ? '' : 's'} in this range already exist and were skipped; generation continues from the next free number.`);
    }

    const summary = {
      count: plan.planned.length,
      start_index: plan.planned[0]?.index ?? startIndex,
      end_index: plan.planned[plan.planned.length - 1]?.index ?? startIndex,
      skipped_existing: plan.skipped.length,
      seats_used: used,
      seats_after: used + plan.planned.length,
      max_students: course.max_students,
    };

    // ── Dry run ───────────────────────────────────────────────────────────
    if (!confirm) {
      return res.json({
        preview: true,
        canProceed: errors.length === 0 && plan.planned.length > 0,
        summary,
        sample_usernames: plan.planned.slice(0, 5).map(p => p.username),
        collisions: plan.skipped.slice(0, 10),
        errors,
        warnings,
      });
    }

    if (errors.length > 0) {
      return res.status(409).json({ error: errors[0], errors, summary });
    }

    // ── Execute ───────────────────────────────────────────────────────────
    const credentials = [];
    const failed = [];
    const results = [];
    const takenUsernames = new Set();

    for (const slot of plan.planned) {
      try {
        const outcome = await prov.provisionAccount({
          email: slot.email,
          username: slot.username,
          firstName: 'Student',
          lastName: String(slot.index),
          role: 'student',
          organization: course.code || course.course_name,
          // Default FALSE: these are disposable lab identities handed out on a
          // printed sheet. Forcing a change would strand the instructor's copy
          // the first time a student signed in. The checkbox exposes the other
          // behaviour for anyone who wants it.
          mustChangePassword: requirePasswordChange === true,
          emailVerified: false,
          provenance: { by: req.user.userId, via: 'cle_cohort', ref: course.course_id },
          takenUsernames,
        });

        if (!outcome.created) {
          failed.push({ username: slot.username, error: 'an account with this name already exists' });
          results.push({ index: slot.index, username: slot.username, action: 'skip', reason: 'already exists' });
          continue;
        }

        await roster.enroll(outcome.user.user_id, course.course_id, {
          role: enrollmentRole,
          via: 'cle_cohort',
        });

        credentials.push({
          user_id: outcome.user.user_id,
          username: outcome.username,
          email: outcome.user.email,
          password: outcome.password,
          role: 'student',
        });
        results.push({ index: slot.index, username: slot.username, action: 'create', created: true });
      } catch (err) {
        failed.push({ username: slot.username, error: err.message });
        results.push({ index: slot.index, username: slot.username, action: 'failed', reason: err.message });
      }
    }

    const finalSummary = {
      total: plan.planned.length,
      created: credentials.length,
      enrolled: credentials.length,
      skipped: plan.skipped.length,
      failed: failed.length,
    };

    const record = await roster.recordImport({
      courseId: course.course_id,
      actorId: req.user.userId,
      source: 'cohort',
      notify: false,
      summary: finalSummary,
      // No passwords in the audit record — it exists to explain a run.
      results,
    });

    roster.logRosterActivity({
      actorId: req.user.userId,
      courseId: course.course_id,
      action: 'cohort_generate',
      detail: { import_id: record.import_id, ...finalSummary, slug: plan.slug },
    });

    res.json({
      import_id: record.import_id,
      summary: finalSummary,
      // Returned exactly once. Nothing stores the plaintext, so a lost sheet
      // means regenerating, not looking it up.
      credentials,
      failed,
      warnings: [
        'These passwords are shown once and cannot be retrieved later. Save or print them now.',
        ...(requirePasswordChange === true
          ? ['Students will be asked to choose their own password the first time they sign in, so this list stops working after that.']
          : []),
      ],
    });
  } catch (error) {
    if (error.status) return res.status(error.status).json({ error: error.message });
    console.error('[CLE] Cohort generation error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// ============================================================================
// PER-STUDENT CREDENTIAL ACTIONS
// ----------------------------------------------------------------------------
// The dangerous surface, and the reason provenance exists.
//
// Enrolling anyone in a course is allowed — staff sit in on courses, and an
// enrolled admin is harmless. Exercising ACCOUNT-level power over them is not.
// "Manages the course AND the target is enrolled" is explicitly NOT sufficient
// authority here: an instructor can enroll any address in their own course, so
// that pair is a two-step path from instructor to admin. The threat is already
// documented at src/utils/guac-credentials.js:333-343.
//
// Every route below therefore calls assertCourseProvisionedStudent(), which
// requires ALL of:
//   • the target is student-tier          (reuses assertDisclosable — G1)
//   • the account is local, not federated (G6)
//   • the account has no MFA enabled      (G6)
//   • the account was minted BY THIS COURSE (provisioned_via + ref — G5)
// Admins bypass the provenance requirement; they already have
// POST /api/admin/users/:id/password.
// ============================================================================

/**
 * Load the target and check both course membership and account authority.
 * Sends the error response and returns null when either fails.
 */
async function loadManageableStudent(req, res, course) {
  const { studentId } = req.params;

  // Course membership first, so a student in someone else's course reads as
  // "not in this course" rather than leaking anything about the account.
  const enrolled = await query(
    `SELECT user_id, status FROM cle_course_enrollment
      WHERE user_id = $1 AND course_id = $2`,
    [studentId, course.course_id]
  );
  if (enrolled.rows.length === 0) {
    res.status(404).json({ error: 'That student is not enrolled in this course.' });
    return null;
  }

  const target = await prov.findUserById(studentId);
  if (!target) {
    res.status(404).json({ error: 'User not found' });
    return null;
  }

  try {
    prov.assertCourseProvisionedStudent(target, req.user, course.course_id);
  } catch (err) {
    res.status(err.status || 403).json({ error: err.message });
    return null;
  }

  return target;
}

// The warning is reused verbatim from admin/settings.js:874 because it
// describes the same true limitation: sessions are stateless JWTs and
// middleware/auth.js never re-reads the row, so a reset ends nothing that is
// already signed in.
const SESSION_SURVIVAL_WARNING =
  'Sessions already signed in are not ended by this reset — their existing login stays valid until it expires (7 days by default).';

/**
 * POST /students/:studentId/password
 * Generate a new password for an account this course created.
 */
router.post('/students/:studentId/password', instructorOnly, async (req, res) => {
  try {
    const course = await loadCourse(req, res);
    if (!course) return;

    const target = await loadManageableStudent(req, res, course);
    if (!target) return;

    // Always server-generated. Letting a caller choose the password would make
    // this a way to set a known credential on someone else's account, which is
    // a materially different (and worse) capability than "issue a new random one".
    //
    // Bounded as well as rotate-on-first-use: this credential gets read aloud,
    // written down, or left sitting in a mailbox, and an unbounded one stays
    // valid for the rest of the term if the student simply never signs in.
    const { password, expires_at: expiresAt } = await prov.setPassword(target.user_id, {
      mustChange: true,
      ttlHours: TEMP_PASSWORD_TTL_HOURS,
      actorId: req.user.userId,
    });

    // An outstanding invitation would be a second, unrelated way in that the
    // instructor does not know about.
    await activation.revokeActivationTokens(target.user_id, 'activate').catch(() => {});

    // Mail the student their own copy unless the caller opts out. The password
    // is still returned either way: the instructor asked for a credential to
    // hand over, and a student whose mail bounces still needs one. Which of the
    // two actually happened is reported rather than assumed.
    let mail = null;
    if (req.body?.notify !== false && canInvite(target.email)) {
      const ctx = await mailContext(req.user.userId);
      mail = await notifyCredentials(target, {
        password, expiresAt, course, ctx, actorId: req.user.userId,
      });
    }

    roster.logRosterActivity({
      actorId: req.user.userId,
      courseId: course.course_id,
      action: 'password_regenerate',
      detail: {
        target_user_id: target.user_id,
        target_email: target.email,
        target_role: target.role,
        emailed: mail ? mail.status === 'queued' : false,
      },
    });

    res.json({
      user_id: target.user_id,
      username: target.username,
      email: target.email,
      // Returned once, in this response only. Nothing stores the plaintext.
      password,
      expires_at: expiresAt,
      emailed: mail ? mail.status === 'queued' : false,
      ...(mail && mail.status !== 'queued' ? { email_note: mail.reason } : {}),
      warnings: [SESSION_SURVIVAL_WARNING],
    });
  } catch (error) {
    if (error.status) return res.status(error.status).json({ error: error.message });
    console.error('[CLE] Password regenerate error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

/**
 * POST /students/:studentId/activation/resend
 * Issue a fresh invitation link, invalidating any previous one.
 */
router.post('/students/:studentId/activation/resend', instructorOnly, async (req, res) => {
  try {
    const course = await loadCourse(req, res);
    if (!course) return;

    const target = await loadManageableStudent(req, res, course);
    if (!target) return;

    if (!mailer.mailEnabled()) {
      return res.status(409).json({
        error: 'Email is not configured on this server, so an invitation cannot be sent. Use "Regenerate password" to hand out a credential directly.',
      });
    }

    const recipient = mailer.checkRecipient(target.email);
    if (!recipient.ok) {
      return res.status(409).json({
        error: `Cannot email ${target.email}: ${recipient.reason}.`,
      });
    }

    const ctx = await mailContext(req.user.userId);
    // issueActivationToken revokes any outstanding invitation first, so the
    // older link in the older email stops working. Otherwise "resend" would
    // widen the window rather than replace it.
    const result = await inviteNewAccount(target, { course, ctx, actorId: req.user.userId });

    roster.logRosterActivity({
      actorId: req.user.userId,
      courseId: course.course_id,
      action: 'activation_resend',
      detail: { target_user_id: target.user_id, target_email: target.email, status: result.status },
    });

    if (result.status !== 'queued') {
      return res.status(502).json({ error: result.reason || 'The invitation could not be queued.' });
    }

    res.json({
      user_id: target.user_id,
      email: target.email,
      sent: true,
      note: 'A new invitation is queued. Any earlier link for this account has been invalidated.',
    });
  } catch (error) {
    if (error.status) return res.status(error.status).json({ error: error.message });
    console.error('[CLE] Activation resend error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// ============================================================================
// READS
// ============================================================================

// GET /imports — recent runs for this course. Never returns secrets.
router.get('/imports', instructorOnly, async (req, res) => {
  try {
    const course = await loadCourse(req, res);
    if (!course) return;

    const r = await query(
      `SELECT import_id, actor_id, source, total_rows, created_count, enrolled_count,
              skipped_count, failed_count, notify, created_at
         FROM cle_roster_import
        WHERE course_id = $1
        ORDER BY created_at DESC
        LIMIT 25`,
      [course.course_id]
    );
    res.json({ imports: r.rows });
  } catch (error) {
    console.error('[CLE] List imports error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

/**
 * GET /email-status?import_id=… — per-recipient delivery state.
 *
 * Exists so "did my students actually get the invitation?" has an answer that
 * isn't a guess. Returns status and error, never a message body — those hold
 * activation links.
 */
router.get('/email-status', instructorOnly, async (req, res) => {
  try {
    const course = await loadCourse(req, res);
    if (!course) return;

    const importId = String(req.query.import_id || '').trim();
    if (!importId) return res.status(400).json({ error: 'import_id is required' });

    // Confirm the run belongs to THIS course before reporting on it — the
    // outbox is a shared table and import_id alone is not authority.
    const owned = await query(
      'SELECT import_id FROM cle_roster_import WHERE import_id = $1 AND course_id = $2',
      [importId, course.course_id]
    );
    if (owned.rows.length === 0) {
      return res.status(404).json({ error: 'Import not found for this course' });
    }

    const messages = await mailer.statusForImport(importId);
    res.json({
      import_id: importId,
      email_enabled: mailer.mailEnabled(),
      messages,
    });
  } catch (error) {
    console.error('[CLE] Email status error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
