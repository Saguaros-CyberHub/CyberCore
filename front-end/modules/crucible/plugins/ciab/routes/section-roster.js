/**
 * ============================================================================
 * CIAB Plugin — Section roster: bulk paths and credentials
 * ============================================================================
 * Mounted at /api/instructor/sections/:sectionId/roster
 *
 *   POST /import   — a CSV roster of real students. Creates accounts that do
 *                    not exist yet (invited by single-use activation link),
 *                    enrolls ones that do.
 *   POST /cohort   — generated lab accounts named off the section code, for
 *                    when students need no real email address at all.
 *   POST /import-from-cle — convenience: pull a roster straight out of a CLE
 *                    course this caller already manages.
 *
 * All of them are PREVIEW-THEN-CONFIRM. A request without `confirm` changes
 * nothing and returns what WOULD happen, so an instructor sees the seat maths
 * and the problem rows before 200 accounts exist. `confirm: true` re-runs the
 * same checks and 409s on the same errors, so a client that skips the preview
 * gets no further than one that did not.
 *
 * A sibling mount to sections.js on purpose: that file owns
 * DELETE /:sectionId/students/:userId, and keeping this surface separate stops
 * it colliding with future /:userId verbs -- the reason cle/routes/api.js:41-47
 * gives for the same split.
 */

const crypto = require('node:crypto');
const express = require('express');
const router = express.Router({ mergeParams: true });

const { requireRole } = require('../../../../../src/middleware/auth');
const { cybercoreQuery } = require('../../../../../src/utils/cybercore-db');
const prov = require('../../../../../src/utils/account-provisioning');
const activation = require('../../../../../src/utils/activation');
const mailer = require('../../../../../src/utils/mailer');
const templates = require('../../../../../src/utils/email-templates');
const { generatePassword } = require('../../../../../src/utils/password-generator');

const { query } = require('../utils/db');
const enrollment = require('../utils/enrollment');
const roster = require('../utils/section-roster');

const instructorOnly = requireRole('instructor', 'admin');

const SECTION_COLUMNS = 'section_id, name, code, term, max_students, status, instructor_id';

// Bounds a credential handed to a human instead of emailed. Mirrors
// ACTIVATION_TTL_HOURS, which bounds the link that would otherwise have gone
// out -- the same exposure, delivered a different way.
const TEMP_PASSWORD_TTL_HOURS = Number(process.env.TEMP_PASSWORD_TTL_HOURS) > 0
  ? Number(process.env.TEMP_PASSWORD_TTL_HOURS) : 72;

/**
 * Can an invitation actually reach this address?
 *
 * Every policy reason enqueue() suppresses for is knowable before the account
 * exists: mail disabled, no key to encrypt the body with, or a recipient the
 * policy blocks. Deciding up front is what lets a fallback account be
 * provisioned CORRECTLY -- rotate on first use, bounded lifetime -- instead of
 * discovering after the INSERT that nobody could be told.
 */
function canInvite(email) {
  return mailer.mailEnabled() && !!mailer.mailKey() && mailer.checkRecipient(email).ok;
}

/** :sectionId arrives via the parent mount's res.locals (see routes/api.js). */
const sectionIdOf = (req, res) => req.params.sectionId || res.locals.sectionId;

/** Load the section this caller may manage, or send the 403 and return null. */
async function loadSection(req, res) {
  const section = await enrollment.getManagedSection(sectionIdOf(req, res), req.user, SECTION_COLUMNS);
  if (!section) {
    res.status(403).json({ error: 'Section not found or access denied' });
    return null;
  }
  return section;
}

/** Branding plus the acting instructor's name, for the emails a run sends. */
async function mailContext(actorId) {
  let siteName = 'CyberHub';
  try {
    const s = await cybercoreQuery(`SELECT value FROM cybercore_site_settings WHERE key = 'site_name'`);
    if (s.rows[0] && s.rows[0].value) siteName = s.rows[0].value;
  } catch (_) { /* branding is cosmetic — never block an import on it */ }

  let instructorName = null;
  try {
    const r = await cybercoreQuery(
      'SELECT first_name, last_name FROM cybercore_user WHERE user_id = $1', [actorId]
    );
    const u = r.rows[0];
    if (u) instructorName = [u.first_name, u.last_name].filter(Boolean).join(' ') || null;
  } catch (_) { /* ditto */ }

  return { siteName, instructorName, publicUrl: mailer.publicUrl() };
}

/**
 * Mint an activation link and queue the invitation for a newly created account.
 *
 * Failure here is deliberately NON-FATAL. The account already exists and is
 * already enrolled; losing the invitation is recoverable with one click on
 * "Resend", whereas throwing would abandon the rest of the roster mid-run.
 */
async function inviteNewAccount(user, { section, ctx, actorId, importId }) {
  try {
    const { token, expiresAt } = await activation.issueActivationToken(user.user_id, {
      createdBy: actorId,
      context: { ciab_section_id: section.section_id, import_id: importId || null },
    });

    const body = templates.activation({
      siteName: ctx.siteName,
      firstName: user.first_name,
      username: user.username,
      activationUrl: activation.activationUrl(token, ctx.publicUrl),
      // The templates speak in terms of a course; a section IS the course from
      // the student's point of view, so this reads correctly without a second
      // set of templates to keep in sync.
      courseName: section.name,
      courseCode: section.code,
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
      context: { ciab_section_id: section.section_id, import_id: importId || null },
      requestedBy: actorId,
    });

    return { status: queued.status, reason: queued.reason || null };
  } catch (err) {
    console.warn(`[CIAB] Could not invite ${user.email}:`, err.message);
    return { status: 'suppressed', reason: `invitation could not be prepared: ${err.message}` };
  }
}

/**
 * Mint a reset link for an account that already exists.
 *
 * Split from inviteNewAccount rather than parameterised, deliberately:
 * issueActivationToken revokes per PURPOSE, so a reset must carry purpose
 * 'reset' or it would silently cancel an outstanding invitation -- and with it
 * the roster's "invited" badge, which pendingActivationFor computes from live
 * 'activate' tokens only.
 */
async function sendPasswordResetLink(user, { section, ctx, actorId }) {
  try {
    const { token, expiresAt } = await activation.issueActivationToken(user.user_id, {
      purpose: 'reset',
      createdBy: actorId,
      context: { ciab_section_id: section.section_id, reason: 'instructor_reset' },
    });

    const body = templates.passwordReset({
      siteName: ctx.siteName,
      firstName: user.first_name,
      username: user.username,
      resetUrl: activation.activationUrl(token, ctx.publicUrl, 'reset'),
      courseName: section.name,
      courseCode: section.code,
      instructorName: ctx.instructorName,
      expiresAt,
    });

    const queued = await mailer.enqueue({
      to: user.email,
      toUserId: user.user_id,
      templateKey: 'passwordReset',
      subject: body.subject,
      text: body.text,
      html: body.html,
      context: { ciab_section_id: section.section_id },
      requestedBy: actorId,
    });

    return { status: queued.status, reason: queued.reason || null, expiresAt };
  } catch (err) {
    console.warn(`[CIAB] Could not queue a reset link for ${user.email}:`, err.message);
    return { status: 'suppressed', reason: `the reset link could not be prepared: ${err.message}`, expiresAt: null };
  }
}

/** Queue the "you've been added to X" notice for an account that already existed. */
async function notifyExisting(user, { section, ctx, actorId, importId }) {
  try {
    const body = templates.courseAdded({
      siteName: ctx.siteName,
      publicUrl: ctx.publicUrl,
      firstName: user.first_name,
      courseName: section.name,
      courseCode: section.code,
      instructorName: ctx.instructorName,
    });
    const queued = await mailer.enqueue({
      to: user.email,
      toUserId: user.user_id,
      templateKey: 'courseAdded',
      subject: body.subject,
      text: body.text,
      html: body.html,
      context: { ciab_section_id: section.section_id, import_id: importId || null },
      requestedBy: actorId,
    });
    return { status: queued.status, reason: queued.reason || null };
  } catch (err) {
    console.warn(`[CIAB] Could not notify ${user.email}:`, err.message);
    return { status: 'suppressed', reason: err.message };
  }
}

// ============================================================================
// POST /import — CSV roster
// ============================================================================

/**
 * The whole CSV pipeline, as a function rather than only a route handler.
 *
 * /import-from-cle needs the identical behaviour over rows it fetched itself --
 * same preview/confirm contract, same seat assessment, same per-row isolation.
 * Calling this is the honest way to get that; re-dispatching through
 * router.handle() with a rewritten req.url would depend on Express's internal
 * matching state and on a body express.json() has already consumed.
 */
async function runImport(req, res, section, body, source = 'csv') {
  try {
    const { rows, confirm, notify_existing: notifyExistingFlag = true, enrollment_role } = body || {};

    if (!Array.isArray(rows) || rows.length === 0) {
      return res.status(400).json({ error: 'rows must be a non-empty array' });
    }
    if (rows.length > roster.MAX_ROWS) {
      return res.status(400).json({
        error: `A roster is limited to ${roster.MAX_ROWS} rows at a time. `
             + 'Split the file and import it in parts.',
      });
    }

    const enrollmentRole = ['student', 'ta', 'guest', 'observer'].includes(enrollment_role)
      ? enrollment_role : 'student';

    const normalized = roster.normalizeRows(rows);
    const classified = await roster.classifyRows(normalized, section.section_id, req.user);
    const used = await roster.seatsUsed(section.section_id);
    const { errors, warnings } = roster.assessRun(classified, section, used);

    const willEnroll = roster.willEnrollCount(classified);
    const willCreate = classified.filter((r) => r.action === roster.ACTIONS.CREATE).length;
    const emailsToSend = willCreate + (notifyExistingFlag !== false
      ? classified.filter((r) => r.action === roster.ACTIONS.ENROLL_EXISTING
                              || r.action === roster.ACTIONS.REACTIVATE).length
      : 0);

    const summary = {
      total: classified.length,
      will_create: willCreate,
      will_enroll_existing: classified.filter((r) => r.action === roster.ACTIONS.ENROLL_EXISTING).length,
      will_reactivate: classified.filter((r) => r.action === roster.ACTIONS.REACTIVATE).length,
      already_enrolled: classified.filter((r) => r.action === roster.ACTIONS.ALREADY_ENROLLED).length,
      // Existing accounts missing a name this file can supply. Shown so
      // re-importing to repair a bad earlier import visibly does work rather
      // than looking like a no-op.
      will_fill_names: classified.filter((r) => r.name_backfill).length,
      duplicates: classified.filter((r) => r.action === roster.ACTIONS.SKIP).length,
      invalid: classified.filter((r) => r.action === roster.ACTIONS.INVALID).length,
      seats_used: used,
      seats_after: used + willEnroll,
      max_students: section.max_students,
      emails_to_send: emailsToSend,
      email_enabled: mailer.mailEnabled(),
    };

    // ---- Dry run -----------------------------------------------------------
    if (!confirm) {
      // Two different misconfigurations produce the same outcome for the
      // instructor -- no invitation arrives -- so both have to say so here.
      // Mail switched on without MAIL_ENCRYPT_KEY is the more dangerous one,
      // because the settings look configured.
      const mailWarning = !mailer.mailEnabled()
        ? 'Email is not configured on this server. Accounts will still be created, and you '
          + 'will be shown temporary passwords to distribute yourself.'
        : !mailer.mailKey()
          ? 'Email is switched on but MAIL_ENCRYPT_KEY is not set, so no invitation can be '
            + 'stored or sent. Accounts will still be created, and you will be shown '
            + 'temporary passwords to distribute yourself.'
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

    // ---- Execute -----------------------------------------------------------
    // Minted BEFORE the loop, not after. Every invitation queued below carries
    // it in the outbox row's context, and mailer.statusForImport() looks runs
    // up by exactly that -- so generating it afterwards would leave
    // GET /email-status permanently empty for the runs that actually sent mail.
    const importId = crypto.randomUUID();
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

      // PER-ROW ISOLATION. One bad row must never abort a run that has already
      // created accounts -- the instructor would be left with a half-made
      // roster and no record of which half.
      try {
        let user;
        let wasCreated = false;
        let generatedPassword = null;

        if (row.action === roster.ACTIONS.CREATE) {
          // An invited account discloses nothing: the activation link IS the
          // credential, single-use and expiring, and no password ever leaves
          // the server. When the invitation cannot be delivered the instructor
          // has to hand the credential over in person instead -- so it becomes
          // a temporary password, and must therefore rotate on first use and
          // expire on its own rather than living forever.
          const invitable = canInvite(row.email);
          const outcome = await prov.provisionAccount({
            email: row.email,
            firstName: row.first_name,
            lastName: row.last_name,
            role: 'student',
            organization: section.code || section.name,
            mustChangePassword: !invitable,
            ...(invitable ? {} : { tempPasswordTtlHours: TEMP_PASSWORD_TTL_HOURS }),
            // provisioned_ref = section_id is what later grants this section's
            // instructor credential control over exactly these accounts, via
            // checkCourseProvisionedStudent(). No extra authorization code.
            provenance: { by: req.user.userId, via: 'ciab_import', ref: section.section_id },
            takenUsernames,
          });
          user = outcome.user;
          wasCreated = outcome.created;
          generatedPassword = outcome.password;
        } else {
          user = await prov.findUserByEmail(row.email);
          if (!user) throw new Error('account disappeared between preview and confirm');
          // Only touches blank columns -- see backfillMissingName. This is the
          // one thing an enroll-existing row may change about the account.
          if (row.name_backfill) {
            await prov.backfillMissingName(user.user_id, {
              firstName: row.first_name,
              lastName: row.last_name,
            }).catch(() => false);
          }
        }

        if (row.action !== roster.ACTIONS.ALREADY_ENROLLED) {
          await roster.enroll(user.user_id, section.section_id, {
            role: enrollmentRole,
            via: wasCreated ? 'ciab_import' : null,
          });
        }

        let mail = null;
        if (wasCreated) {
          mail = await inviteNewAccount(user, { section, ctx, actorId: req.user.userId, importId });
          created.push({
            line: row.line,
            user_id: user.user_id,
            email: user.email,
            username: user.username,
            activation_sent: mail.status === 'queued',
            // Disclosed ONLY when the invitation did not go out, which is what
            // the preview promises. A credential that reached a mailbox must
            // not also be echoed to the screen -- two copies of one secret is
            // strictly worse than one.
            ...(mail.status !== 'queued' && generatedPassword ? { temp_password: generatedPassword } : {}),
            ...(mail.status !== 'queued' ? { email_note: mail.reason } : {}),
          });
        } else if (row.action !== roster.ACTIONS.ALREADY_ENROLLED && notifyExistingFlag !== false) {
          mail = await notifyExisting(user, { section, ctx, actorId: req.user.userId, importId });
        }

        if (mail) { if (mail.status === 'queued') emailsQueued++; else emailsSuppressed++; }

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
      enrolled: created.length + enrolled.filter((e) => !e.already_enrolled).length,
      skipped: classified.filter((r) => r.action === roster.ACTIONS.SKIP
                                     || r.action === roster.ACTIONS.ALREADY_ENROLLED).length,
      failed: failed.length,
      emails_queued: emailsQueued,
      emails_suppressed: emailsSuppressed,
    };

    const record = await roster.recordImport({
      sectionId: section.section_id,
      actorId: req.user.userId,
      // 'csv' or 'cle_course' — the ciab_roster_import CHECK allows both, and
      // filing a CLE pull as a CSV upload would misreport where it came from.
      source,
      notify: notifyExistingFlag !== false,
      summary: finalSummary,
      results,
      importId,
    });

    // Once, at the end, not once per row: a 200-row import would otherwise do
    // 200 cache deletes for no benefit.
    enrollment.invalidateAll();

    roster.logRosterActivity({
      actorId: req.user.userId, sectionId: section.section_id,
      action: 'import', detail: { import_id: record.import_id, source, ...finalSummary },
    });

    res.json({ import_id: record.import_id, summary: finalSummary, created, enrolled, failed, warnings });
  } catch (error) {
    console.error('[CIAB] roster import:', error.message);
    res.status(500).json({ error: 'The import could not be completed', details: error.message });
  }
}

// express.json() here is belt-and-braces, not the size control it looks like:
// server.js:335-339 already parses every /api/ body at 10mb before this router
// sees it, and a second express.json() returns immediately once req._body is
// set. It stays so the router still works mounted standalone (which is how the
// tests drive it). The real cap on an import is roster.MAX_ROWS, in rows.
router.post('/import', instructorOnly, express.json(), async (req, res) => {
  const section = await loadSection(req, res);
  if (!section) return;
  return runImport(req, res, section, req.body || {});
});

// ============================================================================
// POST /cohort — generated lab accounts
// ============================================================================

router.post('/cohort', instructorOnly, express.json(), async (req, res) => {
  try {
    const section = await loadSection(req, res);
    if (!section) return;

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
    const enrollmentRole = ['student', 'ta', 'guest', 'observer'].includes(enrollment_role)
      ? enrollment_role : 'student';

    const plan = await roster.planCohort(section, { count: n, startIndex });
    const used = await roster.seatsUsed(section.section_id);

    // Reuse the same seat assessment the CSV path uses, so both refuse at the
    // same boundary and for the same stated reason.
    const asIfRows = plan.planned.map(() => ({ action: roster.ACTIONS.CREATE }));
    const { errors, warnings } = roster.assessRun(asIfRows, section, used);

    if (!plan.slug) {
      warnings.push('This section has no code, so accounts are named student1, student2, … '
        + 'Set a section code for names like cybr-480-7w1-student1.');
    }
    if (plan.skipped.length > 0) {
      warnings.push(`${plan.skipped.length} name${plan.skipped.length === 1 ? '' : 's'} in this `
        + 'range already exist and were skipped; generation continues from the next free number.');
    }

    const first = plan.planned[0];
    const last = plan.planned[plan.planned.length - 1];
    const summary = {
      count: plan.planned.length,
      start_index: first ? first.index : startIndex,
      end_index: last ? last.index : startIndex,
      skipped_existing: plan.skipped.length,
      seats_used: used,
      seats_after: used + plan.planned.length,
      max_students: section.max_students,
    };

    // ---- Dry run -----------------------------------------------------------
    if (!confirm) {
      return res.json({
        preview: true,
        canProceed: errors.length === 0 && plan.planned.length > 0,
        summary,
        sample_usernames: plan.planned.slice(0, 5).map((p) => p.username),
        collisions: plan.skipped.slice(0, 10),
        errors,
        warnings,
      });
    }

    if (errors.length > 0) {
      return res.status(409).json({ error: errors[0], errors, summary });
    }

    // ---- Execute -----------------------------------------------------------
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
          organization: section.code || section.name,
          // Default FALSE: these are disposable lab identities handed out on a
          // printed sheet. Forcing a change would strand the instructor's copy
          // the first time a student signed in. The checkbox exposes the other
          // behaviour for anyone who wants it.
          mustChangePassword: requirePasswordChange === true,
          emailVerified: false,
          provenance: { by: req.user.userId, via: 'ciab_cohort', ref: section.section_id },
          takenUsernames,
        });

        if (!outcome.created) {
          failed.push({ username: slot.username, error: 'an account with this name already exists' });
          results.push({ index: slot.index, username: slot.username, action: 'skip', reason: 'already exists' });
          continue;
        }

        await roster.enroll(outcome.user.user_id, section.section_id, {
          role: enrollmentRole,
          via: 'ciab_cohort',
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
      sectionId: section.section_id,
      actorId: req.user.userId,
      source: 'cohort',
      notify: false,
      // No passwords in the audit record -- it exists to explain a run.
      summary: finalSummary,
      results,
    });

    enrollment.invalidateAll();

    roster.logRosterActivity({
      actorId: req.user.userId, sectionId: section.section_id,
      action: 'cohort_generate', detail: { import_id: record.import_id, ...finalSummary, slug: plan.slug },
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
          ? ['Students will be asked to choose their own password the first time they sign in, '
             + 'so this list stops working after that.']
          : []),
      ],
    });
  } catch (error) {
    if (error.status) return res.status(error.status).json({ error: error.message });
    console.error('[CIAB] cohort generation:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// ============================================================================
// PER-STUDENT CREDENTIAL ACTIONS
// ----------------------------------------------------------------------------
// The dangerous surface, and the reason provenance exists. Enrolling anybody is
// fine; taking control of their credential is not. assertCourseProvisionedStudent
// re-derives the answer from cybercore_user every time -- never from the roster,
// which these same routes write.
// ============================================================================

/** The target, or null after sending the refusal. */
async function loadManageableStudent(req, res, section) {
  const target = await prov.findUserById(req.params.userId);
  if (!target) {
    res.status(404).json({ error: 'User not found' });
    return null;
  }

  const onRoster = await query(
    `SELECT 1 FROM ciab_enrollment WHERE section_id = $1 AND user_id = $2 LIMIT 1`,
    [section.section_id, target.user_id]
  );
  if (!onRoster.rowCount) {
    res.status(404).json({ error: 'That student is not on this section roster' });
    return null;
  }

  try {
    // source: 'ciab' so a denial is filed against the right subsystem in the
    // audit log rather than showing up as a CLE event.
    prov.assertCourseProvisionedStudent(target, req.user, section.section_id, { source: 'ciab' });
  } catch (err) {
    res.status(err.status || 403).json({ error: err.message });
    return null;
  }
  return target;
}

// POST /students/:userId/password — email a reset link
router.post('/students/:userId/password', instructorOnly, async (req, res) => {
  try {
    const section = await loadSection(req, res);
    if (!section) return;
    const target = await loadManageableStudent(req, res, section);
    if (!target) return;

    if (!mailer.mailEnabled() || !mailer.mailKey()) {
      return res.status(409).json({
        error: 'Email is not configured on this server, so a password-reset link cannot be sent. '
             + 'An administrator can set a password directly from Admin → Users.',
      });
    }

    const recipient = mailer.checkRecipient(target.email);
    if (!recipient.ok) {
      // Names the remaining path explicitly. This is the COHORT case: those
      // accounts carry @cohort.invalid addresses precisely so no mail is ever
      // attempted for them, so the instructor has nothing self-serve here and
      // should not be left to guess that.
      return res.status(409).json({
        error: `Cannot email ${target.email}: ${recipient.reason}. This account has no reachable `
             + 'address, so it cannot receive a reset link — an administrator can set a password '
             + 'for it directly from Admin → Users.',
      });
    }

    const ctx = await mailContext(req.user.userId);
    const result = await sendPasswordResetLink(target, { section, ctx, actorId: req.user.userId });

    roster.logRosterActivity({
      actorId: req.user.userId, sectionId: section.section_id, action: 'password_reset_link',
      detail: { target_user_id: target.user_id, target_email: target.email, status: result.status },
    });

    if (result.status !== 'queued') {
      return res.status(502).json({ error: result.reason || 'The reset link could not be queued.' });
    }

    res.json({
      user_id: target.user_id,
      username: target.username,
      email: target.email,
      sent: true,
      expires_at: result.expiresAt,
      note: `A password-reset link is on its way to ${target.email}. Their current password keeps `
          + 'working until they use it. Any earlier reset link for this account has been invalidated.',
    });
  } catch (error) {
    if (error.status) return res.status(error.status).json({ error: error.message });
    console.error('[CIAB] password reset link:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// POST /students/:userId/activation/resend — a fresh invitation, revoking the old
router.post('/students/:userId/activation/resend', instructorOnly, async (req, res) => {
  try {
    const section = await loadSection(req, res);
    if (!section) return;
    const target = await loadManageableStudent(req, res, section);
    if (!target) return;

    if (target.activated_at) {
      return res.status(409).json({
        error: 'That account has already been activated. Send a password reset instead.',
      });
    }
    if (!canInvite(target.email)) {
      return res.status(409).json({
        error: `Cannot email ${target.email}. An administrator can set a password for this account `
             + 'directly from Admin → Users.',
      });
    }

    const ctx = await mailContext(req.user.userId);
    const result = await inviteNewAccount(target, { section, ctx, actorId: req.user.userId });

    roster.logRosterActivity({
      actorId: req.user.userId, sectionId: section.section_id, action: 'activation_resend',
      detail: { target_user_id: target.user_id, status: result.status },
    });

    if (result.status !== 'queued') {
      return res.status(502).json({ error: result.reason || 'The invitation could not be queued.' });
    }
    res.json({ status: result.status, sent: true, email: target.email });
  } catch (error) {
    if (error.status) return res.status(error.status).json({ error: error.message });
    console.error('[CIAB] activation resend:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// ============================================================================
// RUN HISTORY
// ============================================================================

// GET /imports — the last 25 runs against this section
router.get('/imports', instructorOnly, async (req, res) => {
  try {
    const section = await loadSection(req, res);
    if (!section) return;
    const r = await query(
      `SELECT import_id, actor_id, source, total_rows, created_count, enrolled_count,
              skipped_count, failed_count, notify, created_at
         FROM ciab_roster_import
        WHERE section_id = $1 ORDER BY created_at DESC LIMIT 25`,
      [section.section_id]
    );
    res.json({ imports: r.rows });
  } catch (error) {
    console.error('[CIAB] roster imports:', error.message);
    res.status(500).json({ error: 'Failed to load import history' });
  }
});

// GET /email-status?import_id= — per-recipient delivery state for one run
router.get('/email-status', instructorOnly, async (req, res) => {
  try {
    const section = await loadSection(req, res);
    if (!section) return;
    const importId = String(req.query.import_id || '');
    if (!importId) return res.status(400).json({ error: 'import_id is required' });

    // Scoped to this section before asking the mailer, so an import_id from
    // someone else's section cannot be used to read their delivery log.
    const owns = await query(
      `SELECT 1 FROM ciab_roster_import WHERE import_id = $1 AND section_id = $2`,
      [importId, section.section_id]
    );
    if (!owns.rowCount) return res.status(404).json({ error: 'No such import for this section' });

    const status = await mailer.statusForImport(importId).catch(() => null);
    res.json({ import_id: importId, recipients: status || [] });
  } catch (error) {
    console.error('[CIAB] roster email status:', error.message);
    res.status(500).json({ error: 'Failed to load delivery status' });
  }
});

// ============================================================================
// POST /import-from-cle — pull a roster out of a CLE course
// ----------------------------------------------------------------------------
// A convenience, never a dependency. An instructor who already built a roster in
// the CLE plugin should not have to export and re-import it by hand -- but CIAB
// must keep working with the CLE plugin absent or deactivated, so the require is
// lazy, inside a try, and its failure is a plain 501.
//
// The rows it reads are fed through the SAME preview/confirm pipeline as a CSV,
// so seat caps, elevated-account warnings and per-row isolation all behave
// identically. It is a source of rows, not a second import path.
// ============================================================================

router.post('/import-from-cle', instructorOnly, express.json(), async (req, res) => {
  let cleQuery;
  try {
    ({ query: cleQuery } = require('../../cle/utils/db'));
  } catch (_) {
    return res.status(501).json({
      error: 'The Cyber Learning Environment plugin is not installed on this deployment.',
    });
  }

  try {
    const section = await loadSection(req, res);
    if (!section) return;

    const courseId = String(req.body.course_id || '');
    if (!courseId) return res.status(400).json({ error: 'course_id is required' });

    // Authorisation is the CLE plugin's to give, not ours: an instructor may
    // only pull from a course they themselves manage. Admins match any course,
    // which is getManagedCourse's own rule.
    let course;
    try {
      const { getManagedCourse } = require('../../cle/utils/course-access');
      course = await getManagedCourse(courseId, req.user, 'course_id, course_name, code');
    } catch (err) {
      return res.status(501).json({ error: 'The CLE plugin could not be queried on this deployment.' });
    }
    if (!course) return res.status(403).json({ error: 'Course not found or access denied' });

    const roll = await cleQuery(
      `SELECT user_id FROM cle_course_enrollment
        WHERE course_id = $1 AND status IN ('active','completed')`,
      [courseId]
    );
    if (!roll.rows.length) {
      return res.status(404).json({ error: `${course.course_name} has nobody enrolled to import.` });
    }

    // Resolved to addresses because everything downstream -- classifyRows,
    // provisionAccount, the dedupe -- is keyed on email. These accounts all
    // exist already, so nothing here will mint one.
    const users = await cybercoreQuery(
      `SELECT user_id, email, first_name, last_name FROM cybercore_user
        WHERE user_id = ANY($1::uuid[])`,
      [roll.rows.map((r) => r.user_id)]
    );

    // Straight into the CSV pipeline. One set of rules, one preview contract.
    return runImport(req, res, section, {
      rows: users.rows.map((u, i) => ({
        line: i + 1, email: u.email, first_name: u.first_name, last_name: u.last_name,
      })),
      confirm: req.body.confirm,
      notify_existing: req.body.notify_existing,
      enrollment_role: req.body.enrollment_role,
    }, 'cle_course');
  } catch (error) {
    console.error('[CIAB] import from CLE:', error.message);
    res.status(500).json({ error: 'Could not read that course roster', details: error.message });
  }
});

module.exports = router;
