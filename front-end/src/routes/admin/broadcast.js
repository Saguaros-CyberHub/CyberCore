/*
 * ============================================================================
 * ADMIN BROADCAST
 * ============================================================================
 * Compose one message and send it to a chosen audience. The platform already
 * had four transactional senders (activation, course-added, credentials, relay
 * test); this is the first one where a human writes the words at send time.
 *
 * The shape of the flow is the safety property, not a nicety:
 *
 *   render  -> what will this look like?          (message only, no audience)
 *   preview -> who exactly gets it, and who does not, and why
 *   test    -> send it to myself and nobody else
 *   send    -> re-resolve, verify nothing moved, queue
 *
 * Two rules the endpoints below never bend:
 *
 *   1. The client never supplies a recipient list. It posts the same audience
 *      SPEC every time and the server resolves it. A client-supplied list would
 *      be an admin-authenticated "mail anyone" primitive that walks straight
 *      past mailer.checkRecipient().
 *
 *   2. Nothing reaches the html part unescaped. The admin types plain text;
 *      templates.broadcast() escapes it. There is no rich-text field, no raw
 *      HTML field, and the single call-to-action URL is scheme-checked here
 *      before it is ever interpolated into an href.
 */

const express = require('express');
const router = express.Router();
const crypto = require('crypto');

const { authenticateToken, requireRole } = require('../../middleware/auth');
const { cybercoreQuery } = require('../../utils/cybercore-db');
const { logActivity } = require('../../middleware/activity-logger');
const mailer = require('../../utils/mailer');
const templates = require('../../utils/email-templates');
const audienceUtil = require('../../utils/broadcast-audience');
const emailWorker = require('../../utils/email-worker');

const adminOnly = requireRole('admin');

// Content limits, not the recipient cap. express.json accepts 10 MB, and a
// document pasted into the body would otherwise be encrypted once per
// recipient — 500 copies of a 5 MB blob is a genuinely bad afternoon.
const MAX_SUBJECT = 200;
const MAX_BODY = 20_000;
const MAX_BUTTON_LABEL = 60;

// How many addresses the preview will actually name. The counts are exact; the
// list is a sample, because nobody reads four hundred rows.
const SAMPLE_SIZE = 50;

// ============================================================================
// MESSAGE VALIDATION
// ============================================================================

/**
 * Validate and canonicalise the composed message.
 *
 * Returns `safe` alongside `message`: identical, except that an invalid
 * call-to-action is stripped. That distinction is what lets /render keep
 * painting a live preview while the admin is still typing a URL, without ever
 * rendering `javascript:` into an href — while /send refuses outright on any
 * error at all.
 */
function normalizeMessage(raw = {}) {
  const errors = [];

  const subject = String(raw.subject ?? '').trim();
  const bodyText = String(raw.bodyText ?? '').replace(/\r\n/g, '\n');
  const buttonLabel = String(raw.buttonLabel ?? '').trim();
  const buttonUrl = String(raw.buttonUrl ?? '').trim();
  const includeGreeting = raw.includeGreeting !== false;

  if (!subject) {
    errors.push('A subject is required.');
  } else if (subject.length > MAX_SUBJECT) {
    errors.push(`The subject is ${subject.length} characters; the limit is ${MAX_SUBJECT}.`);
  }

  if (!bodyText.trim()) {
    errors.push('The message body is empty.');
  } else if (bodyText.length > MAX_BODY) {
    errors.push(`The message is ${bodyText.length} characters; the limit is ${MAX_BODY}.`);
  }

  let buttonOk = true;
  if (buttonLabel && !buttonUrl) {
    errors.push('The button has a label but no link.');
    buttonOk = false;
  }
  if (buttonUrl && !buttonLabel) {
    errors.push('The button has a link but no label.');
    buttonOk = false;
  }
  if (buttonLabel.length > MAX_BUTTON_LABEL) {
    errors.push(`The button label is ${buttonLabel.length} characters; the limit is ${MAX_BUTTON_LABEL}.`);
    buttonOk = false;
  }
  if (buttonUrl) {
    // email-templates.button() escapes the url for the attribute, which stops
    // an escape from the href but does nothing about the scheme — `javascript:`
    // survives escaping perfectly intact. Every existing caller passes a URL
    // this repo built; this is the first one a person types.
    let parsed = null;
    try { parsed = new URL(buttonUrl); } catch { /* reported below */ }
    if (!parsed) {
      errors.push('The button link is not a valid URL.');
      buttonOk = false;
    } else if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      errors.push(`The button link must be http:// or https:// — "${parsed.protocol}" is not allowed.`);
      buttonOk = false;
    }
  }

  const message = { subject, bodyText, buttonLabel, buttonUrl, includeGreeting };
  const safe = buttonOk ? message : { ...message, buttonLabel: '', buttonUrl: '' };
  return { message, safe, errors };
}

function renderFor(recipient, message, site) {
  return templates.broadcast({
    siteName: site,
    firstName: recipient?.first_name,
    lastName: recipient?.last_name,
    email: recipient?.email,
    subject: message.subject,
    bodyText: message.bodyText,
    buttonLabel: message.buttonLabel,
    buttonUrl: message.buttonUrl,
    includeGreeting: message.includeGreeting,
  });
}

/**
 * The signed-in admin, read from the database rather than the JWT.
 *
 * req.user.email is a token claim, and is stale if the address changed since
 * they signed in — which would send the "test to yourself" to an address they
 * no longer own.
 */
async function selfRecipient(userId) {
  const result = await cybercoreQuery(
    `SELECT user_id, email, first_name, last_name, role, organization, active, status
       FROM cybercore_user WHERE user_id = $1`,
    [userId]
  );
  return result.rows[0] ? audienceUtil.toRecipient(result.rows[0]) : null;
}

/**
 * Roughly how long the queue will take to drain, in minutes.
 *
 * Worth showing because a broadcast does not jump the queue — drainOutbox()
 * orders by next_attempt_at, so several hundred broadcast rows sit in front of
 * whatever an instructor enqueues in the meantime. An admin who can see "about
 * 8 minutes" will not assume something is broken, and may think twice before
 * firing one off mid-roster-import.
 */
function estimateMinutes(queued, backlog) {
  const batch = Number(emailWorker.BATCH) > 0 ? Number(emailWorker.BATCH) : 25;
  const pollMs = Number(emailWorker.POLL_MS) > 0 ? Number(emailWorker.POLL_MS) : 15_000;
  const ticks = Math.ceil((Number(queued || 0) + Number(backlog || 0)) / batch);
  return Math.max(0, Math.round((ticks * pollMs) / 60_000));
}

// ============================================================================
// RENDER — message only, no audience query
// ============================================================================
//
// Split from /preview deliberately. The live preview fires on a debounce as the
// admin types, and folding it into /preview would re-scan cybercore_user on
// every keystroke burst for a result nobody asked for.

router.post('/broadcast/render', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { safe, errors } = normalizeMessage(req.body?.message);
    const site = await mailer.siteName();
    const me = await selfRecipient(req.user.userId);

    res.json({
      errors,
      // Told to the admin in as many words, because "personalized" changes what
      // the preview in front of them actually represents.
      personalized: templates.hasMergeFields(safe.bodyText),
      merge_keys: templates.MERGE_KEYS,
      rendered_for: me ? { email: me.email, first_name: me.first_name } : null,
      message: renderFor(me, safe, site),
    });
  } catch (error) {
    console.error('[Broadcast] Render error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// ============================================================================
// PREVIEW — resolve the audience and report it exactly
// ============================================================================

router.post('/broadcast/preview', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { safe, errors: messageErrors } = normalizeMessage(req.body?.message);
    const site = await mailer.siteName();

    const resolved = await audienceUtil.resolveAudience(
      { ...(req.body?.audience || {}), message: safe },
      { selfUserId: req.user.userId }
    );

    // Render against a real recipient so merge fields visibly resolve, falling
    // back to the admin when the audience is empty or entirely suppressed.
    const sample = resolved.deliverable[0] || await selfRecipient(req.user.userId);
    const backlog = await mailer.queueBacklog();

    res.json({
      summary: {
        total: resolved.recipients.length,
        deliverable: resolved.deliverable.length,
        suppressed: resolved.suppressed.length,
        duplicates_removed: resolved.duplicatesRemoved,
        sources: resolved.sources,
      },
      suppression: resolved.suppressionReasons,
      sample_recipients: resolved.deliverable.slice(0, SAMPLE_SIZE).map(r => ({
        email: r.email, first_name: r.first_name, role: r.role,
      })),
      sample_truncated: resolved.deliverable.length > SAMPLE_SIZE,
      self_included: resolved.selfIncluded,
      personalized: templates.hasMergeFields(safe.bodyText),
      fingerprint: resolved.fingerprint,
      estimate: {
        backlog,
        batch_per_tick: emailWorker.BATCH,
        poll_seconds: Math.round(emailWorker.POLL_MS / 1000),
        minutes: estimateMinutes(resolved.deliverable.length, backlog),
      },
      rendered_for: sample ? { email: sample.email, first_name: sample.first_name } : null,
      message: renderFor(sample, safe, site),
      errors: [...messageErrors, ...resolved.errors],
      warnings: resolved.warnings,
    });
  } catch (error) {
    console.error('[Broadcast] Preview error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// ============================================================================
// TEST — to the sender, and only ever to the sender
// ============================================================================

router.post('/broadcast/test', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { safe, errors } = normalizeMessage(req.body?.message);
    if (errors.length) return res.status(400).json({ error: errors[0], errors });

    const me = await selfRecipient(req.user.userId);
    if (!me?.email) return res.status(400).json({ error: 'Your account has no email address on file.' });

    const site = await mailer.siteName();
    // sendNow, not enqueue: a slow or refusing relay IS the answer here, and
    // waiting a poll interval to discover it defeats the point of a test.
    const result = await mailer.sendNow(me.email, renderFor(me, safe, site));

    logActivity(req, 'broadcast_test', 'email', null, { to: me.email, ok: result.ok });

    if (!result.ok) {
      // Log it as well as returning it. This used to go only to the browser, so
      // container logs showed a bare "status: 502" with no reason - which is
      // precisely the information needed to tell a wrong port from a blocked
      // one from a refused sender.
      console.error(`[Broadcast] Relay refused via ${result.host}:${result.port} -`, result.error, result.code || '');
      return res.status(502).json({ error: result.error, code: result.code, sent: false });
    }

    // A successful test is NOT proof a broadcast will send: sendNow() does not
    // need MAIL_ENCRYPT_KEY because it stores nothing, while enqueue() suppresses
    // every row without it. Say so rather than letting the admin infer otherwise.
    const blocked = mailer.globalSuppression();
    res.json({
      sent: true,
      to: me.email,
      message_id: result.messageId,
      note: 'The relay accepted this message. That is not proof of delivery — check your mailbox.',
      ...(blocked ? { warning: `This test bypassed the queue. A real broadcast would still be suppressed: ${blocked}.` } : {}),
    });
  } catch (error) {
    console.error('[Broadcast] Test send error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// ============================================================================
// SEND
// ============================================================================

router.post('/broadcast/send', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { message, safe, errors: messageErrors } = normalizeMessage(req.body?.message);
    if (messageErrors.length) {
      return res.status(400).json({ error: messageErrors[0], errors: messageErrors });
    }

    const resolved = await audienceUtil.resolveAudience(
      { ...(req.body?.audience || {}), message: safe },
      { selfUserId: req.user.userId }
    );
    if (resolved.errors.length) {
      return res.status(400).json({ error: resolved.errors[0], errors: resolved.errors });
    }

    // The audience can move between preview and confirm — someone registers,
    // someone is deactivated. A count would not catch it (one added and one
    // removed leaves the count identical), so the preview's fingerprint covers
    // the exact address set AND the message. A mismatch is not an error; it
    // means the admin should look again at what they are about to send.
    const expected = String(req.body?.fingerprint || '');
    if (!expected) {
      return res.status(400).json({ error: 'Preview the broadcast before sending it.' });
    }
    if (expected !== resolved.fingerprint) {
      return res.status(409).json({
        error: 'The audience or the message changed since you previewed it. Review the updated numbers and confirm again.',
        code: 'FINGERPRINT_MISMATCH',
        fingerprint: resolved.fingerprint,
        summary: {
          deliverable: resolved.deliverable.length,
          suppressed: resolved.suppressed.length,
        },
      });
    }

    if (resolved.deliverable.length === 0) {
      const why = resolved.suppressionReasons[0]?.reason;
      return res.status(400).json({
        error: why
          ? `Nobody in this audience can be emailed: ${why}.`
          : 'This audience resolved to nobody.',
        suppression: resolved.suppressionReasons,
      });
    }

    const site = await mailer.siteName();
    const campaignId = crypto.randomUUID();
    const personalized = templates.hasMergeFields(safe.bodyText);

    // When nothing is personalized, every recipient gets byte-identical copy,
    // so render once instead of several hundred times.
    const shared = personalized ? null : renderFor(resolved.deliverable[0], safe, site);

    // Only deliverable recipients are queued. The roster import writes suppressed
    // rows so its report can explain itself after the fact; here the preview
    // already did that BEFORE anything was sent, so several hundred rows saying
    // "reserved domain" would be write-only noise in a table that gets pruned.
    // The counts survive in the activity_log entry below.
    const messages = resolved.deliverable.map(recipient => {
      const body = shared || renderFor(recipient, safe, site);
      return {
        to: recipient.email,
        toUserId: recipient.user_id,
        templateKey: 'broadcast',
        subject: body.subject,
        text: body.text,
        html: body.html,
        // Correlation only, and kept small: this object is stored once per
        // recipient, so an audience summary here would be duplicated 500 times.
        context: { campaign_id: campaignId },
        requestedBy: req.user.userId,
      };
    });

    const outcome = await mailer.enqueueMany(messages, { concurrency: 5 });
    const backlog = await mailer.queueBacklog();

    // The durable record. cybercore_email_outbox is pruned after
    // MAIL_RETENTION_DAYS, so this is the only place a broadcast is remembered
    // permanently — hence the audience spec and the counts, not just the id.
    logActivity(req, 'broadcast_sent', 'email', campaignId, {
      subject: message.subject,
      queued: outcome.queued,
      suppressed_at_queue: outcome.suppressed,
      suppressed_by_policy: resolved.suppressed.length,
      recipients: resolved.deliverable.length,
      personalized,
      audience: resolved.spec,
    });

    res.status(202).json({
      campaign_id: campaignId,
      queued: outcome.queued,
      suppressed: outcome.suppressed + resolved.suppressed.length,
      personalized,
      estimated_minutes: estimateMinutes(0, backlog),
    });
  } catch (error) {
    console.error('[Broadcast] Send error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// ============================================================================
// REPORTS
// ============================================================================
//
// Namespaced under /campaigns so a campaign id can never be a candidate match
// for render|preview|test|send.

router.get('/broadcast/campaigns', authenticateToken, adminOnly, async (req, res) => {
  try {
    res.json({
      campaigns: await mailer.recentCampaigns(req.query.limit),
      retention_days: Number(process.env.MAIL_RETENTION_DAYS) || 30,
    });
  } catch (error) {
    console.error('[Broadcast] Campaign list error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

router.get('/broadcast/campaigns/:campaignId', authenticateToken, adminOnly, async (req, res) => {
  try {
    const rows = await mailer.statusForCampaign(req.params.campaignId);
    if (rows.length === 0) {
      return res.status(404).json({
        error: 'No messages found for that campaign. Delivered mail is pruned after MAIL_RETENTION_DAYS.',
      });
    }
    const counts = rows.reduce((acc, r) => ({ ...acc, [r.status]: (acc[r.status] || 0) + 1 }), {});
    res.json({ campaign_id: req.params.campaignId, counts, messages: rows });
  } catch (error) {
    console.error('[Broadcast] Campaign status error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
