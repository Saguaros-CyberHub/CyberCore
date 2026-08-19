/**
 * ============================================================================
 * MAILER
 * ============================================================================
 * Queue-first outbound email. Nothing here ever talks to SMTP inside an HTTP
 * request: enqueue() writes a row and returns, and email-worker.js drains it.
 *
 * That is not premature engineering. A 200-student roster import would
 * otherwise hold one request open across 200 SMTP transactions, any of which
 * can hang on a slow relay — and a timeout halfway through would leave the
 * instructor with no idea which students were told and which were not.
 *
 * Message bodies are encrypted at rest with pgcrypto and blanked once sent.
 * They carry activation links, which are live credentials until redeemed, and
 * adminer is published on 0.0.0.0:8181 (docker-compose.yml) — plaintext in this
 * table would be one weak database password away from disclosure. Same idiom
 * the schema already uses for guac_password and mfa_secret.
 */

const nodemailer = require('nodemailer');
const { cybercoreQuery } = require('./cybercore-db');
const templates = require('./email-templates');

// Reserved TLDs that can never receive mail (RFC 2606 / 6761). Sending to them
// produces guaranteed bounces, and a bounce rate is a deliverability signal —
// this is how the platform's own synthetic addresses (@clinic.local from group
// deploy, @cohort.invalid from cohort generation) stay out of the relay.
const UNDELIVERABLE_TLDS = ['.invalid', '.local', '.test', '.example', '.localhost'];

const DEFAULT_MAX_ATTEMPTS = Number(process.env.MAIL_MAX_ATTEMPTS) > 0
  ? Number(process.env.MAIL_MAX_ATTEMPTS) : 5;

let _transport = null;

// ============================================================================
// CONFIGURATION
// ============================================================================

function mailEnabled() {
  return process.env.MAIL_ENABLED === 'true' && !!process.env.MAIL_HOST;
}

/**
 * Key for encrypting bodies at rest. Falls back to the other at-rest keys so a
 * deployment that already configured MFA gets working mail without a new
 * secret — but a dedicated MAIL_ENCRYPT_KEY is preferable.
 */
function mailKey() {
  return process.env.MAIL_ENCRYPT_KEY || process.env.MFA_ENCRYPT_KEY || process.env.GUAC_ENCRYPT_KEY || null;
}

function publicUrl() {
  return String(process.env.MAIL_PUBLIC_URL || '').replace(/\/+$/, '');
}

/**
 * Branding for the message being composed. Third caller of this lookup and the
 * last one that should write it out by hand — settings.js and the CLE roster
 * import both grew their own copy.
 *
 * Never throws: branding is cosmetic, and a missing settings table must not
 * stop a message going out.
 */
async function siteName() {
  try {
    const result = await cybercoreQuery(
      `SELECT value FROM cybercore_site_settings WHERE key = 'site_name'`
    );
    return result.rows[0]?.value || 'CyberHub';
  } catch {
    return 'CyberHub';
  }
}

/**
 * Is MAIL_HOST somewhere the connection cannot leave the host or its bridge
 * network? Single-label names are Docker service names (`mailrelay`), which do
 * not resolve publicly; the rest are loopback and RFC 1918 literals.
 */
function isInternalHost(host) {
  const h = String(host || '').trim().toLowerCase();
  if (!h) return false;
  if (h === 'localhost' || h.endsWith('.localhost')) return true;
  if (!h.includes('.')) return true;
  if (h === '::1' || /^127\./.test(h)) return true;
  if (/^10\./.test(h) || /^192\.168\./.test(h)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(h)) return true;
  return false;
}

/**
 * Whether the relay must present a verifiable certificate.
 *
 * The bundled Postfix relay sits on cybercore-net with no published port and
 * presents a self-signed certificate if it offers STARTTLS at all, so refusing
 * it would mean never delivering — and that hop never leaves the bridge.
 *
 * That reasoning does not survive contact with a public relay. An external
 * submission host (Resend, SES, an institutional smarthost) is reached over the
 * internet and is handed MAIL_PASSWORD during AUTH, so skipping verification
 * there is credential interception waiting to happen, not a convenience.
 * MAIL_TLS_INSECURE exists for the rare self-signed relay reached by FQDN.
 */
function tlsRejectUnauthorized() {
  if (process.env.MAIL_TLS_INSECURE === 'true') return false;
  return !isInternalHost(process.env.MAIL_HOST);
}

/** Lazily built and cached; nodemailer pools connections internally. */
function transport() {
  if (_transport) return _transport;
  _transport = nodemailer.createTransport({
    host: process.env.MAIL_HOST,
    // 587, matching the bundled relay that MAIL_HOST also defaults to (it binds
    // submission only). Every external relay documented in example.env — Resend,
    // SES, Gmail — is 587 as well, so 25 was the one port nothing here uses.
    port: Number(process.env.MAIL_PORT) || 587,
    secure: process.env.MAIL_SECURE === 'true',
    // The relay sits on cybercore-net with no published port, so submission is
    // unauthenticated by design. Credentials are only set when relaying to an
    // external smarthost.
    ...(process.env.MAIL_USER ? {
      auth: { user: process.env.MAIL_USER, pass: process.env.MAIL_PASSWORD },
    } : {}),
    // A relay that is down should fail the attempt and let the retry schedule
    // handle it, not wedge the worker.
    connectionTimeout: 10_000,
    greetingTimeout: 10_000,
    socketTimeout: 20_000,
    tls: { rejectUnauthorized: tlsRejectUnauthorized() },
  });
  return _transport;
}

/** Test seam: drop the cached transport so config changes take effect. */
function resetTransport() {
  _transport = null;
}

// ============================================================================
// RECIPIENT POLICY
// ============================================================================

function allowedDomains() {
  return String(process.env.MAIL_ALLOWED_RECIPIENT_DOMAINS || '')
    .split(',')
    .map(d => d.trim().toLowerCase().replace(/^@/, ''))
    .filter(Boolean);
}

/**
 * Decide whether an address may be written to at all.
 *
 * @returns {{ok: true} | {ok: false, reason: string}}
 */
function checkRecipient(address) {
  const addr = String(address || '').trim().toLowerCase();
  if (!addr || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(addr)) {
    return { ok: false, reason: 'not a deliverable address' };
  }

  // Unconditional, ahead of the allowlist. One misconfiguration that pointed
  // the cohort domain at something real would send a burst of near-identical
  // credential mail from a new IP — the textbook spam signature, and a fast way
  // to lose the sending reputation for every future class.
  const cohortDomain = String(process.env.CLE_COHORT_EMAIL_DOMAIN || 'cohort.invalid').toLowerCase();
  if (addr.endsWith(`@${cohortDomain}`)) {
    return { ok: false, reason: 'synthetic cohort address — these accounts are distributed on a credential sheet, not by email' };
  }
  if (UNDELIVERABLE_TLDS.some(tld => addr.endsWith(tld))) {
    return { ok: false, reason: 'reserved domain that cannot receive mail' };
  }

  const allowed = allowedDomains();
  if (allowed.length > 0) {
    const domain = addr.split('@')[1];
    const match = allowed.some(d => domain === d || domain.endsWith(`.${d}`));
    if (!match) {
      return { ok: false, reason: `recipient domain is not in MAIL_ALLOWED_RECIPIENT_DOMAINS (${allowed.join(', ')})` };
    }
  }

  return { ok: true };
}

/**
 * Why NOTHING can be queued right now, or null when the server is able to send.
 *
 * Exists so a caller can ask the question ahead of time and get back the exact
 * string enqueue() would have written to last_error. The broadcast preview
 * depends on that: an admin composing a message to 400 people needs to be told
 * "email is not configured on this server" before they write it, not afterwards
 * via 400 suppressed rows.
 *
 * Note what this is NOT: it is not a recipient check. checkRecipient() answers
 * "may this address be written to"; this answers "can this server write to
 * anyone at all". Both have to pass.
 */
function globalSuppression() {
  if (!mailEnabled()) return 'email is not configured on this server';
  if (!mailKey()) return 'MAIL_ENCRYPT_KEY is not configured, so message bodies cannot be stored securely';
  return null;
}

// ============================================================================
// QUEUE
// ============================================================================

/**
 * Queue one message.
 *
 * Never throws for a policy reason — a suppressed recipient still gets a row,
 * so the roster-import UI can tell an instructor "these 3 were not emailed, and
 * here is why" instead of silently doing nothing. The caller decides how loudly
 * to surface that.
 *
 * @returns {Promise<{email_id: ?string, status: 'queued'|'suppressed', reason?: string}>}
 */
async function enqueue(msg = {}) {
  const to = String(msg.to || '').trim();
  const key = mailKey();

  let status = 'queued';
  let reason = null;

  const recipient = checkRecipient(to);
  // A suppressed row is deliberately still written in both cases. An offline or
  // LAN-only deployment is a real way to run this platform, and the import (or
  // broadcast) report should say "email is not configured here" rather than
  // implying the mail was sent. And refusing to store a body we cannot encrypt
  // is the whole point of the key check.
  const blocked = globalSuppression();
  if (!recipient.ok) {
    status = 'suppressed';
    reason = recipient.reason;
  } else if (blocked) {
    status = 'suppressed';
    reason = blocked;
  }

  const storeBody = status === 'queued';

  try {
    // Every parameter this statement encrypts is cast explicitly, and the cast
    // on $8's FIRST reference is the load-bearing one.
    //
    // Postgres fixes a parameter's type where it first appears. $8 used to first
    // appear as a bare "$8 IS NOT NULL" - a NullTest, which supplies no type - so
    // it stayed "unknown" and the whole INSERT failed to parse with "could not
    // determine data type of parameter $8". Value-independent and therefore fatal
    // to EVERY call, in every deployment, for every template. $6 escaped it only
    // by luck of first appearing inside pgp_sym_encrypt(), which types its
    // argument. The catch below turned that into a "suppressed" row rather than a
    // throw, so the platform reported it had handled mail it had never queued.
    const result = await cybercoreQuery(
      `INSERT INTO cybercore_email_outbox
         (to_address, to_user_id, template_key, subject,
          body_text_cipher, body_html_cipher,
          status, max_attempts, last_error, context, requested_by)
       VALUES ($1, $2, $3, $4,
               CASE WHEN $5::boolean THEN pgp_sym_encrypt($6::text, $7::text) END,
               CASE WHEN $5::boolean AND $8::text IS NOT NULL THEN pgp_sym_encrypt($8::text, $7::text) END,
               $9, $10, $11, $12::jsonb, $13)
       RETURNING email_id, status`,
      [
        to, msg.toUserId || null, msg.templateKey || 'unknown', msg.subject || '(no subject)',
        storeBody, msg.text || '', key || '', msg.html || null,
        status, DEFAULT_MAX_ATTEMPTS, reason,
        JSON.stringify(msg.context || {}), msg.requestedBy || null,
      ]
    );
    return { email_id: result.rows[0].email_id, status, ...(reason ? { reason } : {}) };
  } catch (err) {
    // A queue failure must not take down the import that triggered it — the
    // accounts were already created, and losing the notification is far less
    // bad than losing the transaction.
    console.error('[mailer] Could not queue message to', to, '-', err.message);
    return { email_id: null, status: 'suppressed', reason: `could not be queued: ${err.message}` };
  }
}

/**
 * Queue several, reporting the split. Order is preserved in `results`.
 *
 * Sequential by default, which is what every pre-existing caller wants and got.
 * `concurrency` exists for the admin broadcast, where the audience can run to
 * several hundred: one INSERT round trip per recipient against an off-box
 * database turns a 500-person send into seconds of a held-open request. Kept
 * well under the pool's max of 10 (cybercore-db.js), which drainOutbox is also
 * drawing from at the same time.
 */
async function enqueueMany(messages = [], opts = {}) {
  const concurrency = Math.min(Math.max(1, Number(opts.concurrency) || 1), 5);
  const results = new Array(messages.length);
  for (let i = 0; i < messages.length; i += concurrency) {
    const chunk = messages.slice(i, i + concurrency);
    // enqueue() never rejects for a policy reason and swallows its own write
    // errors, so Promise.all cannot lose a result here.
    const settled = await Promise.all(chunk.map(msg => enqueue(msg)));
    for (let j = 0; j < settled.length; j++) results[i + j] = settled[j];
  }
  return {
    queued: results.filter(r => r.status === 'queued').length,
    suppressed: results.filter(r => r.status === 'suppressed').length,
    results,
  };
}

// ============================================================================
// DELIVERY
// ============================================================================

/**
 * Claim and send up to `limit` due messages.
 *
 * The claim is a single UPDATE with FOR UPDATE SKIP LOCKED so that a second app
 * replica — which does not exist today, but would be an easy thing to add and a
 * miserable thing to debug — cannot send the same message twice.
 */
async function drainOutbox(opts = {}) {
  const limit = Number(opts.limit) > 0 ? Number(opts.limit) : 25;
  const key = mailKey();
  const summary = { attempted: 0, sent: 0, failed: 0, deferred: 0 };

  if (!mailEnabled() || !key) return summary;

  const claimed = await cybercoreQuery(
    `UPDATE cybercore_email_outbox
        SET status = 'sending', attempts = attempts + 1, updated_at = now()
      WHERE email_id IN (
        SELECT email_id FROM cybercore_email_outbox
         WHERE status = 'queued' AND next_attempt_at <= now()
         ORDER BY next_attempt_at
         LIMIT $1
         FOR UPDATE SKIP LOCKED
      )
      RETURNING email_id, to_address, subject, attempts, max_attempts,
                pgp_sym_decrypt(body_text_cipher, $2)::text AS body_text,
                CASE WHEN body_html_cipher IS NOT NULL
                     THEN pgp_sym_decrypt(body_html_cipher, $2)::text END AS body_html`,
    [limit, key]
  );

  for (const row of claimed.rows) {
    summary.attempted++;
    try {
      const info = await transport().sendMail({
        from: process.env.MAIL_FROM || 'no-reply@localhost',
        ...(process.env.MAIL_REPLY_TO ? { replyTo: process.env.MAIL_REPLY_TO } : {}),
        to: row.to_address,
        subject: row.subject,
        text: row.body_text,
        ...(row.body_html ? { html: row.body_html } : {}),
      });

      // Blank the body in the same statement that marks it sent. The link has
      // reached its recipient; keeping a decryptable copy afterwards is pure
      // liability with no operational value.
      await cybercoreQuery(
        `UPDATE cybercore_email_outbox
            SET status = 'sent', sent_at = now(), updated_at = now(),
                smtp_message_id = $2, last_error = NULL,
                body_text_cipher = NULL, body_html_cipher = NULL
          WHERE email_id = $1`,
        [row.email_id, info?.messageId || null]
      );
      summary.sent++;
    } catch (err) {
      const exhausted = row.attempts >= row.max_attempts;
      // Exponential backoff: 4^n minutes — 4, 16, 64, 256. A relay that is down
      // is usually down for a while, and hammering it helps nobody.
      await cybercoreQuery(
        `UPDATE cybercore_email_outbox
            SET status = $2, last_error = $3, updated_at = now(),
                next_attempt_at = now() + (interval '1 minute' * power(4, attempts))
          WHERE email_id = $1`,
        [row.email_id, exhausted ? 'failed' : 'queued', String(err.message).slice(0, 500)]
      );
      if (exhausted) summary.failed++; else summary.deferred++;
    }
  }

  return summary;
}

/**
 * Return messages stranded in 'sending' to the queue.
 *
 * A crash between the claim and the result leaves rows claimed by a process
 * that no longer exists. Nothing else would ever pick them up, so an import's
 * invitations would sit unsent forever with no error to show for it.
 */
async function requeueStalledSends(olderThanMinutes = 15) {
  try {
    const result = await cybercoreQuery(
      `UPDATE cybercore_email_outbox
          SET status = 'queued', updated_at = now(),
              last_error = 'Interrupted mid-send by a server restart; retrying.'
        WHERE status = 'sending'
          AND updated_at < now() - ($1 || ' minutes')::interval`,
      [String(olderThanMinutes)]
    );
    if (result.rowCount > 0) {
      console.warn(`[mailer] Requeued ${result.rowCount} message(s) stranded mid-send by a previous run`);
    }
    return result.rowCount || 0;
  } catch (err) {
    console.warn('[mailer] Could not requeue stalled sends:', err.message);
    return 0;
  }
}

/** Drop delivered mail past its retention window. */
async function pruneOutbox(retentionDays = Number(process.env.MAIL_RETENTION_DAYS) || 30) {
  try {
    const result = await cybercoreQuery(
      `DELETE FROM cybercore_email_outbox
        WHERE status IN ('sent', 'suppressed')
          AND created_at < now() - ($1 || ' days')::interval`,
      [String(retentionDays)]
    );
    return result.rowCount || 0;
  } catch (err) {
    console.warn('[mailer] Could not prune outbox:', err.message);
    return 0;
  }
}

/**
 * Send one already-rendered message immediately, bypassing the queue.
 *
 * ONLY for the admin diagnostics — the relay test and the broadcast's
 * send-to-yourself — where a synchronous answer is the entire point: if this is
 * slow or hangs, that IS the result the operator needs to see. Everything that
 * goes to somebody else goes through enqueue().
 *
 * Note that this does not consult globalSuppression(): a missing
 * MAIL_ENCRYPT_KEY only blocks STORING a body, and nothing is stored here. That
 * asymmetry is deliberate but sharp — a test message can arrive on a server
 * where every queued message would be suppressed, so any UI offering both must
 * check globalSuppression() separately rather than reading a successful test as
 * proof that a real send would work.
 */
async function sendNow(to, message = {}) {
  if (!mailEnabled()) {
    return { ok: false, error: 'MAIL_ENABLED is not "true" or MAIL_HOST is unset.' };
  }
  const recipient = checkRecipient(to);
  if (!recipient.ok) return { ok: false, error: `Refusing to send: ${recipient.reason}` };

  try {
    const info = await transport().sendMail({
      from: process.env.MAIL_FROM || 'no-reply@localhost',
      ...(process.env.MAIL_REPLY_TO ? { replyTo: process.env.MAIL_REPLY_TO } : {}),
      to,
      subject: message.subject,
      text: message.text,
      ...(message.html ? { html: message.html } : {}),
    });
    return { ok: true, messageId: info?.messageId || null, accepted: info?.accepted || [] };
  } catch (err) {
    return {
      ok: false,
      error: err.message,
      code: err.code || err.errno || null,
      host: process.env.MAIL_HOST || null,
      port: Number(process.env.MAIL_PORT) || 587,
    };
  }
}

/** Proves the relay works end to end, for POST /api/admin/mail/test. */
async function sendTest(to, opts = {}) {
  return sendNow(to, templates.testMessage({
    siteName: opts.siteName || 'CyberHub',
    publicUrl: publicUrl(),
  }));
}

// ============================================================================
// REPORTING
// ============================================================================

/**
 * Per-recipient delivery state for an import, so an instructor can see "3
 * bounced" rather than assuming everything arrived. Never returns a body.
 */
async function statusForImport(importId) {
  const result = await cybercoreQuery(
    `SELECT email_id, to_address, template_key, status, attempts, last_error, sent_at, created_at
       FROM cybercore_email_outbox
      WHERE context->>'import_id' = $1
      ORDER BY created_at`,
    [String(importId)]
  );
  return result.rows;
}

/**
 * The same thing for one admin broadcast: same shape, same guarantee that no
 * body is ever returned.
 *
 * campaign_id lives in `context` rather than a column of its own, for the same
 * reason import_id does — this table is a queue, not a campaign archive. The
 * durable record of a broadcast is the activity_log row the route writes; this
 * report only lives as long as the rows do, which is MAIL_RETENTION_DAYS.
 */
async function statusForCampaign(campaignId) {
  const result = await cybercoreQuery(
    `SELECT email_id, to_address, template_key, status, attempts, last_error, sent_at, created_at
       FROM cybercore_email_outbox
      WHERE context->>'campaign_id' = $1
      ORDER BY to_address`,
    [String(campaignId)]
  );
  return result.rows;
}

/**
 * Recent broadcasts, derived from the outbox itself rather than from a campaign
 * table. Everything a delivery summary needs is already on these rows.
 */
async function recentCampaigns(limit = 25) {
  const result = await cybercoreQuery(
    `SELECT context->>'campaign_id'                            AS campaign_id,
            min(created_at)                                    AS started_at,
            min(subject)                                       AS subject,
            count(*)::int                                      AS total,
            count(*) FILTER (WHERE status = 'sent')::int       AS sent,
            count(*) FILTER (WHERE status = 'queued')::int     AS queued,
            count(*) FILTER (WHERE status = 'sending')::int    AS sending,
            count(*) FILTER (WHERE status = 'failed')::int     AS failed,
            count(*) FILTER (WHERE status = 'suppressed')::int AS suppressed
       FROM cybercore_email_outbox
      WHERE template_key = 'broadcast' AND context ? 'campaign_id'
      GROUP BY 1
      ORDER BY started_at DESC
      LIMIT $1`,
    [Math.min(Math.max(1, Number(limit) || 25), 100)]
  );
  return result.rows;
}

/**
 * How much mail is already ahead of a new send. Used to tell an admin how long
 * a broadcast will take to drain, since the worker sends a fixed batch per tick
 * and a large broadcast delays everything queued behind it.
 */
async function queueBacklog() {
  try {
    const result = await cybercoreQuery(
      `SELECT count(*)::int AS n FROM cybercore_email_outbox WHERE status IN ('queued','sending')`
    );
    return result.rows[0]?.n || 0;
  } catch {
    return 0;
  }
}

// ============================================================================
// BOOT DDL
// ============================================================================

/**
 * Idempotent, mirroring ensureMfaColumns() in server.js — the config/postgres
 * scripts only run on a fresh volume. Keep in sync with
 * front-end/migrations/029_email_outbox.sql.
 */
async function ensureEmailOutbox() {
  try {
    await cybercoreQuery(`
      CREATE TABLE IF NOT EXISTS cybercore_email_outbox (
        email_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        to_address       TEXT NOT NULL,
        to_user_id       UUID,
        template_key     TEXT NOT NULL,
        subject          TEXT NOT NULL,
        body_text_cipher BYTEA,
        body_html_cipher BYTEA,
        status           TEXT NOT NULL DEFAULT 'queued'
                         CHECK (status IN ('queued','sending','sent','failed','suppressed')),
        attempts         INTEGER NOT NULL DEFAULT 0,
        max_attempts     INTEGER NOT NULL DEFAULT 5,
        next_attempt_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
        last_error       TEXT,
        smtp_message_id  TEXT,
        context          JSONB NOT NULL DEFAULT '{}'::jsonb,
        requested_by     UUID,
        created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
        sent_at          TIMESTAMPTZ
      )
    `);
    await cybercoreQuery(`
      CREATE INDEX IF NOT EXISTS idx_email_outbox_due
        ON cybercore_email_outbox (next_attempt_at)
        WHERE status IN ('queued','sending')
    `);
    await cybercoreQuery(`
      CREATE INDEX IF NOT EXISTS idx_email_outbox_user
        ON cybercore_email_outbox (to_user_id)
    `);
    await cybercoreQuery(`
      CREATE INDEX IF NOT EXISTS idx_email_outbox_import
        ON cybercore_email_outbox ((context->>'import_id'))
    `);
    // Backs the per-campaign delivery report and the recent-broadcasts list.
    // Keep in sync with front-end/migrations/032_email_outbox_campaign_index.sql.
    await cybercoreQuery(`
      CREATE INDEX IF NOT EXISTS idx_email_outbox_campaign
        ON cybercore_email_outbox ((context->>'campaign_id'))
    `);
    console.log('✅ Email outbox ensured');
  } catch (err) {
    console.warn('⚠️  Could not ensure email outbox:', err.message);
  }
}

module.exports = {
  mailEnabled, mailKey, publicUrl, siteName,
  transport, resetTransport,
  isInternalHost, tlsRejectUnauthorized,
  checkRecipient, allowedDomains, globalSuppression,
  enqueue, enqueueMany,
  drainOutbox, requeueStalledSends, pruneOutbox,
  sendNow, sendTest,
  statusForImport, statusForCampaign, recentCampaigns, queueBacklog,
  ensureEmailOutbox,
  UNDELIVERABLE_TLDS,
};
