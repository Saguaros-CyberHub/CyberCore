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
 * Turn caller-supplied recipients into the exact strings a row and a send need.
 *
 * WHY THIS EXISTS
 * Support tickets are the first message this platform sends to MORE THAN ONE
 * person: To: every active admin, Cc: the course instructor, Reply-To: the
 * student who filed it. Everything before them was a single address.
 *
 * BACKWARD COMPATIBILITY IS THE WHOLE DESIGN CONSTRAINT. Five callers pass
 * `to: <string>` and nothing else — activation links, password resets, roster
 * invitations, credential handouts, broadcasts. For those,
 * resolveAddresses('a@b.c') must produce exactly what
 * `String(msg.to || '').trim()` produced, and the suppression reason must be
 * byte-identical to what checkRecipient() returned, because
 * utils/broadcast-audience.js promises its preview reasons match last_error.
 * test/mailer-policy.test.js pins both.
 *
 * nodemailer accepts a comma-joined string for `to` and `cc`, so a list needs
 * no schema change beyond one nullable column.
 *
 * @param {string|string[]} to
 * @param {string|string[]} [cc]
 * @param {string} [replyTo]
 * @returns {{
 *   toList: string[], ccList: string[], toAttempted: string[],
 *   toAddress: ?string, ccAddress: ?string, replyToAddress: ?string,
 *   dropped: Array<{address: string, field: string, reason: string}>
 * }}
 */
function resolveAddresses(to, cc, replyTo) {
  const dropped = [];
  // Every distinct address is judged ONCE. Without this a duplicate that fails
  // policy would be reported twice, and a duplicate that passes would be
  // delivered twice.
  const seen = new Set();

  const normalize = v => (Array.isArray(v) ? v : (v == null ? [] : [v]))
    .map(a => String(a == null ? '' : a).trim())
    .filter(Boolean);

  const admit = (list, field) => {
    const kept = [];
    for (const addr of list) {
      const key = addr.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      const verdict = checkRecipient(addr);
      if (!verdict.ok) {
        dropped.push({ address: addr, field, reason: verdict.reason });
        continue;
      }
      kept.push(addr);
    }
    return kept;
  };

  const toAttempted = normalize(to);
  const toList = admit(toAttempted, 'to');
  // Cc is admitted second so an address appearing in BOTH lands in To only —
  // nobody should receive two copies of one message.
  const ccList = admit(normalize(cc), 'cc');

  // A Reply-To that fails policy is DROPPED, never fatal. It is a courtesy
  // header: refusing to send a ticket notification because the student's own
  // address is on an unusual domain would be absurd, and MAIL_REPLY_TO is
  // still there as the fallback.
  let replyToAddress = null;
  const reply = normalize(replyTo)[0] || null;
  if (reply) {
    const verdict = checkRecipient(reply);
    if (verdict.ok) replyToAddress = reply;
    else dropped.push({ address: reply, field: 'replyTo', reason: verdict.reason });
  }

  return {
    toList,
    ccList,
    // Kept so a suppressed row can still NAME the address it could not reach.
    // statusForImport() reports per-recipient outcomes keyed on to_address, and
    // blanking it would turn "ada@x.invalid — reserved domain" into an
    // anonymous failure the instructor cannot act on.
    toAttempted,
    toAddress: toList.length ? toList.join(', ') : null,
    ccAddress: ccList.length ? ccList.join(', ') : null,
    replyToAddress,
    dropped,
  };
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
 * Does this database have the Cc columns yet?
 *
 * WHY A PROBE RATHER THAN JUST WRITING THE COLUMNS
 * ensureEmailOutbox() adds cc_address and reply_to with ADD COLUMN IF NOT
 * EXISTS at boot, and that will normally have run. Normally is not good enough
 * here. If the ALTER fails for ANY reason — the app role lacks ALTER, a
 * rollback pairs an old ensureEmailOutbox() with this code, someone restores a
 * snapshot — then an unconditional 15-column INSERT references a column that is
 * not there and EVERY email on the platform dies: activation links, password
 * resets, roster invitations, broadcasts. Worse, enqueue()'s catch block turns
 * that into a `suppressed` row, so the platform reports it has handled mail it
 * never queued. This file's header documents surviving exactly that class of
 * failure once already.
 *
 * The probe turns "all mail dies silently" into "tickets have no Cc". Cached,
 * so it costs one query per process.
 */
let _ccColumns = null;
async function ccColumnsPresent() {
  if (_ccColumns !== null) return _ccColumns;
  try {
    const r = await cybercoreQuery(
      `SELECT count(*)::int AS n
         FROM information_schema.columns
        WHERE table_name = 'cybercore_email_outbox'
          AND column_name IN ('cc_address', 'reply_to')`
    );
    _ccColumns = r.rows[0] && r.rows[0].n === 2;
    if (!_ccColumns) {
      console.warn('[mailer] cc_address/reply_to are missing from cybercore_email_outbox — '
        + 'sending without Cc or per-message Reply-To. Run migrations/034_support_tickets.sql.');
    }
  } catch (err) {
    console.warn('[mailer] Could not probe for the Cc columns:', err.message);
    _ccColumns = false;
  }
  return _ccColumns;
}

/** Test seam: forget the probe result so a migration mid-process is picked up. */
function resetCcColumnProbe() {
  _ccColumns = null;
}

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
  const key = mailKey();
  const {
    toList, toAttempted, toAddress, ccAddress, replyToAddress, dropped,
  } = resolveAddresses(msg.to, msg.cc, msg.replyTo);

  let status = 'queued';
  let reason = null;

  // A suppressed row is deliberately still written in both cases. An offline or
  // LAN-only deployment is a real way to run this platform, and the import (or
  // broadcast) report should say "email is not configured here" rather than
  // implying the mail was sent. And refusing to store a body we cannot encrypt
  // is the whole point of the key check.
  const blocked = globalSuppression();
  if (toList.length === 0) {
    status = 'suppressed';
    // The exact string checkRecipient() produced, so a single-recipient caller
    // gets byte-identically what it got before this function grew a list —
    // broadcast-audience.js promises its preview reasons match last_error.
    const first = dropped.find(d => d.field === 'to');
    reason = first ? first.reason : 'not a deliverable address';
  } else if (blocked) {
    status = 'suppressed';
    reason = blocked;
  }

  // Never null: to_address is NOT NULL, and a suppressed row must still NAME
  // the address it could not reach or the import report becomes anonymous.
  const storedTo = toAddress || toAttempted.join(', ');
  const storeBody = status === 'queued';
  const hasCc = await ccColumnsPresent();

  // Dropped Cc/Reply-To addresses are recorded rather than surfaced as an
  // error: the message itself is fine, and the ticket route wants to be able to
  // say "your instructor could not be copied, and here is why".
  const context = { ...(msg.context || {}) };
  if (dropped.some(d => d.field !== 'to')) {
    context.cc_dropped = dropped.filter(d => d.field !== 'to');
  }

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
    //
    // $1..$13 ARE FROZEN, AND THE ORDER OF THE TWO STATEMENTS BELOW MATTERS.
    // test/sql-param-typing.test.js pins the $8 cast by slicing this file
    // between the first outbox INSERT and the first RETURNING clause, so the
    // Cc-capable statement has to be the one it finds — hence Cc first, legacy
    // second. (Do not name those two marker phrases in a comment above them
    // either: the slice would start here instead of at the SQL.) Renumbering to
    // make room for cc/reply_to would defeat the very check that exists because
    // a numbering mistake here once broke every send in production, so new
    // parameters are APPENDED as $14/$15.
    const result = hasCc
      ? await cybercoreQuery(
        `INSERT INTO cybercore_email_outbox
           (to_address, to_user_id, template_key, subject,
            body_text_cipher, body_html_cipher,
            status, max_attempts, last_error, context, requested_by,
            cc_address, reply_to)
         VALUES ($1, $2, $3, $4,
                 CASE WHEN $5::boolean THEN pgp_sym_encrypt($6::text, $7::text) END,
                 CASE WHEN $5::boolean AND $8::text IS NOT NULL THEN pgp_sym_encrypt($8::text, $7::text) END,
                 $9, $10, $11, $12::jsonb, $13,
                 $14::text, $15::text)
         RETURNING email_id, status`,
        [
          storedTo, msg.toUserId || null, msg.templateKey || 'unknown', msg.subject || '(no subject)',
          storeBody, msg.text || '', key || '', msg.html || null,
          status, DEFAULT_MAX_ATTEMPTS, reason,
          JSON.stringify(context), msg.requestedBy || null,
          ccAddress, replyToAddress,
        ]
      )
      // Legacy fallback, kept verbatim. Reached only when the ALTER has not run;
      // Cc and Reply-To are silently unavailable, which is the whole point of
      // degrading here rather than failing every send.
      : await cybercoreQuery(
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
          storedTo, msg.toUserId || null, msg.templateKey || 'unknown', msg.subject || '(no subject)',
          storeBody, msg.text || '', key || '', msg.html || null,
          status, DEFAULT_MAX_ATTEMPTS, reason,
          JSON.stringify(context), msg.requestedBy || null,
        ]
      );
    return {
      email_id: result.rows[0].email_id,
      status,
      ...(reason ? { reason } : {}),
      ...(context.cc_dropped ? { cc_dropped: context.cc_dropped } : {}),
    };
  } catch (err) {
    // A queue failure must not take down the import that triggered it — the
    // accounts were already created, and losing the notification is far less
    // bad than losing the transaction.
    console.error('[mailer] Could not queue message to', storedTo, '-', err.message);
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

  // Same gate as enqueue(): selecting a column that is not there would fail the
  // claim UPDATE and stall the WHOLE queue, not just the ticket messages.
  const hasCc = await ccColumnsPresent();
  const ccColumns = hasCc ? ', cc_address, reply_to' : '';

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
      RETURNING email_id, to_address, subject, attempts, max_attempts${ccColumns},
                pgp_sym_decrypt(body_text_cipher, $2)::text AS body_text,
                CASE WHEN body_html_cipher IS NOT NULL
                     THEN pgp_sym_decrypt(body_html_cipher, $2)::text END AS body_html`,
    [limit, key]
  );

  for (const row of claimed.rows) {
    summary.attempted++;
    try {
      // The row's own Reply-To wins over the server default, which is what
      // makes "hit Reply and reach the student who filed this" work. With
      // neither set the spread is byte-identical to what it was before Cc
      // existed.
      const replyTo = row.reply_to || process.env.MAIL_REPLY_TO;
      const info = await transport().sendMail({
        from: process.env.MAIL_FROM || 'no-reply@localhost',
        ...(replyTo ? { replyTo } : {}),
        to: row.to_address,
        ...(row.cc_address ? { cc: row.cc_address } : {}),
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
    // cc/replyTo are accepted here for parity with the queue path, so a
    // diagnostic send exercises the same headers a real one will. Nothing in
    // the ticket system calls this — see the docblock above.
    const cc = message.cc ? resolveAddresses(null, message.cc).ccAddress : null;
    const replyTo = message.replyTo || process.env.MAIL_REPLY_TO;
    const info = await transport().sendMail({
      from: process.env.MAIL_FROM || 'no-reply@localhost',
      ...(replyTo ? { replyTo } : {}),
      to,
      ...(cc ? { cc } : {}),
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
 * Per-message delivery state for one ticket: the submission notification, every
 * status change, every reply.
 *
 * Same shape and the same never-return-a-body guarantee as the import and
 * campaign reports. Backed by idx_email_outbox_ticket, so this stays an index
 * scan rather than a jsonb sweep of the whole outbox.
 */
async function statusForTicket(ticketId) {
  const cc = (await ccColumnsPresent()) ? 'cc_address' : 'NULL::text AS cc_address';
  const result = await cybercoreQuery(
    `SELECT email_id, to_address, ${cc}, template_key, status, attempts,
            last_error, sent_at, created_at
       FROM cybercore_email_outbox
      WHERE context->>'ticket_id' = $1
      ORDER BY created_at`,
    [String(ticketId)]
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
    // Support tickets are the first messages here with more than one recipient:
    // To: every active admin, Cc: the course instructor, Reply-To: the student.
    // Both columns are nullable with no default, so this is a metadata-only
    // change — safe on a live table with no rewrite. Keep in sync with
    // front-end/migrations/034_support_tickets.sql.
    //
    // enqueue() and drainOutbox() BOTH probe for these rather than assuming
    // them (see ccColumnsPresent). If this ALTER fails, mail keeps flowing
    // without a Cc instead of every send dying.
    await cybercoreQuery(`ALTER TABLE cybercore_email_outbox ADD COLUMN IF NOT EXISTS cc_address TEXT`);
    await cybercoreQuery(`ALTER TABLE cybercore_email_outbox ADD COLUMN IF NOT EXISTS reply_to   TEXT`);
    await cybercoreQuery(`
      CREATE INDEX IF NOT EXISTS idx_email_outbox_ticket
        ON cybercore_email_outbox ((context->>'ticket_id'))
    `);
    // The probe is cached per process, and on a cold boot it may well have run
    // and cached `false` before the ALTER above. Clear it so the very first
    // message after boot can carry a Cc.
    resetCcColumnProbe();
    console.log('✅ Email outbox ensured');
  } catch (err) {
    console.warn('⚠️  Could not ensure email outbox:', err.message);
  }
}

/**
 * Can this platform, right now, actually deliver to this address?
 *
 * The three conditions that make an enqueue() pointless, in one call: mail is
 * off, there is no key to encrypt the body with (enqueue would accept the row and
 * then suppress it), or the policy blocks the recipient — which is how synthetic
 * @cohort.invalid addresses stay unmailed.
 *
 * Composes the existing predicates rather than restating them. The recipient
 * rules are configurable (CLE_COHORT_EMAIL_DOMAIN, MAIL_ALLOWED_RECIPIENT_DOMAINS)
 * and their reason strings are pinned by test/mailer-policy.test.js, so a second
 * copy of that logic anywhere would drift.
 */
function canSendTo(address) {
  return mailEnabled() && !!mailKey() && checkRecipient(address).ok;
}

module.exports = {
  mailEnabled, mailKey, publicUrl, siteName, canSendTo,
  transport, resetTransport,
  isInternalHost, tlsRejectUnauthorized,
  checkRecipient, allowedDomains, globalSuppression, resolveAddresses,
  ccColumnsPresent, resetCcColumnProbe,
  enqueue, enqueueMany,
  drainOutbox, requeueStalledSends, pruneOutbox,
  sendNow, sendTest,
  statusForImport, statusForCampaign, statusForTicket, recentCampaigns, queueBacklog,
  ensureEmailOutbox,
  UNDELIVERABLE_TLDS,
};
