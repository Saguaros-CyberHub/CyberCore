/**
 * ============================================================================
 * EMAIL TEMPLATES
 * ============================================================================
 * Pure functions: input → { subject, text, html }. No database, no network, no
 * environment reads. That is what makes them testable, and it keeps the
 * decision of WHETHER to send (mailer.js) separate from WHAT to say.
 *
 * Rules every template here follows:
 *   - Always emit a plain-text part. Some mail clients show it, some spam
 *     filters weight its absence, and it is the only part guaranteed readable.
 *   - HTML-escape every interpolated value. Names come from a CSV an instructor
 *     uploaded; treating them as markup is how a roster becomes an injection.
 *   - No external images or stylesheets. Remote content gets stripped by most
 *     clients, and a tracking-pixel-shaped request hurts deliverability.
 *   - Never put a secret in the subject line. Subjects appear in notification
 *     popups, lock screens, and mail-server logs.
 */

/** Escape for HTML text and attribute contexts. */
function esc(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** A human-friendly greeting that degrades gracefully when we have no name. */
function greeting(firstName) {
  const name = String(firstName || '').trim();
  return name ? `Hi ${name},` : 'Hi,';
}

/** "CYBR-480-7W1-1 — Intro to Cyber Ops", or whichever half we actually have. */
function courseLabel(courseName, courseCode) {
  const name = String(courseName || '').trim();
  const code = String(courseCode || '').trim();
  if (name && code && !name.includes(code)) return `${code} — ${name}`;
  return name || code || 'your course';
}

function formatExpiry(expiresAt) {
  if (!expiresAt) return null;
  const d = expiresAt instanceof Date ? expiresAt : new Date(expiresAt);
  if (Number.isNaN(d.getTime())) return null;
  return d.toUTCString();
}

/**
 * Shared HTML shell. Inline styles only — <style> blocks are stripped by
 * Gmail's web client and several others, so anything structural has to live on
 * the element itself.
 */
function shell(siteName, bodyHtml) {
  return `<!DOCTYPE html>
<html><body style="margin:0;padding:0;background:#f5f6f8;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f5f6f8;padding:24px 12px;">
    <tr><td align="center">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;background:#ffffff;border-radius:8px;padding:32px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#1f2430;font-size:15px;line-height:1.6;">
        <tr><td>
          <div style="font-size:18px;font-weight:600;color:#1f2430;margin-bottom:24px;">${esc(siteName)}</div>
          ${bodyHtml}
          <div style="margin-top:32px;padding-top:16px;border-top:1px solid #e6e8ec;font-size:12px;color:#8a90a0;">
            This message was sent by ${esc(siteName)}. If you weren't expecting it, you can ignore it.
          </div>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>`;
}

function button(url, label) {
  return `<div style="margin:28px 0;">
    <a href="${esc(url)}" style="display:inline-block;background:#2f6fed;color:#ffffff;text-decoration:none;padding:12px 24px;border-radius:6px;font-weight:600;">${esc(label)}</a>
  </div>`;
}

// ============================================================================
// TEMPLATES
// ============================================================================

/**
 * A brand-new account: here is a one-time link to choose your password.
 *
 * Note what is NOT here — a password. The link is single-use and expires, so
 * nothing that keeps working sits in the recipient's mailbox afterwards.
 */
function activation(opts = {}) {
  const {
    siteName = 'CyberHub', firstName, activationUrl,
    courseName, courseCode, instructorName, expiresAt, username,
  } = opts;

  const course = courseLabel(courseName, courseCode);
  const expiry = formatExpiry(expiresAt);
  const by = instructorName ? ` by ${instructorName}` : '';

  const subject = courseName || courseCode
    ? `Set up your ${siteName} account for ${course}`
    : `Set up your ${siteName} account`;

  const textLines = [
    greeting(firstName),
    '',
    `An account has been created for you on ${siteName}${courseName || courseCode ? ` for ${course}` : ''}${by}.`,
    '',
    'To finish setting up, choose a password using this link:',
    activationUrl,
    '',
  ];
  if (username) textLines.push(`Your username is: ${username}`, '');
  if (expiry) textLines.push(`This link can only be used once, and expires on ${expiry}.`, '');
  textLines.push(
    "If the link has expired, ask your instructor to send a new one.",
    '',
    `— ${siteName}`
  );

  const html = shell(siteName, `
    <p style="margin:0 0 16px;">${esc(greeting(firstName))}</p>
    <p style="margin:0 0 16px;">An account has been created for you on <strong>${esc(siteName)}</strong>${courseName || courseCode ? ` for <strong>${esc(course)}</strong>` : ''}${esc(by)}.</p>
    <p style="margin:0;">To finish setting up, choose a password:</p>
    ${button(activationUrl, 'Set Your Password')}
    ${username ? `<p style="margin:0 0 16px;">Your username is <strong>${esc(username)}</strong>.</p>` : ''}
    ${expiry ? `<p style="margin:0 0 16px;color:#5a6072;">This link can only be used once, and expires on <strong>${esc(expiry)}</strong>.</p>` : ''}
    <p style="margin:0 0 16px;color:#5a6072;">If the link has expired, ask your instructor to send a new one.</p>
    <p style="margin:0 0 8px;font-size:12px;color:#8a90a0;">If the button doesn't work, copy this address into your browser:<br>
      <span style="word-break:break-all;">${esc(activationUrl)}</span></p>
  `);

  return { subject, text: textLines.join('\n'), html };
}

/**
 * An existing account has been enrolled in a course. Carries no credential —
 * this person already has one — so it is purely a notification.
 */
function courseAdded(opts = {}) {
  const {
    siteName = 'CyberHub', publicUrl, firstName,
    courseName, courseCode, instructorName,
  } = opts;

  const course = courseLabel(courseName, courseCode);
  const by = instructorName ? ` by ${instructorName}` : '';
  const subject = `You've been added to ${course}`;

  const text = [
    greeting(firstName),
    '',
    `You've been added to ${course} on ${siteName}${by}.`,
    '',
    'Sign in with your existing account to see it on your dashboard:',
    publicUrl || '',
    '',
    'Your password has not changed.',
    '',
    `— ${siteName}`,
  ].join('\n');

  const html = shell(siteName, `
    <p style="margin:0 0 16px;">${esc(greeting(firstName))}</p>
    <p style="margin:0 0 16px;">You've been added to <strong>${esc(course)}</strong> on ${esc(siteName)}${esc(by)}.</p>
    <p style="margin:0;">Sign in with your existing account to see it on your dashboard:</p>
    ${publicUrl ? button(publicUrl, 'Go to ' + siteName) : ''}
    <p style="margin:0 0 16px;color:#5a6072;">Your password has not changed.</p>
  `);

  return { subject, text, html };
}

/**
 * A password was issued or regenerated for an account by staff.
 *
 * This is the fallback path, used when activation links are unavailable — it
 * does put a working credential in a mailbox, which is why it leads with the
 * instruction to change it and why the caller pairs it with a short expiry.
 */
function credentialsIssued(opts = {}) {
  const {
    siteName = 'CyberHub', publicUrl, firstName,
    username, password, expiresAt, courseName, courseCode,
  } = opts;

  const course = courseLabel(courseName, courseCode);
  const expiry = formatExpiry(expiresAt);
  // No credential in the subject line — subjects surface on lock screens.
  const subject = `Your temporary ${siteName} password`;

  const textLines = [
    greeting(firstName),
    '',
    `A temporary password has been set for your ${siteName} account${courseName || courseCode ? ` for ${course}` : ''}.`,
    '',
    `Username: ${username}`,
    `Temporary password: ${password}`,
    '',
    "You'll be asked to choose your own password the first time you sign in.",
  ];
  if (expiry) textLines.push('', `This temporary password stops working on ${expiry}.`);
  if (publicUrl) textLines.push('', `Sign in: ${publicUrl}`);
  textLines.push('', `— ${siteName}`);

  const html = shell(siteName, `
    <p style="margin:0 0 16px;">${esc(greeting(firstName))}</p>
    <p style="margin:0 0 16px;">A temporary password has been set for your ${esc(siteName)} account${courseName || courseCode ? ` for <strong>${esc(course)}</strong>` : ''}.</p>
    <table role="presentation" cellpadding="0" cellspacing="0" style="margin:0 0 16px;background:#f5f6f8;border-radius:6px;padding:16px;width:100%;">
      <tr><td style="font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:14px;">
        Username: <strong>${esc(username)}</strong><br>
        Temporary password: <strong>${esc(password)}</strong>
      </td></tr>
    </table>
    <p style="margin:0 0 16px;">You'll be asked to choose your own password the first time you sign in.</p>
    ${expiry ? `<p style="margin:0 0 16px;color:#5a6072;">This temporary password stops working on <strong>${esc(expiry)}</strong>.</p>` : ''}
    ${publicUrl ? button(publicUrl, 'Sign In') : ''}
  `);

  return { subject, text: textLines.join('\n'), html };
}

/** Proves the relay works end to end, for POST /api/admin/mail/test. */
function testMessage(opts = {}) {
  const { siteName = 'CyberHub', publicUrl } = opts;
  return {
    subject: `${siteName} mail test`,
    text: [
      'This is a test message from ' + siteName + '.',
      '',
      'If you are reading it, the app reached the SMTP relay and the relay delivered it.',
      publicUrl ? '' : null,
      publicUrl || null,
    ].filter(v => v !== null).join('\n'),
    html: shell(siteName, `
      <p style="margin:0 0 16px;">This is a test message from <strong>${esc(siteName)}</strong>.</p>
      <p style="margin:0;color:#5a6072;">If you're reading it, the app reached the SMTP relay and the relay delivered it.</p>
    `),
  };
}

const TEMPLATES = { activation, courseAdded, credentialsIssued, testMessage };

module.exports = { ...TEMPLATES, TEMPLATE_KEYS: Object.keys(TEMPLATES), esc, courseLabel };
