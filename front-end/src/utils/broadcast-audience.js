/**
 * ============================================================================
 * BROADCAST AUDIENCE
 * ============================================================================
 * Turns "all active students, plus these four people, plus this pasted list"
 * into a concrete, deduplicated set of recipients — split into the ones that
 * will actually be mailed and the ones that will not, each with the reason.
 *
 * That split is the whole point. An admin about to mail four hundred people is
 * entitled to know the exact number before they commit, and "3 of these cannot
 * be reached, here is why" is far more useful than silently sending 397. The
 * reasons come from mailer.checkRecipient() and mailer.globalSuppression(), not
 * from a second copy of the policy living here, so what the preview says is
 * byte-identical to what enqueue() will write to last_error.
 *
 * WHY SO MUCH OF THIS IS PURE
 * Everything interesting — whitelisting, address parsing, deduplication,
 * precedence, the policy split, the fingerprint — is a pure function taking
 * rows. Only resolveAudience() touches the database. This is what lets the
 * rules that matter be tested without a Postgres instance, in the same way
 * mailer-policy.test.js tests the recipient policy.
 */

const crypto = require('crypto');
const { cybercoreQuery } = require('./cybercore-db');
const { normalizeEmail, legacyNormalizeEmail, isEmailShaped } = require('./email-normalize');
const { findUsersByEmails, VALID_ROLES } = require('./account-provisioning');
const mailer = require('./mailer');

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** The two states an admin may filter on. Anything else means "don't filter". */
const ACTIVITY_STATES = ['active', 'inactive'];

// Generous enough that no real audience hits them, small enough that a paste
// accident cannot turn into an unbounded query parameter.
const MAX_PICKED = 5000;
const MAX_PASTED = 5000;

// ============================================================================
// SPEC NORMALIZATION (pure)
// ============================================================================

function uniqSorted(values) {
  return [...new Set(values)].sort();
}

/**
 * Split a pasted blob into addresses.
 *
 * Accepts a string or an array, because the textarea sends one and a future
 * caller may well send the other. Splits on commas, semicolons and any
 * whitespace, which covers every way a roster gets copied out of a spreadsheet,
 * a mail client, or a chat message.
 *
 * @returns {{addresses: string[], invalid: string[]}}
 */
function parseAddressList(raw) {
  const blob = Array.isArray(raw) ? raw.join('\n') : String(raw ?? '');
  const tokens = blob.split(/[,;\s]+/).map(t => t.trim()).filter(Boolean);

  const addresses = [];
  const invalid = [];
  for (const token of tokens) {
    // Shape first, then canonical form: normalizeEmail() only trims and
    // lowercases, so it will happily return "not an address" unchanged.
    if (!isEmailShaped(token)) { invalid.push(token); continue; }
    const normalized = normalizeEmail(token);
    if (normalized) addresses.push(normalized);
  }
  return { addresses: uniqSorted(addresses), invalid: uniqSorted(invalid) };
}

/**
 * Canonical form of an audience request.
 *
 * Deterministic on purpose — sorted, lowercased, de-duplicated — because the
 * preview/send fingerprint hashes it. Two spellings of the same audience must
 * produce the same bytes or an admin gets a spurious 409 on confirm.
 *
 * Values that cannot be used are not silently dropped: they come back under
 * `rejected` so the caller can tell the admin which of their picks went
 * nowhere. A silently ignored user id is how someone finds out a month later
 * that a student never got the announcement.
 */
function normalizeSpec(raw = {}) {
  const roles = uniqSorted(
    (Array.isArray(raw.roles) ? raw.roles : [])
      .map(r => String(r ?? '').trim().toLowerCase())
      .filter(r => VALID_ROLES.includes(r))
  );

  const activity = ACTIVITY_STATES.includes(raw.activity) ? raw.activity : null;

  const organizations = uniqSorted(
    (Array.isArray(raw.organizations) ? raw.organizations : [])
      .map(o => String(o ?? '').trim().toLowerCase())
      .filter(Boolean)
  );

  // Validated in JS rather than handed to Postgres: `= ANY($1::uuid[])` raises
  // 22P02 on a malformed id, which would turn one typo into a 500.
  const rawIds = (Array.isArray(raw.userIds) ? raw.userIds : [])
    .map(v => String(v ?? '').trim())
    .filter(Boolean)
    .slice(0, MAX_PICKED);
  const userIds = uniqSorted(rawIds.filter(v => UUID_RE.test(v)).map(v => v.toLowerCase()));
  const invalidIds = uniqSorted(rawIds.filter(v => !UUID_RE.test(v)));

  const parsed = parseAddressList(raw.addresses);

  return {
    roles,
    activity,
    organizations,
    userIds,
    addresses: parsed.addresses.slice(0, MAX_PASTED),
    excludeSelf: raw.excludeSelf === true,
    rejected: { userIds: invalidIds, addresses: parsed.invalid },
  };
}

/** True when the spec names nobody at all — which must be an error, not "everyone". */
function isEmptySpec(spec) {
  return !spec.roles.length
    && !spec.organizations.length
    && !spec.activity
    && !spec.userIds.length
    && !spec.addresses.length;
}

// ============================================================================
// QUERIES (pure builders)
// ============================================================================

/**
 * The role/organization/status filter, or null when the admin set none of them.
 *
 * `status NOT IN ('deleted','banned')` is unconditional and cannot be relaxed
 * by any filter. Un-ticking "only active accounts" means "include suspended and
 * inactive people", never "mail the accounts we removed" — a deleted account's
 * mailbox may well belong to someone who has left the institution.
 *
 * On `active` vs `status`: both columns are real and both are maintained (the
 * one writer, admin/groups.js, sets them in lockstep). Rather than pick a
 * winner, this requires BOTH for "active" and accepts EITHER for "inactive",
 * which is the conservative reading in each direction.
 */
function buildFilterQuery(spec) {
  if (!spec.roles.length && !spec.organizations.length && !spec.activity) return null;

  return {
    text: `SELECT user_id, email, first_name, last_name, role, organization, active, status
             FROM cybercore_user
            WHERE status NOT IN ('deleted', 'banned')
              AND ($1::text[] IS NULL OR role = ANY($1::text[]))
              AND ($2::text[] IS NULL OR lower(organization) = ANY($2::text[]))
              AND ($3::text IS NULL
                   OR ($3 = 'active'   AND active = TRUE AND status = 'active')
                   OR ($3 = 'inactive' AND (active = FALSE OR status <> 'active')))
            ORDER BY lower(email)`,
    params: [
      spec.roles.length ? spec.roles : null,
      spec.organizations.length ? spec.organizations : null,
      spec.activity,
    ],
  };
}

/**
 * Hand-picked accounts. Deliberately does NOT apply the role/status filter —
 * picking someone by name means picking them — but keeps the hard block, so
 * there is no path at all to a deleted or banned mailbox.
 */
function buildPickedQuery(spec) {
  if (!spec.userIds.length) return null;
  return {
    text: `SELECT user_id, email, first_name, last_name, role, organization, active, status
             FROM cybercore_user
            WHERE user_id = ANY($1::uuid[])
              AND status NOT IN ('deleted', 'banned')`,
    params: [spec.userIds],
  };
}

// ============================================================================
// COMBINING (pure)
// ============================================================================

function toRecipient(row) {
  return {
    user_id: row.user_id || null,
    email: normalizeEmail(row.email),
    first_name: row.first_name || null,
    last_name: row.last_name || null,
    role: row.role || null,
    organization: row.organization || null,
    active: typeof row.active === 'boolean' ? row.active : null,
    status: row.status || null,
  };
}

/** An address that matched no account. Mailable, just nameless. */
function anonymousRecipient(email) {
  return {
    user_id: null, email, first_name: null, last_name: null,
    role: null, organization: null, active: null, status: null,
  };
}

/**
 * Merge the three sources into one recipient per mailbox.
 *
 * Precedence is first-group-wins, and the caller passes them filter → picked →
 * pasted, so a real account row (which carries a first name for the greeting)
 * always beats a bare pasted address for the same person. Getting this
 * backwards would mail "Hi," to people the platform knows by name.
 */
function dedupeRecipients(groups) {
  const byEmail = new Map();
  const sources = {};
  let duplicatesRemoved = 0;

  for (const { source, rows } of groups) {
    sources[source] = 0;
    for (const row of rows || []) {
      const key = normalizeEmail(row.email);
      if (!key) continue;
      sources[source]++;
      if (byEmail.has(key)) { duplicatesRemoved++; continue; }
      byEmail.set(key, { ...row, email: key, source });
    }
  }

  return { recipients: [...byEmail.values()], duplicatesRemoved, sources };
}

/**
 * Split recipients into "will be mailed" and "will not, because…".
 *
 * The per-recipient check runs BEFORE the server-wide one, matching the order
 * inside enqueue(): when both apply, the specific reason ("reserved domain that
 * cannot receive mail") tells the admin more than the general one.
 */
function splitByPolicy(recipients, checkFn, globalReason = null) {
  const deliverable = [];
  const suppressed = [];

  for (const recipient of recipients) {
    const verdict = checkFn(recipient.email);
    if (!verdict.ok) {
      suppressed.push({ ...recipient, reason: verdict.reason });
    } else if (globalReason) {
      suppressed.push({ ...recipient, reason: globalReason });
    } else {
      deliverable.push(recipient);
    }
  }

  return { deliverable, suppressed };
}

/**
 * Collapse suppressed recipients into "47 × reserved domain that cannot receive
 * mail", with a few examples each. Four hundred individually-listed rows is not
 * a report anybody reads.
 */
function groupSuppressionReasons(suppressed, sampleSize = 5) {
  const byReason = new Map();
  for (const item of suppressed || []) {
    const reason = item.reason || 'unknown';
    if (!byReason.has(reason)) byReason.set(reason, { reason, count: 0, examples: [] });
    const group = byReason.get(reason);
    group.count++;
    if (group.examples.length < sampleSize) group.examples.push(item.email);
  }
  return [...byReason.values()].sort((a, b) => b.count - a.count);
}

/**
 * How many rows disagree with themselves about being active. Surfaced as a
 * preview warning rather than hidden: the two columns are redundant, and a
 * divergence means something wrote one without the other.
 */
function divergenceCount(rows) {
  return (rows || []).filter(
    r => typeof r.active === 'boolean' && r.status && r.active !== (r.status === 'active')
  ).length;
}

/**
 * A hash of exactly what the admin was shown: the audience request, the set of
 * addresses it resolved to, and the message itself.
 *
 * /send recomputes this and refuses on a mismatch. A recipient COUNT would not
 * be enough — one account created and one deactivated between preview and
 * confirm leaves the count identical while changing who gets mailed. Folding
 * the message in closes the other half of the window: previewing, editing the
 * subject, then confirming would otherwise send copy nobody reviewed.
 */
function fingerprint(spec, emails, message = {}) {
  const canonicalSpec = JSON.stringify({
    roles: spec.roles,
    activity: spec.activity,
    organizations: spec.organizations,
    userIds: spec.userIds,
    addresses: spec.addresses,
    excludeSelf: !!spec.excludeSelf,
  });
  const canonicalMessage = JSON.stringify({
    subject: String(message.subject ?? '').trim(),
    bodyText: String(message.bodyText ?? ''),
    buttonLabel: String(message.buttonLabel ?? '').trim(),
    buttonUrl: String(message.buttonUrl ?? '').trim(),
    includeGreeting: message.includeGreeting !== false,
  });

  return crypto.createHash('sha256')
    .update(canonicalSpec).update('\n')
    .update([...emails].sort().join('\n')).update('\n')
    .update(canonicalMessage)
    .digest('hex');
}

// ============================================================================
// RESOLUTION (the one function that touches the database)
// ============================================================================

/**
 * Turn pasted addresses into recipients, preferring the account behind them.
 *
 * Hydrating first matters: a pasted address that belongs to someone already in
 * the filtered audience must collapse into that one recipient, or they get two
 * copies — one greeted by name and one not.
 *
 * The legacy pass exists because accounts created before the Phase-0 email fix
 * are STORED in validator's aggressive form, so `first.last@gmail.com` is on
 * disk as `firstlast@gmail.com` (see email-normalize.js). Without the retry, an
 * admin pasting the address as the student writes it misses the account row and
 * the platform mails the same mailbox twice. routes/auth.js already does this
 * on the login path for the same reason.
 */
async function hydratePastedAddresses(addresses) {
  if (!addresses.length) return [];

  const recipients = [];
  const misses = [];

  const found = await findUsersByEmails(addresses);
  for (const address of addresses) {
    const hit = found.get(address);
    if (hit) recipients.push(toRecipient(hit));
    else misses.push(address);
  }

  if (misses.length) {
    const legacyToOriginal = new Map();
    for (const address of misses) {
      const legacy = legacyNormalizeEmail(address);
      if (legacy && legacy !== address) legacyToOriginal.set(legacy, address);
    }

    if (legacyToOriginal.size) {
      const legacyFound = await findUsersByEmails([...legacyToOriginal.keys()]);
      for (const [legacy, original] of legacyToOriginal) {
        const hit = legacyFound.get(legacy);
        if (!hit) continue;
        // Keep the STORED address, not the pasted one — it is what the filter
        // rows carry, so the dedupe below can see they are the same person.
        recipients.push(toRecipient(hit));
        misses.splice(misses.indexOf(original), 1);
      }
    }
  }

  for (const address of misses) recipients.push(anonymousRecipient(address));
  return recipients;
}

/**
 * Resolve an audience request into deliverable and suppressed recipients.
 *
 * Never throws for a policy reason and never partially applies anything — this
 * is a read. The caller gets `errors` (which must block a send) and `warnings`
 * (which must not) separately.
 *
 * @param {object} rawSpec
 * @param {{selfUserId?: string}} opts
 */
async function resolveAudience(rawSpec, opts = {}) {
  const spec = normalizeSpec(rawSpec);
  const errors = [];
  const warnings = [];

  for (const bad of spec.rejected.userIds) errors.push(`"${bad}" is not a valid user id.`);
  for (const bad of spec.rejected.addresses) errors.push(`"${bad}" is not a valid email address.`);

  if (isEmptySpec(spec)) {
    errors.push('Choose an audience first — pick at least one role or status filter, select users, or paste addresses.');
    return emptyResult(spec, errors, warnings);
  }

  const filterQuery = buildFilterQuery(spec);
  const pickedQuery = buildPickedQuery(spec);

  const [filterRes, pickedRes, pastedRows] = await Promise.all([
    filterQuery ? cybercoreQuery(filterQuery.text, filterQuery.params) : Promise.resolve({ rows: [] }),
    pickedQuery ? cybercoreQuery(pickedQuery.text, pickedQuery.params) : Promise.resolve({ rows: [] }),
    hydratePastedAddresses(spec.addresses),
  ]);

  const filterRows = filterRes.rows.map(toRecipient);
  const pickedRows = pickedRes.rows.map(toRecipient);

  // A pick that resolved to nothing is an error, not a silent omission.
  if (spec.userIds.length && pickedRows.length < spec.userIds.length) {
    const returned = new Set(pickedRes.rows.map(r => String(r.user_id)));
    for (const id of spec.userIds) {
      if (!returned.has(id)) errors.push(`Selected account ${id} no longer exists, or has been deleted or banned.`);
    }
  }

  let { recipients, duplicatesRemoved, sources } = dedupeRecipients([
    { source: 'filter', rows: filterRows },
    { source: 'picked', rows: pickedRows },
    { source: 'pasted', rows: pastedRows },
  ]);

  const selfUserId = opts.selfUserId ? String(opts.selfUserId) : null;
  const selfIncluded = !!selfUserId && recipients.some(r => String(r.user_id) === selfUserId);
  if (selfIncluded && spec.excludeSelf) {
    recipients = recipients.filter(r => String(r.user_id) !== selfUserId);
  }

  // Server-wide block first, so an unconfigured server previews honestly as
  // "0 deliverable" instead of promising a send that enqueue() will suppress.
  const globalReason = mailer.globalSuppression();
  const { deliverable, suppressed } = splitByPolicy(recipients, mailer.checkRecipient, globalReason);

  if (globalReason) warnings.push(`Nothing will be sent: ${globalReason}.`);

  const allowed = mailer.allowedDomains();
  if (allowed.length) {
    warnings.push(
      `This server only delivers to ${allowed.join(', ')} (MAIL_ALLOWED_RECIPIENT_DOMAINS). Everyone else is suppressed.`
    );
  }

  if (duplicatesRemoved > 0) {
    warnings.push(`${duplicatesRemoved} duplicate ${duplicatesRemoved === 1 ? 'address was' : 'addresses were'} collapsed — nobody receives two copies.`);
  }

  const divergent = divergenceCount(recipients);
  if (divergent > 0) {
    warnings.push(`${divergent} account(s) disagree between their \`active\` flag and their \`status\` — check them if the count looks wrong.`);
  }

  const nameless = deliverable.filter(r => !r.first_name).length;
  if (nameless > 0) {
    warnings.push(`${nameless} of ${deliverable.length} recipients have no first name on file; they will be greeted with a plain "Hi,".`);
  }

  return {
    spec,
    recipients,
    deliverable,
    suppressed,
    suppressionReasons: groupSuppressionReasons(suppressed),
    sources,
    duplicatesRemoved,
    selfIncluded,
    fingerprint: fingerprint(spec, deliverable.map(r => r.email), rawSpec.message || {}),
    errors,
    warnings,
  };
}

function emptyResult(spec, errors, warnings) {
  return {
    spec,
    recipients: [],
    deliverable: [],
    suppressed: [],
    suppressionReasons: [],
    sources: {},
    duplicatesRemoved: 0,
    selfIncluded: false,
    fingerprint: null,
    errors,
    warnings,
  };
}

module.exports = {
  // pure
  parseAddressList, normalizeSpec, isEmptySpec,
  buildFilterQuery, buildPickedQuery,
  toRecipient, anonymousRecipient,
  dedupeRecipients, splitByPolicy, groupSuppressionReasons, divergenceCount,
  fingerprint,
  // impure
  hydratePastedAddresses, resolveAudience,
  // constants
  ACTIVITY_STATES, MAX_PICKED, MAX_PASTED,
};
