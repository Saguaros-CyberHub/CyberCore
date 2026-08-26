/**
 * mailer-policy.test.js — the two decisions mailer.js makes before any I/O.
 *
 *   1. checkRecipient — may this address be written to at all? This is what
 *      keeps the platform's own synthetic accounts (@clinic.local from group
 *      deploy, @cohort.invalid from cohort generation) out of the relay, and
 *      what stops a mistyped roster turning the platform into a branded
 *      credential-phishing sender.
 *
 *   2. tlsRejectUnauthorized — must the relay prove who it is? The bundled
 *      Postfix container is self-signed and unreachable from outside the Docker
 *      bridge, so it cannot; a public submission relay is handed MAIL_PASSWORD
 *      over the internet, so it must.
 *
 * Both are pure reads of process.env, so neither needs a database or a relay.
 *
 * Run: node front-end/test/mailer-policy.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const path = require('path');

const mailer = require(path.join(__dirname, '..', 'src', 'utils', 'mailer'));

/** Run fn with env overrides applied, then restore exactly what was there. */
function withEnv(overrides, fn) {
  const saved = new Map();
  for (const [k, v] of Object.entries(overrides)) {
    saved.set(k, process.env[k]);
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  try {
    return fn();
  } finally {
    for (const [k, v] of saved) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

const NO_ALLOWLIST = { MAIL_ALLOWED_RECIPIENT_DOMAINS: '', CLE_COHORT_EMAIL_DOMAIN: undefined };

// ── recipient policy ─────────────────────────────────────────────────────────

test('checkRecipient: accepts an ordinary address when no allowlist is set', () => {
  withEnv(NO_ALLOWLIST, () => {
    assert.deepStrictEqual(mailer.checkRecipient('ada@example.edu'), { ok: true });
  });
});

test('checkRecipient: rejects anything that is not address-shaped', () => {
  withEnv(NO_ALLOWLIST, () => {
    for (const bad of ['', null, undefined, 'ada', 'ada@', '@example.edu', 'ada@localhost', 'a b@example.edu']) {
      assert.strictEqual(mailer.checkRecipient(bad).ok, false, `accepted ${JSON.stringify(bad)}`);
    }
  });
});

test('checkRecipient: rejects every reserved TLD', () => {
  withEnv(NO_ALLOWLIST, () => {
    for (const tld of mailer.UNDELIVERABLE_TLDS) {
      const result = mailer.checkRecipient(`student1@lab${tld}`);
      assert.strictEqual(result.ok, false, `accepted a ${tld} address`);
      assert.match(result.reason, /reserved domain/);
    }
  });
});

test('checkRecipient: rejects the synthetic addresses the platform mints itself', () => {
  withEnv(NO_ALLOWLIST, () => {
    // group deploy and profile lanes
    assert.strictEqual(mailer.checkRecipient('cybr480-student1@clinic.local').ok, false);
    // CLE cohort generation
    assert.strictEqual(mailer.checkRecipient('cybr-480-7w1-1-student7@cohort.invalid').ok, false);
  });
});

test('checkRecipient: rejects the cohort domain even when it is a real one', () => {
  // The guard is unconditional and ahead of the allowlist precisely because a
  // cohort domain pointed at something real is the dangerous misconfiguration.
  withEnv({ CLE_COHORT_EMAIL_DOMAIN: 'lab.example.edu', MAIL_ALLOWED_RECIPIENT_DOMAINS: 'example.edu' }, () => {
    const result = mailer.checkRecipient('student7@lab.example.edu');
    assert.strictEqual(result.ok, false);
    assert.match(result.reason, /credential sheet/);
  });
});

test('checkRecipient: the cohort guard is case-insensitive', () => {
  withEnv({ CLE_COHORT_EMAIL_DOMAIN: 'Cohort.Invalid', MAIL_ALLOWED_RECIPIENT_DOMAINS: '' }, () => {
    assert.strictEqual(mailer.checkRecipient('Student7@COHORT.INVALID').ok, false);
  });
});

test('checkRecipient: an allowlist admits its own domain and subdomains only', () => {
  withEnv({ MAIL_ALLOWED_RECIPIENT_DOMAINS: 'arizona.edu, email.arizona.edu', CLE_COHORT_EMAIL_DOMAIN: undefined }, () => {
    assert.strictEqual(mailer.checkRecipient('ada@arizona.edu').ok, true);
    assert.strictEqual(mailer.checkRecipient('ada@email.arizona.edu').ok, true);
    assert.strictEqual(mailer.checkRecipient('ada@cs.arizona.edu').ok, true, 'subdomain should match');

    const blocked = mailer.checkRecipient('ada@gmail.com');
    assert.strictEqual(blocked.ok, false);
    assert.match(blocked.reason, /MAIL_ALLOWED_RECIPIENT_DOMAINS/);
  });
});

test('checkRecipient: an allowlist entry cannot be matched by a lookalike suffix', () => {
  withEnv({ MAIL_ALLOWED_RECIPIENT_DOMAINS: 'arizona.edu', CLE_COHORT_EMAIL_DOMAIN: undefined }, () => {
    // notarizona.edu ends with "arizona.edu" as a string but is a different domain.
    assert.strictEqual(mailer.checkRecipient('ada@notarizona.edu').ok, false);
  });
});

test('allowedDomains: tolerates padding, empty entries and a leading @', () => {
  withEnv({ MAIL_ALLOWED_RECIPIENT_DOMAINS: ' @Arizona.edu ,, email.arizona.edu ,' }, () => {
    assert.deepStrictEqual(mailer.allowedDomains(), ['arizona.edu', 'email.arizona.edu']);
  });
});

// ── TLS policy ───────────────────────────────────────────────────────────────

test('isInternalHost: Docker service names and loopback are internal', () => {
  for (const host of ['mailrelay', 'localhost', 'mail.localhost', '127.0.0.1', '::1']) {
    assert.strictEqual(mailer.isInternalHost(host), true, `${host} should be internal`);
  }
});

test('isInternalHost: RFC 1918 literals are internal', () => {
  for (const host of ['10.0.0.5', '192.168.1.10', '172.16.0.1', '172.31.255.254']) {
    assert.strictEqual(mailer.isInternalHost(host), true, `${host} should be internal`);
  }
});

test('isInternalHost: public relays and near-miss private ranges are not', () => {
  for (const host of ['smtp.resend.com', 'smtp.gmail.com', 'mail.saguaroscyberhub.org',
    '172.15.0.1', '172.32.0.1', '11.0.0.1', '8.8.8.8', '']) {
    assert.strictEqual(mailer.isInternalHost(host), false, `${host} should NOT be internal`);
  }
});

test('tlsRejectUnauthorized: the bundled relay is exempt, a public relay is not', () => {
  withEnv({ MAIL_HOST: 'mailrelay', MAIL_TLS_INSECURE: undefined }, () => {
    assert.strictEqual(mailer.tlsRejectUnauthorized(), false,
      'the self-signed container would never deliver');
  });
  withEnv({ MAIL_HOST: 'smtp.resend.com', MAIL_TLS_INSECURE: undefined }, () => {
    assert.strictEqual(mailer.tlsRejectUnauthorized(), true,
      'MAIL_PASSWORD would be sent over an unverified connection');
  });
});

test('tlsRejectUnauthorized: MAIL_TLS_INSECURE is an explicit, exact opt-out', () => {
  withEnv({ MAIL_HOST: 'smtp.resend.com', MAIL_TLS_INSECURE: 'true' }, () => {
    assert.strictEqual(mailer.tlsRejectUnauthorized(), false);
  });
  // Anything other than the exact string must not weaken it — a stray "1" or
  // "yes" in an env file should fail closed.
  for (const value of ['1', 'yes', 'TRUE', '']) {
    withEnv({ MAIL_HOST: 'smtp.resend.com', MAIL_TLS_INSECURE: value }, () => {
      assert.strictEqual(mailer.tlsRejectUnauthorized(), true, `"${value}" weakened TLS`);
    });
  }
});

// ── enablement ───────────────────────────────────────────────────────────────

test('mailEnabled: needs both the flag and a host', () => {
  withEnv({ MAIL_ENABLED: 'true', MAIL_HOST: 'mailrelay' }, () => {
    assert.strictEqual(mailer.mailEnabled(), true);
  });
  withEnv({ MAIL_ENABLED: 'true', MAIL_HOST: undefined }, () => {
    assert.strictEqual(mailer.mailEnabled(), false);
  });
  withEnv({ MAIL_ENABLED: 'false', MAIL_HOST: 'mailrelay' }, () => {
    assert.strictEqual(mailer.mailEnabled(), false);
  });
});

test('mailKey: falls back through the other at-rest keys, then reports none', () => {
  const none = { MAIL_ENCRYPT_KEY: undefined, MFA_ENCRYPT_KEY: undefined, GUAC_ENCRYPT_KEY: undefined };
  withEnv({ ...none, MAIL_ENCRYPT_KEY: 'a' }, () => assert.strictEqual(mailer.mailKey(), 'a'));
  withEnv({ ...none, MFA_ENCRYPT_KEY: 'b' }, () => assert.strictEqual(mailer.mailKey(), 'b'));
  withEnv({ ...none, GUAC_ENCRYPT_KEY: 'c' }, () => assert.strictEqual(mailer.mailKey(), 'c'));
  withEnv(none, () => assert.strictEqual(mailer.mailKey(), null));
});

test('publicUrl: strips trailing slashes so activation links do not double up', () => {
  withEnv({ MAIL_PUBLIC_URL: 'https://example.org///' }, () => {
    assert.strictEqual(mailer.publicUrl(), 'https://example.org');
  });
  withEnv({ MAIL_PUBLIC_URL: undefined }, () => {
    assert.strictEqual(mailer.publicUrl(), '');
  });
});

// ── resolveAddresses: multi-recipient, Cc and Reply-To ──────────────────────
//
// Support tickets are the first messages this platform sends to more than one
// person. Five existing callers pass a single string and MUST be unaffected —
// that is what the first test here pins, and it is the reason resolveAddresses
// exists as a separate pure function rather than as logic inside enqueue().

test('a single string recipient behaves exactly as it did before lists existed', () => {
  // THE backward-compatibility pin. Activation links, password resets, roster
  // invitations, credential handouts and broadcasts all take this path.
  withEnv(NO_ALLOWLIST, () => {
    const out = mailer.resolveAddresses('ada@example.edu');
    assert.strictEqual(out.toAddress, 'ada@example.edu');
    assert.strictEqual(out.ccAddress, null);
    assert.strictEqual(out.replyToAddress, null);
    assert.deepStrictEqual(out.toList, ['ada@example.edu']);
    assert.deepStrictEqual(out.dropped, []);
  });
});

test('a string and a one-element array agree', () => {
  withEnv(NO_ALLOWLIST, () => {
    const a = mailer.resolveAddresses('Ada@Example.edu');
    const b = mailer.resolveAddresses(['Ada@Example.edu']);
    assert.deepStrictEqual(a, b);
    // Case is PRESERVED, not lowercased: the local part of an address is
    // case-sensitive per RFC 5321, whatever most providers do in practice.
    assert.strictEqual(a.toAddress, 'Ada@Example.edu');
  });
});

test('surrounding whitespace and empty entries are cleaned up', () => {
  withEnv(NO_ALLOWLIST, () => {
    const out = mailer.resolveAddresses(['  ada@example.edu  ', '', null, undefined]);
    assert.strictEqual(out.toAddress, 'ada@example.edu');
    assert.deepStrictEqual(out.dropped, []);
  });
});

test('several recipients are comma-joined in order, which is what nodemailer takes', () => {
  withEnv(NO_ALLOWLIST, () => {
    const out = mailer.resolveAddresses(['a@example.edu', 'b@example.edu', 'c@example.edu']);
    assert.strictEqual(out.toAddress, 'a@example.edu, b@example.edu, c@example.edu');
    assert.strictEqual(out.toList.length, 3);
  });
});

test('one blocked address is dropped and the rest still go out', () => {
  // The realistic ticket case: an admin roster where one account was created
  // with a @clinic.local synthetic address. That must not silence the ticket.
  withEnv(NO_ALLOWLIST, () => {
    const out = mailer.resolveAddresses(['a@example.edu', 'ghost@clinic.local', 'b@example.edu']);
    assert.strictEqual(out.toAddress, 'a@example.edu, b@example.edu');
    assert.strictEqual(out.dropped.length, 1);
    assert.strictEqual(out.dropped[0].address, 'ghost@clinic.local');
    assert.strictEqual(out.dropped[0].field, 'to');
    assert.match(out.dropped[0].reason, /reserved domain/);
  });
});

test('when every recipient is blocked, toAddress is null but the attempt is remembered', () => {
  // toAttempted is what keeps a suppressed row able to NAME the address it
  // could not reach — statusForImport reports per-recipient outcomes keyed on
  // to_address, and an anonymous failure is one an instructor cannot act on.
  withEnv(NO_ALLOWLIST, () => {
    const out = mailer.resolveAddresses(['ghost@clinic.local', 'other@test']);
    assert.strictEqual(out.toAddress, null);
    assert.deepStrictEqual(out.toList, []);
    assert.deepStrictEqual(out.toAttempted, ['ghost@clinic.local', 'other@test']);
    assert.strictEqual(out.dropped.length, 2);
  });
});

test('an empty or absent recipient produces the same reason it always did', () => {
  // broadcast-audience.js promises its preview reasons are byte-identical to
  // last_error, so this string is part of a contract.
  withEnv(NO_ALLOWLIST, () => {
    for (const empty of ['', '   ', null, undefined, []]) {
      const out = mailer.resolveAddresses(empty);
      assert.strictEqual(out.toAddress, null);
      assert.deepStrictEqual(out.toAttempted, []);
    }
    assert.strictEqual(mailer.checkRecipient('').reason, 'not a deliverable address');
  });
});

test('Cc is carried alongside To', () => {
  withEnv(NO_ALLOWLIST, () => {
    const out = mailer.resolveAddresses(['a@example.edu', 'b@example.edu'], 'teach@example.edu');
    assert.strictEqual(out.toAddress, 'a@example.edu, b@example.edu');
    assert.strictEqual(out.ccAddress, 'teach@example.edu');
  });
});

test('an address in both To and Cc is delivered once, from To', () => {
  // The instructor IS an admin on many small deployments. Without this they
  // receive two copies of every ticket, and Reply-All fans out further.
  withEnv(NO_ALLOWLIST, () => {
    const out = mailer.resolveAddresses(
      ['admin@example.edu', 'teach@example.edu'], 'teach@example.edu');
    assert.strictEqual(out.toAddress, 'admin@example.edu, teach@example.edu');
    assert.strictEqual(out.ccAddress, null);
  });
});

test('the To/Cc overlap check is case-insensitive', () => {
  withEnv(NO_ALLOWLIST, () => {
    const out = mailer.resolveAddresses('Teach@Example.edu', 'teach@example.EDU');
    assert.strictEqual(out.ccAddress, null);
  });
});

test('a repeated recipient is judged once and delivered once', () => {
  withEnv(NO_ALLOWLIST, () => {
    const out = mailer.resolveAddresses(['a@example.edu', 'a@example.edu', 'A@example.edu']);
    assert.strictEqual(out.toAddress, 'a@example.edu');
    // And a repeated BAD address is reported once, not three times.
    const bad = mailer.resolveAddresses(['x@clinic.local', 'x@clinic.local']);
    assert.strictEqual(bad.dropped.length, 1);
  });
});

test('a blocked Cc is dropped without suppressing the message', () => {
  // An instructor on a synthetic @cohort.invalid address must not stop the
  // admins being told about a broken machine.
  withEnv(NO_ALLOWLIST, () => {
    const out = mailer.resolveAddresses('admin@example.edu', 'ghost@clinic.local');
    assert.strictEqual(out.toAddress, 'admin@example.edu');
    assert.strictEqual(out.ccAddress, null);
    assert.strictEqual(out.dropped.length, 1);
    assert.strictEqual(out.dropped[0].field, 'cc');
  });
});

test('Reply-To is validated, and a bad one is dropped rather than fatal', () => {
  withEnv(NO_ALLOWLIST, () => {
    const good = mailer.resolveAddresses('admin@example.edu', null, 'stud@example.edu');
    assert.strictEqual(good.replyToAddress, 'stud@example.edu');
    assert.deepStrictEqual(good.dropped, []);

    // A student on a cohort-generated address: the ticket still reaches the
    // admins, it just cannot be replied to directly.
    const bad = mailer.resolveAddresses('admin@example.edu', null, 'pat@cohort.invalid');
    assert.strictEqual(bad.toAddress, 'admin@example.edu');
    assert.strictEqual(bad.replyToAddress, null);
    assert.strictEqual(bad.dropped[0].field, 'replyTo');
  });
});

test('Reply-To does not consume the address for To or Cc', () => {
  // Reply-To is a header, not a recipient — the student is not a To recipient
  // of their own ticket notification, and must not be excluded from a later
  // reply either.
  withEnv(NO_ALLOWLIST, () => {
    const out = mailer.resolveAddresses('stud@example.edu', null, 'stud@example.edu');
    assert.strictEqual(out.toAddress, 'stud@example.edu');
    assert.strictEqual(out.replyToAddress, 'stud@example.edu');
  });
});

test('the recipient allowlist applies to every field', () => {
  withEnv({ MAIL_ALLOWED_RECIPIENT_DOMAINS: 'example.edu', CLE_COHORT_EMAIL_DOMAIN: undefined }, () => {
    const out = mailer.resolveAddresses(
      ['ok@example.edu', 'no@elsewhere.org'], 'also-no@elsewhere.org', 'nope@elsewhere.org');
    assert.strictEqual(out.toAddress, 'ok@example.edu');
    assert.strictEqual(out.ccAddress, null);
    assert.strictEqual(out.replyToAddress, null);
    assert.deepStrictEqual(out.dropped.map(d => d.field).sort(), ['cc', 'replyTo', 'to']);
  });
});

test('a subdomain of an allowed domain is still allowed, in every field', () => {
  withEnv({ MAIL_ALLOWED_RECIPIENT_DOMAINS: 'example.edu', CLE_COHORT_EMAIL_DOMAIN: undefined }, () => {
    const out = mailer.resolveAddresses('a@mail.example.edu', 'b@cs.example.edu');
    assert.strictEqual(out.toAddress, 'a@mail.example.edu');
    assert.strictEqual(out.ccAddress, 'b@cs.example.edu');
  });
});

test('resolveAddresses never throws on hostile input', () => {
  withEnv(NO_ALLOWLIST, () => {
    for (const junk of [{}, 42, [[]], [{}], [Symbol.iterator ? 'a@b.co' : 'x']]) {
      assert.doesNotThrow(() => mailer.resolveAddresses(junk, junk, junk));
    }
  });
});
