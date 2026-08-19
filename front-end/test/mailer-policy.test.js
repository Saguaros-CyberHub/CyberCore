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
