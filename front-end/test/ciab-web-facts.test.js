/**
 * ciab-web-facts.test.js — the scan documents describe the lane that deploys.
 *
 * WHY THIS FILE EXISTS
 * A CIAB profile asset is {hostname, ip, subnet, role, os, function, critical}
 * and carries no service list, so ai/scan-documents/service-inference.js has to
 * guess what is listening from the hostname and the narrative. That guess runs
 * through vuln-knowledge.js's PORT_DEFAULTS, which says every :80 and every
 * :443 is Apache httpd 2.4.52 — so EVERY web host in EVERY profile got the same
 * banner, a TLS listener, POODLE, TLS 1.0, and ZAP alerts at /search?q= and
 * /login.
 *
 * The lane deploys something else entirely: an LLM-authored container (PHP,
 * Flask, Express) on ONE port, no TLS listener at all, at whatever routes the
 * model invented. A student who runs `nmap` reads about a different company
 * than the one on paper — and that is the one defect this exercise cannot
 * absorb, because the paper IS the exercise.
 *
 * `asset.web_facts` (documented in service-inference.js) is the contract the
 * vuln-app compiler will fill in. This file pins the two halves of it:
 *
 *   1. WITH facts, the documents agree with the facts — no POODLE without a TLS
 *      listener, no Apache banner on an nginx container, no alert URL pointing
 *      at a route the app does not serve.
 *   2. WITHOUT facts, nothing moved. The inference path is frozen byte for
 *      byte, because every profile generated before this contract existed still
 *      renders through it and none of them should shift by a character.
 *
 * ON THE HASHES
 * The no-facts assertions are SHA-256 snapshots of whole documents under a
 * frozen clock. A structural assertion cannot express "and nothing else
 * changed", which is the actual property being defended here. If one of them
 * fails, generate the document (see LEGACY_PROFILE below, with the same frozen
 * clock) and diff it against the previous output before touching the constant:
 * a deliberate change to the inference path is a re-snapshot, and anything else
 * is the bug this file exists to catch.
 *
 * Run: node --test front-end/test/ciab-web-facts.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const SCAN_DOCS = path.join(ROOT, 'modules/crucible/plugins/ciab/ai/scan-documents');

const {
  generateNmap,
  generateNessus,
  generateZap,
  generateScanDocuments,
  buildHostPorts
} = require(SCAN_DOCS);
const {
  inferServices,
  readWebFacts,
  normalizeTlsProtocol
} = require(path.join(SCAN_DOCS, 'service-inference'));

// ── harness ─────────────────────────────────────────────────────────────────

const sha256 = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');

/**
 * Every generator stamps `new Date().toUTCString()` into its header, so a
 * document is only byte-comparable against a clock that does not move.
 */
const RealDate = Date;
const FIXED_MS = RealDate.UTC(2024, 0, 15, 12, 0, 0);
function withFrozenClock(fn) {
  global.Date = class FrozenDate extends RealDate {
    constructor(...args) { super(...(args.length ? args : [FIXED_MS])); }
    static now() { return FIXED_MS; }
  };
  try { return fn(); } finally { global.Date = RealDate; }
}

// ── fixtures ────────────────────────────────────────────────────────────────

// A profile exactly as generation emits one today: no `services`, no facts.
// WEB-01's `function` hits the web-server inference rule, which is what puts
// 80 + 443 + Apache 2.4.52 on it.
const LEGACY_PROFILE = {
  industry: 'healthcare',
  assets: [
    { hostname: 'DC-01', role: 'server', os: 'Windows Server 2022', ip: '10.10.5.10', function: 'Domain controller' },
    { hostname: 'WEB-01', role: 'server', os: 'Ubuntu Server 22.04', ip: '10.10.5.20', function: 'Public web server' },
    { hostname: 'WS-01', role: 'workstation', os: 'Windows 11', ip: '10.10.5.100' }
  ]
};

/** The same WEB-01, but compiled — one asset so the assertions name one host. */
function factsProfile(web_facts) {
  return {
    industry: 'healthcare',
    assets: [
      { hostname: 'WEB-01', role: 'server', os: 'Ubuntu Server 22.04', ip: '10.10.5.20',
        function: 'Public web server', web_facts }
    ]
  };
}

// What the vuln-app compiler actually produces: one container, one port, no TLS.
const PLAIN_HTTP_FACTS = {
  product: 'nginx', version: '1.24.0',
  ports: [80],
  tls: { enabled: false },
  paths: ['/', '/products.php', '/cart.php']
};

// A deliberately dated host: 80 + 443, and a TLS stack old enough to be worth
// finding. This is the shape the curated-Apache role will emit.
const LEGACY_TLS_FACTS = {
  product: 'Apache httpd', version: '2.4.29',
  ports: [80, 443],
  tls: { enabled: true, port: 443, protocols: ['SSLv3', 'TLSv1.0'] },
  paths: ['/', '/search', '/login']
};

// TLS, but current. The listener is real; the 2014-era findings are not.
const MODERN_TLS_FACTS = {
  product: 'nginx', version: '1.24.0',
  ports: [80, 443],
  tls: { enabled: true, port: 443, protocols: ['TLSv1.2', 'TLSv1.3'] },
  paths: ['/']
};

const docs = (profileData, types) => withFrozenClock(() =>
  generateScanDocuments({ profileData, companyName: 'TestCo', domain: 'test.local', types }));
const doc = (profileData, type) => docs(profileData, [type])[0].content;

// ── 1. the inference path is frozen ─────────────────────────────────────────

// Regenerate with the frozen clock above if — and only if — the inference path
// changed on purpose.
const LEGACY_NMAP_SHA = 'b6e4a5f6b34dcaecb225dc7ed073cec381256baaab9e36528823a782559a5f72';
const LEGACY_NESSUS_SHA = '3809efdf83fdd82521be77c305d6886b226cbe6499711c9e019d2ea4b3028a8a';
// The ZAP snapshot is taken with the target line put BACK to https://, because
// that one line is the single intentional change to the no-facts output — see
// the test below it.
const LEGACY_ZAP_SHA = '719ed9febd39b6042460c8895d626843df42bdab95014edb333ef2b14d00ec61';

test('a profile with no web_facts renders byte-identically to the pre-contract output', () => {
  assert.strictEqual(sha256(doc(LEGACY_PROFILE, 'nmap')), LEGACY_NMAP_SHA,
    'the nmap document moved for a profile that carries no facts — the inference path is frozen');
  assert.strictEqual(sha256(doc(LEGACY_PROFILE, 'nessus')), LEGACY_NESSUS_SHA,
    'the nessus document moved for a profile that carries no facts — the inference path is frozen');

  const zap = doc(LEGACY_PROFILE, 'zap');
  const restored = zap.replace('<code>http://WEB-01.test.local</code>', '<code>https://WEB-01.test.local</code>');
  assert.strictEqual(sha256(restored), LEGACY_ZAP_SHA,
    'the zap document moved beyond the target-scheme fix');
});

test('the ZAP target line no longer contradicts the alert URLs beneath it', () => {
  // The header said https:// while every alert said http://. Both now come
  // from webBaseUrl(), so there is one answer to "what is the scheme".
  const zap = doc(LEGACY_PROFILE, 'zap');
  const urls = [...zap.matchAll(/<code>(https?:\/\/[^<]*)<\/code>/g)].map(m => m[1]);
  assert.ok(urls.length >= 5, `expected the target line plus alert URLs, got ${urls.length}`);
  const schemes = new Set(urls.map(u => u.split(':')[0]));
  assert.deepStrictEqual([...schemes], ['http'],
    'no TLS listener is inferred here, so every URL in the report must be http://');
});

// The hashes above say "nothing moved"; these say what they are holding still,
// so a re-snapshot cannot quietly drop the legacy behaviour it is protecting.
test('without facts the documents still make every legacy claim', () => {
  const nmap = doc(LEGACY_PROFILE, 'nmap');
  assert.match(nmap, /80\/tcp\s+open\s+http\s+Apache httpd 2\.4\.52/);
  assert.match(nmap, /443\/tcp\s+open\s+ssl\/http\s+Apache httpd 2\.4\.52/);

  const nessus = doc(LEGACY_PROFILE, 'nessus');
  assert.match(nessus, /SSL Version 2 and 3 Protocol Detection/);
  assert.match(nessus, /TLS Version 1\.0 Protocol Detection/);

  const zap = doc(LEGACY_PROFILE, 'zap');
  assert.match(zap, /\/search\?q=/);
  assert.match(zap, /\/login/);
  assert.match(zap, /Server: Apache\/2\.4\.52/);
});

// ── 2. facts replace the guess ──────────────────────────────────────────────

test('facts declaring port 80 only: no 443, no TLS service, no invented banner', () => {
  const ports = buildHostPorts(factsProfile(PLAIN_HTTP_FACTS).assets[0]);
  const web = ports.filter(p => p.normalized === 'http' || p.normalized === 'https');
  assert.deepStrictEqual(web.map(p => p.port), [80]);
  assert.strictEqual(web[0].normalized, 'http');
  assert.strictEqual(web[0].product, 'nginx');
  assert.strictEqual(web[0].version, '1.24.0');

  // Facts cover the web surface only — the VM's own sshd still comes from
  // inference, or a compiled host would lose services nobody asked it about.
  assert.ok(ports.some(p => p.port === 22), 'inferred SSH must survive the facts merge');

  const nmap = doc(factsProfile(PLAIN_HTTP_FACTS), 'nmap');
  assert.match(nmap, /80\/tcp\s+open\s+http\s+nginx 1\.24\.0/);
  assert.ok(!/443\/tcp/.test(nmap), 'nothing binds 443 on this lane');
  assert.ok(!nmap.includes('ssl/http'), 'there is no TLS listener to name');
  assert.ok(!nmap.includes('2.4.52'), 'the PORT_DEFAULTS Apache banner must not survive the facts');
});

test('facts with no TLS listener produce no TLS findings and no https anywhere', () => {
  const nessus = doc(factsProfile(PLAIN_HTTP_FACTS), 'nessus');
  assert.ok(!nessus.includes('SSL Version 2 and 3 Protocol Detection'),
    'POODLE claimed against a host with no TLS listener');
  assert.ok(!nessus.includes('TLS Version 1.0 Protocol Detection'),
    'TLS 1.0 claimed against a host with no TLS listener');
  // Plain-HTTP findings are untouched: the gate is about TLS, not about
  // suppressing everything the moment facts appear.
  assert.match(nessus, /HTTP TRACE \/ TRACK Methods Allowed/);

  const zap = doc(factsProfile(PLAIN_HTTP_FACTS), 'zap');
  assert.ok(!zap.includes('https://'), 'no TLS listener, so no https URL may appear');
  assert.match(zap, /<code>http:\/\/WEB-01\.test\.local<\/code>/);
});

test('ZAP alerts only name routes the facts declare', () => {
  const zap = doc(factsProfile(PLAIN_HTTP_FACTS), 'zap');
  assert.ok(!zap.includes('/search?q='), 'this app has no /search — the alert would 404');
  assert.ok(!zap.includes('/login'), 'this app has no /login — the alert would 404');
  assert.ok(!zap.includes('SQL Injection'), 'the SQLi alert lives on /search and must go with it');
  // '/' always resolves, so the two root alerts stand.
  assert.match(zap, /Missing Anti-clickjacking Header/);
  assert.match(zap, /Server: nginx\/1\.24\.0/);
  assert.ok(!zap.includes('Apache/2.4.52'), 'the Server header must match the declared product');
});

test('facts declaring 80 + 443 with SSLv3/TLS 1.0 keep the TLS findings and the https target', () => {
  const profileData = factsProfile(LEGACY_TLS_FACTS);

  const nmap = doc(profileData, 'nmap');
  assert.match(nmap, /80\/tcp\s+open\s+http\s+Apache httpd 2\.4\.29/);
  assert.match(nmap, /443\/tcp\s+open\s+ssl\/http\s+Apache httpd 2\.4\.29/);

  const nessus = doc(profileData, 'nessus');
  assert.match(nessus, /SSL Version 2 and 3 Protocol Detection/);
  assert.match(nessus, /TLS Version 1\.0 Protocol Detection/);

  const zap = doc(profileData, 'zap');
  assert.match(zap, /<code>https:\/\/WEB-01\.test\.local<\/code>/);
  assert.ok(!zap.includes('http://WEB-01'), 'the alert URLs must follow the target scheme');
  assert.match(zap, /SQL Injection/); // /search is declared here, so the alert is honest
  // "Apache httpd" is the nmap -sV spelling; a Server header says "Apache".
  assert.match(zap, /Server: Apache\/2\.4\.29/);
});

test('a real TLS listener on modern protocols keeps 443 but drops the 2014 findings', () => {
  const profileData = factsProfile(MODERN_TLS_FACTS);

  const nmap = doc(profileData, 'nmap');
  assert.match(nmap, /443\/tcp\s+open\s+ssl\/http\s+nginx 1\.24\.0/);

  const nessus = doc(profileData, 'nessus');
  assert.ok(!nessus.includes('SSL Version 2 and 3 Protocol Detection'),
    'POODLE is an SSLv2/v3 finding and neither is offered');
  assert.ok(!nessus.includes('TLS Version 1.0 Protocol Detection'),
    'TLS 1.0 is not offered');
  // The listener is real, so it is still inventoried as one — in the XML, since
  // the HTML wrapper drops severity-0 service detections as noise.
  const xml = withFrozenClock(() => generateNessus({ profileData, companyName: 'TestCo' }));
  assert.match(xml, /A nginx server is listening on port 443/);

  const zap = doc(profileData, 'zap');
  assert.match(zap, /<code>https:\/\/WEB-01\.test\.local<\/code>/);
});

// ── 3. reading the contract ─────────────────────────────────────────────────

test('readWebFacts normalizes the shapes a compiler will plausibly emit', () => {
  // Protocol spelling is not the compiler's problem: the gate that decides
  // whether POODLE is honest must not miss on 'TLS 1.0' vs 'TLSv1.0'.
  assert.strictEqual(normalizeTlsProtocol('TLS 1.0'), 'tlsv1.0');
  assert.strictEqual(normalizeTlsProtocol('tls1.0'), 'tlsv1.0');
  assert.strictEqual(normalizeTlsProtocol('TLSv1'), 'tlsv1.0');
  assert.strictEqual(normalizeTlsProtocol('SSLv3'), 'sslv3');
  assert.strictEqual(normalizeTlsProtocol('ssl_3'), 'sslv3');

  const f = readWebFacts({ web_facts: {
    product: '  Flask  ', ports: ['8080', 8080, 0, 99999],
    tls: { enabled: true, port: 8443, protocols: ['TLS 1.0'] },
    paths: ['products', '/products', ' ']
  } });
  assert.strictEqual(f.product, 'Flask');
  assert.strictEqual(f.version, '');
  // 8080 deduped, junk ports dropped, and the TLS port unioned in: a declared
  // listener is open even when `ports` forgot to say so.
  assert.deepStrictEqual(f.ports, [8080, 8443]);
  assert.strictEqual(f.tls.port, 8443);
  assert.deepStrictEqual(f.tls.protocols, ['tlsv1.0']);
  // '/' is the one route a fact block never has to spell out.
  assert.deepStrictEqual(f.paths, ['/', '/products']);
});

test('TLS with no port named lands on a declared port, never an invented 443', () => {
  // 443 is the right guess only when the compiler declared it. Defaulting to it
  // otherwise would put a listener on a port nothing binds — the exact class of
  // claim this contract exists to stop.
  const withDefault = readWebFacts({ web_facts: { ports: [80, 443], tls: { enabled: true } } });
  assert.strictEqual(withDefault.tls.port, 443);

  const oddball = readWebFacts({ web_facts: { ports: [8080], tls: { enabled: true } } });
  assert.strictEqual(oddball.tls.port, 8080);
  assert.deepStrictEqual(oddball.ports, [8080]);
});

test('a TLS block that does not say enabled:true is not a TLS listener', () => {
  // "Probably TLS" is what put POODLE on hosts that never opened 443.
  const f = readWebFacts({ web_facts: { ports: [80], tls: { protocols: ['TLSv1.0'] } } });
  assert.strictEqual(f.tls.enabled, false);
  assert.strictEqual(f.tls.port, null);
  assert.ok(!f.ports.includes(443));
});

test('malformed or empty facts fall back to inference rather than blanking the host', () => {
  for (const web_facts of [null, undefined, 'nginx', [], { ports: [] }, { ports: ['nope'] }]) {
    assert.strictEqual(readWebFacts({ web_facts }), null, `expected null for ${JSON.stringify(web_facts)}`);
  }
  // And the generator then behaves exactly as it does with no facts at all.
  const asset = { hostname: 'WEB-01', role: 'server', os: 'Ubuntu Server 22.04',
    function: 'Public web server', web_facts: { ports: [] } };
  assert.deepStrictEqual(inferServices(asset), ['80/HTTP', '443/HTTPS', '22/SSH']);
});

test('facts beat a declared services list, but only over the web ports', () => {
  // A declared list is still someone's description of the host; the facts are
  // what the compiler is about to build.
  const asset = {
    hostname: 'WEB-01', role: 'server', os: 'Ubuntu Server 22.04',
    services: ['80/HTTP', '443/HTTPS', '22/SSH', '3306/MySQL'],
    web_facts: PLAIN_HTTP_FACTS
  };
  assert.deepStrictEqual(inferServices(asset), ['22/SSH', '3306/MySQL', '80/HTTP']);
});
