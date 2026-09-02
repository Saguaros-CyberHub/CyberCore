/**
 * ============================================================================
 * CALDERA AUTHORING — THE CONTAINER AND THE EDGE
 * ============================================================================
 *
 * ############################################################################
 * # NOTHING HERE HAS EVER BEEN BUILT OR RUN.                                 #
 * #                                                                          #
 * # No Docker daemon is contacted, no Caddy is started, no Caldera is         #
 * # reached. These are SOURCE-TEXT GATES over four real files:               #
 * #     docker-compose.yml                                                    #
 * #     config/caddy/Caddyfile                                                #
 * #     infrastructure/caldera/Dockerfile                                     #
 * #     infrastructure/caldera/conf/local.yml                                 #
 * # They cannot prove the stack works. They CAN prove that the three          #
 * # properties the whole design rests on have not been edited away.           #
 * ############################################################################
 *
 * WHAT THE DESIGN RESTS ON, AND WHY EACH NEEDS A TEST
 * ----------------------------------------------------------------------------
 *  1. THE CONTAINER PUBLISHES NO PORTS. The authoring console is reachable only
 *     through Caddy, and that is true because docker-compose.yml has no `ports:`
 *     key for the caldera service — a property expressed BY AN ABSENCE, which is
 *     the one kind of property a reviewer never notices going missing. Someone
 *     debugging at 2am adds `- "127.0.0.1:8888:8888"`, it works, it ships, and
 *     an adversary authoring console whose login form accepts no password is
 *     now reachable from every lab subnet. §1 fails on that line.
 *
 *  2. EVERY /caldera HANDLE CARRIES BOTH THE GATE AND THE HEADER STRIP. Caddy
 *     advisory GHSA-7r4p-vjf4-gxv4: forward_auth's copy_headers does NOT remove
 *     the CLIENT's copy of a copied header, so a 2xx with no header set forwards
 *     whatever the browser sent. The Caddyfile deletes the identity headers
 *     inbound, before the gate, inside a `route` so that the order is the
 *     written order. §2 asserts that PER SITE BLOCK — not once per file —
 *     because the documented fix for the SPA-subpath problem is "add a third
 *     site block", and a third block that copies the reverse_proxy but not the
 *     route is the exact accident this file exists to prevent.
 *
 *  3. THE BUILD IS PINNED AND RECURSIVE. Caldera's plugins are git SUBMODULES;
 *     a clone without --recursive yields a server with no UI and no abilities,
 *     which presents as a proxy fault. And a floating version — or a floating
 *     `caddy:2-alpine` — lets upstream behaviour that these mitigations are
 *     written against change with no diff to review. §3 and §4 pin both.
 *
 * WHY REAL PARSERS AND NOT REGEX OVER EXPECTED TEXT
 * ----------------------------------------------------------------------------
 * A test that greps for the string it expects passes when someone pastes that
 * string into a COMMENT, and fails when someone reformats the file it is
 * guarding. Both are wrong. So each section below parses the file's actual
 * structure — indentation blocks for YAML, brace balance for the Caddyfile,
 * instruction folding for the Dockerfile — with comments removed FIRST, so a
 * property that is merely described cannot satisfy an assertion, and a property
 * that is real survives being reindented.
 *
 * Run: node --test front-end/test/caldera-container-config.test.js
 * ============================================================================
 */

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');            // front-end/
const REPO = path.join(ROOT, '..');                 // repository root
const COMPOSE = path.join(REPO, 'docker-compose.yml');
const CADDYFILE = path.join(REPO, 'config', 'caddy', 'Caddyfile');
const CALDERA_DIR = path.join(REPO, 'infrastructure', 'caldera');
const DOCKERFILE = path.join(CALDERA_DIR, 'Dockerfile');
const CALDERA_CONF = path.join(CALDERA_DIR, 'conf', 'local.yml');

const read = (p) => fs.readFileSync(p, 'utf8');

// ---------------------------------------------------------------------------
// A tiny indentation reader for docker-compose.yml
// ---------------------------------------------------------------------------
// Not a YAML parser and not trying to be: it answers "which keys does this
// mapping actually declare", which is the only question §1 asks. Deliberately
// literal about two things:
//
//   - ONLY WHOLE-LINE COMMENTS ARE REMOVED. A trailing `#` inside a quoted
//     value ("0.0.0.0:5432:5432") must not be treated as a comment, and a
//     commented-out `# ports:` must not count as a declared key. Dropping only
//     lines whose first non-space character is `#` gets both right.
//   - INDENT IS COLUMNS, NOT NESTING DEPTH. compose files here are 2-space
//     indented throughout; a service is at 2, its keys at 4.

/** Column of the first non-space character, or null for a blank/comment line. */
function indentOf(line) {
  if (!line || !line.trim() || line.trim().startsWith('#')) return null;
  return line.length - line.trimStart().length;
}

/** Split into lines with whole-line comments and blanks dropped. */
function significantLines(src) {
  return src.split(/\r?\n/).filter((l) => indentOf(l) !== null);
}

/**
 * The lines nested under `lines[i]` — everything more deeply indented, stopping
 * at the first line back at or left of the header's own column.
 */
function childLines(lines, i) {
  const base = indentOf(lines[i]);
  const out = [];
  for (let j = i + 1; j < lines.length; j++) {
    if (indentOf(lines[j]) <= base) break;
    out.push(lines[j]);
  }
  return out;
}

/** Index of the line declaring `key:` at exactly column `col`, or -1. */
function findKeyLine(lines, key, col) {
  const re = new RegExp(`^${key}\\s*:`);
  for (let i = 0; i < lines.length; i++) {
    if (indentOf(lines[i]) === col && re.test(lines[i].trim())) return i;
  }
  return -1;
}

/** The block of lines under `key:` at column `col`. Throws if the key is absent. */
function blockUnder(lines, key, col, what) {
  const i = findKeyLine(lines, key, col);
  assert.notStrictEqual(i, -1, `${what}: no \`${key}:\` at indent ${col}`);
  return childLines(lines, i);
}

/** The keys a mapping declares directly, at column `col`. */
function directKeys(lines, col) {
  const keys = [];
  for (const line of lines) {
    if (indentOf(line) !== col) continue;
    const m = line.trim().match(/^([A-Za-z_][\w.-]*)\s*:/);
    if (m) keys.push(m[1]);
  }
  return keys;
}

/** The scalar value of `key:` at column `col`, trimmed of quotes. */
function scalarAt(lines, key, col) {
  const i = findKeyLine(lines, key, col);
  if (i === -1) return null;
  const v = lines[i].trim().slice(lines[i].trim().indexOf(':') + 1).trim();
  return v.replace(/^["']|["']$/g, '');
}

/** The `- item` entries of a sequence under `key:` at column `col`. */
function sequenceUnder(lines, key, col, what) {
  return blockUnder(lines, key, col, what)
    .map((l) => l.trim())
    .filter((l) => l.startsWith('- '))
    .map((l) => l.slice(2).trim().replace(/^["']|["']$/g, ''));
}

/** The block of lines for one compose service. */
function composeService(name) {
  const lines = significantLines(read(COMPOSE));
  const services = blockUnder(lines, 'services', 0, 'docker-compose.yml');
  return blockUnder(services, name, 2, `docker-compose.yml service ${name}`);
}

// ---------------------------------------------------------------------------
// §1 The container: no ports, one network, one named volume
// ---------------------------------------------------------------------------

test('THE POINT OF THIS FILE: the caldera service publishes NO host ports', () => {
  const svc = composeService('caldera');
  const keys = directKeys(svc, 4);

  // The assertion the whole placement rests on. If this fails, someone added a
  // `ports:` mapping and the console is no longer reachable only through Caddy:
  // it is reachable from the host, and — because the compose bridge binds on
  // 0.0.0.0 unless told otherwise — from every lab subnet that can route to the
  // orchestrator. Caldera's own login form accepts no password, so the gate in
  // the Caddyfile is the ONLY thing standing there. Delete the ports line; do
  // not relax this test.
  assert.ok(
    !keys.includes('ports'),
    'docker-compose.yml: the caldera service declares `ports:`. It must not. '
    + 'With no port binding the container is unreachable except through Caddy, '
    + 'which runs forward_auth first — that is a structural control with no '
    + 'firewall rule to keep correct. Use `docker compose exec caldera sh` for '
    + 'debugging instead.'
  );

  // The service this one is modelled on, asserted alongside so the pattern is
  // visible in the failure output rather than only in a comment.
  assert.ok(
    !directKeys(composeService('guacamole'), 4).includes('ports'),
    'docker-compose.yml: guacamole grew a `ports:` key — the internal-only '
    + 'pattern caldera copies is no longer being followed'
  );
});

test('a `ports:` mutation on the caldera service is actually caught', () => {
  // Proves the parser above sees a REAL key rather than matching text: the same
  // reader, run over a mutated copy of the file, must report `ports` present.
  // Without this, §1 could be passing because the parser never finds anything.
  // `\r?\n` because this repository is developed on Windows with
  // core.autocrlf=true, so the working tree carries CRLF and a `\n`-only anchor
  // matches nothing — which would make this proof silently vacuous.
  const original = read(COMPOSE);
  const mutated = original.replace(
    /^(  caldera:\r?\n)/m,
    '$1    ports:\n      - "0.0.0.0:8888:8888"\n'
  );
  assert.ok(mutated !== original, 'the mutation did not apply — the caldera service moved?');

  const lines = significantLines(mutated);
  const services = blockUnder(lines, 'services', 0, 'mutated compose');
  const svc = blockUnder(services, 'caldera', 2, 'mutated compose');
  assert.ok(
    directKeys(svc, 4).includes('ports'),
    'the no-ports test would not notice a ports: key being added — fix the parser, not the assertion'
  );

  // And the inverse: a COMMENTED-OUT ports key must not count as declared,
  // or the guard becomes unfalsifiable and every comment about ports fails it.
  const commented = original.replace(
    /^(  caldera:\r?\n)/m,
    '$1    # ports:  <- deliberately absent, see the comment above\n'
  );
  const cLines = significantLines(commented);
  const cSvc = blockUnder(blockUnder(cLines, 'services', 0, 'x'), 'caldera', 2, 'x');
  assert.ok(!directKeys(cSvc, 4).includes('ports'), 'a commented-out ports key must not count');
});

test('caldera sits on cybercore-net and nowhere else', () => {
  const svc = composeService('caldera');
  const nets = sequenceUnder(svc, 'networks', 4, 'caldera service');
  assert.deepStrictEqual(
    nets, ['cybercore-net'],
    'caldera must be on the single internal bridge, exactly like guacamole — '
    + 'a second network is another way for something to reach it'
  );
});

test('authored content survives a rebuild: a NAMED volume, declared at top level', () => {
  const svc = composeService('caldera');
  const mounts = sequenceUnder(svc, 'volumes', 4, 'caldera service');
  assert.ok(mounts.length > 0, 'caldera declares no volumes — authored adversaries would not survive a rebuild');

  // `name:/path` where the source is a bare name (no `.`, `/` or `$` in front)
  // is a NAMED volume. A bind mount would put instructor content in the repo
  // working tree, and an anonymous volume would be orphaned by every rebuild.
  const named = mounts
    .map((m) => m.split(':')[0])
    .filter((src) => /^[A-Za-z][\w.-]*$/.test(src));
  assert.ok(
    named.length > 0,
    `caldera's volumes are all bind mounts or anonymous (${mounts.join(', ')}); `
    + 'Caldera\'s object store needs a named volume so `docker compose build caldera` '
    + 'does not discard an afternoon of authoring'
  );

  // Every named source must also be DECLARED in the top-level volumes: block.
  // Compose errors on an undeclared one, but the error names a line number and
  // not a reason, and this is the reason.
  const lines = significantLines(read(COMPOSE));
  const topLevel = directKeys(blockUnder(lines, 'volumes', 0, 'docker-compose.yml'), 2);
  for (const src of named) {
    assert.ok(
      topLevel.includes(src),
      `\`${src}\` is mounted into caldera but is not declared in the top-level volumes: block `
      + `(which currently declares ${topLevel.join(', ')})`
    );
  }
});

test('the SSO secret and the redeem URL reach BOTH sides from the environment', () => {
  // The app MINTS the token and the container VERIFIES it, so the same value has
  // to reach both services. A secret named in only one place is a deployment
  // that fails closed at every login, with the cause two files apart.
  const caldera = composeService('caldera');
  const app = composeService('app');
  const calderaEnv = directKeys(blockUnder(caldera, 'environment', 4, 'caldera service'), 6);
  const appEnv = directKeys(blockUnder(app, 'environment', 4, 'app service'), 6);

  assert.ok(calderaEnv.includes('CALDERA_SSO_SECRET'), 'the caldera container cannot verify a token without CALDERA_SSO_SECRET');
  assert.ok(appEnv.includes('CALDERA_SSO_SECRET'), 'the app cannot mint a token without CALDERA_SSO_SECRET');

  // No default, on either side. `${VAR:-something}` here would be a fallback
  // signing key baked into the repository, which is worse than no signing at all
  // because it looks signed.
  const calderaLines = blockUnder(caldera, 'environment', 4, 'caldera service');
  const appLines = blockUnder(app, 'environment', 4, 'app service');
  for (const [where, lines] of [['caldera', calderaLines], ['app', appLines]]) {
    const v = scalarAt(lines, 'CALDERA_SSO_SECRET', 6);
    assert.ok(
      /^\$\{CALDERA_SSO_SECRET(:-)?\}$/.test(v),
      `${where}: CALDERA_SSO_SECRET must come from the environment with no fallback value, got ${v}`
    );
  }

  // Single use needs the burn, and the burn lives in CyberCore because the
  // container has no Redis. Losing this URL silently downgrades the token from
  // single-use to replayable-for-60-seconds.
  assert.ok(calderaEnv.includes('CYBERCORE_REDEEM_URL'), 'without the redeem URL the token stops being single-use');
  const redeem = scalarAt(calderaLines, 'CYBERCORE_REDEEM_URL', 6);
  assert.ok(
    /\/api\/caldera\/redeem/.test(redeem),
    `CYBERCORE_REDEEM_URL must point at the burn endpoint, got ${redeem}`
  );
  assert.ok(
    !/https?:\/\/(?!app[:/])/.test(redeem.replace(/^\$\{[^:]*:-/, '')),
    'the burn must stay on cybercore-net (app:3000), not go out over the public hostname'
  );
});

test('the caldera image is BUILT from this repo, not pulled from a floating tag', () => {
  const svc = composeService('caldera');
  const keys = directKeys(svc, 4);
  assert.ok(keys.includes('build'), 'caldera must be built from infrastructure/caldera — mitre/caldera\'s published tags lag its releases');
  assert.ok(!keys.includes('image'), 'caldera declares both build: and image: — one of them is not what runs');

  const build = blockUnder(svc, 'build', 4, 'caldera service');
  assert.strictEqual(scalarAt(build, 'context', 6), './infrastructure/caldera');
});

// ---------------------------------------------------------------------------
// §2 The edge: the Caddy image pin, and the gate on EVERY /caldera block
// ---------------------------------------------------------------------------

test('the Caddy image is pinned to an exact version, not a floating major tag', () => {
  const image = scalarAt(composeService('caddy'), 'image', 4);
  assert.ok(image, 'the caddy service declares no image');

  // `caddy:2-alpine`, `caddy:2`, `caddy:latest` are all moving targets. The
  // forward_auth mitigations in the Caddyfile are written against a KNOWN
  // behaviour (GHSA-7r4p-vjf4-gxv4), and a floating tag lets that behaviour
  // change with no diff anywhere in this repository to review.
  const m = image.match(/^caddy:(\d+)\.(\d+)\.(\d+)(-[\w.]+)?$/);
  assert.ok(
    m,
    `caddy image "${image}" is not pinned to an exact patch version. `
    + 'Use e.g. caddy:2.10.2-alpine. A floating tag can change forward_auth\'s '
    + 'header handling underneath the mitigations in config/caddy/Caddyfile.'
  );
  assert.strictEqual(m[1], '2', 'the Caddyfile syntax here is Caddy 2');
});

/**
 * Split the Caddyfile into its top-level site blocks.
 *
 * Two things defeat a naive brace scan, and both are in this file:
 *   - `{$CYBERHUB_HOST}` is an environment placeholder, not a block. Its braces
 *     become «» first, or every site header opens a phantom block.
 *   - Comments contain braces AND every word this file greps for, so they are
 *     removed BEFORE the scan. That is what stops a /caldera proxy that is only
 *     DESCRIBED in prose from satisfying the assertions below.
 */
function siteBlocks(raw) {
  const src = raw
    .replace(/\{\$([^}]*)\}/g, (_m, name) => `«${name}»`)
    .split(/\r?\n/)
    .map((line) => line.replace(/(^|\s)#.*$/, '$1'))
    .join('\n');

  const blocks = [];
  let depth = 0;
  let open = -1;
  let headerFrom = 0;
  for (let i = 0; i < src.length; i++) {
    if (src[i] === '{') {
      if (depth === 0) open = i;
      depth++;
    } else if (src[i] === '}') {
      depth--;
      if (depth === 0) {
        blocks.push({ header: src.slice(headerFrom, open).trim(), body: src.slice(open + 1, i) });
        headerFrom = i + 1;
      }
    }
  }
  // The global options block has an empty header and is not a site.
  return blocks.filter((b) => b.header.length > 0);
}

/**
 * The brace-balanced body of the first directive block matching `re`.
 *
 * A lazy /\{([\s\S]*?)\}/ is wrong here in exactly the way that matters: it
 * stops at the closing brace of the NESTED forward_auth block, so the
 * reverse_proxy that follows falls outside the match and a gated handle looks
 * like it proxies nothing.
 */
function directiveBlock(body, re) {
  const at = body.search(re);
  if (at < 0) return null;
  const open = body.indexOf('{', at);
  if (open < 0) return null;
  let depth = 0;
  for (let i = open; i < body.length; i++) {
    if (body[i] === '{') depth++;
    else if (body[i] === '}') {
      depth--;
      if (depth === 0) return body.slice(open + 1, i);
    }
  }
  return null;
}

/** Every site block that routes /caldera, whatever its header. */
function calderaBlocks() {
  return siteBlocks(read(CADDYFILE))
    .map((b) => ({ ...b, handle: directiveBlock(b.body, /handle(_path)?\s+\/caldera/) }))
    .filter((b) => /handle(_path)?\s+\/caldera/.test(b.body));
}

test('THE OTHER POINT OF THIS FILE: every /caldera block has BOTH the gate and the strip', () => {
  const blocks = calderaBlocks();

  // Two today: the public site and the internal :80 listener. The assertions run
  // per block rather than once per file precisely so that a THIRD block — the
  // documented fix for the SPA-subpath problem, a dedicated hostname — cannot be
  // added without them.
  assert.ok(
    blocks.length >= 2,
    `expected the console to be routed in at least 2 site blocks, found ${blocks.length}`
  );

  for (const block of blocks) {
    const where = `site block \`${block.header}\``;
    assert.ok(block.handle, `${where}: could not read the /caldera handle`);

    // (a) THE GATE. Without it the public block publishes an adversary
    // authoring console behind a login form that accepts no password.
    assert.match(
      block.handle, /forward_auth\s+\S+\s*\{[^}]*\}/,
      `${where}: /caldera is proxied with NO forward_auth`
    );

    // (b) THE STRIP. GHSA-7r4p-vjf4-gxv4 — copy_headers does not remove the
    // client's own copy, so an authorize response that is 2xx without the header
    // forwards whatever the browser sent.
    assert.match(
      block.handle, /request_header\s+-X-CyberCore-Auth\b/,
      `${where}: no inbound strip of X-CyberCore-Auth before the gate. `
      + 'Caddy advisory GHSA-7r4p-vjf4-gxv4: without it, a client that supplies '
      + 'its own X-CyberCore-Auth has that value survive forward_auth to Caldera.'
    );

    // (c) ORDER. The strip must be written before the gate...
    const stripAt = block.handle.search(/request_header\s+-X-CyberCore-Auth\b/);
    const gateAt = block.handle.search(/forward_auth\b/);
    assert.ok(
      stripAt < gateAt,
      `${where}: the header strip is written AFTER forward_auth; it would delete the token the gate installed`
    );

    // ...and both must be inside a `route`, because outside one Caddy sorts
    // directives into ITS OWN order, in which request_header runs AFTER
    // forward_auth. Written order only equals executed order inside a route.
    const route = directiveBlock(block.handle, /(^|\s)route\s*\{/);
    assert.ok(route, `${where}: the /caldera handle has no \`route\` block, so directive order is Caddy's, not yours`);
    assert.match(route, /request_header\s+-X-CyberCore-Auth\b/, `${where}: the strip is outside the route`);
    assert.match(route, /forward_auth\b/, `${where}: the gate is outside the route`);
    assert.match(route, /reverse_proxy\b/, `${where}: the proxy is outside the route`);

    // (d) The gate and the proxy in the SAME handle: a forward_auth elsewhere in
    // the site guards something else entirely.
    assert.match(block.handle, /reverse_proxy/, `${where}: the /caldera handle proxies nothing`);
    assert.match(
      block.handle, /reverse_proxy\s+«CALDERA_AUTHORING_UPSTREAM:[^»]+»/,
      `${where}: the upstream must come from CALDERA_AUTHORING_UPSTREAM, never a literal in this file`
    );
    assert.ok(
      !/reverse_proxy\s+\d+\.\d+\.\d+\.\d+/.test(block.handle),
      `${where}: a hard-coded IP for the authoring console`
    );

    // (e) ONE signed header, and only that one. A second, unsigned identity
    // header next to it would be the advisory all over again — the strip covers
    // the names we know about, and a name nobody stripped is a name a client can
    // set.
    const copied = [...block.handle.matchAll(/copy_headers\s+([^\n]+)/g)]
      .flatMap((m) => m[1].trim().split(/[\s,]+/))
      .filter(Boolean);
    assert.deepStrictEqual(
      copied, ['X-CyberCore-Auth'],
      `${where}: copy_headers must carry the signed token and nothing else, got [${copied.join(', ')}]`
    );
  }
});

test('the /caldera upstream is the compose service, not the retired VM name', () => {
  // The authoring instance moved from a Proxmox VM into a container. The default
  // baked into the placeholder is what applies when nobody sets the variable, so
  // a stale default is a deployment that silently probes a name that no longer
  // resolves and reports the console as down.
  for (const block of calderaBlocks()) {
    const m = block.handle.match(/reverse_proxy\s+«CALDERA_AUTHORING_UPSTREAM:([^»]+)»/);
    assert.ok(m, `site block \`${block.header}\`: no CALDERA_AUTHORING_UPSTREAM placeholder`);
    assert.strictEqual(
      m[1], 'caldera:8888',
      `site block \`${block.header}\`: the default upstream should be the compose service name`
    );
  }

  // And compose must pass the variable to Caddy at all, or the placeholder's
  // default is the only value that ever applies.
  const env = directKeys(blockUnder(composeService('caddy'), 'environment', 4, 'caddy service'), 6);
  assert.ok(env.includes('CALDERA_AUTHORING_UPSTREAM'), 'the caddy service does not pass CALDERA_AUTHORING_UPSTREAM through');
});

test('forward_auth still asks the app, and asks it for the authorize path', () => {
  // FAIL CLOSED depends on this pointing at an endpoint that answers non-2xx for
  // anyone who is not staff. A `uri` naming a path that answers 200
  // unauthenticated allows every request with no error anywhere.
  const calderaAuthoring = require(path.join(ROOT, 'src', 'routes', 'caldera-authoring.js'));
  for (const block of calderaBlocks()) {
    const gate = directiveBlock(block.handle, /forward_auth\b/);
    assert.ok(gate, `site block \`${block.header}\`: unreadable forward_auth block`);
    const uri = (gate.match(/uri\s+(\S+)/) || [])[1];
    assert.strictEqual(
      uri, calderaAuthoring.AUTHORIZE_PATH,
      `site block \`${block.header}\`: the Caddyfile asks a different path than the app answers on`
    );
    assert.match(
      block.handle, /forward_auth\s+app:3000\b/,
      `site block \`${block.header}\`: the gate must ask the app container, over the internal network`
    );
  }
});

// ---------------------------------------------------------------------------
// §3 The image: a pinned release, cloned recursively, with the handler baked in
// ---------------------------------------------------------------------------

/**
 * Fold a Dockerfile into logical instructions.
 *
 * Line continuations are joined and comments dropped, so `--recursive` sitting
 * on its own continuation line is found and `--recursive` written in a comment
 * is not. Both cases are in the real file.
 */
function dockerInstructions(src) {
  const out = [];
  let buf = null;
  for (const raw of src.split(/\r?\n/)) {
    const line = raw.trimEnd();
    const trimmed = line.trim();
    if (buf === null) {
      if (!trimmed || trimmed.startsWith('#')) continue;
      buf = trimmed;
    } else {
      if (trimmed.startsWith('#')) continue;   // comments are legal mid-continuation
      buf += ' ' + trimmed;
    }
    if (buf.endsWith('\\')) {
      buf = buf.slice(0, -1).trimEnd();
      continue;
    }
    out.push(buf);
    buf = null;
  }
  if (buf !== null) out.push(buf);
  return out.map((s) => {
    const m = s.match(/^(\w+)\s+([\s\S]*)$/);
    return m ? { op: m[1].toUpperCase(), args: m[2] } : { op: s.toUpperCase(), args: '' };
  });
}

test('the Dockerfile pins a Caldera RELEASE, in one place', () => {
  const ins = dockerInstructions(read(DOCKERFILE));
  const args = ins.filter((i) => i.op === 'ARG' && /^CALDERA_VERSION\b/.test(i.args));
  assert.ok(args.length >= 1, 'no ARG CALDERA_VERSION — the Caldera version must be a single named knob');

  const withDefault = args.filter((a) => a.args.includes('='));
  assert.strictEqual(withDefault.length, 1, 'exactly one ARG CALDERA_VERSION should carry the default; the rest re-declare it per stage');

  const version = withDefault[0].args.split('=')[1].trim().replace(/^["']|["']$/g, '');
  assert.match(
    version, /^\d+\.\d+(\.\d+)?$/,
    `CALDERA_VERSION is "${version}". It must be a release TAG. A branch — master, main, latest, HEAD — `
    + 'lets an unreviewed upstream change land on the next `docker compose build` of a console every '
    + 'instructor can reach.'
  );
});

test('the clone is RECURSIVE and uses the pinned tag — Caldera plugins are submodules', () => {
  const ins = dockerInstructions(read(DOCKERFILE));
  const clones = ins.filter((i) => i.op === 'RUN' && /\bgit clone\b/.test(i.args));
  assert.strictEqual(clones.length, 1, 'expected exactly one `git clone` of Caldera');
  const clone = clones[0].args;

  assert.match(
    clone, /--recursive\b/,
    'the clone is not --recursive. Every Caldera plugin (magma, stockpile, atomic, compass, '
    + 'fieldmanual) is a git SUBMODULE; without it the image contains empty plugin directories '
    + 'and the server starts with no UI and no abilities, which reads as a proxy fault.'
  );
  assert.match(clone, /--branch\s+"?\$\{CALDERA_VERSION\}"?/, 'the clone must use the pinned ARG, not a literal or a default branch');
  assert.ok(!/--branch\s+(master|main|develop)\b/.test(clone), 'the clone names a branch instead of the pinned release');
});

test('the console has exactly one working authentication path', () => {
  // THE INVARIANT IS "AUTHENTICATED", NOT "USES THE CUSTOM HANDLER".
  //
  // There are two mechanisms that can log the console in, and the config must
  // commit to one of them:
  //
  //   a) auth.login.handler.module names our module -> Caldera calls it and it
  //      verifies the signed token. Loaded correctly, but Caldera never reaches
  //      it on a browser page load: check_permissions() returns early on the api
  //      key and only IT calls login_redirect().
  //   b) auth.login.handler.module is 'default' -> Caddy must inject Caldera's
  //      own `KEY` header, because check_permissions() short-circuits on it for
  //      EVERY route. This is the shipped design.
  //
  // Getting this wrong in either direction produces the SAME symptom — Caldera's
  // stock login form, with random unknowable passwords — and no error anywhere.
  // That cost several hours once; this test exists so it costs zero next time.
  const conf = read(CALDERA_CONF);
  const declared = (conf.match(/^auth\.login\.handler\.module\s*:\s*(\S+)\s*$/m) || [])[1];
  assert.ok(declared, 'conf/local.yml does not set auth.login.handler.module at all');

  const blocks = calderaBlocks();
  assert.ok(blocks.length >= 1, 'no /caldera block found in the Caddyfile');

  if (declared === 'default') {
    // Mechanism (b). Every block must inject the key AND strip a client-supplied
    // one — the strip is not hygiene here, it is the whole gate: a caller who
    // could set their own KEY would authenticate to Caldera directly.
    for (const block of blocks) {
      const where = `site block \`${block.header}\``;
      assert.ok(block.handle, `${where}: could not read the /caldera handle`);
      assert.ok(
        // siteBlocks() normalises Caddy's {$VAR} placeholders to «VAR» so its
        // brace counting is not confused by them — so match that form, not the
        // raw one that appears in the file.
        /request_header\s+KEY\s+«CALDERA_API_KEY_RED»/.test(block.handle),
        `${where} does not inject Caldera's KEY header, and the login handler is 'default' — `
        + 'nothing would authenticate the console and Caldera would serve its stock login form.'
      );
      assert.ok(
        /request_header\s+-KEY\b/.test(block.handle),
        `${where} injects KEY but never strips an inbound one. A client supplying its own KEY `
        + 'would bypass forward_auth and authenticate to Caldera directly.'
      );
    }
  } else {
    // Mechanism (a). The module name must match what the Dockerfile installs;
    // the destination basename IS the import path, since it lands at the top of
    // the directory server.py runs from.
    const ins = dockerInstructions(read(DOCKERFILE));
    const copies = ins.filter((i) => i.op === 'COPY' && /login_handler\.py/.test(i.args));
    assert.strictEqual(copies.length, 1, 'the Dockerfile must COPY infrastructure/caldera/login_handler.py into the image');
    const moduleName = path.basename(copies[0].args.trim().split(/\s+/).pop()).replace(/\.py$/, '');
    assert.strictEqual(
      declared, moduleName,
      `conf/local.yml points auth.login.handler.module at "${declared}" but the Dockerfile installs the handler as "${moduleName}"`
    );
  }
});

test('the image configures NO agent contact of any kind', () => {
  // This instance must never take a check-in. A contact is precisely the thing
  // that accepts one, so the config declares none — asserted as a real key scan
  // rather than a substring search, so the long comment in that file explaining
  // WHY there are no contacts does not fail the test that says so.
  const keys = read(CALDERA_CONF)
    .split(/\r?\n/)
    .filter((l) => l.trim() && !l.trim().startsWith('#'))
    .map((l) => (l.match(/^([A-Za-z][\w.]*)\s*:/) || [])[1])
    .filter(Boolean);

  // The invariant is NOT "zero contact keys" — that version of this test was
  // right about the goal and wrong about the mechanism, and it cost a restart
  // loop. Caldera's own EVENT BUS runs over the websocket contact:
  // server.py run_tasks() -> event_svc.fire_event() -> websockets.connect(uri)
  // built from app.contact.websocket. Undefined, the URI has an empty host and
  // the server dies at startup with
  //   socket.gaierror: [Errno -2] Name or service not known
  //
  // So the real invariant is: the ONLY contact permitted is the websocket event
  // bus, and it MUST be bound to loopback. Everything that can accept an agent
  // check-in from off-box stays absent.
  const contacts = keys.filter((k) => k.startsWith('app.contact'));
  assert.deepStrictEqual(
    contacts, ['app.contact.websocket'],
    `conf/local.yml's contact keys are ${JSON.stringify(contacts)}. Exactly one is allowed — `
    + 'app.contact.websocket, which is Caldera\'s internal event bus and without which the '
    + 'server will not start. Every other contact accepts an agent check-in, and the authoring '
    + 'instance has no agents; the per-lane EXECUTOR Calderas are VMs baked by '
    + 'bake-caldera-server.sh and that is where contacts belong.'
  );

  // Loopback is what makes the one permitted contact unreachable. Paired with
  // the service publishing no ports, nothing off-container can reach it — not
  // the host, not a lane, not a peer on cybercore-net.
  const wsBind = (read(CALDERA_CONF).match(/^app\.contact\.websocket:\s*(\S+)/m) || [])[1];
  assert.ok(
    wsBind && /^127\.0\.0\.1:\d+$/.test(wsBind),
    `app.contact.websocket is bound to ${wsBind || '(unset)'}. It must bind 127.0.0.1 — on `
    + '0.0.0.0 the event bus becomes a reachable agent contact the moment anything publishes '
    + 'or forwards that port.'
  );

  // …and the payload plugins are not merely unconfigured, they are deleted, so
  // "takes no check-in" is a property of the image rather than of a config file.
  const ins = dockerInstructions(read(DOCKERFILE));
  const removals = ins.filter((i) => i.op === 'RUN' && /\brm -rf\b/.test(i.args)).map((i) => i.args).join(' ');
  for (const payload of ['plugins/sandcat', 'plugins/manx']) {
    assert.ok(
      removals.includes(payload),
      `the Dockerfile does not remove ${payload}. It is an AGENT PAYLOAD plugin: leaving it in `
      + 'means the image can hand out an agent and serves the endpoint that does so.'
    );
  }

  // The plugin list and the prune must agree, or Caldera fails at startup naming
  // a plugin directory that is not there.
  const listed = (read(CALDERA_CONF).match(/^plugins:\n((?:\s+-\s+\S+\n)+)/m) || [])[1] || '';
  const plugins = listed.split(/\r?\n/).map((l) => l.trim().replace(/^-\s*/, '')).filter(Boolean);
  assert.ok(plugins.length > 0, 'conf/local.yml lists no plugins — magma is the UI, so the console would be blank');
  for (const p of plugins) {
    assert.ok(
      !removals.includes(`plugins/${p}`),
      `conf/local.yml enables the "${p}" plugin but the Dockerfile deletes plugins/${p}`
    );
  }
  assert.ok(plugins.includes('magma'), 'magma is the Caldera 5 UI; without it there is nothing to author in');
});

test('the entrypoint fails closed on a missing or short signing key', () => {
  // Both sides of the contract must refuse to run without CALDERA_SSO_SECRET,
  // and the container's refusal is the loudest one available: it never starts,
  // so there is no window in which the only door is in an undefined state.
  const entry = read(path.join(CALDERA_DIR, 'entrypoint.sh'));
  assert.match(entry, /CALDERA_SSO_SECRET/, 'the entrypoint does not check CALDERA_SSO_SECRET');
  assert.match(entry, /\b32\b/, 'the entrypoint does not enforce the 32-byte floor on CALDERA_SSO_SECRET');
  assert.match(entry, /^set -eu/m, 'the entrypoint must abort on the first failed command, not push on');

  // A default here would be a signing key in the repository, which is worse than
  // no signing because it looks signed.
  assert.ok(
    !/CALDERA_SSO_SECRET:?=["']?[A-Za-z0-9]/.test(entry),
    'the entrypoint appears to supply a fallback CALDERA_SSO_SECRET — there must never be a default'
  );
});
