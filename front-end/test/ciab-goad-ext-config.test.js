/**
 * ciab-goad-ext-config.test.js — replacing ONE extension config.json on the
 * GOAD controller.
 *
 * WHAT IS ACTUALLY AT RISK HERE
 *
 *   1. THE DESTINATION IS A FILE THAT ALREADY WORKS. Unlike a generated lab
 *      tree, extensions/ws01/data/config.json is shipped by the image and the
 *      deploy depends on it. Every failure mode of this pusher therefore has to
 *      leave the stock file intact — not "usually", and not "unless the write
 *      was interrupted". A `> dest` redirect truncates before it writes, so a
 *      dropped chunk would leave install.yml parsing half a JSON document and
 *      failing at a line number rather than a cause. The snapshot assertions
 *      below record the destination's CONTENT after every interpreted shell
 *      line, so "the destination is only ever the stock file or the intended
 *      one" is a fact about the emitted commands and not an inference from a
 *      call log.
 *
 *   2. REFUSING IS THE CORRECT BEHAVIOUR WHEN THE FILE IS ABSENT. A missing
 *      extensions/<key>/data/config.json means the image does not carry that
 *      extension. `mkdir -p` would turn run.sh's loud, correct refusal into a
 *      config file nobody reads and a green deploy with no extension in it.
 *
 *   3. THE KEY INDEXES A PATH. It is not authored today, but it reaches a shell
 *      string that names a directory a later `rm -rf` also names. The traversal
 *      table below is the layered guard asserted end to end, including that a
 *      refusal costs ZERO guest calls.
 *
 *   4. THE TWO HALVES MUST NOT DRIFT. goad-ext-config-push reuses
 *      goad-lab-push's assertShellSafe/runStep/sendBytes rather than copying
 *      them, because "agentShellExec retries the TRANSPORT, not the WORK" is a
 *      contract that lives in those functions. There is an export test for that
 *      at the bottom, so deleting one of the exports fails here rather than in
 *      a deploy.
 *
 * Run: node --test front-end/test/ciab-goad-ext-config.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.join(__dirname, '..');
const UTILS = 'modules/crucible/plugins/ciab/utils';
const ext = require(path.join(ROOT, UTILS, 'goad-ext-config-push.js'));
const push = require(path.join(ROOT, UTILS, 'goad-lab-push.js'));

const KEY = 'ws01';
const DEST = `/opt/goad/extensions/${KEY}/data/config.json`;
const BACKUP = `${DEST}.cc-bak`;
const TOKEN = 'testtoken';
const WORK = `/opt/goad/extensions/.cc-extcfg-${TOKEN}`;

/**
 * A backslash, built rather than typed.
 *
 * `sevenkingdoms\tywin.lannister` is a real value in the stock config, and this
 * repo has been broken more than once by a backslash that survived one round of
 * escaping too many. Building it from a char code means what the test asserts
 * on is unambiguous no matter what touches this file next.
 */
const BS = String.fromCharCode(92);

const sha256 = (b) => crypto.createHash('sha256').update(b).digest('hex');

/**
 * extensions/ws01/data/config.json as the baked image actually has it — 996
 * bytes upstream, reproduced here as the object it parses to so the domain and
 * hostname values are visible at the point the tests reason about them.
 */
function stockConfigObject() {
  return {
    lab_extension: {
      hosts: {
        ws01: {
          hostname: 'casterlyrock',
          type: 'workstation',
          local_admin_password: 'EP+xh7Rk6j90',
          domain: 'sevenkingdoms.local',
          path: 'DC=sevenkingdoms,DC=local',
          local_groups: {
            Administrators: [
              `sevenkingdoms${BS}tywin.lannister`,
              `sevenkingdoms${BS}jaime.lannister`,
            ],
            'Remote Desktop Users': [`sevenkingdoms${BS}Lannister`],
          },
          security: ['enable_run_as_ppl', 'asr', 'powershell_restrict'],
        },
      },
    },
  };
}

const STOCK = `${JSON.stringify(stockConfigObject(), null, 2)}\n`;

/**
 * The same config after a forest rename to cy400test.org — the actual payload
 * this module exists to deliver. Note local_admin_password is byte-identical:
 * it must stay equal to the `ansible_password=` literal in ws01's stock
 * inventory, which is what makes the domain join authenticate.
 */
function renamedConfigText() {
  const cfg = stockConfigObject();
  const h = cfg.lab_extension.hosts.ws01;
  h.hostname = 'WS01';
  h.domain = 'cy400test.org';
  h.path = 'DC=cy400test,DC=org';
  h.local_groups = {
    Administrators: [`CY400TEST${BS}tywin.lannister`, `CY400TEST${BS}jaime.lannister`],
    'Remote Desktop Users': [`CY400TEST${BS}Lannister`],
  };
  return `${JSON.stringify(cfg, null, 2)}\n`;
}

const RENAMED = renamedConfigText();

// ═══════════════════════════════════════════════════════════════════════════
// FakeGuest — a port of the interpreter in ciab-goad-lab-push.test.js.
//
// COPIED, not required: that file is a test suite, so requiring it would run
// its 40-odd tests a second time inside this one. The copy keeps the property
// that makes it worth having — it THROWS on any command shape it does not
// recognise, so a future edit to a shell string cannot quietly stop being
// simulated and start passing vacuously.
//
// What this copy adds, all of them shapes goad-ext-config-push emits and
// goad-lab-push does not:
//   - `mv -f`                                (the file-level atomic replace)
//   - `[ -f BAK ] || cp -p DEST BAK`         (back up once, best-effort)
//   - `... | sha256sum -c - ... && exit 0`   (the probe's short-circuit; the
//                                             lab pusher only ever uses `||`)
// It also records the DESTINATION'S CONTENT after every interpreted line, not
// merely whether it exists, because the property under test here is that the
// file is never partially written.
// ═══════════════════════════════════════════════════════════════════════════

function makeGuest(seed = {}) {
  const dirs = new Set(['/', '/opt', '/opt/goad', '/opt/goad/ad', '/opt/goad/extensions', '/tmp']);
  const files = new Map();
  const log = [];        // every command string, in order
  const snapshots = [];  // { cmd, line, dest } — dest CONTENT, after every line
  let hook = null;       // (cmd, index) => number|Error|undefined

  function parentOf(p) { return p.replace(/\/[^/]*$/, '') || '/'; }
  function mkdirp(p) {
    const parts = p.split('/').filter(Boolean);
    let cur = '';
    for (const part of parts) { cur += `/${part}`; dirs.add(cur); }
  }
  function exists(p) { return dirs.has(p) || files.has(p); }
  function removeTree(p) {
    files.delete(p);
    dirs.delete(p);
    const pfx = `${p}/`;
    for (const k of [...files.keys()]) if (k.startsWith(pfx)) files.delete(k);
    for (const k of [...dirs.keys()]) if (k.startsWith(pfx)) dirs.delete(k);
  }
  function moveTree(a, b) {
    if (!exists(a)) return 1;
    if (dirs.has(b)) return 1;   // rename(2) will not replace a directory
    if (files.has(a)) {
      files.set(b, files.get(a));
      files.delete(a);
      return 0;
    }
    const pfx = `${a}/`;
    for (const k of [...dirs.keys()]) {
      if (k === a || k.startsWith(pfx)) { dirs.add(b + k.slice(a.length)); dirs.delete(k); }
    }
    for (const k of [...files.keys()]) {
      if (k.startsWith(pfx)) { files.set(b + k.slice(a.length), files.get(k)); files.delete(k); }
    }
    dirs.add(b);
    return 0;
  }
  function writeFile(p, buf) {
    if (!dirs.has(parentOf(p))) return 2;   // dash: cannot create, exit 2
    files.set(p, buf);
    return 0;
  }
  function readText(p) { return files.has(p) ? files.get(p).toString('utf8') : null; }

  for (const [p, c] of Object.entries(seed.files || {})) {
    mkdirp(parentOf(p));
    files.set(p, Buffer.isBuffer(c) ? c : Buffer.from(String(c), 'utf8'));
  }
  for (const d of (seed.dirs || [])) mkdirp(d);

  const Q = "'([^']*)'";
  const OPT_EXIT = '(?: \\|\\| exit (\\d+))?';

  function runLine(line) {
    let m;
    if ((m = line.match(/^exit (\d+)$/))) return { exit: Number(m[1]) };

    // Back up once, best-effort. Must be matched BEFORE the bare `[ -f ] ||
    // exit` shape below, which it would otherwise never reach.
    if ((m = line.match(new RegExp(`^\\[ -f ${Q} \\] \\|\\| cp -p ${Q} ${Q} 2>/dev/null$`)))) {
      if (!files.has(m[1]) && files.has(m[2])) files.set(m[3], files.get(m[2]));
      return {};
    }

    if ((m = line.match(new RegExp(`^\\[ -([dfes]) ${Q} \\] (\\|\\||&&) exit (\\d+)$`)))) {
      const [, op, p, join, code] = m;
      const ok = op === 'd' ? dirs.has(p)
        : op === 'f' ? files.has(p)
          : op === 's' ? (files.has(p) && files.get(p).length > 0)
            : exists(p);
      if (join === '||' && !ok) return { exit: Number(code) };
      if (join === '&&' && ok) return { exit: Number(code) };
      return {};
    }

    if ((m = line.match(/^command -v (\S+) >\/dev\/null 2>&1 \|\| exit (\d+)$/))) {
      const present = ['tar', 'base64', 'sha256sum'].includes(m[1]);
      return present ? {} : { exit: Number(m[2]) };
    }

    if ((m = line.match(new RegExp(
      `^printf '%s  %s\\\\n' ${Q} ${Q} \\| sha256sum -c - >/dev/null 2>&1 (\\|\\||&&) exit (\\d+)$`)))) {
      const got = files.has(m[2]) ? sha256(files.get(m[2])) : null;
      const ok = got === m[1];
      if (m[3] === '||' && !ok) return { exit: Number(m[4]) };
      if (m[3] === '&&' && ok) return { exit: Number(m[4]) };
      return {};
    }

    if ((m = line.match(new RegExp(`^rm -rf ((?:${Q} ?)+?)${OPT_EXIT}$`)))) {
      for (const q of m[1].match(/'([^']*)'/g) || []) removeTree(q.slice(1, -1));
      return {};
    }
    if ((m = line.match(new RegExp(`^rm -f ${Q}${OPT_EXIT}$`)))) {
      files.delete(m[1]);
      return {};
    }
    if ((m = line.match(new RegExp(`^mkdir -p ${Q}${OPT_EXIT}$`)))) {
      mkdirp(m[1]);
      return {};
    }
    if ((m = line.match(new RegExp(`^: > ${Q}${OPT_EXIT}$`)))) {
      const rc = writeFile(m[1], Buffer.alloc(0));
      return rc === 0 ? {} : { exit: m[2] ? Number(m[2]) : rc };
    }
    if ((m = line.match(new RegExp(`^printf %s ${Q} >> ${Q}$`)))) {
      if (!dirs.has(parentOf(m[2]))) return { exit: 2 };
      const prev = files.get(m[2]) || Buffer.alloc(0);
      files.set(m[2], Buffer.concat([prev, Buffer.from(m[1], 'utf8')]));
      return {};
    }
    if ((m = line.match(new RegExp(`^base64 -d < ${Q} > ${Q}${OPT_EXIT}$`)))) {
      if (!files.has(m[1])) return { exit: m[3] ? Number(m[3]) : 1 };
      const rc = writeFile(m[2], Buffer.from(files.get(m[1]).toString('utf8'), 'base64'));
      return rc === 0 ? {} : { exit: m[3] ? Number(m[3]) : rc };
    }
    if ((m = line.match(new RegExp(`^mv(?: -f)? ${Q} ${Q}${OPT_EXIT}$`)))) {
      const rc = moveTree(m[1], m[2]);
      return rc === 0 ? {} : { exit: m[3] ? Number(m[3]) : rc };
    }
    throw new Error(`FakeGuest: unrecognised shell line: ${JSON.stringify(line)}`);
  }

  function run(cmd) {
    let stdout = '';
    for (const raw of cmd.split('\n')) {
      const line = raw.trim();
      if (line === '') continue;
      const r = runLine(line);
      // After EVERY line, not every command: the property under test is that
      // the destination never holds a partial file, and a per-command snapshot
      // could not tell a truncating write from an atomic one.
      snapshots.push({ cmd, line, dest: readText(DEST) });
      if (r.stdout) stdout += r.stdout;
      if (r.exit !== undefined) return { exitcode: r.exit, stdout };
    }
    return { exitcode: 0, stdout };
  }

  const pending = new Map();
  let nextPid = 1000;

  return {
    dirs, files, log, snapshots,
    setHook(fn) { hook = fn; },
    exists,
    read: readText,
    agentShellExec: async (node, vmId, cmd) => {
      const pid = ++nextPid;
      pending.set(pid, cmd);
      return { pid };
    },
    pollExecStatus: async (node, vmId, pid) => {
      const cmd = pending.get(pid);
      pending.delete(pid);
      const index = log.length;
      log.push(cmd);
      if (hook) {
        const forced = hook(cmd, index);
        if (forced instanceof Error) throw forced;
        if (typeof forced === 'number') {
          snapshots.push({ cmd, line: '<forced>', dest: readText(DEST) });
          return { exited: true, exitcode: forced, stdout: '', stderr: 'forced' };
        }
      }
      const r = run(cmd);
      return { exited: true, exitcode: r.exitcode, stdout: r.stdout, stderr: '' };
    },
  };
}

/** A controller whose image carries ws01, with its stock config in place. */
function guestWithStock(extra = {}) {
  return makeGuest({
    dirs: [
      '/opt/goad/extensions/ws01/ansible',
      '/opt/goad/extensions/ws01/data',
      '/opt/goad/extensions/elk/ansible',
    ],
    files: Object.assign({ [DEST]: STOCK }, extra),
  });
}

function pushOpts(guest, extra) {
  return Object.assign({
    node: 'node-1',
    vmId: 1701,
    key: KEY,
    content: RENAMED,
    token: TOKEN,
    log: { log() {}, warn() {} },
    deps: { agentShellExec: guest.agentShellExec, pollExecStatus: guest.pollExecStatus },
  }, extra || {});
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. Content guards — every one of these costs zero guest calls
// ═══════════════════════════════════════════════════════════════════════════

test('a stock-shaped config is accepted and its bytes pass through unchanged', () => {
  const { bytes, parsed } = ext.assertExtensionConfig(RENAMED, KEY);
  assert.strictEqual(bytes.toString('utf8'), RENAMED);
  assert.strictEqual(parsed.lab_extension.hosts.ws01.domain, 'cy400test.org');
});

test('a plain object is serialized once, here, so hash/send/verify cannot disagree', () => {
  const asObject = ext.assertExtensionConfig(JSON.parse(RENAMED), KEY);
  const asText = ext.assertExtensionConfig(RENAMED, KEY);
  assert.ok(asObject.bytes.equals(asText.bytes));
});

test('a config that is not STRICT json is refused, DRACARYS-style', () => {
  // Upstream's DRACARYS config.json carries an illegal trailing comma at line
  // 128 and works only because ansible loads it through a YAML loader. So
  // "ansible accepted it" is not evidence a config is JSON, and a rewriter that
  // emitted the same mistake would otherwise be found by ansible at a line
  // number, forty minutes into a deploy.
  const trailingComma = '{"lab_extension": {"hosts": {"ws01": {"domain": "x.org"},}}}';
  assert.throws(() => ext.assertExtensionConfig(trailingComma, KEY), /not strict JSON/);
});

test('more than one top-level key is refused: vars_files puts every one in scope', () => {
  // install.yml reads this file with `vars_files`, so a second top-level key
  // becomes a play-scope ansible variable. A stray `domains` block is exactly
  // what makes the exchange extension permanently rename-unsafe.
  const twoKeys = JSON.stringify({
    lab_extension: { hosts: {} },
    domains: { 'sevenkingdoms.local': { domain_password: 'x' } },
  });
  assert.throws(() => ext.assertExtensionConfig(twoKeys, KEY), /exactly one top-level key/);
});

test('a single top-level key with the wrong name is refused', () => {
  assert.throws(
    () => ext.assertExtensionConfig(JSON.stringify({ lab: { hosts: {} } }), KEY),
    /exactly one top-level key/);
});

test('lab_extension must be a mapping, because combine() needs one', () => {
  assert.throws(
    () => ext.assertExtensionConfig(JSON.stringify({ lab_extension: 'nope' }), KEY),
    /not an object/);
  assert.throws(
    () => ext.assertExtensionConfig(JSON.stringify({ lab_extension: [] }), KEY),
    /not an object/);
});

test('a carriage return is refused, because it rides into the domain_password', () => {
  // Built from a char code, not typed. JSON.stringify escapes a real CR into a
  // two-character sequence, so a fixture written the obvious way carries no CR
  // byte at all and proves nothing about a guard that looks for one.
  const CR = String.fromCharCode(13);
  const withCr = `{"lab_extension":{"hosts":{"ws01":{"local_admin_password":"Sup3r${CR}"}}}}`;
  assert.throws(() => ext.assertExtensionConfig(withCr, KEY), /carriage return/);
  // A CRLF file body is the same refusal by the same rule.
  const crlf = `${JSON.stringify({ lab_extension: { hosts: {} } }, null, 2)}${CR}\n`;
  assert.throws(() => ext.assertExtensionConfig(crlf, KEY), /carriage return/);
});

test('anything approaching the size of the MAIN lab config is refused', () => {
  const huge = JSON.stringify({
    lab_extension: { hosts: { ws01: { note: 'x'.repeat(ext.MAX_CONFIG_BYTES) } } },
  });
  assert.throws(() => ext.assertExtensionConfig(huge, KEY), /over the .*-byte ceiling/);
});

test('empty content, an array, a number and invalid UTF-8 are all refused', () => {
  assert.throws(() => ext.assertExtensionConfig('', KEY), /is empty/);
  assert.throws(() => ext.assertExtensionConfig([], KEY), /must be a string, a Buffer/);
  assert.throws(() => ext.assertExtensionConfig(7, KEY), /must be a string, a Buffer/);
  assert.throws(() => ext.assertExtensionConfig(null, KEY), /must be a string, a Buffer/);
  // A lone 0xFF is not valid UTF-8; toString() would silently replace it with
  // U+FFFD, changing a password we are about to install.
  assert.throws(
    () => ext.assertExtensionConfig(Buffer.from([0x7b, 0xff, 0x7d]), KEY),
    /not valid UTF-8/);
});

// ═══════════════════════════════════════════════════════════════════════════
// 2. The key indexes a path — the layered guard, asserted
// ═══════════════════════════════════════════════════════════════════════════

test('the extension-key regex is strictly NARROWER than the lab-name regex', () => {
  // A dot is half of every traversal shape, and an extension key never needs
  // one. These four are all acceptable LAB names and must not be keys.
  for (const name of ['ws01.bak', 'WS01', 'ws01..old', 'w.s', 'WS01-Old']) {
    assert.ok(/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(name),
      `${name} should be a legal lab name for this test to mean anything`);
    assert.throws(() => ext.assertExtensionKey(name), /extension key/,
      `${name} was accepted as an extension key`);
  }
});

test('every traversal attempt is refused, and none of them reaches the guest', async () => {
  const attempts = [
    '..', '.', '../..', '../../etc', 'ws01/../../etc', 'ws01/data',
    '/opt/goad/extensions/ws01', 'ws01/', './ws01', '',
    // Shell metacharacters, in case a future caller is less careful than today's.
    "ws01'", 'ws01;rm -rf /', 'ws01 x', 'ws01$(id)', 'ws01\n',
  ];
  for (const key of attempts) {
    const guest = guestWithStock();
    await assert.rejects(
      ext.pushExtensionConfig(pushOpts(guest, { key })),
      /extension key/,
      `key ${JSON.stringify(key)} was not refused`);
    assert.strictEqual(guest.log.length, 0,
      `a guest call was made for the refused key ${JSON.stringify(key)}`);
  }
});

test('the destination is asserted literally, after the join', () => {
  const paths = ext.extPathsFor('/opt/goad', KEY, TOKEN);
  assert.strictEqual(paths.dest, DEST);
  assert.strictEqual(ext.assertDestination(paths), DEST);

  // The assertion is not a restatement of the template that built the path: it
  // compares against a posix.join form, which NORMALIZES. A dest that a
  // traversal component could reach stops matching and fails here.
  assert.throws(
    () => ext.assertDestination({ ...paths, dest: '/opt/goad/extensions/ws01/../data/config.json' }),
    /Refusing to write an extension config/);
  assert.throws(
    () => ext.assertDestination({ ...paths, dest: '/etc/config.json' }),
    /Refusing to write an extension config/);
});

test('a trailing slash on the root does not produce a doubled path separator', () => {
  const paths = ext.extPathsFor('/opt/goad/', KEY, TOKEN);
  assert.strictEqual(paths.dest, DEST);
  assert.strictEqual(ext.assertDestination(paths), DEST);
});

test('the work directory is a SIBLING of the extension dirs, never inside data/', () => {
  // Same filesystem, so the final mv is rename(2) — a /tmp staging dir on this
  // image could be a tmpfs, which silently degrades the rename to a copy. And
  // extensions/<key>/data/ is the directory install.yml names in vars_files.
  const paths = ext.extPathsFor('/opt/goad', KEY, TOKEN);
  assert.strictEqual(paths.work, WORK);
  assert.strictEqual(paths.work.replace(/\/[^/]*$/, ''), '/opt/goad/extensions');
  assert.ok(!paths.work.startsWith(paths.dataDir));
  assert.ok(!paths.staged.startsWith(paths.dataDir));
});

test('an unusable work token is refused before any path is built', () => {
  for (const tok of ['', '..', 'a/b', "a'b", 'a b']) {
    assert.throws(() => ext.extPathsFor('/opt/goad', KEY, tok), /work token/);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// 3. The happy path — and the invariant the whole design exists for
// ═══════════════════════════════════════════════════════════════════════════

test('the destination ends byte-identical to the intended content', async () => {
  const guest = guestWithStock();
  const res = await ext.pushExtensionConfig(pushOpts(guest));
  assert.strictEqual(res.pushed, true);
  assert.strictEqual(res.skipped, false);
  assert.strictEqual(guest.read(DEST), RENAMED);
  assert.strictEqual(res.sha256, sha256(Buffer.from(RENAMED, 'utf8')));
  assert.strictEqual(res.dest, DEST);
});

test('the destination is the stock file or the intended one in EVERY snapshot', async () => {
  // The heart of it. Snapshots are taken after every interpreted shell LINE, so
  // a truncating `> dest` (or any incremental write) would show up here as a
  // third value — an empty string or a prefix of the payload — rather than
  // having to be inferred from the absence of such a command.
  const guest = guestWithStock();
  await ext.pushExtensionConfig(pushOpts(guest));

  assert.ok(guest.snapshots.length > 5, 'nothing was simulated');
  const seen = new Set();
  for (const s of guest.snapshots) {
    seen.add(s.dest);
    assert.ok(s.dest === STOCK || s.dest === RENAMED,
      `the destination held a third value after ${JSON.stringify(s.line)}: `
      + `${JSON.stringify(String(s.dest).slice(0, 60))}`);
  }
  assert.deepStrictEqual([...seen].sort(), [RENAMED, STOCK].sort(),
    'the destination never actually changed, so this assertion proved nothing');

  // ...and it changed exactly once, by the rename.
  const transitions = [];
  let prev = STOCK;
  for (const s of guest.snapshots) {
    if (s.dest !== prev) transitions.push(s.line);
    prev = s.dest;
  }
  assert.strictEqual(transitions.length, 1, 'the destination changed more than once');
  assert.match(transitions[0], /^mv -f '[^']*' '\/opt\/goad\/extensions\/ws01\/data\/config\.json'/);
});

test('no emitted command ever redirects into the destination', async () => {
  const guest = guestWithStock();
  await ext.pushExtensionConfig(pushOpts(guest));
  for (const cmd of guest.log) {
    // The probe legitimately READS the destination (sha256sum -c), so the
    // property is specifically that nothing ever redirects INTO it. Both `>`
    // and `>>` leave a partial file behind a dropped chunk; the only writer of
    // the destination is the rename.
    assert.ok(!new RegExp(`>>? '${DEST}'`).test(cmd),
      `a command redirects into the destination — a redirect truncates first:\n${cmd}`);
    assert.ok(!new RegExp(`: > '${DEST}'`).test(cmd),
      `a command truncates the destination:\n${cmd}`);
  }
});

test('.cc-bak holds the STOCK bytes after the push', async () => {
  const guest = guestWithStock();
  await ext.pushExtensionConfig(pushOpts(guest));
  assert.strictEqual(guest.read(BACKUP), STOCK,
    'the backup does not hold the image\'s original config');
});

test('a second push of DIFFERENT content does not overwrite the original backup', async () => {
  // An unconditional `cp -p dest bak` would replace the stock file's copy with
  // our own previous output, destroying the only remaining record of what the
  // image shipped — which is the one thing the backup exists for.
  const guest = guestWithStock();
  await ext.pushExtensionConfig(pushOpts(guest));

  const second = RENAMED.replace('cy400test.org', 'cy401test.org')
    .replace('DC=cy400test', 'DC=cy401test');
  await ext.pushExtensionConfig(pushOpts(guest, { content: second, token: 'tok2' }));

  assert.strictEqual(guest.read(DEST), second);
  assert.strictEqual(guest.read(BACKUP), STOCK,
    'the second push overwrote the stock backup with its own predecessor');
});

test('the work directory is gone after a successful push', async () => {
  const guest = guestWithStock();
  await ext.pushExtensionConfig(pushOpts(guest));
  assert.ok(!guest.exists(WORK), 'the staging directory was left behind');
  assert.strictEqual([...guest.files.keys()].filter((k) => k.startsWith(`${WORK}/`)).length, 0);
});

test('a ~1KB config is one chunk at the shared 48KB chunk size', async () => {
  const guest = guestWithStock();
  const res = await ext.pushExtensionConfig(pushOpts(guest));
  assert.strictEqual(res.chunks, 1);
  assert.ok(Buffer.from(RENAMED, 'utf8').toString('base64').length < push.CHUNK_SIZE);
});

test('base64 can never escape the single quotes it is interpolated into', async () => {
  // The payload is the only caller-controlled text in any command, and it is
  // wrapped in single quotes with no escaping at all. That is safe ONLY because
  // Buffer#toString('base64') emits [A-Za-z0-9+/=] and never a newline — so the
  // test uses a config stuffed with quotes, backslashes and newlines to prove
  // none of them survive the encoding.
  const nasty = JSON.stringify({
    lab_extension: {
      hosts: {
        ws01: {
          hostname: 'WS01',
          domain: 'cy400test.org',
          local_admin_password: `it's "quoted" ${BS}${BS} and ${BS}n newline-ish`,
          note: "'; rm -rf / #",
        },
      },
    },
  }, null, 2);

  const guest = guestWithStock();
  await ext.pushExtensionConfig(pushOpts(guest, { content: nasty, chunkSize: 40 }));
  assert.strictEqual(guest.read(DEST), nasty, 'the nasty payload did not survive intact');

  const chunkCmds = guest.log.filter((c) => c.startsWith('printf %s '));
  assert.ok(chunkCmds.length > 1, 'the chunker was not exercised');
  for (const cmd of chunkCmds) {
    assert.match(cmd, /^printf %s '[A-Za-z0-9+/=]*' >> '[^']*'$/,
      `a chunk command carried something outside the base64 alphabet:\n${cmd}`);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// 4. Refusals that only the controller can decide
// ═══════════════════════════════════════════════════════════════════════════

test('a missing stock config is REFUSED, not created', async () => {
  // mkdir -p here would turn run.sh's loud, correct "extension has no
  // directory" refusal into a config file nobody reads, and the deploy would go
  // green with no extension in it.
  const guest = makeGuest({ dirs: [`/opt/goad/extensions/${KEY}/data`] });
  await assert.rejects(
    ext.pushExtensionConfig(pushOpts(guest)),
    (e) => e.step === 'ext-probe'
      && e.exitcode === ext.EXT_EXIT.NO_STOCK_CONFIG
      && /does not exist/.test(e.message));

  assert.strictEqual(guest.log.length, 1, 'more than the probe ran');
  assert.ok(!guest.exists(DEST), 'the pusher created a config that was not there');
  assert.ok(!guest.exists(WORK));
});

test('an extension the image does not carry is refused with its own code', async () => {
  const guest = makeGuest({ dirs: ['/opt/goad/extensions/elk'] });
  await assert.rejects(
    ext.pushExtensionConfig(pushOpts(guest)),
    (e) => e.step === 'ext-probe'
      && e.exitcode === ext.EXT_EXIT.NO_EXT_DIR
      && /does not carry/.test(e.message));
  assert.strictEqual(guest.log.length, 1);
});

test('a missing sha256sum on the controller is a refusal, never a blind write', async () => {
  const guest = guestWithStock();
  guest.setHook((cmd) => (/command -v sha256sum/.test(cmd) ? ext.EXT_EXIT.NO_SHA256 : undefined));
  await assert.rejects(
    ext.pushExtensionConfig(pushOpts(guest)),
    (e) => e.exitcode === ext.EXT_EXIT.NO_SHA256 && /verified/.test(e.message));
  assert.strictEqual(guest.read(DEST), STOCK);
});

test('a probe that never completes is annotated, and costs no cleanup call', async () => {
  // The probe runs outside the failure path's cleanup, so a controller that has
  // stopped answering is not asked a second question. The failure still has to
  // arrive carrying key/step/dest like every other one.
  const guest = guestWithStock();
  let calls = 0;
  const neverExits = async () => { calls += 1; return { exited: false, stdout: '', stderr: '' }; };
  await assert.rejects(
    ext.pushExtensionConfig(pushOpts(guest, {
      deps: { agentShellExec: guest.agentShellExec, pollExecStatus: neverExits },
    })),
    (e) => {
      assert.strictEqual(e.key, KEY);
      assert.strictEqual(e.step, 'ext-probe');
      assert.strictEqual(e.dest, DEST);
      assert.match(e.message, /Nothing was written/);
      return true;
    });
  assert.strictEqual(calls, 1, 'a second call was made to an unresponsive controller');
  assert.strictEqual(guest.read(DEST), STOCK);
});

test('an unrecognised probe exit code is a refusal, not a push', async () => {
  // The opposite asymmetry to pushLabTree's manifest probe, on purpose: there,
  // "I could not tell" costs a redundant 90-second push; here it would mean
  // writing into a tree we never confirmed exists.
  const guest = guestWithStock();
  guest.setHook((cmd, i) => (i === 0 ? 7 : undefined));
  await assert.rejects(ext.pushExtensionConfig(pushOpts(guest)), /not a code this module emits/);
  assert.strictEqual(guest.log.length, 1);
  assert.strictEqual(guest.read(DEST), STOCK);
});

// ═══════════════════════════════════════════════════════════════════════════
// 5. Idempotency — the no-op path is one call
// ═══════════════════════════════════════════════════════════════════════════

test('a second run issues exactly ONE command, the probe, and sends no chunk', async () => {
  const guest = guestWithStock();
  await ext.pushExtensionConfig(pushOpts(guest));
  const marker = guest.log.length;

  const again = await ext.pushExtensionConfig(pushOpts(guest, { token: 'tok2' }));
  assert.strictEqual(again.skipped, true);
  assert.strictEqual(again.pushed, false);
  assert.strictEqual(again.chunks, 0);

  const cmds = guest.log.slice(marker);
  assert.strictEqual(cmds.length, 1, `expected one probe, got ${cmds.length} calls`);
  assert.match(cmds[0], /sha256sum -c - >\/dev\/null 2>&1 && exit 0/);
  assert.ok(!/printf %s '/.test(cmds[0]), 'the no-op path sent a chunk');
  // `command -v base64` is preflight, not a write, so the check names only the
  // commands that would change something.
  assert.ok(!/\b(mv|mkdir|rm|cp)\b/.test(cmds[0]),
    `the no-op path issued a mutating command:\n${cmds[0]}`);
  assert.deepStrictEqual(again.steps.map((s) => s.name), ['ext-probe']);
});

test('force pushes over a destination that already matches', async () => {
  const guest = guestWithStock();
  await ext.pushExtensionConfig(pushOpts(guest));
  const res = await ext.pushExtensionConfig(pushOpts(guest, { force: true, token: 'tok2' }));
  assert.strictEqual(res.skipped, false);
  assert.strictEqual(res.pushed, true);
  assert.strictEqual(guest.read(DEST), RENAMED);
});

test('force still refuses an extension the image does not carry', async () => {
  // force means "push even though it already matches", never "create it".
  const guest = makeGuest({ dirs: ['/opt/goad/extensions/elk'] });
  await assert.rejects(
    ext.pushExtensionConfig(pushOpts(guest, { force: true })),
    (e) => e.exitcode === ext.EXT_EXIT.NO_EXT_DIR);
});

// ═══════════════════════════════════════════════════════════════════════════
// 6. Failure — the stock file survives every one of them
// ═══════════════════════════════════════════════════════════════════════════

test('a mid-transfer failure leaves the stock config byte-identical', async () => {
  const guest = guestWithStock();
  let seen = 0;
  guest.setHook((cmd) => (/^printf %s '/.test(cmd) && ++seen === 2
    ? new Error('curl exited 52: Proxmox POST failed (596)')
    : undefined));

  await assert.rejects(
    ext.pushExtensionConfig(pushOpts(guest, { chunkSize: 64 })), /596/);

  assert.strictEqual(guest.read(DEST), STOCK, 'the stock config was damaged');
  assert.ok(!guest.exists(WORK), 'the staging directory survived the failure');
  for (const s of guest.snapshots) {
    assert.strictEqual(s.dest, STOCK,
      `the destination changed during a failed push, after ${JSON.stringify(s.line)}`);
  }
});

test('a failed re-verify at install time does not replace the destination', async () => {
  // The re-hash exists so that the check and the rename are adjacent inside one
  // guest command. If it fails, nothing has been replaced.
  const guest = guestWithStock();
  guest.setHook((cmd) => (/^\[ -s /.test(cmd) ? ext.EXT_EXIT.INSTALL_VERIFY : undefined));
  await assert.rejects(
    ext.pushExtensionConfig(pushOpts(guest)),
    (e) => e.step === 'ext-install' && e.exitcode === ext.EXT_EXIT.INSTALL_VERIFY);
  assert.strictEqual(guest.read(DEST), STOCK);
  assert.ok(!guest.exists(WORK));
});

test('the error carries key, step, exitcode and dest, and names the consequence', async () => {
  // challenge-lane-deployer wraps the whole GOAD block in a catch, so this
  // message is the ONLY record of the failure an operator ever sees.
  const guest = guestWithStock();
  guest.setHook((cmd) => (/\nmkdir -p /.test(cmd) ? ext.EXT_EXIT.STAGE_MKDIR : undefined));
  await assert.rejects(ext.pushExtensionConfig(pushOpts(guest)), (e) => {
    assert.strictEqual(e.key, KEY);
    assert.strictEqual(e.step, 'ext-stage');
    assert.strictEqual(e.exitcode, ext.EXT_EXIT.STAGE_MKDIR);
    assert.strictEqual(e.dest, DEST);
    assert.match(e.message, /still holds the stock config/);
    assert.match(e.message, /domain join would fail/);
    assert.ok(Array.isArray(e.steps) && e.steps.length > 0);
    return true;
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 7. Contracts — the two halves must not drift
// ═══════════════════════════════════════════════════════════════════════════

test('goad-lab-push still exports the transport this module reuses', () => {
  // Copying runStep/sendBytes instead of sharing them would put two
  // implementations of "agentShellExec retries the TRANSPORT, not the WORK" in
  // the tree, and they would drift on the first fix to either.
  for (const name of ['assertShellSafe', 'runStep', 'sendBytes']) {
    assert.strictEqual(typeof push[name], 'function',
      `goad-lab-push no longer exports ${name}; goad-ext-config-push depends on it`);
  }
});

test('the extension pusher does not reimplement the transport', () => {
  const src = require('fs').readFileSync(
    path.join(ROOT, UTILS, 'goad-ext-config-push.js'), 'utf8');
  assert.match(src, /require\('\.\/goad-lab-push'\)/);
  for (const name of ['runStep', 'sendBytes', 'assertShellSafe']) {
    assert.ok(!new RegExp(`function ${name}\\s*\\(`).test(src),
      `${name} was re-implemented instead of imported`);
  }
});

test('the transport is never required unless the caller omits deps', () => {
  // script-executor pulls in ./proxmox and ./db at load, so this whole suite
  // runs offline only because the real transport is required lazily.
  assert.ok(!Object.keys(require.cache).some((k) => k.endsWith('script-executor.js')),
    'requiring goad-ext-config-push dragged in the Proxmox transport');
});

test('every emitted command obeys the dash discipline', () => {
  const paths = ext.extPathsFor('/opt/goad', KEY, TOKEN);
  const sha = 'a'.repeat(64);
  const commands = [
    ext.cmdProbe(paths, { sha }),
    ext.cmdProbe(paths, { sha, force: true }),
    ext.cmdStage(paths),
    ext.cmdInstall(paths, sha),
    ext.cmdCleanup(paths),
  ];
  for (const cmd of commands) {
    // No command substitution, no backticks, no here-doc: dash gives us no
    // PIPESTATUS and no `set -e`, so every construct that could hide an exit
    // code is banned by construction.
    assert.ok(!/\$\(|`|<<|\bset -e\b/.test(cmd), `unsafe construct in:\n${cmd}`);
    assert.match(cmd, /exit \d+/);
    // Every quoted token is single-quoted and, apart from printf's own format
    // string — the one place a backslash escape belongs — contains nothing
    // dash would interpret.
    for (const q of cmd.match(/'[^']*'/g) || []) {
      const body = q.slice(1, -1);
      if (body.startsWith('%s')) continue;
      assert.ok(!/[\\"$`\n\r\t]/.test(body), `unsafe quoted token: ${q}`);
    }
  }
});

test('the install replaces by rename and never by redirect', () => {
  const paths = ext.extPathsFor('/opt/goad', KEY, TOKEN);
  const cmd = ext.cmdInstall(paths, 'a'.repeat(64));
  assert.match(cmd, new RegExp(`^mv -f '${WORK}/config\\.json' '${DEST}' \\|\\| exit \\d+$`, 'm'));
  assert.ok(!new RegExp(`> '${DEST}'`).test(cmd),
    'the install redirects into the destination, which truncates before it writes');
  // The backup is conditional, so a later push cannot destroy the stock copy.
  assert.match(cmd, new RegExp(`^\\[ -f '${DEST}\\.cc-bak' \\] \\|\\| cp -p '${DEST}' `, 'm'));
  // The re-hash sits immediately before the rename: one syscall, no window.
  const lines = cmd.split('\n');
  const verifyAt = lines.findIndex((l) => l.includes('sha256sum -c -'));
  const mvAt = lines.findIndex((l) => l.startsWith('mv -f '));
  assert.strictEqual(mvAt, verifyAt + 1, 'something runs between the verify and the rename');
});

test('this file\'s exit codes cannot be confused with the shared transport\'s', () => {
  // A bare exit code in a log line has to say which half of the push failed.
  for (const [name, code] of Object.entries(ext.EXT_EXIT)) {
    assert.ok(code >= 100, `EXT_EXIT.${name} = ${code} collides with goad-lab-push's range`);
  }
  for (const code of Object.values(push.EXIT)) {
    assert.ok(code < 100, `goad-lab-push EXIT code ${code} has grown into the extension range`);
  }
  const codes = Object.values(ext.EXT_EXIT);
  assert.strictEqual(new Set(codes).size, codes.length, 'duplicate exit code');
});
