/**
 * ciab-goad-lab-push.test.js — Track G4: delivering a generated lab tree to the
 * GOAD controller.
 *
 * WHAT IS ACTUALLY AT RISK HERE, because it is not "does tar work"
 *
 *   1. DETERMINISM IS A CORRECTNESS PROPERTY, not a nicety. The .cc-manifest
 *      short-circuit compares sha256(tar) against what is already on the
 *      controller. If the tar carries anything volatile — a real mtime, the
 *      process umask, Object.keys order, a locale-dependent sort — then the
 *      hash differs on every push, the no-op never fires, and every profile
 *      deploy re-uploads the tree and re-swaps the directory. Worse, the same
 *      volatility makes "the tree changed" indistinguishable from "the clock
 *      moved", so the manifest stops meaning anything. Several tests below
 *      re-parse the tar bytes by hand rather than trusting the writer.
 *
 *   2. A PARTIAL PUSH MUST NOT BE VISIBLE. agentShellExec retries the
 *      TRANSPORT (596/ECONNRESET), not the WORK, so a chunk can simply never
 *      land. If the module wrote into /opt/goad/ad/<LAB>/ incrementally, that
 *      leaves a lab directory that is half a lab — and run.sh does not
 *      validate it, it feeds it to ansible. The FakeGuest below is a small
 *      shell interpreter over an in-memory filesystem precisely so
 *      "the destination directory does not exist after a mid-transfer failure"
 *      is a fact about the emitted commands and not an assertion about a mock
 *      call log.
 *
 *   3. THE CHAIN IS THE SECOND ARTIFACT. Pushing the tree alone succeeds,
 *      looks fine, and provisions the wrong lab: run.sh falls back to
 *      playbooks.yml `default:`, which is 16 plays including a hard 5-minute
 *      wait5m.yml plus child-domain, trusts, gmsa and laps that a single-domain
 *      generated lab has no hosts for. It fails by wasting an hour, not by
 *      erroring, which is why it gets its own tests on both delivery paths.
 *
 * The FakeGuest interpreter deliberately THROWS on any command shape it does
 * not recognise. That keeps it honest: a future edit to a shell string cannot
 * quietly stop being simulated and start passing vacuously.
 *
 * Run: node --test front-end/test/ciab-goad-lab-push.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');

const ROOT = path.join(__dirname, '..');
const push = require(path.join(
  ROOT, 'modules/crucible/plugins/ciab/utils/goad-lab-push.js'));

const LAB = 'CIAB-3f9a2c1b';
const CHAIN = ['build.yml', 'ad-servers.yml', 'ad-parent_domain.yml', 'ad-data.yml',
  'ad-relations.yml', 'ad-acl.yml', 'security.yml', 'vulnerabilities.yml'];

/** A realistic-shaped minimal lab tree. */
function sampleFiles() {
  return {
    'data/config.json': JSON.stringify({
      domains: { 'ciab.local': { domain_password: 'Sup3rS3cret!' } },
      hosts: { dc01: { local_admin_password: 'Sup3rS3cret!' } },
    }, null, 2) + '\n',
    'data/inventory': '[domain_controllers]\ndc01\n\n[dc]\ndc01\n',
    'providers/proxmox/inventory': '[all:vars]\nip_range={{ip_range}}\n',
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// A hand-rolled tar reader, so the writer is checked against something that
// did not come out of the same head. Only the fields we pin are decoded.
// ═══════════════════════════════════════════════════════════════════════════

function cstr(buf, off, len) {
  const slice = buf.subarray(off, off + len);
  const nul = slice.indexOf(0);
  return slice.subarray(0, nul === -1 ? slice.length : nul).toString('utf8');
}

function readTar(buf) {
  const out = [];
  let off = 0;
  while (off + 512 <= buf.length) {
    const hdr = buf.subarray(off, off + 512);
    if (hdr.every((b) => b === 0)) break;

    // Verify the checksum the same way tar does: the field itself reads as
    // eight spaces. A writer that pads it differently produces an archive GNU
    // tar rejects with "bad header" and nothing else explains why.
    let sum = 0;
    for (let i = 0; i < 512; i++) sum += (i >= 148 && i < 156) ? 0x20 : hdr[i];
    const stated = parseInt(cstr(hdr, 148, 8).trim() || '-1', 8);
    assert.strictEqual(sum, stated, `bad tar checksum at offset ${off}`);

    const name = cstr(hdr, 0, 100);
    const prefix = cstr(hdr, 345, 155);
    const size = parseInt(cstr(hdr, 124, 12).trim() || '0', 8);
    out.push({
      path: prefix ? `${prefix}/${name}` : name,
      size,
      mode: parseInt(cstr(hdr, 100, 8).trim() || '0', 8),
      uid: parseInt(cstr(hdr, 108, 8).trim() || '0', 8),
      gid: parseInt(cstr(hdr, 116, 8).trim() || '0', 8),
      mtime: parseInt(cstr(hdr, 136, 12).trim() || '0', 8),
      type: String.fromCharCode(hdr[156]),
      magic: cstr(hdr, 257, 6),
      uname: cstr(hdr, 265, 32),
      gname: cstr(hdr, 297, 32),
      content: buf.subarray(off + 512, off + 512 + size),
    });
    off += 512 + 512 * Math.ceil(size / 512);
  }
  return out;
}

const sha256 = (b) => crypto.createHash('sha256').update(b).digest('hex');

// ═══════════════════════════════════════════════════════════════════════════
// FakeGuest — an in-memory Debian-ish filesystem plus just enough /bin/sh to
// run the exact command shapes this module emits.
// ═══════════════════════════════════════════════════════════════════════════

function makeGuest(seed = {}) {
  const dirs = new Set(['/', '/opt', '/opt/goad', '/opt/goad/ad', '/opt/goad-light', '/tmp']);
  const files = new Map();
  const log = [];        // every command string, in order
  const snapshots = [];  // { cmd, destExisted } — for the atomicity assertions
  let hook = null;       // (cmd, index) => number|Error|undefined

  for (const [p, c] of Object.entries(seed.files || {})) {
    files.set(p, Buffer.isBuffer(c) ? c : Buffer.from(String(c), 'utf8'));
    mkdirp(parentOf(p));
  }
  for (const d of (seed.dirs || [])) mkdirp(d);

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

  const Q = "'([^']*)'";
  const OPT_EXIT = '(?: \\|\\| exit (\\d+))?';

  function runLine(line) {
    let m;
    if ((m = line.match(/^exit (\d+)$/))) return { exit: Number(m[1]) };

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

    if ((m = line.match(new RegExp(`^grep -qxF ${Q} ${Q} \\|\\| exit (\\d+)$`)))) {
      const body = files.has(m[2]) ? files.get(m[2]).toString('utf8') : null;
      const hit = body !== null && body.split('\n').includes(m[1]);
      return hit ? {} : { exit: Number(m[3]) };
    }

    if ((m = line.match(new RegExp(`^grep -n ${Q} ${Q} \\| grep -q ${Q} && exit (\\d+)$`)))) {
      const pat = m[1].replace(/\\\./g, '.');
      const body = files.has(m[2]) ? files.get(m[2]).toString('utf8') : '';
      const hit = body.split('\n').some((l) => l.includes(pat) && l.includes(m[3]));
      return hit ? { exit: Number(m[4]) } : {};
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
    if ((m = line.match(new RegExp(`^printf '%s\\\\n' ((?:'[^']*' ?)+) > ${Q}${OPT_EXIT}$`)))) {
      const parts = (m[1].match(/'([^']*)'/g) || []).map((s) => s.slice(1, -1));
      const rc = writeFile(m[2], Buffer.from(`${parts.join('\n')}\n`, 'utf8'));
      return rc === 0 ? {} : { exit: m[3] ? Number(m[3]) : rc };
    }
    if ((m = line.match(new RegExp(`^base64 -d < ${Q} > ${Q}${OPT_EXIT}$`)))) {
      if (!files.has(m[1])) return { exit: m[3] ? Number(m[3]) : 1 };
      const rc = writeFile(m[2], Buffer.from(files.get(m[1]).toString('utf8'), 'base64'));
      return rc === 0 ? {} : { exit: m[3] ? Number(m[3]) : rc };
    }
    if ((m = line.match(new RegExp(
      `^printf '%s  %s\\\\n' ${Q} ${Q} \\| sha256sum -c - >/dev/null 2>&1 \\|\\| exit (\\d+)$`)))) {
      const got = files.has(m[2]) ? sha256(files.get(m[2])) : null;
      return got === m[1] ? {} : { exit: Number(m[3]) };
    }
    if ((m = line.match(new RegExp(`^tar -xzf ${Q} -C ${Q}${OPT_EXIT}$`)))) {
      if (!files.has(m[1]) || !dirs.has(m[2])) return { exit: m[3] ? Number(m[3]) : 2 };
      let plain;
      try { plain = zlib.gunzipSync(files.get(m[1])); } catch { return { exit: m[3] ? Number(m[3]) : 2 }; }
      for (const e of readTar(plain)) {
        const abs = `${m[2]}/${e.path.replace(/\/$/, '')}`;
        if (e.type === '5') mkdirp(abs);
        else { mkdirp(parentOf(abs)); files.set(abs, Buffer.from(e.content)); }
      }
      return {};
    }
    if ((m = line.match(new RegExp(`^if \\[ -e ${Q} \\]; then mv ${Q} ${Q} \\|\\| exit (\\d+); fi$`)))) {
      if (!exists(m[1])) return {};
      return moveTree(m[2], m[3]) === 0 ? {} : { exit: Number(m[4]) };
    }
    if ((m = line.match(new RegExp(
      `^mv ${Q} ${Q} \\|\\| \\{ if \\[ -e ${Q} \\]; then mv ${Q} ${Q}; fi; exit (\\d+); \\}$`)))) {
      if (moveTree(m[1], m[2]) === 0) return {};
      if (exists(m[3])) moveTree(m[4], m[5]);
      return { exit: Number(m[6]) };
    }
    if ((m = line.match(new RegExp(`^mv ${Q} ${Q}${OPT_EXIT}$`)))) {
      const rc = moveTree(m[1], m[2]);
      return rc === 0 ? {} : { exit: m[3] ? Number(m[3]) : rc };
    }
    if ((m = line.match(new RegExp(`^cat ${Q} 2>/dev/null$`)))) {
      return files.has(m[1]) ? { stdout: files.get(m[1]).toString('utf8') } : {};
    }
    if ((m = line.match(new RegExp(`^cp -p ${Q} ${Q} 2>/dev/null$`)))) {
      if (files.has(m[1])) files.set(m[2], files.get(m[1]));
      return {};
    }
    throw new Error(`FakeGuest: unrecognised shell line: ${JSON.stringify(line)}`);
  }

  function run(cmd) {
    let stdout = '';
    for (const raw of cmd.split('\n')) {
      const line = raw.trim();
      if (line === '') continue;
      const r = runLine(line);
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
    read(p) { return files.has(p) ? files.get(p).toString('utf8') : null; },
    tree(prefix) {
      return [...files.keys()].filter((k) => k.startsWith(`${prefix}/`)).sort();
    },
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
          snapshots.push({ cmd, destExists: exists(`/opt/goad/ad/${LAB}`) });
          return { exited: true, exitcode: forced, stdout: '', stderr: 'forced' };
        }
      }
      const r = run(cmd);
      snapshots.push({ cmd, destExists: exists(`/opt/goad/ad/${LAB}`) });
      return { exited: true, exitcode: r.exitcode, stdout: r.stdout, stderr: '' };
    },
  };
}

/** The shared playbooks.yml as the baked controller actually has it. */
const UPSTREAM_PLAYBOOKS = `GOAD-Mini:
  - build.yml
  - ad-servers.yml
  - vulnerabilities.yml

default:
  - build.yml
  - ad-servers.yml
  - ad-parent_domain.yml
  # Wait after the child domain creation before adding servers
  - ad-child_domain.yml
  - wait5m.yml
  - vulnerabilities.yml
`;

/** run.sh from the CURRENT bake: reads only the shared file. */
const RUN_SH_SHARED = `#!/bin/bash
GOAD_ROOT=/opt/goad
LAB_DATA="$GOAD_ROOT/ad/$LAB/data"
PLAYBOOKS_YML="$GOAD_ROOT/playbooks.yml"
`;

/** run.sh with the per-lab override another agent is adding this wave. */
const RUN_SH_PER_LAB = `#!/bin/bash
GOAD_ROOT=/opt/goad
PLAYBOOKS_YML="$GOAD_ROOT/playbooks.yml"
if [ -f "$GOAD_ROOT/ad/$LAB/playbooks.yml" ]; then PLAYBOOKS_YML="$GOAD_ROOT/ad/$LAB/playbooks.yml"; fi
`;

function guestWith(runSh) {
  return makeGuest({
    files: {
      '/opt/goad/playbooks.yml': UPSTREAM_PLAYBOOKS,
      '/opt/goad-light/run.sh': runSh,
    },
  });
}

function pushOpts(guest, extra) {
  return Object.assign({
    node: 'node-1',
    vmId: 1701,
    lab: LAB,
    files: sampleFiles(),
    chain: CHAIN,
    token: 'testtoken',
    log: { log() {}, warn() {} },
    deps: { agentShellExec: guest.agentShellExec, pollExecStatus: guest.pollExecStatus },
  }, extra || {});
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. Determinism — the property the whole idempotency scheme rests on
// ═══════════════════════════════════════════════════════════════════════════

test('identical input yields byte-identical tar bytes and the same hash', () => {
  const a = push.buildLabArchive(sampleFiles());
  const b = push.buildLabArchive(sampleFiles());
  assert.ok(a.tar.equals(b.tar), 'tar bytes differ between two builds of the same tree');
  assert.strictEqual(a.treeSha256, b.treeSha256);
  assert.ok(a.gz.equals(b.gz), 'gz bytes differ between two builds of the same tree');
  assert.strictEqual(a.transferSha256, b.transferSha256);
});

test('the object key order the caller happens to have does not change the bytes', () => {
  // The realistic way this breaks: a generator builds its tree with spread or
  // conditional assignment, so key insertion order varies run to run. Nothing
  // about the LAB changed, but every push would re-upload.
  const forward = sampleFiles();
  const reversed = {};
  for (const k of Object.keys(forward).reverse()) reversed[k] = forward[k];
  assert.notDeepStrictEqual(Object.keys(forward), Object.keys(reversed));
  assert.strictEqual(
    push.buildLabArchive(forward).treeSha256,
    push.buildLabArchive(reversed).treeSha256);
});

test('an array of entries and the equivalent object produce the same archive', () => {
  const obj = sampleFiles();
  const arr = Object.keys(obj).sort().reverse().map((p) => ({ path: p, content: obj[p] }));
  assert.strictEqual(
    push.buildLabArchive(obj).treeSha256,
    push.buildLabArchive(arr).treeSha256);
});

test('every volatile tar header field is pinned', () => {
  const entries = readTar(push.buildTar(sampleFiles()));
  assert.ok(entries.length > 0);
  for (const e of entries) {
    assert.strictEqual(e.mtime, push.TAR_MTIME, `${e.path} carries a live mtime`);
    assert.strictEqual(e.uid, 0);
    assert.strictEqual(e.gid, 0);
    assert.strictEqual(e.uname, 'root');
    assert.strictEqual(e.gname, 'root');
    assert.strictEqual(e.magic, 'ustar');
    assert.strictEqual(e.mode, e.type === '5' ? 0o755 : 0o644,
      `${e.path} mode is not pinned (a umask leaked in)`);
  }
  // mtime 0 would be deterministic too, but GNU tar prints "implausibly old
  // time stamp" for every member on extraction — stderr noise on a channel we
  // are keeping quiet.
  assert.ok(push.TAR_MTIME > 0);
});

test('entries are sorted and every parent directory precedes its children', () => {
  const entries = readTar(push.buildTar({
    'z/last.txt': 'z',
    'data/config.json': '{}',
    'providers/proxmox/inventory': 'x',
  }));
  const paths = entries.map((e) => e.path.replace(/\/$/, ''));
  assert.deepStrictEqual(paths, [...paths].sort(),
    'entry order is not a stable byte sort');
  assert.deepStrictEqual(paths, [
    'data', 'data/config.json',
    'providers', 'providers/proxmox', 'providers/proxmox/inventory',
    'z', 'z/last.txt',
  ]);
  assert.strictEqual(entries.filter((e) => e.type === '5').length, 4,
    'explicit directory entries are missing — extraction mode would come from the umask');
});

test('the archive is padded to a whole tar record so no reader reports a short read', () => {
  const tar = push.buildTar(sampleFiles());
  assert.strictEqual(tar.length % (push.TAR_BLOCK * 20), 0);
  // ...and still ends in the two zero blocks that mark end-of-archive.
  assert.ok(tar.subarray(tar.length - 1024).every((b) => b === 0));
});

test('a changed file changes the hash — content, path, or an addition', () => {
  const base = push.buildLabArchive(sampleFiles()).treeSha256;

  const changedContent = sampleFiles();
  changedContent['data/inventory'] += 'srv01\n';
  assert.notStrictEqual(push.buildLabArchive(changedContent).treeSha256, base);

  // One byte, in the middle of a password. This is the case that matters: a
  // regenerated lab with the same shape and different credentials MUST push.
  const oneByte = sampleFiles();
  oneByte['data/config.json'] = oneByte['data/config.json'].replace('Sup3rS3cret!', 'Sup3rS3cret?');
  assert.notStrictEqual(push.buildLabArchive(oneByte).treeSha256, base);

  const renamed = sampleFiles();
  renamed['data/inventory2'] = renamed['data/inventory'];
  delete renamed['data/inventory'];
  assert.notStrictEqual(push.buildLabArchive(renamed).treeSha256, base);

  const added = sampleFiles();
  added['files/dc01/note.txt'] = 'hello';
  assert.notStrictEqual(push.buildLabArchive(added).treeSha256, base);
});

test('the chain is part of the content address, so a chain edit is not a no-op', () => {
  const a = push.chainSha256(LAB, CHAIN);
  const b = push.chainSha256(LAB, [...CHAIN, 'adcs.yml']);
  assert.notStrictEqual(a, b);
  // ...and the lab name is in it, so two labs never collide on chain identity.
  assert.notStrictEqual(push.chainSha256('CIAB-other', CHAIN), a);
});

test('the gzip container is portable-stable and actually gunzips', () => {
  const tar = push.buildTar(sampleFiles());
  const gz = push.gzipDeterministic(tar);
  assert.ok(zlib.gunzipSync(gz).equals(tar), 'gz does not round-trip');
  assert.strictEqual(gz[0], 0x1f);
  assert.strictEqual(gz[1], 0x8b);
  // MTIME bytes 4..7 must be zero and the OS byte must be 0xff ("unknown").
  // zlib.gzipSync stamps the compiling platform there (0x0a on Windows, 0x03 on
  // Unix), which would make the wire bytes differ between a dev laptop and the
  // container for identical input.
  assert.deepStrictEqual([...gz.subarray(4, 8)], [0, 0, 0, 0]);
  assert.strictEqual(gz[9], 0xff);
});

test('an oversized tree is refused before a single chunk is sent', () => {
  const big = { 'data/config.json': 'x'.repeat(1024), 'data/blob': Buffer.alloc(0) };
  // Incompressible bytes, so the gz stays over the ceiling.
  big['data/blob'] = crypto.randomBytes(push.MAX_ARCHIVE_BYTES + 4096);
  assert.throws(() => push.buildLabArchive(big), /over the .* ceiling/);
});

// ═══════════════════════════════════════════════════════════════════════════
// 2. Chunking
// ═══════════════════════════════════════════════════════════════════════════

test('chunkString splits and reassembles at every boundary size', () => {
  const body = 'abcdefghij'.repeat(30);   // 300 chars
  for (const size of [1, 2, 7, 99, 100, 149, 150, 151, 299, 300, 301, 4096]) {
    const parts = push.chunkString(body, size);
    assert.strictEqual(parts.join(''), body, `reassembly failed at size ${size}`);
    assert.strictEqual(parts.length, Math.ceil(body.length / size), `chunk count wrong at size ${size}`);
    for (const p of parts.slice(0, -1)) {
      assert.strictEqual(p.length, size, `a non-final chunk is short at size ${size}`);
    }
    assert.ok(parts[parts.length - 1].length > 0, `empty tail chunk at size ${size}`);
  }
  assert.deepStrictEqual(push.chunkString('', 10), [], 'empty input must produce no calls');
  assert.deepStrictEqual(push.chunkString('a', 10), ['a']);
  assert.throws(() => push.chunkString('abc', 0), /Invalid chunk size/);
});

test('a chunk command is a single append that can emit nothing on stdout', () => {
  const cmd = push.cmdAppendChunk('/opt/goad/ad/.cc-push-t/payload.b64', 'QUJD');
  // Exactly this shape, on one line: anything else (an echo, a `set -x`, a
  // command substitution) accumulates in QGA's per-process output buffer across
  // ~30 calls, and turns a transfer into a diagnostics problem.
  assert.match(cmd, /^printf %s '[A-Za-z0-9+/=]*' >> '[^']+'$/);
  assert.ok(!cmd.includes('\n'));
  assert.ok(!/echo|cat |printf .*>&|tee/.test(cmd.replace(/^printf %s /, '')));
});

test('base64 payloads cannot contain a character that escapes the single quotes', () => {
  // The single-quoting in cmdAppendChunk is only safe because of this.
  const b64 = push.buildLabArchive(sampleFiles()).gz.toString('base64');
  assert.match(b64, /^[A-Za-z0-9+/=]+$/);
});

// ═══════════════════════════════════════════════════════════════════════════
// 3. Input guards
// ═══════════════════════════════════════════════════════════════════════════

test("the lab name 'default' is refused — it is the inheritance key", () => {
  // Merging our chain under `default:` would rewrite the chain for every lab on
  // the controller, upstream's included.
  assert.throws(() => push.assertLabName('default'), /inheritance key/);
});

test("upstream's shipped lab names are refused", () => {
  for (const name of push.RESERVED_LAB_NAMES) {
    assert.throws(() => push.assertLabName(name), /shipped labs/, `${name} was accepted`);
  }
  assert.strictEqual(push.assertLabName(LAB), LAB);
});

test('lab names that are not safe as a shell path, YAML key and tar prefix are refused', () => {
  for (const bad of ["a'b", 'a b', '../evil', 'a/b', '$LAB', '', 'a\nb']) {
    assert.throws(() => push.assertLabName(bad), /Invalid lab name/, `${JSON.stringify(bad)} was accepted`);
  }
});

test('traversal, absolute and duplicate member paths are refused, not sanitized', () => {
  assert.throws(() => push.buildTar({ '../ansible/roles/x': 'x' }), /Unsafe path/);
  assert.throws(() => push.buildTar({ '/etc/passwd': 'x' }), /Absolute path/);
  assert.throws(() => push.buildTar({ 'data/./config.json': 'x' }), /Unsafe path/);
  // Two spellings of one member: silently letting one win is how a lab loses a
  // file with no diff to look at.
  assert.throws(() => push.buildTar({ 'data/x': 'a', 'data\\x': 'b' }), /Duplicate path/);
  assert.throws(() => push.buildTar({}), /empty/);
});

test('a chain of non-playbooks is refused, and an empty chain names the consequence', () => {
  assert.throws(() => push.assertChain([]), /inherits playbooks\.yml `default:`/);
  assert.throws(() => push.assertChain(null), /inherits/);
  assert.throws(() => push.assertChain(['../../etc/shadow']), /Invalid playbook/);
  assert.throws(() => push.assertChain(['ansible/build.yml']), /never a path/);
  // Duplicates ARE legal: SCCM lists wait5m.yml three times on purpose.
  assert.deepStrictEqual(push.assertChain(['wait5m.yml', 'wait5m.yml']), ['wait5m.yml', 'wait5m.yml']);
});

test('CRLF in text content is normalized, because a \\r rides into every value', () => {
  const a = push.buildLabArchive({ 'data/inventory': '[dc]\r\ndc01\r\n' });
  const b = push.buildLabArchive({ 'data/inventory': '[dc]\ndc01\n' });
  assert.strictEqual(a.treeSha256, b.treeSha256);
  // A Buffer is the escape hatch and is passed through byte for byte.
  const raw = push.buildLabArchive({ 'data/inventory': Buffer.from('[dc]\r\ndc01\r\n', 'utf8') });
  assert.notStrictEqual(raw.treeSha256, b.treeSha256);
});

// ═══════════════════════════════════════════════════════════════════════════
// 4. The chain, artifact two
// ═══════════════════════════════════════════════════════════════════════════

test('the lab-local playbooks.yml carries the chain under BOTH keys', () => {
  const text = push.renderLabPlaybooksYaml(LAB, CHAIN);
  // run.sh resolves `data.get(LAB) or data.get("default")`. Whichever key the
  // per-lab override reaches, it must find THIS chain — a miss falls through to
  // the shared file's 16-play default, silently.
  assert.match(text, new RegExp(`^${LAB}:$`, 'm'));
  assert.match(text, /^default:$/m);
  for (const p of CHAIN) {
    assert.strictEqual((text.match(new RegExp(`^  - ${p.replace('.', '\\.')}$`, 'gm')) || []).length, 2,
      `${p} must appear under both keys`);
  }
  // The chain itself must be ours and nothing else. Only the non-comment lines
  // are the chain; the header comment names the default: plays it exists to
  // avoid, so a naive substring check would trip on its own explanation.
  const listed = text.split(/\r?\n/).filter((l) => l.startsWith('  - '));
  assert.deepStrictEqual([...new Set(listed)].sort(),
    CHAIN.map((p) => `  - ${p}`).sort());
  assert.ok(!listed.some((l) => /wait5m\.yml|ad-child_domain\.yml|laps\.yml|ad-gmsa\.yml/.test(l)),
    'the lab-local chain must not carry the default: plays a single-domain lab has no hosts for');
});

test('merging into the shared playbooks.yml adds our key and touches nothing else', () => {
  const { text, changed, replaced } = push.mergePlaybooksYaml(UPSTREAM_PLAYBOOKS, LAB, CHAIN);
  assert.strictEqual(changed, true);
  assert.strictEqual(replaced, false);
  assert.match(text, new RegExp(`^${LAB}:$`, 'm'));
  // Upstream's own labs, and its load-bearing comments, survive verbatim. A
  // YAML round-trip would have deleted `# Wait after the child domain...`, and
  // in this file a commented-out entry is a semantic statement.
  assert.ok(text.startsWith('GOAD-Mini:\n  - build.yml'));
  assert.match(text, /^default:$/m);
  assert.match(text, /# Wait after the child domain creation before adding servers/);
  assert.match(text, /^  - ad-child_domain\.yml$/m);
});

test('merging is idempotent, which is what makes "no write needed" trustworthy', () => {
  const once = push.mergePlaybooksYaml(UPSTREAM_PLAYBOOKS, LAB, CHAIN);
  const twice = push.mergePlaybooksYaml(once.text, LAB, CHAIN);
  assert.strictEqual(twice.text, once.text);
  assert.strictEqual(twice.changed, false, 'a second merge would rewrite the shared file forever');
  assert.strictEqual(twice.replaced, true);
});

test('a changed chain replaces the old block instead of appending a second one', () => {
  const first = push.mergePlaybooksYaml(UPSTREAM_PLAYBOOKS, LAB, CHAIN).text;
  const second = push.mergePlaybooksYaml(first, LAB, ['build.yml', 'vulnerabilities.yml']).text;
  assert.strictEqual((second.match(new RegExp(`^${LAB}:$`, 'gm')) || []).length, 1,
    'duplicate top-level keys — the second silently wins in YAML and the first is a lie');
  assert.ok(!second.includes('ad-parent_domain.yml') || second.includes('default:'));
  assert.match(second, /^  - vulnerabilities\.yml$/m);
});

test('a merge never rewrites the default: block', () => {
  const before = UPSTREAM_PLAYBOOKS.split('default:')[1];
  const after = push.mergePlaybooksYaml(UPSTREAM_PLAYBOOKS, LAB, CHAIN).text;
  assert.ok(after.includes(`default:${before.replace(/\n+$/, '')}`),
    'the default: chain must come through untouched');
});

test('a merge into an empty or missing file still produces a valid single block', () => {
  const { text, changed } = push.mergePlaybooksYaml('', LAB, CHAIN);
  assert.strictEqual(changed, true);
  assert.strictEqual(text, `${LAB}:\n${CHAIN.map((p) => `  - ${p}\n`).join('')}`);
  assert.strictEqual(push.mergePlaybooksYaml(text, LAB, CHAIN).changed, false);
});

// ═══════════════════════════════════════════════════════════════════════════
// 5. End to end over the fake guest
// ═══════════════════════════════════════════════════════════════════════════

test('a push installs the whole tree, the chain and a manifest, and cleans up', async () => {
  const guest = guestWith(RUN_SH_SHARED);
  const res = await push.pushLabTree(pushOpts(guest));

  assert.strictEqual(res.skipped, false);
  assert.strictEqual(res.pushed, true);
  assert.strictEqual(res.chainMode, 'shared');
  assert.ok(res.chunks >= 1);

  const dest = `/opt/goad/ad/${LAB}`;
  const files = sampleFiles();
  for (const p of Object.keys(files)) {
    assert.strictEqual(guest.read(`${dest}/${p}`), files[p], `${p} did not land intact`);
  }
  // Artifact two rode the tree.
  assert.ok(guest.read(`${dest}/playbooks.yml`).includes(`${LAB}:`));
  // ...and the manifest is the content address, inside the lab directory.
  const manifest = guest.read(`${dest}/.cc-manifest`);
  assert.match(manifest, new RegExp(`^tree_sha256=${res.treeSha256}$`, 'm'));
  assert.match(manifest, new RegExp(`^chain_sha256=${res.chainSha256}$`, 'm'));
  assert.match(manifest, /^chain_mode=shared$/m);

  // No staging litter left under ad/.
  assert.ok(!guest.exists('/opt/goad/ad/.cc-push-testtoken'));
  assert.ok(!guest.exists('/opt/goad/ad/.cc-old-testtoken'));
});

test('the shared playbooks.yml gets the key when run.sh cannot read a per-lab one', async () => {
  const guest = guestWith(RUN_SH_SHARED);
  const res = await push.pushLabTree(pushOpts(guest));
  assert.strictEqual(res.sharedPlaybooksChanged, true);
  const shared = guest.read('/opt/goad/playbooks.yml');
  assert.match(shared, new RegExp(`^${LAB}:$`, 'm'));
  assert.match(shared, /^  - vulnerabilities\.yml$/m);
  assert.ok(shared.startsWith('GOAD-Mini:'), 'upstream content was disturbed');
  // The install is a rename over a backup, never a truncating redirect: a dead
  // write must not leave every lab on the box without a chain.
  assert.strictEqual(guest.read('/opt/goad/playbooks.yml.cc-bak'), UPSTREAM_PLAYBOOKS);
});

test('when run.sh does read ad/<LAB>/playbooks.yml, the shared file is left alone', async () => {
  const guest = guestWith(RUN_SH_PER_LAB);
  const res = await push.pushLabTree(pushOpts(guest));
  assert.strictEqual(res.chainMode, 'per-lab');
  assert.strictEqual(res.sharedPlaybooksChanged, false);
  assert.strictEqual(guest.read('/opt/goad/playbooks.yml'), UPSTREAM_PLAYBOOKS,
    'shared state was modified even though the lab-local override is supported');
  assert.ok(guest.read(`/opt/goad/ad/${LAB}/playbooks.yml`).includes('vulnerabilities.yml'));
});

test('an explicit marker file is honoured even when run.sh looks old', async () => {
  const guest = makeGuest({
    files: {
      '/opt/goad/playbooks.yml': UPSTREAM_PLAYBOOKS,
      '/opt/goad-light/run.sh': RUN_SH_SHARED,
      '/opt/goad-light/.cc-per-lab-playbooks': '1',
    },
  });
  const res = await push.pushLabTree(pushOpts(guest));
  assert.strictEqual(res.chainMode, 'per-lab');
  assert.strictEqual(guest.read('/opt/goad/playbooks.yml'), UPSTREAM_PLAYBOOKS);
});

test('the destination appears exactly once, by rename, and never grows a file at a time', async () => {
  const guest = guestWith(RUN_SH_SHARED);
  await push.pushLabTree(pushOpts(guest));

  const transitions = [];
  let prev = false;
  for (const s of guest.snapshots) {
    if (s.destExists !== prev) transitions.push(s.cmd);
    prev = s.destExists;
  }
  assert.strictEqual(transitions.length, 1,
    'the destination directory changed existence more than once');
  assert.match(transitions[0], /^mv '[^']*\/tree' '\/opt\/goad\/ad\/CIAB-3f9a2c1b'/m,
    'the destination was created by something other than the atomic rename');
});

test('the tree is staged and swapped, so no command ever writes inside the destination', async () => {
  const guest = guestWith(RUN_SH_SHARED);
  await push.pushLabTree(pushOpts(guest));
  const dest = `/opt/goad/ad/${LAB}`;
  for (const cmd of guest.log) {
    const writesInside = new RegExp(`(printf|base64 -d <|tar -xzf)[^\\n]*'${dest}/`).test(cmd);
    assert.ok(!writesInside, `a command writes directly into the destination:\n${cmd}`);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// 6. Failure and idempotency — the two behaviours the design exists for
// ═══════════════════════════════════════════════════════════════════════════

test('a mid-transfer failure leaves NO directory at the destination', async () => {
  const guest = guestWith(RUN_SH_SHARED);
  // Kill it partway through the chunk stream, the way a 596 that outlived its
  // five retries would.
  let seen = 0;
  guest.setHook((cmd) => {
    if (/^printf %s '/.test(cmd) && ++seen === 2) {
      return new Error('curl exited 52: Proxmox POST failed (596)');
    }
    return undefined;
  });

  await assert.rejects(
    push.pushLabTree(pushOpts(guest, { chunkSize: 64 })),
    /596/);

  const dest = `/opt/goad/ad/${LAB}`;
  assert.ok(!guest.exists(dest), 'a half-populated lab directory was left behind');
  assert.strictEqual(guest.tree(dest).length, 0);
  // ...and the staging area went with it.
  assert.ok(!guest.exists('/opt/goad/ad/.cc-push-testtoken'));
});

test('a failure at the extract step also leaves the destination absent', async () => {
  const guest = guestWith(RUN_SH_SHARED);
  guest.setHook((cmd) => (/^mkdir -p '[^']*\/tree'/.test(cmd) ? push.EXIT.EXTRACT : undefined));
  await assert.rejects(push.pushLabTree(pushOpts(guest)), /extract/);
  assert.ok(!guest.exists(`/opt/goad/ad/${LAB}`));
  assert.ok(!guest.exists('/opt/goad/ad/.cc-push-testtoken'));
});

test('an existing good lab survives a failed re-push', async () => {
  const guest = guestWith(RUN_SH_SHARED);
  await push.pushLabTree(pushOpts(guest));
  const dest = `/opt/goad/ad/${LAB}`;
  const before = guest.read(`${dest}/data/config.json`);

  const changed = sampleFiles();
  changed['data/config.json'] = '{"hosts":{}}';
  let seen = 0;
  guest.setHook((cmd) => (/^printf %s '/.test(cmd) && ++seen === 2 ? new Error('ECONNRESET') : undefined));
  await assert.rejects(
    push.pushLabTree(pushOpts(guest, { files: changed, chunkSize: 64, token: 'tok2' })),
    /ECONNRESET/);

  assert.strictEqual(guest.read(`${dest}/data/config.json`), before,
    'the previously good lab was damaged by a failed push');
});

test('re-pushing identical content performs no writes at all', async () => {
  const guest = guestWith(RUN_SH_SHARED);
  const first = await push.pushLabTree(pushOpts(guest));
  const marker = guest.log.length;

  const again = await push.pushLabTree(pushOpts(guest));
  assert.strictEqual(again.skipped, true);
  assert.strictEqual(again.pushed, false);
  assert.strictEqual(again.chunks, 0);
  assert.strictEqual(again.treeSha256, first.treeSha256);

  const cmds = guest.log.slice(marker);
  assert.ok(cmds.length <= 2, `expected only probes, got ${cmds.length} calls`);
  for (const cmd of cmds) {
    assert.ok(!/\b(mv|mkdir|rm|tar|printf|cp)\b/.test(cmd),
      `a re-push of identical content issued a mutating command:\n${cmd}`);
  }
});

test('a re-push after a content change is NOT skipped', async () => {
  const guest = guestWith(RUN_SH_SHARED);
  await push.pushLabTree(pushOpts(guest));

  const changed = sampleFiles();
  changed['data/config.json'] = changed['data/config.json'].replace('Sup3rS3cret!', 'Rotated1!');
  const res = await push.pushLabTree(pushOpts(guest, { files: changed, token: 'tok2' }));
  assert.strictEqual(res.skipped, false);
  assert.match(guest.read(`/opt/goad/ad/${LAB}/data/config.json`), /Rotated1!/);
  // The replaced directory was retired and deleted, not left beside the new one.
  assert.ok(!guest.exists('/opt/goad/ad/.cc-old-tok2'));
});

test('a re-push after a CHAIN change is not skipped even though the files match', async () => {
  const guest = guestWith(RUN_SH_SHARED);
  await push.pushLabTree(pushOpts(guest));
  const res = await push.pushLabTree(pushOpts(guest, {
    chain: [...CHAIN, 'adcs.yml'], token: 'tok3',
  }));
  assert.strictEqual(res.skipped, false);
  assert.match(guest.read('/opt/goad/playbooks.yml'), /^  - adcs\.yml$/m);
  assert.match(guest.read(`/opt/goad/ad/${LAB}/playbooks.yml`), /^  - adcs\.yml$/m);
});

test('a hand-deleted key in the shared file is noticed and restored', async () => {
  // The manifest lives in the lab directory; the shared key does not. Trusting
  // our own past tense would leave a lab that inherits `default:` forever.
  const guest = guestWith(RUN_SH_SHARED);
  await push.pushLabTree(pushOpts(guest));
  guest.files.set('/opt/goad/playbooks.yml', Buffer.from(UPSTREAM_PLAYBOOKS, 'utf8'));

  const res = await push.pushLabTree(pushOpts(guest, { token: 'tok4' }));
  assert.strictEqual(res.skipped, false);
  assert.match(guest.read('/opt/goad/playbooks.yml'), new RegExp(`^${LAB}:$`, 'm'));
});

test('force ignores a matching manifest', async () => {
  const guest = guestWith(RUN_SH_SHARED);
  await push.pushLabTree(pushOpts(guest));
  const res = await push.pushLabTree(pushOpts(guest, { force: true, token: 'tok5' }));
  assert.strictEqual(res.skipped, false);
});

test('a missing tool on the controller fails loudly with the step that found it', async () => {
  const guest = guestWith(RUN_SH_SHARED);
  guest.setHook((cmd) => (/command -v sha256sum/.test(cmd) ? push.EXIT.NO_SHA256 : undefined));
  await assert.rejects(push.pushLabTree(pushOpts(guest)),
    (e) => e.step === 'preflight' && e.exitcode === push.EXIT.NO_SHA256);
});

test('the transport is never required unless the caller omits deps', () => {
  // script-executor pulls in ./proxmox and ./db at load; this whole suite runs
  // offline only because the real transport is required lazily.
  assert.ok(!Object.keys(require.cache).some((k) => k.endsWith('script-executor.js')),
    'requiring goad-lab-push dragged in the Proxmox transport');
});

test('every guest command is built from validated, quote-free paths', () => {
  const paths = push.labPathsFor('/opt/goad', LAB, 'testtoken');
  const commands = [
    push.cmdPreflight(paths),
    push.cmdSupportsPerLabPlaybooks('/opt/goad-light/run.sh', '/opt/goad-light/.cc-per-lab-playbooks'),
    push.cmdProbeManifest(paths, { treeSha: 'a'.repeat(64), chainSha: 'b'.repeat(64), chainMode: 'shared', sharedKeyLine: `${LAB}:` }),
    push.cmdStage(paths),
    push.cmdTruncate(paths.payloadB64),
    push.cmdDecodeVerify(paths.payloadB64, paths.payloadTgz, 'c'.repeat(64)),
    push.cmdExtract(paths),
    push.cmdWriteManifest(paths, push.buildManifest({
      lab: LAB, treeSha: 'a'.repeat(64), chainSha: 'b'.repeat(64), chainMode: 'shared',
      pushedAt: '2026-08-31T00:00:00.000Z',
    })),
    push.cmdSwap(paths),
    push.cmdReadShared(paths),
    push.cmdInstallShared(paths),
    push.cmdCleanup(paths),
  ];
  for (const cmd of commands) {
    // No command substitution, no backticks, no here-doc: dash gives us no
    // PIPESTATUS and no `set -e`, so every construct that could hide an exit
    // code is banned by construction.
    assert.ok(!/\$\(|`|<<|\bset -e\b/.test(cmd), `unsafe construct in:\n${cmd}`);
    // Every branch that can fail ends in an explicit distinct exit code.
    assert.match(cmd, /exit \d+/);
  }
  // rm -rf must never be able to name the ad/ directory itself.
  assert.throws(() => push.labPathsFor('/opt/goad', LAB, ''), /unsafe work token/);

  // The swap must be able to undo itself. rename(2) cannot replace a non-empty
  // directory, so the old lab is retired first; if the install then fails and
  // nothing puts it back, the lab is simply GONE — a worse outcome than the
  // failed push it came from.
  const swap = push.cmdSwap(paths);
  assert.match(swap, /if \[ -e '[^']*\.cc-old-testtoken' \]; then mv '[^']*\.cc-old-testtoken' '[^']*CIAB-3f9a2c1b'; fi/,
    'cmdSwap has no rollback for a failed install');
});

test('a tree with no data/ is refused before anything is uploaded', async () => {
  // cmdExtract guards this on the far side too, but finding out there costs a
  // full transfer and reports only "exit 42".
  const guest = guestWith(RUN_SH_SHARED);
  await assert.rejects(
    push.pushLabTree(pushOpts(guest, { files: { 'providers/proxmox/inventory': 'x' } })),
    /no data\/ directory/);
  assert.strictEqual(guest.log.length, 0, 'a guest call was made before the tree was validated');
});
