/**
 * goad-lab-push.js — deliver a GENERATED lab tree to the GOAD controller.
 * ============================================================================
 * THE GAP THIS CLOSES
 * /opt/goad on controller template 1700 is populated exactly ONCE, at bake
 * time, by a cloud-init `git init && git fetch --depth 1 <GOAD_REF>` (see
 * infrastructure/proxmox-templates/vm-templates/bake-goad-controller-vm.sh).
 * Everything under ad/ is therefore upstream's eight shipped labs and nothing
 * else. A lab we GENERATE — ad/CIAB-<hash>/data/config.json + data/inventory +
 * providers/proxmox/inventory — has no way of reaching the box. Re-baking the
 * template per profile is a ~90 minute answer to a ~90 second problem.
 *
 * WHY THIS TRANSPORT AND NOT ANOTHER
 *
 *   REJECTED — an HTTP pull from the orchestrator. It would work today with no
 *   new code: the lane has an egress hole to the orchestrator, and
 *   profile-deploy.js already serves prebuilt tarballs over it. It is rejected
 *   on CONTENT, not on plumbing. That endpoint is deliberately unauthenticated
 *   ("Lane web VMs pull their prebuilt vuln-app image tarball here (they have
 *   no JWT)"), and a generated config.json carries EVERY host's
 *   local_admin_password and EVERY domain's domain_password in cleartext — the
 *   exact credentials students are meant to have to WORK for. Publishing the
 *   whole cohort's AD credential set on a shared, estate-reachable, tokenless
 *   URL is a real security regression, and "we'll add a token later" is how it
 *   stays tokenless. Do not re-propose it. If a pull is ever genuinely needed,
 *   it needs its own authenticated route, not that one.
 *
 *   REJECTED — guestWriteLargeText() from src/utils/script-executor.js. It is
 *   the WINDOWS sibling: it writes chunks with agent/file-write into
 *   C:\Windows\Temp and reassembles them with a PowerShell
 *   [Convert]::FromBase64String stub. The controller is Debian. It would fail
 *   on the very first `New-Item`.
 *
 *   CHOSEN — the channel executeShellViaFile() (script-executor.js ~line 587)
 *   already proved and which currently has no other caller for arbitrary
 *   payloads: base64 in 48KB chunks appended over agentShellExec, which routes
 *   through proxmoxFormPOST (curl, because Node's https.request reliably 596s
 *   on PVE 9.1.9 for agent/exec) and retries 596/ECONNRESET. No inbound port,
 *   no credentials on the wire beyond the Proxmox API token we already hold,
 *   and the payload never leaves the virtio-serial channel.
 *
 * WHAT "RETRIES 596/ECONNRESET" MEANS FOR THE DESIGN, and it is the whole
 * reason this file is shaped the way it is: agentShellExec retries the
 * TRANSPORT, not the WORK. A chunk that lands twice is fine (we truncate first
 * and append in order, and a duplicated append would fail the sha256 check
 * anyway). A chunk that never lands is a hole in the middle of a base64 stream.
 * So the destination directory must never be written incrementally — we stage
 * the entire tree under a work directory and rename() it into place as the
 * last act. A half-finished push leaves a stray dot-directory that the next
 * push deletes, never a half-populated ad/<LAB>/ that run.sh would happily
 * feed to ansible.
 *
 * TWO ARTIFACTS, NOT ONE
 * Pushing the tree alone is INSUFFICIENT, and the failure is silent. run.sh
 * resolves its playbook chain with
 *     chain = data.get("$LAB") or data.get("default") or []
 * against /opt/goad/playbooks.yml. A lab with no key of its own inherits
 * `default:` — sixteen playbooks including a hard `wait5m.yml`, plus
 * ad-child_domain.yml, ad-trusts.yml, ad-gmsa.yml and laps.yml, none of which a
 * single-domain generated lab has any hosts for. It does not error; it burns
 * the better part of an hour and then runs plays against empty groups. So the
 * chain is delivered as a first-class artifact:
 *
 *   preferred — ad/<LAB>/playbooks.yml inside the tree, which rides the atomic
 *   swap and touches no shared state. Another agent is adding that override to
 *   run.sh in this same wave, so we detect support rather than assume it, and
 *   the file we write is a MAP keyed by both <LAB> and `default` so it works
 *   with the existing `.get(LAB) or .get('default')` loader whichever key that
 *   override happens to look up.
 *
 *   fallback — merge a `<LAB>:` block into the shared /opt/goad/playbooks.yml.
 *   Read-modify-write of a shared file, so the merge itself is a pure function
 *   here (mergePlaybooksYaml) and the write is a rename, not an edit in place.
 *
 * DETERMINISM IS THE IDEMPOTENCY MECHANISM
 * The tar is byte-stable for a given file set — sorted entries, fixed mtime,
 * fixed uid/gid/mode, no volatile header fields — so sha256(tar) is a content
 * address for the tree. We record it in ad/<LAB>/.cc-manifest INSIDE the
 * directory, which means the manifest only becomes visible at the instant of
 * the atomic rename. A push that dies anywhere before that leaves nothing that
 * claims to be complete, and the next push re-does the work. A push whose
 * manifest already matches does nothing at all: three probe calls, no writes.
 *
 * COST
 * pollExecStatus has a 3s poll floor, so every guest call costs ~3s regardless
 * of size. A 1MB tree is ~28 chunks plus ~8 control calls, call it 100 seconds.
 * That is paid ONCE PER PROFILE, not per lane. Do not shrink it by widening the
 * chunks past what proxmoxFormPOST's urlencoded body tolerates, and do not
 * pipeline the chunks — appends must be ordered.
 *
 * SHELL DISCIPLINE (these strings run under /bin/sh, which is dash on Debian)
 *   - `set -e` is NOT in play. Every step checks its own exit code and exits a
 *     distinct number, so a failure names the step that produced it.
 *   - Every chunk command produces EMPTY stdout. QGA buffers exec output per
 *     process, and the aggregate across ~30 calls is not free; more to the
 *     point, a chunk that prints anything means the command got mangled.
 *   - No `$(...)`, no pipelines whose exit code matters (dash has no
 *     PIPESTATUS), no here-docs — everything is literal, single-quoted, and
 *     built from validated identifiers so there is nothing to escape.
 */

const crypto = require('crypto');
const zlib = require('zlib');

// ─── Constants ──────────────────────────────────────────────────────────────

/** Where the bake script puts upstream GOAD. Everything is relative to this. */
const GOAD_ROOT = '/opt/goad';

/** Our orchestration scripts live beside it; run.sh is what we probe for
 *  per-lab playbooks.yml support. */
const DEFAULT_RUN_SH = '/opt/goad-light/run.sh';

/**
 * 48KB of BASE64 per agent call — the same number executeShellViaFile uses,
 * for the same reason. proxmoxFormPOST urlencodes the body, and base64's
 * alphabet only expands on `+`, `/` and `=` (~6%), so this stays comfortably
 * inside what pveproxy accepts in one POST.
 */
const CHUNK_SIZE = 48 * 1024;

/**
 * Fixed mtime for every tar entry: 2020-01-01T00:00:00Z.
 *
 * NOT zero. A tar written with mtime 0 makes GNU tar print
 * "implausibly old time stamp" on extraction for every member, which is stderr
 * noise on a channel where we are trying to keep output empty, and it makes any
 * human who lists the archive think it is corrupt. Any fixed plausible value
 * gives the same determinism; this one is the SOURCE_DATE_EPOCH convention.
 */
const TAR_MTIME = 1577836800;

const TAR_BLOCK = 512;
/** GNU tar's default blocking factor. Padding to it means `tar -tvf` on the
 *  archive is silent instead of warning about a short final read. */
const TAR_RECORD = TAR_BLOCK * 20;

const FILE_MODE = 0o644;
const DIR_MODE = 0o755;

/** A generated lab tree is a handful of small text files. Anything approaching
 *  this is a bug in the generator (a whole role library accidentally included,
 *  a log captured into the tree), and it is much cheaper to refuse it here than
 *  to discover it 20 minutes into a chunk loop. */
const MAX_ARCHIVE_BYTES = 16 * 1024 * 1024;

/** Per-call timeouts. The floor on all of them is pollExecStatus's 3s poll. */
const TIMEOUT_PROBE = 30000;
const TIMEOUT_CHUNK = 60000;
const TIMEOUT_WORK = 120000;

/**
 * Upstream's shipped labs. We refuse to write any of these names: they are the
 * curriculum's known-good reference labs, they came from the pinned GOAD
 * checkout, and a generator that emitted `GOAD-Light` would silently replace
 * one with a swap that has no undo.
 */
const RESERVED_LAB_NAMES = Object.freeze([
  'DRACARYS', 'GOAD', 'GOAD-Light', 'GOAD-Mini',
  'MINILAB', 'NHA', 'SCCM', 'TEMPLATE',
]);

/** Lab directory name. Deliberately narrow: this string is interpolated into
 *  single-quoted shell paths, used as a YAML mapping key, and used as a tar
 *  member prefix. Nothing outside this charset is safe in all three. */
const LAB_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

/** A playbook is a bare filename in ansible/ — never a path. `../../etc` in
 *  this list would be handed straight to ansible-playbook by run.sh. */
const PLAYBOOK_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*\.yml$/;

const MANIFEST_NAME = '.cc-manifest';
const PLAYBOOKS_NAME = 'playbooks.yml';

// ─── Errors ─────────────────────────────────────────────────────────────────

/**
 * Carries the step name and guest exit code so a caller's toast can say
 * "extract failed (exit 31)" instead of "Error". The exit numbers are unique
 * per step across every command in this file precisely so that number is
 * enough to find the line.
 */
class LabPushError extends Error {
  constructor(message, details) {
    super(message);
    this.name = 'LabPushError';
    Object.assign(this, details || {});
  }
}

// ─── Validation ─────────────────────────────────────────────────────────────

function assertLabName(lab) {
  const name = String(lab === null || lab === undefined ? '' : lab).trim();
  if (!LAB_NAME_RE.test(name)) {
    throw new LabPushError(
      `Invalid lab name ${JSON.stringify(lab)}: must match ${LAB_NAME_RE} `
      + '(it becomes a shell path, a YAML key and a tar prefix)');
  }
  // `default:` is the inheritance key run.sh falls back to. Merging our chain
  // under it would rewrite the chain for EVERY lab on the controller, including
  // upstream's — the single most destructive thing this module could do.
  if (name === 'default') {
    throw new LabPushError(
      "Lab name 'default' is refused: it is playbooks.yml's inheritance key, "
      + 'and writing it would replace the chain for every other lab');
  }
  if (RESERVED_LAB_NAMES.includes(name)) {
    throw new LabPushError(
      `Lab name '${name}' is one of upstream's shipped labs `
      + `(${RESERVED_LAB_NAMES.join(', ')}); generated labs must use their own name, `
      + 'because the push swaps the directory and there is no undo');
  }
  return name;
}

/**
 * Every path we interpolate into a shell string goes through here. The charset
 * checks above already make this unreachable for well-formed input; it exists
 * so that a future caller who passes `root` from config cannot turn a path into
 * shell.
 */
function assertShellSafe(p, what) {
  const s = String(p);
  if (s === '' || /['"\\\n\r\t$`]/.test(s) || /[\x00-\x1f]/.test(s)) {
    throw new LabPushError(`Refusing to build a shell command with unsafe ${what}: ${JSON.stringify(s)}`);
  }
  return s;
}

/**
 * Normalize a tree-relative member path.
 *
 * Rejects, rather than sanitizes: a generator that produced `../ansible/x` or
 * `/etc/passwd` has a bug, and quietly rewriting it to something harmless would
 * hide that bug until someone wondered why a file was missing. tar extraction
 * is the one place where a traversal is a remote write outside the staging dir.
 */
function normalizeMemberPath(p) {
  const raw = String(p === null || p === undefined ? '' : p).trim().replace(/\\/g, '/');
  if (raw === '') throw new LabPushError('Empty path in lab tree');
  if (raw.startsWith('/')) throw new LabPushError(`Absolute path in lab tree: ${raw}`);
  const parts = raw.split('/');
  for (const part of parts) {
    if (part === '' || part === '.' || part === '..') {
      throw new LabPushError(`Unsafe path in lab tree: ${raw}`);
    }
    if (/[\x00-\x1f]/.test(part)) throw new LabPushError(`Control character in lab tree path: ${JSON.stringify(raw)}`);
  }
  if (raw.length > 240) {
    // ustar can carry 100 (name) + 155 (prefix) with a `/` between; 240 leaves
    // headroom and keeps the error at generation time rather than in splitName.
    throw new LabPushError(`Path too long for a ustar header (${raw.length} > 240): ${raw}`);
  }
  return parts.join('/');
}

function assertChain(chain) {
  if (!Array.isArray(chain) || chain.length === 0) {
    throw new LabPushError('A playbook chain is required: without one the lab '
      + "inherits playbooks.yml `default:` — 16 plays including wait5m.yml, "
      + 'child-domain, trusts, gmsa and laps that a generated lab has no hosts for');
  }
  return chain.map((p) => {
    const name = String(p === null || p === undefined ? '' : p).trim();
    if (!PLAYBOOK_RE.test(name)) {
      throw new LabPushError(`Invalid playbook in chain: ${JSON.stringify(p)} `
        + '(expected a bare <name>.yml, never a path)');
    }
    return name;
  });
  // Duplicates are legal and intentional upstream — SCCM lists wait5m.yml three
  // times to burn ten minutes — so no uniqueness check here.
}

// ─── Deterministic tar (ustar) ──────────────────────────────────────────────

/** Octal, zero-padded, NUL-terminated: the ustar numeric field encoding. */
function writeOctal(buf, value, offset, length) {
  const digits = length - 1;
  const s = Math.floor(value).toString(8).padStart(digits, '0');
  if (s.length > digits) {
    throw new LabPushError(`Value ${value} does not fit an ${length}-byte ustar octal field`);
  }
  buf.write(s, offset, digits, 'ascii');
  buf[offset + digits] = 0;
}

/**
 * Split a member path across ustar's name(100) + prefix(155) fields.
 *
 * The split must fall on a `/`, and the joined form must reproduce the original
 * exactly (readers rebuild it as prefix + '/' + name), so there is no clever
 * packing available — take the rightmost slash that leaves a fitting name.
 */
function splitName(path) {
  if (Buffer.byteLength(path) <= 100) return { name: path, prefix: '' };
  let cut = -1;
  for (let i = path.length - 1; i > 0; i--) {
    if (path[i] !== '/') continue;
    const name = path.slice(i + 1);
    const prefix = path.slice(0, i);
    if (Buffer.byteLength(name) <= 100 && Buffer.byteLength(prefix) <= 155) { cut = i; break; }
  }
  if (cut < 0) throw new LabPushError(`Path cannot be encoded in a ustar header: ${path}`);
  return { name: path.slice(cut + 1), prefix: path.slice(0, cut) };
}

/**
 * One 512-byte ustar header.
 *
 * Every field that a normal tar implementation would fill from the filesystem
 * or the clock is pinned here: uid/gid 0, uname/gname root, mtime TAR_MTIME,
 * fixed mode. That pinning IS the content-addressing — without it the same
 * files produce a different sha on every machine and the .cc-manifest
 * short-circuit never fires.
 */
function tarHeader(path, { size, mode, typeflag }) {
  const buf = Buffer.alloc(TAR_BLOCK, 0);
  const { name, prefix } = splitName(path);
  buf.write(name, 0, 100, 'utf8');
  writeOctal(buf, mode, 100, 8);
  writeOctal(buf, 0, 108, 8);              // uid
  writeOctal(buf, 0, 116, 8);              // gid
  writeOctal(buf, size, 124, 12);
  writeOctal(buf, TAR_MTIME, 136, 12);
  buf.write('        ', 148, 8, 'ascii');  // checksum placeholder: eight spaces
  buf.write(typeflag, 156, 1, 'ascii');
  buf.write('ustar\0', 257, 6, 'ascii');
  buf.write('00', 263, 2, 'ascii');
  buf.write('root', 265, 32, 'ascii');
  buf.write('root', 297, 32, 'ascii');
  writeOctal(buf, 0, 329, 8);              // devmajor
  writeOctal(buf, 0, 337, 8);              // devminor
  buf.write(prefix, 345, 155, 'utf8');

  let sum = 0;
  for (let i = 0; i < TAR_BLOCK; i++) sum += buf[i];
  // Six octal digits, NUL, space — the historical encoding every reader accepts.
  buf.write(sum.toString(8).padStart(6, '0'), 148, 6, 'ascii');
  buf[154] = 0;
  buf[155] = 0x20;
  return buf;
}

/**
 * Accept the two shapes a caller naturally has: a plain object of
 * path -> content, or an array of { path, content }. Returns entries sorted by
 * a BYTE comparison of the path.
 *
 * The sort must not be localeCompare: it is locale-dependent, so an orchestrator
 * running under a different LANG would produce a different byte order and
 * therefore a different sha for identical input.
 */
function normalizeFiles(files) {
  const list = [];
  if (Array.isArray(files)) {
    for (const f of files) {
      if (!f || typeof f !== 'object') throw new LabPushError('Lab tree entry must be an object with { path, content }');
      list.push({ path: f.path, content: f.content });
    }
  } else if (files && typeof files === 'object') {
    for (const k of Object.keys(files)) list.push({ path: k, content: files[k] });
  } else {
    throw new LabPushError('Lab tree must be an object of path -> content, or an array of { path, content }');
  }
  if (list.length === 0) throw new LabPushError('Lab tree is empty — nothing to push');

  const seen = new Map();
  const out = [];
  for (const item of list) {
    const path = normalizeMemberPath(item.path);
    if (seen.has(path)) {
      throw new LabPushError(`Duplicate path in lab tree: ${path} `
        + '(two entries normalize to the same member, so one would silently win)');
    }
    seen.set(path, true);
    out.push({ path, content: toBytes(item.content, path) });
  }
  out.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return out;
}

/**
 * Text becomes LF-normalized UTF-8; a Buffer is passed through untouched.
 *
 * CRLF is not cosmetic here. An `inventory` line ending in \r gives ansible a
 * host named "dc01\r"; a config.json with CRLF is fine for the JSON parser but
 * the trailing \r rides into every password string it quotes. Both fail far
 * away from the cause. A caller that genuinely wants CRLF passes a Buffer.
 */
function toBytes(content, path) {
  if (Buffer.isBuffer(content)) return content;
  if (typeof content === 'string') return Buffer.from(content.replace(/\r\n/g, '\n'), 'utf8');
  if (content === null || content === undefined) {
    throw new LabPushError(`Lab tree entry ${path} has no content`);
  }
  throw new LabPushError(`Lab tree entry ${path} must be a string or Buffer, got ${typeof content}`);
}

/** Every ancestor directory of every member, so the archive carries explicit
 *  0755 dir entries instead of relying on tar's implicit parent creation
 *  (whose mode depends on the extracting process's umask — not deterministic). */
function directoriesFor(entries) {
  const dirs = new Set();
  for (const e of entries) {
    const parts = e.path.split('/');
    for (let i = 1; i < parts.length; i++) dirs.add(parts.slice(0, i).join('/'));
  }
  return Array.from(dirs).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

/**
 * Build the tar. Byte-identical for identical input, on any host, at any time.
 *
 * Order is: all directories and files interleaved in one lexicographic sort of
 * the path. 'data' sorts before 'data/config.json' because it is a prefix, so
 * parents always precede their children without a second pass.
 */
function buildTar(files) {
  const entries = normalizeFiles(files);
  const dirs = directoriesFor(entries);

  const merged = [
    ...dirs.map((d) => ({ path: d, dir: true })),
    ...entries.map((e) => ({ path: e.path, dir: false, content: e.content })),
  ].sort((a, b) => {
    if (a.path < b.path) return -1;
    if (a.path > b.path) return 1;
    return a.dir ? -1 : 1;  // a dir and a file cannot share a path, but be total
  });

  const blocks = [];
  for (const m of merged) {
    if (m.dir) {
      blocks.push(tarHeader(`${m.path}/`, { size: 0, mode: DIR_MODE, typeflag: '5' }));
      continue;
    }
    blocks.push(tarHeader(m.path, { size: m.content.length, mode: FILE_MODE, typeflag: '0' }));
    blocks.push(m.content);
    const pad = (TAR_BLOCK - (m.content.length % TAR_BLOCK)) % TAR_BLOCK;
    if (pad) blocks.push(Buffer.alloc(pad, 0));
  }
  // Two zero blocks mark end-of-archive, then pad the whole thing out to a
  // record boundary so no reader reports a short read.
  blocks.push(Buffer.alloc(TAR_BLOCK * 2, 0));
  let out = Buffer.concat(blocks);
  const tail = (TAR_RECORD - (out.length % TAR_RECORD)) % TAR_RECORD;
  if (tail) out = Buffer.concat([out, Buffer.alloc(tail, 0)]);
  return out;
}

// ─── Deterministic gzip ─────────────────────────────────────────────────────

const CRC_TABLE = (() => {
  const t = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    t[n] = c;
  }
  return t;
})();

/** Hand-rolled rather than zlib.crc32(), which only exists from Node 20.15/22.2
 *  — the orchestrator container's Node version is not pinned by this repo. */
function crc32(buf) {
  let c = 0 ^ (-1);
  for (let i = 0; i < buf.length; i++) c = (c >>> 8) ^ CRC_TABLE[(c ^ buf[i]) & 0xFF];
  return (c ^ (-1)) >>> 0;
}

/**
 * gzip with a hand-built header, because zlib.gzipSync's is NOT portable-stable:
 * it stamps the OS byte from the compiling platform (0x0a on Windows, 0x03 on
 * Unix), so the same tree gzipped on a dev laptop and in the container produces
 * different bytes. We emit OS=0xff ("unknown") and MTIME=0, leaving
 * deflateRawSync — which is deterministic for a given level — as the only
 * variable, and that only across zlib major versions.
 *
 * The content address is taken over the TAR anyway (see buildLabArchive), so
 * even a zlib upgrade cannot break idempotency; this only keeps the wire bytes
 * and their sha reproducible for a given orchestrator build.
 */
function gzipDeterministic(buf, level = 9) {
  const body = zlib.deflateRawSync(buf, { level });
  // XFL: 2 = compressor used maximum compression, 4 = fastest. 0 otherwise.
  const xfl = level === 9 ? 0x02 : level === 1 ? 0x04 : 0x00;
  const head = Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, xfl, 0xff]);
  const tail = Buffer.alloc(8);
  tail.writeUInt32LE(crc32(buf), 0);
  tail.writeUInt32LE(buf.length % 4294967296, 4);
  return Buffer.concat([head, body, tail]);
}

function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

/**
 * The archive plus both hashes.
 *
 *   treeSha256     — sha256 of the TAR. This is the content address: it depends
 *                    only on the file set (paths, bytes, and the pinned header
 *                    fields), never on compression. It is what .cc-manifest
 *                    records and what makes a re-push a no-op.
 *   transferSha256 — sha256 of the .tar.gz actually sent, checked by sha256sum
 *                    on the far side. This one answers "did all 28 chunks land
 *                    intact", which is a different question.
 */
function buildLabArchive(files) {
  const tar = buildTar(files);
  const gz = gzipDeterministic(tar);
  if (gz.length > MAX_ARCHIVE_BYTES) {
    throw new LabPushError(
      `Lab archive is ${gz.length} bytes, over the ${MAX_ARCHIVE_BYTES}-byte ceiling. `
      + 'A generated lab is a handful of small text files; this size means the tree '
      + 'picked up something it should not have.');
  }
  return {
    tar,
    gz,
    treeSha256: sha256(tar),
    transferSha256: sha256(gz),
    tarBytes: tar.length,
    gzBytes: gz.length,
  };
}

// ─── Chunking ───────────────────────────────────────────────────────────────

/**
 * Split into fixed-size pieces. Exported because the boundary cases (exact
 * multiple, one under, one over, empty) are where a chunker silently drops or
 * duplicates a tail, and that failure surfaces as a corrupt archive 90 seconds
 * later with no clue attached.
 */
function chunkString(s, size) {
  const str = String(s === null || s === undefined ? '' : s);
  const n = Math.floor(Number(size));
  if (!(n > 0)) throw new LabPushError(`Invalid chunk size ${size}`);
  if (str.length === 0) return [];
  const out = [];
  for (let i = 0; i < str.length; i += n) out.push(str.slice(i, i + n));
  return out;
}

// ─── playbooks.yml rendering and merging ────────────────────────────────────

/** `<key>:\n  - a.yml\n  - b.yml\n` — the exact shape upstream's file uses. */
function renderChainBlock(key, chain) {
  return `${key}:\n${chain.map((p) => `  - ${p}\n`).join('')}`;
}

/**
 * The lab-local ad/<LAB>/playbooks.yml.
 *
 * Written as a MAP, not a bare list, and carrying BOTH the lab key and
 * `default`. run.sh's loader is
 *     chain = data.get("$LAB") or data.get("default") or []
 * and the override another agent is adding may point that same loader at this
 * file, or may look it up some other way. A bare list would make .get() return
 * None on both attempts and fall through to the shared file's `default:` — the
 * exact 16-playbook inheritance this artifact exists to prevent, arrived at
 * silently. Duplicating the chain under two keys costs a dozen lines and makes
 * every plausible loader resolve to the same answer.
 */
function renderLabPlaybooksYaml(labName, chain) {
  const name = assertLabName(labName);
  const list = assertChain(chain);
  return ''
    + `# Generated by CyberCore goad-lab-push. Per-lab override for ${name}.\n`
    + '#\n'
    + '# Both keys carry the same chain on purpose: run.sh resolves\n'
    + '#   chain = data.get("<LAB>") or data.get("default") or []\n'
    + '# so whichever key the loader reaches, it gets this lab\'s chain and never\n'
    + "# falls through to the shared playbooks.yml `default:` (16 plays, including\n"
    + '# wait5m.yml, child-domain, trusts, gmsa and laps, which this lab has no\n'
    + '# hosts for).\n'
    + renderChainBlock(name, list)
    + '\n'
    + renderChainBlock('default', list);
}

/** Top-level mapping key at column 0, e.g. `GOAD-Mini:`. */
const TOP_KEY_RE = /^([A-Za-z0-9._-]+)\s*:\s*$/;

/**
 * Splice a lab's chain into the shared playbooks.yml, as a pure function.
 *
 * Deliberately a TEXT splice and not a YAML round-trip: the shared file is
 * upstream's, it is full of load-bearing comments (`# - laps.yml` is a
 * semantic statement in this file, not a note — see goad-preflight chainForLab),
 * and any dump/reload would normalize them out of existence.
 *
 * The result is canonical — our block always ends up last, separated by exactly
 * one blank line — which is what makes it idempotent: merging the output again
 * returns it unchanged, so `changed === false` is a reliable "skip the write".
 *
 * @returns {{ text: string, changed: boolean, replaced: boolean }}
 */
function mergePlaybooksYaml(existingText, labName, chain) {
  const name = assertLabName(labName);
  const list = assertChain(chain);
  const block = renderChainBlock(name, list);

  const original = String(existingText === null || existingText === undefined ? '' : existingText)
    .replace(/\r\n/g, '\n');

  const kept = [];
  let skipping = false;
  let replaced = false;
  for (const line of original.split('\n')) {
    const key = line.match(TOP_KEY_RE);
    if (key) {
      // A new top-level key always ends any block we were dropping.
      skipping = key[1] === name;
      if (skipping) replaced = true;
    } else if (line.startsWith('#')) {
      // A column-0 comment also ends the block. Without this, a comment written
      // after our appended block on a previous life of the file would be eaten
      // by the next merge.
      skipping = false;
    }
    if (!skipping) kept.push(line);
  }

  const head = kept.join('\n').replace(/\n+$/, '');
  const text = head ? `${head}\n\n${block}` : block;
  return { text, changed: text !== original, replaced };
}

/** sha256 over the canonical chain rendering, so the manifest notices a chain
 *  edit even when not one byte of the tree changed. */
function chainSha256(labName, chain) {
  return sha256(Buffer.from(renderChainBlock(assertLabName(labName), assertChain(chain)), 'utf8'));
}

// ─── Remote paths ───────────────────────────────────────────────────────────

/**
 * Everything the remote steps touch, derived once so no command builds a path
 * of its own.
 *
 * The work directory lives INSIDE /opt/goad/ad/ rather than /tmp for one
 * reason: the final swap is rename(2), which is only atomic within a
 * filesystem. /tmp on this image may be a tmpfs, in which case a `mv` from
 * there would degrade to a copy — non-atomic, and briefly a half-populated
 * ad/<LAB>/. Dot-prefixed so it is visually distinct from a lab directory if a
 * failure ever leaves one behind.
 */
function labPathsFor(root, labName, token) {
  const goadRoot = assertShellSafe(String(root || GOAD_ROOT).replace(/\/+$/, ''), 'GOAD root');
  const lab = assertLabName(labName);
  const tok = assertShellSafe(token, 'work token');
  const adDir = `${goadRoot}/ad`;
  const work = `${adDir}/.cc-push-${tok}`;
  if (work === adDir || work === goadRoot) {
    throw new LabPushError('Refusing to use the ad/ directory itself as a work directory');
  }
  return {
    goadRoot,
    adDir,
    dest: `${adDir}/${lab}`,
    work,
    stage: `${work}/tree`,
    payloadB64: `${work}/payload.b64`,
    payloadTgz: `${work}/payload.tgz`,
    playbooksB64: `${work}/playbooks.b64`,
    playbooksNew: `${work}/playbooks.yml.new`,
    manifest: `${adDir}/${lab}/${MANIFEST_NAME}`,
    stageManifest: `${work}/tree/${MANIFEST_NAME}`,
    sharedPlaybooks: `${goadRoot}/${PLAYBOOKS_NAME}`,
    sharedBackup: `${goadRoot}/${PLAYBOOKS_NAME}.cc-bak`,
    retired: `${adDir}/.cc-old-${tok}`,
  };
}

// ─── Manifest ───────────────────────────────────────────────────────────────

/**
 * The content-address record, written INSIDE the lab directory so it only
 * becomes visible when the atomic rename lands. That placement is the whole
 * trick: there is no window in which a manifest claims a tree that is not
 * fully there.
 *
 * Every line is a single token with no spaces, because the idempotency probe
 * matches them with `grep -qxF` (exact whole line, fixed string) — no regex
 * metacharacter can leak in from a sha or a lab name.
 */
function buildManifest({ lab, treeSha, chainSha, chainMode, pushedAt }) {
  return [
    'schema=1',
    'source=cybercore/goad-lab-push',
    `lab=${lab}`,
    `tree_sha256=${treeSha}`,
    `chain_sha256=${chainSha}`,
    `chain_mode=${chainMode}`,
    `pushed_at=${pushedAt || new Date().toISOString()}`,
  ].join('\n') + '\n';
}

// ─── Shell command builders ─────────────────────────────────────────────────
//
// Each returns one /bin/sh -c string. They are separate named functions so the
// test can assert on their exact text — in particular that no chunk command can
// ever emit output.

/** Distinct exit codes per failure, unique across the whole file. */
const EXIT = Object.freeze({
  NO_AD_DIR: 10, NO_TAR: 11, NO_BASE64: 12, NO_SHA256: 13,
  STAGE_RM: 20, STAGE_MKDIR: 21, STAGE_TRUNC: 22,
  DECODE: 30, SHA_MISMATCH: 31, DECODE_RM: 32,
  EXTRACT_MKDIR: 40, EXTRACT: 41, EXTRACT_EMPTY: 42,
  MANIFEST_WRITE: 50,
  SWAP_NO_STAGE: 60, SWAP_RETIRE: 61, SWAP_INSTALL: 62,
  MERGE_EMPTY: 70, MERGE_INSTALL: 71,
  PROBE_NO_MANIFEST: 80, PROBE_TREE: 81, PROBE_CHAIN: 82, PROBE_MODE: 83, PROBE_SHARED: 84,
  SUPPORT_NO_RUNSH: 90, SUPPORT_ABSENT: 91,
});

function cmdPreflight(paths) {
  return [
    `[ -d '${paths.adDir}' ] || exit ${EXIT.NO_AD_DIR}`,
    `command -v tar >/dev/null 2>&1 || exit ${EXIT.NO_TAR}`,
    `command -v base64 >/dev/null 2>&1 || exit ${EXIT.NO_BASE64}`,
    `command -v sha256sum >/dev/null 2>&1 || exit ${EXIT.NO_SHA256}`,
    'exit 0',
  ].join('\n');
}

/**
 * Is this controller's run.sh able to read ad/<LAB>/playbooks.yml?
 *
 * Two ways to say yes, because the override lands in a different agent's change
 * and we must not couple to its exact spelling:
 *   - an explicit marker file, which that change can drop, or
 *   - run.sh mentioning both a lab variable and playbooks.yml on one line,
 *     which any plausible implementation does
 *       (LAB_PLAYBOOKS="$GOAD_ROOT/ad/$LAB/playbooks.yml").
 * The current baked run.sh has `PLAYBOOKS_YML="$GOAD_ROOT/playbooks.yml"` with
 * no LAB on that line, so it correctly answers "no" and we take the shared
 * merge path.
 *
 * Guessing wrong in the "no" direction is harmless (we merge the shared file,
 * which every version of run.sh reads). Guessing wrong in the "yes" direction
 * would leave the lab inheriting `default:`, so this errs toward "no".
 */
function cmdSupportsPerLabPlaybooks(runShPath, markerPath) {
  return [
    `[ -f '${markerPath}' ] && exit 0`,
    `[ -f '${runShPath}' ] || exit ${EXIT.SUPPORT_NO_RUNSH}`,
    `grep -n 'playbooks\\.yml' '${runShPath}' | grep -q 'LAB' && exit 0`,
    `exit ${EXIT.SUPPORT_ABSENT}`,
  ].join('\n');
}

/**
 * Exit 0 means "already delivered, do nothing". Anything else means push.
 *
 * Only exit 0 short-circuits, so every failure mode of the probe itself — no
 * manifest, unreadable file, missing grep — falls through to a full push. That
 * asymmetry is deliberate: a redundant push costs 90 seconds, a wrongly skipped
 * one costs a lab that is quietly the wrong shape.
 */
function cmdProbeManifest(paths, { treeSha, chainSha, chainMode, sharedKeyLine }) {
  const lines = [
    `[ -f '${paths.manifest}' ] || exit ${EXIT.PROBE_NO_MANIFEST}`,
    `grep -qxF 'tree_sha256=${treeSha}' '${paths.manifest}' || exit ${EXIT.PROBE_TREE}`,
    `grep -qxF 'chain_sha256=${chainSha}' '${paths.manifest}' || exit ${EXIT.PROBE_CHAIN}`,
    `grep -qxF 'chain_mode=${chainMode}' '${paths.manifest}' || exit ${EXIT.PROBE_MODE}`,
  ];
  if (sharedKeyLine) {
    // The manifest lives in the lab directory, but the shared-file key does not.
    // Someone could have hand-edited playbooks.yml since; check it is still
    // there rather than trusting our own past tense.
    lines.push(`grep -qxF '${sharedKeyLine}' '${paths.sharedPlaybooks}' || exit ${EXIT.PROBE_SHARED}`);
  }
  lines.push('exit 0');
  return lines.join('\n');
}

function cmdStage(paths) {
  return [
    `rm -rf '${paths.work}' || exit ${EXIT.STAGE_RM}`,
    `mkdir -p '${paths.work}' || exit ${EXIT.STAGE_MKDIR}`,
    'exit 0',
  ].join('\n');
}

function cmdTruncate(path) {
  return `: > '${path}' || exit ${EXIT.STAGE_TRUNC}\nexit 0`;
}

/**
 * The only command that runs dozens of times. It is one line, it appends, and
 * it prints NOTHING — printf writes to the redirected fd and nothing else on
 * the line can produce output. Its exit code is printf's (or the shell's, if
 * the redirect itself fails), which is exactly the signal we want.
 *
 * Single quotes are safe unconditionally: base64's alphabet is
 * [A-Za-z0-9+/=] and Buffer#toString('base64') never inserts newlines, so the
 * payload cannot contain a quote, a backslash or a newline to escape.
 */
function cmdAppendChunk(path, chunk) {
  return `printf %s '${chunk}' >> '${path}'`;
}

function cmdDecodeVerify(b64Path, outPath, sha) {
  return [
    `base64 -d < '${b64Path}' > '${outPath}' || exit ${EXIT.DECODE}`,
    // Two spaces between hash and path — sha256sum -c's own format. Output goes
    // to /dev/null rather than using --status, which busybox's sha256sum lacks.
    `printf '%s  %s\\n' '${sha}' '${outPath}' | sha256sum -c - >/dev/null 2>&1 || exit ${EXIT.SHA_MISMATCH}`,
    `rm -f '${b64Path}' || exit ${EXIT.DECODE_RM}`,
    'exit 0',
  ].join('\n');
}

function cmdExtract(paths) {
  return [
    `mkdir -p '${paths.stage}' || exit ${EXIT.EXTRACT_MKDIR}`,
    `tar -xzf '${paths.payloadTgz}' -C '${paths.stage}' || exit ${EXIT.EXTRACT}`,
    // A tar that extracted zero members exits 0. Without this check an empty
    // archive would swap an empty directory over a good lab.
    `[ -d '${paths.stage}/data' ] || exit ${EXIT.EXTRACT_EMPTY}`,
    'exit 0',
  ].join('\n');
}

function cmdWriteManifest(paths, manifestText) {
  const lines = manifestText.replace(/\n+$/, '').split('\n');
  for (const l of lines) assertShellSafe(l, 'manifest line');
  const args = lines.map((l) => `'${l}'`).join(' ');
  return `printf '%s\\n' ${args} > '${paths.stageManifest}' || exit ${EXIT.MANIFEST_WRITE}\nexit 0`;
}

/**
 * The swap, and the only moment the destination changes.
 *
 * rename(2) cannot replace a non-empty directory, so this cannot be one call:
 * retire the old one, then install the new one, then delete the retired one.
 * The middle step is the only window where ad/<LAB>/ does not exist, and it is
 * two renames wide. If the install fails we put the old one back, so the
 * failure mode is "nothing changed", never "the lab is gone".
 *
 * Both directories are on the same filesystem (work lives under ad/), so both
 * renames are atomic and neither can partially complete.
 */
function cmdSwap(paths) {
  return [
    `[ -d '${paths.stage}' ] || exit ${EXIT.SWAP_NO_STAGE}`,
    `if [ -e '${paths.dest}' ]; then mv '${paths.dest}' '${paths.retired}' || exit ${EXIT.SWAP_RETIRE}; fi`,
    `mv '${paths.stage}' '${paths.dest}' || { if [ -e '${paths.retired}' ]; then mv '${paths.retired}' '${paths.dest}'; fi; exit ${EXIT.SWAP_INSTALL}; }`,
    `rm -rf '${paths.retired}'`,
    'exit 0',
  ].join('\n');
}

/** Read the shared file so the merge can happen here, where it is testable.
 *  A missing file is not an error — we create it. */
function cmdReadShared(paths) {
  return `cat '${paths.sharedPlaybooks}' 2>/dev/null\nexit 0`;
}

/**
 * Install the merged shared playbooks.yml.
 *
 * `mv` and not a redirect: a `>` truncates first, so an interrupted write
 * leaves the controller with a half playbooks.yml and every lab on the box —
 * upstream's included — loses its chain. The rename is atomic and the backup
 * gives an operator something to diff.
 */
function cmdInstallShared(paths) {
  return [
    `[ -s '${paths.playbooksNew}' ] || exit ${EXIT.MERGE_EMPTY}`,
    `cp -p '${paths.sharedPlaybooks}' '${paths.sharedBackup}' 2>/dev/null`,
    `mv '${paths.playbooksNew}' '${paths.sharedPlaybooks}' || exit ${EXIT.MERGE_INSTALL}`,
    'exit 0',
  ].join('\n');
}

function cmdCleanup(paths) {
  return `rm -rf '${paths.work}' '${paths.retired}'\nexit 0`;
}

// ─── Transport ──────────────────────────────────────────────────────────────

/**
 * The real transport is required LAZILY. script-executor.js pulls in ./proxmox
 * and ./db at module load, both of which read env and open handles; a test that
 * injects its own transport must never drag that in just by requiring this
 * file.
 */
function defaultDeps() {
  const se = require('../../../../../src/utils/script-executor');
  return { agentShellExec: se.agentShellExec, pollExecStatus: se.pollExecStatus };
}

/**
 * Run one command in the guest and return its status.
 *
 * There is no `set -e` in these strings and agentShellExec retries only the
 * TRANSPORT, so this is the single place that turns "the command ran" into
 * "the command worked": a non-exit (timeout) and a non-zero exit are both
 * errors here unless the caller explicitly asks for the raw status.
 */
async function runStep(ctx, name, command, { timeoutMs = TIMEOUT_WORK, allowNonZero = false } = {}) {
  const { pid } = await ctx.agentShellExec(ctx.node, ctx.vmId, command);
  const status = await ctx.pollExecStatus(ctx.node, ctx.vmId, pid, timeoutMs);
  const exitcode = status && status.exited ? (status.exitcode || 0) : -1;
  ctx.steps.push({ name, exitcode });
  if (!status || !status.exited) {
    throw new LabPushError(`GOAD lab push step '${name}' did not complete within ${timeoutMs}ms`, {
      step: name, exitcode: -1, stderr: (status && status.stderr) || '',
    });
  }
  if (exitcode !== 0 && !allowNonZero) {
    throw new LabPushError(
      `GOAD lab push step '${name}' failed (exit ${exitcode})`
      + `${status.stderr ? `: ${String(status.stderr).trim().slice(0, 300)}` : ''}`,
      { step: name, exitcode, stderr: status.stderr || '' });
  }
  return { ...status, exitcode };
}

/**
 * Stage a byte payload on the guest: truncate, append base64 chunks in order,
 * decode, verify sha256, drop the base64.
 *
 * Ordered and serial on purpose. The appends are position-dependent, and
 * agentShellExec's retry can re-run a call it believes failed — which is safe
 * for an append-in-order stream that ends in a hash check, and would not be for
 * anything concurrent.
 */
async function sendBytes(ctx, { b64Path, outPath, bytes, label }) {
  const b64 = bytes.toString('base64');
  const chunks = chunkString(b64, ctx.chunkSize);
  await runStep(ctx, `${label}:truncate`, cmdTruncate(b64Path));
  for (let i = 0; i < chunks.length; i++) {
    await runStep(ctx, `${label}:chunk[${i + 1}/${chunks.length}]`,
      cmdAppendChunk(b64Path, chunks[i]), { timeoutMs: TIMEOUT_CHUNK });
  }
  await runStep(ctx, `${label}:verify`, cmdDecodeVerify(b64Path, outPath, sha256(bytes)));
  return chunks.length;
}

// ─── The entry point ────────────────────────────────────────────────────────

/**
 * Deliver a generated lab tree (and its playbook chain) to the GOAD controller.
 *
 * @param {object} opts
 * @param {string} opts.node            Proxmox node hosting the controller
 * @param {number|string} opts.vmId     controller VMID
 * @param {string} opts.lab             lab directory name, e.g. 'CIAB-3f9a2c1b'
 * @param {object|Array} opts.files     tree-relative path -> string|Buffer
 * @param {string[]} opts.chain         the playbook chain for this lab
 * @param {string} [opts.root]          GOAD root on the guest (default /opt/goad)
 * @param {string} [opts.runShPath]     run.sh to probe for per-lab support
 * @param {'auto'|boolean} [opts.perLabPlaybooks]  override the support probe
 * @param {number} [opts.chunkSize]     base64 chars per guest call
 * @param {boolean} [opts.force]        push even if the manifest already matches
 * @param {string} [opts.token]         work-directory suffix (tests pin it)
 * @param {object} [opts.deps]          { agentShellExec, pollExecStatus }
 * @returns {Promise<object>} summary incl. { skipped, treeSha256, steps }
 */
async function pushLabTree(opts) {
  const o = opts || {};
  const lab = assertLabName(o.lab);
  const chain = assertChain(o.chain);
  const node = o.node;
  const vmId = o.vmId;
  if (!node || (vmId === undefined || vmId === null || vmId === '')) {
    throw new LabPushError('pushLabTree requires { node, vmId } for the GOAD controller');
  }

  // The chain is part of the TREE, so it is covered by the content address and
  // rides the atomic swap. A caller that also hand-supplied playbooks.yml is
  // ambiguous about which one wins — say so instead of picking.
  const files = normalizeFiles(o.files);
  if (files.some((f) => f.path === PLAYBOOKS_NAME)) {
    throw new LabPushError(
      `Do not put ${PLAYBOOKS_NAME} in the lab tree: pushLabTree renders it from `
      + '`chain` so that one source of truth ends up in both artifacts');
  }
  // cmdExtract's sentinel is `[ -d <stage>/data ]`, which is what stops an
  // archive that unpacked to nothing from being swapped over a good lab. Check
  // the same invariant HERE so a caller that forgot data/ finds out now, not
  // after a 90-second upload followed by a bare "exit 42".
  if (!files.some((f) => f.path.startsWith('data/'))) {
    throw new LabPushError(
      'Lab tree has no data/ directory. A GOAD lab is data/config.json plus '
      + 'data/inventory; without them run.sh stops at "Lab not found" and the '
      + 'push would have staged an unusable directory.');
  }

  const labPlaybooks = renderLabPlaybooksYaml(lab, chain);
  const treeFiles = [...files, { path: PLAYBOOKS_NAME, content: labPlaybooks }];

  const archive = buildLabArchive(treeFiles);
  const chainSha = chainSha256(lab, chain);
  const token = o.token
    || `${archive.treeSha256.slice(0, 12)}-${crypto.randomBytes(3).toString('hex')}`;
  const paths = labPathsFor(o.root || GOAD_ROOT, lab, token);
  const runShPath = assertShellSafe(o.runShPath || DEFAULT_RUN_SH, 'run.sh path');
  const markerPath = `${runShPath.replace(/\/[^/]*$/, '')}/.cc-per-lab-playbooks`;

  const deps = o.deps || {};
  const resolved = deps.agentShellExec && deps.pollExecStatus ? deps : { ...defaultDeps(), ...deps };
  const ctx = {
    node,
    vmId,
    chunkSize: Number(o.chunkSize) > 0 ? Math.floor(Number(o.chunkSize)) : CHUNK_SIZE,
    agentShellExec: resolved.agentShellExec,
    pollExecStatus: resolved.pollExecStatus,
    steps: [],
  };
  const log = o.log || console;

  // ── 1. can this controller read ad/<LAB>/playbooks.yml? ───────────────────
  let perLab;
  if (o.perLabPlaybooks === true || o.perLabPlaybooks === false) {
    perLab = o.perLabPlaybooks;
  } else {
    const probe = await runStep(ctx, 'support-probe',
      cmdSupportsPerLabPlaybooks(runShPath, markerPath),
      { timeoutMs: TIMEOUT_PROBE, allowNonZero: true });
    perLab = probe.exitcode === 0;
  }
  const chainMode = perLab ? 'per-lab' : 'shared';
  const sharedKeyLine = perLab ? null : `${lab}:`;
  log.log(`[GoadLabPush] ${lab}: chain mode '${chainMode}' `
    + `(${perLab ? 'run.sh reads the lab-local override' : 'merging a key into ' + paths.sharedPlaybooks})`);

  // ── 2. is it already there? ───────────────────────────────────────────────
  if (!o.force) {
    const probe = await runStep(ctx, 'manifest-probe',
      cmdProbeManifest(paths, { treeSha: archive.treeSha256, chainSha, chainMode, sharedKeyLine }),
      { timeoutMs: TIMEOUT_PROBE, allowNonZero: true });
    if (probe.exitcode === 0) {
      log.log(`[GoadLabPush] ${lab}: already at ${archive.treeSha256.slice(0, 12)} — nothing to do`);
      return {
        lab,
        skipped: true,
        pushed: false,
        dest: paths.dest,
        treeSha256: archive.treeSha256,
        transferSha256: archive.transferSha256,
        chainSha256: chainSha,
        chainMode,
        tarBytes: archive.tarBytes,
        gzBytes: archive.gzBytes,
        chunks: 0,
        sharedPlaybooksChanged: false,
        steps: ctx.steps,
      };
    }
  }

  await runStep(ctx, 'preflight', cmdPreflight(paths), { timeoutMs: TIMEOUT_PROBE });
  await runStep(ctx, 'stage', cmdStage(paths));

  let sharedChanged = false;
  try {
    // ── 3. the chain FIRST, then the tree ─────────────────────────────────
    // Order matters, and this is the safer of the two. A failure between them
    // leaves either (a) a chain key naming a lab directory that does not exist
    // — run.sh stops with "Lab not found" before it starts ansible, loud and
    // free — or, if reversed, (b) a lab present with no chain, which run.sh
    // silently resolves to `default:` and provisions wrongly for an hour.
    if (!perLab) {
      const current = await runStep(ctx, 'read-shared-playbooks', cmdReadShared(paths),
        { timeoutMs: TIMEOUT_PROBE, allowNonZero: true });
      const merged = mergePlaybooksYaml(current.stdout || '', lab, chain);
      if (merged.changed) {
        await sendBytes(ctx, {
          b64Path: paths.playbooksB64,
          outPath: paths.playbooksNew,
          bytes: Buffer.from(merged.text, 'utf8'),
          label: 'playbooks',
        });
        await runStep(ctx, 'install-shared-playbooks', cmdInstallShared(paths));
        sharedChanged = true;
        log.log(`[GoadLabPush] ${lab}: ${merged.replaced ? 'replaced' : 'added'} `
          + `the ${lab}: key in ${paths.sharedPlaybooks}`);
      }
    }

    // ── 4. the tree ────────────────────────────────────────────────────────
    log.log(`[GoadLabPush] ${lab}: sending ${archive.gzBytes} gz bytes `
      + `(${archive.tarBytes} tar) in ~${Math.ceil((archive.gzBytes * 4 / 3) / ctx.chunkSize)} chunks`);
    const chunks = await sendBytes(ctx, {
      b64Path: paths.payloadB64,
      outPath: paths.payloadTgz,
      bytes: archive.gz,
      label: 'tree',
    });
    await runStep(ctx, 'extract', cmdExtract(paths));

    // The manifest goes into the STAGE, so it becomes visible only at the
    // rename. Nothing on the controller ever sees a manifest for a tree that
    // is not completely in place.
    await runStep(ctx, 'manifest', cmdWriteManifest(paths, buildManifest({
      lab, treeSha: archive.treeSha256, chainSha, chainMode,
    })));

    await runStep(ctx, 'swap', cmdSwap(paths));

    // Best-effort: a leftover work directory is inert, and failing the push
    // over a failed rm would be worse than the mess.
    await runStep(ctx, 'cleanup', cmdCleanup(paths), { allowNonZero: true });

    log.log(`[GoadLabPush] ${lab}: installed at ${paths.dest} (${archive.treeSha256.slice(0, 12)})`);
    return {
      lab,
      skipped: false,
      pushed: true,
      dest: paths.dest,
      treeSha256: archive.treeSha256,
      transferSha256: archive.transferSha256,
      chainSha256: chainSha,
      chainMode,
      tarBytes: archive.tarBytes,
      gzBytes: archive.gzBytes,
      chunks,
      sharedPlaybooksChanged: sharedChanged,
      steps: ctx.steps,
    };
  } catch (err) {
    // Take the staging area with us. Everything written so far lives under
    // paths.work; the destination has not been touched unless the swap itself
    // succeeded, and if the swap failed it already rolled itself back.
    try {
      await runStep(ctx, 'cleanup-after-failure', cmdCleanup(paths), { allowNonZero: true });
    } catch (cleanupErr) {
      log.warn?.(`[GoadLabPush] ${lab}: cleanup after failure also failed: ${cleanupErr.message}`);
    }
    if (err instanceof LabPushError) err.steps = ctx.steps;
    throw err;
  }
}

module.exports = {
  // Constants a caller or test should not re-derive.
  GOAD_ROOT,
  DEFAULT_RUN_SH,
  CHUNK_SIZE,
  TAR_MTIME,
  TAR_BLOCK,
  MAX_ARCHIVE_BYTES,
  RESERVED_LAB_NAMES,
  EXIT,
  LabPushError,
  // Validation.
  assertLabName,
  assertChain,
  normalizeMemberPath,
  assertShellSafe,
  // The transport itself, shared with goad-ext-config-push.js.
  //
  // Exported rather than copied because agentShellExec retries the TRANSPORT
  // and not the WORK: "a failed call may have run, may have run twice, or may
  // never have run" is a subtle contract, and runStep/sendBytes are where it is
  // handled (ordered appends, empty stdout, a sha256 gate before anything is
  // installed). A second implementation of that would drift on the first fix to
  // either copy, and the drift would surface as a corrupt file on a live lane.
  // No behaviour change here — these are the same functions pushLabTree calls.
  runStep,
  sendBytes,
  // The deterministic archive.
  buildTar,
  gzipDeterministic,
  buildLabArchive,
  chunkString,
  // The second artifact.
  renderChainBlock,
  renderLabPlaybooksYaml,
  mergePlaybooksYaml,
  chainSha256,
  // Remote layout + commands, exported so the shell text itself is testable.
  labPathsFor,
  buildManifest,
  cmdPreflight,
  cmdSupportsPerLabPlaybooks,
  cmdProbeManifest,
  cmdStage,
  cmdTruncate,
  cmdAppendChunk,
  cmdDecodeVerify,
  cmdExtract,
  cmdWriteManifest,
  cmdSwap,
  cmdReadShared,
  cmdInstallShared,
  cmdCleanup,
  // The entry point.
  pushLabTree,
};
