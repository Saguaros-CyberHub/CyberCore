/**
 * goad-ext-config-push.js — deliver ONE rewritten extension config.json to the
 * GOAD controller.
 * ============================================================================
 * WHY THIS EXISTS AT ALL
 * extensions/ws01/ansible/install.yml imports the MAIN lab's data.yml
 * (data_path: "../ad/{{domain_name}}/data/"), then layers its own
 * ../data/config.json in as `lab_extension` and merges the two. It then does:
 *
 *     member_domain:   "{{ lab.hosts[dict_key].domain }}"                 # from the EXTENSION config
 *     domain_password: "{{ lab.domains[member_domain].domain_password }}" # from the MAIN config
 *
 * So the extension config names a domain that the main config must be able to
 * look up. Rename the forest in the main config and leave the extension's
 * alone, and `lab.domains['sevenkingdoms.local']` is undefined: the play dies
 * on an undefined-attribute error roughly forty minutes into a deploy, with the
 * forest already built. The fix is one 996-byte file, rewritten with the same
 * transform and delivered here.
 *
 * WHY pushLabTree CANNOT DO IT, which is the whole reason for a second module
 *   - labPathsFor() hardcodes `adDir = ${root}/ad`. extensions/ is not under
 *     ad/, so there is no argument that aims it here.
 *   - It swaps the whole destination DIRECTORY (retire, rename, delete).
 *     Pointed at extensions/ws01/ that swap would delete ansible/, inventory
 *     and providers/ — everything except the one file we meant to change.
 *     run.sh would then fail its own `[ -f "$EXT_INV_SRC" ]` check, which is at
 *     least loud, but the extension is gone from the image until a re-bake.
 *
 * DO NOT RE-IMPLEMENT THE TRANSPORT. assertShellSafe, runStep and sendBytes
 * come from goad-lab-push.js. They carry the retry semantics (agentShellExec
 * retries the TRANSPORT, not the WORK), the "every chunk command produces empty
 * stdout" discipline, and the ordered append + sha256 verify that makes a
 * dropped chunk detectable. Two copies of that would drift on the first bug fix
 * to either, and the drift would surface as a corrupt config on a live lane.
 *
 * THE FIVE STEPS, and the failure each one is shaped around
 *
 *   1. PROBE + preflight in ONE round trip. Every guest call costs ~3s
 *      (pollExecStatus' poll floor), and the common case is "already correct",
 *      so the whole no-op path is one call.
 *
 *      It REFUSES when the stock file is not already there, rather than
 *      creating it. A missing extensions/<key>/data/config.json means the image
 *      does not carry that extension (or carries a version of it that has no
 *      config of its own, like elk and wazuh). `mkdir -p` would turn run.sh's
 *      correct, loud "extension '<key>' has no directory" refusal into a config
 *      file sitting in a tree nothing reads — a green deploy with no extension
 *      in it, discovered by an instructor opening Kibana.
 *
 *   2. STAGE a work directory as a SIBLING of the extension directories.
 *      Same filesystem, so the final `mv` is rename(2) and cannot half-happen.
 *      Not inside extensions/<key>/data/, because that directory is what
 *      install.yml names in `vars_files` and it should hold exactly the files
 *      ansible expects to find there.
 *
 *   3. SEND via sendBytes. ~1.3KB of base64 for a 996-byte config: one chunk
 *      against the shared 48KB CHUNK_SIZE, so this is a single call.
 *
 *   4. INSTALL. Re-hash the staged file ONE SYSCALL before the rename, so the
 *      check and the replace are adjacent inside a single guest command; back
 *      the stock file up to .cc-bak first, best-effort and only once; then
 *      `mv -f`.
 *
 *      NEVER `> dest`. A redirect truncates before it writes, so an interrupted
 *      write leaves install.yml parsing half a JSON document — and it fails
 *      reporting a line number, not a cause. `mv` of a fully-verified file is
 *      atomic: the destination holds either the stock config or the intended
 *      one, never anything in between.
 *
 *   5. CLEANUP, non-fatal. A leftover dot-directory beside extensions/ is
 *      inert; failing the push over a failed `rm` would be worse than the mess.
 *
 * PATH SAFETY IS LAYERED, because each layer covers a gap the others have:
 * an extension-key regex deliberately NARROWER than LAB_NAME_RE; the same
 * case-refusal shape run.sh uses, written so the two can be read side by side;
 * assertShellSafe on every joined path; and a literal equality assertion on the
 * final destination AFTER the join, checked against an independently-normalized
 * form so it is not merely restating the template that built it.
 *
 * SHELL DISCIPLINE — identical to goad-lab-push.js, and for the same reasons:
 * these strings run under dash, `set -e` is not in play, every step checks its
 * own exit code, and no command uses $(...), backticks, a pipeline whose exit
 * code matters, or a here-doc.
 *
 * EXIT CODES: everything this file defines is >= 100. A code below 100 came out
 * of the shared transport in goad-lab-push.js (its EXIT map), so the number
 * alone says which half of the push failed.
 */

const crypto = require('crypto');
const posix = require('path').posix;
const util = require('util');

const {
  GOAD_ROOT,
  CHUNK_SIZE,
  LabPushError,
  assertShellSafe,
  runStep,
  sendBytes,
} = require('./goad-lab-push');

// ─── Constants ──────────────────────────────────────────────────────────────

/** The one file this module ever writes, relative to extensions/<key>/. */
const CONFIG_REL = 'data/config.json';
const CONFIG_NAME = 'config.json';

/** The single top-level key install.yml reads. See assertExtensionConfig. */
const TOP_KEY = 'lab_extension';

/**
 * The stock configs are 573 B (lx01) and 996 B (ws01); a rewritten one is the
 * same shape. 64KB is three orders of magnitude of headroom and still refuses
 * the realistic accident — a rewriter that handed us the MAIN lab's 10.7KB
 * config, or a whole tree serialized by mistake — before a chunk loop starts.
 */
const MAX_CONFIG_BYTES = 64 * 1024;

/** Per-call timeouts. The floor on both is pollExecStatus' 3s poll. */
const TIMEOUT_PROBE = 30000;
const TIMEOUT_WORK = 120000;

/**
 * Deliberately NARROWER than goad-lab-push's LAB_NAME_RE, which permits dots.
 *
 * A dot is half of every traversal shape, and unlike a lab name this string is
 * never authored — it comes from GOAD_EXTENSIONS, whose whole catalog is
 * ['elk','wazuh','ws01','lx01'] plus the two upstream keys we have not
 * admitted. Lowercase only for the same reason: upstream's directory names are
 * all lowercase and the controller's filesystem is case-sensitive, so 'WS01'
 * would name a directory that does not exist. Refuse it here, where the message
 * can say so, rather than at the join.
 */
const EXT_KEY_RE = /^[a-z0-9][a-z0-9_-]{0,31}$/;

/** Work-directory suffix. No dots at all — the token is ours, not a caller's
 *  identifier, and the default shape below never needs one. */
const TOKEN_RE = /^[A-Za-z0-9][A-Za-z0-9-]{0,63}$/;

/**
 * Distinct exit codes, unique within this file and disjoint from
 * goad-lab-push's EXIT map (all < 100) so a bare number identifies the step.
 */
const EXT_EXIT = Object.freeze({
  // Probe. Everything here except STALE is a refusal.
  NO_EXT_DIR: 100,
  NO_STOCK_CONFIG: 101,
  NO_BASE64: 102,
  NO_SHA256: 103,
  STALE: 109,
  // Stage.
  STAGE_RM: 110,
  STAGE_MKDIR: 111,
  // Install.
  INSTALL_EMPTY: 120,
  INSTALL_VERIFY: 121,
  INSTALL_MV: 122,
});

/**
 * A literal backslash-n, for printf's format string.
 *
 * Built from a char code on purpose. This shell text is generated code, and the
 * repo has been broken more than once by a newline escape that survived one
 * round of escaping too many and arrived at the guest as a real newline —
 * splitting one command into two, the second of which is a bare path. There is
 * nothing here for an editor, a sed pass or a template to eat.
 */
const SH_NL = String.fromCharCode(92) + 'n';

// ─── Errors ─────────────────────────────────────────────────────────────────

/**
 * Carries { key, step, exitcode, dest }.
 *
 * The message is load-bearing and not decorative: challenge-lane-deployer wraps
 * the whole GOAD block in a catch, so this arrives as ONE log line and nothing
 * else about the failure is recorded. It has to name the consequence, because
 * the operator reading it is not looking at this file.
 */
class ExtConfigPushError extends LabPushError {
  constructor(message, details) {
    super(message, details);
    this.name = 'ExtConfigPushError';
  }
}

// ─── Validation ─────────────────────────────────────────────────────────────

/**
 * Layer 1 (charset) and layer 2 (run.sh's own guard, written in run.sh's shape).
 *
 * The second check is redundant against the regex above and stays anyway: it is
 * the exact predicate the controller applies to the same string, so the two can
 * be read side by side and neither can quietly become weaker than the other.
 * bake-goad-controller-vm.sh, in the extension loop:
 *
 *     case "$ext" in
 *       .|*"/"*|*".."*)
 *         echo "ERROR: refusing unsafe extension key '$ext'" >&2
 *         exit 1
 *         ;;
 *     esac
 */
function assertExtensionKey(key) {
  // NOT trimmed, unlike assertLabName. A lab name is authored by a human; an
  // extension key comes from GOAD_EXTENSIONS or from splitting a comma list, so
  // surrounding whitespace means a caller bug and trimming it away would hide
  // the bug rather than the whitespace.
  const k = String(key === null || key === undefined ? '' : key);
  if (!EXT_KEY_RE.test(k)) {
    throw new ExtConfigPushError(
      `Invalid GOAD extension key ${JSON.stringify(key)}: must match ${EXT_KEY_RE} `
      + '(lowercase, no dots — the key indexes a path under /opt/goad/extensions, '
      + 'and a dot is half of every traversal shape)',
      { key: k });
  }
  if (k === '.' || k.indexOf('/') !== -1 || k.indexOf('..') !== -1) {
    throw new ExtConfigPushError(
      `Refusing unsafe extension key ${JSON.stringify(key)} `
      + '(the same refusal run.sh makes: case "$ext" in .|*/*|*..*)',
      { key: k });
  }
  return k;
}

function assertToken(token) {
  const t = String(token === null || token === undefined ? '' : token);
  if (!TOKEN_RE.test(t)) {
    throw new ExtConfigPushError(
      `Invalid work token ${JSON.stringify(token)}: must match ${TOKEN_RE} `
      + '(it becomes a directory name beside extensions/, which a later rm -rf names)');
  }
  return t;
}

/**
 * Turn the caller's content into the exact bytes that will land at dest, or
 * refuse.
 *
 * Accepts a string, a Buffer, or a plain object (which is serialized here). The
 * object form exists because the rebrand transform naturally has one, and
 * serializing it in one place means the bytes we hash, the bytes we send and
 * the bytes we verify cannot disagree.
 *
 * THE GUARDS, and what each one actually catches:
 *
 *   strict JSON — upstream's own DRACARYS config.json has an illegal trailing
 *   comma at line 128 and works only because ansible loads it through a YAML
 *   loader. So "ansible accepted it" is NOT evidence that a config is JSON, and
 *   a rewriter that emitted the same mistake would be discovered by ansible
 *   reporting a line number rather than a cause. Parse it here.
 *
 *   exactly one top-level key, and it is lab_extension — install.yml pulls this
 *   file in with `vars_files`, so EVERY top-level key becomes an ansible
 *   variable at play scope. A stray `domains` or `lab` key would silently
 *   override the main lab's own data, which is precisely why the exchange
 *   extension (which ships its own `domains` block) is rename-unsafe. And
 *   `lab_extension` is the only name the merge task reads: anything else is
 *   loaded, shadows something, and is never used on purpose.
 *
 *   no carriage return — a CR inside a JSON string literal is legal JSON, so it
 *   survives the parse and rides straight into the domain_password ansible
 *   quotes at the domain join, which then fails as bad credentials and traces
 *   back to nothing.
 *
 *   a round trip through JSON — for the object form this catches the values
 *   JSON.stringify silently drops or rewrites (undefined members, functions,
 *   non-finite numbers); for text it is free.
 */
function assertExtensionConfig(content, key) {
  let text;
  if (Buffer.isBuffer(content)) {
    text = content.toString('utf8');
    // Decode/encode must round-trip, or the buffer was not valid UTF-8 and
    // toString() has already replaced bytes with U+FFFD — silently changing a
    // password we are about to install.
    if (!Buffer.from(text, 'utf8').equals(content)) {
      throw new ExtConfigPushError(
        `Extension config for '${key}' is not valid UTF-8 `
        + '(it does not survive a decode/encode round trip)',
        { key });
    }
  } else if (typeof content === 'string') {
    text = content;
  } else if (content && typeof content === 'object' && !Array.isArray(content)) {
    text = `${JSON.stringify(content, null, 2)}\n`;
  } else {
    throw new ExtConfigPushError(
      `Extension config for '${key}' must be a string, a Buffer or a plain object, got ${
        content === null ? 'null' : Array.isArray(content) ? 'an array' : typeof content}`,
      { key });
  }

  if (/\r/.test(text)) {
    throw new ExtConfigPushError(
      `Extension config for '${key}' contains a carriage return. That is legal JSON `
      + 'inside a string, so it survives the parse and rides into the domain_password '
      + 'ansible quotes at the domain join — which then fails as bad credentials.',
      { key });
  }

  const bytes = Buffer.from(text, 'utf8');
  if (bytes.length === 0) {
    throw new ExtConfigPushError(`Extension config for '${key}' is empty`, { key });
  }
  if (bytes.length > MAX_CONFIG_BYTES) {
    throw new ExtConfigPushError(
      `Extension config for '${key}' is ${bytes.length} bytes, over the `
      + `${MAX_CONFIG_BYTES}-byte ceiling. An extension config is one host's entry; this `
      + 'size means something much larger (the main lab config, or a whole tree) was '
      + 'handed to the wrong pusher.',
      { key });
  }

  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new ExtConfigPushError(
      `Extension config for '${key}' is not strict JSON: ${err.message}. `
      + "Upstream's DRACARYS config parses only because ansible reads it with a YAML "
      + 'loader, so this has to be checked here — otherwise the first sign of it is '
      + 'ansible failing at a line number, forty minutes in.',
      { key });
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new ExtConfigPushError(
      `Extension config for '${key}' must be a JSON object at the top level`, { key });
  }
  const keys = Object.keys(parsed);
  if (keys.length !== 1 || keys[0] !== TOP_KEY) {
    throw new ExtConfigPushError(
      `Extension config for '${key}' must have exactly one top-level key, '${TOP_KEY}', `
      + `got [${keys.join(', ')}]. install.yml loads this file with vars_files, so every `
      + 'top-level key becomes a play-scope ansible variable and would shadow the main '
      + "lab's own data.",
      { key });
  }
  const ext = parsed[TOP_KEY];
  if (!ext || typeof ext !== 'object' || Array.isArray(ext)) {
    throw new ExtConfigPushError(
      `Extension config for '${key}' has a '${TOP_KEY}' that is not an object; the merge `
      + 'task does `lab|combine(lab_extension, recursive=True)`, which needs a mapping',
      { key });
  }
  if (!util.isDeepStrictEqual(JSON.parse(JSON.stringify(parsed)), parsed)) {
    throw new ExtConfigPushError(
      `Extension config for '${key}' does not survive a JSON round trip — some value is `
      + 'dropped or rewritten by serialization, so the file on the controller would not '
      + 'be what the caller built',
      { key });
  }

  return { bytes, text, parsed };
}

// ─── Remote paths ───────────────────────────────────────────────────────────

/**
 * Everything the remote steps touch, derived once so no command builds a path
 * of its own.
 *
 * The work directory is a SIBLING of the extension directories — under
 * extensions/, not under extensions/<key>/data/. Two reasons, and the first is
 * the load-bearing one: the final `mv` must be rename(2), which is only atomic
 * within a filesystem, and a work dir in /tmp (possibly a tmpfs on this image)
 * would silently degrade it to copy-then-unlink. The second: extensions/<key>/
 * data/ is the directory install.yml names in `vars_files`, and it should hold
 * exactly the files ansible expects to find there.
 */
function extPathsFor(root, key, token) {
  const goadRoot = assertShellSafe(String(root || GOAD_ROOT).replace(/\/+$/, ''), 'GOAD root');
  const k = assertExtensionKey(key);
  const tok = assertToken(token);

  const extRoot = assertShellSafe(`${goadRoot}/extensions`, 'extensions root');
  const extDir = assertShellSafe(`${extRoot}/${k}`, 'extension directory');
  const dataDir = assertShellSafe(`${extDir}/data`, 'extension data directory');
  const dest = assertShellSafe(`${dataDir}/${CONFIG_NAME}`, 'extension config path');
  const backup = assertShellSafe(`${dest}.cc-bak`, 'extension config backup path');
  const work = assertShellSafe(`${extRoot}/.cc-extcfg-${tok}`, 'work directory');

  // A work directory equal to any real directory would make the cleanup `rm -rf`
  // delete the extensions tree. Unreachable given the token charset; it stays
  // because the cost of being wrong here is the whole extensions/ directory.
  if (work === extRoot || work === extDir || work === dataDir || work === goadRoot) {
    throw new ExtConfigPushError(
      'Refusing to use a real GOAD directory as the extension-config work directory',
      { key: k });
  }

  return {
    goadRoot,
    key: k,
    extRoot,
    extDir,
    dataDir,
    dest,
    backup,
    work,
    staged: assertShellSafe(`${work}/${CONFIG_NAME}`, 'staged config path'),
    stagedB64: assertShellSafe(`${work}/${CONFIG_NAME}.b64`, 'staged base64 path'),
  };
}

/**
 * The last path check, and the only one that is not a charset test.
 *
 * `dest` is compared against a form built by posix.join, which NORMALIZES: a key
 * that contained a traversal component would collapse under join and stop
 * matching the template-built string, so any disagreement between "the path we
 * assembled" and "the path those components actually denote" fails here. That
 * is what makes this more than a restatement of the template above it.
 */
function assertDestination(paths) {
  const joined = posix.join(paths.goadRoot, 'extensions', paths.key, 'data', CONFIG_NAME);
  const normalized = posix.normalize(paths.dest);
  if (paths.dest !== joined || normalized !== paths.dest) {
    throw new ExtConfigPushError(
      `Refusing to write an extension config to ${JSON.stringify(paths.dest)}: `
      + `it is not ${JSON.stringify(joined)}`,
      { key: paths.key, dest: paths.dest });
  }
  if (!paths.dest.startsWith(`${paths.goadRoot}/extensions/`)) {
    throw new ExtConfigPushError(
      `Refusing to write an extension config outside ${paths.goadRoot}/extensions/: ${paths.dest}`,
      { key: paths.key, dest: paths.dest });
  }
  return paths.dest;
}

// ─── Shell command builders ─────────────────────────────────────────────────
//
// Separate named functions so the emitted text itself is testable — in
// particular that nothing ever redirects into the destination.

/**
 * Probe and preflight in one call, and the only call the no-op path makes.
 *
 * Exit 0 means "the destination already holds exactly these bytes". STALE means
 * "push it". EVERY OTHER CODE IS A REFUSAL — the opposite asymmetry to
 * pushLabTree's manifest probe, and deliberately so: there, an unreadable probe
 * falls through to a redundant push that costs 90 seconds; here, what the probe
 * is checking is whether the file we are about to replace exists at all, so
 * "I could not tell" must not become "create it anyway".
 *
 * With `force`, the hash comparison is omitted and the command falls through to
 * STALE — but the two existence refusals still apply. `force` means "push even
 * though it already matches", never "push into an image that has no such
 * extension".
 */
function cmdProbe(paths, { sha, force = false } = {}) {
  const lines = [
    `[ -d '${paths.extDir}' ] || exit ${EXT_EXIT.NO_EXT_DIR}`,
    `[ -f '${paths.dest}' ] || exit ${EXT_EXIT.NO_STOCK_CONFIG}`,
    `command -v base64 >/dev/null 2>&1 || exit ${EXT_EXIT.NO_BASE64}`,
    `command -v sha256sum >/dev/null 2>&1 || exit ${EXT_EXIT.NO_SHA256}`,
  ];
  if (!force) {
    // Two spaces between hash and path — sha256sum -c's own format. Output goes
    // to /dev/null rather than using --status, which busybox's sha256sum lacks.
    lines.push(`printf '%s  %s${SH_NL}' '${sha}' '${paths.dest}' `
      + '| sha256sum -c - >/dev/null 2>&1 && exit 0');
  }
  lines.push(`exit ${EXT_EXIT.STALE}`);
  return lines.join('\n');
}

function cmdStage(paths) {
  return [
    `rm -rf '${paths.work}' || exit ${EXT_EXIT.STAGE_RM}`,
    `mkdir -p '${paths.work}' || exit ${EXT_EXIT.STAGE_MKDIR}`,
    'exit 0',
  ].join('\n');
}

/**
 * Back up, re-verify, replace — in that order, in ONE command.
 *
 * The re-hash is not paranoia about the transport (sendBytes already verified
 * the decode); it is what makes the check and the replace adjacent, so nothing
 * can run between "these are the right bytes" and "these bytes are now the
 * config". It costs one syscall on a 1KB file.
 *
 * The backup is written ONLY IF ABSENT. On a second push of a *different*
 * config, an unconditional `cp` would overwrite .cc-bak with our own previous
 * output and destroy the only remaining copy of the image's stock file — which
 * is the one thing the backup exists to preserve.
 *
 * `mv -f`, never `> dest`: a redirect truncates before it writes, so a write
 * interrupted halfway leaves install.yml parsing half a JSON document and
 * failing at a line number instead of a cause. After a rename the destination
 * holds the stock config or the intended one, and nothing else.
 */
function cmdInstall(paths, sha) {
  return [
    `[ -s '${paths.staged}' ] || exit ${EXT_EXIT.INSTALL_EMPTY}`,
    `[ -f '${paths.backup}' ] || cp -p '${paths.dest}' '${paths.backup}' 2>/dev/null`,
    `printf '%s  %s${SH_NL}' '${sha}' '${paths.staged}' `
      + `| sha256sum -c - >/dev/null 2>&1 || exit ${EXT_EXIT.INSTALL_VERIFY}`,
    `mv -f '${paths.staged}' '${paths.dest}' || exit ${EXT_EXIT.INSTALL_MV}`,
    'exit 0',
  ].join('\n');
}

function cmdCleanup(paths) {
  return `rm -rf '${paths.work}'\nexit 0`;
}

// ─── Diagnostics ────────────────────────────────────────────────────────────

/**
 * What the operator needs to know, in one line, because that is all they get:
 * challenge-lane-deployer wraps the GOAD block in a catch and logs the message.
 */
function refusalFor(exitcode, key, paths) {
  switch (exitcode) {
    case EXT_EXIT.NO_EXT_DIR:
      return `the controller has no ${paths.extDir}. This image does not carry the `
        + `'${key}' extension, so run.sh will refuse the deploy anyway; writing a config `
        + 'into a tree that does not exist would only hide that.';
    case EXT_EXIT.NO_STOCK_CONFIG:
      return `${paths.dest} does not exist. Either the image predates this extension's `
        + `config, or '${key}' ships no config of its own (elk and wazuh do not) and `
        + 'nothing should be pushing one.';
    case EXT_EXIT.NO_BASE64:
      return 'the controller has no base64, which the chunked transport needs.';
    case EXT_EXIT.NO_SHA256:
      return 'the controller has no sha256sum, so a delivered file could not be verified.';
    default:
      return `the probe exited ${exitcode}, which is not a code this module emits.`;
  }
}

// ─── The entry point ────────────────────────────────────────────────────────

/**
 * Replace ONE extension's data/config.json on the GOAD controller.
 *
 * @param {object} opts
 * @param {string} opts.node          Proxmox node hosting the controller
 * @param {number|string} opts.vmId   controller VMID
 * @param {string} opts.key           extension key, e.g. 'ws01'
 * @param {string|Buffer|object} opts.content  the rewritten config
 * @param {string} [opts.root]        GOAD root on the guest (default /opt/goad)
 * @param {boolean} [opts.force]      push even when the destination already matches
 * @param {string} [opts.token]       work-directory suffix (tests pin it)
 * @param {number} [opts.chunkSize]   base64 chars per guest call
 * @param {object} [opts.deps]        { agentShellExec, pollExecStatus }
 * @param {object} [opts.log]         console-shaped logger
 * @returns {Promise<object>} { key, dest, skipped, pushed, sha256, bytes, chunks, steps }
 */
async function pushExtensionConfig(opts) {
  const o = opts || {};
  const key = assertExtensionKey(o.key);
  const node = o.node;
  const vmId = o.vmId;
  if (!node || vmId === undefined || vmId === null || vmId === '') {
    throw new ExtConfigPushError(
      'pushExtensionConfig requires { node, vmId } for the GOAD controller', { key });
  }

  // Content first: every refusal below is decidable with no I/O, so a bad
  // rewrite costs zero guest calls and reports the reason rather than an exit
  // code from three steps later.
  const { bytes } = assertExtensionConfig(o.content, key);
  const sha = crypto.createHash('sha256').update(bytes).digest('hex');

  const token = o.token || `${sha.slice(0, 12)}-${crypto.randomBytes(3).toString('hex')}`;
  const paths = extPathsFor(o.root || GOAD_ROOT, key, token);
  const dest = assertDestination(paths);

  const deps = o.deps || {};
  const resolved = deps.agentShellExec && deps.pollExecStatus
    ? deps
    : { ...defaultDeps(), ...deps };
  const ctx = {
    node,
    vmId,
    chunkSize: Number(o.chunkSize) > 0 ? Math.floor(Number(o.chunkSize)) : CHUNK_SIZE,
    agentShellExec: resolved.agentShellExec,
    pollExecStatus: resolved.pollExecStatus,
    steps: [],
  };
  const log = o.log || console;

  const result = {
    key,
    dest,
    backup: paths.backup,
    skipped: false,
    pushed: false,
    sha256: sha,
    bytes: bytes.length,
    chunks: 0,
    steps: ctx.steps,
  };

  // ── 1. probe + preflight, one round trip ──────────────────────────────────
  //
  // Outside the try/catch below, because that block's cleanup deletes a work
  // directory this step has not created yet — and a controller that just failed
  // to answer a probe is the last place to spend another 3-second call. The
  // probe's own failure is annotated here instead, so it still arrives carrying
  // { key, step, dest } like every other failure from this module.
  let probe;
  try {
    probe = await runStep(ctx, 'ext-probe', cmdProbe(paths, { sha, force: !!o.force }),
      { timeoutMs: TIMEOUT_PROBE, allowNonZero: true });
  } catch (err) {
    throw new ExtConfigPushError(
      `Could not probe the '${key}' extension config on the controller: ${err.message}. `
      + `Nothing was written; ${dest} still holds whatever the image shipped.`,
      { key, step: 'ext-probe', exitcode: err.exitcode === undefined ? -1 : err.exitcode,
        dest, steps: ctx.steps, cause: err });
  }
  if (probe.exitcode === 0) {
    log.log(`[GoadExtConfig] ${key}: ${dest} already at ${sha.slice(0, 12)} — nothing to do`);
    result.skipped = true;
    return result;
  }
  if (probe.exitcode !== EXT_EXIT.STALE) {
    throw new ExtConfigPushError(
      `Cannot rewrite the '${key}' extension config: ${refusalFor(probe.exitcode, key, paths)}`,
      { key, step: 'ext-probe', exitcode: probe.exitcode, dest, steps: ctx.steps });
  }

  try {
    // ── 2. stage ────────────────────────────────────────────────────────────
    await runStep(ctx, 'ext-stage', cmdStage(paths), { timeoutMs: TIMEOUT_WORK });

    // ── 3. send ─────────────────────────────────────────────────────────────
    result.chunks = await sendBytes(ctx, {
      b64Path: paths.stagedB64,
      outPath: paths.staged,
      bytes,
      label: 'ext-config',
    });

    // ── 4. install ──────────────────────────────────────────────────────────
    await runStep(ctx, 'ext-install', cmdInstall(paths, sha), { timeoutMs: TIMEOUT_WORK });

    // ── 5. cleanup, non-fatal ───────────────────────────────────────────────
    await runStep(ctx, 'ext-cleanup', cmdCleanup(paths),
      { timeoutMs: TIMEOUT_WORK, allowNonZero: true });

    log.log(`[GoadExtConfig] ${key}: installed ${bytes.length} bytes at ${dest} `
      + `(${sha.slice(0, 12)}, ${result.chunks} chunk${result.chunks === 1 ? '' : 's'})`);
    result.pushed = true;
    return result;
  } catch (err) {
    // Everything written so far lives under paths.work. The destination is
    // untouched unless the rename itself succeeded, and the rename is the last
    // thing that can fail.
    try {
      await runStep(ctx, 'ext-cleanup-after-failure', cmdCleanup(paths),
        { timeoutMs: TIMEOUT_WORK, allowNonZero: true });
    } catch (cleanupErr) {
      log.warn?.(`[GoadExtConfig] ${key}: cleanup after failure also failed: ${cleanupErr.message}`);
    }
    const step = err.step || 'ext-push';
    const exitcode = err.exitcode === undefined ? -1 : err.exitcode;
    throw new ExtConfigPushError(
      `GOAD extension config push failed for '${key}' at step '${step}' (exit ${exitcode}): `
      + `${err.message}. ${dest} still holds the stock config, which names the stock forest `
      + `root; ${key}'s domain join would fail against a forest that no longer has that domain.`,
      { key, step, exitcode, dest, steps: ctx.steps, cause: err });
  }
}

/**
 * The real transport is required LAZILY, for the same reason goad-lab-push does
 * it: script-executor.js pulls in ./proxmox and ./db at module load, both of
 * which read env and open handles.
 */
function defaultDeps() {
  const se = require('../../../../../src/utils/script-executor');
  return { agentShellExec: se.agentShellExec, pollExecStatus: se.pollExecStatus };
}

module.exports = {
  // Constants a caller or test should not re-derive.
  CONFIG_REL,
  CONFIG_NAME,
  TOP_KEY,
  MAX_CONFIG_BYTES,
  EXT_KEY_RE,
  EXT_EXIT,
  ExtConfigPushError,
  // Validation.
  assertExtensionKey,
  assertExtensionConfig,
  // Remote layout + commands, exported so the shell text itself is testable.
  extPathsFor,
  assertDestination,
  cmdProbe,
  cmdStage,
  cmdInstall,
  cmdCleanup,
  // The entry point.
  pushExtensionConfig,
};
