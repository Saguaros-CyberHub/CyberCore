/**
 * ============================================================================
 * CIAB PER-LANE RESEED — the half of the golden-image design that makes it safe
 * ----------------------------------------------------------------------------
 * A golden image is IDENTICAL BY DEFINITION. That is the whole reason it is
 * fast, and it is also the whole reason it cannot be the source of anything a
 * student is supposed to discover for themselves.
 *
 * THE DEFECT THIS EXISTS TO FIX
 * -----------------------------
 * The vuln-app image is cached on (profile_id, difficulty) and hashBundle
 * covers only the generated source plus the Dockerfile. So every lane in every
 * section of every course runs a byte-identical image, carrying byte-identical
 * FLAG{...} strings — and nothing plants them, so they exist only where the
 * file generator happened to embed them. One student pastes a value in the
 * group chat and the whole cohort is done. Golden AD images make it strictly
 * worse: the domain password, every user password and the service credential
 * the exercise pivots on would be identical for every student too.
 *
 * THE RULE
 * --------
 * Anything that must differ per student is RESEEDED AFTER CLONE, never baked.
 * If a value can be read off the golden image, it is not a secret — it is
 * decoration. This file is where the per-lane values are actually written into
 * the guests.
 *
 * WHAT GETS RESEEDED, AND WHY IN THIS ORDER
 * -----------------------------------------
 *   0. assertGoldenSubnet — a pre-baked GOAD lane whose spec declares no
 *      goad.fixed_subnet (or declares one the lane was not actually built on)
 *      has every AD-integrated DNS record, every SPN and every SYSVOL/DFS
 *      referral pointing at an address that does not exist on this lane. The
 *      lane still boots and still reports active, so the student is the one who
 *      finds out. This THROWS. It is the one failure here that is not a
 *      best-effort step.
 *
 *   1. host identity on the web box — SSH host keys and machine-id. Cloned
 *      from a golden image these are shared across the entire cohort, so
 *      `ssh-keyscan` fingerprints collide and every lane looks like the same
 *      host to anything that caches by key.
 *
 *   2. the per-lane flag, written where the app exposes it. The VALUE comes
 *      from the existing per-lane flag system (src/utils/flag-manager.js,
 *      cybercore_lane_flag, CSPRNG) — deliberately NOT a fourth flag mechanism.
 *      See resolveAppFlag for why it reuses the web box's `user` flag rather
 *      than inventing a flag_type.
 *
 *   3. lane-unique seeded data (order numbers, patient ids, an invoice base) so
 *      two students cannot compare answers about the records in the site.
 *
 *   4. THE PIVOT CREDENTIAL, ON EVERY SIDE AT ONCE. This is the half that is
 *      easy to miss and that silently breaks the exercise. A prebaked lane has
 *      NO CONTROLLER — there is no Ansible run to change a password with — so
 *      the AD side is done with Set-ADAccountPassword over the DC's OWN guest
 *      agent. That makes the DC guest agent a hard dependency of reseed, which
 *      is why waitForDcAgent is a real wait-and-retry loop and not a
 *      console.warn.
 *
 *      AND THERE ARE MORE THAN TWO SIDES. The credential the student actually
 *      reads is the one the COMPANY WEBSITE publishes: the application config
 *      cc_web plants under the docroot (one of five formats at one of six
 *      paths, picked per client) and the integration-settings page, which
 *      prints it in the clear. Both are baked into the golden image. For a long
 *      while this file rotated AD, wrote `AD_SERVICE_PASSWORD` into an env file
 *      it created itself with `mkdir -p` — so the step could not fail — and left
 *      the website advertising the BAKED password to every student in the
 *      section. plan.warnings was empty. The lane was green. The pivot did not
 *      work. That is the exact silent-success class this project exists to
 *      remove, sitting on the one seam the design is built around.
 *
 *      So the publishers are rewritten IN PLACE and FORMAT-AWARE (an ini, a PHP
 *      array, an XML element, a JSON document and an HTML attribute are five
 *      different operations), at locations the BAKE recorded rather than
 *      locations this file guessed — goad-lab-content emits them as
 *      site.reseed.plants and they ride on spec.reseed.pivot.site.
 *
 *      ALL SIDES OR NONE. Every publisher is read first, rewritten on the
 *      orchestrator and staged beside itself as `<path>.ccreseed`; AD is
 *      changed only once every staging succeeded; the files are published only
 *      once AD accepted. A publisher that is missing, that moved, or that does
 *      not carry the value where the descriptor says stops the whole phase
 *      BEFORE the directory is touched, and every side stays on the baked
 *      value with the reason recorded.
 *
 *      AND THE RULE HAS A BOUNDARY. Per-lane uniqueness is for secrets whose
 *      ONLY job is to differ between students. It must never be applied to a
 *      credential whose specific VALUE or PROPERTY carries the exercise: a
 *      password drawn from a wordlist precisely so an AS-REP hash falls to an
 *      offline crack, a password that IS the sAMAccountName because that
 *      equality is the technique, a password planted in a share file or a
 *      directory description the student is meant to FIND and reuse. Rotating
 *      one of those into a 20-character CSPRNG value reports `credential: ok`
 *      and leaves a chain nobody can walk — the same silent success this file
 *      exists to remove, aimed at the exercise instead of at the plumbing.
 *
 *      This end does not GUESS which is which. The attack-chain designer
 *      already records what every entry and every edge is FOR (planted_at.format,
 *      edge_type, the prerequisites that plant a crackable password), and
 *      profile-deploy reads those declarations and puts the verdict on the spec:
 *      `reseed.pivot.rotate:false` with a `fixed_reason`, plus `reseed.fixed`
 *      naming every other credential the exercise depends on the VALUE of. A
 *      fixed credential is REPORTED, never quietly skipped — an operator reading
 *      the reseed record has to be able to tell "deliberately not rotated" from
 *      "forgotten" — and `reseed.uniqueness` says, in both directions, which
 *      values still differ per student and which do not.
 *
 *   5. verification, of both halves. The published files are READ BACK and the
 *      value parsed out of them — an operation nobody observed did not happen —
 *      and the reseeded credential is authenticated for real
 *      (PrincipalContext.ValidateCredentials on the DC). The outcome is recorded
 *      on the lane row. "We ran Set-ADAccountPassword and it exited 0" is not
 *      evidence that a student can log in with it, and "we wrote the file" is
 *      not evidence the website stopped serving the old one.
 *
 * SECURITY — NON-NEGOTIABLE
 * -------------------------
 * Secrets go through agentExecArgv / agentShellExec ONLY. Never a staged file.
 * script-executor's executePowerShellViaFile / executeShellViaFile stage the
 * script into C:\Windows\Temp (world-traversable) with a tee'd .log beside it,
 * and script_args is interpolated UNQUOTED; the Remove-Item lives inside the
 * stub so a timeout leaves both behind. A student holding the low-priv shell we
 * deliberately gave them could read the credential out of either file and skip
 * the exercise. That is the rule stated at src/utils/script-executor.js and
 * enforced in src/utils/flag-manager.js, and it is why this file imports
 * neither of the staged helpers.
 *
 * On top of that rule, every secret this file sends is base64-encoded and
 * decoded inside the guest. Two reasons, both load-bearing:
 *   - a base64 payload is /^[A-Za-z0-9+/=]+$/, so it is inert inside a
 *     single-quoted PowerShell literal AND inside a single-quoted POSIX shell
 *     word. There is no quoting question left to get wrong, for any password
 *     the generator can ever produce.
 *   - it makes assertNoCleartextSecret a mechanical check the tests can hold
 *     us to: no command this module dispatches may contain a cleartext secret.
 *
 * NOTHING SECRET IS RECORDED ON THE LANE ROW. The pivot password is LOOT — the
 * thing the student is meant to find on the web box — not state we need to
 * keep. Lane config is read by student-facing code paths (workstation_user /
 * workstation_pass are served straight to the owner), so a password stored
 * there would hand over the answer. What IS recorded is a truncated SHA-256
 * fingerprint, which is enough for an instructor to confirm that the web box
 * and AD carry the SAME value without the value itself existing in the
 * database.
 *
 * FAILURE CONTRACT
 * ----------------
 * reseedLane NEVER THROWS. The deployer's postDeploy hook
 * (src/utils/challenge-lane-deployer.js) records a hook throw as
 * config.post_deploy_error and does not fail the lane; this matches that
 * contract and goes one better, recording a STRUCTURED outcome under
 * config.reseed so an instructor sees which step failed rather than one string.
 * A lane that deployed must not be destroyed because a password reset timed out.
 * ============================================================================
 */

const crypto = require('crypto');

const {
  waitForGuestAgent,
  waitForAgentExecReady,
  agentExecArgv,
  agentShellExec,
  pollExecStatus,
} = require('../../../../../src/utils/script-executor');
const { proxmoxAPI } = require('../../../../../src/utils/proxmox');
const { cybercoreQuery } = require('../../../../../src/utils/cybercore-db');
const { ensureLaneFlags } = require('../../../../../src/utils/flag-manager');
const goadDeploy = require('../../../../../src/utils/goad-deploy');

const LOG = '[CIAB Reseed]';

// Full path so QEMU guest-agent CreateProcess resolves it regardless of the
// guest's PATH. Same constant flag-manager and goad-deploy use.
const WIN_PS = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';

// How long we are willing to wait for a freshly-cloned DC's guest agent before
// giving up on the credential. Generous on purpose: a golden Windows Server
// clone routinely spends several minutes on first-boot device enumeration
// before qemu-ga answers, and abandoning the reseed early is how every lane in
// a batch ends up with the baked password.
const DC_AGENT_TIMEOUT_MS = 900000;   // 15 min

// Individual guest commands. The AD write and the credential validation both
// touch the directory, which on a cold DC can be slow; the shell steps are
// local and quick.
const WIN_CMD_TIMEOUT_MS = 300000;    // 5 min
const SH_CMD_TIMEOUT_MS  = 180000;    // 3 min

// Defaults for a spec that declares no `reseed` block. The paths match what
// vuln-app-install.js lays down for a docker-mode app (/opt/vuln-app) so the
// common case needs no spec change at all.
const DEFAULT_APP_DIR       = '/opt/vuln-app';
const DEFAULT_FLAG_PATH     = '/opt/vuln-app/flag.txt';
const DEFAULT_ENV_PATH      = '/opt/vuln-app/.env';
const DEFAULT_ENV_KEY       = 'AD_SERVICE_PASSWORD';
const DEFAULT_SEED_PATH     = '/opt/vuln-app/.lane-seed';
const DEFAULT_CONTAINER     = 'vuln-app';

// A generated password only ever contains these. No quote of any kind, so it is
// safe in every literal we build even before base64 encoding, and no ambiguous
// glyphs (0/O, 1/l/I) because a student has to be able to TYPE it off a screen.
const PW_UPPER  = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
const PW_LOWER  = 'abcdefghijkmnopqrstuvwxyz';
const PW_DIGIT  = '23456789';
const PW_SYMBOL = '!#%*+-=?@_';
const PW_LENGTH = 20;

// What a base64 payload may contain. Anything outside this set means someone
// handed a raw secret to a command builder, which is the bug this guards.
const B64_RE = /^[A-Za-z0-9+/=]*$/;

// sAMAccountName and DNS domain, validated rather than trusted: both come from
// admin-authored spec JSON and both end up inside a single-quoted PowerShell
// literal. Same reasoning (and the same explicit newline check) as
// flag-manager.isSafePath — in JavaScript `$` also matches before a trailing
// newline, so /^[safe]+$/ alone would accept "svc-web\n" and let whatever
// follows run as its own statement.
const AD_SAM_RE    = /^[A-Za-z0-9._$-]{1,64}$/;
const AD_DOMAIN_RE = /^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$/;

// Absolute POSIX paths only, and nothing that could terminate a single-quoted
// shell word or open a subshell.
const POSIX_PATH_RE = /^\/[A-Za-z0-9 _.\-/]{0,255}$/;

// ── the site's own copy of the credential ───────────────────────────────────
//
// THE HALF THAT WAS MISSING, AND THE ONLY ONE THE STUDENT EVER SEES.
//
// Rotating the account in Active Directory and writing the new value into an
// env file this module creates itself is not a reseed — it is two green steps
// and a broken exercise. The credential the student actually reads comes off
// the COMPANY WEBSITE: out of the application config cc_web plants under the
// docroot (one of five formats, at one of six paths, chosen per client), and
// off the integration-settings page, which prints it in the clear in an input
// box. Both of those are baked into the golden image. Left alone they go on
// advertising the BAKED password for the life of the section while AD honours a
// different one per lane, and nothing reports it: the lane is active, the flag
// is planted, plan.warnings is empty, and the pivot the whole engagement is
// built around simply does not work.
//
// So the reseed rewrites the site's own files, IN PLACE and FORMAT-AWARE.
// Rewriting an ini, a PHP array, a JSON document, an XML element and an HTML
// attribute are five different operations; a regex that happens to work on one
// corrupts another into a 500 the student reads as "the lab is broken".
//
// It does NOT guess where they are. goad-lab-content emits the locations and
// the formats as data (site.reseed.plants) at the moment the site is authored —
// the only moment anything knows them — and they ride onto the deploy spec at
// spec.reseed.pivot.site. A target that is missing, moved, or whose value is
// not where the descriptor says is a LOUD failure that leaves both sides on the
// baked value, never a silent pass.

/** The rewrite operations this module implements. Pinned in the tests against
 *  goad-lab-content.SITE_RESEED_OPS, which is the producer's own list: an
 *  operation only one end knows about is a target that is silently skipped. */
const PLANT_OPS = Object.freeze(['dotenv', 'ini', 'php', 'json', 'xml', 'slot']);

/** Key / section / element names, validated rather than trusted: they come from
 *  spec JSON and end up inside a RegExp we build. */
const PLANT_NAME_RE = /^[A-Za-z0-9_.\-]{1,64}$/;

/** What a read of a path that is not there answers with. A SENTINEL RATHER THAN
 *  A NON-ZERO EXIT, so "the file is gone" is an answer this module can act on
 *  and report, instead of an error indistinguishable from a transport failure. */
const PLANT_MISSING = '__CIAB_PLANT_MISSING__';

/** The staged rewrite sits beside its target, never in a temp directory. Same
 *  reasoning as the env file's `.new`: nothing reads it, umask 077 keeps it at
 *  0600 root:root so the web user cannot serve it, and it is removed on both
 *  the commit and the abort path. */
const PLANT_STAGE_SUFFIX = '.ccreseed';

/** Base64 characters per guest command. The bake writes files to the controller
 *  in exactly this size, and a lane's pages are a few kilobytes, so almost
 *  everything is one command. */
const PLANT_CHUNK = 32768;

/** A cap on what this module will pull out of a guest and push back. A pivot
 *  config is under a kilobyte and the largest page the site generator emits is
 *  ~16KB; anything at this size is not one of our targets and reading it into
 *  the orchestrator is not something to do quietly. */
const PLANT_MAX_BYTES = 512 * 1024;

// ============================================================================
// 0. THE ASSERTION THAT IS NOT BEST-EFFORT
// ============================================================================

/**
 * Refuse to reseed a pre-baked GOAD lane that is not standing on the subnet its
 * golden images were baked on.
 *
 * challenge-lane-deployer.applyPrebakedFixedSubnet already refuses to BUILD a
 * prebaked lane with no goad.fixed_subnet.int. This is the second half of that
 * guard and it checks something the first one cannot: that the base the spec
 * declares is the base the lane actually came up on. If those disagree — a spec
 * edited after the bake, a subnet scheme that re-derived the base, a lane
 * rebuilt from a stale challenge row — then the AD-integrated DNS zone, every
 * SPN and every SYSVOL/DFS referral in the golden image name an address nothing
 * on this lane owns. Nothing fails: the clones boot, DHCP answers, the lane
 * reports active, and the first `nxc`, domain join or Kerberos ticket request
 * is where the student discovers the forest is fiction.
 *
 * Reseeding on top of that is worse than useless: Set-ADAccountPassword would
 * be aimed at a directory the rest of the lane cannot reach, so we would report
 * a credential the student can never use.
 *
 * @param {object} spec  the challenge spec
 * @param {object} a
 * @param {string} a.goadSubnetBase  the INTERNAL /24 base the lane was built on
 * @returns {null|{base:string}}  null when the lane is not a golden AD lane
 * @throws when it is, and the declaration is missing or disagrees
 */
function assertGoldenSubnet(spec, { goadSubnetBase } = {}) {
  if (!spec || !spec.goad || !spec.goad.prebaked) return null;

  const fixed = spec.goad.fixed_subnet || {};
  // Trimmed for the same reason applyPrebakedFixedSubnet trims: these are
  // hand-typed into the create form, and ' 10.39.16' survives a truthiness
  // check and then builds ' 10.39.16.1', which Proxmox accepts and no guest
  // can reach.
  const declared = String(fixed.int == null ? '' : fixed.int).trim();

  if (!declared) {
    throw new Error(
      'Refusing to reseed: this challenge is marked pre-baked GOAD ' +
      '(spec.goad.prebaked) but declares no goad.fixed_subnet.int. The golden AD ' +
      'images answer on the base they were baked on, so every DNS record, SPN and ' +
      'SYSVOL path in them names an address this lane does not have — and the lane ' +
      'still reports active. Set spec.goad.fixed_subnet = { int: "<base the images ' +
      'were baked on>", ext: "<external base>" }, or clear spec.goad.prebaked to ' +
      'provision the lab live instead.'
    );
  }

  const actual = String(goadSubnetBase == null ? '' : goadSubnetBase).trim();
  if (!actual || actual !== declared) {
    throw new Error(
      `Refusing to reseed: this pre-baked GOAD lane declares ` +
      `goad.fixed_subnet.int = '${declared}' but was built on '${actual || '(none)'}'. ` +
      `The golden images' baked DNS, SPN and SYSVOL records all name ${declared}.x ` +
      `addresses that nothing on this lane owns, so AD is unreachable in exactly the ` +
      `way that still lets the lane report active. Rebuild the lane on ${declared} or ` +
      `re-bake the images on ${actual}.`
    );
  }

  return { base: declared };
}

// ============================================================================
// THE PLANT OPERATIONS — pure, so what will be written to a guest is readable
// ============================================================================
//
// EVERY REWRITE IS DONE HERE, ON THE ORCHESTRATOR, not by a sed the guest runs.
// Three reasons, and none of them is convenience:
//
//   1. a rewrite that cannot be read back is a rewrite that did not happen. The
//      guest returns bytes, this code changes them, and the guest returns the
//      bytes AGAIN afterwards so the new value can be parsed out and compared.
//      The probe design in this repository says an operation nobody observed did
//      not occur, and an in-guest one-liner leaves nothing to observe.
//   2. `sed -i "s/x/$PW/"` puts the password in sed's argv, which is
//      world-readable in /proc/<pid>/cmdline for as long as it runs. The rule at
//      the top of this file is about a staged script, but an argv is the same
//      leak in a shorter window.
//   3. these are five real parsers' worth of edge cases (a PHP escape, an XML
//      entity, JSON's quoting, an ini section) and they belong somewhere a test
//      can drive them directly with the actual bytes roles/cc_web renders.
//
// Every reader and every writer returns null for "the value is not where the
// descriptor says it is". Null is never swallowed: it becomes a recorded
// failure and both sides stay on the baked value.

function reQuote(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** The four characters goad-lab-content's esc() escapes, and nothing else. */
function htmlEscape(v) {
  return String(v).replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
/** &amp; LAST, or '&amp;lt;' round-trips to '<' instead of '&lt;'. */
function htmlUnescape(v) {
  return String(v).replace(/&quot;/g, '"').replace(/&gt;/g, '>')
    .replace(/&lt;/g, '<').replace(/&amp;/g, '&');
}

/** roles/cc_web/templates/pivot-credential.j2 escapes exactly &, < and > in the
 *  xml branch — not the apostrophe and not the quote. Matching it exactly is
 *  what makes a read-back compare equal. */
function xmlEscape(v) {
  return String(v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
function xmlUnescape(v) {
  return String(v).replace(/&gt;/g, '>').replace(/&lt;/g, '<').replace(/&amp;/g, '&');
}

/** The php branch of the same template: backslash then apostrophe. */
function phpEscape(v) {
  return String(v).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}
function phpUnescape(v) {
  return String(v).replace(/\\([\s\S])/g, '$1');
}

function escapeFor(mode, v) {
  if (mode === 'html') return htmlEscape(v);
  if (mode === 'xml') return xmlEscape(v);
  return String(v);
}
function unescapeFor(mode, v) {
  if (mode === 'html') return htmlUnescape(v);
  if (mode === 'xml') return xmlUnescape(v);
  return String(v);
}

/** Split without losing whether the file ended in a newline: putting one back
 *  that was not there (or dropping one that was) makes every rewrite a diff
 *  even when the value did not change. */
function splitDoc(text) {
  const s = String(text == null ? '' : text);
  const trailing = s.endsWith('\n');
  return { lines: (trailing ? s.slice(0, -1) : s).split('\n'), trailing };
}
function joinDoc(doc) {
  return doc.lines.join('\n') + (doc.trailing ? '\n' : '');
}

// ── dotenv ──────────────────────────────────────────────────────────────────
// `AD_PASSWORD={{ _pass }}` in the role's template; `KEY=value` in the vuln-app
// env file. Unquoted and to end of line in both, which is what the readers of
// those files expect.
function dotenvFind(doc, plant) {
  const re = new RegExp(`^[\\t ]*${reQuote(plant.key)}[\\t ]*=`);
  for (let i = 0; i < doc.lines.length; i += 1) if (re.test(doc.lines[i])) return i;
  return -1;
}
function dotenvRead(text, plant) {
  const doc = splitDoc(text);
  const i = dotenvFind(doc, plant);
  if (i === -1) return null;
  const line = doc.lines[i];
  return line.slice(line.indexOf('=') + 1).replace(/\r$/, '');
}
function dotenvWrite(text, plant, value) {
  const doc = splitDoc(text);
  const i = dotenvFind(doc, plant);
  if (i !== -1) {
    doc.lines[i] = `${plant.key}=${value}`;
    return joinDoc(doc);
  }
  // `create` is true ONLY for the app env file this module owns outright. A
  // site plant never creates: a key that is not there means the descriptor and
  // the guest disagree, and inventing the key writes a file nothing reads.
  if (!plant.create) return null;
  if (String(text == null ? '' : text) === '') return `${plant.key}=${value}\n`;
  doc.lines.push(`${plant.key}=${value}`);
  doc.trailing = true;
  return joinDoc(doc);
}

// ── ini ─────────────────────────────────────────────────────────────────────
// SECTION-SCOPED, because `password = ...` is not unique in an ini: the role
// writes a [directory] section and an [application] one, and a generator that
// took the first match would rewrite whichever came first today.
function iniFind(doc, plant) {
  const secRe = /^[\t ]*\[([^\]]*)\][\t ]*\r?$/;
  const keyRe = new RegExp(`^([\\t ]*${reQuote(plant.key)}[\\t ]*=[\\t ]*)(.*?)[\\t ]*\r?$`);
  let section = '';
  for (let i = 0; i < doc.lines.length; i += 1) {
    const sm = doc.lines[i].match(secRe);
    if (sm) { section = sm[1].trim(); continue; }
    if (plant.section && section !== plant.section) continue;
    const km = doc.lines[i].match(keyRe);
    if (km) return { index: i, prefix: km[1], value: km[2] };
  }
  return null;
}
function iniRead(text, plant) {
  const hit = iniFind(splitDoc(text), plant);
  return hit ? hit.value : null;
}
function iniWrite(text, plant, value) {
  const doc = splitDoc(text);
  const hit = iniFind(doc, plant);
  if (!hit) return null;
  doc.lines[hit.index] = `${hit.prefix}${value}`;
  return joinDoc(doc);
}

// ── php ─────────────────────────────────────────────────────────────────────
// `    'ad_password' => 'value',` — the value is single-quoted with PHP's own
// two-character escapes, so the whole quoted run has to be matched rather than
// "everything up to the next apostrophe".
function phpFind(doc, plant) {
  const re = new RegExp(
    `^([\\t ]*'${reQuote(plant.key)}'[\\t ]*=>[\\t ]*')((?:\\\\[\\s\\S]|[^'\\\\])*)('[\\s\\S]*)$`);
  for (let i = 0; i < doc.lines.length; i += 1) {
    const m = doc.lines[i].match(re);
    if (m) return { index: i, prefix: m[1], value: m[2], suffix: m[3] };
  }
  return null;
}
function phpRead(text, plant) {
  const hit = phpFind(splitDoc(text), plant);
  return hit ? phpUnescape(hit.value) : null;
}
function phpWrite(text, plant, value) {
  const doc = splitDoc(text);
  const hit = phpFind(doc, plant);
  if (!hit) return null;
  doc.lines[hit.index] = `${hit.prefix}${phpEscape(value)}${hit.suffix}`;
  return joinDoc(doc);
}

// ── json ────────────────────────────────────────────────────────────────────
// Parsed and re-serialised rather than patched with a regex: a JSON file
// half-rewritten by a substitution is a file the app cannot load at all, which
// the student meets as a broken site. indent 4 matches ansible's to_nice_json,
// so a lane's file stays byte-comparable with the baked one apart from the
// value.
function jsonWalk(obj, keys, stopShort) {
  let cur = obj;
  const upto = keys.length - (stopShort ? 1 : 0);
  for (let i = 0; i < upto; i += 1) {
    if (!cur || typeof cur !== 'object' || Array.isArray(cur)
      || !Object.prototype.hasOwnProperty.call(cur, keys[i])) return undefined;
    cur = cur[keys[i]];
  }
  return cur;
}
function jsonRead(text, plant) {
  let obj;
  try { obj = JSON.parse(String(text)); } catch (_) { return null; }
  const v = jsonWalk(obj, plant.keys, false);
  return typeof v === 'string' ? v : null;
}
function jsonWrite(text, plant, value) {
  let obj;
  try { obj = JSON.parse(String(text)); } catch (_) { return null; }
  const parent = jsonWalk(obj, plant.keys, true);
  const last = plant.keys[plant.keys.length - 1];
  if (!parent || typeof parent !== 'object' || Array.isArray(parent)
    || !Object.prototype.hasOwnProperty.call(parent, last)) return null;
  parent[last] = value;
  return JSON.stringify(obj, null, 4) + (String(text).endsWith('\n') ? '\n' : '');
}

// ── xml ─────────────────────────────────────────────────────────────────────
// One element, first occurrence. The role writes exactly one <password> inside
// <directory>; the extra settings it appends are <setting name="...">, so there
// is no second candidate to pick wrongly.
function xmlMatch(text, plant) {
  const re = new RegExp(`(<${reQuote(plant.element)}>)([\\s\\S]*?)(</${reQuote(plant.element)}>)`);
  const m = String(text).match(re);
  return m ? { whole: m[0], open: m[1], value: m[2], close: m[3], index: m.index } : null;
}
function xmlRead(text, plant) {
  const m = xmlMatch(text, plant);
  return m ? xmlUnescape(m.value) : null;
}
function xmlWrite(text, plant, value) {
  const m = xmlMatch(text, plant);
  if (!m) return null;
  const s = String(text);
  return s.slice(0, m.index) + m.open + xmlEscape(value) + m.close
    + s.slice(m.index + m.whole.length);
}

// ── slot ────────────────────────────────────────────────────────────────────
// An anchor, then a run that ends at a terminator, with fixed text either side
// of the value. It covers both places a generated PAGE prints the credential:
// the readonly input on the settings page (empty prefix and suffix, terminator
// '"') and the mirrored staff-directory cell, where the password sits inside a
// sentence and the words either side ride along in the descriptor.
//
// A DUPLICATE ANCHOR IS A REFUSAL, not "take the first one". Two matches mean
// the page changed shape under the descriptor, and picking one at random is the
// same class of silent wrong answer this whole file exists to remove.
function slotBounds(text, plant) {
  const s = String(text);
  const at = s.indexOf(plant.anchor);
  if (at === -1) return null;
  if (s.indexOf(plant.anchor, at + 1) !== -1) return null;
  const start = at + plant.anchor.length;
  const end = s.indexOf(plant.terminator, start);
  if (end === -1) return null;
  return { start, end };
}
function slotRead(text, plant) {
  const b = slotBounds(text, plant);
  if (!b) return null;
  let region = String(text).slice(b.start, b.end);
  if (plant.prefix) {
    if (region.indexOf(plant.prefix) !== 0) return null;
    region = region.slice(plant.prefix.length);
  }
  if (plant.suffix) {
    if (region.length < plant.suffix.length
      || region.slice(region.length - plant.suffix.length) !== plant.suffix) return null;
    region = region.slice(0, region.length - plant.suffix.length);
  }
  return unescapeFor(plant.escape, region);
}
function slotWrite(text, plant, value) {
  const b = slotBounds(text, plant);
  if (!b) return null;
  const s = String(text);
  return s.slice(0, b.start) + plant.prefix + escapeFor(plant.escape, value)
    + plant.suffix + s.slice(b.end);
}

const PLANT_READERS = Object.freeze({
  dotenv: dotenvRead, ini: iniRead, php: phpRead, json: jsonRead, xml: xmlRead, slot: slotRead,
});
const PLANT_WRITERS = Object.freeze({
  dotenv: dotenvWrite, ini: iniWrite, php: phpWrite, json: jsonWrite, xml: xmlWrite, slot: slotWrite,
});

/** The value the guest currently publishes at this plant, or null if it is not
 *  where the descriptor says. */
function readPlantValue(plant, text) {
  const fn = PLANT_READERS[plant && plant.op];
  if (!fn) throw new Error(`no reader for plant operation '${plant && plant.op}'`);
  return fn(text, plant);
}

/** The file's bytes with this plant's value replaced, or null if it is not
 *  where the descriptor says. */
function writePlantValue(plant, text, value) {
  const fn = PLANT_WRITERS[plant && plant.op];
  if (!fn) throw new Error(`no writer for plant operation '${plant && plant.op}'`);
  return fn(text, plant, value);
}

/**
 * Validate one descriptor off the spec, and say WHY when it is not usable.
 *
 * Everything here arrives as JSON written by another process and ends up either
 * inside a single-quoted shell word or inside a RegExp this module builds, so
 * none of it is trusted. A descriptor that does not validate is a recorded
 * warning naming the field — never a target that is quietly dropped, because a
 * dropped target is a page that goes on publishing the baked password.
 *
 * @returns {{plant:object|null, error:string|null}}
 */
function normalizePlant(raw, index) {
  const at = `spec.reseed.pivot.site.plants[${index}]`;
  if (!raw || typeof raw !== 'object') return { plant: null, error: `${at} is not an object` };

  const path = firstString(raw.path);
  if (!path) return { plant: null, error: `${at} names no path` };
  if (!POSIX_PATH_RE.test(path)) {
    return { plant: null, error: `${at} path '${path}' is not a safe absolute POSIX path` };
  }
  const op = firstString(raw.op);
  if (!op || PLANT_OPS.indexOf(op) === -1) {
    return { plant: null, error: `${at} names operation '${op}', and this module implements ${PLANT_OPS.join(', ')}` };
  }

  const plant = {
    kind: firstString(raw.kind) || 'plant',
    path,
    op,
    format: firstString(raw.format) || op,
    create: raw.create === true,
    why: firstString(raw.why) || '',
  };

  const name = (field) => {
    const v = firstString(raw[field]);
    if (!v || !PLANT_NAME_RE.test(v)) return null;
    return v;
  };

  if (op === 'dotenv' || op === 'ini' || op === 'php') {
    plant.key = name('key');
    if (!plant.key) return { plant: null, error: `${at} (${op}) needs a usable 'key'` };
    if (op === 'ini') {
      plant.section = name('section');
      if (!plant.section) return { plant: null, error: `${at} (ini) needs a usable 'section'` };
    }
  } else if (op === 'json') {
    const keys = Array.isArray(raw.keys) ? raw.keys.map((k) => firstString(k)) : null;
    if (!keys || keys.length === 0 || keys.length > 8 || keys.some((k) => !k || !PLANT_NAME_RE.test(k))) {
      return { plant: null, error: `${at} (json) needs 'keys': 1-8 usable object keys` };
    }
    plant.keys = keys;
  } else if (op === 'xml') {
    plant.element = name('element');
    if (!plant.element) return { plant: null, error: `${at} (xml) needs a usable 'element'` };
  } else {
    // slot
    const anchor = typeof raw.anchor === 'string' ? raw.anchor : '';
    const terminator = typeof raw.terminator === 'string' ? raw.terminator : '';
    if (!anchor || !terminator) {
      return { plant: null, error: `${at} (slot) needs a non-empty 'anchor' and 'terminator'` };
    }
    if (anchor.length + terminator.length > 4096) {
      return { plant: null, error: `${at} (slot) anchor and terminator are implausibly long` };
    }
    plant.anchor = anchor;
    plant.terminator = terminator;
    plant.prefix = typeof raw.prefix === 'string' ? raw.prefix : '';
    plant.suffix = typeof raw.suffix === 'string' ? raw.suffix : '';
    const esc = firstString(raw.escape) || 'none';
    if (['none', 'html', 'xml'].indexOf(esc) === -1) {
      return { plant: null, error: `${at} (slot) names escape mode '${esc}'` };
    }
    plant.escape = esc;
  }

  return { plant, error: null };
}

// ============================================================================
// PLAN RESOLUTION — pure, so the whole shape is testable without a cluster
// ============================================================================

function firstString(...vals) {
  for (const v of vals) {
    if (typeof v === 'string' && v.trim()) return v.trim();
  }
  return null;
}

/**
 * Which machine carries the web app, which machine is the DC, and what the
 * pivot credential is called.
 *
 * The web box is resolved from the vuln-app install target first, because that
 * is the field the synthesizer already fills in and the one vuln-app-install.js
 * matches on — the SPEC name, not proxmox_name (which carries the student
 * suffix and matches nothing on every lane at once).
 *
 * @returns {{web:object|null, dc:object|null, dcCandidates:Array, pivot:object|null,
 *            flagPath:string, seedPath:string, appDir:string, container:string,
 *            restartCommand:string|null, seedCommand:string|null, warnings:string[]}}
 */
function resolveReseedPlan({ spec, deployedVMs }) {
  const s = spec || {};
  const reseed = s.reseed || {};
  const vms = (deployedVMs || []).filter(v => v && v.name && v.type !== 'lxc');
  const byName = new Map(vms.map(v => [String(v.name).toLowerCase(), v]));
  const specVms = Array.isArray(s.vms) ? s.vms : [];
  const warnings = [];

  // ── the web box ──────────────────────────────────────────────────────────
  const wantedWeb = firstString(
    reseed.web_vm,
    s.vuln_app_install && s.vuln_app_install.target_vm
  );
  let web = wantedWeb ? byName.get(wantedWeb.toLowerCase()) || null : null;
  if (!web) {
    // Fall back to the spec's own role marking. 'dmz' is the CIAB pivot host
    // (engagement-model PLACEMENTS) and is the usual carrier of the app.
    const roleMatch = specVms.find(v =>
      v && ['web', 'dmz'].includes(String(v.role || '').toLowerCase()));
    if (roleMatch) web = byName.get(String(roleMatch.name).toLowerCase()) || null;
  }
  if (!web && wantedWeb) {
    warnings.push(
      `web box '${wantedWeb}' is not among this lane's machines ` +
      `(${vms.map(v => v.name).join(', ') || 'none'})`
    );
  }

  // ── the domain controllers ───────────────────────────────────────────────
  // Prefer the spec's own role marking; fall back to the resolved GOAD lab
  // definition, which is what actually governs a prebaked lane's roster.
  const dcNames = new Set();
  for (const v of specVms) {
    if (String(v && v.role || '').toLowerCase() === 'dc') dcNames.add(String(v.name).toLowerCase());
  }
  if (dcNames.size === 0 && s.goad && s.goad.enabled) {
    try {
      const { labDef } = goadDeploy.resolveGoadLab(s);
      for (const v of (labDef && labDef.vms) || []) {
        if (String(v.role || '').toLowerCase() === 'dc') dcNames.add(String(v.name).toLowerCase());
      }
    } catch (err) {
      warnings.push(`could not resolve the GOAD lab definition: ${err.message}`);
    }
  }
  const dcCandidates = vms.filter(v => dcNames.has(String(v.name).toLowerCase()));
  // Whichever DC we can talk to is enough — Set-ADAccountPassword replicates.
  // Ordered so the choice is deterministic across lanes and across retries.
  dcCandidates.sort((a, b) => String(a.name).localeCompare(String(b.name)));
  const dc = dcCandidates[0] || null;

  // ── the credentials this lane must NOT rotate ────────────────────────────
  // THE OTHER HALF OF THE RULE. Per-lane uniqueness is for secrets whose only
  // job is to differ between students. A credential whose specific VALUE or
  // PROPERTY carries the exercise — a password drawn from a wordlist so an
  // AS-REP hash cracks, a password that IS the sAMAccountName, a password
  // planted in a share file the student has to find — must survive the reseed
  // untouched, and the plan has to SAY SO. Rotating one of those reports
  // `credential: ok` and leaves a chain nobody can walk, and an operator
  // reading the report has to be able to tell "deliberately not rotated" from
  // "forgotten". The producer decides this from the lab's own declarations
  // (profile-deploy.fixedCredentialsFromIr); this end only has to carry it.
  const fixed = [];
  for (const entry of (Array.isArray(reseed.fixed) ? reseed.fixed : [])) {
    const fsam = firstString(entry && entry.sam);
    if (!fsam) continue;
    fixed.push({
      sam: fsam,
      domain: firstString(entry.domain),
      technique: firstString(entry.technique) || 'declared by the attack chain',
      why: firstString(entry.why) || 'no reason recorded',
    });
  }
  const uniqueness = {
    per_lane: (Array.isArray((reseed.uniqueness || {}).per_lane) ? reseed.uniqueness.per_lane : [])
      .map((v) => firstString(v)).filter(Boolean),
    baked: (Array.isArray((reseed.uniqueness || {}).baked) ? reseed.uniqueness.baked : [])
      .map((v) => firstString(v)).filter(Boolean),
  };

  // ── the credential ───────────────────────────────────────────────────────
  // REQUIRED, not guessed. Resetting the password of an account we invented a
  // name for fails on every lane at once, and resetting the wrong real account
  // breaks the forest. A spec that names none gets the credential phase skipped
  // and says so on the lane row.
  const pivotSpec = reseed.pivot || {};
  const sam = firstString(pivotSpec.sam, pivotSpec.username, pivotSpec.account);
  let domain = firstString(pivotSpec.domain, s.goad && s.goad.domain);
  if (!domain && s.goad && s.goad.enabled) {
    try {
      const { labDef } = goadDeploy.resolveGoadLab(s);
      domain = firstString(labDef && labDef.forestRoot);
    } catch (_) { /* already warned above */ }
  }

  // AN EXPLICIT REFUSAL TO ROTATE, carried from the producer. Absent (the shape
  // every spec written before this had) means rotate, which is what those specs
  // meant; `false` is the only value that stops the phase, and it always
  // arrives with the reason that stopped it.
  let pivotFixed = null;
  if (sam && pivotSpec.rotate === false) {
    pivotFixed = {
      sam,
      domain: domain || null,
      reason: firstString(pivotSpec.fixed_reason)
        || 'the deploy spec marks this credential rotate:false and recorded no reason',
    };
  }

  // WHY A DECLARED PIVOT WAS NOT ROTATED, kept beside the warning that says it.
  // Without this, every rejection below reported the same step text — "spec.
  // reseed.pivot.sam is not declared" — on a lane whose spec DID declare it and
  // whose domain this end refused, which is the "reads like forgotten" failure
  // this module exists to remove. Only ever set when `sam` is declared.
  let pivotDeclined = null;
  const decline = (message) => {
    warnings.push(message);
    if (!pivotDeclined) pivotDeclined = message;
  };

  let pivot = null;
  if (sam && !pivotFixed) {
    if (!AD_SAM_RE.test(sam)) {
      decline(`pivot account '${sam}' is not a usable sAMAccountName — credential reseed skipped`);
    } else if (!domain) {
      decline(`pivot account '${sam}' has no domain (set spec.reseed.pivot.domain) — credential reseed skipped`);
    } else if (!AD_DOMAIN_RE.test(domain)) {
      decline(`pivot domain '${domain}' is not a usable DNS domain — credential reseed skipped`);
    } else if (domain.indexOf('.') === -1) {
      // A NETBIOS SHORT NAME, WHICH IS NOT A DOMAIN EITHER OF THESE CALLS TAKE.
      // Set-ADAccountPassword -Server and PrincipalContext('Domain', …) both
      // want DNS. A short name is accepted by the character class above, gets as
      // far as the DC, and fails there — on every lane in the section at once,
      // after the staged rewrites are already sitting on the web box. The
      // website prints the short name beside the account (site.reseed.domain is
      // `bindNetbios`), so this is the exact field a producer picks up by
      // mistake; spec.reseed.pivot.netbios is where it belongs.
      decline(
        `pivot domain '${domain}' is a single label — a NetBIOS short name, not the DNS domain ` +
        `Set-ADAccountPassword -Server and ValidateCredentials need. It would fail on the DC on ` +
        `every lane at once. Set spec.reseed.pivot.domain to the account's FQDN (its domain in ` +
        `labIR.principals.users) — credential reseed skipped`
      );
    } else {
      pivot = {
        sam,
        domain,
        envPath: firstString(pivotSpec.env_path) || DEFAULT_ENV_PATH,
        envKey:  firstString(pivotSpec.env_key)  || DEFAULT_ENV_KEY,
        sitePlants: [],
        siteUnrotatable: [],
      };
      if (!POSIX_PATH_RE.test(pivot.envPath)) {
        decline(`pivot env path '${pivot.envPath}' is not a safe absolute path — credential reseed skipped`);
        pivot = null;
      } else if (!/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(pivot.envKey)) {
        decline(`pivot env key '${pivot.envKey}' is not a usable env var name — credential reseed skipped`);
        pivot = null;
      }

      // ── where the WEBSITE publishes the same credential ─────────────────
      // The seam. Without this block the reseed rotates AD, writes an env file
      // it created itself, and leaves the site serving the baked password —
      // green on both steps, and a pivot that does not work.
      if (pivot) {
        const siteSpec = (pivotSpec.site && typeof pivotSpec.site === 'object') ? pivotSpec.site : null;
        const rawPlants = siteSpec && Array.isArray(siteSpec.plants) ? siteSpec.plants : null;
        for (const entry of (siteSpec && Array.isArray(siteSpec.unrotatable) ? siteSpec.unrotatable : [])) {
          const where = firstString(entry && entry.where);
          const why = firstString(entry && entry.why);
          if (where) pivot.siteUnrotatable.push({ where, why: why || 'no reason recorded' });
        }
        if (!siteSpec || !rawPlants || rawPlants.length === 0) {
          // NOT A SKIP. A prebaked lane always has the website that carries the
          // credential — installCompanyWebsite runs on every bake that is not
          // explicitly declared AD-only — so the absence of this block means the
          // producer did not emit it, and every lane in the section is about to
          // publish the baked password. Say exactly that, on the lane row.
          warnings.push(
            `spec.reseed.pivot names AD account '${sam}' and declares NO site plants ` +
            `(spec.reseed.pivot.site.plants). The account will be rotated per lane and the company ` +
            `website will go on publishing the BAKED password out of its own config file and off its ` +
            `integration-settings page, so the pivot the exercise is built around will not work and ` +
            `nothing else reports it. The bake emits these: goad-lab-content.generateSiteContent ` +
            `returns them as site.reseed.`
          );
        } else {
          for (let i = 0; i < rawPlants.length; i += 1) {
            const { plant, error } = normalizePlant(rawPlants[i], i);
            if (error) {
              warnings.push(`${error} — that publisher will NOT be rewritten and will keep serving the baked password`);
            } else {
              pivot.sitePlants.push(plant);
            }
          }
        }
      }
    }
  }

  const flagPath = firstString(reseed.flag_path) || DEFAULT_FLAG_PATH;
  const seedPath = firstString(reseed.seed_path) || DEFAULT_SEED_PATH;

  return {
    web,
    dc,
    dcCandidates,
    pivot,
    pivotFixed,
    pivotDeclined,
    fixed,
    uniqueness,
    flagPath: POSIX_PATH_RE.test(flagPath) ? flagPath : DEFAULT_FLAG_PATH,
    seedPath: POSIX_PATH_RE.test(seedPath) ? seedPath : DEFAULT_SEED_PATH,
    appDir: firstString(reseed.app_dir) || DEFAULT_APP_DIR,
    container: firstString(reseed.container) || DEFAULT_CONTAINER,
    restartCommand: firstString(reseed.restart_command),
    seedCommand: firstString(reseed.seed_command),
    warnings,
  };
}

// ============================================================================
// SECRET GENERATION + THE ENCODING THAT MAKES QUOTING A NON-QUESTION
// ============================================================================

/** One CSPRNG character from `alphabet`. */
function pick(alphabet) {
  return alphabet[crypto.randomInt(alphabet.length)];
}

/**
 * A per-lane pivot password: 20 characters, all four Windows complexity classes
 * guaranteed, no quote characters, no ambiguous glyphs.
 *
 * CSPRNG rather than a seeded/derived value on purpose. A derivation keyed on
 * anything the image knows (profile id, difficulty, challenge key) reproduces
 * the exact defect this file exists to fix — every lane from one bake would
 * derive the same string.
 */
function generatePivotPassword() {
  const all = PW_UPPER + PW_LOWER + PW_DIGIT + PW_SYMBOL;
  const chars = [pick(PW_UPPER), pick(PW_LOWER), pick(PW_DIGIT), pick(PW_SYMBOL)];
  while (chars.length < PW_LENGTH) chars.push(pick(all));
  // Fisher-Yates over the CSPRNG, so the guaranteed four are not pinned to the
  // first four positions.
  for (let i = chars.length - 1; i > 0; i--) {
    const j = crypto.randomInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join('');
}

/** Truncated SHA-256. The only representation of a secret that touches the DB. */
function fingerprint(value) {
  return crypto.createHash('sha256').update(String(value), 'utf8').digest('hex').slice(0, 16);
}

/**
 * Encode a secret for transport into a guest.
 *
 * Everything secret this module sends goes through here, so every command it
 * builds interpolates only /^[A-Za-z0-9+/=]+$/ — inert inside a single-quoted
 * PowerShell literal and inside a single-quoted POSIX shell word alike. There
 * is no password this can fail to quote correctly, which is a stronger property
 * than any escaping routine we could write.
 */
function b64(secret) {
  return Buffer.from(String(secret), 'utf8').toString('base64');
}

/** PowerShell expression that turns a base64 blob back into the cleartext. */
function psDecode(encoded) {
  assertB64(encoded);
  return `[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encoded}'))`;
}

function assertB64(encoded) {
  if (typeof encoded !== 'string' || !B64_RE.test(encoded)) {
    throw new Error('refusing to build a command around a value that is not base64 — a raw secret reached a command builder');
  }
  return encoded;
}

/**
 * The mechanical form of the security rule, checked at dispatch time.
 *
 * Every command this module sends is passed through here with the secrets it is
 * allowed to be ABOUT. If a cleartext secret is present in the command text,
 * something bypassed b64() and the command is refused rather than sent — a
 * cleartext password in an argv the guest agent logs is the same leak as one in
 * C:\Windows\Temp, only harder to notice.
 */
function assertNoCleartextSecret(command, secrets) {
  const text = String(command || '');
  for (const s of (secrets || [])) {
    if (!s) continue;
    if (text.includes(String(s))) {
      throw new Error('refusing to dispatch a guest command containing a cleartext secret');
    }
  }
  return text;
}

// ============================================================================
// GUEST EXEC — argv / shell only. No staged file, no tee'd log, nothing left.
// ============================================================================

function defaultDeps(overrides) {
  return Object.assign({
    api: proxmoxAPI,
    agentExecArgv,
    agentShellExec,
    pollExecStatus,
    waitForGuestAgent,
    waitForAgentExecReady,
    ensureLaneFlags,
    cybercoreQuery,
    now: () => Date.now(),
    sleep: (ms) => new Promise(r => setTimeout(r, ms)),
  }, overrides || {});
}

/** Run one PowerShell command in a Windows guest; throw unless it exits 0. */
async function winExec(deps, node, vmId, psCommand, secrets = [], timeoutMs = WIN_CMD_TIMEOUT_MS) {
  assertNoCleartextSecret(psCommand, secrets);
  const { pid } = await deps.agentExecArgv(
    node, vmId,
    [WIN_PS, '-NoProfile', '-NonInteractive', '-Command', psCommand],
    deps.api
  );
  const status = await deps.pollExecStatus(node, vmId, pid, timeoutMs);
  if (!status || !status.exited) throw new Error('guest command timed out');
  if (status.exitcode !== 0) {
    throw new Error(
      `guest command exited ${status.exitcode}: ` +
      `${String(status.stderr || status.stdout || '').substring(0, 300)}`
    );
  }
  return status;
}

/** Run one /bin/sh command in a Linux guest; throw unless it exits 0. */
async function shExec(deps, node, vmId, shellCommand, secrets = [], timeoutMs = SH_CMD_TIMEOUT_MS) {
  assertNoCleartextSecret(shellCommand, secrets);
  const { pid } = await deps.agentShellExec(node, vmId, shellCommand);
  const status = await deps.pollExecStatus(node, vmId, pid, timeoutMs);
  if (!status || !status.exited) throw new Error('guest command timed out');
  if (status.exitcode !== 0) {
    throw new Error(
      `guest command exited ${status.exitcode}: ` +
      `${String(status.stderr || status.stdout || '').substring(0, 300)}`
    );
  }
  return status;
}

/**
 * Read one publisher's bytes out of a Linux guest.
 *
 * Returns null for "there is no such file", which is an ANSWER — the descriptor
 * and the guest disagree and somebody has to be told — rather than an error to
 * be retried. Anything else that goes wrong still throws.
 *
 * @returns {Promise<string|null>} the file's decoded contents, or null
 */
async function readPlantFile(deps, node, vmId, plantPath) {
  const status = await shExec(deps, node, vmId, buildReadPlantCommand({ path: plantPath }));
  const raw = String((status && status.stdout) || '');
  if (raw.indexOf(PLANT_MISSING) !== -1) return null;
  const b64text = raw.replace(/\s+/g, '');
  if (!b64text) return null;
  if (!B64_RE.test(b64text)) {
    throw new Error(`reading ${plantPath} returned something that is not base64 (${b64text.length} chars)`);
  }
  const buf = Buffer.from(b64text, 'base64');
  if (buf.length > PLANT_MAX_BYTES) {
    throw new Error(`${plantPath} is ${buf.length} bytes, past the ${PLANT_MAX_BYTES}-byte limit this step will handle`);
  }
  return buf.toString('utf8');
}

/**
 * Wait until the DC's guest agent will actually run a command.
 *
 * This is a HARD DEPENDENCY of the credential reseed, not a nicety. A prebaked
 * lane has no controller, so this agent is the only way to change a password in
 * the directory; if it never comes up there is no fallback and the exercise's
 * pivot cannot exist. Warning once and carrying on is how every lane in a batch
 * silently keeps the baked password.
 *
 * Two probes, because they fail differently: guest-ping answers well before the
 * exec RPC will accept anything on a freshly-cloned Windows Server, so a
 * ping-only wait returns "ready" and the very next call fails.
 *
 * @returns {Promise<{ok:boolean, rounds:number, error:(string|null)}>}
 */
async function waitForDcAgent({ deps, node, vmId, timeoutMs = DC_AGENT_TIMEOUT_MS, logTag = LOG }) {
  const started = deps.now();
  let rounds = 0;
  let lastError = null;

  while (deps.now() - started < timeoutMs) {
    rounds++;
    try {
      const remaining = timeoutMs - (deps.now() - started);
      const up = await deps.waitForGuestAgent(node, vmId, Math.max(1, Math.min(60000, remaining)));
      if (!up) throw new Error('guest-ping never answered');
      // Ping is not exec. Prove the channel with a real command before we
      // decide the DC is usable.
      await winExec(deps, node, vmId, 'exit 0', [], 60000);
      console.log(`${logTag} DC guest agent ready on vm=${vmId} after ${rounds} round(s)`);
      return { ok: true, rounds, error: null };
    } catch (err) {
      lastError = String((err && err.message) || err);
      if (deps.now() - started >= timeoutMs) break;
      const waitMs = Math.min(30000, 5000 + rounds * 5000);
      console.warn(
        `${logTag} DC guest agent not ready on vm=${vmId} (round ${rounds}): ` +
        `${lastError.substring(0, 160)} — retrying in ${waitMs / 1000}s`
      );
      await deps.sleep(waitMs);
    }
  }

  return {
    ok: false,
    rounds,
    error: `DC guest agent never became usable within ${Math.round(timeoutMs / 60000)}m` +
           (lastError ? ` (last error: ${lastError.substring(0, 200)})` : ''),
  };
}

// ============================================================================
// COMMAND BUILDERS — pure, so the tests can read what will actually be sent
// ============================================================================

/**
 * Wipe the golden image's SSH host keys and machine-id and mint new ones.
 *
 * Cloned from one image these are identical across the whole cohort: every
 * lane presents the same host fingerprint, so an SSH client that cached one
 * lane accepts every other lane silently, and anything keyed on machine-id
 * (systemd journal ids, some agents' node identity) collides section-wide.
 * No secret here — but it goes down the same argv/shell channel as everything
 * else, because there is no reason to keep a second one open.
 */
function buildHostIdentityCommand() {
  return [
    'set -e',
    'rm -f /etc/ssh/ssh_host_*',
    // ssh-keygen -A is present on every distro we bake; dpkg-reconfigure is the
    // Debian-native path and regenerates the same set. Either is fine, so try
    // the native one first and fall back rather than failing the step.
    'if command -v dpkg-reconfigure >/dev/null 2>&1; then',
    '  DEBIAN_FRONTEND=noninteractive dpkg-reconfigure openssh-server >/dev/null 2>&1 || ssh-keygen -A',
    'else',
    '  ssh-keygen -A',
    'fi',
    // machine-id must be EMPTIED rather than deleted on some images: systemd
    // treats a missing file as "first boot" and a zero-length one as "generate
    // me one", and only the latter is safe to do on a running system.
    ': > /etc/machine-id',
    'rm -f /var/lib/dbus/machine-id',
    'systemd-machine-id-setup >/dev/null 2>&1 || true',
    'if [ -s /etc/machine-id ]; then cp /etc/machine-id /var/lib/dbus/machine-id; fi',
    'systemctl restart ssh >/dev/null 2>&1 || systemctl restart sshd >/dev/null 2>&1 || true',
    'exit 0',
  ].join('\n');
}

/**
 * Write the lane's flag where the app exposes it.
 *
 * 0644 on purpose: this one is LOOT, the thing the app is supposed to hand over
 * when the student exploits it. The privileged pair (user.txt / root.txt) is
 * planted separately by flag-manager, which sets its own permissions — root.txt
 * at 0600 root:root, because THAT one is the escalation.
 */
function buildFlagCommand({ flagPath, container, encodedFlag }) {
  assertB64(encodedFlag);
  const dir = flagPath.replace(/\/[^/]+$/, '') || '/';
  return [
    'set -e',
    `mkdir -p '${dir}'`,
    `printf %s '${encodedFlag}' | base64 -d > '${flagPath}'`,
    `chmod 644 '${flagPath}'`,
    // A docker-mode app reads the copy INSIDE the container. Best-effort: a
    // bind-mounted app already sees the host file, and a stopped container is
    // the vuln-app installer's problem, not this step's.
    'if command -v docker >/dev/null 2>&1; then',
    `  docker cp '${flagPath}' '${container}':'${flagPath}' >/dev/null 2>&1 || true`,
    'fi',
    'exit 0',
  ].join('\n');
}

/**
 * Lane-unique seed values for the records the site displays.
 *
 * Two students comparing "what is the order number on the overdue invoice"
 * must not get the same answer, or the whole exercise degrades into one person
 * solving it and the rest transcribing. These are NOT secrets — they are on
 * every page of the app — so they are written in cleartext, but through the
 * same channel as everything else.
 *
 * The heredoc delimiter is quoted ('CIAB_LANE_SEED'), so the shell performs no
 * expansion on the body: a value containing $ or a backtick is data.
 */
function buildSeedCommand({ seedPath, seed, seedCommand }) {
  const dir = seedPath.replace(/\/[^/]+$/, '') || '/';
  const lines = [
    'set -e',
    `mkdir -p '${dir}'`,
    `cat > '${seedPath}' <<'CIAB_LANE_SEED'`,
    `LANE_SEED=${seed.lane_seed}`,
    `LANE_TOKEN=${seed.lane_token}`,
    `ORDER_NUMBER_BASE=${seed.order_number_base}`,
    `PATIENT_ID_BASE=${seed.patient_id_base}`,
    `INVOICE_BASE=${seed.invoice_base}`,
    'CIAB_LANE_SEED',
    `chmod 644 '${seedPath}'`,
  ];
  if (seedCommand) lines.push(seedCommand);
  lines.push('exit 0');
  return lines.join('\n');
}

/**
 * READ one publisher's current bytes back out of the guest.
 *
 * A SENTINEL FOR "not there" RATHER THAN A NON-ZERO EXIT. The whole point of
 * this step is to tell three outcomes apart — the file is there and says what
 * the descriptor claims, the file is there and does not, the file is gone — and
 * only the first is allowed to proceed. Collapsing the last two into "the
 * command failed" is how a moved plant becomes a transport error somebody
 * retries.
 *
 * base64 rather than cat: the file holds a password, and `cat` would put the
 * cleartext into the guest-agent's captured stdout, which is the same exposure
 * as a log. It also survives a config file with a stray CR or a byte that is
 * not UTF-8.
 */
function buildReadPlantCommand({ path }) {
  if (!POSIX_PATH_RE.test(path)) throw new Error(`unsafe plant path: ${path}`);
  return `if [ -f '${path}' ]; then base64 < '${path}'; else printf %s '${PLANT_MISSING}'; fi`;
}

/**
 * STAGE a rewritten publisher beside itself, without publishing it.
 *
 * Half of "all sides or none". Nothing reads `<path>.ccreseed`, so a lane that
 * dies between here and the commit is untouched everywhere: every publisher
 * still carries the baked value and AD still honours it.
 *
 * umask 077 + chmod 600, so the staged copy is root-only even when it is
 * staged INSIDE THE DOCROOT — which it is for the site's own config, because
 * cc_web plants that file in the web root on purpose. A 0644 staging file there
 * would be a second downloadable copy of the credential for as long as it
 * existed.
 *
 * @returns {string[]} one command per chunk; the last one materialises the file
 */
function buildStagePlantCommands({ path, encodedContent, chunkSize = PLANT_CHUNK }) {
  if (!POSIX_PATH_RE.test(path)) throw new Error(`unsafe plant path: ${path}`);
  assertB64(encodedContent);
  const stage = `${path}${PLANT_STAGE_SUFFIX}`;
  if (encodedContent.length <= chunkSize) {
    return [[
      'set -e',
      'umask 077',
      `printf %s '${encodedContent}' | base64 -d > '${stage}'`,
      `chmod 600 '${stage}'`,
      'exit 0',
    ].join('\n')];
  }
  const out = [];
  for (let i = 0; i < encodedContent.length; i += chunkSize) {
    out.push([
      'set -e',
      'umask 077',
      `printf %s '${encodedContent.slice(i, i + chunkSize)}' ${i === 0 ? '>' : '>>'} '${stage}.b64'`,
      'exit 0',
    ].join('\n'));
  }
  out.push([
    'set -e',
    'umask 077',
    `base64 -d < '${stage}.b64' > '${stage}'`,
    `rm -f '${stage}.b64'`,
    `chmod 600 '${stage}'`,
    'exit 0',
  ].join('\n'));
  return out;
}

/**
 * PUBLISH one staged rewrite. Runs only after AD accepted the same value.
 *
 * A REDIRECT INTO THE EXISTING FILE, NOT A RENAME. cc_web installs the pivot
 * config as 0640 root:www-data and the pages as world-readable; a `mv` would
 * replace those with the staging file's 0600 root:root and apache would stop
 * being able to read its own config — a correctly rewritten credential that
 * nothing can serve. Redirecting keeps the destination inode, its owner and its
 * mode, and changes only the bytes.
 */
function buildCommitPlantCommand({ path }) {
  if (!POSIX_PATH_RE.test(path)) throw new Error(`unsafe plant path: ${path}`);
  const stage = `${path}${PLANT_STAGE_SUFFIX}`;
  return [
    'set -e',
    `[ -f '${stage}' ] || { echo 'staged rewrite missing' >&2; exit 1; }`,
    `cat '${stage}' > '${path}'`,
    `rm -f '${stage}'`,
    'exit 0',
  ].join('\n');
}

/** Drop a staged rewrite. Every publisher stays on the baked value. */
function buildDiscardPlantCommand({ path }) {
  if (!POSIX_PATH_RE.test(path)) throw new Error(`unsafe plant path: ${path}`);
  const stage = `${path}${PLANT_STAGE_SUFFIX}`;
  return `rm -f '${stage}' '${stage}.b64'; exit 0`;
}

/**
 * Make the app re-read what was just published.
 *
 * Best-effort by design and last in the sequence: the files on disk are the
 * record, and a container that did not restart is a stale process rather than a
 * disagreement between the website and the directory.
 */
function buildRestartCommand({ container, restartCommand }) {
  const lines = ['set -e'];
  if (restartCommand) {
    lines.push(restartCommand);
  } else {
    lines.push('if command -v docker >/dev/null 2>&1; then');
    lines.push(`  docker restart '${container}' >/dev/null 2>&1 || true`);
    lines.push('fi');
  }
  lines.push('exit 0');
  return lines.join('\n');
}

/**
 * Reset the AD side of the credential from the DC's OWN guest agent.
 *
 * There is no controller on a prebaked lane, so there is no Ansible to do this
 * with — this command IS the mechanism. `-Reset` rather than
 * `-OldPassword/-NewPassword` because we do not know the baked value and are
 * not trying to: the point is that whatever it was stops being true everywhere
 * at once.
 *
 * ChangePasswordAtLogon $false and PasswordNeverExpires $true are not
 * convenience. A service account flagged "must change at next logon" cannot
 * authenticate at all over SMB/LDAP, so the student would find a correct
 * credential that fails — the exact dead end this whole step exists to avoid.
 */
function buildAdResetCommand({ sam, domain, encodedPassword }) {
  if (!AD_SAM_RE.test(sam)) throw new Error(`unsafe AD account name: ${sam}`);
  if (!AD_DOMAIN_RE.test(domain)) throw new Error(`unsafe AD domain: ${domain}`);
  return [
    "$ErrorActionPreference='Stop';",
    'Import-Module ActiveDirectory -ErrorAction Stop;',
    `$p = ${psDecode(encodedPassword)};`,
    '$s = ConvertTo-SecureString -AsPlainText -Force -String $p;',
    `Set-ADAccountPassword -Identity '${sam}' -Reset -NewPassword $s -Server '${domain}' -ErrorAction Stop;`,
    `Set-ADUser -Identity '${sam}' -ChangePasswordAtLogon $false -PasswordNeverExpires $true ` +
      `-Enabled $true -Server '${domain}' -ErrorAction Stop;`,
    'exit 0',
  ].join(' ');
}

/**
 * Prove the reseeded credential actually authenticates.
 *
 * "Set-ADAccountPassword exited 0" is not evidence a student can log in: the
 * account can be locked out, disabled, flagged for a password change, or in a
 * domain whose policy rejected the value in a way the cmdlet reported as
 * success on one DC and never replicated. ValidateCredentials does a real bind,
 * which is the same thing the student's tooling will do.
 *
 * Exit 3 (not 1) for "authenticated: false", so a genuine authentication
 * failure is distinguishable from PowerShell blowing up before it got there.
 */
function buildVerifyCommand({ sam, domain, encodedPassword }) {
  if (!AD_SAM_RE.test(sam)) throw new Error(`unsafe AD account name: ${sam}`);
  if (!AD_DOMAIN_RE.test(domain)) throw new Error(`unsafe AD domain: ${domain}`);
  return [
    "$ErrorActionPreference='Stop';",
    'Add-Type -AssemblyName System.DirectoryServices.AccountManagement;',
    `$p = ${psDecode(encodedPassword)};`,
    `$ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('Domain','${domain}');`,
    `if ($ctx.ValidateCredentials('${sam}', $p)) { exit 0 } else { exit 3 }`,
  ].join(' ');
}

/**
 * Lane-unique record identifiers.
 *
 * CSPRNG, and wide enough that two lanes colliding is not a thing that happens
 * in a section: order numbers land in a 9,000,000-wide band, patient ids in a
 * 900,000-wide one.
 */
function generateSeedValues() {
  return {
    lane_seed:         crypto.randomInt(1, 2147483647),
    lane_token:        crypto.randomBytes(4).toString('hex'),
    order_number_base: 1000000 + crypto.randomInt(9000000),
    patient_id_base:   100000  + crypto.randomInt(900000),
    invoice_base:      10000   + crypto.randomInt(90000),
  };
}

// ============================================================================
// THE FLAG — reuse the existing per-lane system, do not invent a fourth one
// ============================================================================

/**
 * The value the app should hand over, taken from cybercore_lane_flag.
 *
 * WHY THE WEB BOX'S `user` FLAG RATHER THAN A NEW flag_type. Adding a third
 * type would change the denominator on every student board at once:
 * flag-manager.buildStudentBoard indexes `machine[r.flag_type]` and counts
 * every row into `total`, so a 'pivot' or 'app' type would appear as an
 * uncapturable slot on machines that have none. Reusing 'user' means the string
 * the app exposes IS the string the deployer plants as user.txt on that same
 * box a moment later — one capture per machine, verifySubmission already scopes
 * it to the submitter's own lane, and the instructor dashboard already shows it.
 *
 * ORDERING IS LOAD-BEARING AND ALREADY CORRECT. ensureLaneFlags mints the row
 * here, during postDeploy; challenge-lane-deployer plants flags in step 6,
 * AFTER this hook, and its ON CONFLICT re-assigns the column to itself so it
 * re-reads the SAME value rather than rotating it. Calling it here cannot
 * desync disk from database, and planting last still means nothing clobbers the
 * files.
 */
async function resolveAppFlag({ deps, laneId, userId, webVmName }) {
  const flags = await deps.ensureLaneFlags({
    laneId, userId, vms: [{ name: webVmName }],
  });
  const userFlag = (flags || []).find(f => f.flagType === 'user');
  if (!userFlag || !userFlag.flagValue) {
    throw new Error(`no user flag was minted for ${webVmName}`);
  }
  return userFlag.flagValue;
}

// ============================================================================
// RECORDING
// ============================================================================

/**
 * Merge the reseed outcome into the lane row's config.
 *
 * A MERGE (`config || $2`), never a replace: challenge-lane-deployer builds the
 * lane's active config from the batch-wide laneConfig object and writes it
 * whole, so anything this clobbered would be a field the deployer owns.
 *
 * NOTHING SECRET GOES IN HERE. `pivot_fingerprint` is a truncated SHA-256 of
 * the password, which is what lets an instructor confirm the web box and AD
 * carry the same value without the value existing in the database. Lane config
 * is read by student-facing paths (workstation_user / workstation_pass are
 * served to the lane's owner), so the password itself would be the answer key.
 */
async function recordReseedOnLane(laneId, record, deps = {}) {
  const d = defaultDeps(deps);
  await d.cybercoreQuery(
    `UPDATE cybercore_lane
        SET config = COALESCE(config, '{}'::jsonb) || $2::jsonb,
            updated_at = NOW()
      WHERE lane_id = $1`,
    [laneId, JSON.stringify({ reseed: record })]
  );
  return record;
}

// ============================================================================
// ENTRY POINT
// ============================================================================

/**
 * Reseed one lane's per-student values after the clones are up.
 *
 * NEVER THROWS. Matches (and sharpens) the postDeploy contract in
 * challenge-lane-deployer: a hook throw is recorded as config.post_deploy_error
 * and the lane is not failed. A lane with a stale password is recoverable by
 * re-running this; a lane torn down because a DC booted slowly is not.
 *
 * @param {object}   a
 * @param {string}   a.laneId
 * @param {string}   a.userId          owning student, for cybercore_lane_flag
 * @param {object}   a.spec            challenge spec
 * @param {Array}    a.deployedVMs     [{vm_id, name, proxmox_name, type, node}]
 * @param {string}   [a.goadSubnetBase] the INTERNAL base the lane was built on
 * @param {boolean}  [a.recordOnLane=true]
 * @param {object}   [a.deps]          injected for tests
 * @returns {Promise<object>} the record written under config.reseed
 */
async function reseedLane({
  laneId, userId, spec, deployedVMs,
  goadSubnetBase = null,
  logTag = LOG,
  recordOnLane = true,
  deps = {},
}) {
  const d = defaultDeps(deps);
  const record = {
    status: 'reseeded',
    at: new Date().toISOString(),
    steps: {},
    warnings: [],
    verified: false,
    error: null,
  };

  const fail = (step, err) => {
    const msg = String((err && err.message) || err);
    record.steps[step] = `failed: ${msg}`;
    record.status = 'failed';
    record.error = record.error || `${step}: ${msg}`;
    console.error(`${logTag} Lane ${laneId}: ${step} failed — ${msg}`);
  };

  let plan = null;
  let password = null;
  let encodedPassword = null;

  try {
    // ── 0. the assertion that is allowed to stop everything ────────────────
    const golden = assertGoldenSubnet(spec, { goadSubnetBase });
    record.steps.fixed_subnet = golden ? `ok (${golden.base})` : 'n/a (not a pre-baked AD lane)';

    plan = resolveReseedPlan({ spec, deployedVMs });
    record.warnings = plan.warnings.slice();
    record.web_vm = plan.web ? plan.web.name : null;
    record.dc_vm  = plan.dc  ? plan.dc.name  : null;

    // WHAT THIS LANE DELIBERATELY DOES NOT ROTATE, AND WHERE UNIQUENESS COMES
    // FROM INSTEAD. On the record before anything else runs, because it is true
    // whatever happens below — including on a lane that fails at step 1. An
    // instructor reading `credential: ok` and an instructor reading nothing at
    // all must both be able to see which credentials are identical across the
    // section on purpose, and why.
    if (plan.fixed.length > 0) record.fixed_credentials = plan.fixed;
    if (plan.uniqueness.per_lane.length > 0 || plan.uniqueness.baked.length > 0) {
      record.uniqueness = plan.uniqueness;
    }

    if (!plan.web) {
      // Nothing to reseed ON. Everything below writes to the web box, so say so
      // once and stop rather than reporting four separate skips.
      record.status = 'skipped';
      record.steps.web = 'skipped: no web box on this lane';
      if (recordOnLane) await recordReseedOnLane(laneId, record, d).catch(() => {});
      return record;
    }

    const web = plan.web;

    // The exec channel 596s for a while after ping starts answering on a fresh
    // clone; probe it for real before the first command, exactly as
    // flag-manager does for its Linux targets.
    const webUp = await d.waitForGuestAgent(web.node, web.vm_id, 300000);
    if (!webUp) throw new Error(`web box ${web.name}: guest agent never came up (5m)`);
    const execUp = await d.waitForAgentExecReady(web.node, web.vm_id, `${logTag}[${web.name}]`, 180000);
    if (!execUp) throw new Error(`web box ${web.name}: guest exec channel never became ready (3m)`);

    // ── 1. host identity ───────────────────────────────────────────────────
    try {
      await shExec(d, web.node, web.vm_id, buildHostIdentityCommand());
      record.steps.host_identity = 'ok';
    } catch (err) { fail('host_identity', err); }

    // ── 2. the flag ────────────────────────────────────────────────────────
    let flagValue = null;
    try {
      flagValue = await resolveAppFlag({ deps: d, laneId, userId, webVmName: web.name });
      await shExec(
        d, web.node, web.vm_id,
        buildFlagCommand({
          flagPath: plan.flagPath,
          container: plan.container,
          encodedFlag: b64(flagValue),
        }),
        [flagValue]
      );
      record.steps.flag = 'ok';
      record.flag_source = 'cybercore_lane_flag';
      record.flag_path = plan.flagPath;
    } catch (err) { fail('flag', err); }

    // ── 3. lane-unique seeded data ─────────────────────────────────────────
    try {
      const seed = generateSeedValues();
      await shExec(
        d, web.node, web.vm_id,
        buildSeedCommand({ seedPath: plan.seedPath, seed, seedCommand: plan.seedCommand })
      );
      record.steps.seed_data = 'ok';
      // Not secret — these are printed on every page of the site — and an
      // instructor needs them to answer "which order is this student's".
      record.seed = seed;
    } catch (err) { fail('seed_data', err); }

    // ── 4. the pivot credential, both sides or neither ─────────────────────
    if (plan.pivotFixed) {
      // NOT A SKIP AND NOT A FAILURE — A DECISION, RECORDED IN WORDS. The
      // password's own value is what the exercise is about (a wordlist value an
      // AS-REP hash has to crack to, a password that IS the account name, a
      // string planted in a share file the student must find), so rotating it
      // would report success and delete the chain. Everything else on this lane
      // is still per-student; `uniqueness` above says exactly what.
      record.steps.credential =
        `not rotated (deliberate): ${plan.pivotFixed.reason}`;
      record.steps.verify = 'skipped: nothing was rotated to verify';
      record.credential_state = 'deliberately_fixed';
      record.pivot_user = plan.pivotFixed.domain
        ? `${plan.pivotFixed.domain}\\${plan.pivotFixed.sam}`
        : plan.pivotFixed.sam;
      record.warnings.push(
        `${record.pivot_user} is NOT rotated per lane, on purpose: ${plan.pivotFixed.reason}. ` +
        `Every lane in this section holds the same value for it — per-lane uniqueness for this ` +
        `engagement comes from the flag and the seeded data instead (see reseed.uniqueness).`
      );
    } else if (!plan.pivot) {
      // TWO DIFFERENT SENTENCES, because they call for two different actions.
      // "Nobody declared one" is a spec that never named an account. A DECLINE
      // is a spec that named one this end refused — a NetBIOS short name is the
      // live case — and reporting that as "not declared" sends an operator
      // looking for a missing field that is sitting right there.
      record.steps.credential = plan.pivotDeclined
        ? `skipped: ${plan.pivotDeclined}`
        : 'skipped: spec.reseed.pivot.sam is not declared';
      record.steps.verify = 'skipped';
    } else if (!plan.dc) {
      // Loud, because a spec that names an AD account and a lane with no DC on
      // it is a misconfiguration, not a variation.
      fail('credential', new Error(
        `spec.reseed.pivot names AD account '${plan.pivot.sam}' but this lane has no domain ` +
        `controller among its machines (${(deployedVMs || []).map(v => v.name).join(', ') || 'none'})`
      ));
      record.steps.verify = 'skipped';
    } else {
      const { sam, domain, envPath, envKey } = plan.pivot;
      record.pivot_user = `${domain}\\${sam}`;
      password = generatePivotPassword();
      encodedPassword = b64(password);

      // EVERY PLACE THIS LANE PUBLISHES THE CREDENTIAL, IN ONE LIST.
      //
      // The app env file this module owns, plus every publisher the bake
      // declared: the site's own config (an ini, a PHP include, an XML, a JSON
      // or a dotenv, whichever this client's site was authored with) and the
      // pages that print the value. They are rotated ALL OR NONE, for the same
      // reason the AD side and the web side were: a lane where one of them
      // still spells the baked password is a dead end the student cannot
      // distinguish from their own mistake.
      const targets = [{
        kind: 'app_env',
        path: envPath,
        op: 'dotenv',
        key: envKey,
        format: 'dotenv',
        // The one target this module is allowed to CREATE: it is the app's own
        // env file and nothing else writes it. Every site plant is create:false
        // — a missing one means the descriptor is wrong, and writing a new file
        // nothing reads is the silent success this whole change removes.
        create: true,
        why: 'the vuln-app environment file this reseed owns',
      }].concat(plan.pivot.sitePlants);

      for (const entry of plan.pivot.siteUnrotatable) {
        record.warnings.push(
          `${entry.where} publishes this credential and cannot be rewritten mechanically: ${entry.why}`
        );
      }

      const stagedPaths = [];
      // Which side of the point of no return a failure lands on. Everything
      // before the AD write is fully reversible — drop the staged files and the
      // lane is exactly as it was. After it, the directory holds a value only
      // this run knew, so there is nothing to roll back TO, and the honest
      // outcome is a loud, specific failure rather than a rollback that cannot
      // be one.
      let adRotated = false;
      const discardStaged = async () => {
        for (const p of stagedPaths.splice(0)) {
          await shExec(d, web.node, web.vm_id, buildDiscardPlantCommand({ path: p }))
            .catch(rollbackErr => {
              record.warnings.push(
                `staged rewrite at ${p}${PLANT_STAGE_SUFFIX} could not be removed: ${rollbackErr.message}`
              );
            });
        }
      };

      try {
        // 4a. READ every publisher and compute its new bytes. Nothing is
        //     written yet, so a descriptor that does not match what is on the
        //     box stops here with AD untouched.
        const rewrites = [];
        for (const target of targets) {
          const current = await readPlantFile(d, web.node, web.vm_id, target.path);
          if (current === null) {
            if (!target.create) {
              throw new Error(
                `${target.kind} at ${target.path} is not on this lane. The bake recorded it as a place ` +
                `the website publishes the pivot credential, so either the golden image no longer ` +
                `matches the spec or the path moved. Rotating the account now would leave whatever ` +
                `DOES serve that credential spelling the baked value.`
              );
            }
            record.warnings.push(
              `${target.path} did not exist and was created by the reseed — nothing on this lane was ` +
              `reading it before, so confirm the app really loads it`
            );
          }
          const before = current === null ? '' : current;
          const next = writePlantValue(target, before, password);
          if (next === null) {
            throw new Error(
              `${target.kind} at ${target.path} does not carry the credential where the bake said it ` +
              `does (${target.op}${target.key ? ` key '${target.key}'` : ''}` +
              `${target.section ? ` in section '${target.section}'` : ''}` +
              `${target.element ? ` element '${target.element}'` : ''}` +
              `${target.anchor ? ` anchor ${JSON.stringify(String(target.anchor).slice(0, 48))}` : ''}). ` +
              `Nothing was rewritten and the account was NOT rotated, so every publisher still agrees ` +
              `with Active Directory.`
            );
          }
          // The mechanical form of the rule, one layer up from
          // assertNoCleartextSecret: if the rewrite did not actually take, the
          // bytes we are about to ship are the old ones.
          if (readPlantValue(target, next) !== password) {
            throw new Error(
              `the rewrite of ${target.path} did not change the value it was supposed to change`
            );
          }
          rewrites.push({ target, content: next });
        }

        // 4b. STAGE each of them beside itself. Still nothing published.
        for (const { target, content } of rewrites) {
          const commands = buildStagePlantCommands({
            path: target.path,
            encodedContent: b64(content),
          });
          for (const command of commands) {
            await shExec(d, web.node, web.vm_id, command, [password]);
          }
          stagedPaths.push(target.path);
        }

        // 4c. the DC's agent is the only way to change the directory on a
        //     prebaked lane. Wait for it properly — see waitForDcAgent.
        const agent = await waitForDcAgent({
          deps: d, node: plan.dc.node, vmId: plan.dc.vm_id, logTag,
        });
        record.steps.dc_agent = agent.ok
          ? `ok (${agent.rounds} round(s))`
          : `failed: ${agent.error}`;
        if (!agent.ok) throw new Error(agent.error);

        // 4d. AD side. THE POINT OF NO RETURN: -Reset does not need the old
        //     value and we never knew it, so from here there is nothing to put
        //     back.
        await winExec(
          d, plan.dc.node, plan.dc.vm_id,
          buildAdResetCommand({ sam, domain, encodedPassword }),
          [password]
        );
        adRotated = true;

        // 4e. publish. Only now does the whole lane agree.
        for (const { target } of rewrites) {
          await shExec(d, web.node, web.vm_id, buildCommitPlantCommand({ path: target.path }));
        }
        stagedPaths.length = 0;

        // 4f. READ IT BACK. "We wrote the file" is not evidence the file says
        //     what we meant — a commit that half-ran, a role that rewrote the
        //     config from a template a moment later, a bind mount pointing
        //     somewhere else. The published value is parsed out of the bytes
        //     the guest returns and compared to the one AD now honours.
        const published = [];
        for (const { target } of rewrites) {
          const after = await readPlantFile(d, web.node, web.vm_id, target.path);
          if (after === null) {
            throw new Error(`${target.path} is not there after the reseed wrote it`);
          }
          const seen = readPlantValue(target, after);
          if (seen !== password) {
            throw new Error(
              `${target.path} still publishes a DIFFERENT credential than the one Active Directory ` +
              `now honours (read back ${seen === null ? 'nothing the descriptor could find'
                : `a ${String(seen).length}-character value`}). The student would read this page and ` +
              `be told the password is wrong.`
            );
          }
          published.push({ kind: target.kind, path: target.path, format: target.format });
        }
        record.steps.publish_verify = `ok (${published.length} publisher(s) read back)`;
        record.published = published;
        record.site_publishers = published.filter((p) => p.kind !== 'app_env').length;

        // 4g. let the app pick the new value up. Best-effort, last, and never
        //     the reason a correct rotation is reported as failed.
        await shExec(
          d, web.node, web.vm_id,
          buildRestartCommand({ container: plan.container, restartCommand: plan.restartCommand })
        ).catch(restartErr => {
          record.warnings.push(`the app was not restarted after the rewrite: ${restartErr.message}`);
        });

        record.steps.credential = 'ok';
        record.pivot_fingerprint = fingerprint(password);
        record.pivot_env_path = envPath;
      } catch (err) {
        fail('credential', err);
        if (adRotated) {
          // The one outcome a rollback cannot reach, and the one an instructor
          // has to be told about in words rather than left to infer from a step
          // name. Re-running the reseed fixes it: it rotates again and
          // republishes everywhere.
          record.credential_state = 'ad_rotated_not_published';
          record.warnings.push(
            `THE DIRECTORY WAS ALREADY ROTATED when this failed: ${domain}\\${sam} now holds a ` +
            `password that at least one publisher on this lane does not serve, so the pivot will not ` +
            `work until this reseed is re-run (which rotates the account again and republishes it ` +
            `everywhere). Set-ADAccountPassword -Reset needs no old value and this run never knew ` +
            `the baked one, so there is nothing to put back.`
          );
        } else {
          record.credential_state = 'unchanged';
        }
        // All sides or none: drop every staged rewrite so each publisher keeps
        // the value it had. Before 4d that is the baked value AD still honours;
        // after it, the staged copies are the only thing that agreed with the
        // directory and they are stale the moment a re-run mints a new password.
        await discardStaged();
      }

      // ── 5. verification ──────────────────────────────────────────────────
      if (record.steps.credential === 'ok') {
        try {
          await winExec(
            d, plan.dc.node, plan.dc.vm_id,
            buildVerifyCommand({ sam, domain, encodedPassword }),
            [password]
          );
          record.verified = true;
          record.verified_at = new Date().toISOString();
          record.steps.verify = 'ok';
        } catch (err) {
          // The credential is set on both sides but does not authenticate —
          // the student would hit a dead end they cannot diagnose. Say so.
          fail('verify', err);
        }
      } else {
        record.steps.verify = 'skipped';
      }
    }
  } catch (err) {
    // Everything that reaches here is fatal to the reseed but NOT to the lane.
    fail('reseed', err);
  }

  if (record.status !== 'failed') {
    console.log(
      `${logTag} Lane ${laneId}: reseeded (` +
      Object.entries(record.steps).map(([k, v]) => `${k}=${v}`).join(', ') + ')'
    );
  }

  if (recordOnLane) {
    await recordReseedOnLane(laneId, record, d).catch(err => {
      console.warn(`${logTag} Could not record reseed on lane ${laneId}: ${err.message}`);
    });
  }
  return record;
}

/**
 * The postDeploy-shaped hook, plus the map lane-provision needs to re-apply the
 * records once the deployer has finished writing lane config.
 *
 * WHY A MAP AND A SECOND WRITE. challenge-lane-deployer's step 8 builds the
 * lane's active config from the batch-wide `laneConfig` object and writes it
 * WHOLE (`config = $2::jsonb`), and postDeploy runs before it. So the merge
 * reseedLane does during the hook is real — and is then overwritten a few
 * seconds later on the deploy path. Re-applying after deployChallengeLanes
 * returns is what makes the record survive; keeping the in-hook write is what
 * makes a standalone re-reseed of one lane work, and leaves a partial record
 * behind if the deploy dies between the two.
 *
 * The hook itself never throws, so reseed can never be the reason a lane that
 * otherwise deployed is reported as failed.
 *
 * @returns {{hook:function, records:Map<string,object>}}
 */
function makeReseedPostDeploy({ logTag = LOG, deps = {} } = {}) {
  const records = new Map();

  async function reseedForLane({ laneId, user, spec, deployedVMs, goadSubnetBase }) {
    const record = await reseedLane({
      laneId,
      userId: user && user.id,
      spec,
      deployedVMs,
      goadSubnetBase,
      logTag,
      deps,
    });
    records.set(laneId, record);
    return record;
  }

  return { hook: reseedForLane, records };
}

module.exports = {
  reseedLane,
  makeReseedPostDeploy,
  recordReseedOnLane,
  waitForDcAgent,
  // Pure, so they are testable without a cluster.
  assertGoldenSubnet,
  resolveReseedPlan,
  generatePivotPassword,
  generateSeedValues,
  fingerprint,
  b64,
  psDecode,
  assertNoCleartextSecret,
  buildHostIdentityCommand,
  buildFlagCommand,
  buildSeedCommand,
  buildReadPlantCommand,
  buildStagePlantCommands,
  buildCommitPlantCommand,
  buildDiscardPlantCommand,
  buildRestartCommand,
  buildAdResetCommand,
  buildVerifyCommand,
  // The format-aware rewrite, exported so the tests can drive it against the
  // exact bytes roles/cc_web/templates/pivot-credential.j2 renders.
  normalizePlant,
  readPlantValue,
  writePlantValue,
  readPlantFile,
  htmlEscape,
  htmlUnescape,
  // Constants the tests and callers share.
  WIN_PS,
  DC_AGENT_TIMEOUT_MS,
  DEFAULT_FLAG_PATH,
  DEFAULT_ENV_PATH,
  DEFAULT_ENV_KEY,
  DEFAULT_SEED_PATH,
  DEFAULT_CONTAINER,
  PW_LENGTH,
  PLANT_OPS,
  PLANT_MISSING,
  PLANT_STAGE_SUFFIX,
  PLANT_CHUNK,
  PLANT_MAX_BYTES,
};
