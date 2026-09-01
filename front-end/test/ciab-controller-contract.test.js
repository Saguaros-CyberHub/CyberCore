/**
 * ciab-controller-contract.test.js — Track Z4: the controller template's
 * contract with everything that pushes data at it.
 *
 * WHY THIS FILE EXISTS
 * infrastructure/proxmox-templates/vm-templates/bake-goad-controller-vm.sh is
 * the only place CyberCore's GOAD provisioning actually lives. It bakes VM
 * template 1700; every lane full-clones 1700; and the entrypoint the
 * orchestrator drives over the guest agent — /opt/goad-light/run.sh — exists
 * ONLY as a cloud-init heredoc inside that bake script. Nothing else in the
 * repo can be unit-tested into covering it:
 *
 *   - run.sh is generated text, not a tracked file, so no test can require() it
 *   - it runs on a Debian guest, over WinRM, against a live Proxmox lane
 *   - it is invoked exactly once per deploy, ~90 minutes long, and the failures
 *     it exists to prevent surface at the 95% mark
 *
 * So these are source-text assertions over the bake script, in the style of
 * ciab-deploy-parity.test.js. That is a blunt instrument and the right one:
 * the properties defended below are all of the "someone reasonably re-inlines
 * it" kind, and the cost of finding out on a lane is a 90-minute bake.
 *
 * WHAT IS BEING DEFENDED — four things, in rising order of how quietly they
 * fail:
 *
 *  1. THE ROLLBACK. 1700 is baked IN PLACE. There is no undo: cloud-init
 *     git-fetches GOAD_REF and ansible-galaxy resolves requirements.yml at bake
 *     time, so a re-bake is a NEW build, not the same build again. The only way
 *     back from a bad bake is a second template that still holds the last
 *     known-good tree, plus a one-line change of the id goad-deploy.js clones.
 *
 *  2. THE PER-LAB PLAYBOOK CHAIN. run.sh used to read the chain only from
 *     upstream's shared /opt/goad/playbooks.yml, keyed by lab name with a
 *     `default` fallback. `default` is the FULL 16-playbook GOAD chain —
 *     child-domain, trusts, gmsa, laps, and a hard five-minute wait5m.yml. A
 *     generated single-domain lab that misses its key does not skip those; it
 *     runs them and dies 15-25 minutes in on reciprocal data it cannot make
 *     consistent.
 *
 *  3. THE EXTRA-VARS OVERLAY. --extra-vars outranks every inventory level, so
 *     the file run.sh writes is the highest-precedence input in the whole run.
 *     A generated lab has to be able to add to it WITHOUT the pusher rewriting
 *     run.sh's own block, or every generated profile carries a fork of the
 *     entrypoint.
 *
 *  4. THE RECEIVING DIRECTORY. A push that dies halfway leaves a tarball that
 *     is present and short. Size and mtime cannot tell that from a complete
 *     one, and a truncated data/ tree still parses and still provisions — the
 *     only things missing are the objects nobody notices are missing. That is
 *     the exact failure mode this entire pipeline exists to handle (an audit
 *     found 20 GOAD tasks that report SUCCESS and do nothing), so the payload
 *     is never allowed to be the thing that says "done".
 *
 * THE OTHER HALF. ciab/utils/goad-lab-push.js is the pusher, written in the
 * same wave as this change. It delivers by a different transport (base64 chunks
 * over the guest agent, staged and renamed into place), so most of what it does
 * needs nothing from the controller — but three things have to be spelled
 * IDENTICALLY on both sides or the halves silently disagree, and each of them
 * has a test below:
 *
 *   - `.cc-manifest` inside ad/<LAB>/, `key=value` one token per line, payload
 *     key `tree_sha256=`. Both routes write it; both routes read it as "is this
 *     already delivered?" with grep -qxF.
 *   - `/opt/goad-light/.cc-per-lab-playbooks`, the marker the pusher's support
 *     probe short-circuits on. Its fallback is a grep of run.sh for a line
 *     carrying both LAB and playbooks.yml — a coincidence of spelling that
 *     breaks on the next rename, which is why the marker is the real contract.
 *   - the per-lab chain shapes the reader accepts, since the pusher emits a
 *     MAP keyed by both <LAB> and `default` rather than a bare list.
 *
 * PLUS one trap guard that is not about the contract at all. The cloud-init
 * heredoc opens UNQUOTED (`cat > "$USERDATA_PATH" << SNIPPET`), so bash runs
 * command substitution inside its body AT BAKE TIME, on the Proxmox node.
 * Twelve prose comments carried paired backticks and therefore executed. Most
 * were command-not-found noise that silently blanked the comment — but one was
 * `grep win_psmodule|Install-Module`, a grep with no file operand, which reads
 * the bake script's own stdin and hangs the bake outright on a TTY. Two
 * assertions below make that class of mistake un-reintroducible.
 *
 * Run: node --test front-end/test/ciab-controller-contract.test.js  (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const REPO = path.join(ROOT, '..');

const BAKE_REL = 'infrastructure/proxmox-templates/vm-templates/bake-goad-controller-vm.sh';
const BAKE = path.join(REPO, BAKE_REL);
const MANIFEST_JSON = path.join(
  ROOT, 'modules/crucible/plugins/ciab/data/goad-role-manifest.json');
const GOAD_DEPLOY = path.join(ROOT, 'src/utils/goad-deploy.js');

const src = fs.readFileSync(BAKE, 'utf8');
const lines = src.split(/\r?\n/);

// ── slicing helpers ─────────────────────────────────────────────────────────
// Everything interesting is nested two levels deep: a write_files entry inside
// a heredoc inside a shell script. Asserting against the whole file would let a
// match in one section satisfy a claim about another — the run.sh block and the
// prep.sh block share most of their vocabulary.

const HEREDOC_OPEN = 'cat > "$USERDATA_PATH" << SNIPPET';

/** The body of the unquoted cloud-init heredoc, as an array of lines. */
function heredocLines() {
  const start = lines.indexOf(HEREDOC_OPEN);
  assert.notStrictEqual(start, -1,
    `${BAKE_REL} no longer opens the cloud-init heredoc with the exact line `
    + `${JSON.stringify(HEREDOC_OPEN)}; every assertion in this file slices on it.`);
  const end = lines.indexOf('SNIPPET', start + 1);
  assert.ok(end > start, 'the cloud-init heredoc has no SNIPPET terminator');
  return lines.slice(start + 1, end);
}

/**
 * One `- path: <p>` write_files entry, from its header to the next entry at the
 * same indentation. Returned as text so index comparisons (X before Y) work.
 */
function writeFileBlock(p) {
  const header = `  - path: ${p}\n`;
  const at = src.indexOf(header);
  assert.notStrictEqual(at, -1,
    `${BAKE_REL} no longer writes ${p} via cloud-init write_files`);
  const rest = src.slice(at + header.length);
  const next = rest.search(/\n {2}- path: /);
  return next === -1 ? rest : rest.slice(0, next);
}

const heredoc = heredocLines();
const runSh = writeFileBlock('/opt/goad-light/run.sh');
const extractSh = writeFileBlock('/opt/goad-light/extract-lab.sh');

/** The capability marker the pusher's support probe short-circuits on. */
const PER_LAB_MARKER = '/opt/goad-light/.cc-per-lab-playbooks';

/** Assert `a` appears before `b` in `text`, with both present. */
function before(text, a, b, why) {
  const ia = text.indexOf(a);
  const ib = text.indexOf(b);
  assert.notStrictEqual(ia, -1, `missing: ${a}\n${why}`);
  assert.notStrictEqual(ib, -1, `missing: ${b}\n${why}`);
  assert.ok(ia < ib, `${a}\nmust come BEFORE\n${b}\n${why}`);
}

/** Strip shell/YAML comment lines, for "must NOT contain" assertions. */
function codeOnly(text) {
  return text.split(/\r?\n/).filter((l) => !/^\s*#/.test(l)).join('\n');
}

// ════════════════════════════════════════════════════════════════════════════
// 1. THE ROLLBACK — frozen template, one-line revert
// ════════════════════════════════════════════════════════════════════════════

test('the bake target and the frozen rollback target are two distinct, stated VMIDs', () => {
  // Proxmox cannot renumber a VMID, so "keep the working template" is only
  // expressible as a SECOND template at a second id. Naming it in this file —
  // the file that destroys the thing it protects — is the point; an id that
  // lives only in someone's shell history is not a rollback plan.
  const bakeId = src.match(/^VMID=(\d+)$/m);
  const rollbackId = src.match(/^ROLLBACK_TEMPLATE_VMID=(\d+)$/m);
  assert.ok(bakeId, `${BAKE_REL} must define VMID=<n> at column 0`);
  assert.ok(rollbackId,
    `${BAKE_REL} must define ROLLBACK_TEMPLATE_VMID=<n>. This was an explicit `
    + `requirement: one re-bake, with the working template kept as a one-line rollback.`);
  assert.notStrictEqual(rollbackId[1], bakeId[1],
    'the rollback template cannot be the same id this script bakes over');
});

test('the header documents the whole revert procedure, not just the id', () => {
  // A constant with no procedure is worse than nothing: it reads as "handled"
  // while the person holding a broken lab at 2am still has to derive the steps.
  // The header must name the freeze (clone + template), the file to edit, and
  // the symbol to change — the three things that are not guessable.
  const header = src.slice(0, src.indexOf('set -euo pipefail'));
  assert.ok(/ROLLBACK/.test(header),
    'the script header must carry a ROLLBACK section');
  assert.ok(/qm clone \d+ \d+/.test(header),
    'the header must give the literal freeze command (qm clone <live> <frozen> ...); '
    + 'the freeze has to happen BEFORE the destroy, so it cannot be left implicit');
  assert.ok(/qm template \d+/.test(header),
    'a clone of a template lands as a normal VM — the header must say to re-freeze it '
    + 'with qm template, or the "frozen" copy is a bootable VM that will run cloud-init');
  assert.ok(/goad-deploy\.js/.test(header) && /CONTROLLER_TEMPLATE_VMID/.test(header),
    'the header must name front-end/src/utils/goad-deploy.js and CONTROLLER_TEMPLATE_VMID — '
    + 'that constant IS the rollback switch');
});

test('the one-line rollback is real: goad-deploy.js pins exactly the id this script bakes', () => {
  // The whole plan rests on goad-deploy.js resolving the controller template
  // through ONE constant. If it ever computes the id, or a second caller clones
  // a hardcoded 1700, the documented revert silently covers only half the
  // deploys — and the half it misses is not obvious from either file.
  const bakeId = src.match(/^VMID=(\d+)$/m)[1];
  const deploy = fs.readFileSync(GOAD_DEPLOY, 'utf8');
  const pin = deploy.match(/^const CONTROLLER_TEMPLATE_VMID = (\d+);$/m);
  assert.ok(pin,
    'src/utils/goad-deploy.js must keep CONTROLLER_TEMPLATE_VMID as a single top-level '
    + 'const — it is the documented one-line rollback switch');
  assert.strictEqual(pin[1], bakeId,
    `goad-deploy.js clones template ${pin[1]} but the bake script bakes ${bakeId}. `
    + 'Re-baking would replace a template nothing deploys.');
});

test('the bake never writes to the frozen id — it only checks and prints it', () => {
  // The one way to destroy a rollback is to bake onto it. Every live use of the
  // constant must be a read: the assignment, the existence probe, or an echo.
  // Anything else (qm create / clone / destroy / set targeting it) means this
  // script can eat the copy it exists to protect.
  const offenders = [];
  lines.forEach((line, i) => {
    if (!line.includes('ROLLBACK_TEMPLATE_VMID')) return;
    const t = line.trim();
    if (t.startsWith('#')) return;                       // prose
    if (/^ROLLBACK_TEMPLATE_VMID=\d+$/.test(t)) return;  // the definition
    if (t.startsWith('echo ')) return;                   // operator guidance
    if (/^if qm status \$ROLLBACK_TEMPLATE_VMID /.test(t)) return; // the probe
    offenders.push(`${i + 1}: ${t}`);
  });
  assert.deepStrictEqual(offenders, [],
    'the frozen rollback template must never be a write target:\n' + offenders.join('\n'));
});

test('a bake with no rollback template in place says so, loudly', () => {
  // Deliberately a warning and not a refusal: the first bake on a fresh cluster
  // has nothing to freeze, and a hard failure there is unfixable without editing
  // this script. But by the time this runs, 1700 has already been destroyed —
  // so if the freeze did not happen, the last known-good tree is already gone,
  // and the only honest thing left is to say it before spending 25 minutes.
  assert.ok(/qm status \$ROLLBACK_TEMPLATE_VMID/.test(src),
    'the bake must probe for the frozen template before building the replacement');
  assert.ok(/WARNING: no frozen rollback template/.test(src),
    'a missing rollback template must produce an explicit warning, not silence');
});

// ════════════════════════════════════════════════════════════════════════════
// 2. PER-LAB PLAYBOOK CHAIN — prefer ad/<LAB>/playbooks.yml, fall back as before
// ════════════════════════════════════════════════════════════════════════════

test('run.sh prefers the lab-owned chain, and that check PRECEDES the shared fallback', () => {
  // Order is the assertion. A preference expressed the other way round — read
  // the shared map, then override if a per-lab file exists — reintroduces the
  // read of the shared mutable file on every run, which is the thing being
  // removed: a generated profile would have to read-modify-write
  // /opt/goad/playbooks.yml inside the guest on every push. Concurrent pushes
  // race, a failed push leaves a key pointing at a tree that is not there, and
  // no key is traceable to the lab that wrote it.
  assert.ok(runSh.includes('LAB_PLAYBOOKS_YML="\\$LAB_ROOT/playbooks.yml"'),
    'run.sh must define LAB_PLAYBOOKS_YML as <lab tree>/playbooks.yml');
  assert.ok(runSh.includes('LAB_ROOT="\\$GOAD_ROOT/ad/\\$LAB"'),
    'LAB_ROOT must be $GOAD_ROOT/ad/$LAB — the per-lab files live inside the lab tree '
    + 'so that a push is one atomic operation and the chain is versioned with its data');

  before(runSh,
    'if [ -f "\\$LAB_PLAYBOOKS_YML" ]; then',
    'CHAIN_SRC="\\$PLAYBOOKS_YML"',
    'The per-lab file must be TESTED FIRST and the shared file used only as the else branch.');
});

test('the shared playbooks.yml fallback is preserved byte-for-byte', () => {
  // Every lab CyberCore ships today (GOAD-Light, GOAD, GOAD-Mini, NHA, SCCM,
  // DRACARYS) resolves through this read, and GOAD-Light and GOAD are not even
  // keys in upstream's file — they land on `default`. Any change to this
  // expression changes the chain for labs that are working in production right
  // now, which is precisely what "backward compatible" forbids here.
  assert.ok(runSh.includes('PLAYBOOKS_YML="\\$GOAD_ROOT/playbooks.yml"'),
    'the shared upstream map must still be resolved at $GOAD_ROOT/playbooks.yml');
  assert.ok(runSh.includes('.get("\\$LAB") or (data or {}).get("default") or []'),
    'the shared-file read must stay "<lab> or default or []" — that is what every '
    + 'shipped lab depends on');
});

test('the chain reader opens the SELECTED file, not the shared one', () => {
  // The easy way to get this wrong is to add the preference but leave the
  // python opening $PLAYBOOKS_YML. It fails silently in the worst direction: a
  // generated lab that shipped its own short chain runs the full 16-playbook
  // `default` instead, and dies 15-25 minutes in on child-domain / trust data
  // it has no way to make consistent.
  assert.ok(runSh.includes('with open("\\$CHAIN_SRC") as f:'),
    'the python chain reader must open $CHAIN_SRC');
  assert.ok(!codeOnly(runSh).includes('with open("\\$PLAYBOOKS_YML")'),
    'the chain reader still opens the shared file directly, so the per-lab preference '
    + 'is decorative — the selected source is $CHAIN_SRC');
  assert.ok(runSh.includes('if isinstance(data, list):'),
    'a per-lab file should be allowed to be a bare LIST: the whole file IS that lab\'s '
    + 'chain, so a generator cannot name the wrong key');
  // Both shapes must survive, because the two halves picked different ones:
  // a bare list is what a generator should emit, but goad-lab-push.js writes a
  // MAP keyed by BOTH <LAB> and `default` precisely so it works whichever key
  // the override happens to look up. Dropping the mapping branch here would
  // make every pushed lab fall through to an empty chain.
  before(runSh, 'if isinstance(data, list):', '.get("\\$LAB") or (data or {}).get("default")',
    'The per-lab reader must accept a bare list AND a mapping — the pusher emits a mapping.');
  // The error message has to name the file that was actually consulted, or the
  // reader goes and edits the wrong one.
  assert.ok(/no playbook chain found for lab '\\\$LAB' in \\\$CHAIN_SRC/.test(runSh),
    'the "no chain found" error must name $CHAIN_SRC, not the shared file');
});

// ════════════════════════════════════════════════════════════════════════════
// 3. EXTRA-VARS OVERLAY — appended after the base block, never replacing it
// ════════════════════════════════════════════════════════════════════════════

test('the base extra_vars.yml is still written exactly once, truncating', () => {
  // This block carries the connection contract the whole chain depends on:
  // admin_user, the single-NIC adapter forcing, route_gateway and
  // dns_server_forwarder pinned to the lane gateway. If the overlay ever became
  // an alternative to it rather than an addition, a generated lab would lose
  // all of that and fail in DNS, ~40 minutes in.
  const creates = runSh.split('cat > "\\$RUNTIME/extra_vars.yml" <<EXTRA').length - 1;
  assert.strictEqual(creates, 1,
    'run.sh must create $RUNTIME/extra_vars.yml exactly once with a truncating redirect');
});

test('the overlay is APPENDED after the base block, and is optional', () => {
  // Append order is the mechanism, not a detail: ansible loads
  // --extra-vars '@file' as ONE yaml document, and PyYAML's mapping loader
  // keeps the LAST occurrence of a duplicate key. Appending is therefore how a
  // generated lab both adds variables and corrects one of ours, without the
  // pusher rewriting run.sh's own file — the read-modify-write this contract
  // removes everywhere else.
  before(runSh,
    'cat > "\\$RUNTIME/extra_vars.yml" <<EXTRA',
    '>> "\\$RUNTIME/extra_vars.yml"',
    'The overlay must be appended AFTER the base block, or it loses every key it shares '
    + 'with it instead of winning.');
  assert.ok(runSh.includes('LAB_EXTRA_VARS="\\$LAB_ROOT/extra_vars.yml"'),
    'the overlay path must be <lab tree>/extra_vars.yml, shipped inside the pushed tree');
  assert.ok(runSh.includes('if [ -f "\\$LAB_EXTRA_VARS" ]; then'),
    'the overlay must be OPTIONAL — every lab shipped in the image has no such file, '
    + 'and all of them must keep running unchanged');
  const appends = runSh.split('>> "\\$RUNTIME/extra_vars.yml"').length - 1;
  assert.strictEqual(appends, 1, 'exactly one append site, so precedence is readable');
});

test('the overlay carries the precedence warning a future author needs', () => {
  // --extra-vars is not "another place to put defaults". It beats host_vars,
  // group_vars, play vars, role defaults and upstream's own data/inventory, so
  // anything written here is a hard override for the entire chain. The specific
  // landmine is data_path: each upstream playbook sets it per-import for
  // data.yml's vars_files, and overriding it globally breaks `lab` loading in
  // every play at once — with no error that points here.
  const overlay = runSh.slice(runSh.indexOf('extra-vars overlay'));
  assert.ok(/--extra-vars/.test(overlay) && /inventory/i.test(overlay),
    'the overlay block must state that --extra-vars outranks every inventory level');
  assert.ok(/data_path/.test(overlay),
    'the overlay block must warn against setting data_path — it is the one key that '
    + 'breaks the whole chain silently');
});

// ════════════════════════════════════════════════════════════════════════════
// 4. RECEIVING DIRECTORY + IDEMPOTENT EXTRACT
// ════════════════════════════════════════════════════════════════════════════

test('the receiving directory exists in the image, created at bake time', () => {
  // Created by the bake, not by the first push, for two reasons: the pusher
  // never has to mkdir over the guest agent (one fewer round trip that can
  // half-succeed), and it can never be created with the wrong mode by whichever
  // caller happened to get there first.
  const runcmd = src.slice(src.indexOf('\nruncmd:'));
  assert.ok(/- \[ install, -d, -m, '0755', -o, root, -g, root, \/opt\/goad-inbox \]/.test(runcmd),
    'runcmd must create /opt/goad-inbox root:root 0755 at bake time');
});

test('the push contract is written down where the receiving half lives', () => {
  // The pusher lives in a different tree. The two halves only meet if the path,
  // the tarball shape and the manifest convention are stated once, in the file
  // that actually runs. Each token below is a place they can silently disagree.
  const body = heredoc.join('\n');
  for (const token of [
    '/opt/goad-inbox/',        // the path
    'lab.tar.gz',              // the payload name
    '.cc-manifest',            // the commit marker
    'tree_sha256',             // the completeness proof, spelled as the pusher spells it
    'tar -czf lab.tar.gz -C',  // contents-not-directory: the classic mis-tar
  ]) {
    assert.ok(body.includes(token),
      `the receiving-directory contract must state ${JSON.stringify(token)} — the pusher `
      + 'lives in another tree and this comment is the only shared spec');
  }
  assert.ok(/WRITTEN LAST/.test(body),
    'the contract must say the manifest is written LAST; the write ORDER is the entire '
    + 'guarantee that a partial transfer is detectable');
});

test('the manifest grammar is grep -qxF-able, and the key is tree_sha256', () => {
  // Not cosmetic. goad-lab-push.js matches its own manifest lines with
  // `grep -qxF 'tree_sha256=<sha>'` — exact whole line, fixed string — and the
  // controller has to write a file that predicate can match, or a tree
  // delivered by one route is invisible to the other's "already delivered?"
  // probe and gets re-pushed forever. `key=value` with no spaces is also what
  // keeps a sha or a lab name from ever leaking a regex metacharacter.
  const code = codeOnly(extractSh);
  assert.ok(code.includes("awk -F= -v k=\"\\$1\" '\\$1 == k { print \\$2; exit }'"),
    'the manifest reader must parse key=value (-F=), the grammar the pusher writes');
  assert.ok(code.includes('manifest_get tree_sha256'),
    "the payload's content address is spelled tree_sha256, not sha256 — that is the key "
    + 'goad-lab-push.js writes and probes');
  assert.ok(code.includes('grep -qxF "tree_sha256=\\$WANT_SHA"'),
    'the idempotence check must use the same grep -qxF predicate the pusher uses, so both '
    + 'routes agree on what "already delivered" means');
});

test('the capability marker the pusher probes for is baked into the image', () => {
  // goad-lab-push.js has to decide FROM OUTSIDE whether this controller honours
  // ad/<LAB>/playbooks.yml, because a lane cloned from the previous template
  // does not — and a lab delivered to one of those with no shared-file merge
  // silently inherits `default`, which is the 16-play chain and most of an hour.
  //
  // Its fallback test is a grep of run.sh for a line carrying both LAB and
  // playbooks.yml. Our LAB_PLAYBOOKS_YML= line satisfies it, but that is a
  // COINCIDENCE OF SPELLING: rename the variable and the probe answers "no"
  // forever, silently, in the safe-looking direction. The marker is the actual
  // contract, so assert both — the marker, and the grep-visible line that
  // covers a controller baked before the marker existed.
  assert.ok(src.includes(`  - path: ${PER_LAB_MARKER}\n`),
    `${BAKE_REL} must bake ${PER_LAB_MARKER}; it is the explicit hook the pusher's `
    + 'support probe short-circuits on');
  const grepVisible = runSh.split(/\r?\n/).some(
    (l) => l.includes('playbooks.yml') && l.includes('LAB'));
  assert.ok(grepVisible,
    "run.sh must keep at least one line carrying both 'LAB' and 'playbooks.yml' — that is "
    + "the pusher's fallback probe for controllers baked before the marker file");
});

test('an incomplete push is refused, not extracted', () => {
  // The failure being designed out: a transfer that dies halfway leaves
  // lab.tar.gz PRESENT and SHORT. Presence, size and mtime cannot tell that
  // apart from a complete file. A truncated data/ tree still parses and still
  // provisions — the only things missing are the objects nobody notices are
  // missing, which is this pipeline's dominant failure mode. So the payload is
  // never the commit point; the manifest is, and everything else is refused.
  const code = codeOnly(extractSh);
  assert.ok(code.includes('if [ ! -f "\\$MANIFEST" ]; then'),
    'extract-lab.sh must refuse when the manifest is absent (push still in flight)');
  assert.ok(code.includes('sha256sum "\\$BUNDLE"'),
    'extract-lab.sh must verify the payload sha against the manifest');
  assert.ok(code.includes('if [ -z "\\$WANT_SHA" ]; then'),
    'a manifest with no tree_sha256 line proves nothing and must be refused, not trusted '
    + 'for merely existing');
  assert.ok(/manifest says lab=/.test(extractSh),
    'a manifest addressed to a different lab must be refused, not extracted');
  // Three independent refusals, each exiting non-zero. A helper that warned and
  // continued would hand run.sh a partial tree, which is the whole bug.
  const exits = code.split('exit 1').length - 1;
  assert.ok(exits >= 4,
    `extract-lab.sh has only ${exits} hard refusals; incomplete, corrupt, misaddressed and `
    + 'malformed bundles must each fail the run rather than degrade it');
});

test('extraction is atomic: stage, validate, then swap', () => {
  // Untarring over the destination is the same bug one level down — tar dying
  // partway leaves a half-written lab in the exact place run.sh is about to
  // read. Staging alongside and renaming makes the visible window a single
  // syscall, so no reader can observe a partial tree.
  const code = codeOnly(extractSh);
  assert.ok(code.includes('tar -xzf "\\$BUNDLE" -C "\\$STAGE"'),
    'extract-lab.sh must untar into a staging directory');
  assert.ok(!/tar -xzf[^\n]*-C "\\\$DEST"/.test(code),
    'extract-lab.sh must never untar directly over the destination tree');
  assert.ok(code.includes('mv "\\$STAGE" "\\$DEST"'),
    'the staged tree must be moved into place (rename within one filesystem)');
  assert.ok(code.includes('if [ ! -d "\\$STAGE/data" ] || [ ! -d "\\$STAGE/providers/proxmox" ]; then'),
    'the staged tree must be validated for the two directories run.sh requires BEFORE '
    + 'the swap — failing here names the missing piece, failing in run.sh says only '
    + '"Lab not found" and sends the reader to the wrong machine');
  // The manifest goes in before the rename, so it becomes visible at the same
  // instant the tree does. Copying it after the swap would open exactly the
  // window this whole design closes: a complete-looking directory with no
  // record, or a record that lands while a reader is already in the tree.
  before(code, 'cp "\\$MANIFEST" "\\$STAGE/.cc-manifest"', 'mv "\\$STAGE" "\\$DEST"',
    'The manifest must be placed inside the STAGED tree, before the rename.');
});

test('re-extracting the same bundle is a hard no-op', () => {
  // run.sh calls this on every provisioning run and the pusher may call it too.
  // Re-unpacking identical bytes is not "cheap": run.sh and goad-deploy.js both
  // patch roles and data IN PLACE after delivery (the mssql win_template fix,
  // the child_domain reboot fix), and a re-extract would silently revert those
  // edits mid-chain.
  //
  // The record is ad/<LAB>/.cc-manifest and NOT a private stamp file, because
  // the other delivery route writes that same file from its side. Two records
  // of one fact drift, and the one that drifts is always the one the next
  // reader trusts.
  assert.ok(extractSh.includes('DEST_MANIFEST="\\$DEST/.cc-manifest"'),
    'the installed record must be ad/<LAB>/.cc-manifest — the file both delivery routes '
    + 'write and both read');
  assert.ok(!/\.cc-extracted/.test(extractSh),
    'no second stamp file: one fact, one record, or they drift');
  before(codeOnly(extractSh),
    'if [ -f "\\$DEST_MANIFEST" ] && grep -qxF "tree_sha256=\\$WANT_SHA" "\\$DEST_MANIFEST"; then',
    'STAGE="\\$AD_ROOT/.incoming-\\$LAB.\\$\\$"',
    'The idempotence check must short-circuit BEFORE any staging work happens.');
});

test('a lab with nothing in the inbox is not an error', () => {
  // run.sh calls extract-lab.sh unconditionally, including for every lab baked
  // into the image (GOAD-Light, GOAD, NHA...). If a missing inbox entry failed,
  // this change would break all six shipped labs at once — the exact opposite
  // of backward compatible.
  const code = codeOnly(extractSh);
  before(code, 'if [ ! -d "\\$INBOX" ]; then', 'exit 0',
    'A missing inbox directory must exit 0 early, before any manifest checks.');
});

test('run.sh lands a pushed tree BEFORE deciding the lab does not exist', () => {
  // Ordering, again, is the assertion. A generated lab is not in the image; it
  // arrives in the inbox. Extract after the existence check and every pushed
  // lab dies on "Lab not found" while its tree sits complete and verified two
  // directories away.
  before(runSh,
    '/opt/goad-light/extract-lab.sh "\\$LAB"',
    'if [ ! -d "\\$LAB_DATA" ] || [ ! -d "\\$LAB_PROVIDER" ]; then',
    'The extract must run before run.sh concludes the lab is missing.');
  // Unconditional on purpose. Guarding the call with [ -x ] would turn a
  // missing helper into a silent skip and then into "lab not found", pointing
  // the reader at the wrong half of the contract.
  assert.ok(!/\[ -x \/opt\/goad-light\/extract-lab\.sh \]/.test(runSh),
    'the extract call must not be silently skippable');
});

// ════════════════════════════════════════════════════════════════════════════
// 5. THE HEREDOC TRAP — nothing inside the bake body may execute at bake time
// ════════════════════════════════════════════════════════════════════════════

test('no backticks survive anywhere inside the unquoted cloud-init heredoc', () => {
  // `cat > "$USERDATA_PATH" << SNIPPET` is UNQUOTED, so bash performs command
  // substitution inside its body — on the Proxmox node, at bake time. Twelve
  // prose comments carried paired backticks and DID execute: most produced
  // command-not-found noise and silently blanked the comment they were in, but
  // `grep win_psmodule|Install-Module` is a grep with no file operand, which
  // reads the bake script's own stdin and hangs the bake on a TTY.
  //
  // Backticks in prose are the natural way to quote an identifier, which is
  // exactly why this needs a test and not a comment: the next author will reach
  // for them, and nothing in the output will look wrong until a comment is
  // mysteriously empty or the bake stops at 40%.
  const offenders = [];
  const start = lines.indexOf(HEREDOC_OPEN);
  heredoc.forEach((line, i) => {
    if (line.includes('`')) offenders.push(`${start + 2 + i}: ${line.trim()}`);
  });
  assert.deepStrictEqual(offenders, [],
    'backticks inside the unquoted heredoc EXECUTE on the Proxmox node at bake time. '
    + "Use plain quotes in prose:\n" + offenders.join('\n'));
});

test('every $ inside the two runtime scripts is escaped for the outer heredoc', () => {
  // run.sh and extract-lab.sh are the two files that run on the LANE, long
  // after the bake. Any unescaped $ in their bodies is expanded by the bake's
  // shell instead — almost always to the empty string, since these are runtime
  // variables the bake has never heard of. The result is a syntactically valid
  // script with a hole in it: `[ -f "" ]`, `cd `, a test that is always false.
  // Nothing fails at bake time and nothing looks wrong in the source.
  const BS = '\\';
  const offenders = [];
  for (const [name, block] of [['run.sh', runSh], ['extract-lab.sh', extractSh]]) {
    block.split(/\r?\n/).forEach((line, i) => {
      for (let p = 0; p < line.length; p++) {
        if (line[p] !== '$') continue;
        let n = 0;
        for (let j = p - 1; j >= 0 && line[j] === BS; j--) n++;
        if (n % 2 === 0) { offenders.push(`${name}+${i + 1}: ${line.trim()}`); break; }
      }
    });
  }
  assert.deepStrictEqual(offenders, [],
    'unescaped $ inside a write_files body is expanded at BAKE time, not on the lane. '
    + 'Write \\$VAR:\n' + offenders.join('\n'));
});

// ════════════════════════════════════════════════════════════════════════════
// 6. THE CALLER CONTRACT AND THE PIN — neither may move alone
// ════════════════════════════════════════════════════════════════════════════

test('run.sh still takes exactly the four positional arguments goad-deploy.js sends', () => {
  // goad-deploy.js drives this over the guest agent as
  //   /opt/goad-light/run.sh LAB HOST_MAP INITIAL_USER INITIAL_PASSWORD
  // and there is no negotiation: the controller is a baked template, so a
  // signature change means every already-deployed lane calls the new run.sh
  // wrongly. Both halves are asserted, because "add an optional 5th argument"
  // is the natural next request and this is where it has to be noticed.
  assert.ok(runSh.includes('if [ \\$# -lt 4 ]; then'),
    'run.sh must still require at least 4 positional arguments');
  assert.ok(runSh.includes('LAB="\\$1"; HOST_MAP="\\$2"; INITIAL_USER="\\$3"; INITIAL_PASSWORD="\\$4"'),
    'run.sh must still bind LAB/HOST_MAP/INITIAL_USER/INITIAL_PASSWORD in that order');

  const deploy = fs.readFileSync(GOAD_DEPLOY, 'utf8');
  assert.ok(/\/opt\/goad-light\/run\.sh \$\{sq\(labName\)\} \$\{sq\(hostMap\)\} \$\{sq\(initialUser\)\} \$\{sq\(initialPass\)\}/.test(deploy),
    'goad-deploy.js must still invoke run.sh with exactly those four arguments in that order');
});

test('GOAD_REF is still a pinned SHA and still matches the vendored manifest', () => {
  // Repeated from ciab-goad-role-manifest.test.js on purpose, because THIS file
  // is the one a future author edits when they change the bake. The pin and the
  // vendored role manifest describe the same GOAD or the validator built on the
  // manifest is describing a library the controller does not run — and GOAD
  // roles fail QUIETLY, so the symptom is a green deploy with nothing planted.
  const m = src.match(/^GOAD_REF="\$\{GOAD_REF:-([^}"]*)\}"/m);
  assert.ok(m, `${BAKE_REL} must still define GOAD_REF with an env override`);
  assert.match(m[1], /^[0-9a-f]{40}$/,
    `GOAD_REF must be a full commit SHA, not a branch: ${JSON.stringify(m[1])}`);
  const manifest = JSON.parse(fs.readFileSync(MANIFEST_JSON, 'utf8'));
  assert.strictEqual(m[1], manifest.goad_ref,
    'GOAD_REF and goad-role-manifest.json goad_ref must move together, in one commit');
});

test('the additions did not disturb the git-fetch-by-SHA clone form', () => {
  // --branch takes branch and tag names only and rejects a SHA outright, and
  // --depth 1 alone fetches just the tip so a follow-up checkout dies with
  // "reference is not a tree". init + fetch-by-ref is the one shallow form that
  // accepts all three spellings, and it is the only reason the pin above works.
  assert.ok(/git init -q \/opt\/goad;/.test(src) && /git fetch -q --depth 1 origin "\$GOAD_REF"/.test(src),
    'the GOAD clone must stay init + fetch-by-ref + checkout FETCH_HEAD');
  assert.ok(!/git clone[^\n]*--branch "\$GOAD_REF"/.test(src),
    'git clone --branch cannot take a commit SHA — the pin would silently become "default branch"');
});
