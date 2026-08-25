// ============================================================================
// The bake script embeds cc-emit.js and host-baseline.json verbatim, because it
// runs on a Proxmox node with no checkout — it cannot read them from the repo
// the way attack-runner.js reads cc-attack.sh.
//
// Two copies of the same file is a drift hazard with a nasty failure shape: the
// repo copy is what the tests above exercise, and the embedded copy is what a
// student's lane actually runs. They would diverge silently, and the divergence
// would only surface as "the attack behaves differently than it does in test".
//
// Regenerate with: python scripts/sync-bake-payloads.py
// ============================================================================
'use strict';

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..', '..');
const BAKE = path.join(ROOT, 'infrastructure', 'proxmox-templates', 'vm-templates',
  'bake-cybr400-loggen-template.sh');
const CLE = path.join(__dirname, '..', 'modules', 'crucible', 'plugins', 'cle');

const bake = fs.readFileSync(BAKE, 'utf8');

function embedded(terminator) {
  const re = new RegExp(`<<'${terminator}'\\n([\\s\\S]*?)\\n${terminator}\\n`);
  const m = re.exec(bake);
  assert.ok(m, `no ${terminator} heredoc in the bake script`);
  return m[1];
}

test('the bake embeds the same cc-emit.js the tests exercise', () => {
  const repo = fs.readFileSync(path.join(CLE, 'utils', 'cc-emit.js'), 'utf8').replace(/\n$/, '');
  assert.strictEqual(embedded('CC_EMIT_EOF'), repo,
    'bake copy of cc-emit.js has drifted — run python scripts/sync-bake-payloads.py');
});

test('the bake embeds the same host-baseline.json the tests exercise', () => {
  const repo = fs.readFileSync(path.join(CLE, 'playbooks', 'host-baseline.json'), 'utf8').replace(/\n$/, '');
  assert.strictEqual(embedded('HOST_PB_EOF'), repo,
    'bake copy of host-baseline.json has drifted — run python scripts/sync-bake-payloads.py');
});

test('no embedded payload contains its own heredoc terminator', () => {
  // A line equal to the terminator would end the heredoc early and splice the
  // rest of the file into the shell script as commands.
  for (const term of ['CC_EMIT_EOF', 'HOST_PB_EOF']) {
    const body = embedded(term);
    assert.ok(!body.split('\n').some((l) => l.trim() === term),
      `${term} appears inside its own payload`);
  }
});

test('the embedded payloads are staged through quoted heredocs', () => {
  // An UNQUOTED heredoc would expand every $ and backtick in the JavaScript.
  // cc-emit.js is full of ${...} template literals; the file would arrive on the
  // guest with them replaced by empty strings and still parse, which is the
  // worst kind of corruption — silent and syntactically valid.
  assert.ok(bake.includes("<<'CC_EMIT_EOF'"), 'cc-emit.js must use a QUOTED heredoc');
  assert.ok(bake.includes("<<'HOST_PB_EOF'"), 'host-baseline.json must use a QUOTED heredoc');
});

test('the guest gets the emitter, the host playbook and its service', () => {
  for (const needle of [
    'path: /opt/cybercore/cc-emit.js',
    'content: ${CC_EMIT_B64}',
    'path: /opt/cybercore/host-baseline.json',
    'content: ${HOST_PB_B64}',
    'path: /etc/systemd/system/cc-hostbase.service',
    '[ systemctl, enable, cc-hostbase ]',
  ]) {
    assert.ok(bake.includes(needle), `bake script is missing: ${needle}`);
  }
});

test('the pre-seal check refuses to seal an image without benign host traffic', () => {
  // Without it, source.type:host exists ONLY during an attack and one terms
  // click ends the exercise for the whole class.
  assert.ok(/check HOSTBASE_SERVICE\s+yes/.test(bake));
  assert.ok(/check HOST_PB\s+yes/.test(bake));
  assert.ok(/check CC_EMIT\s+yes/.test(bake));
  assert.ok(/check CC_EMIT_PARSES\s+yes/.test(bake));
});

test('rotation covers the benign host stream', () => {
  // loggen-rotate.sh only ever looked at logs.json. An uncovered append-only
  // file on this image has already gone wrong twice: 2.5 GB of logs.json, and
  // 54,609 logs_*.jsonl entries that stalled guest-exec on an idle box.
  assert.ok(bake.includes('H="$DIR/host.json"'), 'host.json is not rotated');
  assert.ok(bake.includes("name 'host-*.json'"), 'rotated host files are never reaped');
});

test('the bake and the catalog pin the same log-generator commit', () => {
  // Duplicated in two files with nothing tying them together. The bake verifies
  // the IMAGE against its own copy and the catalog test only checks its copy is
  // 40 hex characters, so a re-pin that updates one and not the other passes
  // both and is only caught by the runtime ref= mismatch on a deployed lane.
  const inBake = /LOGGEN_REF:-([0-9a-f]{40})/.exec(bake);
  assert.ok(inBake, 'no LOGGEN_REF default in the bake script');
  const { LOGGEN_REF } = require(path.join(CLE, 'utils', 'loggen-catalog.js'));
  assert.strictEqual(inBake[1], LOGGEN_REF,
    'bake-cybr400-loggen-template.sh and loggen-catalog.js pin different commits');
});
