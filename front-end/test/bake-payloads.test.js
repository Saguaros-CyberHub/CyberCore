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
// E1 moved the engine out of the CLE plugin into shared core; the bake still
// embeds the same two files from their new home.
const INCIDENT = path.join(__dirname, '..', 'src', 'incident');

// Normalised, because this comparison is about CONTENT.
//
// The repo has no .gitattributes and core.autocrlf is on, so every .sh in a
// Windows working tree is checked out CRLF while sync-bake-payloads.py writes
// LF. Comparing raw bytes would fail on which machine ran the test rather than
// on whether the payloads actually match.
//
// Worth knowing separately: a CRLF shell script does not run on a Linux node.
// The kernel reads the shebang up to the newline, so the interpreter it looks
// for carries a trailing carriage return and it reports a bad interpreter.
// That only bites if a bake script is copied FROM a Windows checkout rather
// than pulled on the node; `*.sh text eol=lf` in .gitattributes settles it.
const nl = (t) => t.split('\r\n').join('\n');
const bake = nl(fs.readFileSync(BAKE, 'utf8'));

function embedded(terminator) {
  const re = new RegExp(`<<'${terminator}'\\n([\\s\\S]*?)\\n${terminator}\\n`);
  const m = re.exec(bake);
  assert.ok(m, `no ${terminator} heredoc in the bake script`);
  return m[1];
}

test('the bake embeds the same cc-emit.js the tests exercise', () => {
  const repo = fs.readFileSync(path.join(INCIDENT, 'cc-emit.js'), 'utf8').replace(/\n$/, '');
  assert.strictEqual(embedded('CC_EMIT_EOF'), repo,
    'bake copy of cc-emit.js has drifted — run python scripts/sync-bake-payloads.py');
});

test('the bake embeds the same host-baseline.json the tests exercise', () => {
  const repo = fs.readFileSync(path.join(INCIDENT, 'playbooks', 'host-baseline.json'), 'utf8').replace(/\n$/, '');
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
  const { LOGGEN_REF } = require(path.join(INCIDENT, 'catalog.js'));
  assert.strictEqual(inBake[1], LOGGEN_REF,
    'bake-cybr400-loggen-template.sh and loggen-catalog.js pin different commits');
});

test('the technique label is stripped from attack events, and only after the filter', () => {
  // Filebeat runs processors in declaration order. drop_event tests
  // loggen.mitre.technique to decide what ships; drop_fields then removes it.
  // Reverse them and every attack event is discarded, because the field the
  // filter tests no longer exists — a total, silent outage of the feature.
  const proc = bake.slice(bake.indexOf('id: loggen-attack'));
  const dropEvent = proc.indexOf('- drop_event:');
  const dropFields = proc.indexOf('- drop_fields:');
  assert.ok(dropEvent > -1, 'attack input must drop untagged events');
  assert.ok(dropFields > -1, 'attack input must strip the technique label');
  assert.ok(dropEvent < dropFields,
    'drop_event must come BEFORE drop_fields or every attack event is discarded');
  // Both fields, and log.file.path is the one that matters most. filestream
  // stamps the source path on every document, and the two trees give it exactly
  // two values -- /opt/log-generator/... and /opt/log-generator-attack/... -- so
  // it sat in Discover's field list as a one-click enumeration of the whole run.
  // Easier than any oracle it was kept alongside, because it is a direct match
  // rather than a negation.
  assert.ok(/fields: \['loggen\.mitre', 'log\.file\.path'\]/.test(proc),
    'the attack input must strip both the technique label and the source path');
});

test('the baseline input keeps its labels and its events', () => {
  // Benign traffic must stay tagged: it is the false-positive floor that keeps
  // mitre.technique:* from being an answer key. And it must have no drop_event,
  // or untagged benign events — the overwhelming majority — never ship at all.
  const base = bake.slice(bake.indexOf('id: loggen-baseline'), bake.indexOf('id: loggen-attack'));
  assert.ok(!base.includes('drop_event'), 'the baseline must not drop untagged events');
  assert.ok(!/fields: \[[^\]]*loggen\.mitre/.test(base), 'the baseline must keep its MITRE labels');
  // It DOES drop log.file.path, and the pairing with the attack input is the
  // whole point. Removing the path from only one tree replaces a direct-match
  // oracle with an inverted one: NOT _exists_ : log.file.path would then select
  // exactly the attack events, which is no better and much harder to spot.
  assert.ok(/fields: \['log\.file\.path'\]/.test(base),
    'the baseline must drop log.file.path too, or its absence identifies attacks');
});

test('every cloud-init block scalar keeps its indentation', () => {
  // `bash -n` validates the shell AROUND the heredocs and sees nothing inside
  // them. An indentation slip in a `content: |` block therefore passes every
  // other check in this repo and then fails at bake time as "bake did not
  // complete" forty minutes later, with nothing pointing at the cause.
  //
  // That happened: a tidy-up collapsed `      ExecStart=` to ` ExecStart=`,
  // which ends the block scalar early. cloud-init then cannot parse the
  // user-data at all, so runcmd never runs and the image is untouched.
  //
  // In a YAML literal block the first content line fixes the indent; every
  // later line must meet it, and whatever ends the block has to be structure —
  // a list item or a key — not a stray line of the payload.
  const lines = bake.split('\n');
  const problems = [];

  for (let i = 0; i < lines.length; i += 1) {
    const open = /^(\s*)content: \|\s*$/.exec(lines[i]);
    if (!open) continue;
    const keyIndent = open[1].length;

    let j = i + 1;
    while (j < lines.length && lines[j].trim() === '') j += 1;
    if (j >= lines.length) continue;

    const bodyIndent = /^(\s*)/.exec(lines[j])[1].length;
    if (bodyIndent <= keyIndent) {
      problems.push(`line ${j + 1}: block body is not indented past its key`);
      continue;
    }

    for (; j < lines.length; j += 1) {
      const line = lines[j];
      if (line.trim() === '') continue;
      const indent = /^(\s*)/.exec(line)[1].length;
      if (indent >= bodyIndent) continue;
      // The block ends here — so this line must be YAML: a list item, a key, a
      // comment, or the heredoc terminator that ends the whole document. The
      // bug this exists for, a stray ` ExecStart=...`, is none of those.
      const structural = indent <= keyIndent
        && (line === 'CLOUDINIT'
          || /^\s*#/.test(line)
          || /^\s*(- |[A-Za-z_][\w.]*:)/.test(line));
      if (!structural) {
        problems.push(`line ${j + 1}: "${line.trim().slice(0, 60)}" breaks out of the block `
          + `(indent ${indent}, body is ${bodyIndent})`);
      }
      break;
    }
  }

  assert.deepStrictEqual(problems, [], problems.join('\n'));
});

test('every systemd unit the bake writes is complete', () => {
  // A truncated block scalar produces a unit file that is still syntactically
  // fine and simply missing its ExecStart, which systemd reports only when the
  // service is first started — on a student's lane, not during the bake.
  const units = [...bake.matchAll(/- path: (\/etc\/systemd\/system\/[^\n]+)\n([\s\S]*?)(?=\n {2}- path: |\nCLOUDINIT)/g)];
  assert.ok(units.length >= 4, `expected several unit files, found ${units.length}`);
  for (const [, unitPath, body] of units) {
    assert.ok(body.includes('[Service]') || body.includes('[Timer]'),
      `${unitPath} has no [Service] or [Timer] section`);
    if (body.includes('[Service]')) {
      assert.ok(/^\s+ExecStart=/m.test(body), `${unitPath} has no ExecStart=`);
    }
  }
});

test('no dashboard panel can point at the attack', () => {
  // Both dashboards have to survive a student reading them. A panel that
  // aggregates the technique, splits on the dataset, or filters a file path
  // hands over the finding — and the whole point of the workbench is that it
  // looks identical on a day with no attack at all.
  const NDJSON = path.join(ROOT, 'infrastructure', 'proxmox-templates', 'vm-templates',
    'cybr400-kibana', 'cybr400-loggen-dashboard.ndjson');
  const raw = nl(fs.readFileSync(NDJSON, 'utf8'));
  for (const banned of ['mitre', 'data_stream.dataset', 'log.file.path',
    'loggen.attack', 'loggen.baseline', 'log-generator-attack']) {
    assert.ok(!raw.includes(banned), `a dashboard panel references "${banned}"`);
  }
});

test('the workbench teaches the tail, not just the head', () => {
  // The rare-terms panels are the teaching core. A beginner sorts descending
  // and reads the top; almost everything interesting in a real hunt is at the
  // bottom, because an intruder is by definition not the busiest thing on the
  // network. If these silently flip back to desc the dashboard still renders
  // and quietly stops teaching the lesson.
  const NDJSON = path.join(ROOT, 'infrastructure', 'proxmox-templates', 'vm-templates',
    'cybr400-kibana', 'cybr400-loggen-dashboard.ndjson');
  const objs = nl(fs.readFileSync(NDJSON, 'utf8')).split('\n')
    .filter(Boolean).map((l) => JSON.parse(l));
  const rare = objs.filter((o) => o.id && /hunt-rare/.test(o.id));
  assert.strictEqual(rare.length, 2, 'expected two rare-terms panels');
  for (const o of rare) {
    const cols = o.attributes.state.datasourceStates.formBased.layers.layer1.columns;
    const terms = cols.col_terms;
    assert.strictEqual(terms.params.orderDirection, 'asc', `${o.id} is not sorted ascending`);
    assert.strictEqual(terms.params.otherBucket, false,
      `${o.id} keeps an Other bucket, which swamps the rare values`);
  }
});
