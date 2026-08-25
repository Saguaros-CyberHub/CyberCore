// ============================================================================
// Playbook contract tests.
//
// These enforce the properties no human review reliably catches, and every one
// of them guards a failure that is SILENT in production:
//
//   * an unresolved {{token}} ships literal braces to Kibana -- exactly the
//     "{clientIP}" tell log-generator itself has at the pinned commit
//   * a seventh top-level key falls to dynamic mapping under ecs@mappings,
//     where a name like source.ip is typed `ip` and then REJECTS every document
//     whose value is not an address. No warning, no error, no events.
//   * an untagged attack event is dropped by the agent's drop_event processor
//   * a (source.type, source.name) pair that only ever appears during an attack
//     is a one-click answer key -- one terms agg and the exercise is over
//
// The last one is the reason this file exists. It is not enough for source.type
// to occur in benign traffic: loggen.source.name and loggen.source.host are
// mapped keywords sitting in Discover's field list right beside it.
// ============================================================================
'use strict';

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const P = path.join(__dirname, '..', 'modules', 'crucible', 'plugins', 'cle');
const PLAYBOOK_DIR = path.join(P, 'playbooks');
const emit = require(path.join(P, 'utils', 'cc-emit.js'));
const catalog = require(path.join(P, 'utils', 'loggen-catalog.js'));

/** The five durations the Attack Console offers. */
const UI_DURATIONS = [300, 900, 1800, 3600, 7200];

/** Hosts log-generator's own baseline emits, observed on a deployed lane. */
const LOGGEN_HOSTS = [
  'api.example.com', 'web-01', 'auth-01', 'k8s-01',
  'db-01', 'firewall-01', 'app-server-01', 'srv-prod-01',
];

const ENVELOPE_KEYS = ['timestamp', 'level', 'source', 'message', 'metadata', 'mitre'];

const files = fs.readdirSync(PLAYBOOK_DIR).filter((f) => f.endsWith('.json')).sort();
const load = (f) => JSON.parse(fs.readFileSync(path.join(PLAYBOOK_DIR, f), 'utf8'));

function planOf(f, requested) {
  const pb = load(f);
  const want = requested == null ? Math.max(emit.minSecondsFor(pb), pb.nominal_seconds) : requested;
  return emit.planTimeline(pb, { rng: emit.makeRng(emit.seedFrom('fixed-seed')), requested: want });
}

const linesOf = (plan) => plan.events.map((ev) => emit.toLine(ev, Date.now()));

// ---------------------------------------------------------------------------

test('every catalog technique has a playbook, and every playbook a catalog entry', () => {
  const onDisk = new Set(files.filter((f) => /^T\d/.test(f)).map((f) => f.replace('.json', '')));
  const inCatalog = new Set(catalog.TECHNIQUES.map((t) => t.id));

  const missing = [...inCatalog].filter((id) => !onDisk.has(id));
  assert.deepStrictEqual(missing, [], `catalog techniques with no playbook: ${missing}`);

  // The reverse direction matters just as much: a playbook for a technique the
  // console cannot offer is dead content that will rot without anyone noticing.
  const orphan = [...onDisk].filter((id) => !inCatalog.has(id));
  assert.deepStrictEqual(orphan, [], `playbooks with no catalog entry: ${orphan}`);
});

test('every chain in the catalog has a playbook', () => {
  for (const c of catalog.CHAINS) {
    assert.ok(files.includes(`chain-${c.key}.json`), `no playbook for chain ${c.key}`);
  }
});

test('a chain playbook only uses techniques the catalog says that chain contains', () => {
  // Otherwise the console advertises one campaign and the lane generates a
  // different one, and the mismatch is only visible by reading both lists.
  for (const c of catalog.CHAINS) {
    const pb = load(`chain-${c.key}.json`);
    const declared = new Set(c.techniques);
    const used = new Set(pb.steps.map((s) => s.technique).filter(Boolean));
    const extra = [...used].filter((t) => !declared.has(t));
    assert.deepStrictEqual(extra, [], `chain ${c.key} emits ${extra} which its catalog entry does not list`);
  }
});

test('no playbook ships an unresolved {{token}}', () => {
  for (const f of files) {
    for (const line of linesOf(planOf(f))) {
      assert.ok(!/\{\{/.test(line), `${f} emitted an unresolved token: ${line.slice(0, 160)}`);
    }
  }
});

test('every event carries exactly the six envelope keys and nothing more', () => {
  for (const f of files) {
    for (const line of linesOf(planOf(f))) {
      const doc = JSON.parse(line);
      for (const k of Object.keys(doc)) {
        assert.ok(ENVELOPE_KEYS.includes(k), `${f} emitted top-level key "${k}"`);
      }
      assert.ok(doc.timestamp && doc.level && doc.source && doc.metadata !== undefined);
      assert.ok(doc.source.type && doc.source.name && doc.source.host);
    }
  }
});

test('every attack event is tagged, or the agent silently drops it', () => {
  for (const f of files) {
    if (f === 'host-baseline.json') continue;
    for (const line of linesOf(planOf(f))) {
      const doc = JSON.parse(line);
      assert.ok(doc.mitre && doc.mitre.technique, `${f} emitted an untagged event`);
    }
  }
});

test('the serialization the wrapper greps for is exactly what is emitted', () => {
  // count_lines() in cc-attack.sh is `grep -c '"technique":"'`. If JSON.stringify
  // ever spaced that differently the console would report lines=0 -- "the attack
  // ran and nothing happened", the single most misleading output this can give.
  const line = linesOf(planOf('T1110.001.json'))[0];
  assert.ok(line.includes('"technique":"'), 'the grep contract in cc-attack.sh no longer matches');
});

test('the benign floor covers every field value the attacks use', () => {
  // THE anti-oracle test. A (type/name) pair or a host that appears only during
  // an attack is a single terms aggregation away from ending the exercise.
  const base = planOf('host-baseline.json');
  const benignPairs = new Set(base.events.map((e) => `${e.source.type}/${e.source.name}`));
  const benignHosts = new Set(base.events.map((e) => e.source.host));

  for (const f of files) {
    if (f === 'host-baseline.json') continue;
    for (const ev of planOf(f).events) {
      const pair = `${ev.source.type}/${ev.source.name}`;
      assert.ok(benignPairs.has(pair),
        `${f} emits ${pair}, which never occurs in benign traffic -- one terms agg finds the attack`);
      assert.ok(benignHosts.has(ev.source.host) || LOGGEN_HOSTS.includes(ev.source.host),
        `${f} emits host ${ev.source.host}, which never occurs in benign traffic`);
    }
  }
});

test('the host baseline keeps a false-positive floor of MITRE labels', () => {
  // If benign host traffic were entirely untagged, mitre.technique:* would
  // isolate the attack inside the host source -- the same oracle that
  // BASELINE_STRIP_MITRE=0 exists to prevent for log-generator's own output.
  const lines = linesOf(planOf('host-baseline.json'));
  const tagged = lines.filter((l) => JSON.parse(l).mitre).length;
  const pct = (tagged / lines.length) * 100;
  assert.ok(pct >= 4 && pct <= 20, `benign host traffic is ${pct.toFixed(1)}% tagged; want roughly 10%`);
});

test('bursts stay rigid while dwell absorbs the requested duration', () => {
  // The whole point of the rigid/elastic split. A brute force is 240 attempts in
  // 90 seconds; uniformly scaling that to the console's 2-hour option makes it
  // one attempt every 30 seconds, which is not a brute force and will not trip
  // any threshold rule a student writes.
  // Measured on ONE step. Spanning every WARN event would also cross the elastic
  // dwell between the guessing burst and the lockout messages, which is supposed
  // to stretch -- that is the elastic half doing its job, not a regression.
  const spans = UI_DURATIONS.map((d) => {
    const burst = planOf('T1110.001.json', d).events.filter((e) => /^Failed password/.test(e.message));
    return Math.max(...burst.map((e) => e.offset)) - Math.min(...burst.map((e) => e.offset));
  });
  for (const s of spans) {
    assert.ok(Math.abs(s - spans[0]) < 5, `burst span drifted across durations: ${spans}`);
  }
});

test('a playbook plans at every duration it advertises and refuses the rest', () => {
  for (const f of files) {
    if (f === 'host-baseline.json') continue;
    const pb = load(f);
    const min = emit.minSecondsFor(pb);
    for (const d of UI_DURATIONS) {
      if (d >= min) {
        const plan = planOf(f, d);
        const last = Math.max(...plan.events.map((e) => e.offset));
        assert.ok(last <= d, `${f} at ${d}s ran ${last - d}s past its deadline`);
        assert.ok(plan.events.length > 0);
      } else {
        assert.throws(
          () => planOf(f, d),
          /needs at least/,
          `${f} should refuse ${d}s rather than compress a burst into something absurd`
        );
      }
    }
  }
});

test('the same run id produces the same attack on every lane', () => {
  // Thirty lanes must see one exercise, not thirty. An instructor saying "there
  // are 245 events, find them" has to be right on all of them, and a retried
  // lane has to match the twenty-nine that did not fail.
  const pb = load('T1110.001.json');
  const once = () => emit.planTimeline(pb, {
    rng: emit.makeRng(emit.seedFrom('11111111-2222-3333-4444-555555555555')),
    requested: 300,
  }).events.map((e) => emit.toLine(e, 0)).join('');
  assert.strictEqual(once(), once());
});

test('one run reads as one adversary, not a shuffle', () => {
  // Entity coherence is what makes an event pivotable. log-generator randomises
  // every field of every line independently, which is why its output cannot be
  // followed even when the volume is right.
  const ips = new Set();
  for (const ev of planOf('T1110.001.json', 300).events) {
    const m = /from (\d+\.\d+\.\d+\.\d+) port/.exec(ev.message);
    if (m) ips.add(m[1]);
  }
  assert.strictEqual(ips.size, 1, `expected one attacker IP across the run, got ${[...ips]}`);
});

test('the emitter registers no SIGTERM handler', () => {
  // Abort is `kill -TERM -$PGID` and the cap is `timeout -k 30`. Node's default
  // terminates immediately, which is what makes both work. A handler doing async
  // flush work can outlive the 30s grace and be SIGKILLed mid-write, producing
  // the torn line openAppend() has to repair.
  assert.strictEqual(process.listenerCount('SIGTERM'), 0);
});

test('an event never contradicts itself about who or what it describes', () => {
  // Each {{token}} used to sample the pool independently, so one event could say
  // "Failed password for jsmith" and carry metadata.user=svc_backup. A student
  // pivoting on the structured field then gets a different answer than one
  // reading the message, and nothing in the data says which is right.
  // Bare account names only. "for apatel@corp.example from" in a mail-gateway
  // line is the same person as metadata.user=apatel, not a disagreement.
  for (const f of files) {
    for (const ev of planOf(f).events) {
      const m = /for ([^\s@]+) from/.exec(ev.message);
      if (m && ev.metadata && ev.metadata.user) {
        assert.strictEqual(ev.metadata.user, m[1],
          `${f}: message says ${m[1]} but metadata.user says ${ev.metadata.user}`);
      }
    }
  }
});

test('a pool still varies between events, or a spray is one account repeated', () => {
  const users = new Set();
  for (const ev of planOf('T1110.001.json', 300).events) {
    const m = /for (\S+) from/.exec(ev.message);
    if (m) users.add(m[1]);
  }
  assert.ok(users.size >= 3, `expected several accounts sprayed, got ${[...users]}`);
});

test('no event states the conclusion a student is meant to reach', () => {
  // The signal has to be in the SHAPE of the data, not in a sentence naming it.
  // A netflow record does not say "anomaly" — it reports bytes and timestamps,
  // and the analyst notices. A line reading "Periodic outbound connection
  // detected ... jitter<5%" hands over the finding and turns a hunt into
  // reading. Real auditd rule keys name what the rule watches, not the verdict
  // the analyst is supposed to draw from it.
  const VERDICT = /(suspect|anomal|beacon|inject(ion|ed)|credential-access|persistence|lateral-movement|weaken|encrypted|exfiltrat|malicious|compromis|intrusion|spray|staged|proc-inject|cred-access|hijack|\bdetected\b)/i;
  for (const f of files) {
    for (const ev of planOf(f).events) {
      assert.ok(!VERDICT.test(ev.message),
        `${f} states its own conclusion: ${ev.message.slice(0, 110)}`);
      for (const [k, v] of Object.entries(ev.metadata || {})) {
        assert.ok(!VERDICT.test(String(v)),
          `${f} metadata ${k}=${v} states the conclusion`);
      }
    }
  }
});

test('a chain runs its own scripted length, not a duration the console picked', () => {
  // resolveSelection gives chains duration:'' on purpose — the product decision
  // is that a chain runs its scripted length. The wrapper passes that through
  // as `--duration ''`, and parseArgs turns a valueless flag into boolean true.
  // Testing truthiness alone therefore sent `true` to parseDuration and threw,
  // so EVERY chain exited 4 with lines=0 while the console showed it running.
  const emitPath = path.join(P, 'utils', 'cc-emit.js');
  const src = fs.readFileSync(emitPath, 'utf8');
  assert.ok(/typeof args\.duration === 'string'/.test(src),
    'a valueless --duration must fall back to the playbook length, not be parsed');
  assert.throws(() => emit.parseDuration(true), /unparseable/,
    'parseDuration should still reject a non-string, so the guard above is load-bearing');
});

test('every chain playbook plans at its own nominal length', () => {
  for (const c of catalog.CHAINS) {
    const pb = load(`chain-${c.key}.json`);
    const plan = emit.planTimeline(pb, {
      rng: emit.makeRng(1), requested: Number(pb.nominal_seconds),
    });
    assert.ok(plan.events.length > 0, `chain ${c.key} produced no events`);
    assert.ok(Number(pb.nominal_seconds) >= emit.minSecondsFor(pb),
      `chain ${c.key} declares a nominal length shorter than its own bursts`);
  }
});

test('no metadata field has a vocabulary the benign floor never uses', () => {
  // The gap that let the worst oracle through. The pair test above checks
  // source.type/name/host; nothing checked METADATA VALUES, and the floor had
  // shipped event_action:"routine" on all 28 of its steps while the playbooks
  // used 33 other values and never "routine". One clause --
  //
  //     NOT loggen.metadata.event_action : "routine"
  //
  // -- returned every attack event in the index and no benign one: 100% recall,
  // 100% precision, every technique, all semester. Every field in this metadata
  // is mapped as an explicit keyword, so each one sits in Discover's field list
  // with a top-values popover; a field whose values split cleanly on
  // attack-vs-benign is not a field, it is the answer.
  //
  // Subset, not overlap: ONE attack-only value is a complete filter on its own.
  const vocab = (names) => {
    const out = new Map();
    for (const f of names) {
      for (const line of linesOf(planOf(f))) {
        for (const [k, v] of Object.entries(JSON.parse(line).metadata || {})) {
          if (typeof v !== 'string' && typeof v !== 'number') continue;
          if (!out.has(k)) out.set(k, new Set());
          out.get(k).add(String(v));
        }
      }
    }
    return out;
  };

  const benign = vocab(['host-baseline.json']);
  const attack = vocab(files.filter((f) => f !== 'host-baseline.json'));

  const benignAll = new Set();
  for (const set of benign.values()) for (const v of set) benignAll.add(v);

  const leaks = [];
  for (const [key, values] of attack) {
    const floor = benign.get(key) || new Set();
    // Only CLOSED vocabularies can become one-click filters. Discover shows a
    // keyword field's top values in a popover, so a field with a dozen values
    // that split cleanly on attack-vs-benign hands the answer over; a field
    // with thousands (addresses, file paths) shows the attacker's value as one
    // row among thousands, which is an indicator a student has to WORK for --
    // exactly what the exercise is meant to reward. Demanding the floor also
    // pre-enumerate every staging path an attacker might pick would be
    // impossible and would delete the real indicators along with the oracles.
    if (floor.size > 50) continue;
    // Fall back to the WHOLE benign vocabulary, not just this field's. Pools are
    // shared, so an account that shows up benignly as metadata.user is an
    // ordinary account whether or not one sampled day happened to name it as a
    // target_user. What matters is whether a value exists in benign traffic at
    // all -- that is what makes it a filter.
    const only = [...values].filter((v) => !floor.has(v) && !benignAll.has(v));
    if (only.length) leaks.push(`${key}: ${only.slice(0, 6).join(', ')}`);
  }
  assert.deepEqual(leaks, [], `attack-only metadata values are one-click answer keys:\n  ${leaks.join('\n  ')}`);
});

test('the benign floor uses every address space the attacks use', () => {
  // The vocabulary test above deliberately skips fields with large value sets,
  // because demanding the floor pre-enumerate every attacker address would be
  // impossible. That exemption left a hole big enough to drive the second-worst
  // oracle through: the floor was 300 addresses of pure RFC1918 while ten
  // playbooks resolved their adversary into TEST-NET, so
  //
  //     NOT loggen.metadata.src_ip : 10.*
  //
  // returned 6,151 attack events and zero benign ones.
  //
  // Worse than the filter is the habit. A student who learns "the intruder is
  // the unfamiliar address" has learned something that fails on every intrusion
  // that matters, because by the time you see an adversary they are usually
  // inside your address space using an account you issued them.
  //
  // So the assertion is on the SPACE, not the values: whatever /8 an attack can
  // come from, ordinary traffic must come from it too.
  const spaceOf = (addr) => String(addr).split('.')[0];
  const spaces = (names) => {
    const out = new Set();
    for (const f of names) {
      for (const line of linesOf(planOf(f))) {
        const md = JSON.parse(line).metadata || {};
        for (const key of ['src_ip', 'dst_ip']) {
          if (md[key]) out.add(spaceOf(md[key]));
        }
      }
    }
    return out;
  };

  const benign = spaces(['host-baseline.json']);
  const attack = spaces(files.filter((f) => f !== 'host-baseline.json'));
  const only = [...attack].filter((s) => !benign.has(s));
  assert.deepEqual(only, [], `attack-only address spaces ${only.join(', ')} — `
    + `"not one of ours" is a one-click filter, and the wrong lesson`);
});
