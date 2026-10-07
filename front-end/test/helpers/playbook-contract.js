// ============================================================================
// The playbook contract, as reusable assertions.
//
// Every function here was lifted VERBATIM out of test/loggen-playbooks.test.js.
// Its 21 tests encoded what a valid cc-emit playbook IS, but they encoded it as
// twenty-one for-loops over `readdirSync(playbooks/)` -- which meant the contract
// only ever applied to the fifteen playbooks that happen to sit on disk.
//
// E4 compiles playbooks at RUNTIME from a client profile. A compiled playbook is
// never on disk, is never reviewed by a human, and is different on every
// engagement -- so it is exactly the artefact that most needs the contract, and
// the one the file-walking version could not reach. Hence this module: same
// assertions, same messages, same semantics, addressable by a caller that holds
// a playbook OBJECT rather than a filename.
//
// WHY EACH ONE EXISTS is documented at the function. In short, every failure
// these catch is SILENT in production -- no error, no warning, just an exercise
// that is either broken or already solved:
//
//   * an unresolved {{token}} ships literal braces to Kibana
//   * a seventh top-level key falls to dynamic mapping under ecs@mappings and
//     silently REJECTS documents
//   * an untagged attack event is dropped by the agent's drop_event processor
//   * a (source.type, source.name) pair, metadata value or address space that
//     only ever occurs during an attack is a one-terms-agg answer key
//
// House rule: these functions ASSERT. They do not return findings and they do
// not collect warnings. A contract that can be ignored is documentation.
// ============================================================================
'use strict';

const assert = require('assert');
const path = require('path');

const P = path.join(__dirname, '..', '..', 'src', 'incident');
const emit = require(path.join(P, 'cc-emit.js'));

/** The five durations the Attack Console offers. */
const UI_DURATIONS = [300, 900, 1800, 3600, 7200];

/** Hosts log-generator's own baseline emits, observed on a deployed lane. */
const LOGGEN_HOSTS = [
  'api.example.com', 'web-01', 'auth-01', 'k8s-01',
  'db-01', 'firewall-01', 'app-server-01', 'srv-prod-01',
];

const ENVELOPE_KEYS = ['timestamp', 'level', 'source', 'message', 'metadata', 'mitre'];

/**
 * The seed the on-disk contract tests have always used.
 *
 * Fixed, not random: a contract that passes on Tuesday and fails on Wednesday
 * teaches the team to re-run CI instead of reading the failure.
 */
const FIXED_SEED = 'fixed-seed';

// ---------------------------------------------------------------------------
// Plumbing. Every assertion below plans the playbook the same way the on-disk
// tests did -- default duration is the playbook's own nominal length, floored at
// its rigid burst time so a playbook can never be asked for less than it needs.
// ---------------------------------------------------------------------------

function planOf(playbook, opts) {
  const o = opts || {};
  const rng = o.rng
    || emit.makeRng(typeof o.seed === 'number' ? o.seed : emit.seedFrom(o.seed || FIXED_SEED));
  const requested = o.requested == null
    ? Math.max(emit.minSecondsFor(playbook), Number(playbook.nominal_seconds))
    : o.requested;
  return emit.planTimeline(playbook, { rng, requested });
}

const linesOf = (plan) => plan.events.map((ev) => emit.toLine(ev, Date.now()));

/** What to call this playbook in a failure message. */
const labelOf = (opts, playbook) => (opts && opts.label)
  || (playbook && playbook.name) || 'playbook';

/** Accept a playbook or a {playbook,label} pair -- callers hold both. */
function subject(playbook, opts) {
  const o = opts || {};
  const pb = playbook && playbook.steps ? playbook : (playbook && playbook.playbook);
  const label = o.label || (playbook && playbook.label) || labelOf(null, pb);
  return { pb, plan: o.plan || planOf(pb, o), label };
}

// ---------------------------------------------------------------------------
// The wire format
// ---------------------------------------------------------------------------

/**
 * No playbook ships an unresolved {{token}}.
 *
 * log-generator itself ships literal "{clientIP}" in its metadata at the pinned
 * commit. That is the most obvious synthetic tell there is, and this emitter
 * exists partly to not reproduce it.
 */
function assertNoUnresolvedTokens(playbook, opts) {
  const { plan, label } = subject(playbook, opts);
  for (const line of linesOf(plan)) {
    assert.ok(!/\{\{/.test(line), `${label} emitted an unresolved token: ${line.slice(0, 160)}`);
  }
}

/**
 * Every event carries exactly the six envelope keys and nothing more.
 *
 * A seventh top-level key falls to dynamic mapping under ecs@mappings, where a
 * name like source.ip is typed `ip` and then REJECTS every document whose value
 * is not an address. No warning, no error, no events.
 */
function assertSixKeyEnvelope(playbook, opts) {
  const { plan, label } = subject(playbook, opts);
  for (const line of linesOf(plan)) {
    const doc = JSON.parse(line);
    for (const k of Object.keys(doc)) {
      assert.ok(ENVELOPE_KEYS.includes(k), `${label} emitted top-level key "${k}"`);
    }
    assert.ok(doc.timestamp && doc.level && doc.source && doc.metadata !== undefined);
    assert.ok(doc.source.type && doc.source.name && doc.source.host);
  }
}

/**
 * Every attack event is tagged, or the agent silently drops it.
 *
 * The sensor's drop_event processor keeps attack traffic only where
 * mitre.technique is present. An untagged step therefore produces an attack
 * that ran, exited 0, reported lines>0 -- and put nothing in the index.
 */
function assertEveryAttackEventTagged(playbook, opts) {
  const { plan, label } = subject(playbook, opts);
  for (const line of linesOf(plan)) {
    const doc = JSON.parse(line);
    assert.ok(doc.mitre && doc.mitre.technique, `${label} emitted an untagged event`);
  }
}

/**
 * The serialization the wrapper greps for is exactly what is emitted.
 *
 * count_lines() in cc-attack.sh is `grep -c '"technique":"'`. If JSON.stringify
 * ever spaced that differently the console would report lines=0 -- "the attack
 * ran and nothing happened", the single most misleading output this can give.
 */
function assertGrepSerialization(playbook, opts) {
  const { plan } = subject(playbook, opts);
  const line = linesOf(plan)[0];
  assert.ok(line.includes('"technique":"'), 'the grep contract in cc-attack.sh no longer matches');
}

// ---------------------------------------------------------------------------
// The anti-oracle assertions.
//
// These are the reason the original file exists. A student with Discover open
// and one terms aggregation must not be able to separate attack from benign on
// any field the platform maps as a keyword.
// ---------------------------------------------------------------------------

/**
 * The benign floor covers every (source.type/name) pair and host the attacks use.
 *
 * It is not enough for source.type to occur in benign traffic: loggen.source.name
 * and loggen.source.host are mapped keywords sitting in Discover's field list
 * right beside it. A pair or host that appears only during an attack is a single
 * terms aggregation away from ending the exercise.
 *
 * `opts.attacks` is the list of attack playbooks (or {playbook,label} pairs) that
 * must live inside this floor.
 */
function assertSourceVocabularySubset(floor, opts) {
  const o = opts || {};
  const base = o.floorPlan || planOf(floor, o);
  const benignPairs = new Set(base.events.map((e) => `${e.source.type}/${e.source.name}`));
  const benignHosts = new Set(base.events.map((e) => e.source.host));
  const extraHosts = o.extraHosts || LOGGEN_HOSTS;

  for (const entry of o.attacks || []) {
    const { plan, label } = subject(entry, entry);
    for (const ev of plan.events) {
      const pair = `${ev.source.type}/${ev.source.name}`;
      assert.ok(benignPairs.has(pair),
        `${label} emits ${pair}, which never occurs in benign traffic -- one terms agg finds the attack`);
      assert.ok(benignHosts.has(ev.source.host) || extraHosts.includes(ev.source.host),
        `${label} emits host ${ev.source.host}, which never occurs in benign traffic`);
    }
  }
}

/**
 * No metadata field has a vocabulary the benign floor never uses.
 *
 * The gap that let the worst oracle through. The pair test above checks
 * source.type/name/host; nothing checked METADATA VALUES, and the floor had
 * shipped event_action:"routine" on all 28 of its steps while the playbooks
 * used 33 other values and never "routine". One clause --
 *
 *     NOT loggen.metadata.event_action : "routine"
 *
 * -- returned every attack event in the index and no benign one: 100% recall,
 * 100% precision, every technique, all semester. Every field in this metadata
 * is mapped as an explicit keyword, so each one sits in Discover's field list
 * with a top-values popover; a field whose values split cleanly on
 * attack-vs-benign is not a field, it is the answer.
 *
 * Subset, not overlap: ONE attack-only value is a complete filter on its own.
 */
function assertMetadataVocabularySubset(floor, opts) {
  const o = opts || {};
  const vocabOf = (plans) => {
    const out = new Map();
    for (const plan of plans) {
      for (const line of linesOf(plan)) {
        for (const [k, v] of Object.entries(JSON.parse(line).metadata || {})) {
          if (typeof v !== 'string' && typeof v !== 'number') continue;
          if (!out.has(k)) out.set(k, new Set());
          out.get(k).add(String(v));
        }
      }
    }
    return out;
  };

  const benign = vocabOf([o.floorPlan || planOf(floor, o)]);
  const attack = vocabOf((o.attacks || []).map((e) => subject(e, e).plan));

  const benignAll = new Set();
  for (const set of benign.values()) for (const v of set) benignAll.add(v);

  const leaks = [];
  for (const [key, values] of attack) {
    const floorVals = benign.get(key) || new Set();
    // Only CLOSED vocabularies can become one-click filters. Discover shows a
    // keyword field's top values in a popover, so a field with a dozen values
    // that split cleanly on attack-vs-benign hands the answer over; a field
    // with thousands (addresses, file paths) shows the attacker's value as one
    // row among thousands, which is an indicator a student has to WORK for --
    // exactly what the exercise is meant to reward. Demanding the floor also
    // pre-enumerate every staging path an attacker might pick would be
    // impossible and would delete the real indicators along with the oracles.
    if (floorVals.size > 50) continue;
    // Fall back to the WHOLE benign vocabulary, not just this field's. Pools are
    // shared, so an account that shows up benignly as metadata.user is an
    // ordinary account whether or not one sampled day happened to name it as a
    // target_user. What matters is whether a value exists in benign traffic at
    // all -- that is what makes it a filter.
    const only = [...values].filter((v) => !floorVals.has(v) && !benignAll.has(v));
    if (only.length) leaks.push(`${key}: ${only.slice(0, 6).join(', ')}`);
  }
  assert.deepEqual(leaks, [], `attack-only metadata values are one-click answer keys:\n  ${leaks.join('\n  ')}`);
}

/**
 * The benign floor uses every address space the attacks use.
 *
 * The vocabulary test above deliberately skips fields with large value sets,
 * because demanding the floor pre-enumerate every attacker address would be
 * impossible. That exemption left a hole big enough to drive the second-worst
 * oracle through: the floor was 300 addresses of pure RFC1918 while ten
 * playbooks resolved their adversary into TEST-NET, so
 *
 *     NOT loggen.metadata.src_ip : 10.*
 *
 * returned 6,151 attack events and zero benign ones.
 *
 * Worse than the filter is the habit. A student who learns "the intruder is
 * the unfamiliar address" has learned something that fails on every intrusion
 * that matters, because by the time you see an adversary they are usually
 * inside your address space using an account you issued them.
 *
 * So the assertion is on the SPACE, not the values: whatever /8 an attack can
 * come from, ordinary traffic must come from it too.
 */
function assertAddressSpaceSubset(floor, opts) {
  const o = opts || {};
  const spaceOf = (addr) => String(addr).split('.')[0];
  const spaces = (plans) => {
    const out = new Set();
    for (const plan of plans) {
      for (const line of linesOf(plan)) {
        const md = JSON.parse(line).metadata || {};
        for (const key of ['src_ip', 'dst_ip']) {
          if (md[key]) out.add(spaceOf(md[key]));
        }
      }
    }
    return out;
  };

  const benign = spaces([o.floorPlan || planOf(floor, o)]);
  const attack = spaces((o.attacks || []).map((e) => subject(e, e).plan));
  const only = [...attack].filter((s) => !benign.has(s));
  assert.deepEqual(only, [], `attack-only address spaces ${only.join(', ')} — `
    + `"not one of ours" is a one-click filter, and the wrong lesson`);
}

/**
 * All three anti-oracle checks against one floor.
 *
 * Source pairs, metadata vocabularies AND address spaces, because a floor that
 * covers two of the three still hands the exercise over on the third. The
 * compiler emits (floor, attack) as a matched pair and has to clear all of it.
 */
function assertFloorCoversAttackValues(floor, opts) {
  const o = Object.assign({}, opts || {});
  // Plan the floor ONCE. It is the expensive half (13k events on the baked
  // baseline) and all three checks want the identical sample, not three
  // independent draws that could disagree about what benign traffic contains.
  o.floorPlan = o.floorPlan || planOf(floor, o);
  assertSourceVocabularySubset(floor, o);
  assertMetadataVocabularySubset(floor, o);
  assertAddressSpaceSubset(floor, o);
}

/**
 * The floor keeps a false-positive floor of MITRE labels.
 *
 * If benign traffic were entirely untagged, mitre.technique:* would isolate the
 * attack in one click -- the same oracle that BASELINE_STRIP_MITRE=0 exists to
 * prevent for log-generator's own output. Roughly one benign event in ten
 * carries a label, so the field is a lead rather than an answer.
 */
function assertBenignMitreFloor(playbook, opts) {
  const o = opts || {};
  const { plan } = subject(playbook, o);
  const min = o.min == null ? 4 : o.min;
  const max = o.max == null ? 20 : o.max;
  const lines = linesOf(plan);
  const tagged = lines.filter((l) => JSON.parse(l).mitre).length;
  const pct = (tagged / lines.length) * 100;
  assert.ok(pct >= min && pct <= max, `benign host traffic is ${pct.toFixed(1)}% tagged; want roughly 10%`);
}

/**
 * No event states the conclusion a student is meant to reach.
 *
 * The signal has to be in the SHAPE of the data, not in a sentence naming it.
 * A netflow record does not say "anomaly" — it reports bytes and timestamps,
 * and the analyst notices. A line reading "Periodic outbound connection
 * detected ... jitter<5%" hands over the finding and turns a hunt into
 * reading. Real auditd rule keys name what the rule watches, not the verdict
 * the analyst is supposed to draw from it.
 */
const VERDICT = /(suspect|anomal|beacon|inject(ion|ed)|credential-access|persistence|lateral-movement|weaken|encrypted|exfiltrat|malicious|compromis|intrusion|spray|staged|proc-inject|cred-access|hijack|\bdetected\b)/i;

function assertStatesNoConclusion(playbook, opts) {
  const { plan, label } = subject(playbook, opts);
  for (const ev of plan.events) {
    assert.ok(!VERDICT.test(ev.message),
      `${label} states its own conclusion: ${ev.message.slice(0, 110)}`);
    for (const [k, v] of Object.entries(ev.metadata || {})) {
      assert.ok(!VERDICT.test(String(v)),
        `${label} metadata ${k}=${v} states the conclusion`);
    }
  }
}

// ---------------------------------------------------------------------------
// Coherence: one run has to read as one adversary
// ---------------------------------------------------------------------------

/**
 * An event never contradicts itself about who or what it describes.
 *
 * Each {{token}} used to sample the pool independently, so one event could say
 * "Failed password for jsmith" and carry metadata.user=svc_backup. A student
 * pivoting on the structured field then gets a different answer than one
 * reading the message, and nothing in the data says which is right.
 * Bare account names only. "for apatel@corp.example from" in a mail-gateway
 * line is the same person as metadata.user=apatel, not a disagreement.
 */
function assertNoSelfContradiction(playbook, opts) {
  const { plan, label } = subject(playbook, opts);
  for (const ev of plan.events) {
    const m = /for ([^\s@]+) from/.exec(ev.message);
    if (m && ev.metadata && ev.metadata.user) {
      assert.strictEqual(ev.metadata.user, m[1],
        `${label}: message says ${m[1]} but metadata.user says ${ev.metadata.user}`);
    }
  }
}

/**
 * One run reads as one adversary, not a shuffle.
 *
 * Entity coherence is what makes an event pivotable. log-generator randomises
 * every field of every line independently, which is why its output cannot be
 * followed even when the volume is right.
 */
function assertOneAdversaryNotAShuffle(playbook, opts) {
  const o = opts || {};
  const { plan } = subject(playbook, Object.assign({ requested: 300 }, o));
  const re = o.extract || /from (\d+\.\d+\.\d+\.\d+) port/;
  const ips = new Set();
  for (const ev of plan.events) {
    const m = re.exec(ev.message);
    if (m) ips.add(m[1]);
  }
  assert.strictEqual(ips.size, 1, `expected one attacker IP across the run, got ${[...ips]}`);
}

/**
 * A pool still varies between events, or a spray is one account repeated.
 *
 * The mirror image of the assertion above: entities are fixed for the run, pools
 * are re-sampled per event. Freeze both and "many accounts, one source" -- the
 * actual signature -- disappears.
 */
function assertPoolVariesBetweenEvents(playbook, opts) {
  const o = opts || {};
  const { plan } = subject(playbook, Object.assign({ requested: 300 }, o));
  const re = o.extract || /for (\S+) from/;
  const min = o.min == null ? 3 : o.min;
  const users = new Set();
  for (const ev of plan.events) {
    const m = re.exec(ev.message);
    if (m) users.add(m[1]);
  }
  assert.ok(users.size >= min, `expected several accounts sprayed, got ${[...users]}`);
}

/**
 * The same run id produces the same attack on every lane.
 *
 * Thirty lanes must see one exercise, not thirty. An instructor saying "there
 * are 245 events, find them" has to be right on all of them, and a retried
 * lane has to match the twenty-nine that did not fail.
 */
function assertDeterministicPerRunId(playbook, opts) {
  const o = opts || {};
  const runId = o.runId || '11111111-2222-3333-4444-555555555555';
  // 300s unless the playbook's own rigid floor needs more. Every on-disk attack
  // playbook fits inside 300, so this is the historical value for all of them;
  // the clamp only matters for a compiled scenario, which can be longer.
  const requested = o.requested == null
    ? Math.max(300, emit.minSecondsFor(playbook))
    : o.requested;
  const once = () => emit.planTimeline(playbook, {
    rng: emit.makeRng(emit.seedFrom(runId)),
    requested,
  }).events.map((e) => emit.toLine(e, 0)).join('');
  assert.strictEqual(once(), once());
}

// ---------------------------------------------------------------------------
// Timing
// ---------------------------------------------------------------------------

/**
 * Bursts stay rigid while dwell absorbs the requested duration.
 *
 * The whole point of the rigid/elastic split. A brute force is 240 attempts in
 * 90 seconds; uniformly scaling that to the console's 2-hour option makes it
 * one attempt every 30 seconds, which is not a brute force and will not trip
 * any threshold rule a student writes.
 * Measured on ONE step. Spanning every WARN event would also cross the elastic
 * dwell between the guessing burst and the lockout messages, which is supposed
 * to stretch -- that is the elastic half doing its job, not a regression.
 */
function assertRigidBurstsElasticDwell(playbook, opts) {
  const o = opts || {};
  const match = o.match || /^Failed password/;
  const durations = o.durations || UI_DURATIONS;
  const tolerance = o.tolerance == null ? 5 : o.tolerance;
  const spans = durations.map((d) => {
    const burst = planOf(playbook, Object.assign({}, o, { requested: d }))
      .events.filter((e) => match.test(e.message));
    // Guard, not a change of contract: an empty burst makes the span NaN, and
    // NaN fails the comparison below with a message that says nothing about why.
    // Never fires for a playbook that actually contains the burst being measured.
    assert.ok(burst.length > 0,
      `${labelOf(o, playbook)} has no step matching ${match} to measure at ${d}s`);
    return Math.max(...burst.map((e) => e.offset)) - Math.min(...burst.map((e) => e.offset));
  });
  for (const s of spans) {
    assert.ok(Math.abs(s - spans[0]) < tolerance, `burst span drifted across durations: ${spans}`);
  }
}

/**
 * A playbook plans at every duration it advertises and refuses the rest.
 *
 * Refusing is the only honest behaviour below the rigid floor: asking for five
 * minutes of a beacon whose point is ten minutes of check-ins has no right
 * answer -- compress it and it is not a beacon, truncate it and half the story
 * is gone. The console disables the option rather than letting the instructor
 * discover it lane by lane.
 */
function assertPlansAtEveryDuration(playbook, opts) {
  const o = opts || {};
  const label = labelOf(o, playbook);
  const durations = o.durations || UI_DURATIONS;
  const min = emit.minSecondsFor(playbook);
  for (const d of durations) {
    if (d >= min) {
      const plan = planOf(playbook, Object.assign({}, o, { requested: d }));
      const last = Math.max(...plan.events.map((e) => e.offset));
      assert.ok(last <= d, `${label} at ${d}s ran ${last - d}s past its deadline`);
      assert.ok(plan.events.length > 0);
    } else {
      assert.throws(
        () => planOf(playbook, Object.assign({}, o, { requested: d })),
        /needs at least/,
        `${label} should refuse ${d}s rather than compress a burst into something absurd`
      );
    }
  }
}

module.exports = {
  // plumbing
  planOf,
  linesOf,
  emit,
  UI_DURATIONS,
  LOGGEN_HOSTS,
  ENVELOPE_KEYS,
  FIXED_SEED,
  VERDICT,
  // wire format
  assertNoUnresolvedTokens,
  assertSixKeyEnvelope,
  assertEveryAttackEventTagged,
  assertGrepSerialization,
  // anti-oracle
  assertSourceVocabularySubset,
  assertMetadataVocabularySubset,
  assertAddressSpaceSubset,
  assertFloorCoversAttackValues,
  assertBenignMitreFloor,
  assertStatesNoConclusion,
  // coherence
  assertNoSelfContradiction,
  assertOneAdversaryNotAShuffle,
  assertPoolVariesBetweenEvents,
  assertDeterministicPerRunId,
  // timing
  assertRigidBurstsElasticDwell,
  assertPlansAtEveryDuration,
};
