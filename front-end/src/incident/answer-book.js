/**
 * ============================================================================
 * INSTRUCTOR ANSWER BOOK — the log lines one attack actually wrote
 * ============================================================================
 * answer-key.js already computes the GRADED truth: which techniques fired and
 * which values are indicators. That is what scoring.js needs. It is not what a
 * human marking thirty submissions needs, because it never shows the evidence
 * itself — an instructor reading `techniques: [T1110.001]` and `iocs: [...]`
 * still has to go and find out what the attack looked like in Kibana before
 * they can tell whether a student's answer is right.
 *
 * So this is the same computation projected for a person: the concrete messages,
 * grouped the way they appear in Discover, with the queries that return them and
 * the counts those queries must produce.
 *
 * WHY IT IS RECOMPUTED, NOT STORED OR OBSERVED
 * ----------------------------------------------------------------------------
 * Same reasoning as answer-key.js, and it is worth restating because it is what
 * makes this feature cheap: cc-emit is deterministic on the run id, so
 * re-running planTimeline() with the same seed reproduces exactly the event list
 * every lane wrote. No Elasticsearch query, no guest round-trip, no new column.
 * The CLE launch path stores neither `playbook` nor `answer_key`, and does not
 * need to — the run row carries the seed (run_id), the selection, and the
 * duration, which is the complete input.
 *
 * A consequence worth knowing: this book is valid for a run that FAILED on every
 * lane. It describes what the attack WOULD have written, which is exactly what
 * an instructor needs when deciding whether a student could reasonably have
 * found anything.
 *
 * WHY THE GROUPING IS BY SOURCE AND NOT BY PLAYBOOK STEP
 * ----------------------------------------------------------------------------
 * planTimeline() does not tag an event with the step that produced it, and the
 * per-step message sequence cannot be reconstructed without replaying the
 * engine's RNG in lockstep — duplicating cc-emit's inner loop here would be a
 * second implementation to keep in sync, and a silently wrong one the first time
 * the engine changes.
 *
 * Grouping by (technique, source.type, source.name, level) needs none of that
 * and is closer to what the instructor is looking at anyway: Discover groups by
 * source, not by the generator's internal structure. The playbook's step
 * ORDERING still travels, separately, as the timeline.
 *
 * THE QUERIES ARE THE POINT
 * ----------------------------------------------------------------------------
 * There is deliberately NO field that isolates the attack — closing those
 * oracles is most of what this system's design is about, and `log.file.path`
 * was dropped from both agent inputs precisely so a student could not filter on
 * it. That leaves the instructor in the same position as the student, which is
 * correct for the exercise and useless for marking.
 *
 * The resolution is that an IOC-based query is not an oracle: it requires
 * already knowing the attacker's address, which is the thing the student is
 * being asked to find. So the book ships the queries keyed on the run's own
 * indicators, each with the count it must return. An instructor pastes one in
 * and knows immediately whether the lane ingested the attack, and a student's
 * answer can be checked against a number rather than an impression.
 */

'use strict';

const emit = require('./cc-emit');
const { compileAnswerKey, loadFloorPlaybook } = require('./answer-key');

const ANSWER_BOOK_VERSION = 1;

/** How many worked examples to show per distinct message shape. */
const EXAMPLES_PER_PATTERN = 3;

/** Kibana field prefix. The ndjson parser lands everything under `loggen`. */
const F = {
  type: 'loggen.source.type',
  name: 'loggen.source.name',
  host: 'loggen.source.host',
  level: 'loggen.level',
  message: 'loggen.message',
  md: 'loggen.metadata',
};

/**
 * Collapse an event message to the shape shared by its siblings.
 *
 * Every event carries fresh random ports, pids and byte counts, so raw messages
 * are almost all distinct and a frequency table over them tells an instructor
 * nothing. Normalising the variable parts turns 2,916 unique strings into the
 * four sentences the attack actually says, which is the useful view.
 *
 * Addresses are replaced BEFORE bare digits, or an address would be eaten a
 * component at a time and every distinct IP would collapse to the same
 * meaningless `#.#.#.#`.
 */
function patternOf(message) {
  return String(message || '')
    .replace(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g, '<addr>')
    .replace(/\b[0-9a-f]{8,}\b/gi, '<hash>')
    .replace(/\d+/g, '#');
}

/** A stable key for one activity group. */
function groupKey(ev) {
  return [
    ev.technique || '-',
    (ev.source && ev.source.type) || '-',
    (ev.source && ev.source.name) || '-',
    ev.level || '-',
  ].join('|');
}

/** KQL needs its double quotes and backslashes escaped inside a phrase. */
function kqlValue(v) {
  return String(v).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

/**
 * Which metadata field an IOC lives in, so the query can name it exactly.
 *
 * A phrase match on the right keyword field is exact and fast; falling back to
 * the message is neither, but it is correct for an indicator that only ever
 * appears in prose (a staging path inside a command line, say).
 */
function fieldForIoc(ioc, events) {
  const value = String(ioc.value);
  const counts = new Map();
  for (const ev of events) {
    for (const [k, v] of Object.entries((ev && ev.metadata) || {})) {
      if (String(v) === value) counts.set(k, (counts.get(k) || 0) + 1);
    }
  }
  if (!counts.size) return null;
  // The field it appears in most often. An address can be both a src_ip on the
  // auth events and a dst_ip on the firewall ones; the instructor wants the one
  // that returns the most of the attack.
  return [...counts.entries()].sort((a, b) => b[1] - a[1])[0][0];
}

/**
 * Build the instructor's view of one run.
 *
 * @param {object} run      the cybercore_incident_run row (needs run_id, duration_seconds)
 * @param {object} opts
 * @param {string|object} opts.playbook  the same playbook the guest was handed
 * @param {object} [opts.floor]          the benign floor, for look-alikes
 * @param {string} [opts.label]          human name for the selection
 */
function buildAnswerBook(run, opts = {}) {
  if (!run || !run.run_id) throw new Error('buildAnswerBook: a run with run_id is required');

  const playbook = typeof opts.playbook === 'string' ? JSON.parse(opts.playbook) : opts.playbook;
  if (!playbook || !Array.isArray(playbook.steps) || !playbook.steps.length) {
    throw new Error('buildAnswerBook: a playbook with steps is required');
  }
  const floor = opts.floor || loadFloorPlaybook();

  // The three inputs that must match the guest exactly. Wrong here and the book
  // describes an attack that never ran — see answer-key.js's header.
  const requested = Number(run.duration_seconds) > 0
    ? Number(run.duration_seconds)
    : Number(playbook.nominal_seconds);
  const plan = emit.planTimeline(playbook, {
    rng: emit.makeRng(emit.seedFrom(run.run_id)),
    requested,
  });
  const events = plan.events;

  // The graded key is the authority on techniques and indicators; recomputing
  // that classification here would be a second opinion nobody asked for.
  const key = compileAnswerKey({
    runId: run.run_id,
    playbook,
    floor,
    requestedSeconds: requested,
  });

  // ── Activity groups: what a person sees in Discover ──────────────────────
  const groups = new Map();
  for (const ev of events) {
    const gk = groupKey(ev);
    if (!groups.has(gk)) {
      groups.set(gk, {
        technique: ev.technique || null,
        tactic: ev.tactic || null,
        source_type: (ev.source && ev.source.type) || null,
        source_name: (ev.source && ev.source.name) || null,
        level: ev.level || null,
        hosts: new Set(),
        first_offset_s: ev.offset,
        last_offset_s: ev.offset,
        event_count: 0,
        _patterns: new Map(),
      });
    }
    const g = groups.get(gk);
    g.event_count += 1;
    if (ev.source && ev.source.host) g.hosts.add(ev.source.host);
    if (ev.offset < g.first_offset_s) g.first_offset_s = ev.offset;
    if (ev.offset > g.last_offset_s) g.last_offset_s = ev.offset;

    const pat = patternOf(ev.message);
    if (!g._patterns.has(pat)) g._patterns.set(pat, { pattern: pat, count: 0, examples: [] });
    const p = g._patterns.get(pat);
    p.count += 1;
    if (p.examples.length < EXAMPLES_PER_PATTERN) p.examples.push(ev.message);
  }

  const activity = [...groups.values()]
    .map((g) => ({
      technique: g.technique,
      tactic: g.tactic,
      source_type: g.source_type,
      source_name: g.source_name,
      level: g.level,
      hosts: [...g.hosts].sort(),
      first_offset_s: Math.round(g.first_offset_s),
      last_offset_s: Math.round(g.last_offset_s),
      event_count: g.event_count,
      messages: [...g._patterns.values()].sort((a, b) => b.count - a.count),
      // The query that returns exactly this group on a lane, scoped to the run
      // window by the instructor's own time picker.
      kql: [
        `${F.type} : "${kqlValue(g.source_type)}"`,
        `${F.name} : "${kqlValue(g.source_name)}"`,
        `${F.level} : "${kqlValue(g.level)}"`,
      ].join(' and '),
    }))
    .sort((a, b) => (a.first_offset_s - b.first_offset_s) || b.event_count - a.event_count);

  // ── Where the events landed, for a quick sanity read ─────────────────────
  const bySource = new Map();
  for (const ev of events) {
    const k = `${(ev.source && ev.source.type) || '-'}/${(ev.source && ev.source.name) || '-'}`;
    bySource.set(k, (bySource.get(k) || 0) + 1);
  }

  // ── The queries an instructor actually pastes ────────────────────────────
  //
  // Ordered most-selective first. Each carries the count it must return, which
  // is what turns "did this lane get the attack" from a judgement into a check.
  const queries = [];
  for (const ioc of key.iocs || []) {
    const field = fieldForIoc(ioc, events);
    const kql = field
      ? `${F.md}.${field} : "${kqlValue(ioc.value)}"`
      : `${F.message} : "${kqlValue(ioc.value)}"`;
    let hits = 0;
    for (const ev of events) {
      if (field) {
        if (String((ev.metadata || {})[field]) === String(ioc.value)) hits += 1;
      } else if (String(ev.message || '').includes(ioc.value)) hits += 1;
    }
    queries.push({
      label: `${ioc.key || 'indicator'}: ${ioc.value}`,
      kql,
      expect_events: hits,
      why: field
        ? `The run's ${ioc.key || 'indicator'}. A student who found this value has found the attack.`
        : 'Appears only inside message text, so this is a full-text match rather than a field filter.',
    });
  }
  queries.sort((a, b) => b.expect_events - a.expect_events);

  // ── Benign traffic that resembles the attack ─────────────────────────────
  //
  // The floor deliberately emits from the same (type, name) pairs and tags some
  // of its own events with real technique ids, so a student CAN correctly flag
  // something that is not the attack. An instructor marking without knowing
  // which look-alikes exist will mark a defensible answer wrong.
  const attackPairs = new Set(activity.map((a) => `${a.source_type}/${a.source_name}`));
  const lookAlikes = [];
  for (const step of floor.steps || []) {
    const src = step.source || {};
    const pair = `${src.type}/${src.name}`;
    if (!attackPairs.has(pair)) continue;
    lookAlikes.push({
      source_type: src.type || null,
      source_name: src.name || null,
      technique: step.technique || null,
      why: step.technique
        ? `Benign, and deliberately tagged ${step.technique}. A student reporting it found what was planted; score partial, never wrong.`
        : 'Ordinary traffic from the same source the attack used. Expect false positives here.',
      kql: `${F.type} : "${kqlValue(src.type)}" and ${F.name} : "${kqlValue(src.name)}"`,
    });
  }

  return {
    version: ANSWER_BOOK_VERSION,
    run_id: run.run_id,
    generated_at: new Date().toISOString(),
    selection: {
      mode: run.mode || null,
      label: opts.label || run.technique_id || run.chain_key || run.tactic_id || null,
      technique_id: run.technique_id || null,
      tactic_id: run.tactic_id || null,
      chain_key: run.chain_key || null,
      duration_seconds: Math.round(requested),
    },
    totals: {
      // The number every lane must show. The emitter is deterministic on the
      // run id, so a lane reporting anything else did not ingest all of it.
      events_per_lane: events.length,
      activity_groups: activity.length,
      techniques: (key.techniques || []).length,
      iocs: (key.iocs || []).length,
    },
    // One adversary identity per run — the thing that makes the events
    // pivotable, and the answer to "who did it" for marking purposes.
    adversary: plan.entities || {},
    techniques: key.techniques || [],
    timeline: key.timeline || [],
    activity,
    by_source: [...bySource.entries()]
      .map(([k, count]) => ({ source: k, count }))
      .sort((a, b) => b.count - a.count),
    iocs: key.iocs || [],
    queries,
    look_alikes: lookAlikes,
    floor_techniques: key.floor_techniques || [],
  };
}

module.exports = {
  ANSWER_BOOK_VERSION,
  buildAnswerBook,
  // Exported for the tests, which pin the message-collapsing rule directly:
  // it is the difference between four readable sentences and 2,916 unique ones.
  patternOf,
  kqlValue,
};
