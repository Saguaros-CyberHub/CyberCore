#!/usr/bin/env node
/* eslint-disable no-console */
// ============================================================================
// cc-emit.js — CYBR 400 attack telemetry emitter
// ----------------------------------------------------------------------------
// Writes technique-appropriate synthetic log events from a declarative playbook.
// Staged onto the lane by attack-runner.js on every dispatch, exactly like
// cc-attack.sh, so a guest can never run a stale copy. Do not edit on the guest.
//
// WHY THIS EXISTS
//   log-generator's --mitre-technique is a FILTER, not a simulator. It runs all
//   twelve generators at their configured rates and tags the lines whose message
//   text happens to match a keyword. Measured on a deployed lane, one T1005 run
//   wrote 37,004 lines of which 76 carried the technique -- 30,571 of them
//   API-gateway records from api.example.com. T1005 is "read files off a local
//   host". No filter over API gateway logs can represent that, and log-generator
//   has no process, file or registry source to filter in the first place.
//
// THE ENVELOPE IS NOT NEGOTIABLE
//   Output must be byte-compatible with log-generator's ND-JSON, because three
//   things downstream key off it and none of them fail loudly:
//     * the agent drops any attack event lacking `loggen.mitre.technique` (that
//       path exists only because the ndjson parser uses target: loggen)
//     * the dashboard's terms panels read loggen.source.{type,host} / .level
//     * the component template types ONLY loggen.{timestamp,level,message,
//       metadata,source.*,mitre.*}. Anything else falls to dynamic mapping under
//       ecs@mappings, where a name like `source.ip` gets typed `ip` and then
//       REJECTS every document whose value is not an address -- silently, with a
//       healthy agent and no error the console can see.
//   So: six top-level keys, never more. Extra structure goes under metadata.
//
// METADATA VALUES ARE ALL STRINGS
//   loggen.metadata is mapped `flattened`, so nothing in it can be summed or
//   range-queried in Lens. Quantities belong in the message text, which is what
//   real logs do anyway.
// ============================================================================
'use strict';

const fs = require('fs');
const path = require('path');

// ---------------------------------------------------------------------------
// Deterministic RNG, seeded from the RUN ID.
//
// Every lane in a class runs the same run id, so every student sees the SAME
// attack: the instructor can say "there are 412 events, find them" and be right
// on all thirty machines. Unseeded randomness would silently turn one exercise
// into thirty different ones, and a retried lane would not match the other 29.
// ---------------------------------------------------------------------------
function makeRng(seed) {
  let a = (seed >>> 0) || 0x9e3779b9;
  return function rng() {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** FNV-1a over a string — turns a run UUID into a usable 32-bit seed. */
function seedFrom(str) {
  let h = 0x811c9dc5;
  const s = String(str || '');
  for (let i = 0; i < s.length; i += 1) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

/**
 * Business rhythm.
 *
 * A dead-flat 24/7 histogram is the single most obvious synthetic tell there is
 * -- more obvious than volume, more obvious than field values. Real enterprise
 * telemetry has a shape: it climbs from about 07:00, peaks mid-morning, dips at
 * lunch, tails off after 18:00, and drops to a floor of batch jobs and
 * monitoring overnight. Weekends run at a fraction of a weekday.
 *
 * It also carries pedagogy that nothing else does. "Unusual hour" is a real
 * signal an analyst uses constantly, and it only exists if the ordinary hours
 * look ordinary. On a flat baseline, 03:00 means nothing.
 *
 * Applied to the benign daemon only. An instructor fires an attack whenever
 * they fire it; if that happens to be against the overnight floor it stands out
 * more, which is exactly true of real intrusions.
 */
function intensityAt(rhythm, date) {
  if (!rhythm) return 1;
  const offset = Number(rhythm.utc_offset || 0);
  const local = new Date(date.getTime() + offset * 3600 * 1000);
  const hour = local.getUTCHours();
  const day = local.getUTCDay(); // 0 Sun .. 6 Sat

  const curve = Array.isArray(rhythm.hourly) && rhythm.hourly.length === 24 ? rhythm.hourly : null;
  let factor = curve ? Number(curve[hour]) : 1;
  if (!Number.isFinite(factor) || factor < 0) factor = 1;

  if ((day === 0 || day === 6) && rhythm.weekend != null) {
    const w = Number(rhythm.weekend);
    if (Number.isFinite(w) && w >= 0) factor *= w;
  }
  return factor;
}

/**
 * One of a step's message templates, weighted.
 *
 * Without this a step emits one sentence over and over, and a benign stream
 * built from 25 such steps reads as 25 sentences on a loop — which is its own
 * kind of obviously-synthetic, just a different kind from a flat histogram.
 * Real sources say several things: nginx serves 200s and 404s and the odd 500,
 * sshd accepts keys and passwords and rejects some, postgres runs queries and
 * checkpoints and autovacuums.
 *
 * A template may override level and metadata as well as the message, because a
 * 500 is not an INFO and a failed logon is not a success.
 */
function pickTemplate(rng, step) {
  const t = step.templates;
  if (!Array.isArray(t) || !t.length) return step;
  let total = 0;
  for (const x of t) total += Number(x.weight) || 1;
  let r = rng() * total;
  for (const x of t) {
    r -= Number(x.weight) || 1;
    if (r <= 0) return x;
  }
  return t[t.length - 1];
}

const pick = (rng, arr) => arr[Math.floor(rng() * arr.length)];
const randInt = (rng, lo, hi) => lo + Math.floor(rng() * (hi - lo + 1));

// ---------------------------------------------------------------------------
// Duration parsing — the SAME grammar loggen-catalog.js formatDuration() emits.
// The wrapper only ever holds the formatted string in $DUR; resolveSelection()
// never passes a seconds form down.
// ---------------------------------------------------------------------------
const DURATION_RE = /^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$/;

function parseDuration(value) {
  const raw = String(value == null ? '' : value).trim();
  if (raw === '') return 0;
  if (/^\d+$/.test(raw)) return Number(raw);
  const m = DURATION_RE.exec(raw);
  if (!m || (!m[1] && !m[2] && !m[3])) {
    throw new Error(`cc-emit: unparseable duration ${JSON.stringify(value)}`);
  }
  return Number(m[1] || 0) * 3600 + Number(m[2] || 0) * 60 + Number(m[3] || 0);
}

// ---------------------------------------------------------------------------
// Entities resolve ONCE per run; pools are sampled per event.
//
// A run has to read as one adversary doing one thing: the same source IP across
// 180 failed logons, the same account in the success that follows. log-generator
// randomises every field of every line independently, which is why its output
// cannot be pivoted through and reads as noise even when the volume is right.
// ---------------------------------------------------------------------------
function resolveEntities(playbook, rng) {
  const out = {};
  for (const [key, spec] of Object.entries(playbook.entities || {})) {
    if (typeof spec === 'string' || typeof spec === 'number') {
      out[key] = String(spec);
    } else if (spec && Array.isArray(spec.oneOf)) {
      out[key] = String(pick(rng, spec.oneOf));
    } else if (spec && typeof spec.ipv4Host === 'string') {
      out[key] = `${spec.ipv4Host}.${randInt(rng, 2, 254)}`;
    } else {
      throw new Error(`cc-emit: unsupported entity spec for ${key}`);
    }
  }
  return out;
}

const TOKEN_RE = /\{\{([a-zA-Z0-9_]+)(?:\.(\d+))?(?::(\d+)-(\d+))?\}\}/g;

function expand(template, ctx, rng, seq, depth) {
  if (typeof template !== 'string') return template;
  const out = expandOnce(template, ctx, rng, seq);
  // Pool values may themselves contain tokens -- "/home/{{users}}/notes.md" is
  // the natural way to write a per-user path. Re-expand until stable, bounded so
  // a self-referential pool cannot spin. Leaving it at one pass ships literal
  // "{{users}}" to Kibana, which is exactly the "{clientIP}" tell log-generator
  // has at this commit and the thing this emitter exists to avoid.
  if (out !== template && /\{\{/.test(out) && (depth || 0) < 3) {
    return expand(out, ctx, rng, seq, (depth || 0) + 1);
  }
  return out;
}

function expandOnce(template, ctx, rng, seq) {
  return template.replace(TOKEN_RE, (whole, key, idx, lo, hi) => {
    if (key === 'rand' && lo != null) return String(randInt(rng, Number(lo), Number(hi)));
    if (key === 'port') return String(randInt(rng, 32768, 60999));
    if (key === 'pid') return String(randInt(rng, 400, 32000));
    if (key === 'seq') return String(seq);
    if (Object.prototype.hasOwnProperty.call(ctx.entities, key)) return ctx.entities[key];
    const pool = ctx.pools[key];
    if (Array.isArray(pool) && pool.length) {
      if (idx != null) return String(pool[Number(idx) % pool.length]);
      // Sampled ONCE per event, then reused. Sampling per occurrence makes an
      // event contradict itself -- "Failed password for jsmith" carrying
      // metadata.user=svc_backup -- so a student pivoting on the structured
      // field gets a different answer than one reading the message. Both are
      // wrong, and nothing about the data says which.
      if (!Object.prototype.hasOwnProperty.call(ctx.sampled, key)) {
        ctx.sampled[key] = String(pick(rng, pool));
      }
      return ctx.sampled[key];
    }
    // Left intact rather than "undefined". log-generator itself ships literal
    // "{clientIP}" in its metadata at this commit, and that is exactly the tell
    // we must not reproduce -- an unresolved token fails a unit test instead.
    return whole;
  });
}

function expandDeep(value, ctx, rng, seq) {
  if (typeof value === 'string') return expand(value, ctx, rng, seq);
  if (Array.isArray(value)) return value.map((v) => expandDeep(v, ctx, rng, seq));
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = expandDeep(v, ctx, rng, seq);
    return out;
  }
  return value == null ? value : String(value);
}

// ---------------------------------------------------------------------------
// Timeline: RIGID bursts, ELASTIC dwell.
//
// This is the part that must not be a single uniform scale factor. A brute force
// is 200 attempts in 40 seconds. Stretch that uniformly to the console's 2-hour
// option and it becomes one attempt every 36 seconds -- not a brute force, no
// threshold rule will fire on it, and it is indistinguishable from the
// baseline's own authentication generator at 10/min. The exercise evaporates
// precisely for the techniques it matters most for.
//
// So each step has two independent parts:
//   spread  RIGID   how long the burst itself takes. Never scaled.
//   gap     ELASTIC dwell before the step. Absorbs all of the scaling.
//
// requested = sum(spread) + scaled(sum(gap)). Longer runs mean an adversary who
// waits longer between phases, which is what a longer intrusion actually looks
// like -- not one who types more slowly.
//
// If the rigid floor alone exceeds the requested duration the run REFUSES rather
// than compressing a burst into something physically absurd.
// ---------------------------------------------------------------------------
/**
 * Where each step starts, for a given dwell scale.
 *
 * Split out because the rigid floor cannot be computed arithmetically once
 * `overlap` exists: overlapping steps share wall-clock, so summing their spreads
 * over-counts. Laying the steps out at gapScale=0 gives the true floor whatever
 * the overlap topology, and the layout is monotonic in gapScale, so the scale
 * that lands the run on the requested duration can be solved for directly.
 */
function layout(steps, gapScale) {
  const starts = [];
  let cursor = 0;
  let prevStart = 0;
  for (const step of steps) {
    const gap = parseDuration(step.gap || '0s') * gapScale;
    const spread = parseDuration(step.spread || '0s');
    // overlap: run alongside the previous phase rather than after it. An
    // adversary does not politely finish discovery before starting collection,
    // and the benign host baseline's activity types all happen at once.
    const start = step.overlap ? prevStart + gap : cursor + gap;
    starts.push(start);
    prevStart = start;
    cursor = Math.max(cursor, start + spread);
  }
  return { starts, end: cursor };
}

function planTimeline(playbook, opts) {
  const rng = opts.rng;
  const steps = playbook.steps || [];
  if (!steps.length) throw new Error('cc-emit: playbook has no steps');

  const nominal = Number(playbook.nominal_seconds);
  if (!Number.isFinite(nominal) || nominal <= 0) {
    throw new Error('cc-emit: playbook nominal_seconds must be a positive number');
  }

  const requested = opts.requested == null ? nominal : opts.requested;
  if (!Number.isFinite(requested) || requested <= 0) {
    throw new Error('cc-emit: requested duration must be a positive number');
  }

  const rigidTotal = layout(steps, 0).end;
  if (requested < rigidTotal) {
    throw new Error(
      `cc-emit: playbook needs at least ${Math.round(rigidTotal)}s of burst time `
      + `but was asked for ${Math.round(requested)}s`
    );
  }

  // Solve for the dwell scale that lands the run exactly on the requested
  // duration. Bisection rather than division because overlap makes the
  // relationship piecewise-linear -- monotonic, so this converges in ~40 steps.
  let gapScale = 0;
  if (layout(steps, 1).end < requested || layout(steps, 1).end > requested) {
    let lo = 0;
    let hi = 1;
    while (layout(steps, hi).end < requested && hi < 1e6) hi *= 2;
    for (let i = 0; i < 60; i += 1) {
      const mid = (lo + hi) / 2;
      if (layout(steps, mid).end < requested) lo = mid; else hi = mid;
    }
    gapScale = (lo + hi) / 2;
  }

  const { starts } = layout(steps, gapScale);
  const entities = resolveEntities(playbook, rng);
  const pools = playbook.pools || {};

  const events = [];

  for (let si = 0; si < steps.length; si += 1) {
    const step = steps[si];
    const spread = parseDuration(step.spread || '0s');
    const start = starts[si];
    // Intensity scales the COUNT, not the timing: a quiet hour means fewer
    // people doing things, not the same people doing them slower.
    const intensity = opts.intensity == null ? 1 : opts.intensity;
    const count = Math.round(Math.max(1, Number(step.count || 1)) * intensity);
    if (count < 1) continue; // an hour too quiet for this activity at all
    const technique = step.technique || playbook.technique || null;
    const tactic = step.tactic || playbook.tactic || null;

    for (let i = 0; i < count; i += 1) {
      // Jittered, not evenly spaced. A perfectly uniform interval is the single
      // most obvious synthetic tell there is, and real tooling is bursty.
      const frac = count === 1 ? 0 : i / (count - 1);
      const slot = spread / Math.max(count, 1);
      const jitter = spread > 0 ? (rng() - 0.5) * slot : 0;
      const seq = i + 1;
      const src = step.source || {};
      const tpl = pickTemplate(rng, step);
      // Fresh sample cache per event: pool draws are consistent WITHIN one
      // event and vary BETWEEN them, which is what a spray from one host
      // against many accounts actually looks like.
      const ctx = { entities, pools, sampled: {} };
      events.push({
        // Clamped to the requested window. Jitter on the final event of a step
        // can otherwise push it a few seconds past the deadline, and
        // attack-worker schedules its finishing poll off expected_finish_at --
        // an event landing after that is one the run gets no credit for.
        offset: Math.min(requested, Math.max(0, start + frac * spread + jitter)),
        level: tpl.level || step.level || 'INFO',
        source: {
          type: expand(src.type || 'server', ctx, rng, seq),
          name: expand(src.name || 'unknown', ctx, rng, seq),
          host: expand(src.host || 'localhost', ctx, rng, seq),
        },
        message: expand(tpl.message || step.message || '', ctx, rng, seq),
        metadata: expandDeep(tpl.metadata || step.metadata || {}, ctx, rng, seq),
        technique,
        tactic,
        subtechnique: step.subtechnique || playbook.subtechnique || null,
      });
    }
  }

  events.sort((a, b) => a.offset - b.offset);
  return { events, entities, rigidTotal, requested, gapScale };
}

// ---------------------------------------------------------------------------
// The wire format. Matches log-generator's writer field for field.
// ---------------------------------------------------------------------------
function toLine(event, whenMs) {
  const doc = {
    timestamp: new Date(whenMs).toISOString(),
    level: event.level,
    source: event.source,
    message: event.message,
    metadata: event.metadata,
  };
  // Only tag when there IS a technique. The benign host baseline leaves most of
  // its events untagged, so that mitre.technique:* stays useless as an oracle
  // inside the host source too.
  if (event.technique) {
    doc.mitre = {
      technique: event.technique,
      tactic: event.tactic || null,
      subtechnique: event.subtechnique || null,
    };
  }
  return JSON.stringify(doc) + '\n';
}

// ---------------------------------------------------------------------------
// Writer.
//
// One writeSync of one newline-terminated line onto an O_APPEND fd. Linux
// serialises appends under i_rwsem, so two concurrent runs on one lane -- which
// migration 006 explicitly designs for, excluding only 'dispatching' from the
// mutex -- never interleave WITHIN a line. A buffered stream would split a
// logical line at a buffer boundary and splice two events into invalid JSON that
// the agent's parser then rejects.
//
// Synchronous also means nothing is lost when `timeout -k 30` escalates to
// SIGKILL, which is why this file registers no SIGTERM handler at all.
// ---------------------------------------------------------------------------
function openAppend(outPath) {
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  // Repair a torn tail before appending. An aborted run can leave a partial
  // line; without this the next run's first event is glued onto it, producing
  // one invalid line with no mitre.technique that drop_event eats silently --
  // two events gone with no trace.
  try {
    const st = fs.statSync(outPath);
    if (st.size > 0) {
      const fd0 = fs.openSync(outPath, 'r');
      const buf = Buffer.alloc(1);
      fs.readSync(fd0, buf, 0, 1, st.size - 1);
      fs.closeSync(fd0);
      if (buf[0] !== 0x0a) fs.appendFileSync(outPath, '\n', 'utf8');
    }
  } catch (e) { /* file does not exist yet */ }
  return fs.openSync(outPath, 'a');
}

/**
 * Rotate the output if it has grown past the cap.
 *
 * Nothing else covers this file: loggen-rotate.sh's size branch is hardcoded to
 * the BASELINE directory, and the wrapper's `-mtime +7` reaper never fires on a
 * file that is appended to continuously. Safe to do here precisely because the
 * emitter is short-lived and no daemon holds the fd -- unlike log-generator,
 * which is why the baseline's rotation needs a systemctl restart.
 *
 * Renames INTO the agent's *.json glob so filestream finishes the old file.
 */
function rotateIfLarge(outPath, maxBytes, nowMs) {
  try {
    const st = fs.statSync(outPath);
    if (st.size >= maxBytes) {
      fs.renameSync(outPath, `${outPath.replace(/\.json$/, '')}-${Math.floor(nowMs / 1000)}.json`);
    }
  } catch (e) { /* nothing to rotate */ }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Emit a planned timeline.
 *
 * Scheduling is against a MONOTONIC base, never wall-clock. The wrapper's own
 * header documents that these guests' clocks are not trustworthy -- the lane
 * gateway may not forward NTP and Proxmox only syncs guest RTC on resume. A
 * chrony step backwards would stall a wall-clock scheduler until the hard cap
 * fired (rc=124, reported to the class as "hit the hard runtime cap"); a step
 * forwards, or a VM suspend/resume, would dump every missed event at once.
 */
async function emit(plan, opts) {
  const fd = openAppend(opts.out);
  const base = process.hrtime.bigint();
  const elapsedS = () => Number(process.hrtime.bigint() - base) / 1e9;

  let written = 0;
  const report = () => {
    if (!opts.countFile) return;
    try {
      fs.writeFileSync(`${opts.countFile}.tmp`, String(written), 'utf8');
      fs.renameSync(`${opts.countFile}.tmp`, opts.countFile);
    } catch (e) { /* the count is a convenience, never a reason to fail a run */ }
  };

  try {
    for (const ev of plan.events) {
      // Capped sleeps so a SIGKILL-less abort still lands promptly, and so a
      // long dwell does not sit in one enormous timer (delays over 2^31-1 ms
      // fire immediately in Node, which would burst the whole playbook).
      let guard = 0;
      while (elapsedS() < ev.offset && guard < 10_000_000) {
        await sleep(Math.min((ev.offset - elapsedS()) * 1000, 1000));
        guard += 1;
      }
      fs.writeSync(fd, toLine(ev, Date.now()));
      written += 1;
      if (written % 25 === 0) report();
    }
  } finally {
    report();
    try { fs.closeSync(fd); } catch (e) { /* already gone */ }
  }
  return written;
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------
function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (!a.startsWith('--')) continue;
    const key = a.slice(2);
    const next = argv[i + 1];
    if (next && !next.startsWith('--')) { out[key] = next; i += 1; } else { out[key] = true; }
  }
  return out;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.playbook || !args.out) {
    console.error('usage: cc-emit.js --playbook <f> --out <f> [--duration 30m] [--run-id ID] [--daemon] [--count-file <f>] [--max-bytes N]');
    process.exit(2);
  }

  let playbook;
  try {
    playbook = JSON.parse(fs.readFileSync(args.playbook, 'utf8'));
  } catch (err) {
    console.error(`cc-emit: unreadable playbook: ${err.message}`);
    process.exit(3);
  }

  const maxBytes = Number(args['max-bytes'] || 268435456);
  rotateIfLarge(args.out, maxBytes, Date.now());

  // Seeded from the run id so every lane in the class emits an identical
  // attack. --seed exists for tests.
  const seed = args.seed ? Number(args.seed) : seedFrom(args['run-id'] || playbook.technique || 'cybr400');

  if (args.daemon) {
    // The benign host stream. Re-seeds each cycle so hosts and accounts drift
    // the way a real estate does rather than one machine looping forever.
    let s = seed;
    for (;;) {
      rotateIfLarge(args.out, maxBytes, Date.now());
      // Recomputed every cycle so the curve moves through the day on its own.
      const intensity = intensityAt(playbook.rhythm, new Date());
      const plan = planTimeline(playbook, {
        rng: makeRng(s),
        requested: playbook.nominal_seconds,
        intensity,
      });
      await emit(plan, { out: args.out });
      s = (s + 0x9e3779b9) >>> 0;
    }
  }

  const requested = args.duration ? parseDuration(args.duration) : Number(playbook.nominal_seconds);
  let plan;
  try {
    plan = planTimeline(playbook, { rng: makeRng(seed), requested });
  } catch (err) {
    console.error(`cc-emit: ${err.message}`);
    process.exit(4);
  }

  const written = await emit(plan, {
    out: args.out,
    countFile: args['count-file'] || null,
  });
  console.log(`cc-emit: wrote ${written} event(s) over ${Math.round(requested)}s `
    + `(rigid ${Math.round(plan.rigidTotal)}s, dwell x${plan.gapScale.toFixed(2)}, seed ${seed})`);
  process.exit(0);
}

/**
 * The shortest duration a playbook can honestly run in — the sum of its rigid
 * bursts once overlap is accounted for.
 *
 * The console must not offer a duration below this. Asking for 5 minutes of a
 * beacon whose whole point is 10 minutes of regular check-ins has no honest
 * answer: compress it and it is not a beacon, truncate it and half the story is
 * missing. Refusing is the only correct behaviour, so the picker disables the
 * option rather than letting the instructor discover it lane by lane.
 */
function minSecondsFor(playbook) {
  return Math.ceil(layout(playbook.steps || [], 0).end);
}

module.exports = {
  makeRng,
  seedFrom,
  parseDuration,
  resolveEntities,
  intensityAt,
  pickTemplate,
  layout,
  minSecondsFor,
  expand,
  expandDeep,
  planTimeline,
  toLine,
  openAppend,
  rotateIfLarge,
  emit,
  DURATION_RE,
};

// No SIGTERM/SIGINT handler, deliberately. Abort is `kill -TERM -$PGID` and the
// hard cap is `timeout -k 30`; Node's default terminates immediately, which is
// what makes both work. A handler doing async flush work can outlive the 30s
// grace and be SIGKILLed mid-write -- the torn-line case openAppend() repairs.
// Synchronous appends leave nothing to flush, so a handler buys nothing and
// risks exactly the corruption it would appear to prevent.

if (require.main === module) {
  main().catch((err) => { console.error(`cc-emit: ${err && err.message}`); process.exit(1); });
}
