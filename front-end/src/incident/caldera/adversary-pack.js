'use strict';

/**
 * adversary-pack.js — CyberCore's own adversary profiles, resolved against the
 * live Caldera catalog rather than hardcoded.
 * ============================================================================
 * WHY THESE ARE NOT SHIPPED AS ADVERSARY YAML
 * ----------------------------------------------------------------------------
 * A Caldera adversary references its steps by `ability_id` and nothing else, so
 * shipping one as a file means hardcoding those ids. That is safe for stockpile,
 * whose ids are fixed UUIDs in its own YAML. It is NOT safe for the abilities the
 * atomic plugin generates: it derives each id as
 * `md5(json.dumps(test))` over the whole Atomic Red Team test object, so an id is
 * stable only for a pinned ATOMIC_RED_TEAM_REF. Move the pin, or let Red Canary
 * reword a description, and the id changes.
 *
 * A hardcoded adversary would then not fail — it would silently lose that step.
 * The operation still runs, still reports success, and the technique the class
 * was told to hunt for simply never executes. That is the same class of silent
 * hole the empty fact source used to leave, and it is worse here because the
 * answer key would still name the technique.
 *
 * So a pack declares INTENT — an ordered list of ATT&CK techniques for a
 * platform — and resolves it against whatever the server actually has at the
 * moment it is created. Whatever cannot be resolved is REPORTED, never dropped
 * quietly, on the same principle adversary.js applies to unmapped steps: an
 * instructor who cannot see what was removed cannot tell a scoping decision from
 * a bug.
 *
 * PURE. No network, no clock, no randomness: the same catalog resolves to the
 * same adversary, so two seeding runs agree and re-seeding is a no-op.
 */

const { v5: uuidv5 } = require('uuid');
const { normalizeAbility } = require('./adversary');

/**
 * Fixed, and never to be changed: it is what makes re-seeding idempotent rather
 * than a second copy of every profile. Distinct from the namespaces in
 * adversary.js and fact-source.js.
 */
const PACK_NAMESPACE = 'f3c1b27e-58a4-4d6b-9e30-7a1c5d0b8f42';

/** Prefix on every generated profile, so an instructor can tell ours apart. */
const NAME_PREFIX = 'CyberCore: ';

/**
 * The profiles.
 *
 * Ordered by intent, not by convenience: each pack reads as one adversary doing
 * one thing, because an operation whose steps do not tell a story is a list of
 * alerts rather than an intrusion to reconstruct.
 *
 * `technique` is matched exactly. `nameMatch` only DISAMBIGUATES when several
 * abilities implement the same technique; it never causes a step to resolve to
 * something that implements a different one.
 */
const PACKS = Object.freeze([
  {
    key: 'foothold-survey',
    name: 'Foothold survey',
    description: 'What an operator runs in the first minutes on a new host: who am I, what is this machine, who else is on the domain. Almost entirely read-only, so it is the exercise for separating ordinary administration from reconnaissance.',
    platform: 'windows',
    steps: [
      { technique: 'T1033' },
      { technique: 'T1082' },
      { technique: 'T1016' },
      { technique: 'T1057' },
      { technique: 'T1087.001' },
      { technique: 'T1087.002' },
      { technique: 'T1069.002' },
      { technique: 'T1018' },
    ],
  },
  {
    key: 'credential-harvest',
    name: 'Credential harvest',
    description: 'Collecting secrets already on the host, then asking the domain for more. The loudest profile in the pack and the one most likely to raise a real detection rule.',
    platform: 'windows',
    steps: [
      { technique: 'T1552.001' },
      { technique: 'T1555' },
      { technique: 'T1003.001' },
      { technique: 'T1558.003' },
    ],
  },
  {
    key: 'lateral-move',
    name: 'Quiet lateral move',
    description: 'Reach a second machine and run something on it. Read the note on step ordering in this file before editing: the discovery step is not optional padding.',
    platform: 'windows',
    steps: [
      // FIRST, AND DELIBERATELY SO. The SMB and WMI lateral abilities gate on an
      // `isAccessibleFrom` RELATIONSHIP, not on facts, and that relationship has
      // to be LEARNED — a source-seeded one faults inside Caldera 5.3.0's link
      // generation. Remote-host discovery is what creates it, and the seeded
      // host facts from caldera-lane-facts.js are what give it somewhere to go.
      // Move this step down and everything after it silently skips.
      { technique: 'T1018' },
      { technique: 'T1021.002' },
      { technique: 'T1570' },
      { technique: 'T1053.005' },
    ],
  },
  {
    key: 'tamper-and-persist',
    name: 'Defence tamper and persist',
    description: 'Weaken what is watching, then arrange to come back. Pairs with a lane where Defender is left enabled, because the impair-defenses step is then a real event rather than a no-op.',
    platform: 'windows',
    steps: [
      { technique: 'T1562.001' },
      { technique: 'T1547.001' },
      { technique: 'T1112' },
      { technique: 'T1053.005' },
      { technique: 'T1070.004' },
    ],
  },
  {
    key: 'stage-and-exfil',
    name: 'Stage and exfiltrate',
    description: 'Find files worth taking, collect them in one place, compress them and send them out. The end of the story, and the part a timeline exercise needs in order to have an end.',
    platform: 'windows',
    steps: [
      { technique: 'T1083' },
      { technique: 'T1005' },
      { technique: 'T1074.001' },
      { technique: 'T1560.001' },
      { technique: 'T1041' },
    ],
  },
  {
    key: 'linux-survey',
    name: 'Foothold survey (Linux)',
    description: 'The Linux counterpart to the Windows survey, for lanes whose estate is not all Windows. Smaller on purpose: a lane with one Linux host does not need five profiles for it.',
    platform: 'linux',
    steps: [
      { technique: 'T1033' },
      { technique: 'T1082' },
      { technique: 'T1016' },
      { technique: 'T1057' },
      { technique: 'T1087.001' },
      { technique: 'T1083' },
    ],
  },
]);

const str = (value) => (value === null || value === undefined ? '' : String(value).trim());

/**
 * Catalog rows, normalised once, keeping the plugin name that normalizeAbility
 * drops. The plugin is only ever used to make a DETERMINISTIC choice between
 * equally valid candidates; a row without one still resolves.
 */
function catalog(abilities) {
  const out = [];
  for (const raw of Array.isArray(abilities) ? abilities : []) {
    const ability = normalizeAbility(raw);
    if (ability) out.push({ ...ability, plugin: str(raw && raw.plugin).toLowerCase() || null });
  }
  return out;
}

/**
 * The single candidate for one step, or null.
 *
 * Ties are broken deterministically and in that order: a name match first
 * (the author said which one they meant), then the plugin preference, then the
 * id. Sorting by id last is what makes two servers with the same catalog produce
 * the same profile instead of whichever row happened to be listed first.
 */
function pick(step, rows, platform) {
  const wanted = str(step.technique).toUpperCase();
  const match = str(step.nameMatch).toLowerCase();
  const candidates = rows.filter((row) => row.technique.toUpperCase() === wanted
    && (!platform || row.platforms.includes(platform)));
  if (!candidates.length) return null;
  const scored = candidates.map((row) => ({
    row,
    named: match && row.name.toLowerCase().includes(match) ? 0 : 1,
    // stockpile first: its abilities are hand-written for Caldera and tend to
    // parse their output into facts, which atomic's shell-outs do not.
    sourced: row.plugin === 'stockpile' ? 0 : 1,
  }));
  scored.sort((a, b) => a.named - b.named || a.sourced - b.sourced || a.row.id.localeCompare(b.row.id));
  return scored[0].row;
}

/**
 * One pack, against one catalog.
 *
 * Returns the wire body `createAdversary` wants plus the two things an
 * instructor needs in order to trust it: what each step resolved to, and what
 * did not resolve at all.
 */
function resolvePack(pack, abilities) {
  const rows = catalog(abilities);
  const resolved = [];
  const unresolved = [];
  const seen = new Set();
  for (const step of pack.steps) {
    const row = pick(step, rows, pack.platform);
    if (!row) { unresolved.push({ technique: step.technique, reason: 'no_ability_for_platform' }); continue; }
    // One ability twice in an ordering runs it twice, which reads as a bug in
    // the story rather than as tradecraft.
    if (seen.has(row.id)) { unresolved.push({ technique: step.technique, reason: 'duplicate_ability' }); continue; }
    seen.add(row.id);
    resolved.push({ technique: step.technique, ability_id: row.id, name: row.name, tactic: row.tactic, plugin: row.plugin });
  }
  return {
    key: pack.key,
    adversary_id: uuidv5(pack.key, PACK_NAMESPACE),
    name: `${NAME_PREFIX}${pack.name}`,
    description: pack.description,
    platform: pack.platform,
    atomic_ordering: resolved.map((entry) => entry.ability_id),
    resolved,
    unresolved,
  };
}

/** Every pack, resolved. Packs that resolved no step at all are still reported. */
function resolveAll(abilities, packs) {
  return (Array.isArray(packs) ? packs : PACKS).map((pack) => resolvePack(pack, abilities));
}

/** Just the fields Caldera's POST /api/v2/adversaries accepts. */
function toWire(resolvedPack) {
  return {
    adversary_id: resolvedPack.adversary_id,
    name: resolvedPack.name,
    description: resolvedPack.description,
    atomic_ordering: [...resolvedPack.atomic_ordering],
    objective: null,
    tags: ['cybercore'],
  };
}

module.exports = { PACKS, PACK_NAMESPACE, NAME_PREFIX, resolvePack, resolveAll, toWire };
