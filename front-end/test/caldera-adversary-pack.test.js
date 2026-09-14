'use strict';

/**
 * CyberCore's adversary pack.
 * ============================================================================
 * These profiles are resolved against the live catalog instead of shipped as
 * files, because the atomic plugin derives an ability id from a hash of the
 * Atomic Red Team test object. That id is stable only for a pinned
 * ATOMIC_RED_TEAM_REF, so a hardcoded profile would not break when the pin moved
 * — it would quietly lose that step while still reporting success, and the
 * answer key would still name the technique nobody ran.
 *
 * So the properties worth testing are about RESOLUTION: that it prefers the
 * right ability when several implement a technique, that it never silently drops
 * one, that it is deterministic, and that the one order-dependent profile keeps
 * its order.
 *
 * Run: node --test test/caldera-adversary-pack.test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const pack = require('../src/incident/caldera/adversary-pack');
const { PACKS, resolvePack, resolveAll, toWire } = pack;

/** A catalog row shaped the way GET /api/v2/abilities returns them. */
const row = (id, technique, opts = {}) => ({
  ability_id: id,
  name: opts.name || id,
  technique_id: technique,
  tactic: opts.tactic || 'discovery',
  plugin: opts.plugin || 'stockpile',
  executors: (opts.platforms || ['windows']).map((platform) => ({ platform, name: 'psh' })),
});

const byKey = (key) => PACKS.find((p) => p.key === key);

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

test('a technique implemented only by atomic still resolves', () => {
  const resolved = resolvePack(byKey('credential-harvest'), [
    row('at-lsass', 'T1003.001', { plugin: 'atomic', name: 'Dump LSASS.exe' }),
  ]);
  assert.deepEqual(resolved.atomic_ordering, ['at-lsass']);
  assert.equal(resolved.resolved[0].plugin, 'atomic');
});

/**
 * Stockpile's abilities are written for Caldera and usually parse their output
 * into facts; atomic's shell out and return text. When both implement a
 * technique the one that feeds the rest of the operation wins.
 */
test('stockpile wins a tie, but only a tie', () => {
  const catalog = [
    row('at-user', 'T1033', { plugin: 'atomic' }),
    row('sp-user', 'T1033', { plugin: 'stockpile' }),
  ];
  assert.deepEqual(resolvePack(byKey('foothold-survey'), catalog).atomic_ordering, ['sp-user']);
  // With no stockpile row the atomic one is not merely tolerated, it is chosen.
  assert.deepEqual(
    resolvePack(byKey('foothold-survey'), [row('at-user', 'T1033', { plugin: 'atomic' })]).atomic_ordering,
    ['at-user'],
  );
});

test('an ability for the wrong platform is never chosen', () => {
  const linux = resolvePack(byKey('linux-survey'), [row('win-only', 'T1033', { platforms: ['windows'] })]);
  assert.deepEqual(linux.atomic_ordering, []);
  assert.ok(linux.unresolved.some((u) => u.technique === 'T1033'));

  const both = resolvePack(byKey('linux-survey'), [row('cross', 'T1033', { platforms: ['windows', 'linux'] })]);
  assert.deepEqual(both.atomic_ordering, ['cross']);
});

/**
 * The same rule adversary.js applies to unmapped steps: an instructor who cannot
 * see what was removed cannot tell a scoping decision from a bug.
 */
test('every step that cannot be resolved is reported', () => {
  const resolved = resolvePack(byKey('foothold-survey'), [row('sp-user', 'T1033')]);
  assert.equal(resolved.resolved.length, 1);
  assert.equal(resolved.unresolved.length, byKey('foothold-survey').steps.length - 1);
  for (const miss of resolved.unresolved) assert.ok(miss.technique && miss.reason);
});

test('one ability is never ordered twice', () => {
  // A single row claiming two of the pack's techniques would otherwise appear
  // twice in the ordering and run twice.
  const shared = { ...row('multi', 'T1033'), technique_id: 'T1033' };
  const resolved = resolvePack({ key: 'x', name: 'X', description: 'd', platform: 'windows',
    steps: [{ technique: 'T1033' }, { technique: 'T1033' }] }, [shared]);
  assert.deepEqual(resolved.atomic_ordering, ['multi']);
  assert.equal(resolved.unresolved.length, 1);
  assert.equal(resolved.unresolved[0].reason, 'duplicate_ability');
});

// ---------------------------------------------------------------------------
// The order-dependent profile
// ---------------------------------------------------------------------------

/**
 * THE ONE THAT BREAKS SILENTLY IF REORDERED.
 *
 * The SMB and WMI lateral abilities gate on an `isAccessibleFrom` RELATIONSHIP,
 * not on facts, and that relationship has to be LEARNED — a source-seeded one
 * faults inside Caldera 5.3.0's link generation rather than being ignored. The
 * remote-host discovery step is what creates it. Move it later in the list and
 * every step after it skips, while the operation still reports success.
 */
test('the lateral profile discovers remote hosts before it tries to reach one', () => {
  const steps = byKey('lateral-move').steps.map((s) => s.technique);
  assert.equal(steps[0], 'T1018', 'remote-host discovery must be the first step of the lateral profile');
  for (const later of ['T1021.002', 'T1570']) {
    assert.ok(steps.indexOf(later) > steps.indexOf('T1018'),
      `${later} must come after T1018 or its isAccessibleFrom relationship is never learned`);
  }
});

// ---------------------------------------------------------------------------
// Determinism and the wire body
// ---------------------------------------------------------------------------

test('the same catalog resolves to the same profile every time', () => {
  const catalog = [row('a', 'T1033'), row('b', 'T1082'), row('c', 'T1016')];
  const once = JSON.stringify(resolveAll(catalog));
  assert.equal(once, JSON.stringify(resolveAll(catalog)));
  // Listing order must not change the outcome either.
  assert.equal(once, JSON.stringify(resolveAll([...catalog].reverse())));
});

test('profile ids are stable, so re-seeding updates rather than duplicates', () => {
  const first = resolvePack(byKey('foothold-survey'), []).adversary_id;
  const second = resolvePack(byKey('foothold-survey'), [row('a', 'T1033')]).adversary_id;
  assert.equal(first, second, 'the id must not depend on what resolved');
  assert.match(first, /^[0-9a-f-]{36}$/);
  // Distinct packs never collide.
  assert.equal(new Set(PACKS.map((p) => resolvePack(p, []).adversary_id)).size, PACKS.length);
});

test('the wire body carries only what Caldera accepts', () => {
  const wire = toWire(resolvePack(byKey('foothold-survey'), [row('a', 'T1033')]));
  assert.deepEqual(Object.keys(wire).sort(),
    ['adversary_id', 'atomic_ordering', 'description', 'name', 'objective', 'tags']);
  assert.deepEqual(wire.atomic_ordering, ['a']);
  assert.ok(wire.name.startsWith('CyberCore: '), 'ours must be distinguishable in the picker');
});

test('an empty or malformed catalog yields no ordering and never throws', () => {
  for (const catalog of [[], null, undefined, [null, {}, { ability_id: 'no-technique' }]]) {
    const all = resolveAll(catalog);
    assert.equal(all.length, PACKS.length);
    for (const resolved of all) {
      assert.deepEqual(resolved.atomic_ordering, []);
      assert.ok(resolved.unresolved.length);
    }
  }
});

test('every declared pack is well formed', () => {
  for (const p of PACKS) {
    assert.ok(p.key && p.name && p.description, `${p.key} is missing a field an instructor reads`);
    assert.ok(['windows', 'linux'].includes(p.platform));
    assert.ok(p.steps.length >= 4, `${p.key} has too few steps to read as an intrusion`);
    for (const step of p.steps) assert.match(step.technique, /^T\d{4}(\.\d{3})?$/);
  }
  assert.equal(new Set(PACKS.map((p) => p.key)).size, PACKS.length, 'pack keys must be unique');
});
