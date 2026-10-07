'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { PACKS, resolvePack, resolveAll, toWire } = require('../src/incident/caldera/adversary-pack');
const fixture = require('./fixtures/caldera-pack-catalog.json');
const row = (id, technique, opts = {}) => ({
  ability_id: id,
  name: opts.name || id,
  technique_id: technique,
  tactic: 'discovery',
  plugin: opts.plugin === undefined ? 'stockpile' : opts.plugin,
  executors: (opts.platforms || ['windows']).map((platform) => ({ platform, name: 'psh' })),
});
const byKey = (key) => PACKS.find((p) => p.key === key);
const basicPack = (steps, extra = {}) => ({ key: 'test', name: 'Test', description: 'Test profile', platform: 'windows', steps, ...extra });

test('curated Atomic selection wins over Stockpile and similarly named tests', () => {
  const intent = basicPack([{ technique: 'T1059.001', plugin: 'atomic', abilityName: 'PowerShell Command Execution' }]);
  const abilities = [
    row('0', 'T1059.001', { name: 'PowerShell Command Execution', plugin: 'stockpile' }),
    row('1', 'T1059.001', { name: 'PowerShell Command Execution extended', plugin: 'atomic' }),
    row('2', 'T1059.001', { name: 'PowerShell Command Execution', plugin: null }),
    row('selected-live-id', 'T1059.001', { name: 'PowerShell Command Execution', plugin: 'atomic' }),
  ];
  assert.deepEqual(resolvePack(intent, abilities).atomic_ordering, ['selected-live-id']);
  assert.deepEqual(resolvePack(intent, [...abilities].reverse()), resolvePack(intent, abilities));
});

test('missing exact test is reported rather than replaced by another test of that technique', () => {
  const intent = basicPack([{ technique: 'T1003.001', plugin: 'atomic', abilityName: 'Dump LSASS.exe Memory using comsvcs.dll' }]);
  const actual = resolvePack(intent, [row('different', 'T1003.001', { name: 'Dump LSASS.exe Memory using NanoDump', plugin: 'atomic' })]);
  assert.deepEqual(actual.atomic_ordering, []);
  assert.deepEqual(actual.unresolved, [{ step: 1, technique: 'T1003.001', plugin: 'atomic', name: 'Dump LSASS.exe Memory using comsvcs.dll', reason: 'no_matching_ability' }]);
});

test('exact name cannot override platform or technique constraints', () => {
  const intent = basicPack([{ technique: 'T1033', plugin: 'atomic', abilityName: 'User Discovery - whoami' }]);
  const actual = resolvePack(intent, [
    row('wrong-platform', 'T1033', { name: 'User Discovery - whoami', plugin: 'atomic', platforms: ['linux'] }),
    row('wrong-technique', 'T1082', { name: 'User Discovery - whoami', plugin: 'atomic' }),
  ]);
  assert.equal(actual.atomic_ordering.length, 0);
  assert.equal(actual.unresolved.length, 1);
});

test('legacy technique-only packs retain Stockpile preference and cross-platform support', () => {
  const intent = basicPack([{ technique: 'T1033' }], { platform: 'linux' });
  const atomic = row('at', 'T1033', { plugin: 'atomic', platforms: ['linux'] });
  const stockpile = row('sp', 'T1033', { platforms: ['windows', 'linux'] });
  assert.deepEqual(resolvePack(intent, [atomic, stockpile]).atomic_ordering, ['sp']);
  assert.deepEqual(resolvePack(intent, [atomic]).atomic_ordering, ['at']);
  assert.deepEqual(resolvePack(intent, [row('windows', 'T1033')]).atomic_ordering, []);
});

test('all pinned upstream selectors resolve and every Windows profile deliberately includes Atomic', () => {
  for (const p of PACKS) {
    const actual = resolvePack(p, fixture.abilities);
    assert.deepEqual(actual.unresolved, [], p.key);
    assert.equal(actual.resolved.length, p.steps.length, p.key);
    if (p.platform === 'windows') {
      assert.ok(actual.resolved.some((s) => s.plugin === 'atomic'), p.key);
      for (const step of p.steps) assert.ok(step.plugin && step.abilityName, p.key);
    }
    assert.deepEqual(actual.prerequisites, p.prerequisites);
  }
  assert.deepEqual(PACKS.slice(6).map((p) => p.key), ['powershell-foothold', 'domain-mapping', 'scheduled-persistence']);
});

test('Atomic review metadata is pinned to the vendored data and avoids runtime downloads/installers', () => {
  const dockerfile = fs.readFileSync(path.join(__dirname, '../../infrastructure/caldera/Dockerfile'), 'utf8');
  assert.ok(dockerfile.includes(`ARG ATOMIC_RED_TEAM_REF=${fixture._provenance.atomic_red_team_ref}`), 'Review fixture/selectors when updating the ART pin');
  assert.ok(dockerfile.includes(`ARG CALDERA_VERSION=${fixture._provenance.caldera_version}`), 'Review Stockpile selectors when updating Caldera');
  for (const ability of fixture.abilities.filter((r) => r.plugin === 'atomic')) {
    assert.equal(ability.review.dependencies, 0, ability.name);
    assert.equal(ability.review.external_downloads, false, ability.name);
    assert.ok(ability.atomic_test_guid && ability.source.includes(fixture._provenance.atomic_red_team_ref));
  }
});

const parsers = (ability) => ability.executors.flatMap((ex) => Object.values(ex.parsers || {}).flat());
const requirements = (ability) => (ability.requirements || []).flatMap((r) => Object.values(r).flat());

test('lateral steps preserve actual learned reachability, mounted-share and transferred-agent relationships', () => {
  const actual = resolvePack(byKey('lateral-move'), fixture.abilities);
  const ordered = actual.atomic_ordering.map((id) => fixture.abilities.find((r) => r.ability_id === id));
  assert.equal(ordered[0].name, 'Remote Host Ping');
  assert.equal(ordered[0].technique_id, 'T1016', 'T1018 cannot resolve upstream Remote Host Ping');
  const mountIndex = ordered.findIndex((r) => r.name === 'Mount Share');
  const copyIndex = ordered.findIndex((r) => r.name === 'Copy 54ndc47 (SMB)');
  const startIndex = ordered.findIndex((r) => r.name === 'Start 54ndc47 (WMI)');
  assert.ok(mountIndex > 0 && copyIndex > mountIndex && startIndex > copyIndex);
  assert.ok(parsers(ordered[0]).some((p) => p.edge === 'isAccessibleFrom'));
  assert.ok(parsers(ordered[mountIndex]).some((p) => p.edge === 'has_share'));
  assert.ok(requirements(ordered[copyIndex]).some((p) => p.edge === 'has_share'));
  assert.ok(parsers(ordered[copyIndex]).some((p) => p.edge === 'has_54ndc47_copy'));
  assert.ok(requirements(ordered[startIndex]).some((p) => p.edge === 'has_54ndc47_copy'));
  const withoutPing = fixture.abilities.filter((r) => r.name !== 'Remote Host Ping');
  const missing = resolvePack(byKey('lateral-move'), withoutPing).unresolved;
  assert.equal(missing[0].name, 'Remote Host Ping');
  assert.equal(missing[0].plugin, 'stockpile');
});

test('collection creates staging and copies discovered files before compression and upload', () => {
  const actual = resolvePack(byKey('stage-and-exfil'), fixture.abilities);
  const ordered = actual.atomic_ordering.map((id) => fixture.abilities.find((r) => r.ability_id === id));
  assert.deepEqual(ordered.slice(2).map((r) => r.name), [
    'Find files', 'Create staging directory', 'Stage sensitive files', 'Compress staged directory', 'Exfil staged directory',
  ]);
  assert.ok(parsers(ordered[2]).some((p) => p.source === 'host.file.path'));
  assert.ok(parsers(ordered[3]).some((p) => p.source === 'host.dir.staged'));
  assert.ok(requirements(ordered[4]).some((p) => p.source === 'host.file.path'));
  assert.ok(requirements(ordered[4]).some((p) => p.source === 'host.dir.staged'));
  assert.ok(parsers(ordered[5]).some((p) => p.source === 'host.dir.compress'));
  assert.ok(requirements(ordered[6]).some((p) => p.source === 'host.dir.compress'));
});

test('same technique can intentionally run different tests, but one ability is never ordered twice', () => {
  const repeated = basicPack([{ technique: 'T1033' }, { technique: 'T1033' }]);
  const actual = resolvePack(repeated, [row('one', 'T1033')]);
  assert.deepEqual(actual.atomic_ordering, ['one']);
  assert.equal(actual.unresolved[0].reason, 'duplicate_ability');
  const domain = resolvePack(byKey('domain-mapping'), fixture.abilities);
  assert.equal(domain.resolved.filter((r) => r.technique === 'T1018').length, 2);
  assert.equal(new Set(domain.atomic_ordering).size, domain.atomic_ordering.length);
});

test('existing profile identities survive changes in selectors and catalog hashes', () => {
  const existing = {
    'foothold-survey': '7047c5e8-51fb-510f-9b99-b04bea6c0cc7',
    'credential-harvest': 'ab64d7fa-640c-5d92-8268-bc4d7378c356',
    'lateral-move': '45bf309b-9955-5921-a8c4-1094b35fea69',
    'tamper-and-persist': '89d1cc56-1dbc-56a2-864a-9be1cdea2006',
    'stage-and-exfil': '4f596b7a-bbcb-506c-98be-7c6e144e222a',
    'linux-survey': '3c9a6dda-f57b-54ac-8b64-56a1a733d11a',
  };
  const rehashed = fixture.abilities.map((r) => ({ ...r, ability_id: `live-${r.ability_id}` }));
  for (const [key, id] of Object.entries(existing)) {
    assert.equal(resolvePack(byKey(key), []).adversary_id, id);
    assert.equal(resolvePack(byKey(key), rehashed).adversary_id, id);
  }
  for (const p of resolveAll(rehashed)) {
    assert.ok(p.atomic_ordering.every((id) => id.startsWith('live-')), 'IDs come only from the live catalog');
  }
});

test('resolution is independent of catalog order and does not mutate input metadata', () => {
  const original = JSON.stringify(fixture.abilities);
  assert.deepEqual(resolveAll(fixture.abilities), resolveAll([...fixture.abilities].reverse()));
  assert.equal(JSON.stringify(fixture.abilities), original);
  const resolved = resolvePack(byKey('credential-harvest'), fixture.abilities);
  resolved.prerequisites.push('local edit');
  assert.ok(!byKey('credential-harvest').prerequisites.includes('local edit'));
});

test('wire body includes prerequisites but only Caldera-supported fields', () => {
  const resolved = resolvePack(byKey('scheduled-persistence'), fixture.abilities);
  const wire = toWire(resolved);
  assert.deepEqual(Object.keys(wire).sort(), ['adversary_id', 'atomic_ordering', 'description', 'name', 'objective', 'tags']);
  assert.deepEqual(wire.atomic_ordering, resolved.atomic_ordering);
  assert.match(wire.description, /Prerequisites: .*Elevated Windows PowerShell/);
  wire.atomic_ordering.push('local edit');
  assert.ok(!resolved.atomic_ordering.includes('local edit'));
});

test('empty or malformed catalogs report every missing step', () => {
  for (const catalog of [[], null, undefined, [null, {}, { ability_id: 'no-technique' }]]) {
    for (const actual of resolveAll(catalog)) {
      assert.deepEqual(actual.atomic_ordering, []);
      assert.equal(actual.unresolved.length, byKey(actual.key).steps.length);
      assert.ok(actual.unresolved.every((s) => s.technique && s.reason && s.step));
    }
  }
});

test('every declared profile has a unique identity, explicit prerequisites and at least four steps', () => {
  assert.equal(new Set(PACKS.map((p) => p.key)).size, PACKS.length);
  assert.equal(new Set(resolveAll([]).map((p) => p.adversary_id)).size, PACKS.length);
  for (const p of PACKS) {
    assert.ok(p.name && p.description && p.prerequisites.length && p.steps.length >= 4, p.key);
    assert.ok(['windows', 'linux'].includes(p.platform));
    for (const step of p.steps) assert.match(step.technique, /^T\d{4}(\.\d{3})?$/);
  }
});
