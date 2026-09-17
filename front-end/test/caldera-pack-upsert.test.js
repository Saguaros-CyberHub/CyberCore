'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createCalderaClient } = require('../src/incident/caldera/client');
const { resolveAll, toWire } = require('../src/incident/caldera/adversary-pack');
const { compileAdversary } = require('../src/incident/caldera/adversary');
const fixture = require('./fixtures/caldera-pack-catalog.json');

test('managed and compiled adversaries satisfy the upstream optional objective contract', async () => {
  // Caldera 5.3.0 app/objects/c_adversary.py: AdversarySchema.objective is
  // ma.fields.String() without allow_none; the constructor supplies the default
  // when omitted. Both POST and PUT validate that schema before writing.
  // https://github.com/mitre/caldera/blob/5.3.0/app/objects/c_adversary.py
  const requests = [];
  const client = createCalderaClient({
    baseUrl: 'https://caldera.example', apiKey: 'test-only',
    transport: async (request) => {
      const body = JSON.parse(request.body);
      requests.push({ method: request.method, body });
      if ('objective' in body && typeof body.objective !== 'string') {
        return { status: 422, ok: false, text: '{"objective":["Field may not be null."]}' };
      }
      return { status: 200, ok: true, text: JSON.stringify(body) };
    },
  });
  await assert.rejects(client.upsertAdversary({ adversary_id: 'invalid', objective: null }), { status: 422 });
  requests.length = 0;
  const packs = resolveAll(fixture.abilities);
  for (const pack of packs) await client.upsertAdversary(toWire(pack));
  const compiled = compileAdversary({
    scenario: { scenario_id: 'schema-contract', name: 'Schema contract',
      attack_path: [{ step: 1, technique: 'T1082' }] },
    abilities: fixture.abilities,
    options: { platform: 'windows' },
  });
  assert.ok(compiled.adversary.atomic_ordering.length);
  await client.createAdversary(compiled.adversary);
  assert.deepEqual(requests.map((request) => request.method), [...packs.map(() => 'PUT'), 'POST']);
  assert.ok(requests.every(({ body }) => !Object.hasOwn(body, 'objective')),
    'Let Caldera supply its default objective instead of sending null.');
});

test('managed adversaries use PUT so a second seed replaces the existing ordering', async () => {
  const stored = new Map();
  const requests = [];
  const client = createCalderaClient({
    baseUrl: 'https://caldera.example', apiKey: 'test-only',
    transport: async (request) => {
      requests.push(request);
      assert.equal(request.method, 'PUT');
      const body = JSON.parse(request.body);
      stored.set(body.adversary_id, body);
      return { status: 200, ok: true, text: JSON.stringify(body) };
    },
  });
  await client.upsertAdversary({ adversary_id: 'stable-profile', atomic_ordering: ['old-step'] });
  await client.upsertAdversary({ adversary_id: 'stable-profile', atomic_ordering: ['atomic-step', 'discovery'] });
  assert.equal(stored.size, 1);
  assert.deepEqual(stored.get('stable-profile').atomic_ordering, ['atomic-step', 'discovery']);
  assert.equal(requests[1].url, 'https://caldera.example/api/v2/adversaries/stable-profile');
});

test('upsert does not treat a rejected write as an update', async () => {
  const client = createCalderaClient({
    baseUrl: 'https://caldera.example', apiKey: 'test-only',
    transport: async () => ({ status: 409, ok: false, text: 'conflict' }),
  });
  await assert.rejects(client.upsertAdversary({ adversary_id: 'stable-profile' }), { status: 409 });
  assert.throws(() => client.upsertAdversary({}), { code: 'CALDERA_BAD_ADVERSARY' });
});
