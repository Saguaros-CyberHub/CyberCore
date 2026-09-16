'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createCalderaClient } = require('../src/incident/caldera/client');

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
