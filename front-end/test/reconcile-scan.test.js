/**
 * reconcile-scan.test.js — the storage scan's I/O behavior.
 *
 * THE INVARIANT THIS FILE MOSTLY EXISTS FOR
 * scanClusterVolumes() MUST NEVER REJECT. The reconcile handler starts it at
 * t=0 and awaits it last, so it overlaps the cluster and DB queries. If one of
 * those throws first, this promise is never awaited — and an unhandled
 * rejection takes the Node 20 process down. A scan that cannot reach Proxmox at
 * all has to come back as a resolved `complete: false`, not a throw. That is
 * "the node list itself fails" below, and it is the difference between a red
 * banner in the admin UI and a container restart.
 *
 * Everything else here is about not paying for the same Ceph pool N times.
 *
 * Run: node front-end/test/reconcile-scan.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const path = require('path');

// batch-deployer calls getSchedulingConfig() at MODULE level, and site-config
// reads config/site.json, which is gitignored and absent from a plain checkout.
// Same require.cache stub provision-slots.test.js uses.
const UTILS = path.join(__dirname, '..', 'src', 'utils');
require.cache[require.resolve(path.join(UTILS, 'site-config.js'))] = {
  id: 'site-config', filename: 'site-config', loaded: true,
  exports: {
    getSchedulingConfig: () => ({
      min_free_mem_gb: 8, min_free_disk_gb: 20,
      max_concurrent_lanes: 5, max_concurrent_clones: 4,
      node_score_weights: { cpu: 0.35, mem: 0.55, disk: 0.10 },
    }),
    getClusterNodes: () => [],
    getNodeAddress: () => null,
  },
};

const { scanClusterVolumes } = require(path.join(UTILS, 'storage-scan.js'));

const CEPH = { storage: 'ceph-vm', type: 'rbd', shared: 1, content: 'images', active: 1, enabled: 1 };
const LOCAL = { storage: 'local-lvm', type: 'lvmthin', shared: 0, content: 'images', active: 1, enabled: 1 };

/**
 * A fake Proxmox that records every call and tracks peak concurrency.
 * `overrides` maps a path substring to a handler or the string 'hang'.
 */
function fakeProxmox({ nodes, storages = [CEPH, LOCAL], contents = {}, overrides = {} }) {
  const calls = [];
  let inFlight = 0;
  let peak = 0;

  const api = async (method, p) => {
    calls.push(p);
    inFlight++; peak = Math.max(peak, inFlight);
    try {
      for (const [frag, handler] of Object.entries(overrides)) {
        if (p.includes(frag)) {
          if (handler === 'hang') return await new Promise(() => {});
          return await handler(p);
        }
      }
      if (p === '/api2/json/nodes') return nodes;
      if (/\/storage$/.test(p)) return storages;
      const m = p.match(/nodes\/([^/]+)\/storage\/([^/]+)\/content/);
      if (m) return contents[m[2]] || [];
      throw new Error(`unexpected path ${p}`);
    } finally {
      inFlight--;
    }
  };
  return { api, calls, peak: () => peak };
}

const online = (...names) => names.map(node => ({ node, status: 'online' }));
const contentCalls = (calls) => calls.filter(c => c.includes('/content'));

test('a shared pool is listed ONCE, not once per node', async () => {
  const px = fakeProxmox({
    nodes: online('n1', 'n2', 'n3'),
    contents: { 'ceph-vm': [{ volid: 'ceph-vm:vm-600001-disk-0', size: 100 }] },
  });

  const r = await scanClusterVolumes({
    proxmoxAPI: px.api, deadlineAt: Date.now() + 30000, concurrency: 4,
  });

  assert.strictEqual(contentCalls(px.calls).length, 4,
    '1 shared ceph pool + 3 node-local stores; the old scan made 6');
  assert.strictEqual(r.complete, true);
  assert.strictEqual(r.nodes_total, 3);
  assert.strictEqual(r.nodes_scanned, 3);
  assert.strictEqual(r.stats.calls_naive, 6);
  assert.strictEqual(r.stats.calls_saved, 2);
  assert.strictEqual(r.volumes.filter(v => v.storage === 'ceph-vm').length, 1,
    'the shared pool contributes its volumes exactly once');
});

test('offline nodes cost nothing — no socket is opened', async () => {
  const px = fakeProxmox({
    nodes: [...online('n1'), { node: 'n2', status: 'offline' }, { node: 'n3', status: 'offline' }],
  });
  const r = await scanClusterVolumes({ proxmoxAPI: px.api, deadlineAt: Date.now() + 30000 });

  assert.ok(!px.calls.some(c => c.includes('/n2/') || c.includes('/n3/')),
    'reaching an offline node burns the full per-call timeout and returns nothing');
  assert.deepStrictEqual(r.skipped.nodes.map(n => n.node), ['n2', 'n3']);
  assert.strictEqual(r.complete, false, 'unscanned nodes mean the result is partial');
});

test('a failed shared reader falls through to the next node', async () => {
  let firstTry = true;
  const px = fakeProxmox({
    nodes: online('n1', 'n2'),
    storages: [CEPH],
    contents: { 'ceph-vm': [{ volid: 'ceph-vm:vm-600001-disk-0', size: 5 }] },
    overrides: {
      'ceph-vm/content': async (p) => {
        if (firstTry) { firstTry = false; throw new Error('storage not online'); }
        return [{ volid: 'ceph-vm:vm-600001-disk-0', size: 5 }];
      },
    },
  });

  const r = await scanClusterVolumes({ proxmoxAPI: px.api, deadlineAt: Date.now() + 30000 });
  assert.strictEqual(r.volumes.length, 1);
  assert.strictEqual(r.volumes[0].node, 'n2', 'volumes are tagged with the reader that worked');
  assert.strictEqual(r.storages_failed.length, 0);
});

test('every reader failing is reported, not thrown', async () => {
  const px = fakeProxmox({
    nodes: online('n1', 'n2'),
    storages: [CEPH],
    overrides: { 'ceph-vm/content': async () => { throw new Error('rbd: connection timeout'); } },
  });
  const r = await scanClusterVolumes({ proxmoxAPI: px.api, deadlineAt: Date.now() + 30000 });

  assert.strictEqual(r.storages_failed.length, 1);
  assert.match(r.storages_failed[0].reason, /rbd: connection timeout/);
  assert.strictEqual(r.complete, false);
});

test('the node list itself failing RESOLVES — it must never reject', async () => {
  const px = fakeProxmox({
    nodes: [],
    overrides: { '/api2/json/nodes': async () => { throw new Error('ECONNREFUSED'); } },
  });

  // .then/.catch rather than await so a rejection is unmistakable in the result.
  const outcome = await scanClusterVolumes({ proxmoxAPI: px.api, deadlineAt: Date.now() + 30000 })
    .then(v => ({ resolved: true, v }), e => ({ resolved: false, e }));

  assert.strictEqual(outcome.resolved, true,
    'the handler awaits this LAST; a rejection here is an unhandled rejection ' +
    'and Node 20 exits the process');
  assert.deepStrictEqual(outcome.v.volumes, []);
  assert.strictEqual(outcome.v.complete, false);
  assert.match(outcome.v.error, /Could not list cluster nodes: ECONNREFUSED/);
});

test('a hung storage returns partial results at the deadline', async () => {
  const px = fakeProxmox({
    nodes: online('n1'),
    storages: [CEPH, LOCAL],
    contents: { 'local-lvm': [{ volid: 'local-lvm:vm-600002-disk-0', size: 9 }] },
    overrides: { 'ceph-vm/content': 'hang' },
  });

  const started = Date.now();
  const r = await scanClusterVolumes({
    proxmoxAPI: px.api, deadlineAt: started + 2500, concurrency: 4, perCallTimeoutMs: 30000,
  });
  const elapsed = Date.now() - started;

  assert.ok(elapsed < 6000, `returned in ${elapsed}ms — the deadline is a hard floor`);
  assert.strictEqual(r.complete, false);
  assert.ok(r.volumes.some(v => v.storage === 'local-lvm'),
    'whatever finished is still reported');
});

test('an already-expired deadline makes zero calls', async () => {
  const px = fakeProxmox({ nodes: online('n1') });
  const r = await scanClusterVolumes({ proxmoxAPI: px.api, deadlineAt: Date.now() - 1 });
  assert.strictEqual(px.calls.length, 0);
  assert.strictEqual(r.complete, false);
  assert.match(r.error, /no time left/);
});

test('concurrency is respected — pveproxy is a single daemon with few workers', async () => {
  const px = fakeProxmox({
    nodes: online('n1', 'n2', 'n3', 'n4', 'n5', 'n6'),
    overrides: {
      '/content': async () => { await new Promise(r => setTimeout(r, 20)); return []; },
      '/storage': async () => { await new Promise(r => setTimeout(r, 20)); return [CEPH, LOCAL]; },
    },
  });
  await scanClusterVolumes({ proxmoxAPI: px.api, deadlineAt: Date.now() + 30000, concurrency: 3 });
  assert.ok(px.peak() <= 3, `peak in-flight was ${px.peak()}, cap was 3`);
});

test('a transient node-storage failure is retried before giving up', async () => {
  // Requests for a peer are forwarded by the API host over the cluster link,
  // and that hop fails transiently under load. One retry recovers it.
  let n2Calls = 0;
  const px = fakeProxmox({
    nodes: online('n1', 'n2'),
    storages: [LOCAL],
    overrides: {
      // Guarded: overrides match by substring, and the CONTENT path for this
      // node contains '/n2/storage' too.
      '/n2/storage': async (p) => {
        if (!p.endsWith('/storage')) return [];
        n2Calls++;
        if (n2Calls === 1) throw new Error('596 connection error');
        return [LOCAL];
      },
    },
  });

  const r = await scanClusterVolumes({ proxmoxAPI: px.api, deadlineAt: Date.now() + 30000 });
  assert.strictEqual(n2Calls, 2, 'retried once');
  assert.strictEqual(r.nodes_scanned, 2);
  assert.strictEqual(r.complete, true, 'a recovered node is not a coverage hole');
});

test('a node that fails every attempt is named with its reason', async () => {
  const px = fakeProxmox({
    nodes: online('n1', 'n2'),
    storages: [LOCAL],
    overrides: { '/n2/storage': async () => { throw new Error('595 no route to host'); } },
  });

  const r = await scanClusterVolumes({
    proxmoxAPI: px.api, deadlineAt: Date.now() + 30000, nodeListAttempts: 2,
  });
  assert.strictEqual(r.nodes_scanned, 1);
  const n2 = r.skipped.nodes.find(n => n.node === 'n2');
  assert.ok(n2, 'the node must appear in the skip list, not vanish');
  assert.match(n2.reason, /595 no route to host/,
    'the raw Proxmox error is the only thing that points at a cause');
  assert.deepStrictEqual(r.coverage.nodes_unlisted, ['n2']);
});

test('losing nodes leaves shared coverage complete on a Ceph cluster', async () => {
  const px = fakeProxmox({
    nodes: online('n1', 'n2', 'n3'),
    storages: [CEPH, LOCAL],
    contents: { 'ceph-vm': [{ volid: 'ceph-vm:vm-600001-disk-0', size: 5 }] },
    overrides: {
      '/n2/storage': async () => { throw new Error('596 connection error'); },
      '/n3/storage': async () => { throw new Error('596 connection error'); },
    },
  });

  const r = await scanClusterVolumes({ proxmoxAPI: px.api, deadlineAt: Date.now() + 30000 });
  assert.strictEqual(r.nodes_scanned, 1, 'only n1 answered');
  assert.strictEqual(r.coverage.shared_complete, true,
    'the Ceph pool was still read in full — from n1, which is all it takes');
  assert.strictEqual(r.coverage.shared_read, 1);
  assert.ok(r.volumes.some(v => v.storage === 'ceph-vm'), 'and its volumes are present');
  assert.strictEqual(r.complete, false, 'n2/n3 local images remain unknown');
});

test('storageFilter narrows the scan (used by the disk sweep)', async () => {
  const px = fakeProxmox({ nodes: online('n1', 'n2'), storages: [CEPH, LOCAL] });
  await scanClusterVolumes({
    proxmoxAPI: px.api, deadlineAt: Date.now() + 30000, storageFilter: 'ceph-vm',
  });
  const listed = contentCalls(px.calls);
  assert.strictEqual(listed.length, 1);
  assert.ok(listed[0].includes('ceph-vm'));
});

test('onProgress reports completion against the planned job count', async () => {
  const px = fakeProxmox({ nodes: online('n1', 'n2') });
  const seen = [];
  await scanClusterVolumes({
    proxmoxAPI: px.api, deadlineAt: Date.now() + 30000,
    onProgress: (done, total) => seen.push([done, total]),
  });
  assert.strictEqual(seen.length, 3, '1 shared + 2 local jobs');
  assert.deepStrictEqual(seen[seen.length - 1], [3, 3]);
});
