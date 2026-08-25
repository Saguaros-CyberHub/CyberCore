/**
 * reconcile-ui.test.js — the audit panel and the admin API client.
 *
 * TWO THINGS ARE PINNED HERE
 *
 * 1. The refactor that moved the audit off the request path rewrote
 *    runReconcile() around a poller and moved the result markup into
 *    renderReconcileResult(). Every row in that markup carries a destroy
 *    button, and several are wired by delegation on data attributes rather
 *    than inline onclick — so dropping one during the move would be invisible
 *    in review and would silently disarm a repair the audit still advertises.
 *    The first block asserts each hook survives.
 *
 * 2. api() used to call resp.json() BEFORE checking resp.ok. When the
 *    Cloudflare tunnel gave up on the origin at 100s it returned an HTML page,
 *    so the operator saw `Unexpected token '<', "<!DOCTYPE "... is not valid
 *    JSON` — a parse error standing in for a timeout, with the status that
 *    explained it thrown away. The second block pins the readable message AND
 *    the err.status / err.data contract that existing callers depend on.
 *
 * Follows the repo's vm-stub idiom (see audit-ui.test.js, sidebar-nav.test.js).
 *
 * Run: node front-end/test/reconcile-ui.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const PUB = path.join(__dirname, '..', 'public');
const LANES_SRC = fs.readFileSync(path.join(PUB, 'js', 'admin', 'admin-lanes.js'), 'utf8');
const CORE_SRC = fs.readFileSync(path.join(PUB, 'js', 'admin', 'admin-core.js'), 'utf8');
const ADMIN_HTML = fs.readFileSync(path.join(PUB, 'admin.html'), 'utf8');

// ============================================================================
// A reconcile payload exercising every section at once.
// ============================================================================
const RESULT = {
  timestamp: '2026-08-24T18:02:11.412Z',
  duration_ms: 6400,
  summary: {
    proxmox_cyberhub_vms: 42, db_active_lanes: 20, db_expected_vms: 60,
    orphaned_on_proxmox: 1, stale_in_db: 1, sdn_zones: 3, orphaned_zones: 1,
    sdn_vnets: 9, orphaned_vnets: 1, deployed_groups: 2,
    orphaned_disks: 1, orphaned_disks_total_gb: '32.00', orphaned_guac_connections: 1,
    cluster_nodes_live: 10, cluster_nodes_declared: 6, nodes_undeclared: 1,
    nodes_stale_declared: 0, nodes_ip_mismatch: 0, nodes_offline: 0,
    zones_peer_drift: 1, node_drift_issues: 2,
    disk_scan_complete: true, disk_scan_trusted: true,
  },
  orphaned_on_proxmox: [{ vmid: 600999, name: 'ghost', status: 'stopped', node: 'n1', type: 'qemu', role: 'challenge', vxlan_inferred: 999 }],
  stale_in_db: [{ lane_id: 'aaaaaaaa-bbbb', name: 'dead lane', vxlan_id: 12, status: 'active', created_at: '2026-08-01T00:00:00Z' }],
  orphaned_zones: [{ zone: 'ghostz', type: 'vxlan', vnet_count: 2 }],
  orphaned_vnets: [{ vnet: 'ghostv', zone: 'gonez', tag: 55 }],
  orphaned_disks: [{ vmid: 600999, role: 'challenge', volid: 'ceph-vm:vm-600999-disk-0', node: 'n1', storage: 'ceph-vm', size_gb: '32.00', shared: true }],
  orphaned_guac_connections: [{ id: '77', name: 'x - y - Kali', protocol: 'rdp', parent: 'ROOT', tracked: true }],
  cluster_nodes: {
    live: [
      { node: 'n1', status: 'online', live_ip: '100.100.10.10', declared_ip: '100.100.10.10', declared: true, vm_count: 4 },
      { node: 'n6', status: 'online', live_ip: '100.100.10.16', declared_ip: null, declared: false, vm_count: 2 },
    ],
    undeclared: [{ node: 'n6', status: 'online', live_ip: '100.100.10.16', schedulable: true }],
    stale_declared: [], ip_mismatch: [], offline: [],
    declared_count: 6, live_count: 10, issue_count: 1,
    config_stale_in_memory: false,
  },
  zone_peer_drift: [{
    zone: 'goadlab', type: 'vxlan', readable: true,
    peers: '100.100.10.10', peers_list: ['100.100.10.10'],
    expected_peers: ['100.100.10.10', '100.100.10.16'],
    missing_peers: ['100.100.10.16'], extra_peers: [], vnet_count: 12, digest: 'abc123',
  }],
  sdn_pending: false,
  disk_scan: { complete: true, trusted: true, warnings: [] },
  guac_scan: { ok: true },
  cluster_view: { nodes_total: 10, nodes_online: 10, trusted: true },
  warnings: [],
};

const clone = (o) => JSON.parse(JSON.stringify(o));

function makeContext() {
  const elements = new Map();
  const el = (id) => {
    if (!elements.has(id)) {
      elements.set(id, {
        id, value: '', innerHTML: '', textContent: '', disabled: false, style: {},
        dataset: {}, classList: { add() {}, remove() {}, contains: () => false },
        closest: () => null, querySelectorAll: () => [],
      });
    }
    return elements.get(id);
  };

  const context = {
    document: {
      getElementById: el,
      addEventListener() {},
      querySelectorAll: () => [],
      visibilityState: 'visible',
      createElement: () => ({ style: {}, click() {} }),
    },
    escHtml: (s) => String(s ?? '')
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;'),
    formatTime: (s) => `${s}s`,
    api: async () => ({}),
    Toast: { success() {}, error() {}, warning() {}, info() {} },
    Confirm: { show: async () => true },
    Utils: { setBtnLoading() {} },
    navigator: { clipboard: { writeText: async () => {} } },
    setInterval: () => 0, clearInterval() {}, setTimeout: () => 0, clearTimeout() {},
    Date, JSON, Math, console, encodeURIComponent, URLSearchParams, parseFloat, parseInt,
  };
  context.window = context;
  vm.createContext(context);
  vm.runInContext(LANES_SRC, context);
  return { context, el };
}

// ============================================================================
// 1. THE MOVE DROPPED NOTHING
// ============================================================================

test('every repair hook survives the render refactor', () => {
  const { context, el } = makeContext();
  context.renderReconcileResult(clone(RESULT), { age_seconds: 12 });
  const html = el('reconcileResults').innerHTML;

  for (const hook of [
    'destroyOrphanVM(600999',
    "markLaneDeleted('aaaaaaaa-bbbb'",
    "destroyOrphanZone('ghostz'",
    "destroyOrphanVNet('ghostv'",
    'destroyOrphanDisk(',
    'class="btn btn-sm guac-conn-delete"',
    'data-conn-id="77"',
    'sweepAllOrphanDisks(this)',
    'sweepAllOrphanGuacConns(this)',
  ]) {
    assert.ok(html.includes(hook), `missing repair hook: ${hook}`);
  }
});

test('the header shows relative age and a re-scan control', () => {
  const { context, el } = makeContext();
  context.renderReconcileResult(clone(RESULT), { age_seconds: 240 });
  const html = el('reconcileResults').innerHTML;
  assert.ok(html.includes('Last audited'));
  assert.ok(html.includes('4m ago'));
  assert.ok(html.includes('runReconcile()'), 'Re-scan button');
});

test('node drift alone flips the badge off "In Sync"', () => {
  const r = clone(RESULT);
  // Everything clean EXCEPT the new node checks.
  Object.assign(r.summary, {
    orphaned_on_proxmox: 0, stale_in_db: 0, orphaned_zones: 0,
    orphaned_vnets: 0, orphaned_disks: 0, orphaned_guac_connections: 0,
  });
  r.orphaned_on_proxmox = []; r.stale_in_db = []; r.orphaned_zones = [];
  r.orphaned_vnets = []; r.orphaned_disks = []; r.orphaned_guac_connections = [];

  const { context, el } = makeContext();
  context.renderReconcileResult(r, { age_seconds: 0 });
  const html = el('reconcileResults').innerHTML;
  assert.ok(html.includes('Issues Found'),
    'a node that is invisible to SSH must not read as "In Sync"');
  assert.ok(!html.includes('All clear'));
});

test('an undeclared node gets a copyable site.json snippet naming it', () => {
  const { context, el } = makeContext();
  context.renderReconcileResult(clone(RESULT), { age_seconds: 0 });
  const html = el('reconcileResults').innerHTML;
  assert.ok(html.includes('Nodes missing from site.json'));
  assert.ok(html.includes('&quot;n6&quot;: &quot;100.100.10.16&quot;'), 'the snippet names node and IP');
  assert.ok(html.includes('copySiteJsonSnippet'));
  assert.ok(html.includes('already receiving lane deployments'),
    'the operator has to know these nodes are live, not merely misconfigured');
});

test('a drifted zone offers a repair; an unreadable one does not', () => {
  const { context, el } = makeContext();
  context.renderReconcileResult(clone(RESULT), { age_seconds: 0 });
  let html = el('reconcileResults').innerHTML;
  assert.ok(html.includes('class="btn btn-sm zone-peers-fix"'));
  assert.ok(html.includes('data-zone="goadlab"'));
  assert.ok(html.includes('data-digest="abc123"'));
  assert.ok(!html.includes('Fix All'), 'applying SDN is cluster-wide — no bulk control');

  const r = clone(RESULT);
  r.zone_peer_drift = [{ zone: 'z', type: 'vxlan', readable: false, peers: null, peers_list: [], expected_peers: ['1.2.3.4'], missing_peers: [], extra_peers: [], vnet_count: 0, digest: null }];
  const ctx2 = makeContext();
  ctx2.context.renderReconcileResult(r, { age_seconds: 0 });
  html = ctx2.el('reconcileResults').innerHTML;
  assert.ok(!html.includes('zone-peers-fix'),
    'never offer to overwrite peers nobody managed to read');
  assert.ok(html.includes('no repair offered'));
});

test('an untrusted scan disables Sweep All but still lists the disks', () => {
  const r = clone(RESULT);
  r.disk_scan = { complete: false, trusted: false, warnings: ['Disk scan incomplete — 8 of 10 nodes scanned.'] };
  r.warnings = ['Disk scan incomplete — 8 of 10 nodes scanned.'];

  const { context, el } = makeContext();
  context.renderReconcileResult(r, { age_seconds: 0 });
  const html = el('reconcileResults').innerHTML;

  assert.ok(!html.includes('sweepAllOrphanDisks(this)'),
    'a bulk delete against a partial cluster view can destroy a live VM disk');
  assert.ok(html.includes('Sweep All disabled'));
  assert.ok(html.includes('destroyOrphanDisk('), 'individual rows remain — the finding is still real');
  assert.ok(html.includes('8 of 10 nodes scanned'), 'the warning is surfaced, not just logged');
});

test('a partial scan names every node it missed, and why', () => {
  // The original report was a bare "3 of 9 nodes scanned" with no way to find
  // out which six or what went wrong. The reasons were in the payload all
  // along and simply were not rendered.
  const r = clone(RESULT);
  r.disk_scan = {
    complete: false, trusted: false, nodes_total: 9, nodes_scanned: 3,
    duration_ms: 8200, calls_made: 14,
    coverage: { shared_total: 2, shared_read: 2, local_total: 3, local_read: 3, shared_complete: true },
    nodes_skipped: [
      { node: 'cyberhub-node-6', reason: '595 no route to host' },
      { node: 'cyberhub-node-7', reason: 'offline' },
    ],
    storages_failed: [{ node: 'cyberhub-node-8', storage: 'local-lvm', shared: false, reason: 'timed out after 12s' }],
    warnings: [],
  };

  const { context, el } = makeContext();
  context.renderReconcileResult(r, { age_seconds: 0 });
  const html = el('reconcileResults').innerHTML;

  assert.ok(html.includes('Disk Scan Coverage'));
  assert.ok(html.includes('cyberhub-node-6') && html.includes('595 no route to host'));
  assert.ok(html.includes('cyberhub-node-7') && html.includes('offline'));
  assert.ok(html.includes('cyberhub-node-8') && html.includes('timed out after 12s'),
    'a failed storage is a coverage hole just like an unreachable node');
  assert.ok(html.includes('3 of 9'), 'the ratio is still stated');
  assert.ok(html.includes('PROXMOX_API_URL'),
    'point at the forwarding hop — repeated same-node failures are usually that');
});

test('a complete scan shows no coverage table', () => {
  const { context, el } = makeContext();
  context.renderReconcileResult(clone(RESULT), { age_seconds: 0 });
  assert.ok(!el('reconcileResults').innerHTML.includes('Disk Scan Coverage'));
});

test('a shared-storage disk is labelled as such', () => {
  const { context, el } = makeContext();
  context.renderReconcileResult(clone(RESULT), { age_seconds: 0 });
  assert.ok(el('reconcileResults').innerHTML.includes('(shared)'),
    'otherwise the Node column implies the disk lives only on that one node');
});

test('progress renders a counted phase line', () => {
  const { context, el } = makeContext();
  context.renderReconcileProgress({ phase: 'storage', done: 6, total: 11, elapsed_s: 74 });
  const html = el('reconcileResults').innerHTML;
  assert.ok(html.includes('Scanning storage — 6/11 storage targets'));
  assert.ok(html.includes('55%'), 'progress bar width: round(6/11 * 100)');
});

test('an aborted job offers a forced re-run; an ordinary failure does not', () => {
  const { context, el } = makeContext();
  context.renderReconcileError('Scan aborted — the server restarted during the audit. Re-run it.', true);
  assert.ok(el('reconcileResults').innerHTML.includes('runReconcile(true)'));

  context.renderReconcileError('Proxmox unreachable', false);
  assert.ok(!el('reconcileResults').innerHTML.includes('runReconcile(true)'));
});

test('reconcileAgeLabel reads naturally across scales', () => {
  const { context } = makeContext();
  assert.strictEqual(context.reconcileAgeLabel(null), 'never');
  assert.strictEqual(context.reconcileAgeLabel(3), 'just now');
  assert.strictEqual(context.reconcileAgeLabel(240), '4m ago');
  assert.strictEqual(context.reconcileAgeLabel(7200), '2h ago');
});

test('the audit lives on its own tab, wired to render the cached result', () => {
  assert.ok(
    /switchTab\('audit', this\);\s*reconcileTabActivate\(\)/.test(ADMIN_HTML),
    'without this the tab only fills in after clicking Audit Proxmox');
  assert.ok(/<div class="tab-content" id="tab-audit">/.test(ADMIN_HTML));
  assert.ok(/id="btnReconcile"/.test(ADMIN_HTML) && /id="reconcileResults"/.test(ADMIN_HTML));
});

test('the audit is no longer scoped to Active Lanes', () => {
  assert.ok(
    /switchTab\('lanes', this\)"/.test(ADMIN_HTML),
    'the lanes tab should carry no audit hook');
  assert.ok(!/switchTab\('lanes', this\);\s*reconcileTabActivate/.test(ADMIN_HTML));

  // Both ids must exist exactly once, or switchTab and getElementById would
  // resolve to whichever copy the parser saw first.
  assert.strictEqual((ADMIN_HTML.match(/id="reconcileResults"/g) || []).length, 1);
  assert.strictEqual((ADMIN_HTML.match(/id="btnReconcile"/g) || []).length, 1);

  const lanesTab = ADMIN_HTML.slice(
    ADMIN_HTML.indexOf('id="tab-lanes"'), ADMIN_HTML.indexOf('id="tab-audit"'));
  assert.ok(!lanesTab.includes('reconcileResults'), 'the panel moved out of the lanes tab');
  assert.ok(!lanesTab.includes('runReconcile()'), 'so did the trigger');
});

test('the empty state explains the audit and offers to run it', () => {
  const { context, el } = makeContext();
  context.renderReconcileEmpty();
  const html = el('reconcileResults').innerHTML;
  assert.ok(html.includes('No audit has been run yet'));
  assert.ok(html.includes('runReconcile()'), 'a dedicated tab needs a way forward');
  assert.ok(/[Rr]ead-only/.test(html), 'say that looking costs nothing before they click');
});

test('an unreadable cache says so rather than passing for a fresh result', () => {
  const { context, el } = makeContext();
  context.renderReconcileEmpty('Could not load the last audit result.');
  assert.ok(el('reconcileResults').innerHTML.includes('Could not load the last audit result.'));
});

test('the result panel cannot blank its own tab', () => {
  const { context, el } = makeContext();
  context.renderReconcileResult(clone(RESULT), { age_seconds: 0 });
  const html = el('reconcileResults').innerHTML;
  assert.ok(!html.includes('Dismiss'),
    'Dismiss made sense under Active Lanes, where hiding the panel revealed the ' +
    'lane table; on its own tab it just empties the page');
  assert.ok(html.includes('runReconcile()'), 'Re-scan remains the way to refresh');
});

test('Sweep All no longer sends a VMID pattern that skips two ranges', () => {
  assert.ok(!LANES_SRC.includes('^[167][0-9]{5}$') || LANES_SRC.includes('// audited with. The old'),
    'the literal may survive only inside the comment explaining why it went');
  const sweepCall = LANES_SRC.slice(LANES_SRC.indexOf('async function sweepAllOrphanDisks'));
  const body = sweepCall.slice(0, sweepCall.indexOf('\n}'));
  assert.ok(!/vmid_pattern:\s*'/.test(body),
    'goad_controller (2xxxxx) and attached_module (8xxxxx) disks were listed in ' +
    'the table but excluded from the sweep the button ran');
});

// ============================================================================
// 2. THE api() CONTRACT
// ============================================================================

function makeApi(fetchImpl) {
  const context = {
    localStorage: { getItem: () => 'tok' },
    fetch: fetchImpl,
    AbortController, setTimeout, clearTimeout,
    document: { getElementById: () => ({ style: {}, classList: { add() {}, remove() {} } }), querySelectorAll: () => [], addEventListener() {} },
    Toast: { success() {}, error() {} },
    console, JSON, Date, Math, URLSearchParams, encodeURIComponent,
  };
  context.window = context;
  vm.createContext(context);
  vm.runInContext(CORE_SRC, context);
  return context.api;
}

const resp = (status, body, ok) => async () => ({
  ok: ok !== undefined ? ok : status < 400,
  status,
  text: async () => body,
});

test('THE REPORTED BUG: an HTML 524 page reads as a gateway timeout', async () => {
  const api = makeApi(resp(524, '<!DOCTYPE html><html><head><title>524</title></head></html>'));
  const err = await api('GET', '/reconcile').then(() => null, e => e);

  assert.ok(err, 'must still throw');
  assert.match(err.message, /^Gateway timeout \(524\)/,
    "the operator saw `Unexpected token '<'` — a parse error standing in for a timeout");
  assert.strictEqual(err.status, 524, 'the status that explains the failure must survive');
  assert.ok(err.data.raw.startsWith('<!DOCTYPE'), 'the body is kept for diagnosis');
});

test('the err.status / err.data contract is unchanged for JSON errors', async () => {
  const api = makeApi(resp(409, JSON.stringify({ error: 'Audience shifted', recipients: 12 })));
  const err = await api('POST', '/broadcast', { x: 1 }).then(() => null, e => e);

  assert.strictEqual(err.message, 'Audience shifted');
  assert.strictEqual(err.status, 409);
  assert.strictEqual(err.data.recipients, 12,
    'callers read err.data to tell a re-check apart from a failure');
});

test('a JSON 2xx still returns its parsed body; an empty one returns null', async () => {
  assert.deepStrictEqual(await makeApi(resp(200, '{"ok":true}'))('GET', '/x'), { ok: true });
  assert.strictEqual(await makeApi(resp(204, ''))('GET', '/x'), null,
    'an empty 2xx used to throw on resp.json()');
});

test('a 2xx carrying HTML throws rather than returning a string', async () => {
  const err = await makeApi(resp(200, '<html>login</html>'))('GET', '/x').then(() => null, e => e);
  assert.match(err.message, /Unexpected non-JSON response \(200\)/);
  assert.strictEqual(err.status, 200);
});

test('a client-side abort reports the timeout and keeps status numeric', async () => {
  const api = makeApi(async () => { const e = new Error('aborted'); e.name = 'AbortError'; throw e; });
  const err = await api('GET', '/slow', null, { timeoutMs: 5000 }).then(() => null, e => e);
  assert.match(err.message, /Request timed out after 5s/);
  assert.strictEqual(err.status, 0);
  assert.strictEqual(err.data, null);
});

test('a dead network is named as such', async () => {
  const api = makeApi(async () => { throw new TypeError('Failed to fetch'); });
  const err = await api('GET', '/x').then(() => null, e => e);
  assert.match(err.message, /Network error: Failed to fetch/);
  assert.strictEqual(err.status, 0);
});

test('every gateway status the tunnel can emit has a readable message', async () => {
  for (const status of [502, 503, 504, 520, 521, 522, 523, 524]) {
    const err = await makeApi(resp(status, '<html>err</html>'))('GET', '/x').then(() => null, e => e);
    assert.ok(!/Unexpected token/.test(err.message), `${status} leaked a parse error`);
    assert.ok(err.message.includes(String(status)), `${status} is not named in its message`);
  }
});

// ============================================================================
// LANE DRIFT TABLE + PURGE
// ============================================================================
// The drift table is what makes the leak visible: `released_but_alive` names a
// lane whose record has already given its VXLAN back to the pool while its
// machines keep running, which is the state nothing in the UI could show before.

const DRIFT = [
  { lane_id: 'dead-1', name: 'old-lane', vxlan_id: 77, status: 'error',
    expected_count: 2, present_count: 1, present_vmids: [100077], missing_vmids: [600077],
    drift: 'released_but_alive', purgeable: true, claims_infra: false,
    reason: 'Status error released this lane VXLAN for reuse, but 1 machine is still running.' },
  { lane_id: 'half-2', name: 'partly-gone', vxlan_id: 88, status: 'active',
    expected_count: 3, present_count: 2, present_vmids: [100088, 600088], missing_vmids: [700088],
    drift: 'partial', purgeable: true, claims_infra: true,
    reason: '1 of 3 machines are missing.' },
  { lane_id: 'nonet-3', name: 'no-network', vxlan_id: 99, status: 'active',
    expected_count: 2, present_count: 2, present_vmids: [100099, 600099], missing_vmids: [],
    drift: 'infra_missing', purgeable: false, claims_infra: true,
    reason: 'No SDN VNet carries tag 99.' },
];

const withDrift = (extra = {}) => {
  const r = clone(RESULT);
  r.lane_drift = clone(DRIFT);
  r.job_id = 'rc_test_abcd1234';
  Object.assign(r.summary, {
    lanes_released_but_alive: 1, lanes_partial: 1, lanes_infra_missing: 1, lanes_needing_purge: 2,
  });
  return Object.assign(r, extra);
};

test('the drift table renders a Purge button only for purgeable rows', () => {
  const { context, el } = makeContext();
  context.renderReconcileResult(withDrift(), { age_seconds: 4 });
  const html = el('reconcileResults').innerHTML;

  assert.ok(html.includes('Lanes Needing Attention'), 'the drift section must render');
  assert.ok(html.includes("purgeLane('dead-1'"), 'released_but_alive must offer Purge');
  assert.ok(html.includes("purgeLane('half-2'"), 'partial must offer Purge');
  assert.ok(!html.includes("purgeLane('nonet-3'"),
    'infra_missing must NOT offer Purge — the machines are fine, the network is not');
});

test('the drift table names the danger rather than just labelling it', () => {
  const { context, el } = makeContext();
  context.renderReconcileResult(withDrift(), { age_seconds: 4 });
  const html = el('reconcileResults').innerHTML;
  assert.ok(html.includes('Released but alive'), 'the severe verdict needs a plain-language label');
  assert.ok(/1\/2 up/.test(html), 'the machine count must be visible per row');
  assert.ok(html.includes('collide'), 'the header must say why released_but_alive matters');
});

test('a degraded scan disables every Purge button', () => {
  // Exactly the rule Sweep All already follows. A quorum-less cluster drops
  // every guest out of /cluster/resources, so every lane looks gone — each with
  // a destructive button beside it.
  const { context, el } = makeContext();
  const r = withDrift();
  r.disk_scan = { complete: false, trusted: false, warnings: ['degraded'] };
  context.renderReconcileResult(r, { age_seconds: 4 });
  const html = el('reconcileResults').innerHTML;
  assert.ok(!html.includes('purgeLane('), 'no purge may be offered on an untrusted scan');
});

test('an absent lane_drift key renders nothing rather than throwing', () => {
  // The audit payload is a contract the UI renders directly, and an older cached
  // result predates this field entirely.
  const { context, el } = makeContext();
  context.renderReconcileResult(clone(RESULT), { age_seconds: 4 });
  assert.ok(!el('reconcileResults').innerHTML.includes('Lanes Needing Attention'));
});

test('the rendered audit job id is captured for the repair calls', () => {
  // Every destructive call sends this so the server can 409 a stale render
  // rather than acting on a table that may be a day old.
  //
  // Asserted against the source, not the sandbox: `_rec` is a top-level `const`,
  // and vm.runInContext puts only `var`s and function declarations on the
  // context object, so there is nothing to read back at runtime.
  const start = LANES_SRC.indexOf('function renderReconcileResult(');
  assert.notStrictEqual(start, -1);
  const head = LANES_SRC.slice(start, start + 900);
  assert.match(head, /_rec\.resultJobId = r\.job_id \|\| null;/,
    'renderReconcileResult must stamp the job id of the result it is drawing');
});

test('every destructive client call carries audit_job_id', () => {
  // Source-level: the calls are inside async handlers that need a live server to
  // exercise, but the omission is silent — the server simply never checks.
  for (const hook of [
    "'/reconcile/destroy-vm'",
    "'/reconcile/destroy-zone'",
    "'/reconcile/destroy-vnet'",
    "'/reconcile/destroy-disk'",
    "'/reconcile/destroy-guac-connection'",
    "'/reconcile/mark-deleted'",
    "'/sweep-orphaned-disks'",
  ]) {
    const at = LANES_SRC.indexOf(hook);
    assert.notStrictEqual(at, -1, `missing call site for ${hook}`);
    const call = LANES_SRC.slice(at, LANES_SRC.indexOf(')', at + hook.length) + 1);
    assert.ok(call.includes('audit_job_id'),
      `${hook} must send audit_job_id — without it the server cannot detect a stale page: ${call}`);
  }
});

test('purgeLane dry-runs before it destroys', () => {
  // A lane's VMIDs are mostly DERIVED from vxlan_id, so "purge lane 42" can mean
  // a different set of machines than the operator expects. Confirming against
  // the real target list beats confirming against a lane name.
  const start = LANES_SRC.indexOf('async function purgeLane(');
  assert.notStrictEqual(start, -1, 'purgeLane must exist');
  const fn = LANES_SRC.slice(start, start + 3000);
  const dry = fn.indexOf('dry_run: true');
  const confirm = fn.indexOf('Confirm.show');
  assert.ok(dry !== -1 && confirm !== -1 && dry < confirm,
    'the dry run must happen before the confirmation dialog');
  assert.ok(fn.includes('confirm_vxlan'), 'the VXLAN must be confirmed back to the server');
  assert.ok(fn.includes('contested'), 'a recycled VXLAN must be surfaced to the operator');
});
