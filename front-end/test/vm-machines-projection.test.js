/**
 * Tests for the per-machine projection on GET /api/cle/courses/:id/vms
 * (cle/routes/vms.js — projectMachines)
 *
 * A lane holds N workstations, but the VM list has always described SLOT 0 only:
 * one row per lane, keyed on config.workstation_vmid. `machines[]` is what lets
 * the UI offer "rebuild just these machines" and what gives the row an honest
 * machine count, so the invariants worth pinning are the ones that would make
 * that picker act on the wrong machine — silently, since every field involved
 * looks plausible when it is wrong:
 *
 *   1. The credential must be resolved PER VMID. src/utils/lane-credentials.js
 *      exists because reversing the per-slot / flattened fallback order hands
 *      every slot of a multi-machine lane slot 0's password. This is that
 *      resolver's newest call site, and the first one that renders every slot at
 *      once — so the bug would now be visible as two identical passwords rather
 *      than one wrong one.
 *   2. ip_confirmed must be per-slot with NO fallback to the flat slot-0 key,
 *      or slot 1 claims a reserved lease nothing ever checked.
 *   3. A legacy lane with no config.workstations[] must still yield a slot 0, or
 *      every lane deployed before that key existed gets no picker at all.
 *   4. The deny-list. guac_connection_id is the identifier the console route
 *      mints tokens against; adding it to a document polled every 8s should be
 *      a deliberate act, not a merge artifact.
 *
 * The function is lifted out of the route source by brace-matching rather than
 * requiring the route, which pulls in the Proxmox client, the CLE pool and the
 * audit writer at require time — the same technique and the same reasoning as
 * provision-slots.test.js.
 *
 * Run: node --test "test/*.test.js"
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const ROUTE = path.join(
  __dirname, '..', 'modules', 'crucible', 'plugins', 'cle', 'routes', 'vms.js'
);
const src = fs.readFileSync(ROUTE, 'utf8');

const { resolveLaneWorkstationCredential } =
  require(path.join(__dirname, '..', 'src', 'utils', 'lane-credentials.js'));

function extractFn(name) {
  let start = src.indexOf(`async function ${name}(`);
  if (start === -1) start = src.indexOf(`function ${name}(`);
  assert.notStrictEqual(start, -1, `${name} not found in vms.js — did it get renamed?`);
  let depth = 0, i = src.indexOf('{', start);
  const open = i;
  for (; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}' && --depth === 0) break;
  }
  return { header: src.slice(start, open), body: src.slice(open, i + 1) };
}

const { header, body } = extractFn('projectMachines');
// The REAL resolver is injected, not a stub: rule 1 above is only meaningful if
// the production fallback order is the thing under test.
// eslint-disable-next-line no-new-func
const projectMachines = new Function(
  'resolveLaneWorkstationCredential',
  `return (${header}${body});`
)(resolveLaneWorkstationCredential);

/** A two-machine lane, shaped the way lane-deployer records one. */
function twoSlotConfig() {
  return {
    // Flat slot-0 mirrors, which every existing reader still uses.
    workstation_vmid: 610003,
    ip: '10.39.16.50',
    ip_confirmed: true,
    console_protocol: 'rdp',
    console_port: 3389,
    console_host: '100.100.60.136',
    console_via: 'gateway',
    guac_connection_id: 'g-slot0',
    workstation_user: 'cactus-user',
    workstation_pass: 'SLOT-ZERO-PASS',
    credentials_source: 'cloudinit',
    ws_ip: { 0: '10.39.16.50' },
    ws_ip_confirmed: { 0: true },
    workstations: [
      {
        slot: 0, vmid: 610003, octet: 50, ip: '10.39.16.50',
        mac: 'BC:24:11:00:00:50', hostname: 'cle-cybv454-10003',
        provider_type: 'qemu', template_id: 't-win', template_name: 'Windows 11',
        console_protocol: 'rdp', console_port: 3389,
        console_host: '100.100.60.136', console_via: 'gateway',
        guac_connection_id: 'g-slot0', workspace_resource_id: 'r-slot0',
        workstation_user: 'cactus-user', workstation_pass: 'SLOT-ZERO-PASS',
        credentials_source: 'cloudinit',
        resources: { cores: 4, memory_mb: 32768 },
      },
      {
        slot: 1, vmid: 310221, octet: 51, ip: '10.39.16.51',
        mac: 'BC:24:11:00:00:51', hostname: 'cle-cybv454-10003-ws1',
        provider_type: 'qemu', template_id: 't-elk', template_name: 'ELK Stack',
        console_protocol: 'rdp', console_port: 3390,
        console_host: '100.100.60.136', console_via: 'gateway',
        guac_connection_id: 'g-slot1', workspace_resource_id: 'r-slot1',
        workstation_user: 'elk-admin', workstation_pass: 'SLOT-ONE-PASS',
        credentials_source: 'cloudinit',
        resources: { cores: 2, memory_mb: 8192 },
      },
    ],
  };
}

const LIVE = { 610003: { vmid: 610003, status: 'running' }, 310221: { vmid: 310221, status: 'stopped' } };

test('a two-slot lane yields two machines in slot order', () => {
  const got = projectMachines(twoSlotConfig(), LIVE, 'active', 'cle-cybv454-10003');
  assert.strictEqual(got.length, 2);
  assert.deepStrictEqual(got.map(m => m.slot), [0, 1]);
  assert.deepStrictEqual(got.map(m => m.vmid), [610003, 310221]);
});

test('each slot gets its OWN password, not slot 0\'s', () => {
  // The bug src/utils/lane-credentials.js:17-19 warns about, at its newest call
  // site. A regression here reads as two students sharing one login.
  const got = projectMachines(twoSlotConfig(), LIVE, 'active', 'lane');
  assert.strictEqual(got[0].workstation_pass, 'SLOT-ZERO-PASS');
  assert.strictEqual(got[1].workstation_pass, 'SLOT-ONE-PASS');
  assert.strictEqual(got[0].workstation_user, 'cactus-user');
  assert.strictEqual(got[1].workstation_user, 'elk-admin');
});

test('a template-sourced password is flagged shared', () => {
  // 'template' means the password is the image's built-in one and identical on
  // every lane from it — the UI has to say so rather than present it as this
  // student's own.
  const cfg = twoSlotConfig();
  cfg.workstations[1].credentials_source = 'template';
  const got = projectMachines(cfg, LIVE, 'active', 'lane');
  assert.strictEqual(got[0].credentials_shared, false);
  assert.strictEqual(got[1].credentials_shared, true);
});

test('ip_confirmed is per-slot and never inherits the flat slot-0 key', () => {
  const cfg = twoSlotConfig();          // ws_ip_confirmed has 0:true, no 1
  const got = projectMachines(cfg, LIVE, 'active', 'lane');
  assert.strictEqual(got[0].ip_confirmed, true);
  assert.strictEqual(got[1].ip_confirmed, false,
    'slot 1 must not inherit slot 0\'s lease confirmation');
  assert.strictEqual(got[0].observed_ip, '10.39.16.50');
  assert.strictEqual(got[1].observed_ip, null);
});

test('power state is live per machine, and falls back to the lane status', () => {
  const got = projectMachines(twoSlotConfig(), LIVE, 'active', 'lane');
  assert.strictEqual(got[0].power_state, 'running');
  assert.strictEqual(got[1].power_state, 'stopped');

  // Not in the cluster at all: 'unknown' for a live lane, the lane's own status
  // otherwise — mirroring how the row-level field is derived.
  assert.strictEqual(projectMachines(twoSlotConfig(), {}, 'active', 'lane')[0].power_state, 'unknown');
  assert.strictEqual(projectMachines(twoSlotConfig(), {}, 'deploying', 'lane')[0].power_state, 'deploying');
});

test('console endpoint is composed per slot, so ports do not collide', () => {
  const got = projectMachines(twoSlotConfig(), LIVE, 'active', 'lane');
  assert.strictEqual(got[0].console_endpoint, '100.100.60.136:3389');
  assert.strictEqual(got[1].console_endpoint, '100.100.60.136:3390');
  assert.strictEqual(got[0].has_console, true);
});

test('a legacy lane with no workstations[] still yields slot 0', () => {
  // Lanes deployed before config.workstations[] existed have only the flat keys.
  // Without this fallback every one of them gets no picker at all.
  const legacy = {
    workstation_vmid: 610007, workstation_ip: '10.39.20.50',
    template_id: 't-win', template_name: 'Windows 11', provider_type: 'qemu',
    console_protocol: 'rdp', console_port: 3389, console_host: '100.100.60.140',
    guac_connection_id: 'g-legacy',
    workstation_user: 'cactus-user', workstation_pass: 'LEGACY', credentials_source: 'cloudinit',
  };
  const got = projectMachines(legacy, { 610007: { status: 'running' } }, 'active', 'cle-old-10007');
  assert.strictEqual(got.length, 1);
  assert.strictEqual(got[0].slot, 0);
  assert.strictEqual(got[0].vmid, 610007);
  assert.strictEqual(got[0].hostname, 'cle-old-10007', 'slot 0 clones under the bare lane name');
  assert.strictEqual(got[0].workstation_pass, 'LEGACY');
  assert.strictEqual(got[0].console_endpoint, '100.100.60.140:3389');
});

test('a lane with nothing recorded at all yields no machines rather than throwing', () => {
  assert.deepStrictEqual(projectMachines({}, {}, 'error', 'lane'), []);
  assert.deepStrictEqual(projectMachines(null, {}, 'error', 'lane'), []);
});

test('a failed slot rebuild surfaces per machine', () => {
  // What lets the picker pre-tick the machines whose last rebuild failed.
  const cfg = twoSlotConfig();
  cfg.rebuild = {
    at: '2026-08-24T18:11:02Z', status: 'partial',
    slots: {
      0: { status: 'ok', at: '2026-08-24T18:12:00Z' },
      1: { status: 'error', at: '2026-08-24T18:13:00Z', message: 'VM 310221 still present after destroy' },
    },
  };
  const got = projectMachines(cfg, LIVE, 'active', 'lane');
  assert.strictEqual(got[0].rebuild_error, null);
  assert.match(got[1].rebuild_error, /still present after destroy/);
  assert.strictEqual(got[1].rebuilt_at, '2026-08-24T18:13:00Z');
});

test('the projection carries no cluster-global or Guacamole identifiers', () => {
  // A deny-list, so adding one of these to an 8s-polled document is a
  // deliberate act rather than a merge artifact. guac_connection_id in
  // particular is what GET /:laneId/console mints tokens against.
  const keys = Object.keys(projectMachines(twoSlotConfig(), LIVE, 'active', 'lane')[0]);
  for (const banned of ['mac', 'octet', 'guac_connection_id', 'workspace_resource_id']) {
    assert.ok(!keys.includes(banned), `${banned} must not be in the machine projection`);
  }
});

test('a malformed entry with no slot is dropped rather than sorted to the front', () => {
  const cfg = twoSlotConfig();
  cfg.workstations.push({ vmid: 999999 });   // no slot
  const got = projectMachines(cfg, LIVE, 'active', 'lane');
  assert.deepStrictEqual(got.map(m => m.slot), [0, 1]);
});
