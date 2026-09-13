/**
 * lane-gateway-template.test.js — which LXC template a lane gateway is cloned from.
 *
 * WHY THIS FILE EXISTS
 * resolveGatewayVmid had no test at all, and retiring the v1 subnet scheme very
 * nearly turned that gap into a broken deploy.
 *
 * The old body consulted a per-module v1 map first:
 *
 *     const v1Map = { cyberlabs: 1691, crucible: 1692, forge: 1693 };
 *     return v1Map[module] || (spec && spec.gateway_vmid) || 1692;
 *
 * Every module that exists was IN that map, so the spec.gateway_vmid override
 * could never be reached. Deleting the map alongside the rest of v1 handed it
 * reach for the first time — which reads like fixing a latent bug and is in fact
 * the opposite, because of what the one stored value points at.
 *
 * There is exactly one spec.gateway_vmid in the repository: the seeded
 * metasploitable2-basic challenge (migrations/007_cybercore_tables.sql) carries
 * 1699. 1699 WAS the original shared gateway template. That id has since been
 * recycled — it is KALI_TEMPLATE_VMID today, a QEMU image. Honouring the
 * override would make that challenge issue an LXC clone of the Kali template as
 * its lane gateway. Every other gateway_vmid in the codebase is a lane INSTANCE
 * id (GATEWAY_VMID_OFFSET + vxlanId), not a template, so nothing would have
 * gained from switching it on either.
 *
 * So the field stays inert, exactly as it behaved at runtime before. These tests
 * pin that, and pin the two live templates, because the next person to delete a
 * branch here will face the same inviting-looking dead code.
 *
 * Run: node --test "test/*.test.js"
 */

const { test } = require('node:test');
const assert = require('node:assert');
const path = require('node:path');

const UTILS = path.join(__dirname, '..', 'src', 'utils');

function stub(rel, exports) {
  const p = require.resolve(path.join(UTILS, rel));
  require.cache[p] = { id: p, filename: p, loaded: true, exports };
  return exports;
}

// lane-networking reads site.json through site-config at first access; the file
// is gitignored and absent in a plain checkout.
stub('site-config.js', {
  getV2LabNetwork: () => ({
    bridge: 'vmbr0', vlan_tag: 60, subnet: '100.100.60.0/22',
    gateway: '100.100.60.1',
    host_range: { first: '100.100.60.10', last: '100.100.63.254' },
    reserved: [],
  }),
  getSchedulingConfig: () => ({ min_free_mem_gb: 8, min_free_disk_gb: 20 }),
  getDefaultTemplateNode: () => 'node-5',
  getClusterNodes: () => [],
  getNodeAddress: () => null,
  getPhysicalClusterIps: () => ({}),
});
stub('tailscale.js', { isEnabled: () => false });

const net = require(path.join(UTILS, 'lane-networking.js'));

// ── the two templates that still exist ──────────────────────────────────────

test('a v2 lane clones the single-LAN gateway, a v3 lane the segmented one', () => {
  assert.strictEqual(net.resolveGatewayVmid('crucible', 'v2'), 1694);
  assert.strictEqual(net.resolveGatewayVmid('crucible', 'v3'), 1695);
});

test('the module no longer selects the template', () => {
  // It used to: cyberlabs got 1691, crucible 1692, forge 1693. The parameter is
  // retained only because five call sites pass it positionally, so dropping it
  // would slide subnetScheme into its place.
  for (const mod of ['crucible', 'cyberlabs', 'forge', 'anything-else', undefined]) {
    assert.strictEqual(net.resolveGatewayVmid(mod, 'v2'), 1694, `module ${mod} must not change the answer`);
    assert.strictEqual(net.resolveGatewayVmid(mod, 'v3'), 1695, `module ${mod} must not change the answer`);
  }
});

// ── the trap ────────────────────────────────────────────────────────────────

test('THE TRAP: spec.gateway_vmid is inert, because its one stored value is now the Kali template', () => {
  // This is the seeded metasploitable2-basic shape, verbatim: a v2 challenge
  // whose spec still carries the 1699 it was written with years ago.
  const seeded = { gateway_vmid: 1699 };

  assert.strictEqual(net.resolveGatewayVmid('crucible', 'v2', seeded), 1694,
    'a stale spec.gateway_vmid must NOT become the gateway template');
  assert.strictEqual(net.resolveGatewayVmid('crucible', 'v3', seeded), 1695,
    'and it must not override the segmented gateway either');

  // The reason it must not, stated as an assertion rather than a comment: the
  // value collides with a QEMU image, so honouring it would clone the wrong kind
  // of machine.
  assert.strictEqual(net.KALI_TEMPLATE_VMID, 1699,
    '1699 is the Kali QEMU template — if this id is ever reassigned again, re-read the header of this file');
});

test('no scheme resolves to a retired v1 template', () => {
  // 1691/1692/1693 were the per-module v1 gateways. 1692 in particular still
  // EXISTS on the cluster, deliberately — it is the frozen clone ancestor of
  // 1694 and therefore of 1695 (see v2_gateway/bake.sh) — so a resolver bug that
  // returned it would not fail loudly at clone time. It would quietly build a
  // lane on a gateway with no cybercore firstboot, no Tailscale, and a baked
  // 192.18.0.1 lan0. That is precisely the failure this assertion exists to stop.
  const retired = new Set([1691, 1692, 1693]);
  for (const scheme of ['v2', 'v3', 'v1', 'nonsense', undefined, null]) {
    for (const mod of ['crucible', 'cyberlabs', 'forge']) {
      const got = net.resolveGatewayVmid(mod, scheme, { gateway_vmid: 1692 });
      assert.ok(!retired.has(got),
        `scheme ${scheme} on module ${mod} resolved to retired v1 template ${got}`);
    }
  }
});

// ── the scheme itself ───────────────────────────────────────────────────────

test('resolveLaneNetworking refuses a retired scheme by name, not by WAN address', () => {
  // The ordering here is the whole point. Letting anything non-v3 fall into the
  // v2 arm would be one line shorter and the wrong answer: a v1 lane never had a
  // pooled WAN address, so it would fail with "needs its allocated WAN address
  // passed as opts.wanIp" — true, and completely the wrong diagnosis. The lane is
  // not missing an address; its scheme no longer exists.
  assert.throws(
    () => net.resolveLaneNetworking('v1', 'crucible', 10881, { wanIp: '100.100.60.20' }),
    (err) => {
      assert.match(err.message, /v1/, 'the message must name the scheme that was refused');
      assert.doesNotMatch(err.message, /opts\.wanIp/,
        'it must NOT be diagnosed as a missing WAN address — that sends the reader to the allocator');
      return true;
    }
  );
});

test('a v2 lane still resolves one flat segment and a v3 lane two', () => {
  // The guard above must not have made the live schemes collateral damage.
  const v2 = net.resolveLaneNetworking('v2', 'crucible', 10881, { wanIp: '100.100.60.20' });
  assert.ok(v2.lan && v2.lan.base3, 'v2 keeps its single lan');
  assert.ok(!v2.lanExt && !v2.lanInt, 'and has no segments');

  const v3 = net.resolveLaneNetworking('v3', 'crucible', 10881, { wanIp: '100.100.60.20' });
  assert.ok(v3.lanExt && v3.lanInt, 'v3 keeps ext and int');
  assert.ok(!v3.lan, 'and deliberately omits lan, so a caller reading net.lan fails loudly');
  assert.notStrictEqual(v3.lanExt.base3, v3.lanInt.base3, 'the two segments are different subnets');
});
