/**
 * lab-network-config.test.js — getV2LabNetwork() over the widened pool.
 *
 * config/site.json is gitignored, so the hardcoded defaults in site-config.js
 * ARE the live contract for any site that has not declared cluster.networking.
 * That makes "an un-edited site.json behaves exactly as it did" a real
 * compatibility requirement, not a hypothetical one — hence the legacy-shape
 * tests below.
 *
 * Run: node --test front-end/test/lab-network-config.test.js
 */

const { test } = require('node:test');
const assert = require('assert');
const path = require('path');
const fs = require('fs');

const SITE_CONFIG = path.join(__dirname, '..', 'src', 'utils', 'site-config.js');

/** Load a fresh site-config.js against an in-memory config/site.json. */
function loadWith(config) {
  const realRead = fs.readFileSync;
  fs.readFileSync = (p, ...rest) =>
    String(p).split(String.fromCharCode(92)).join('/').endsWith('config/site.json')
      ? JSON.stringify(config)
      : realRead(p, ...rest);
  try {
    delete require.cache[require.resolve(SITE_CONFIG)];
    const mod = require(SITE_CONFIG);
    mod.getConfig();   // prime the module-level cache while the stub is live
    return mod;
  } finally {
    fs.readFileSync = realRead;
  }
}

const net = (cfg) => loadWith({ cluster: { networking: { v2_lab_network: cfg } } }).getV2LabNetwork();

test('no cluster.networking at all — the shape every un-configured site gets', () => {
  const n = loadWith({ cluster: {} }).getV2LabNetwork();
  assert.strictEqual(n.subnet, '100.100.60.0/24');
  assert.strictEqual(n.gateway, '100.100.60.1');
  assert.strictEqual(n.bridge, 'vmbr0');
  assert.strictEqual(n.vlan_tag, 60);
  assert.strictEqual(n.cidr, '/24');
  assert.strictEqual(n.subnet_base, '100.100.60');
  // The historical floor. Every lane deployed to date is at or above .10, so
  // this is what keeps widening from moving an address already on the wire.
  assert.strictEqual(n.host_range.first, '100.100.60.10');
  assert.strictEqual(n.host_range.last, '100.100.60.254');
});

test('legacy { subnet_base, cidr } still synthesizes the block', () => {
  const n = net({ subnet_base: '100.100.60', cidr: '/24' });
  assert.strictEqual(n.subnet, '100.100.60.0/24');
  assert.strictEqual(n.prefix_len, 24);
});

test('widening to /22 keeps the base and every existing address', () => {
  const n = net({ subnet: '100.100.60.0/22', gateway: '100.100.60.1' });
  assert.strictEqual(n.network, '100.100.60.0');
  assert.strictEqual(n.broadcast, '100.100.63.255');
  assert.strictEqual(n.prefix_len, 22);
  // `cidr` keeps its old meaning: the suffix concatenated onto a net0 address.
  assert.strictEqual(n.cidr, '/22');
  assert.strictEqual(n.subnet_base, '100.100.60');
  assert.strictEqual(n.host_range.first, '100.100.60.10');
  assert.strictEqual(n.host_range.last, '100.100.63.254');
});

test('network, broadcast and gateway are reserved without being asked for', () => {
  const n = net({ subnet: '100.100.60.0/22', reserved: ['100.100.60.2'] });
  for (const ip of ['100.100.60.1', '100.100.60.0', '100.100.63.255', '100.100.60.2']) {
    assert.ok(n.reserved.includes(ip), `${ip} should be reserved`);
  }
  assert.strictEqual(new Set(n.reserved).size, n.reserved.length, 'no duplicates');
});

test('a gateway outside the block is refused, not silently deployed', () => {
  // Every lane gateway is configured with gw=<this>; off-subnet means every
  // lane comes up unreachable, and the deploy would report success.
  assert.throws(
    () => net({ subnet: '100.100.60.0/22', gateway: '100.100.70.1' }),
    /gateway 100\.100\.70\.1 is outside subnet/
  );
});

test('an unusably small prefix is refused', () => {
  assert.throws(() => net({ subnet: '100.100.60.0/31' }), /too small to hold any lane/);
});

test('a host_range outside the block, or inverted, is refused', () => {
  assert.throws(
    () => net({ subnet: '100.100.60.0/22', host_range: { first: '100.100.60.10', last: '100.100.70.1' } }),
    /host_range .* outside/
  );
  assert.throws(
    () => net({ subnet: '100.100.60.0/22', host_range: { first: '100.100.63.1', last: '100.100.60.10' } }),
    /host_range .* empty or falls outside/
  );
});

test('probe defaults to the tagged VLAN interface, not the bare bridge', () => {
  // vmbr0 carries VLAN 60 only as tagged frames for guests: an arping on the
  // bare bridge never sees a lane gateway and reports every address free.
  assert.strictEqual(net({ subnet: '100.100.60.0/22' }).probe.interface, 'vmbr0.60');
  assert.strictEqual(net({ subnet: '100.100.60.0/22', vlan_tag: 61 }).probe.interface, 'vmbr0.61');
  assert.strictEqual(net({ subnet: '100.100.60.0/22' }).probe.enabled, true);
  assert.strictEqual(net({ subnet: '100.100.60.0/22', probe: { enabled: false } }).probe.enabled, false);
});
