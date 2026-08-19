/**
 * ipv4.test.js — the address maths the lane WAN allocator walks.
 *
 * These are pure functions, but they are the ones that decide whether a lane
 * gateway gets a routable address, so the boundary cases are worth pinning:
 * a /22 that does not start on a multiple of 4, the top of the 32-bit space
 * (where `<<` would go negative), and a CIDR written with a host address rather
 * than the network address.
 *
 * Run: node --test front-end/test/ipv4.test.js
 */

const { test } = require('node:test');
const assert = require('assert');
const path = require('path');

const { ipToInt, intToIp, parseCidr, ipInCidr } =
  require(path.join(__dirname, '..', 'src', 'utils', 'ipv4.js'));

test('ipToInt / intToIp round-trip across the whole space', () => {
  for (const ip of ['0.0.0.0', '10.41.86.50', '100.100.60.32', '192.168.1.1', '255.255.255.255']) {
    assert.strictEqual(intToIp(ipToInt(ip)), ip, ip);
  }
  // The top of the space is where a `1 << 31` implementation goes negative.
  assert.strictEqual(ipToInt('255.255.255.255'), 4294967295);
  assert.strictEqual(intToIp(4294967295), '255.255.255.255');
});

test('ipToInt rejects non-addresses rather than coercing them', () => {
  for (const bad of ['100.100.60', '100.100.60.256', '100.100.60.1.1', 'a.b.c.d', '', '100.100.60.-1']) {
    assert.throws(() => ipToInt(bad), /Not an IPv4 address/, JSON.stringify(bad));
  }
});

test('parseCidr on the /24 the lab runs today', () => {
  const c = parseCidr('100.100.60.0/24');
  assert.strictEqual(c.network, '100.100.60.0');
  assert.strictEqual(c.broadcast, '100.100.60.255');
  assert.strictEqual(c.firstHost, '100.100.60.1');
  assert.strictEqual(c.lastHost, '100.100.60.254');
  assert.strictEqual(c.size, 256);
});

test('parseCidr on the /22 the lab is widening to', () => {
  const c = parseCidr('100.100.60.0/22');
  assert.strictEqual(c.network, '100.100.60.0');
  assert.strictEqual(c.broadcast, '100.100.63.255');
  assert.strictEqual(c.lastHost, '100.100.63.254');
  assert.strictEqual(c.size, 1024);
  // The whole point of widening: every address deployed under the old /24 is
  // still inside the new block, so nothing already on the wire has to move.
  assert.ok(ipInCidr('100.100.60.10', '100.100.60.0/22'));
  assert.ok(ipInCidr('100.100.60.249', '100.100.60.0/22'));
});

test('parseCidr normalizes a host address to its block', () => {
  // An operator who writes the gateway with a prefix into `subnet` must still
  // get the right pool, not a block starting at the gateway.
  assert.strictEqual(parseCidr('100.100.60.5/22').network, '100.100.60.0');
  assert.strictEqual(parseCidr('100.100.63.200/22').network, '100.100.60.0');
});

test('parseCidr respects prefix boundaries — .60 is a /22 boundary but not a /21', () => {
  assert.strictEqual(parseCidr('100.100.60.0/22').network, '100.100.60.0');
  // 60 is not a multiple of 8, so a /21 written at .60 covers .56-.63.
  assert.strictEqual(parseCidr('100.100.60.0/21').network, '100.100.56.0');
  assert.strictEqual(parseCidr('100.100.56.0/21').broadcast, '100.100.63.255');
});

test('parseCidr rejects malformed blocks', () => {
  for (const bad of ['100.100.60.0', '100.100.60.0/33', '100.100.60.0/', 'not-a-cidr', '100.100.60.0/22/24']) {
    assert.throws(() => parseCidr(bad), /Not a CIDR block/, JSON.stringify(bad));
  }
});

test('ipInCidr edges', () => {
  assert.ok(ipInCidr('100.100.60.0', '100.100.60.0/22'));
  assert.ok(ipInCidr('100.100.63.255', '100.100.60.0/22'));
  assert.ok(!ipInCidr('100.100.64.0', '100.100.60.0/22'));
  assert.ok(!ipInCidr('100.100.59.255', '100.100.60.0/22'));
});
