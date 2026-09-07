'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const identity = require('../src/utils/wazuh-agent-identity');
const raw = 'A1'.repeat(32);
const encode = text => Buffer.from(text).toString('base64');

test('readable names preserve the VM name and append the full VMID after truncation', () => {
  assert.equal(identity.readableAgentName('cle-cybr400-inperson-10811', 610811), 'cle-cybr400-inperson-10811-vm-610811');
  assert.equal(identity.readableAgentName('DC01-Student', 710811), 'DC01-Student-vm-710811');
  assert.equal(identity.readableAgentName('  Résumé / Windows 11! ', 12), 'Resume-Windows-11-vm-12');
  assert.equal(identity.readableAgentName('💻', 13), 'vm-vm-13');
  const long = identity.readableAgentName('x'.repeat(300), 9007199254740991);
  assert.equal(long.length, 128); assert.ok(long.endsWith('-vm-9007199254740991'));
  for (const bad of [0, -1, 1.2, NaN, '12', Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => identity.readableAgentName('name', bad), /VMID/);
  }
});

test('name validation supports existing legacy fixtures and readable names without accepting shell text', () => {
  for (const good of ['cc-test', 'cc-lane01-guest42', 'Windows-11-vm-42', 'dc01.user-vm-9007199254740991']) {
    assert.equal(identity.isAgentName(good), true, good);
  }
  for (const bad of ['Windows 11-vm-42', '-name-vm-42', 'name-vm-0', 'name-vm-01', 'name-vm-9007199254740992',
    'name-vm-42;whoami', 'name-vm-42\n', 'x'.repeat(128) + '-vm-42', 'vmname', null]) {
    assert.equal(identity.isAgentName(bad), false, String(bad));
  }
});

test('key fingerprints preserve the literal secret including case independently of ID and display name', () => {
  const expected = crypto.createHash('sha256').update(raw, 'ascii').digest('hex');
  const readable = 'Windows-11-vm-42';
  assert.equal(identity.rawKeyFingerprint(raw), expected);
  assert.equal(identity.keyFingerprint(encode(`013 ${readable} any ${raw}`), { name: readable, id: '013' }), expected);
  assert.equal(identity.keyFingerprint(encode(`099 cc-test any ${raw}`)), expected);
  assert.notEqual(identity.rawKeyFingerprint(raw.toLowerCase()), expected);
  assert.notEqual(identity.keyFingerprint(encode(`099 cc-test any ${raw.toLowerCase()}`)), expected);
  assert.notEqual(identity.rawKeyFingerprint('b2'.repeat(32)), expected);
});

test('key validation rejects malformed records, other identities, noncanonical base64 and source restrictions', () => {
  const valid = encode(`013 Windows-11-vm-42 any ${raw}`);
  assert.throws(() => identity.keyFingerprint(valid, { name: 'Other-vm-42' }), /registration/);
  assert.throws(() => identity.keyFingerprint(valid, { id: '014' }), /registration/);
  for (const record of [
    `000 cc-test any ${raw}`, `013 cc-test 10.0.0.1 ${raw}`, `013 cc-test any ${raw}\n`,
    `013  cc-test any ${raw}`, `013 cc-test any ${raw} extra`, `013 bad name any ${raw}`,
    `013 cc-test any ${'q'.repeat(64)}`, `013 cc-test any ${'a'.repeat(63)}`,
  ]) assert.throws(() => identity.keyFingerprint(encode(record)), /registration/);
  for (const bad of [valid + '\n', valid.replace(/=+$/, ''), '@@', '', 'A'.repeat(2049)]) {
    assert.throws(() => identity.keyFingerprint(bad), /base64/);
  }
  assert.throws(() => identity.rawKeyFingerprint(raw + ' '), /invalid/);
});
