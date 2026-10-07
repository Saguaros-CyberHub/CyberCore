'use strict';

const crypto = require('node:crypto');

function isAgentName(name) {
  if (typeof name !== 'string' || name.length > 128) return false;
  if (/^cc-[A-Za-z0-9][A-Za-z0-9._-]{0,124}$/.test(name)) return true;
  const match = name.match(/^[A-Za-z0-9][A-Za-z0-9._-]*-vm-([1-9][0-9]{0,15})$/);
  return !!match && Number.isSafeInteger(Number(match[1]));
}

function readableAgentName(displayName, vmId) {
  if (!Number.isSafeInteger(vmId) || vmId <= 0) throw new TypeError('A positive VMID is required for the Wazuh agent name.');
  const suffix = `-vm-${vmId}`;
  const label = String(displayName || '').normalize('NFKD').replace(/[\u0300-\u036f]/g, '')
    .replace(/[^A-Za-z0-9._-]+/g, '-').replace(/-+/g, '-')
    .replace(/^[^A-Za-z0-9]+|[-_.]+$/g, '')
    .slice(0, 128 - suffix.length).replace(/[-_.]+$/g, '') || 'vm';
  return label + suffix;
}

function rawKeyFingerprint(rawKey) {
  if (typeof rawKey !== 'string' || !/^[a-fA-F0-9]{64}$/.test(rawKey)) {
    throw new TypeError('The Wazuh registration key is invalid.');
  }
  // Wazuh derives credentials from the literal key string, including its case.
  return crypto.createHash('sha256').update(rawKey, 'ascii').digest('hex');
}

function keyFingerprint(base64Key, { name, id } = {}) {
  if (typeof base64Key !== 'string' || base64Key.length > 2048 || !/^[A-Za-z0-9+/]+={0,2}$/.test(base64Key)
      || Buffer.from(base64Key, 'base64').toString('base64') !== base64Key) {
    throw new TypeError('The Wazuh enrollment key is not canonical base64.');
  }
  const record = Buffer.from(base64Key, 'base64').toString('utf8');
  const fields = record.split(' ');
  if (/[^\x20-\x7e]/.test(record) || fields.length !== 4 || !/^[0-9]{1,8}$/.test(fields[0]) || Number(fields[0]) === 0
      || !isAgentName(fields[1]) || fields[2] !== 'any' || !/^[a-fA-F0-9]{64}$/.test(fields[3])
      || (name !== undefined && fields[1] !== name) || (id !== undefined && fields[0] !== String(id))) {
    throw new TypeError('The Wazuh enrollment key does not match the requested registration.');
  }
  return rawKeyFingerprint(fields[3]);
}

module.exports = { readableAgentName, isAgentName, keyFingerprint, rawKeyFingerprint };
