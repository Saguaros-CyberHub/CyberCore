'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const { EventEmitter, once } = require('node:events');
const { setTimeout: delay } = require('node:timers/promises');
const { openRdpProbe } = require('../src/utils/guacd-probe');

const NONCE = 'ab'.repeat(32);
const TARGET = { hostname: '100.100.63.27', port: 3392, nonce: NONCE };
const ARGS = ['VERSION_1_5_0', 'port', 'password', 'hostname', 'preconnection-blob',
  'username', 'preconnection-id', 'security', 'disable-auth', 'enable-drive', 'disable-copy'];
const wire = (...values) => values.map(value => `${Array.from(String(value)).length}.${value}`).join(',') + ';';

// Independent ASCII decoder for the client instructions this fixture expects.
function readInstruction(text) {
  const result = [];
  let offset = 0;
  while (offset < text.length) {
    const dot = text.indexOf('.', offset);
    assert.notEqual(dot, -1);
    const length = Number(text.slice(offset, dot));
    result.push(text.slice(dot + 1, dot + 1 + length));
    offset = dot + 2 + length;
  }
  return result;
}

async function broker(t, onInstruction) {
  const sockets = new Set();
  const received = [];
  const server = net.createServer(socket => {
    sockets.add(socket);
    socket.setNoDelay(true);
    socket.on('error', () => {});
    socket.on('close', () => sockets.delete(socket));
    let buffered = '';
    socket.on('data', data => {
      buffered += data.toString('utf8');
      let end;
      while ((end = buffered.indexOf(';')) !== -1) {
        const message = readInstruction(buffered.slice(0, end + 1));
        received.push(message);
        buffered = buffered.slice(end + 1);
        onInstruction(message, socket);
      }
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise(resolve => server.close(resolve));
  });
  return { received, sockets, settings: { guacdHost: '127.0.0.1', guacdPort: server.address().port, guacdSsl: false } };
}

test('uses actual RDP target and nonce through a fragmented versioned guacd handshake without credentials', async t => {
  const fixture = await broker(t, (message, socket) => {
    if (message[0] === 'select') {
      const response = wire('args', ...ARGS);
      socket.write(response.slice(0, 2));
      setImmediate(() => {
        socket.write(response.slice(2, 21));
        setImmediate(() => socket.write(response.slice(21)));
      });
    }
    if (message[0] === 'connect') socket.write(wire('ready', '$probe') + wire('sync', '123456'));
  });
  const probe = openRdpProbe({ ...TARGET, ...fixture.settings });
  t.after(probe.close);
  assert.deepEqual(await probe.completion, { connected: true });
  const instructions = fixture.received;
  assert.deepEqual(instructions.map(message => message[0]), ['select', 'size', 'audio', 'video', 'image', 'connect']);
  assert.deepEqual(instructions[0], ['select', 'rdp']);
  const supplied = Object.fromEntries(ARGS.map((name, i) => [name, instructions[5][i + 1]]));
  assert.equal(supplied.VERSION_1_5_0, 'VERSION_1_5_0');
  assert.equal(supplied.hostname, TARGET.hostname);
  assert.equal(supplied.port, String(TARGET.port));
  assert.equal(supplied['preconnection-blob'], NONCE);
  assert.equal(supplied['preconnection-id'], '0');
  assert.equal(supplied.username, '');
  assert.equal(supplied.password, '');
  assert.equal(supplied.security, 'rdp');
  assert.equal(supplied['disable-auth'], 'true');
  assert.equal(supplied['enable-drive'], 'false');
  assert.equal(supplied['disable-copy'], 'true');
  const socket = [...fixture.sockets][0];
  const disconnected = once(socket, 'close');
  probe.close();
  probe.close();
  await disconnected;
  assert.equal(fixture.sockets.size, 0);
});

test('maps a legacy argument list without a version slot and acknowledges sync', async t => {
  let syncReceived;
  const synced = new Promise(resolve => { syncReceived = resolve; });
  const legacy = ARGS.slice(1);
  const fixture = await broker(t, (message, socket) => {
    if (message[0] === 'select') socket.write(wire('args', ...legacy));
    if (message[0] === 'connect') socket.write(wire('ready', '$legacy') + wire('sync', '712', '0'));
    if (message[0] === 'sync') syncReceived(message);
  });
  const probe = openRdpProbe({ ...TARGET, ...fixture.settings });
  t.after(probe.close);
  await probe.completion;
  assert.equal(fixture.received.find(message => message[0] === 'connect').length, legacy.length + 1);
  assert.deepEqual(await synced, ['sync', '712', '0']);
});

test('negotiates its supported version with a newer broker', async t => {
  const fixture = await broker(t, (message, socket) => {
    if (message[0] === 'select') socket.write(wire('args', 'VERSION_1_6_0', ...ARGS.slice(1)));
    if (message[0] === 'connect') socket.write(wire('ready', '$newer'));
  });
  const probe = openRdpProbe({ ...TARGET, ...fixture.settings });
  t.after(probe.close);
  await probe.completion;
  assert.equal(fixture.received.find(message => message[0] === 'connect')[1], 'VERSION_1_5_0');
});

test('times out a stalled broker and releases its socket', async t => {
  const fixture = await broker(t, () => {});
  const probe = openRdpProbe({ ...TARGET, ...fixture.settings, timeoutMs: 150 });
  await assert.rejects(probe.completion, { code: 'GUACD_PROBE_TIMEOUT' });
  for (const socket of fixture.sockets) await once(socket, 'close');
  assert.equal(fixture.sockets.size, 0);
});

test('a ready acknowledgement cannot leave a probe socket open past its lifetime', async () => {
  const socket = new EventEmitter();
  socket.write = () => {};
  socket.destroy = () => { socket.destroyed = true; socket.emit('close'); };
  const closed = once(socket, 'close');
  const probe = openRdpProbe({ ...TARGET, timeoutMs: 20 }, { connect: () => socket });
  socket.emit('connect');
  socket.emit('data', Buffer.from(wire('args', ...ARGS)));
  socket.emit('data', Buffer.from(wire('ready', '$ready-only')));
  await probe.completion;
  await closed;
  assert.equal(socket.destroyed, true);
});

test('reports connection failures without echoing remote data', async () => {
  const socket = new EventEmitter();
  socket.destroy = () => { socket.destroyed = true; };
  const probe = openRdpProbe(TARGET, { connect: () => socket });
  const rejection = assert.rejects(probe.completion, error => error.code === 'GUACD_PROBE_CONNECTION' && !error.message.includes(NONCE));
  socket.emit('error', new Error(`Sensitive transport data ${NONCE}`));
  await rejection;
  assert.equal(socket.destroyed, true);
});

test('reports peer close during handshake', async t => {
  const fixture = await broker(t, (_message, socket) => socket.end());
  const probe = openRdpProbe({ ...TARGET, ...fixture.settings });
  await assert.rejects(probe.completion, { code: 'GUACD_PROBE_CLOSED' });
});

test('rejects errors across UTF-8 packet boundaries without disclosing the nonce', async t => {
  const fixture = await broker(t, (_message, socket) => {
    const bytes = Buffer.from(wire('error', `é ${NONCE}`, '519'));
    const split = bytes.indexOf(0xc3) + 1;
    socket.write(bytes.subarray(0, split));
    setImmediate(() => socket.end(bytes.subarray(split)));
  });
  const probe = openRdpProbe({ ...TARGET, ...fixture.settings });
  await assert.rejects(probe.completion, error => error.code === 'GUACD_PROBE_REJECTED' && !error.message.includes(NONCE));
});

for (const [name, response] of [
  ['missing preconnection support', wire('args', 'VERSION_1_5_0', 'hostname', 'port')],
  ['duplicate argument names', wire('args', ...ARGS, 'hostname')],
  ['untrusted argument syntax', wire('args', ...ARGS, 'bad;argument')],
  ['out-of-order ready', wire('ready', '$wrong-order')],
  ['oversized length', '999999999999.'],
  ['oversized element', '4097.'],
  ['invalid separator', '4.args!'],
  ['invalid UTF-8', Buffer.from([0xff])],
]) {
  test(`rejects ${name} and cleans up`, async t => {
    const fixture = await broker(t, (_message, socket) => socket.write(response));
    const probe = openRdpProbe({ ...TARGET, ...fixture.settings });
    await assert.rejects(probe.completion, { code: 'GUACD_PROBE_PROTOCOL' });
    for (const socket of fixture.sockets) await once(socket, 'close');
  });
}

test('bounds accumulated small instruction elements', async t => {
  const fixture = await broker(t, (_message, socket) => socket.write('0.,'.repeat(257)));
  const probe = openRdpProbe({ ...TARGET, ...fixture.settings });
  await assert.rejects(probe.completion, { code: 'GUACD_PROBE_PROTOCOL' });
});

test('rejects invalid target settings before opening any socket', () => {
  let attempts = 0;
  const connect = () => { attempts++; throw new Error('unexpected connect'); };
  for (const invalid of [
    { hostname: 'gateway-from-user' }, { hostname: '::1' }, { port: 0 }, { port: '3389x' },
    { nonce: 'short' }, { nonce: ';'.repeat(64) }, { guacdHost: 'host;command' },
    { guacdPort: 65536 }, { guacdSsl: 'yes' }, { timeoutMs: 0 }, { timeoutMs: 60001 }, { signal: {} },
  ]) {
    assert.throws(() => openRdpProbe({ ...TARGET, ...invalid }, { connect }), { code: 'GUACD_PROBE_CONFIG' });
  }
  assert.equal(attempts, 0);
});

test('abort before connecting opens no socket; in-flight abort closes its socket', async t => {
  const before = new AbortController();
  before.abort();
  let attempts = 0;
  const cancelled = openRdpProbe({ ...TARGET, signal: before.signal }, { connect: () => { attempts++; } });
  await assert.rejects(cancelled.completion, { code: 'GUACD_PROBE_ABORTED' });
  assert.equal(attempts, 0);

  const fixture = await broker(t, () => {});
  const during = new AbortController();
  const probe = openRdpProbe({ ...TARGET, ...fixture.settings, signal: during.signal });
  const rejection = assert.rejects(probe.completion, { code: 'GUACD_PROBE_ABORTED' });
  during.abort();
  await rejection;
});

test('explicit early close settles completion and cancels the timer', async () => {
  const socket = new EventEmitter();
  socket.destroy = () => { socket.destroyed = true; };
  const probe = openRdpProbe({ ...TARGET, timeoutMs: 20 }, { connect: () => socket });
  probe.close();
  assert.deepEqual(await probe.completion, { closed: true });
  await delay(30);
  assert.equal(socket.destroyed, true);
});

test('TLS uses the configured backend and verified certificates, starting only after secureConnect', async () => {
  const socket = new EventEmitter();
  const writes = [];
  socket.write = text => writes.push(text);
  socket.destroy = () => { socket.destroyed = true; };
  let settings;
  const probe = openRdpProbe({ ...TARGET, guacdHost: 'broker.internal', guacdPort: '14822', guacdSsl: 'true' }, {
    connect: () => { throw new Error('plaintext transport used'); },
    tlsConnect: value => { settings = value; return socket; },
  });
  assert.deepEqual(settings, { host: 'broker.internal', port: 14822, rejectUnauthorized: true, servername: 'broker.internal' });
  socket.emit('connect');
  assert.deepEqual(writes, []);
  socket.emit('secureConnect');
  assert.deepEqual(writes, [wire('select', 'rdp')]);
  probe.close();
  await probe.completion;
  assert.equal(socket.destroyed, true);
});
