'use strict';

const net = require('node:net');
const tls = require('node:tls');
const { TextDecoder } = require('node:util');

// This is a short control-plane probe, not a remote desktop client. In
// particular, it never accepts credentials or supplies remote desktop input.
// Handshake: https://guacamole.apache.org/doc/1.5.5/gug/guacamole-protocol.html
// preconnection-blob: guacamole-server/1.5.5/src/protocols/rdp/settings.c
const MAX_ELEMENT = 4096;
const MAX_ELEMENTS = 256;
const MAX_BUFFER = 65536;
const MAX_RECEIVED = 262144;

function failure(message, suffix = 'PROTOCOL') {
  return Object.assign(new Error(message), { code: `GUACD_PROBE_${suffix}` });
}

function instruction(...values) {
  return values.map(value => {
    const text = String(value);
    return `${Array.from(text).length}.${text}`;
  }).join(',') + ';';
}

// Lengths count Unicode characters, not TCP bytes. TextDecoder preserves UTF-8
// characters split across packets and rejects invalid encodings. Neither an
// unfinished element nor a stream of tiny instructions may grow without bound.
function parser(onInstruction) {
  const decoder = new TextDecoder('utf-8', { fatal: true });
  let pending = [], elements = [], frameLength = 0, received = 0;
  return buffer => {
    received += buffer.length;
    if (received > MAX_RECEIVED) throw failure('Guacd probe exceeded its response limit.');
    pending = pending.concat(Array.from(decoder.decode(buffer, { stream: true })));
    if (pending.length > MAX_BUFFER) throw failure('Guacd probe instruction is too large.');
    while (pending.length) {
      let dot = 0;
      while (dot < pending.length && pending[dot] !== '.') {
        if (!/^[0-9]$/.test(pending[dot]) || dot >= 5) {
          throw failure('Guacd probe returned an invalid element length.');
        }
        dot++;
      }
      if (dot === pending.length) return;
      if (!dot) throw failure('Guacd probe returned an empty element length.');
      const length = Number(pending.slice(0, dot).join(''));
      if (length > MAX_ELEMENT) throw failure('Guacd probe element is too large.');
      const end = dot + 1 + length;
      if (pending.length <= end) return;
      const separator = pending[end];
      if (separator !== ',' && separator !== ';') throw failure('Guacd probe returned an invalid separator.');
      elements.push(pending.slice(dot + 1, end).join(''));
      frameLength += end + 1;
      if (elements.length > MAX_ELEMENTS || frameLength > MAX_BUFFER) {
        throw failure('Guacd probe instruction is too large.');
      }
      pending = pending.slice(end + 1);
      if (separator === ';') {
        const complete = elements;
        elements = [];
        frameLength = 0;
        onInstruction(complete);
      }
    }
  };
}

function validPort(value) {
  return /^\d{1,5}$/.test(String(value)) && Number(value) >= 1 && Number(value) <= 65535;
}

function sslFlag(value) {
  if (value === true || value === 'true') return true;
  if (value === false || value === 'false' || value === '') return false;
  throw failure('The guacd TLS setting must be true or false.', 'CONFIG');
}

function versionFor(value) {
  if (!/^VERSION_\d+_\d+_\d+$/.test(value)) throw failure('Guacd returned an invalid protocol version.');
  const offered = value.slice(8).split('_').map(Number);
  const supported = [[1, 5, 0], [1, 3, 0], [1, 1, 0], [1, 0, 0]];
  const version = supported.find(candidate => {
    for (let i = 0; i < 3; i++) {
      if (candidate[i] !== offered[i]) return candidate[i] < offered[i];
    }
    return true;
  });
  if (!version) throw failure('Guacd returned an unsupported protocol version.');
  return `VERSION_${version.join('_')}`;
}

/**
 * Ask the actual guacd backend to send an RDP preconnection PDU to a trusted
 * gateway listener. The nonce is supplied by that listener's orchestrator.
 *
 * Returns immediately with { close, completion }. completion confirms only the
 * Guacamole handshake (or rejects before it); it does NOT authenticate the
 * broker. The gateway's nonce receipt is the sole success condition. Keep the
 * handle open until that receipt, then close it in finally. A hard lifetime
 * deadline also destroys the socket after a successful Guacamole handshake.
 *
 * With TLS, Node verifies the broker certificate using its configured trust
 * store. There is no insecure certificate bypass.
 */
function openRdpProbe(options = {}, dependencies = {}) {
  const { hostname, port, nonce, signal, timeoutMs = 15000 } = options;
  const guacdHost = options.guacdHost ?? process.env.GUACD_HOSTNAME ?? 'guacd';
  const guacdPort = options.guacdPort ?? process.env.GUACD_PORT ?? 4822;
  const secure = sslFlag(options.guacdSsl ?? process.env.GUACD_SSL ?? false);
  if (net.isIP(hostname) !== 4 || !validPort(port)
      || typeof nonce !== 'string' || !/^[a-f0-9]{32,128}$/i.test(nonce)
      || typeof guacdHost !== 'string' || !guacdHost || guacdHost.length > 253
      || (!net.isIP(guacdHost) && !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/i.test(guacdHost))
      || !validPort(guacdPort) || !Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60000
      || (signal != null && (!(signal instanceof AbortSignal)))) {
    throw failure('The guacd probe target or connection settings are invalid.', 'CONFIG');
  }

  let socket, timer, stopped = false, accepted = false, sentArgs = false;
  let resolveCompletion, rejectCompletion;
  const completion = new Promise((resolve, reject) => {
    resolveCompletion = resolve;
    rejectCompletion = reject;
  });

  function stop(error) {
    if (stopped) return;
    stopped = true;
    clearTimeout(timer);
    signal?.removeEventListener('abort', abort);
    socket?.destroy();
    if (error) rejectCompletion(error);
    else resolveCompletion({ closed: true });
  }
  const abort = () => stop(failure('The guacd probe was cancelled.', 'ABORTED'));
  const handle = { close: () => stop(), completion };
  if (signal?.aborted) {
    abort();
    return handle;
  }

  function write(...values) {
    if (!stopped) socket.write(instruction(...values));
  }

  function receive(values) {
    if (stopped) return;
    const [opcode, ...args] = values;
    if (opcode === 'error') {
      // Do not echo the server message: it may include the nonce or parameters.
      throw failure('Guacd rejected the RDP probe.', 'REJECTED');
    }
    if (!sentArgs) {
      if (opcode !== 'args') throw failure('Guacd did not send the expected RDP arguments.');
      let version;
      if (args[0]?.startsWith('VERSION_')) version = versionFor(args.shift());
      if (args.some(arg => !/^[a-z][a-z0-9-]{0,127}$/.test(arg))
          || new Set(args).size !== args.length
          || ['hostname', 'port', 'preconnection-blob', 'preconnection-id'].some(arg => !args.includes(arg))) {
        throw failure('Guacd does not support the required RDP probe arguments.');
      }
      const parameters = {
        hostname, port: String(port), 'preconnection-blob': nonce, 'preconnection-id': '0',
        security: 'rdp', 'disable-auth': 'true', 'disable-audio': 'true', 'read-only': 'true',
        'disable-copy': 'true', 'disable-paste': 'true', 'enable-drive': 'false',
        'enable-printing': 'false', 'enable-sftp': 'false', 'enable-audio-input': 'false',
      };
      // The fixed order also works with servers predating version negotiation.
      write('size', '640', '480', '96');
      write('audio');
      write('video');
      write('image', 'image/png');
      const ordered = args.map(arg => Object.hasOwn(parameters, arg) ? parameters[arg] : '');
      if (version) ordered.unshift(version);
      sentArgs = true;
      write('connect', ...ordered);
    } else if (opcode === 'ready') {
      if (accepted || args.length !== 1 || !args[0]) throw failure('Guacd returned an invalid ready instruction.');
      accepted = true;
      resolveCompletion({ connected: true });
    } else if (opcode === 'disconnect') {
      stop(accepted ? undefined : failure('Guacd ended the probe before accepting it.', 'CLOSED'));
    } else if (accepted && opcode === 'sync') {
      if (args.length < 1 || args.length > 2 || args.some(arg => !/^\d{1,20}$/.test(arg))) {
        throw failure('Guacd returned an invalid sync instruction.');
      }
      write('sync', ...args);
    } else if (!accepted) {
      throw failure('Guacd returned an unexpected handshake instruction.');
    }
  }

  const consume = parser(receive);
  signal?.addEventListener('abort', abort, { once: true });
  timer = setTimeout(() => stop(failure('The guacd probe timed out.', 'TIMEOUT')), timeoutMs);
  try {
    const connect = secure ? (dependencies.tlsConnect || tls.connect) : (dependencies.connect || net.connect);
    const settings = { host: guacdHost, port: Number(guacdPort) };
    if (secure) {
      settings.rejectUnauthorized = true;
      if (!net.isIP(guacdHost)) settings.servername = guacdHost;
    }
    socket = connect(settings);
    socket.once(secure ? 'secureConnect' : 'connect', () => write('select', 'rdp'));
    socket.on('data', data => {
      if (stopped) return;
      try { consume(data); }
      catch (error) { stop(error.code?.startsWith('GUACD_PROBE_') ? error : failure('Guacd returned invalid UTF-8 or protocol data.')); }
    });
    socket.on('error', () => stop(failure('The guacd probe connection failed.', 'CONNECTION')));
    socket.once('close', () => stop(accepted ? undefined : failure('Guacd closed the probe before accepting it.', 'CLOSED')));
  } catch (_) {
    stop(failure('The guacd probe connection could not be opened.', 'CONNECTION'));
  }
  return handle;
}

module.exports = { openRdpProbe };
