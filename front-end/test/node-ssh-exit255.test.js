/**
 * node-ssh-exit255.test.js -- ssh exit 255 is two different faults wearing one code.
 *
 * THE INCIDENT THIS EXISTS FOR
 * A challenge lane placed on cyberhub-node-8 had its gateway LXC clone fine and
 * then never reach 'running' -- node-8 had just joined the cluster and was still
 * Ceph-backfilling, so pct start's lxc.hook.pre-start lost the race for the
 * udev-created /dev/rbd-pve symlink. The orchestrator then tried to write DHCP
 * reservations into a stopped container and logged:
 *
 *     nodeExec exit 255 ... pct exec 110881 -- /bin/sh -c mkdir -p /etc/dnsmasq.d
 *     ssh could not reach 'cyberhub-node-8' ... check authorized_keys
 *     container '110881' not running!
 *
 * ssh had connected perfectly. The real cause was printed two lines UNDER a hint
 * pointing at SSH keys, so every reader chased PROXMOX_SSH_KEY / PROXMOX_SSH_USER
 * while the actual answer -- a container that never booted -- sat below it. The
 * deploy then carried on for another 3-5 minutes and died somewhere unrelated,
 * on the GOAD controller's prep.sh: "ssh: connect to host 10.42.129.1 port 22:
 * No route to host".
 *
 * The classification that would have caught this already existed inside
 * nodeExec, but only as message TEXT -- no caller could branch on it. classifyExit
 * is that logic pulled out as a pure function returning tags, and these tests pin
 * the exact discrimination the incident needed: exit 255 from a dead container is
 * NOT an SSH-key problem, and must never be described as one.
 *
 * node-ssh.js requires ./site-config at load time and config/site.json is
 * gitignored (absent in a plain checkout), so site-config is stubbed through
 * require.cache before the require, the way gateway-clone-recovery.test.js does.
 *
 * Run: node --test test/node-ssh-exit255.test.js
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

// Every node in these tests is "declared", so the ssh-layer hint is the
// authorized_keys one -- the exact wrong hint the incident printed.
stub('site-config.js', {
  getNodeAddress: () => '100.100.10.18',
});

const { classifyExit } = require(path.join(UTILS, 'node-ssh.js'));

test('exit 255 from a stopped container is a REMOTE fault, not an ssh fault', () => {
  const c = classifyExit({
    code: 255,
    stdout: '',
    stderr: `container '110881' not running!\n`,
    node: 'cyberhub-node-8',
  });

  assert.strictEqual(c.reachedRemote, true);
  assert.strictEqual(c.sshLayer, false);
  assert.strictEqual(c.remoteNotRunning, true);
  assert.match(c.hint, /REMOTE command failed/);
  assert.match(c.hint, /container '110881' not running!/);
  // The whole point: the node-8 log must never again offer an SSH-key theory
  // for a container that simply is not running.
  assert.ok(!c.hint.includes('authorized_keys'),
    `hint must not blame SSH keys for a stopped container, got: ${c.hint}`);
});

test('exit 255 with "No route to host" is an ssh-layer fault', () => {
  const c = classifyExit({
    code: 255,
    stdout: '',
    stderr: 'ssh: connect to host 100.100.10.18 port 22: No route to host\r\n',
    node: 'cyberhub-node-8',
  });

  assert.strictEqual(c.sshLayer, true);
  assert.strictEqual(c.reachedRemote, false);
  assert.strictEqual(c.remoteNotRunning, false);
  assert.match(c.hint, /authorized_keys/);
});

test('exit 255 with "Permission denied (publickey)" is an ssh-layer fault', () => {
  const c = classifyExit({
    code: 255,
    stdout: '',
    stderr: 'Permission denied (publickey).\r\n',
    node: 'cyberhub-node-8',
  });

  assert.strictEqual(c.sshLayer, true);
  assert.strictEqual(c.reachedRemote, false);
  assert.strictEqual(c.remoteNotRunning, false);
});

test('any exit code other than 255 is untagged and gets no hint', () => {
  const c = classifyExit({
    code: 1,
    stdout: '',
    stderr: 'mkdir: cannot create directory: Permission denied\n',
    node: 'cyberhub-node-8',
  });

  assert.strictEqual(c.reachedRemote, false);
  assert.strictEqual(c.sshLayer, false);
  assert.strictEqual(c.remoteNotRunning, false);
  assert.strictEqual(c.hint, '');
});

test('remoteNotRunning is detected on stdout too, not just stderr', () => {
  const c = classifyExit({
    code: 255,
    stdout: `container '110881' not running!\n`,
    stderr: '',
    node: 'cyberhub-node-8',
  });

  assert.strictEqual(c.remoteNotRunning, true);
  assert.strictEqual(c.reachedRemote, true);
  assert.strictEqual(c.sshLayer, false);
  // With stderr empty the hint falls back to stdout's last non-empty line.
  assert.match(c.hint, /REMOTE command failed: container '110881' not running!/);
});
