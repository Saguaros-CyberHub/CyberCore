const { test } = require('node:test');
const assert = require('node:assert/strict');
const { stopController } = require('../src/utils/goad-deploy');

function fixture({ syncResult = { exited: true, exitcode: 0 }, syncError, stopError } = {}) {
  const calls = [];
  const args = {
    controllerVmId: 210881, bestNode: 'pve4',
    proxmoxAPI: async (method, url, body) => {
      assert.equal(method, 'POST');
      if (url.endsWith('/agent/exec')) {
        assert.deepEqual(new URLSearchParams(body).getAll('command'), ['/bin/sync']);
        calls.push('sync');
        return { pid: 123 };
      }
      assert.match(url, /qemu\/210881\/status\/stop$/);
      calls.push('stop');
      if (stopError) throw stopError;
      return 'UPID:stop';
    },
    waitForTask: async (node, task) => {
      assert.equal(node, 'pve4');
      assert.equal(task, 'UPID:stop');
      calls.push('stopped');
    },
    deps: { pollExecStatus: async (node, vmid, pid, timeout) => {
      assert.deepEqual([node, vmid, pid, timeout], ['pve4', 210881, 123, 30000]);
      calls.push('sync_finished');
      if (syncError) throw syncError;
      return syncResult;
    } },
  };
  return { calls, args };
}

test('controller power-off follows a completed filesystem flush', async () => {
  const f = fixture();
  const result = await stopController(f.args);
  assert.deepEqual(f.calls, ['sync', 'sync_finished', 'stop', 'stopped']);
  assert.equal(result.stopped, true);
  assert.deepEqual(result.log_flush, { synced: true, error: null });
});

for (const failure of [
  { syncResult: { exited: false } },
  { syncResult: { exited: true, exitcode: 1, stderr: 'private-diagnostic-value' } },
  { syncError: new Error('private-diagnostic-value') },
]) {
  test(`unconfirmed flush still stops the controller and records a sanitized warning: ${JSON.stringify(failure)}`, async () => {
    const f = fixture(failure);
    const result = await stopController(f.args);
    assert.equal(result.stopped, true);
    assert.equal(result.log_flush.synced, false);
    assert.match(result.log_flush.error, /diagnostics may be incomplete/);
    assert.ok(!JSON.stringify(result).includes('private-diagnostic-value'));
    assert.deepEqual(f.calls.slice(-2), ['stop', 'stopped']);
  });
}

test('power-off failure retains both cleanup and flush outcomes', async () => {
  const f = fixture({ stopError: new Error('stop rejected') });
  const result = await stopController(f.args);
  assert.equal(result.stopped, false);
  assert.equal(result.error, 'stop rejected');
  assert.equal(result.log_flush.synced, true);
});
