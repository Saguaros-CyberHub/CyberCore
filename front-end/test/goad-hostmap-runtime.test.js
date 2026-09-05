const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { CONTROLLER_HOST_MAP_PY, ensureControllerHostMap, prepareGoadDeploymentSpec, runGoadPlaybook } = require('../src/utils/goad-deploy');

function temporary(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cybercore-hostmap-test-'));
  t.after(() => {
    assert.equal(path.dirname(dir), os.tmpdir());
    fs.rmSync(dir, { recursive: true, force: true });
  });
  return dir;
}

test('actual helper uses HOST_MAP for the external ELK subnet and leaves WS01 internal', t => {
  const dir = temporary(t);
  const inventory = path.join(dir, 'inventory');
  fs.writeFileSync(inventory, '[default]\nelk ansible_host=10.9.9.24 ansible_connection=ssh\nws01 ansible_host=10.9.9.31 dict_key=ws01\n');
  const hostMap = 'DC01|10.9.9.10|02:01,ELK|10.9.8.24|02:02,ws01|10.9.9.31|02:03,kali|10.9.8.50|02:04';
  const result = spawnSync('python', ['-c', CONTROLLER_HOST_MAP_PY, inventory, hostMap], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.match(fs.readFileSync(inventory, 'utf8'), /elk ansible_host=10\.9\.8\.24 ansible_connection=ssh/);
  assert.match(fs.readFileSync(inventory, 'utf8'), /ws01 ansible_host=10\.9\.9\.31 dict_key=ws01/);
});

test('actual helper refuses inventory with no matching assigned host', t => {
  const dir = temporary(t);
  const inventory = path.join(dir, 'inventory');
  fs.writeFileSync(inventory, 'unknown ansible_host=10.9.9.24\n');
  const result = spawnSync('python', ['-c', CONTROLLER_HOST_MAP_PY, inventory, 'elk|10.9.8.24|02:02'], { encoding: 'utf8' });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /no host matching HOST_MAP/);
});

test('bake contains the same helper and invokes it after rendering each extension inventory', () => {
  const bake = fs.readFileSync(path.join(__dirname, '../../infrastructure/proxmox-templates/vm-templates/bake-goad-controller-vm.sh'), 'utf8');
  const block = bake.match(/  - path: \/opt\/goad-light\/apply-host-map\.py\n[\s\S]*?    content: \|\n([\s\S]*?)\n  - path:/);
  assert.ok(block);
  const helper = block[1].split('\n').map(line => line.replace(/^      /, '')).join('\n').trim();
  assert.equal(helper, CONTROLLER_HOST_MAP_PY.trim());
  assert.match(bake, /python3 \/opt\/goad-light\/apply-host-map\.py "\\\$RUNTIME\/inventory_ext_\\\$ext" "\\\$HOST_MAP"/);
});

test('existing controller patch runs offline, is idempotent, and refuses unknown runner shape', async t => {
  const dir = temporary(t).replace(/\\/g, '/');
  const runner = `${dir}/run.sh`;
  const original = '#!/bin/bash\nset -eu\necho "==> Rendered extension inventory: $RUNTIME/inventory_ext_$ext"\n';
  fs.writeFileSync(runner, original);
  let result;
  const api = async (method, url, body) => {
    if (method === 'POST') {
      const argv = new URLSearchParams(body).getAll('command');
      assert.equal(argv[0], '/usr/bin/python3');
      let program = argv[2].replaceAll('/opt/goad-light', dir);
      const gitBash = 'C:/Program Files/Git/bin/bash.exe';
      if (process.platform === 'win32' && fs.existsSync(gitBash)) program = program.replace("['bash',", `[${JSON.stringify(gitBash)},`);
      const execution = spawnSync('python', ['-c', program], { encoding: 'utf8' });
      result = { exited: 1, exitcode: execution.status, 'out-data': execution.stdout, 'err-data': execution.stderr };
      return { pid: 1 };
    }
    return result;
  };
  await ensureControllerHostMap({ controllerVmId: 1, bestNode: 'offline', proxmoxAPI: api });
  const first = fs.readFileSync(runner, 'utf8');
  assert.match(first, /apply-host-map\.py/);
  assert.equal(fs.readFileSync(`${dir}/apply-host-map.py`, 'utf8'), CONTROLLER_HOST_MAP_PY);
  await ensureControllerHostMap({ controllerVmId: 1, bestNode: 'offline', proxmoxAPI: api });
  assert.equal(fs.readFileSync(runner, 'utf8'), first);
  fs.writeFileSync(runner, '#!/bin/bash\necho unsupported\n');
  await assert.rejects(ensureControllerHostMap({ controllerVmId: 1, bestNode: 'offline', proxmoxAPI: api }), /Cannot safely adapt/);
});

test('actual playbook runner patches v3 addressing before launching the minted lab and selected extensions', async () => {
  const spec = prepareGoadDeploymentSpec({ goad: { enabled: true, version: 'GOAD-Mini',
    domain: 'cy400test.org', rename_forest: true, extensions: ['elk', 'ws01'] },
  vms: [{ name: 'DC01' }, { name: 'ws01' }, { name: 'ELK' }] });
  const calls = [];
  const answers = new Map();
  let pid = 0;
  let launch;
  const api = async (method, url, body) => {
    if (method === 'GET') return { exited: 1, exitcode: 0, 'out-data': answers.get(Number(url.match(/pid=(\d+)/)[1])) };
    const argv = new URLSearchParams(body).getAll('command');
    const command = argv.join(' ');
    if (command.includes('.cc-extension-install')) {
      calls.push('capability');
      answers.set(++pid, 'yes');
      return { pid };
    }
    if (argv[0] === '/usr/bin/python3' && command.includes('apply-host-map.py')) {
      calls.push('addressing');
      answers.set(++pid, 'HOST_MAP inventory support ready');
      return { pid };
    }
    if (command.includes('nohup setsid')) {
      calls.push('launch'); launch = command;
      throw new Error('__CAPTURED_RUN__');
    }
    // Best-effort SQL pre-patches stop before the global polling helper.
    throw new Error('__OFFLINE_PATCH_SKIP__');
  };
  await assert.rejects(runGoadPlaybook({ controllerVmId: 1, bestNode: 'offline', spec,
    vxlanId: 4242, laneSubnetBase: '10.9.9', extSubnetBase: '10.9.8', proxmoxAPI: api }), /__CAPTURED_RUN__/);
  assert.deepEqual(calls, ['capability', 'addressing', 'launch']);
  assert.ok(launch.includes(`/opt/goad-light/run.sh '${spec.goad.version}'`));
  assert.match(launch, /ELK\|10\.9\.8\.24\|/);
  assert.match(launch, /ws01\|10\.9\.9\.31\|/);
  assert.match(launch, /kali\|10\.9\.8\.50\|/);
  assert.ok(launch.includes("'elk,ws01'"));
});
