const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { setTimeout: delay } = require('node:timers/promises');
const { buildGoadPlaybookLaunch } = require('../src/utils/goad-playbook-launch');

const bash = process.platform === 'win32' ? 'C:/Program Files/Git/bin/bash.exe' : 'bash';
const quote = value => `'${value.replace(/'/g, `'\\''`)}'`;
const unixPath = value => value.replace(/\\/g, '/');

async function exercise(t, { exitcode = 0, failLogSync = false, failTempSync = false, argv = [] } = {}) {
  const temporaryRoot = path.resolve(os.tmpdir());
  const directory = fs.mkdtempSync(path.join(temporaryRoot, 'goad-launch-'));
  t.after(() => {
    assert.equal(path.dirname(path.resolve(directory)), temporaryRoot);
    assert.match(path.basename(directory), /^goad-launch-/);
    fs.rmSync(directory, { recursive: true, force: true, maxRetries: 20, retryDelay: 20 });
  });
  const root = unixPath(directory);
  const bin = `${root}/bin`;
  fs.mkdirSync(bin);
  const logPath = `${root}/run 'quoted'.log`;
  const donePath = `${root}/done 'quoted'.txt`;
  const tracePath = `${root}/trace`;
  const argsPath = `${root}/args`;
  const runner = `${root}/fake 'runner'.sh`;
  const executable = (file, body) => fs.writeFileSync(file, `#!/bin/sh\n${body}\n`, { mode: 0o700 });
  executable(runner, `printf '%s\\0' "$@" > "$ARGS_PATH"\nprintf 'stdout secret\\n'\nprintf 'stderr secret\\n' >&2\nexit "$RUN_RC"`);
  executable(`${bin}/sync`, `
case "$2" in
  "$LOG_PATH") kind=log;;
  "$DONE_PATH".tmp.*) kind=temp;;
  *) kind=directory;;
esac
visible=no
[ ! -e "$DONE_PATH" ] || visible=yes
printf 'sync:%s:visible=%s\\n' "$kind" "$visible" >> "$TRACE_PATH"
[ "$kind" != log ] || [ "$FAIL_LOG_SYNC" != yes ] || exit 1
[ "$kind" != temp ] || [ "$FAIL_TEMP_SYNC" != yes ] || exit 1
exit 0`);
  executable(`${bin}/mv`, `printf 'rename\\n' >> "$TRACE_PATH"\nexec /bin/mv "$@"`);
  // Git Bash lacks setsid. Its stand-in changes only process detachment;
  // Linux executes the real setsid and both platforms run the nested sh -c.
  if (process.platform === 'win32') executable(`${bin}/setsid`, 'exec "$@"');
  fs.writeFileSync(donePath, '0\n'); // A previous run must not look complete.
  const launch = buildGoadPlaybookLaunch({ logPath, donePath, argv: ['/bin/sh', runner, ...argv] });
  const environment = {
    LOG_PATH: logPath, DONE_PATH: donePath, TRACE_PATH: tracePath, ARGS_PATH: argsPath,
    RUN_RC: String(exitcode), FAIL_LOG_SYNC: failLogSync ? 'yes' : 'no', FAIL_TEMP_SYNC: failTempSync ? 'yes' : 'no',
  };
  const prelude = Object.entries(environment).map(([key, value]) => `export ${key}=${quote(value)}`).join('\n');
  const shellBin = bin.replace(/^([A-Za-z]):\//, (_, drive) => `/${drive.toLowerCase()}/`);
  // Waiting here is test-only: it also releases the detached shell's working
  // directory before Windows removes the fixture. Production returns at '&'.
  const result = spawnSync(bash, ['-c', `${prelude}\nexport PATH=${quote(shellBin)}:$PATH\n${launch}\nwait`], {
    cwd: directory, encoding: 'utf8', timeout: 5000,
  });
  assert.equal(result.status, 0, result.stderr || String(result.error));
  assert.equal(result.stdout, '');
  assert.equal(result.stderr, '');
  const deadline = Date.now() + 5000;
  let trace = '';
  while (Date.now() < deadline) {
    trace = fs.existsSync(tracePath) ? fs.readFileSync(tracePath, 'utf8') : '';
    if (failTempSync ? trace.includes('sync:temp:') : trace.includes('sync:directory:')) break;
    await delay(20);
  }
  assert.match(trace, /sync:temp:/, 'detached worker reached sentinel synchronization');
  if (failTempSync) {
    // Let the shell's cleanup trap finish before this fixture is removed.
    while (fs.readdirSync(directory).some(name => name.includes('.tmp.')) && Date.now() < deadline) await delay(20);
  }
  return {
    done: fs.existsSync(donePath) ? fs.readFileSync(donePath, 'utf8') : null,
    log: fs.readFileSync(logPath, 'utf8'), trace,
    args: fs.readFileSync(argsPath, 'utf8').split('\0').slice(0, -1),
    files: fs.readdirSync(directory),
  };
}

for (const exitcode of [0, 1, 2, 255]) {
  test(`detached launch durably publishes the original exit ${exitcode}`, async t => {
    const result = await exercise(t, { exitcode, argv: ['ordinary argument'] });
    assert.equal(result.done, `${exitcode}\n`);
    assert.equal(result.log, 'stdout secret\nstderr secret\n');
    assert.deepEqual(result.trace.trim().split('\n'), [
      'sync:log:visible=no', 'sync:temp:visible=no', 'rename', 'sync:directory:visible=yes',
    ]);
    assert.ok(!result.files.some(name => name.includes('.tmp.')));
  });
}

test('arguments survive both shells without substitution or command execution', async t => {
  const argv = ['', 'space and \'single\' "double" quotes', '$(touch injected-dollar)',
    '`touch injected-backtick`', 'value; touch injected-semicolon', 'line one\nline two', '$HOME', '\\domain\\account'];
  const result = await exercise(t, { argv });
  assert.deepEqual(result.args, argv);
  assert.equal(result.done, '0\n');
  assert.ok(!result.files.some(name => name.startsWith('injected-')));
});

test('a failed log flush cannot publish successful completion', async t => {
  const result = await exercise(t, { failLogSync: true });
  assert.equal(result.done, '125\n');
});

test('a failed log flush preserves the original Ansible failure', async t => {
  const result = await exercise(t, { exitcode: 2, failLogSync: true });
  assert.equal(result.done, '2\n');
});

test('failed temporary completion flush never publishes a partial or stale sentinel', async t => {
  const result = await exercise(t, { failTempSync: true });
  assert.equal(result.done, null);
  assert.ok(!result.trace.includes('rename'));
  assert.ok(!result.files.some(name => name.includes('.tmp.')));
});

test('invalid launch arguments fail without exposing their contents', () => {
  assert.throws(() => buildGoadPlaybookLaunch({ logPath: '/tmp/log', donePath: '/tmp/done', argv: ['secret\0argument'] }),
    { name: 'TypeError', message: 'Invalid GOAD playbook launch paths or arguments' });
});

test('each required launcher tool is checked before any runner starts', () => {
  const required = ['nohup', 'setsid', 'sync', 'mv'];
  const launch = buildGoadPlaybookLaunch({ logPath: '/unused/log', donePath: '/unused/done', argv: ['/secret/runner'] });
  for (const missing of required) {
    const available = required.filter(tool => tool !== missing).map(tool => `${tool}() { :; }`).join('\n');
    const result = spawnSync(bash, ['-c', `PATH=/missing-goad-tools\n${available}\n${launch}`], { encoding: 'utf8', timeout: 5000 });
    assert.equal(result.status, 125, missing);
    assert.equal(result.stdout, '');
    assert.equal(result.stderr, 'GOAD launcher tools unavailable\n');
  }
});
