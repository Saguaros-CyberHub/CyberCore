/**
 * ciab-bake-wiring.test.js — the two orphaned capabilities are actually called.
 *
 * WHY THIS FILE EXISTS
 * goad-lab-push.js and goad-postcondition-probe.js were both written, both
 * tested, and both invoked by nothing. A library with a green test suite and no
 * caller is indistinguishable from a working feature right up until someone
 * deploys a generated client environment and finds that the lab was never
 * delivered and its vulnerabilities were never checked — which is the exact
 * silent-success failure the whole bake track exists to eliminate, reproduced
 * one level up.
 *
 * So every assertion here is about a CALL happening, not happening, or happening
 * in a particular order. Source text proves none of that, and the deploy path it
 * lives on needs Proxmox, a controller VM and ninety minutes.
 *
 * FIVE PROPERTIES:
 *
 *   1. AN EXISTING GOAD LANE IS UNCHANGED. Every built-in lab already lives at
 *      /opt/goad/ad/ from the controller bake. Re-pushing one would swap the
 *      reference lab every other lane runs for a copy assembled by a different
 *      program, with no undo and no error if the two ever disagreed by a byte.
 *      So: zero pushes, zero probes, and the playbook called with exactly the
 *      arguments it was called with before any of this existed.
 *
 *   2. A GENERATED LAB IS DELIVERED ONCE, BEFORE THE PLAYBOOK. Ordering is the
 *      property — a push after run.sh has read ad/<LAB> is a push into a lab
 *      that already ran as something else.
 *
 *   3. THE PROBE RUNS AFTER THE PLAYBOOK AND ITS REPORT IS DATA. A probe that
 *      aborted a deploy would make "this lane is missing its vulnerabilities"
 *      and "the probe could not connect" the same event, which is the ambiguity
 *      the probe was built to remove. It is recorded, including when it throws.
 *
 *   4. NO SECRET REACHES AN ARGV OR A WORLD-TRAVERSABLE PATH. Asserted against
 *      the REAL runPostconditionProbe with a fake guest underneath it, by
 *      decoding every command the probe issues — including the base64 payloads,
 *      because "not in plaintext" is not the claim being made.
 *
 *   5. A PHASE WITH NO IMPLEMENTATION REFUSES BY NAME. Both flavours: a steps
 *      object missing a key (the orchestrator's own guard) and a step built by
 *      buildBakeSteps for work that does not exist yet — which is the compile
 *      phase's chassis composer, and only that one now: provision and capture
 *      are wired to bake-staging.js and refuse on their own terms instead (see
 *      test/ciab-bake-staging.test.js for what they do).
 *
 * Plus the boot sweep, which can only be asserted from source: server.js cannot
 * be started in a test, and a stranded bake leaks a whole staging lane.
 *
 * OFFLINE. script-executor and node-ssh are stubbed through require.cache before
 * goad-deploy is loaded, so nothing reaches Proxmox; ciab/utils/db.js is stubbed
 * COMPLETELY (query, getPool, setPool, pool) before bake-orchestrator is loaded,
 * because a partial stub leaves the real module loaded for the omitted export
 * and that one builds a pg pool.
 *
 * Run: node --test front-end/test/ciab-bake-wiring.test.js  (or npm test)
 */

const { test, beforeEach } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const CIAB = path.join(ROOT, 'modules', 'crucible', 'plugins', 'ciab');

function stub(absPath, exports) {
  const p = require.resolve(absPath);
  require.cache[p] = { id: p, filename: p, loaded: true, exports };
  return exports;
}

// ── the fake guest ──────────────────────────────────────────────────────────
//
// One object standing in for the QEMU guest agent: proxmoxAPI answers
// agent/exec with a pid and remembers the argv, pollExecStatus answers as the
// command would have. Everything the code under test says to the controller
// passes through here, which is what makes the argv assertions in §4 total
// rather than a sample.

function makeGuest() {
  const calls = [];
  const argvByPid = new Map();
  let nextPid = 5000;

  const proxmoxAPI = async (method, urlPath, body) => {
    calls.push({ method, path: urlPath, body });
    if (urlPath.endsWith('/time')) return { time: Math.floor(Date.now() / 1000), localtime: 0 };
    if (method === 'GET' && /\/config(?:\?current=1)?$/.test(urlPath)) return { localtime: 0 };
    if (urlPath.endsWith('/status/current')) return { status: 'stopped' };
    if (/\/agent\/exec$/.test(urlPath)) {
      const argv = String(body).split('&')
        .map((kv) => decodeURIComponent(kv.replace(/^command=/, '')));
      const pid = nextPid += 1;
      argvByPid.set(pid, argv);
      return { pid };
    }
    return { data: 'UPID:fake:0000' };
  };

  const pollExecStatus = async (node, vmId, pid) => {
    const cmd = (argvByPid.get(pid) || []).join(' ');
    let stdout = '';
    if (/cybercore-clock-read/.test(cmd)) {
      return { exited: true, exitcode: 0, stdout: JSON.stringify({
        utc_milliseconds: Date.now(), timezone: 'UTC',
      }), stderr: '' };
    }
    // The WinRM reachability probe deployGoadLane runs from the controller.
    if (/\/dev\/tcp\//.test(cmd)) stdout = 'OK';
    // The probe's exit sentinel: present on the first poll, so the runner does
    // not spin. Its absence is what a timeout looks like and is not under test.
    else if (/done\.txt/.test(cmd)) stdout = '0';
    // Any other `[ -f p ] && cat p || echo __MISSING__` read — the per-host
    // result documents. Missing is a legitimate answer that parseProbeResult
    // grades as "every check failed", which is all §4 needs.
    else if (/\[ -f .+ \] && cat /.test(cmd)) stdout = '__MISSING__';
    return { exited: true, exitcode: 0, stdout, stderr: '' };
  };

  return {
    calls,
    proxmoxAPI,
    pollExecStatus,
    argvs: () => Array.from(argvByPid.values()),
  };
}

let guest = makeGuest();

stub(path.join(ROOT, 'src', 'utils', 'script-executor.js'), {
  agentExec: async () => ({ pid: 1 }),
  agentShellExec: async (node, vmId, shellCmd) => guest.proxmoxAPI(
    'POST', `/api2/json/nodes/${node}/qemu/${vmId}/agent/exec`,
    ['/bin/sh', '-c', shellCmd].map((a) => `command=${encodeURIComponent(a)}`).join('&')),
  pollExecStatus: (...args) => guest.pollExecStatus(...args),
  waitForGuestAgent: async () => true,
  updateScriptStatus: async () => {},
});

stub(path.join(ROOT, 'src', 'utils', 'node-ssh.js'), {
  pctExec: async () => ({ code: 0, stdout: '', stderr: '' }),
  pctPushFromString: async () => ({ code: 0 }),
  sshExec: async () => ({ code: 0, stdout: '', stderr: '' }),
});

let dbLog = [];
stub(path.join(CIAB, 'utils', 'db.js'), {
  query: async (text, params) => {
    dbLog.push({ sql: String(text).replace(/\s+/g, ' ').trim(), params: params || [] });
    return { rows: [], rowCount: 0 };
  },
  getPool: () => null,
  setPool: () => {},
  pool: null,
});

const goad = require(path.join(ROOT, 'src', 'utils', 'goad-deploy.js'));
const orch = require(path.join(CIAB, 'utils', 'bake-orchestrator.js'));
const labPush = require(path.join(CIAB, 'utils', 'goad-lab-push.js'));
const labProbe = require(path.join(CIAB, 'utils', 'goad-postcondition-probe.js'));

beforeEach(() => { guest = makeGuest(); dbLog = []; });

// ── fixtures ────────────────────────────────────────────────────────────────

const VXLAN = 10101;
const BASE = '10.39.16';
const EXT = '10.167.16';

/** The three secrets §4 hunts for. Distinctive enough that a substring hit is
 *  never a coincidence, and shaped like the passwords GOAD actually generates. */
const DOMAIN_PW = 'Zx9-Domain-Secret-Aa1';
const USER_PW = 'Zx9-User-Secret-Bb2';
const LOCAL_PW = 'Zx9-LocalAdmin-Secret-Cc3';

/** A small GOAD-shaped lab that yields real checks on a real host. */
function generatedLabConfig() {
  return {
    lab: {
      domains: {
        'clinic.local': {
          dc: 'dc01',
          domain_password: DOMAIN_PW,
          netbios_name: 'CLINIC',
          organisation_units: { Servers: { path: 'DC=clinic,DC=local' } },
          groups: { global: { Admins: { path: 'CN=Users,DC=clinic,DC=local' } } },
          users: {
            'billing.svc': {
              firstname: 'Billing',
              surname: 'Service',
              password: USER_PW,
              groups: ['Admins'],
              path: 'CN=Users,DC=clinic,DC=local',
              spns: ['MSSQLSvc/dc01.clinic.local:1433'],
            },
          },
          acls: {
            GenericAll_admins_billing: {
              for: 'Admins', to: 'billing.svc', right: 'GenericAll', inheritance: 'None',
            },
          },
        },
      },
      hosts: {
        dc01: {
          hostname: 'CLINIC-DC01',
          type: 'dc',
          domain: 'clinic.local',
          local_admin_password: LOCAL_PW,
          path: 'DC=clinic,DC=local',
          local_groups: { Administrators: ['clinic\\billing.svc'] },
          vulns: ['no_ldap_signing'],
          vulns_vars: {},
        },
      },
    },
  };
}

const GENERATED_NAME = 'CIAB-a1b2c3d4';

function generatedTree() {
  return {
    name: GENERATED_NAME,
    files: {
      'data/config.json': JSON.stringify(generatedLabConfig(), null, 2),
      'data/inventory': '[all:vars]\ndomain_name=CIAB-a1b2c3d4\n',
      'providers/proxmox/inventory': '[all]\ndc01\n',
    },
    chain: ['build.yml', 'ad-parent_domain.yml', 'ad-data.yml', 'vulnerabilities.yml'],
  };
}

/** A built-in GOAD-Light spec: the lane shape that must not change. */
function builtInSpec() {
  return {
    goad: { enabled: true, version: 'GOAD-Light' },
    vms: [{ name: 'DC01' }, { name: 'DC02' }, { name: 'SRV02' }],
  };
}

/** A generated-lab spec: one DC, described entirely on the spec. */
function generatedSpec(over = {}) {
  return {
    goad: {
      enabled: true,
      version: GENERATED_NAME,
      lab: {
        forestRoot: 'clinic.local',
        vms: [{ name: 'DC01', role: 'dc', os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 10 }],
      },
      generated_lab: generatedTree(),
      ...over,
    },
    vms: [{ name: 'DC01' }],
  };
}

/** deployGoadLane's arguments, minus whatever a test wants to vary. */
function laneArgs(spec, deps, over = {}) {
  return {
    lane: { lane_id: 'lane-1' },
    spec,
    module: 'ciab',
    vnet: { vnet: 'vx10101' },
    vxlanId: VXLAN,
    gatewayVmId: 110101,
    bestNode: 'pve1',
    templateNode: 'pve1',
    laneSubnetBase: BASE,
    extSubnetBase: EXT,
    // Include the actual roster so the clock gate runs. Waiting is injected
    // below; the tests exercise the gate without real VM boot delays.
    deployedVMs: goad.resolveGoadLab(spec).labDef.vms.map((vm, index) => ({
      name: vm.name, type: 'qemu', node: 'pve1', vm_id: 600000 + index,
    })),
    proxmoxAPI: guest.proxmoxAPI,
    waitForTask: async () => ({}),
    query: async (sql, params) => { dbLog.push({ sql: String(sql).replace(/\s+/g, ' ').trim(), params }); },
    deps: { sleep: async () => {}, ...deps },
    ...over,
  };
}

/** The jsonb the lane row was patched with, parsed. */
function laneConfigWrite() {
  const row = dbLog.find((c) => /UPDATE cybercore_lane/.test(c.sql));
  return row ? JSON.parse(row.params[0]).goad : null;
}

// ---------------------------------------------------------------------------
// 1. A built-in GOAD lane is untouched
// ---------------------------------------------------------------------------

test('a spec with no generated lab pushes nothing and probes nothing', async () => {
  const pushes = [];
  const probes = [];
  const playbooks = [];

  const out = await goad.deployGoadLane(laneArgs(builtInSpec(), {
    pushLabTree: async (o) => { pushes.push(o); return { skipped: false, treeSha256: 'x', chainMode: 'per-lab' }; },
    runPostconditionProbe: async (o) => { probes.push(o); return { passed: true, summary: {}, checks: [], errors: [] }; },
    runPlaybook: async (o) => { playbooks.push(o); return { exited: true, exitcode: 0 }; },
  }));

  assert.strictEqual(pushes.length, 0,
    'the built-in labs are already at /opt/goad/ad/ from the controller bake; re-pushing one '
    + 'replaces the reference lab every other lane runs, with no undo');
  assert.strictEqual(probes.length, 0,
    'a built-in lane must not acquire a fifteen-minute post-condition wait it never had');
  assert.strictEqual(playbooks.length, 1);
  assert.strictEqual(out.delivery, null);
  assert.strictEqual(out.verification.ran, false);
});

test('the playbook still receives exactly the arguments it always did', async () => {
  const spec = builtInSpec();
  let seen = null;
  const args = laneArgs(spec, { runPlaybook: async (o) => { seen = o; return { exited: true, exitcode: 0 }; } });
  await goad.deployGoadLane(args);

  assert.deepStrictEqual(Object.keys(seen).sort(),
    ['bestNode', 'controllerVmId', 'extSubnetBase', 'laneSubnetBase', 'proxmoxAPI', 'spec', 'vxlanId'].sort(),
    'runGoadPlaybook takes seven named arguments; adding or dropping one here changes what every '
    + 'existing GOAD lane runs');
  assert.strictEqual(seen.spec, spec, 'the spec must be passed through, not a copy');
  assert.strictEqual(seen.bestNode, 'pve1');
  assert.strictEqual(seen.vxlanId, VXLAN);
  assert.strictEqual(seen.laneSubnetBase, BASE);
  assert.strictEqual(seen.extSubnetBase, EXT);
  assert.strictEqual(seen.proxmoxAPI, args.proxmoxAPI);
});

test('a built-in lane records controller ownership and cleanup without delivery or probe keys', async () => {
  await goad.deployGoadLane(laneArgs(builtInSpec(), {
    runPlaybook: async () => ({ exited: true, exitcode: 0 }),
  }));
  const written = laneConfigWrite();
  assert.deepStrictEqual(Object.keys(written).sort(),
    ['clock', 'controller_clone_attempted', 'controller_node', 'controller_stop', 'controller_vmid', 'error', 'provisioned_at', 'stage', 'status'],
    'delivery and probe keys must appear only when the thing they describe happened');
  assert.strictEqual(written.status, 'provisioned');
  assert.strictEqual(written.controller_stop.stopped, true);
  assert.strictEqual(written.clock.passed, true);
  assert.strictEqual(written.clock.phase, 'after_provisioning');
});

test('the injected defaults ARE the shipped implementations', () => {
  // The one property an injected-deps design loses: "wired to something" and
  // "wired to the code that does the work" look identical from every other
  // angle, and this whole task exists because two libraries were wired to
  // nothing at all.
  const d = goad.defaultGoadDeps();
  assert.strictEqual(d.pushLabTree, labPush.pushLabTree);
  assert.strictEqual(d.runPostconditionProbe, labProbe.runPostconditionProbe);
  assert.strictEqual(d.buildExpectationSet, labProbe.buildExpectationSet);
  assert.strictEqual(d.collectLabSecrets, labProbe.collectLabSecrets);
  assert.strictEqual(d.assertNoSecrets, labProbe.assertNoSecrets);
  assert.strictEqual(d.runPlaybook, goad.runGoadPlaybook);
});

// ---------------------------------------------------------------------------
// 2. A generated lab is delivered exactly once, before the playbook
// ---------------------------------------------------------------------------

test('a generated lab is pushed once, and before the playbook runs', async () => {
  const order = [];
  const pushes = [];

  await goad.deployGoadLane(laneArgs(generatedSpec(), {
    pushLabTree: async (o) => {
      order.push('push'); pushes.push(o);
      return { lab: o.lab, skipped: false, treeSha256: 'deadbeefcafe0000', chainMode: 'per-lab' };
    },
    runPlaybook: async () => { order.push('playbook'); return { exited: true, exitcode: 0 }; },
    runPostconditionProbe: async () => {
      order.push('probe');
      return { passed: true, summary: { ok: 4, total: 4, failed: 0, inconclusive: 0 }, checks: [], errors: [] };
    },
  }));

  assert.deepStrictEqual(order, ['push', 'playbook', 'probe'],
    'run.sh resolves ad/<LAB> when it starts, so a push after it is a push into a lab that has '
    + 'already run as something else');
  assert.strictEqual(pushes.length, 1, 'the tree is content-addressed; pushing twice is a bug, not a retry');
  assert.strictEqual(pushes[0].lab, GENERATED_NAME);
  assert.deepStrictEqual(pushes[0].chain, generatedTree().chain);
  assert.strictEqual(pushes[0].node, 'pve1');
  assert.ok(pushes[0].vmId > 200000, 'the push targets the lane CONTROLLER, not a lab host');
});

test('the push uses this module’s transport, not goad-lab-push’s own default', async () => {
  // Otherwise an injected exec covers everything except the push, which quietly
  // keeps talking to the real cluster.
  const se = require(path.join(ROOT, 'src', 'utils', 'script-executor.js'));
  let seen = null;
  await goad.deployGoadLane(laneArgs(generatedSpec(), {
    pushLabTree: async (o) => { seen = o; return { skipped: true, treeSha256: 'a', chainMode: 'per-lab' }; },
    runPlaybook: async () => ({ exited: true, exitcode: 0 }),
    runPostconditionProbe: async () => ({ passed: true, summary: {}, checks: [], errors: [] }),
  }));
  assert.strictEqual(seen.deps.agentShellExec, se.agentShellExec);
  assert.strictEqual(seen.deps.pollExecStatus, se.pollExecStatus);
});

test('a delivery that fails stops the deploy instead of provisioning the wrong lab', async () => {
  // The push is the only thing that puts ad/CIAB-… on the controller. If it
  // failed and the deploy carried on, run.sh would resolve whatever tree the
  // controller already had for that name — or none — and the lane would come up
  // as a different lab with nothing raised.
  await assert.rejects(
    () => goad.deployGoadLane(laneArgs(generatedSpec(), {
      pushLabTree: async () => { throw new Error('extract failed (exit 31)'); },
      runPlaybook: async () => { throw new Error('the playbook must never be reached'); },
    })),
    /exit 31/);
});

test('a generated lab whose name disagrees with the version is refused', async () => {
  // run.sh takes spec.goad.version. Pushing one name and running another is
  // silent at every layer: the push succeeds, the playbook succeeds, and the
  // lane is a lab nobody asked for.
  const spec = generatedSpec();
  spec.goad.generated_lab.name = 'CIAB-99999999';
  await assert.rejects(
    () => goad.deployGoadLane(laneArgs(spec, { runPlaybook: async () => ({}) })),
    /CIAB-99999999.*CIAB-a1b2c3d4|CIAB-a1b2c3d4.*CIAB-99999999/s);
});

test('a generated lab with no chain is refused before the lane is built', () => {
  const spec = generatedSpec();
  delete spec.goad.generated_lab.chain;
  assert.throws(() => goad.resolveGeneratedLab(spec), /chain is required/);
  // …and the default: chain is named, because that is what would otherwise run.
  assert.throws(() => goad.resolveGeneratedLab(spec), /default:/);
});

// ---------------------------------------------------------------------------
// 3. The probe runs after the playbook, and its report is data
// ---------------------------------------------------------------------------

test('a failing probe is recorded on the lane, not thrown', async () => {
  const report = {
    passed: false,
    summary: { ok: 2, total: 4, failed: 2, inconclusive: 0, negative: 1 },
    errors: [],
    checks: [
      { id: 'acl:dc01:GenericAll', ok: false, expect: 'present' },
      { id: 'vuln:dc01:no_ldap_signing', ok: false, expect: 'present' },
      { id: 'ou:dc01', ok: true, expect: 'present' },
    ],
  };
  let out;
  await assert.doesNotReject(async () => {
    out = await goad.deployGoadLane(laneArgs(generatedSpec(), {
      pushLabTree: async () => ({ skipped: false, treeSha256: 'abc123abc123', chainMode: 'per-lab' }),
      runPlaybook: async () => ({ exited: true, exitcode: 0 }),
      runPostconditionProbe: async () => report,
    }));
  });

  assert.strictEqual(out.verification.ran, true);
  assert.strictEqual(out.verification.passed, false);
  assert.strictEqual(out.verification.report, report,
    'the caller gets the whole document — the bake stores it in verify_report');

  const written = laneConfigWrite();
  assert.strictEqual(written.status, 'provisioned',
    'a failed probe does not fail the lane: at this layer the report is data, and the bake '
    + 'orchestrator is what decides a failure means refusal');
  assert.strictEqual(written.probe.passed, false);
  assert.deepStrictEqual(written.probe.failed_checks,
    ['acl:dc01:GenericAll', 'vuln:dc01:no_ldap_signing']);
  assert.strictEqual(written.generated_lab.tree_sha256, 'abc123abc123');
});

test('a probe that throws is recorded as a probe that threw', async () => {
  // The distinction the whole component rests on: "the lab is missing its
  // vulnerabilities" and "the probe could not answer" must not be the same
  // outcome. passed:null is the second one.
  let out;
  await assert.doesNotReject(async () => {
    out = await goad.deployGoadLane(laneArgs(generatedSpec(), {
      pushLabTree: async () => ({ skipped: false, treeSha256: 'abc', chainMode: 'per-lab' }),
      runPlaybook: async () => ({ exited: true, exitcode: 0 }),
      runPostconditionProbe: async () => { throw new Error('guest-exec never returned'); },
    }));
  });
  assert.strictEqual(out.verification.ran, false);
  assert.strictEqual(out.verification.passed, null);
  assert.match(out.verification.error, /guest-exec never returned/);
  assert.strictEqual(laneConfigWrite().probe.passed, null);
});

test('a failed playbook skips the probe and says so', async () => {
  // Grading a half-built forest costs up to fifteen minutes to restate what the
  // exit code already said — but "not probed" must never look like "probed clean".
  let probed = 0;
  await assert.rejects(() => goad.deployGoadLane(laneArgs(generatedSpec(), {
    pushLabTree: async () => ({ skipped: false, treeSha256: 'abc', chainMode: 'per-lab' }),
    runPlaybook: async () => { throw new Error('GOAD playbook exit 2'); },
    runPostconditionProbe: async () => { probed += 1; return { passed: true }; },
  })), /exit 2/);
  assert.strictEqual(probed, 0);
  const written = laneConfigWrite();
  assert.strictEqual(written.status, 'failed');
  assert.strictEqual(written.probe.ran, false);
  assert.match(written.probe.reason, /playbook failed/);
});

test('spec.goad.probe === false is an opt-out that is recorded, not a silent skip', async () => {
  const out = await goad.runLaneVerification({
    controllerVmId: 210101, bestNode: 'pve1', spec: generatedSpec({ probe: false }),
    proxmoxAPI: guest.proxmoxAPI, deps: {},
  });
  assert.strictEqual(out.ran, false);
  assert.strictEqual(out.passed, null);
  assert.match(out.reason, /opted out/);
});

// ---------------------------------------------------------------------------
// 4. No secret in any argv or staged path — asserted against the real probe
// ---------------------------------------------------------------------------

/** Every command the guest was asked to run, plus every base64 payload inside
 *  one, decoded. "Not in plaintext" is not the claim being made. */
function allGuestPayloads() {
  const out = [];
  for (const argv of guest.argvs()) {
    const cmd = argv.join(' ');
    out.push({ kind: 'argv', text: cmd, cmd });
    const re = /echo ([A-Za-z0-9+/=]{8,}) \| base64 -d > (\S+)/g;
    let m;
    while ((m = re.exec(cmd)) !== null) {
      out.push({
        kind: 'payload',
        text: Buffer.from(m[1], 'base64').toString('utf8'),
        cmd,
        dest: m[2],
      });
    }
  }
  return out;
}

async function runRealProbe(specOver = {}) {
  return goad.runLaneVerification({
    controllerVmId: 210101,
    bestNode: 'pve1',
    spec: generatedSpec(specOver),
    proxmoxAPI: guest.proxmoxAPI,
    // Only the clock is faked: the probe module's real runner, real playbook
    // text, real vars file, real chunked writes.
    deps: { sleep: async () => {} },
  });
}

test('the real probe runs end to end against the fake guest', async () => {
  const out = await runRealProbe();
  assert.strictEqual(out.ran, true, out.error || '');
  assert.ok(guest.argvs().length > 0, 'the probe must actually talk to the controller');
  // The result documents are __MISSING__ here, and fail-closed is the contract.
  assert.strictEqual(out.passed, false);
});

test('no lab secret appears in any argv the probe issues', async () => {
  await runRealProbe();
  for (const secret of [DOMAIN_PW, USER_PW, LOCAL_PW]) {
    for (const argv of guest.argvs()) {
      assert.ok(argv.join(' ').indexOf(secret) === -1,
        `a lab secret reached a command line: ${argv.join(' ').slice(0, 200)}\n`
        + 'script-executor interpolates script_args UNQUOTED and an argv is visible to every '
        + 'process on the controller.');
    }
  }
});

test('a secret that travels at all travels only in a 0600 file under the root-only probe dir', async () => {
  await runRealProbe({ probe: { verify_credentials: true } });
  const carriers = allGuestPayloads()
    .filter((p) => [DOMAIN_PW, USER_PW, LOCAL_PW].some((s) => p.text.indexOf(s) !== -1));

  assert.ok(carriers.length > 0,
    'the probe needs a become credential; if nothing carries one this test is asserting nothing');
  for (const c of carriers) {
    assert.strictEqual(c.kind, 'payload',
      `a secret appeared in a command line rather than a written payload: ${c.cmd.slice(0, 200)}`);
    assert.ok(c.dest.startsWith(labProbe.CONTROLLER_PROBE_DIR),
      `a secret was written outside ${labProbe.CONTROLLER_PROBE_DIR}: ${c.dest}`);
    assert.match(c.cmd, /umask 077;/,
      'the file must never be briefly world-readable between creation and chmod');
    assert.match(c.cmd, /chmod 600 /,
      'and an existing file the redirect truncates keeps its old mode without this');
  }
});

test('nothing staged into C:\\Windows\\Temp carries a secret', async () => {
  // C:\Windows\Temp is traversable by Users, which is the low-priv shell the lab
  // deliberately hands a student. The expectation set lands there; credentials
  // must not.
  await runRealProbe({ probe: { verify_credentials: true } });
  for (const p of allGuestPayloads()) {
    if (p.text.indexOf('C:\\Windows\\Temp') === -1) continue;
    for (const secret of [DOMAIN_PW, USER_PW, LOCAL_PW]) {
      assert.ok(p.text.indexOf(secret) === -1,
        'a payload that names the world-traversable staging directory also contains a lab secret');
    }
  }
});

test('the credentials reach the probe as no_log parameters, and the guard is armed', async () => {
  let opts = null;
  await goad.runLaneVerification({
    controllerVmId: 210101, bestNode: 'pve1',
    spec: generatedSpec({ probe: { verify_credentials: true } }),
    proxmoxAPI: guest.proxmoxAPI,
    deps: { runPostconditionProbe: async (o) => { opts = o; return { passed: true, summary: {}, checks: [], errors: [] }; } },
  });

  assert.strictEqual(opts.becomePassword, DOMAIN_PW,
    'the become credential comes from the lab config, and it is an OPTION — the module writes it '
    + 'into a 0600 controller file and hands it to the guest under no_log');
  assert.strictEqual(opts.becomeUser, 'administrator',
    'GOAD connects as vagrant, a LOCAL admin, which cannot read the directory facts being checked');
  assert.deepStrictEqual(opts.credentials['clinic.local\\billing.svc'],
    { username: 'clinic.local\\billing.svc', password: USER_PW });
  assert.ok(opts.secrets.includes(DOMAIN_PW) && opts.secrets.includes(USER_PW)
    && opts.secrets.includes(LOCAL_PW),
    'collectLabSecrets’ harvest must be handed on, or the module’s own assertNoSecrets is nominal');
  // And the staged half really is clean.
  assert.doesNotThrow(() => labProbe.assertNoSecrets(opts.expectationSet, opts.secrets));
  assert.ok(opts.expectationSet.checks.length > 0, 'an empty set would make the guard vacuous');
});

// ---------------------------------------------------------------------------
// 5. A phase with no implementation refuses by name
// ---------------------------------------------------------------------------

test('buildBakeSteps supplies exactly the five phases the orchestrator sequences', () => {
  const steps = orch.buildBakeSteps();
  assert.deepStrictEqual(Object.keys(steps).sort(), orch.PHASES.map((p) => p.step).sort());
  for (const phase of orch.PHASES) {
    assert.strictEqual(typeof steps[phase.step], 'function', `${phase.step} must be a function`);
  }
});

test('a phase with no implementation throws a NAMED error rather than returning', async () => {
  const steps = orch.buildBakeSteps();
  const args = { bake: { bake_id: 'b1', lab_name: 'CIAB-a1b2c3d4', spec: {} }, setDetail: async () => {}, record: async () => true };

  // COMPILE ONLY, now that provision and capture are built (bake-staging.js).
  // Nothing composes a chassis plus a client profile into an ad/<LAB> tree yet,
  // and a spec that carries no generated_lab has nothing to fall back to — so
  // this is the one phase left that can refuse by construction.
  for (const step of ['compile']) {
    await assert.rejects(() => steps[step](args), (err) => {
      assert.strictEqual(err.name, 'BakeStepNotImplemented', `${step} must refuse by name`);
      assert.strictEqual(err.code, 'BAKE_STEP_NOT_IMPLEMENTED');
      assert.strictEqual(err.step, step);
      assert.ok(err instanceof orch.BakeStepNotImplemented);
      return true;
    }, `the '${step}' phase must refuse — a phase that returns nothing produces a bake that reaches `
      + "'ready' having built nothing");
  }
});

test('the not-implemented message names what is missing, not just that it is', async () => {
  const steps = orch.buildBakeSteps();
  const args = { bake: { bake_id: 'b1', lab_name: 'L', spec: {} }, setDetail: async () => {}, record: async () => true };
  await assert.rejects(() => steps.compile(args), /chassis/);
});

test('the built phases refuse on their OWN terms, and name the field, not the feature', async () => {
  // The successor property to the two refusals that used to live here. provision
  // and capture are bake-staging's now, and a refusal from either must still be
  // actionable: an operator can set a spec field, and cannot install a phase.
  const steps = orch.buildBakeSteps();
  const args = { bake: { bake_id: 'b1', lab_name: 'L', spec: {} }, setDetail: async () => {}, record: async () => true };
  await assert.rejects(() => steps.provision(args), /goad\.enabled/,
    'a spec with no GOAD forest has nothing to capture, and that is a fact about the client');
  await assert.rejects(() => steps.capture(args), /spec\.goad\.fixed_subnet/,
    'and a capture with no pinned subnet would produce templates no lane can be built correctly '
    + 'from — the refusal names the field that fixes it');
});

test('an injected implementation replaces the refusal', async () => {
  const seen = [];
  const steps = orch.buildBakeSteps({
    compileLab: async () => { seen.push('compile'); return generatedTree(); },
    provisionStagingLane: async (a) => { seen.push('provision'); return { staging_lane_id: 'lane-9', verify_report: a.spec ? { ran: true, passed: true, report: { passed: true, summary: { ok: 1, total: 1 }, checks: [], errors: [] } } : null }; },
    captureGolden: async () => { seen.push('capture'); return { golden_vmids: [9001] }; },
  });
  const detail = [];
  const args = {
    bake: { bake_id: 'b1', lab_name: GENERATED_NAME, spec: { goad: {} } },
    setDetail: async (d) => { detail.push(d); },
    record: async () => true,
  };

  assert.strictEqual(await steps.compile(args), null, 'a step may only return bake COLUMNS');
  assert.strictEqual(await steps.push(args), null);
  const patch = await steps.provision(args);
  assert.strictEqual(patch.staging_lane_id, 'lane-9');
  assert.deepStrictEqual(await steps.capture(args), { golden_vmids: [9001] });
  assert.deepStrictEqual(seen, ['compile', 'provision', 'capture']);
  assert.ok(detail.some((d) => /ready to deliver/.test(d) && /playbook chain/.test(d)),
    'the push phase must report the content address it validated');
});

test('the push phase prepares a spec goad-deploy will actually deliver from', async () => {
  let handed = null;
  const steps = orch.buildBakeSteps({
    compileLab: async () => generatedTree(),
    provisionStagingLane: async (a) => { handed = a.spec; return {}; },
  });
  const args = {
    bake: { bake_id: 'b1', lab_name: GENERATED_NAME, spec: { goad: { enabled: true }, fixed_subnet: '10.39.16' } },
    setDetail: async () => {}, record: async () => true,
  };
  await steps.compile(args);
  await steps.push(args);
  await steps.provision(args);

  assert.ok(handed, 'provision must receive the prepared spec');
  assert.strictEqual(handed.fixed_subnet, '10.39.16', 'the rest of the spec must survive');
  assert.strictEqual(handed.goad.version, GENERATED_NAME);
  // The contract the delivery half reads. If these two ever disagree the tree is
  // installed somewhere run.sh does not look.
  assert.strictEqual(handed.goad.generated_lab.name, GENERATED_NAME);
  assert.deepStrictEqual(goad.resolveGeneratedLab(handed).chain, generatedTree().chain);
  assert.notStrictEqual(handed, args.bake.spec,
    'the row’s spec is the record of what was asked for; a phase must not edit it in place');
});

test('the push phase refuses exactly what pushLabTree would, ninety minutes earlier', async () => {
  const args = (tree) => ({
    bake: { bake_id: 'b1', lab_name: tree.name, spec: { goad: {} } },
    setDetail: async () => {}, record: async () => true,
  });
  const build = (tree) => {
    const steps = orch.buildBakeSteps({ compileLab: async () => tree });
    return async () => { await steps.compile(args(tree)); await steps.push(args(tree)); };
  };

  const reserved = generatedTree(); reserved.name = 'GOAD-Light';
  await assert.rejects(build(reserved)(), /shipped labs|reserved/i,
    'a generated lab must never be able to overwrite a reference lab');

  const noData = generatedTree(); noData.files = { 'README.md': 'x' };
  await assert.rejects(build(noData)(), /data\//,
    'a tree with no data/ stages an unusable directory and run.sh stops at "Lab not found"');

  const clash = generatedTree(); clash.files['playbooks.yml'] = 'CIAB: []';
  await assert.rejects(build(clash)(), /playbooks\.yml/,
    'the chain is rendered from `chain`; two sources of truth is ambiguity, not a merge');
});

test('a steps object missing a key fails the bake by name, and never skips', async () => {
  // The orchestrator's own guard, which is the backstop for a caller that built
  // its steps object by hand.
  const steps = orch.buildBakeSteps({
    compileLab: async () => generatedTree(),
    provisionStagingLane: async () => ({ verify_report: { ran: true, passed: true, report: { passed: true, summary: { ok: 1, total: 1 }, checks: [], errors: [] } } }),
  });
  delete steps.capture;

  const result = await orch.bakeProfile(
    { bake_id: 'b-missing', profile_id: 'p1', lab_name: GENERATED_NAME, spec: { goad: {} } },
    { steps, heartbeatMs: 0 });

  assert.strictEqual(result.status, 'failed');
  assert.match(result.error, /'capture' phase/);
  const failed = dbLog.find((c) => /SET status = 'failed'/.test(c.sql));
  assert.ok(failed, 'the failure must reach the row — it is the only thing an operator can see');
  assert.match(String(failed.params[1]), /capture/);
});

// ---------------------------------------------------------------------------
// 6. The verify phase is what turns a report into a refusal
// ---------------------------------------------------------------------------

test('a clean report passes and says what it proved', () => {
  const v = orch.gradeVerifyReport({
    ran: true, passed: true,
    report: { passed: true, summary: { ok: 12, total: 12, negative: 3, declared: 2 }, checks: [], errors: [] },
  });
  assert.strictEqual(v.ok, true);
  assert.match(v.detail, /12/);
});

test('a report with failing checks refuses and names them', () => {
  const v = orch.gradeVerifyReport({
    passed: false,
    summary: { ok: 1, total: 3, failed: 2 },
    errors: [],
    checks: [
      { id: 'vuln:dc01:adcs_esc7', ok: false },
      { id: 'acl:dc01:GenericAll', ok: false },
      { id: 'ou:srv02', ok: true },
    ],
  });
  assert.strictEqual(v.ok, false);
  assert.match(v.detail, /adcs_esc7/);
  assert.match(v.detail, /acl:dc01:GenericAll/);
});

test('"the probe never ran" is a refusal, not a pass', () => {
  // Same doctrine as BAKE_DRIFT_UNKNOWN: "I could not check" and "there is
  // nothing wrong" must never be the same answer.
  for (const recorded of [
    null,
    undefined,
    {},
    { ran: false, error: 'guest-exec never returned' },
    { ran: false, reason: 'the playbook failed' },
  ]) {
    const v = orch.gradeVerifyReport(recorded);
    assert.strictEqual(v.ok, false, `${JSON.stringify(recorded)} must not pass`);
  }
  assert.match(orch.gradeVerifyReport({}).detail, /no post-condition report/);
  assert.match(orch.gradeVerifyReport({ ran: false, error: 'boom' }).detail, /boom/);
});

test('the verify phase refuses a bake whose probe found the vulnerabilities missing', async () => {
  const steps = orch.buildBakeSteps();
  await assert.rejects(
    () => steps.verify({
      bake: {
        verify_report: {
          ran: true, passed: false,
          report: { passed: false, summary: { ok: 1, total: 2, failed: 1 }, errors: [], checks: [{ id: 'vuln:dc01:adcs_esc7', ok: false }] },
        },
      },
      setDetail: async () => {}, record: async () => true,
    }),
    (err) => { assert.strictEqual(err.code, 'BAKE_VERIFY_FAILED'); return /adcs_esc7/.test(err.message); });
});

test('the verify phase passes a clean report through', async () => {
  const steps = orch.buildBakeSteps();
  const detail = [];
  const out = await steps.verify({
    bake: { verify_report: { ran: true, passed: true, report: { passed: true, summary: { ok: 5, total: 5 }, errors: [], checks: [] } } },
    setDetail: async (d) => { detail.push(d); }, record: async () => true,
  });
  assert.strictEqual(out, null);
  assert.match(detail[0], /Verified/);
});

// ---------------------------------------------------------------------------
// 7. The boot sweep
// ---------------------------------------------------------------------------

test('server.js calls recoverStrandedBakes at boot', () => {
  // Source text, because server.js cannot be started in a test — and this one is
  // not cosmetic: a bake abandoned by a restart holds a whole staging lane plus a
  // controller VM, and the row is the ONLY thing that knows their ids. Without
  // the sweep the leak is permanent, silent, and unenumerable.
  const src = fs.readFileSync(path.join(ROOT, 'src', 'server.js'), 'utf8').replace(/\s+/g, ' ');
  assert.match(src, /require\('\.\.\/modules\/crucible\/plugins\/ciab\/utils\/bake-orchestrator'\) \.?recoverStrandedBakes\(\)/,
    'src/server.js must sweep stranded bakes at boot, the same way it sweeps stranded engagements');
  // In the same neighbourhood as the sweeps it matches, so the ordering
  // reasoning in that block stays true.
  assert.ok(src.indexOf('recoverStrandedEngagements') < src.indexOf('recoverStrandedBakes'),
    'the bake sweep belongs after the engagement sweep, with the other plugin sweeps');
  assert.ok(src.indexOf('recoverStrandedBakes') < src.indexOf('recoverStrandedCourseLabs'),
    'and before the CLE course sweep, where the comment block explains why');
});

test('recoverStrandedBakes is exported under exactly the name server.js calls', () => {
  assert.strictEqual(typeof orch.recoverStrandedBakes, 'function');
});
