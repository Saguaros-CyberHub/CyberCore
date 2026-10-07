/**
 * ciab-lane-reseed.test.js — S4: the per-lane reseed.
 *
 * WHY THIS FILE EXISTS
 * The vuln-app image is cached on (profile_id, difficulty) and hashBundle
 * covers only the generated source plus the Dockerfile, so every lane in every
 * section runs a BYTE-IDENTICAL image. Golden AD images make that worse: the
 * domain password, every user password and the credential the exercise pivots
 * on would be identical for every student too. One student pastes a value into
 * the group chat and the cohort is finished.
 *
 * The golden-image design is only safe because of this reseed, so the headline
 * assertion here is the specific defect it exists to fix: TWO LANES FROM ONE
 * BAKE MUST GET DIFFERENT FLAGS AND DIFFERENT PIVOT CREDENTIALS. Everything
 * else in this file defends a property that, if it broke, would break silently:
 *
 *   - both sides of the credential carry the SAME value per lane. A web
 *     credential AD no longer honours is a dead end the student cannot
 *     distinguish from their own mistake.
 *   - a pre-baked lane with no (or a disagreeing) goad.fixed_subnet is refused.
 *     Without that, the golden images' baked DNS, SPN and SYSVOL records name
 *     addresses the lane does not have and the lane still reports active.
 *   - no secret reaches a staged file, a temp path or a log. script_args is
 *     interpolated UNQUOTED and staged scripts land in world-traversable
 *     C:\\Windows\\Temp with a tee'd log beside them, so a student holding the
 *     low-priv shell we deliberately gave them could read the credential and
 *     skip the exercise.
 *   - the DC guest agent gets a real wait-and-retry. A prebaked lane has no
 *     controller, so that agent is the ONLY way to change a password in the
 *     directory; warning once and carrying on is how every lane in a batch
 *     silently keeps the baked value.
 *   - a reseed failure is recorded on the lane and does not fail it.
 *
 * challenge-lane-deployer (reached through lane-provision) pulls site-config at
 * module load, which reads a gitignored config/site.json — same require.cache
 * stub ciab-lane-provision.test.js uses.
 *
 * Run: node --test front-end/test/ciab-lane-reseed.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const UTILS = path.join(ROOT, 'src', 'utils');
const CIAB_UTILS = path.join(ROOT, 'modules/crucible/plugins/ciab/utils');

require.cache[require.resolve(path.join(UTILS, 'site-config.js'))] = {
  id: 'site-config', filename: 'site-config', loaded: true,
  exports: {
    getSchedulingConfig: () => ({
      min_free_mem_gb: 8, min_free_disk_gb: 20,
      max_concurrent_lanes: 5, max_concurrent_clones: 4,
      node_score_weights: { cpu: 0.35, mem: 0.55, disk: 0.10 },
    }),
    getDefaultTemplateNode: () => 'node-1',
  },
};

const reseed = require(path.join(CIAB_UTILS, 'lane-reseed.js'));
const laneProvision = require(path.join(CIAB_UTILS, 'lane-provision.js'));
const flagManager = require(path.join(UTILS, 'flag-manager.js'));

const RESEED_SRC = fs.readFileSync(path.join(CIAB_UTILS, 'lane-reseed.js'), 'utf8');

// The producer of the descriptor the reseed consumes, and the compiler that
// feeds it. Required here rather than fixtured by hand: a hand-written plant
// list would be a test of a shape nobody emits.
const labContent = require(path.join(CIAB_UTILS, 'goad-lab-content.js'));
const labCompile = require(path.join(CIAB_UTILS, 'goad-lab-compile.js'));

// THE OTHER END OF THE SEAM, AND IT IS THE REAL ONE. spec.reseed is built by
// profile-deploy's bake overlay, and the defect this section is about lived
// entirely there: it named the account off the CHAIN instead of off the website,
// took the NetBIOS short name for a DNS domain, and never put site.reseed on the
// spec at all — while this module's consumer half was complete and green. So the
// spec these tests feed the consumer is the one the PRODUCER emits, not a
// hand-written approximation of it; a fixture here would have gone on passing
// through all three defects. The router pulls the plugin's db module at load, so
// that one is stubbed the way ciab-bake-route.test.js stubs it.
const CIAB_DB = require.resolve(path.join(CIAB_UTILS, 'db.js'));
require.cache[CIAB_DB] = {
  id: CIAB_DB, filename: CIAB_DB, loaded: true, children: [], paths: [],
  exports: {
    pool: { query: async () => ({ rows: [], rowCount: 0 }) },
    query: async () => ({ rows: [], rowCount: 0 }),
    getPool: () => ({ query: async () => ({ rows: [], rowCount: 0 }) }),
    setPool: () => {},
  },
};
const deployRouter = require(path.join(CIAB_UTILS, '..', 'routes', 'profile-deploy.js'));

// The one thing that actually writes the pivot config onto a lane.
const CC_WEB_PIVOT_J2 = fs.readFileSync(
  path.join(ROOT, '..', 'infrastructure', 'ansible', 'cc-web', 'roles', 'cc_web',
    'templates', 'pivot-credential.j2'), 'utf8');

/**
 * roles/cc_web/templates/pivot-credential.j2, in JavaScript.
 *
 * A PORT, and the test below pins it: every line this emits for a format is
 * asserted to be a line the template really contains, so a change to the role
 * fails here rather than on a lane. Without it these tests would be about bytes
 * this repository invented, and the rewrite would be proved against a file
 * shape that does not exist.
 */
function renderPivotConfig(pivot) {
  const d = pivot.domain;
  const u = pivot.username;
  const p = pivot.password;
  const extra = pivot.extra || {};
  const entries = Object.entries(extra);
  if (pivot.format === 'dotenv') {
    return ['# Application environment. Generated during provisioning.',
      `AD_DOMAIN=${d}`, `AD_USERNAME=${u}`, `AD_PASSWORD=${p}`, 'AD_AUTH_ENABLED=true']
      .concat(entries.map(([k, v]) => `${k.toUpperCase().replace(/[^A-Z0-9_]/g, '_')}=${v}`))
      .concat(['']).join('\n');
  }
  if (pivot.format === 'php') {
    const e = (s) => String(s).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
    return ['<?php', '// Application configuration. Generated during provisioning.', 'return [',
      `    'ad_domain'   => '${e(d)}',`,
      `    'ad_username' => '${e(u)}',`,
      `    'ad_password' => '${e(p)}',`,
      "    'ad_auth_enabled' => true,"]
      .concat(entries.map(([k, v]) => `    '${e(k)}' => '${e(v)}',`))
      .concat(['];', '']).join('\n');
  }
  if (pivot.format === 'json') {
    // ansible's to_nice_json: indent 4, keys sorted.
    const obj = { ad: { auth_enabled: true, domain: d, password: p, username: u }, extra };
    return `${JSON.stringify(obj, null, 4)}\n`;
  }
  if (pivot.format === 'ini') {
    const lines = ['; Application configuration. Generated during provisioning.', '[directory]',
      `domain = ${d}`, `username = ${u}`, `password = ${p}`, 'auth_enabled = true'];
    if (entries.length) {
      lines.push('', '[application]');
      for (const [k, v] of entries) lines.push(`${k} = ${v}`);
    }
    return `${lines.concat(['']).join('\n')}`;
  }
  const x = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return ['<?xml version="1.0" encoding="utf-8"?>',
    '<!-- Application configuration. Generated during provisioning. -->',
    '<configuration>', '  <directory>',
    `    <domain>${x(d)}</domain>`,
    `    <username>${x(u)}</username>`,
    `    <password>${x(p)}</password>`,
    '    <authEnabled>true</authEnabled>', '  </directory>']
    .concat(entries.map(([k, v]) => `  <setting name="${x(k).replace(/"/g, '&quot;')}">${x(v)}</setting>`))
    .concat(['</configuration>', '']).join('\n');
}

/** The profile shape goad-lab-compile takes. Same one ciab-goad-lab-content
 *  uses, so the pinned run ids land on the same chain shapes. */
function siteProfile(o) {
  return {
    json_data: {
      student_view: {
        meta: { run_id: o.runId, client_type: 'SMB', difficulty: 'intermediate' },
        quick: { company_name: o.company, employees_total: o.employees },
        raw: {
          threats: {
            organization: {
              company_name: o.company,
              domain_public: o.domain,
              employees_total: o.employees,
              hq_city: o.city,
              industry: o.industry,
              department_breakdown: o.departments,
            },
            it_environment: { delivery: 'Hybrid' },
          },
        },
        stakeholders: o.stakeholders,
      },
    },
  };
}

const RIDGELINE = Object.freeze({
  company: 'Ridgeline Dental Group', domain: 'ridgelinedental.com', employees: 46,
  city: 'Boise, ID', industry: 'Healthcare',
  departments: { Clinical: 18, Administration: 9, Finance: 5, IT: 3 },
  stakeholders: [
    { name: 'Alice Kwan', role: 'Practice Principal', department: 'Clinical' },
    { name: 'Tom Iverson', role: 'Practice Manager', department: 'Administration' },
    { name: 'Nadia Farouk', role: 'Head of Nursing', department: 'Clinical' },
  ],
});

const siteCache = {};
/**
 * A REAL bake's worth of website: a compiled lab, a proven attack chain, the
 * site goad-lab-content authors for it, and the exact bytes that end up on the
 * golden image's disk — the pages it emitted plus the config cc_web renders.
 *
 * This is the fixture the whole section is about. The plant descriptors are not
 * written here; they are whatever the producer emitted for this client.
 */
function bakedSite(runId) {
  if (!siteCache[runId]) {
    const compiled = labCompile.compileLabWithChain(siteProfile(Object.assign({ runId }, RIDGELINE)));
    const lab = JSON.parse(compiled.files['data/config.json']).lab;
    const site = labContent.generateSiteContent(compiled.ir, { runId: compiled.run_id, lab });
    const files = {};
    for (const route of site.routes) files[`${site.docroot}/${route.file}`] = route.content;
    files[site.pivot.path] = renderPivotConfig(site.pivot);
    // The bake row the deploy gate hands the overlay, with the one witness of
    // what the staging lane really installed on it.
    const bake = {
      bake_id: `bake-${runId}`, lab_name: compiled.ir.lab_name, status: 'ready',
      verify_report: {
        cc_web: {
          applicable: true, passed: true,
          pivot_path: site.pivot.path,
          pivot_account: `${site.pivot.domain}\\${site.pivot.username}`,
        },
      },
      spec: {
        goad: {
          lab: { ...compiled.ir, forestRoot: compiled.ir.foothold_credential.domain },
        },
      },
    };
    siteCache[runId] = { ir: compiled.ir, site, files, bake, baked: site.pivot.password };
  }
  return siteCache[runId];
}

/**
 * The spec a pre-baked lane of that client is deployed from — the golden spec
 * plus THE SEAM AS THE PRODUCER REALLY EMITS IT.
 *
 * Built by profile-deploy's own reseedBlockForBake rather than written out here.
 * The account, the DNS domain, the plant descriptors and the rotate/fixed
 * verdict are the four things the producer got wrong, and every one of them is
 * invisible to a test that hand-writes the answer it wants.
 */
function bakedSpec(runId) {
  const { ir, bake } = bakedSite(runId);
  return {
    reseed: deployRouter.reseedBlockForBake({
      spec: {}, bake, ir, foothold: ir.foothold_credential,
    }),
  };
}

// ── the fixture: ONE bake, deployed to many lanes ───────────────────────────

// The base the golden images were provisioned on. Every lane in this file is
// built on it, which is exactly the condition assertGoldenSubnet enforces.
const BAKED_BASE = '10.167.161';

/** The spec a whole section shares. Nothing in it is per-student — that is the point. */
function goldenSpec(overrides = {}) {
  return Object.assign({
    goad: {
      enabled: true,
      prebaked: true,
      fixed_subnet: { int: BAKED_BASE, ext: '10.39.161' },
    },
    vms: [
      { name: 'DC01',   role: 'dc',  os: 'windows' },
      { name: 'WEB-01', role: 'web', os: 'linux' },
    ],
    vuln_app_install: { mode: 'docker', target_vm: 'WEB-01' },
    reseed: {
      pivot: { sam: 'svc-webapp', domain: 'tuc.local' },
    },
  }, overrides);
}

/** What the deployer hands the hook: `name` is the SPEC name, proxmox_name carries the student suffix. */
function deployedVMs(suffix) {
  return [
    { vm_id: 610001, name: 'DC01',   proxmox_name: `dc01-${suffix}`,   type: 'qemu', node: 'n1' },
    { vm_id: 610002, name: 'WEB-01', proxmox_name: `web-01-${suffix}`, type: 'qemu', node: 'n1' },
    { vm_id: 610003, name: 'gw',     proxmox_name: `gw-${suffix}`,     type: 'lxc',  node: 'n1' },
  ];
}

/**
 * A DISK, not a stub that returns exit 0.
 *
 * The defect this file is now mostly about is a step that reports success
 * whether or not it did anything, so a fake guest that answers "exit 0, no
 * output" to every command would reproduce the bug rather than catch it. This
 * interprets the SMALL command vocabulary lane-reseed uses for file work —
 * read, staged write, chunked staged write, publish, discard — against a real
 * map of paths to bytes, so a test can look at what the guest ACTUALLY ends up
 * serving instead of at what the orchestrator meant to write.
 *
 * Everything else (host keys, machine-id, the seed heredoc, `docker restart`)
 * is a no-op that exits 0, which is what those commands are here.
 */
function runGuestShell(files, command, guestOpts = {}) {
  let stdout = '';
  for (const line of String(command).split('\n')) {
    const t = line.trim();
    if (!t || t === 'set -e' || t === 'umask 077' || t === 'exit 0') continue;
    let m;
    // read: `if [ -f 'P' ]; then base64 < 'P'; else printf %s '<sentinel>'; fi`
    if ((m = t.match(/^if \[ -f '(.+?)' \]; then base64 < '(.+?)'; else printf %s '(.+?)'; fi$/))) {
      stdout += files.has(m[1])
        ? Buffer.from(files.get(m[1]), 'utf8').toString('base64')
        : m[3];
      continue;
    }
    // single-chunk staged write
    if ((m = t.match(/^printf %s '([A-Za-z0-9+/=]*)' \| base64 -d > '(.+?)'$/))) {
      files.set(m[2], Buffer.from(m[1], 'base64').toString('utf8'));
      continue;
    }
    // chunked staged write: raw base64 accumulated, then decoded
    if ((m = t.match(/^printf %s '([A-Za-z0-9+/=]*)' (>>?) '(.+?)'$/))) {
      const prev = m[2] === '>>' && files.has(m[3]) ? files.get(m[3]) : '';
      files.set(m[3], prev + m[1]);
      continue;
    }
    if ((m = t.match(/^base64 -d < '(.+?)' > '(.+?)'$/))) {
      if (!files.has(m[1])) return { exitcode: 1, stdout: '', stderr: `${m[1]}: no such file` };
      files.set(m[2], Buffer.from(files.get(m[1]), 'base64').toString('utf8'));
      continue;
    }
    // publish: a redirect into the existing file, which is what keeps the
    // destination's owner and mode
    if ((m = t.match(/^cat '(.+?)' > '(.+?)'$/))) {
      if (!files.has(m[1])) return { exitcode: 1, stdout: '', stderr: `${m[1]}: no such file` };
      // dropCommit models the anti-pattern under test: the command exits 0 and
      // the file it was supposed to change is exactly as it was. Nothing but a
      // read-back can tell that apart from success.
      if (!(guestOpts.dropCommit || []).includes(m[2])) files.set(m[2], files.get(m[1]));
      continue;
    }
    if (t.startsWith('rm -f ')) {
      for (const q of (t.match(/'[^']*'/g) || [])) files.delete(q.slice(1, -1));
      continue;
    }
    if ((m = t.match(/^\[ -f '(.+?)' \] \|\| \{ /))) {
      if (!files.has(m[1])) return { exitcode: 1, stdout: '', stderr: 'staged rewrite missing' };
      continue;
    }
    // chmod / mkdir / docker / ssh-keygen / heredoc bodies: nothing this disk
    // models, and nothing that decides whether the credential landed.
  }
  return { exitcode: 0, stdout, stderr: '' };
}

/**
 * A cluster-free stand-in for the guest agent, the flag table and the lane row.
 *
 * Every command the module dispatches is captured verbatim, because the command
 * TEXT is the artifact under test: it is what would carry a cleartext secret,
 * and it is where the two halves of the credential can be compared. The web
 * box's FILES are modelled too (see runGuestShell), because "what the lane
 * serves afterwards" is the only honest test of a publisher rewrite.
 */
function harness(opts = {}) {
  const commands = [];
  const laneWrites = [];
  const flagRows = opts.flagRows || new Map();   // shareable across lanes on purpose
  const logs = [];
  const files = new Map(Object.entries(opts.files || {}));
  let pid = 0;
  let clock = 0;

  // How many rounds of waitForDcAgent fail before the DC answers. Infinity
  // means "this DC never comes up", the case that must not silently proceed.
  const dcReadyAfter = opts.dcReadyAfter == null ? 0 : opts.dcReadyAfter;
  let dcRounds = 0;

  const deps = {
    api: () => { throw new Error('proxmoxAPI must not be reached from a test'); },

    agentExecArgv: async (node, vmId, argv) => {
      const entry = { kind: 'win', node, vmId, argv, command: argv[argv.length - 1] };
      commands.push(entry);
      return { pid: ++pid, _entry: entry };
    },

    agentShellExec: async (node, vmId, command) => {
      const entry = { kind: 'sh', node, vmId, command };
      // Run it against the disk NOW, so the effect is ordered with the command
      // rather than with whenever the poll happens to be answered.
      entry.result = runGuestShell(files, command, { dropCommit: opts.dropCommit });
      commands.push(entry);
      return { pid: ++pid, _entry: entry };
    },

    pollExecStatus: async () => {
      const entry = commands[commands.length - 1];
      // The DC probe is `exit 0` on the DC. Fail it until dcReadyAfter rounds
      // have gone by, so the retry loop is exercised for real.
      if (entry && entry.kind === 'win' && entry.command === 'exit 0') {
        dcRounds++;
        if (dcRounds <= dcReadyAfter) {
          return { exited: true, exitcode: 1, stdout: '', stderr: 'guest-exec 596' };
        }
      }
      const forced = opts.failCommand && opts.failCommand(entry);
      if (forced) return { exited: true, exitcode: forced.exitcode || 1, stdout: '', stderr: forced.stderr || 'forced' };
      if (entry && entry.result) return Object.assign({ exited: true }, entry.result);
      return { exited: true, exitcode: 0, stdout: '', stderr: '' };
    },

    waitForGuestAgent: async () => true,
    waitForAgentExecReady: async () => true,

    // Mirrors flag-manager.ensureLaneFlags: CSPRNG on first call for a
    // (lane, vm, type), and the SAME value on every call after — that
    // idempotence is what lets the deployer plant the identical string later.
    ensureLaneFlags: async ({ laneId, userId, vms }) => {
      const out = [];
      for (const vm of vms) {
        for (const flagType of ['user', 'root']) {
          const key = `${laneId}:${vm.name}:${flagType}`;
          if (!flagRows.has(key)) flagRows.set(key, flagManager.generateFlagValue());
          out.push({
            vmName: vm.name, flagType, flagId: key,
            flagValue: flagRows.get(key), plantStatus: 'pending', userId,
          });
        }
      }
      return out;
    },

    cybercoreQuery: async (sql, params) => {
      laneWrites.push({ sql, params });
      return { rowCount: 1, rows: [] };
    },

    now: () => clock,
    sleep: async (ms) => { clock += ms; },
  };

  return {
    deps, commands, laneWrites, flagRows, logs, files,
    get dcRounds() { return dcRounds; },
    get clock() { return clock; },
  };
}

/** Run `fn` with console captured, so a log line carrying a secret is catchable. */
async function withCapturedConsole(fn) {
  const lines = [];
  const orig = { log: console.log, warn: console.warn, error: console.error };
  const grab = (...a) => lines.push(a.map(String).join(' '));
  console.log = grab; console.warn = grab; console.error = grab;
  try {
    const value = await fn();
    return { value, lines };
  } finally {
    Object.assign(console, orig);
  }
}

const shCommands  = (h) => h.commands.filter(c => c.kind === 'sh').map(c => c.command);
const winCommands = (h) => h.commands.filter(c => c.kind === 'win').map(c => c.command);
const allCommandText = (h) => h.commands.map(c => c.kind === 'win' ? c.argv.join(' ') : c.command);

function decodeOne(text, re) {
  const m = String(text).match(re);
  return m ? Buffer.from(m[1], 'base64').toString('utf8') : null;
}
const SH_B64 = /printf %s '([A-Za-z0-9+/=]+)' \| base64 -d/;
const PS_B64 = /FromBase64String\('([A-Za-z0-9+/=]+)'\)/;

/** The flag as it is actually written into the app on the web box. */
function flagFromCommands(h) {
  const cmd = shCommands(h).find(c => /base64 -d > '/.test(c));
  return cmd ? decodeOne(cmd, SH_B64) : null;
}
/**
 * The password THE LANE ACTUALLY SERVES at one path, parsed back out of the
 * bytes on the modelled disk with the same descriptor the reseed used.
 *
 * Read off the disk rather than out of the dispatched command on purpose: a
 * command that was sent and a file that changed are exactly the two things this
 * defect proved are not the same.
 */
function publishedValue(h, plant) {
  const text = h.files.get(plant.path);
  if (text === undefined) return null;
  return reseed.readPlantValue(plant, text);
}

/** What the web box ends up serving out of the app env file. */
function webPasswordFromCommands(h, envPath = reseed.DEFAULT_ENV_PATH) {
  return publishedValue(h, { op: 'dotenv', key: reseed.DEFAULT_ENV_KEY, path: envPath });
}
/** The password as it is actually sent to Set-ADAccountPassword on the DC. */
function adPasswordFromCommands(h) {
  const cmd = winCommands(h).find(c => /Set-ADAccountPassword/.test(c));
  return cmd ? decodeOne(cmd, PS_B64) : null;
}
/** The password as it is actually authenticated with. */
function verifyPasswordFromCommands(h) {
  const cmd = winCommands(h).find(c => /ValidateCredentials/.test(c));
  return cmd ? decodeOne(cmd, PS_B64) : null;
}

async function reseedOneLane(laneId, h, specOverrides) {
  return reseed.reseedLane({
    laneId,
    userId: 'user-1',
    spec: goldenSpec(specOverrides),
    deployedVMs: deployedVMs(laneId),
    goadSubnetBase: BAKED_BASE,
    deps: h.deps,
  });
}

// ════════════════════════════════════════════════════════════════════════════
// 1. THE HEADLINE — the defect this whole design exists to fix
// ════════════════════════════════════════════════════════════════════════════

test('two lanes from ONE bake get different flags AND different pivot credentials', async () => {
  // Same spec, same golden images, same everything the cache keys on. The ONLY
  // difference is the lane id. If these come out equal, every student in the
  // section holds every other student's answers.
  const shared = new Map();   // one flag store, as the real table is
  const a = harness({ flagRows: shared });
  const b = harness({ flagRows: shared });

  const recA = await reseedOneLane('lane-aaaa', a);
  const recB = await reseedOneLane('lane-bbbb', b);

  assert.strictEqual(recA.status, 'reseeded', JSON.stringify(recA));
  assert.strictEqual(recB.status, 'reseeded', JSON.stringify(recB));

  const flagA = flagFromCommands(a);
  const flagB = flagFromCommands(b);
  assert.ok(flagA && flagManager.FLAG_RE.test(flagA), `lane A flag looks wrong: ${flagA}`);
  assert.ok(flagB && flagManager.FLAG_RE.test(flagB), `lane B flag looks wrong: ${flagB}`);
  assert.notStrictEqual(flagA, flagB,
    'two lanes off one bake were written the SAME flag — this is the defect, not a variation');

  const pwA = adPasswordFromCommands(a);
  const pwB = adPasswordFromCommands(b);
  assert.ok(pwA && pwA.length >= reseed.PW_LENGTH, `lane A password looks wrong: ${pwA}`);
  assert.ok(pwB && pwB.length >= reseed.PW_LENGTH, `lane B password looks wrong: ${pwB}`);
  assert.notStrictEqual(pwA, pwB,
    'two lanes off one bake got the SAME pivot credential — the golden image is still the source of the secret');

  // And the fingerprints on the lane rows differ too, which is how an
  // instructor can tell the two lanes apart without either password existing.
  assert.notStrictEqual(recA.pivot_fingerprint, recB.pivot_fingerprint);
});

test('the flag comes from cybercore_lane_flag, not from a fourth flag mechanism', async () => {
  // Re-running the reseed must re-read the canonical value rather than mint a
  // new one, because challenge-lane-deployer plants the SAME row's value as
  // user.txt afterwards. A second value here desyncs disk from database.
  const shared = new Map();
  const first  = harness({ flagRows: shared });
  const second = harness({ flagRows: shared });

  await reseedOneLane('lane-same', first);
  await reseedOneLane('lane-same', second);

  assert.strictEqual(flagFromCommands(first), flagFromCommands(second),
    'a re-reseed minted a new flag — the guest and cybercore_lane_flag now disagree');
  assert.strictEqual(
    shared.get('lane-same:WEB-01:user'), flagFromCommands(first),
    'the value written into the app is not the web box\'s own user flag row');
});

// ════════════════════════════════════════════════════════════════════════════
// 2. BOTH SIDES OR NEITHER
// ════════════════════════════════════════════════════════════════════════════

test('the AD side and the web side carry the SAME value for one lane', async () => {
  const h = harness();
  const rec = await reseedOneLane('lane-pair', h);

  const web = webPasswordFromCommands(h);
  const ad  = adPasswordFromCommands(h);
  const ver = verifyPasswordFromCommands(h);

  assert.ok(web, 'nothing was staged on the web box');
  assert.ok(ad, 'Set-ADAccountPassword never ran');
  assert.strictEqual(web, ad,
    'the web box was given a credential AD does not honour — a dead end the student cannot diagnose');
  assert.strictEqual(ver, ad, 'the verification checked a different value than it set');

  assert.strictEqual(rec.steps.credential, 'ok');
  assert.strictEqual(rec.verified, true);
  assert.strictEqual(
    rec.pivot_fingerprint,
    crypto.createHash('sha256').update(ad, 'utf8').digest('hex').slice(0, 16),
    'the recorded fingerprint does not describe the value actually planted');
});

test('the web credential is STAGED before AD and only published after it', async () => {
  // The ordering is the mechanism, not decoration: nothing reads
  // `<path>.ccreseed`, so any failure before the publish leaves EVERY side on
  // the baked value.
  const h = harness({ files: { [reseed.DEFAULT_ENV_PATH]: `${reseed.DEFAULT_ENV_KEY}=baked-value\n` } });
  await reseedOneLane('lane-order', h);

  const seq = h.commands.map(c => c.command);
  const iStage  = seq.findIndex(t => /base64 -d > '[^']+\.ccreseed'/.test(t));
  const iAd     = seq.findIndex(t => /Set-ADAccountPassword/.test(t));
  const iCommit = seq.findIndex(t => /cat '[^']+\.ccreseed' > '/.test(t));

  assert.ok(iStage >= 0, 'the credential was never staged');
  assert.ok(iAd > iStage, 'AD was changed before the web side was even staged');
  assert.ok(iCommit > iAd, 'the web side was published before AD accepted the same value');
});

test('a DC that never answers leaves EVERY side on the baked value', async () => {
  // dcReadyAfter: Infinity — the agent is simply gone. Every staged rewrite
  // must be removed and Set-ADAccountPassword must never have run, so the app
  // and the directory still agree with each other (on the wrong-but-consistent
  // value) and the file on disk is untouched.
  const h = harness({
    dcReadyAfter: Infinity,
    files: { [reseed.DEFAULT_ENV_PATH]: `${reseed.DEFAULT_ENV_KEY}=baked-value\n` },
  });
  const rec = await reseedOneLane('lane-nodc', h);

  assert.strictEqual(winCommands(h).filter(c => /Set-ADAccountPassword/.test(c)).length, 0,
    'AD was changed even though the DC agent never came up');
  assert.ok(shCommands(h).some(c => /^rm -f '[^']+\.ccreseed'/.test(c)),
    'the staged rewrite was left on the web box, so the app now disagrees with AD');
  assert.ok(!shCommands(h).some(c => /cat '[^']+\.ccreseed' > '/.test(c)),
    'the staged rewrite was published without AD ever accepting it');
  assert.strictEqual(
    h.files.get(reseed.DEFAULT_ENV_PATH), `${reseed.DEFAULT_ENV_KEY}=baked-value\n`,
    'the file on the web box changed even though AD never accepted a new value');
  assert.strictEqual([...h.files.keys()].filter(k => k.endsWith('.ccreseed')).length, 0,
    'a staged copy of the new credential was left behind on the guest');
  assert.strictEqual(rec.steps.verify, 'skipped');
  assert.match(rec.steps.credential, /^failed:/);
});

// ════════════════════════════════════════════════════════════════════════════
// 3. THE FIXED-SUBNET ASSERTION
// ════════════════════════════════════════════════════════════════════════════

test('a pre-baked lane with no fixed_subnet is refused', () => {
  for (const fixed of [undefined, {}, { int: '' }, { int: '   ' }, { ext: '10.39.161' }]) {
    assert.throws(
      () => reseed.assertGoldenSubnet(
        { goad: { prebaked: true, fixed_subnet: fixed } },
        { goadSubnetBase: BAKED_BASE }),
      /fixed_subnet/,
      `fixed_subnet ${JSON.stringify(fixed)} must not pass`);
  }
});

test('a fixed_subnet that disagrees with the lane is refused too', () => {
  // The silent case: the field is present and looks answered, but the lane was
  // built somewhere else, so every baked DNS record, SPN and SYSVOL path names
  // an address nothing on the lane owns — while the lane reports active.
  assert.throws(
    () => reseed.assertGoldenSubnet(
      { goad: { prebaked: true, fixed_subnet: { int: BAKED_BASE } } },
      { goadSubnetBase: '10.40.7' }),
    (err) => /10\.167\.161/.test(err.message) && /10\.40\.7/.test(err.message),
    'a lane built off the baked base must be named in the refusal');

  assert.throws(
    () => reseed.assertGoldenSubnet(
      { goad: { prebaked: true, fixed_subnet: { int: BAKED_BASE } } },
      { goadSubnetBase: null }),
    /fixed_subnet|built on/);
});

test('the assertion is silent on a lane that has no golden AD images', () => {
  assert.strictEqual(reseed.assertGoldenSubnet(null, { goadSubnetBase: '10.40.7' }), null);
  assert.strictEqual(reseed.assertGoldenSubnet({}, { goadSubnetBase: '10.40.7' }), null);
  assert.strictEqual(
    reseed.assertGoldenSubnet({ goad: { enabled: true } }, { goadSubnetBase: '10.40.7' }), null,
    'a live-provisioned GOAD lane builds its own AD, so there is no baked base to honour');
  assert.deepStrictEqual(
    reseed.assertGoldenSubnet(goldenSpec(), { goadSubnetBase: BAKED_BASE }),
    { base: BAKED_BASE });
});

test('the refusal records on the lane instead of failing the lane', async () => {
  const h = harness();
  const rec = await reseed.reseedLane({
    laneId: 'lane-wrongsubnet',
    userId: 'user-1',
    spec: goldenSpec({ goad: { enabled: true, prebaked: true, fixed_subnet: { int: BAKED_BASE } } }),
    deployedVMs: deployedVMs('x'),
    goadSubnetBase: '10.40.7',
    deps: h.deps,
  });

  assert.strictEqual(rec.status, 'failed');
  assert.match(rec.error, /fixed_subnet|built on/);
  assert.strictEqual(h.commands.length, 0, 'a lane on the wrong subnet must not be touched at all');
});

// ════════════════════════════════════════════════════════════════════════════
// 4. THE SECURITY RULE — no staged file, no temp path, no secret in a log
// ════════════════════════════════════════════════════════════════════════════

test('no secret reaches a command, a temp path or a log', async () => {
  const h = harness();
  const { value: rec, lines } = await withCapturedConsole(() => reseedOneLane('lane-secret', h));

  const flag = flagFromCommands(h);
  const pw   = adPasswordFromCommands(h);
  assert.ok(flag && pw, 'the fixture did not actually plant anything to check');

  // Every secret crosses the wire base64-encoded, so the cleartext must appear
  // nowhere in any argv element of any dispatched command.
  for (const text of allCommandText(h)) {
    assert.ok(!text.includes(pw), `a cleartext password reached a guest command:\n${text}`);
    assert.ok(!text.includes(flag), `a cleartext flag reached a guest command:\n${text}`);
  }

  // ...nor in anything we printed. A log line is the other copy that outlives
  // the command.
  for (const line of lines) {
    assert.ok(!line.includes(pw), `a log line carried the password: ${line}`);
    assert.ok(!line.includes(flag), `a log line carried the flag: ${line}`);
  }

  // ...nor on the lane row. Lane config is served to the lane's owner
  // (workstation_user / workstation_pass), so a password there is the answer key.
  const written = JSON.stringify(h.laneWrites) + JSON.stringify(rec);
  assert.ok(!written.includes(pw), 'the pivot password was persisted to the lane row');
  assert.ok(!written.includes(flag), 'the flag value was persisted to the lane row');
});

test('nothing is written through a staged script or a world-traversable temp path', async () => {
  const h = harness();
  await reseedOneLane('lane-nostage', h);

  for (const text of allCommandText(h)) {
    assert.ok(!/C:\\Windows\\Temp/i.test(text), `a command touched C:\\Windows\\Temp:\n${text}`);
    assert.ok(!/(^|[\s'"])\/tmp\//.test(text), `a command touched /tmp:\n${text}`);
  }

  // The rule at src/utils/script-executor.js, held as source text: the staged
  // helpers tee a log into a directory Users can traverse and the Remove-Item
  // lives inside the stub, so a timeout leaves both behind.
  for (const banned of ['executePowerShellViaFile', 'executeShellViaFile', 'guestFileWrite', 'writeFileViaShellExec']) {
    assert.ok(!new RegExp(`\\b${banned}\\s*[,(]`).test(RESEED_SRC),
      `lane-reseed.js calls ${banned} — secrets must go through agentExecArgv/agentShellExec only`);
  }
  assert.ok(/require\(.*script-executor.*\)/.test(RESEED_SRC));
});

test('a raw secret handed to a command builder is refused, not quoted', async () => {
  // The mechanical form of the rule. If anything ever bypasses b64(), the
  // command is not sent at all rather than sent with a hand-rolled escape.
  assert.throws(() => reseed.psDecode("hunter2'; whoami #"), /base64/);
  assert.throws(() => reseed.buildFlagCommand({
    flagPath: '/opt/vuln-app/flag.txt', container: 'vuln-app', encodedFlag: 'not base64!',
  }), /base64/);
  assert.throws(
    () => reseed.assertNoCleartextSecret("echo 'S3cret'", ['S3cret']),
    /cleartext secret/);
  assert.strictEqual(
    reseed.assertNoCleartextSecret("echo 'UzNjcmV0'", ['S3cret']),
    "echo 'UzNjcmV0'");
});

test('a generated password is typeable and inert in both shells', () => {
  for (let i = 0; i < 200; i++) {
    const pw = reseed.generatePivotPassword();
    assert.strictEqual(pw.length, reseed.PW_LENGTH);
    // No quote of any kind: these land inside single-quoted PowerShell and
    // POSIX literals even before base64 encoding.
    assert.ok(!/['"`\\]/.test(pw), `password contains a quote: ${pw}`);
    // Windows complexity, or Set-ADAccountPassword rejects it on every lane.
    assert.ok(/[A-Z]/.test(pw) && /[a-z]/.test(pw) && /[0-9]/.test(pw) && /[^A-Za-z0-9]/.test(pw),
      `password misses a character class: ${pw}`);
    // Ambiguous glyphs: a student has to read this off a screen and type it.
    assert.ok(!/[0O1lI]/.test(pw), `password contains an ambiguous glyph: ${pw}`);
  }
});

test('an AD identity from spec JSON is validated, not trusted', () => {
  const encoded = reseed.b64('x');
  for (const sam of ["svc'; whoami; '", 'svc\nwhoami', 'a'.repeat(65), '']) {
    assert.throws(() => reseed.buildAdResetCommand({ sam, domain: 'tuc.local', encodedPassword: encoded }),
      /unsafe AD account/, `sAMAccountName ${JSON.stringify(sam)} must not pass`);
  }
  for (const domain of ["tuc.local'; whoami; '", 'tuc.local\nwhoami', '']) {
    assert.throws(() => reseed.buildVerifyCommand({ sam: 'svc-webapp', domain, encodedPassword: encoded }),
      /unsafe AD domain/, `domain ${JSON.stringify(domain)} must not pass`);
  }
});

// ════════════════════════════════════════════════════════════════════════════
// 5. THE DC GUEST AGENT IS A HARD DEPENDENCY
// ════════════════════════════════════════════════════════════════════════════

test('the DC guest agent wait RETRIES rather than warning once', async () => {
  // A prebaked lane has no controller, so this agent is the only way to change
  // the directory. A freshly-cloned Windows Server routinely spends minutes on
  // first-boot device enumeration before qemu-ga will run anything.
  const h = harness({ dcReadyAfter: 4 });
  const res = await reseed.waitForDcAgent({ deps: h.deps, node: 'n1', vmId: 610001 });

  assert.strictEqual(res.ok, true);
  assert.strictEqual(res.rounds, 5, 'the wait gave up (or never retried) instead of waiting out the boot');
  assert.ok(h.clock > 0, 'it retried without ever backing off');
});

test('ping answering is not treated as the agent being ready', async () => {
  // waitForGuestAgent returns true here on the first call; only the real exec
  // probe fails. A ping-only wait would report ready and the very next command
  // — Set-ADAccountPassword — would be the one that failed.
  const h = harness({ dcReadyAfter: 2 });
  const res = await reseed.waitForDcAgent({ deps: h.deps, node: 'n1', vmId: 610001 });
  assert.strictEqual(res.rounds, 3);
});

test('an agent that never comes up eventually fails, and says so', async () => {
  const h = harness({ dcReadyAfter: Infinity });
  const res = await reseed.waitForDcAgent({ deps: h.deps, node: 'n1', vmId: 610001 });

  assert.strictEqual(res.ok, false);
  assert.ok(res.rounds > 1, 'it warned once and gave up — the failure this test exists for');
  assert.match(res.error, /never became usable/);
  assert.ok(h.clock >= reseed.DC_AGENT_TIMEOUT_MS - 30000,
    'it abandoned the DC long before the timeout it advertises');
});

// ════════════════════════════════════════════════════════════════════════════
// 6. FAILURE IS RECORDED, NOT PROPAGATED
// ════════════════════════════════════════════════════════════════════════════

test('a reseed failure records on the lane without failing it', async () => {
  const h = harness({ dcReadyAfter: Infinity });
  const rec = await reseedOneLane('lane-failrec', h);   // must RESOLVE, not reject

  assert.strictEqual(rec.status, 'failed');
  assert.match(rec.error, /credential/);
  assert.match(rec.steps.dc_agent, /^failed:/);

  const write = h.laneWrites.find(w => /UPDATE cybercore_lane/.test(w.sql));
  assert.ok(write, 'the failure was never written to the lane row');
  assert.match(write.sql, /config = COALESCE\(config, '\{\}'::jsonb\) \|\| \$2::jsonb/,
    'the record REPLACED lane config instead of merging into it');
  const merged = JSON.parse(write.params[1]);
  assert.strictEqual(merged.reseed.status, 'failed');
  assert.strictEqual(merged.reseed.verified, false);

  // The independent steps still ran: SSH host keys, machine-id and the flag
  // have nothing to do with whether a DC booted.
  assert.strictEqual(rec.steps.host_identity, 'ok');
  assert.strictEqual(rec.steps.flag, 'ok');
  assert.strictEqual(rec.steps.seed_data, 'ok');
});

test('a credential that sets but does not authenticate is reported, not celebrated', async () => {
  // "Set-ADAccountPassword exited 0" is not evidence a student can log in — the
  // account can be disabled, locked, or flagged to change at next logon.
  const h = harness({
    failCommand: (e) => (e && e.kind === 'win' && /ValidateCredentials/.test(e.command))
      ? { exitcode: 3 } : null,
  });
  const rec = await reseedOneLane('lane-noauth', h);

  assert.strictEqual(rec.steps.credential, 'ok');
  assert.strictEqual(rec.verified, false);
  assert.match(rec.steps.verify, /^failed:/);
  assert.strictEqual(rec.status, 'failed');
});

test('a successful reseed records the verification on the lane row', async () => {
  const h = harness();
  const rec = await reseedOneLane('lane-verified', h);

  const write = h.laneWrites.find(w => /UPDATE cybercore_lane/.test(w.sql));
  const merged = JSON.parse(write.params[1]);
  assert.strictEqual(merged.reseed.verified, true);
  assert.ok(merged.reseed.verified_at, 'verified with no timestamp is not an audit trail');
  assert.strictEqual(merged.reseed.pivot_user, 'tuc.local\\svc-webapp');
  assert.strictEqual(merged.reseed.status, 'reseeded');
  assert.strictEqual(rec.steps.fixed_subnet, `ok (${BAKED_BASE})`);
});

// ════════════════════════════════════════════════════════════════════════════
// 7. PLAN RESOLUTION
// ════════════════════════════════════════════════════════════════════════════

test('the web box is matched on the SPEC name, never on proxmox_name', () => {
  // proxmox_name carries the student's suffix. Matching it finds nothing on
  // every lane simultaneously — the same trap vuln-app-install.js documents.
  const plan = reseed.resolveReseedPlan({
    spec: goldenSpec(),
    deployedVMs: deployedVMs('student7'),
  });
  assert.strictEqual(plan.web.name, 'WEB-01');
  assert.strictEqual(plan.dc.name, 'DC01');
  assert.strictEqual(plan.pivot.sam, 'svc-webapp');
  assert.strictEqual(plan.pivot.domain, 'tuc.local');
});

test('the gateway container is never a reseed target', () => {
  // The lane gateway is an LXC with no QEMU guest agent, and it is plumbing.
  const plan = reseed.resolveReseedPlan({
    spec: goldenSpec({ vms: [{ name: 'gw', role: 'web' }] }),
    deployedVMs: deployedVMs('s1'),
  });
  assert.notStrictEqual(plan.web && plan.web.name, 'gw');
});

test('an undeclared pivot account is SKIPPED, never guessed', async () => {
  // Resetting an account we invented a name for fails on every lane at once;
  // resetting the wrong real one breaks the forest.
  const h = harness();
  const rec = await reseed.reseedLane({
    laneId: 'lane-nopivot', userId: 'user-1',
    spec: goldenSpec({ reseed: {} }),
    deployedVMs: deployedVMs('s1'),
    goadSubnetBase: BAKED_BASE,
    deps: h.deps,
  });

  assert.strictEqual(rec.status, 'reseeded');
  assert.match(rec.steps.credential, /^skipped:/);
  assert.strictEqual(winCommands(h).length, 0, 'a DC was touched for a credential nobody declared');
  assert.strictEqual(rec.steps.flag, 'ok', 'the flag must still be reseeded without a pivot');
});

test('a declared pivot with no DC on the lane is a loud failure, not a skip', async () => {
  const h = harness();
  const rec = await reseed.reseedLane({
    laneId: 'lane-nodcvm', userId: 'user-1',
    spec: goldenSpec({ vms: [{ name: 'WEB-01', role: 'web' }] }),
    deployedVMs: [{ vm_id: 610002, name: 'WEB-01', type: 'qemu', node: 'n1' }],
    goadSubnetBase: BAKED_BASE,
    deps: h.deps,
  });
  assert.strictEqual(rec.status, 'failed');
  assert.match(rec.steps.credential, /no domain controller/);
});

test('a lane with no web box is skipped once, not reported as four failures', async () => {
  const h = harness();
  const rec = await reseed.reseedLane({
    laneId: 'lane-noweb', userId: 'user-1',
    spec: goldenSpec({ vms: [{ name: 'DC01', role: 'dc' }], vuln_app_install: null }),
    deployedVMs: [{ vm_id: 610001, name: 'DC01', type: 'qemu', node: 'n1' }],
    goadSubnetBase: BAKED_BASE,
    deps: h.deps,
  });
  assert.strictEqual(rec.status, 'skipped');
  assert.strictEqual(h.commands.length, 0);
});

test('lane-unique record ids are wide enough that two students never collide', () => {
  const seen = new Set();
  for (let i = 0; i < 500; i++) {
    const s = reseed.generateSeedValues();
    assert.ok(s.order_number_base >= 1000000 && s.order_number_base < 10000000);
    assert.ok(s.patient_id_base >= 100000 && s.patient_id_base < 1000000);
    seen.add(`${s.order_number_base}:${s.patient_id_base}:${s.lane_token}`);
  }
  assert.strictEqual(seen.size, 500, 'the seed generator repeats itself');
});

test('the seed file body cannot be expanded by the shell', () => {
  // A quoted heredoc delimiter is what makes the body data rather than script.
  const cmd = reseed.buildSeedCommand({
    seedPath: '/opt/vuln-app/.lane-seed',
    seed: reseed.generateSeedValues(),
    seedCommand: null,
  });
  assert.match(cmd, /<<'CIAB_LANE_SEED'/);
});

// ════════════════════════════════════════════════════════════════════════════
// 8. THE HOOK — reseed rides the deployer's postDeploy contract
// ════════════════════════════════════════════════════════════════════════════

test('the reseed runs AFTER the vuln-app install, and still runs when it fails', async () => {
  // Order: the reseed writes the flag and the credential INTO the app's
  // directory, so reseeding first would have the installer overwrite them. And
  // a failed Docker pull has nothing to do with whether the AD credential is
  // still the baked one, so it must not skip the reseed.
  const order = [];
  const reseedHook = async () => { order.push('reseed'); };

  // makeProfilePostDeploy composes makeVulnAppPostDeploy internally. An install
  // whose target_vm is not on the lane is the one failure that is reachable
  // without a cluster, and it fails in the same place a Docker pull would: the
  // hook, before the reseed.
  const hook = laneProvision.makeProfilePostDeploy({
    vulnAppInstall: { target_vm: 'not-on-this-lane', mode: 'docker' },
    reseedHook,
  });

  await assert.rejects(
    () => hook({ laneId: 'l1', user: { id: 'u1' }, spec: {}, deployedVMs: [{ name: 'WEB-01' }] }),
    /not among this lane's machines/,
    'the vuln-app failure must still reach config.post_deploy_error');
  assert.deepStrictEqual(order, ['reseed'],
    'the reseed was skipped because the vuln-app install failed');

  // Held as source text, because the ordering when BOTH succeed cannot be
  // observed without a cluster and reversing it is silent: the installer would
  // lay the app down on top of the flag, the credential and the seeded ids.
  const provisionSrc = fs.readFileSync(path.join(CIAB_UTILS, 'lane-provision.js'), 'utf8');
  const body = provisionSrc.slice(provisionSrc.indexOf('function makeProfilePostDeploy'));
  assert.ok(body.indexOf('await vulnHook(') < body.indexOf('await reseedHook('),
    'the reseed runs before the vuln-app install, so the install overwrites everything it wrote');

  // With no vuln app at all the reseed still runs on its own.
  order.length = 0;
  const ok = laneProvision.makeProfilePostDeploy({ vulnAppInstall: null, reseedHook });
  await ok({ laneId: 'l2', user: { id: 'u1' }, spec: {}, deployedVMs: [] });
  assert.deepStrictEqual(order, ['reseed']);
});

test('no vuln app and no reseed means no hook at all', () => {
  assert.strictEqual(
    laneProvision.makeProfilePostDeploy({ vulnAppInstall: null, reseedHook: null }), null,
    'an empty hook would make the deployer run a post_deploy phase for nothing');
});

test('the hook never throws on a reseed failure', async () => {
  const h = harness({ dcReadyAfter: Infinity });
  const { hook, records } = reseed.makeReseedPostDeploy({ deps: h.deps });

  await hook({
    laneId: 'lane-hook', user: { id: 'user-1' },
    spec: goldenSpec(), deployedVMs: deployedVMs('s1'),
    goadSubnetBase: BAKED_BASE,
  });

  assert.strictEqual(records.size, 1);
  assert.strictEqual(records.get('lane-hook').status, 'failed');
});

test('records are re-applied after the deploy, because the deployer rewrites config whole', async () => {
  // challenge-lane-deployer's final step writes `config = $2::jsonb` built from
  // the batch-wide laneConfig, and postDeploy runs BEFORE it. Without this pass
  // every reseed record — including the verification result — is silently gone
  // by the time the deploy returns.
  const seen = [];
  const original = reseed.recordReseedOnLane;
  reseed.recordReseedOnLane = async (laneId, record) => { seen.push([laneId, record]); return record; };
  try {
    await laneProvision.applyReseedRecords(new Map([
      ['lane-a', { status: 'reseeded' }],
      ['lane-b', { status: 'failed' }],
    ]));
  } finally {
    reseed.recordReseedOnLane = original;
  }
  assert.deepStrictEqual(seen.map(([id]) => id), ['lane-a', 'lane-b']);
});

test('a lane whose record cannot be written still deploys', async () => {
  const original = reseed.recordReseedOnLane;
  reseed.recordReseedOnLane = async () => { throw new Error('cybercore_db unreachable'); };
  try {
    await laneProvision.applyReseedRecords(new Map([['lane-a', { status: 'reseeded' }]]));
  } finally {
    reseed.recordReseedOnLane = original;
  }
  // Reaching here without a throw IS the assertion: losing a mirror record must
  // not fail a lane that actually deployed.
  assert.ok(true);
});

// ════════════════════════════════════════════════════════════════════════════
// 10. THE PUBLISHER — what the WEBSITE serves after the reseed
// ────────────────────────────────────────────────────────────────────────────
// The defect these are about: the reseed rotated the account in Active
// Directory, wrote AD_SERVICE_PASSWORD into an env file it created itself with
// `mkdir -p` (so the step could not fail), and left the company website
// publishing the BAKED password out of its own config file and off
// /admin/integrations. plan.warnings was empty. The lane was green. The pivot
// the entire engagement is built around did not work, and nothing said so.
// ════════════════════════════════════════════════════════════════════════════

test('the rendered pivot config in these tests is the one roles/cc_web really writes', () => {
  // Pins renderPivotConfig against the template. Every one of these is the
  // jinja source of a line the port emits, so a change to the role's layout
  // fails HERE rather than on a lane ninety minutes into a bake.
  const mustContain = [
    'AD_PASSWORD={{ _pass }}',
    "'ad_password' => '{{ _pass",
    "'password': _pass",
    'password = {{ _pass }}',
    '<password>{{ _pass',
    '[directory]',
    '<directory>',
  ];
  for (const needle of mustContain) {
    assert.ok(CC_WEB_PIVOT_J2.indexOf(needle) !== -1,
      `roles/cc_web/templates/pivot-credential.j2 no longer contains ${JSON.stringify(needle)}, so `
      + 'the bytes these tests rewrite are not the bytes a lane really carries');
  }
  // And the format list the site may pick from is the list this port renders.
  for (const entry of labContent.SITE_CONFIG_FILES) {
    const rendered = renderPivotConfig({
      format: entry.format, domain: 'CLINIC', username: 'svc.web', password: 'PlaceHolder-9',
      extra: { ldap_host: 'dc01.clinic.local' },
    });
    assert.ok(rendered.indexOf('PlaceHolder-9') !== -1,
      `the ${entry.format} branch of the port does not plant the password at all`);
  }
});

test('both ends of the seam implement the SAME rewrite vocabulary', () => {
  // goad-lab-content emits an operation name; lane-reseed implements it. An
  // operation only one end knows about is a publisher that is silently skipped,
  // which is this defect with a new coat of paint.
  assert.deepStrictEqual(
    reseed.PLANT_OPS.slice().sort(), labContent.SITE_RESEED_OPS.slice().sort(),
    'lane-reseed and goad-lab-content disagree about which rewrites exist');
});

test('EXIT: two lanes from one bake SERVE different credentials, and each page agrees with its own AD password', async () => {
  // THE HEADLINE OF THIS FIX, and the thing the old code got wrong. Not "two
  // lanes dispatched different Set-ADAccountPassword commands" — that already
  // passed while the exercise was broken. What is asserted is the bytes the web
  // box ends up serving, parsed back out with the descriptor, on both lanes.
  const runId = 'RUN_SITE_A_5';
  const { site, files, baked } = bakedSite(runId);
  const overrides = { reseed: bakedSpec(runId).reseed };

  const shared = new Map();
  const a = harness({ flagRows: shared, files: Object.assign({}, files) });
  const b = harness({ flagRows: shared, files: Object.assign({}, files) });

  const recA = await reseedOneLane('lane-web-a', a, overrides);
  const recB = await reseedOneLane('lane-web-b', b, overrides);

  assert.strictEqual(recA.steps.credential, 'ok', JSON.stringify(recA));
  assert.strictEqual(recB.steps.credential, 'ok', JSON.stringify(recB));

  const adA = adPasswordFromCommands(a);
  const adB = adPasswordFromCommands(b);
  assert.notStrictEqual(adA, adB, 'the two lanes were given the same AD password');

  // Every publisher the bake declared, on both lanes.
  assert.ok(site.reseed.plants.length >= 2,
    'this client publishes the credential in fewer places than the fixture assumes');
  for (const plant of site.reseed.plants) {
    const servedA = publishedValue(a, plant);
    const servedB = publishedValue(b, plant);
    assert.strictEqual(servedA, adA,
      `lane A serves ${JSON.stringify(servedA)} at ${plant.path} and Active Directory honours `
      + 'something else — the student reads the page, types the password, and is told it is wrong');
    assert.strictEqual(servedB, adB, `lane B's ${plant.path} disagrees with its own AD password`);
    assert.notStrictEqual(servedA, servedB,
      `both lanes serve the SAME credential at ${plant.path} — one student pastes it into the group `
      + 'chat and the cohort is finished');
    assert.notStrictEqual(servedA, baked,
      `${plant.path} still serves the BAKED password after a reseed that reported success`);
  }

  // And the lane row says which publishers were rewritten, without the value.
  assert.strictEqual(recA.steps.publish_verify,
    `ok (${site.reseed.plants.length + 1} publisher(s) read back)`);
  assert.ok(recA.site_publishers >= 2, 'the record does not say the website was rewritten');
  const written = JSON.stringify(recA) + JSON.stringify(a.laneWrites);
  assert.ok(!written.includes(adA), 'the rotated password was persisted to the lane row');
});

test('every plant format is rewritten in its OWN grammar, and nothing else in the file moves', () => {
  // Rewriting an ini, a PHP array, a JSON document and an XML element are four
  // different operations. A regex that happens to work on one corrupts another
  // into a file the app cannot load, which the student meets as a broken site
  // rather than as a finding.
  const NEW = 'Rot4ted-P@ss-word';
  for (const format of Object.keys(labContent.SITE_PIVOT_FIELD)) {
    const field = labContent.SITE_PIVOT_FIELD[format];
    const before = renderPivotConfig({
      format,
      domain: 'RIDGELINE',
      username: 'svc.web',
      password: 'bak3d-Value!',
      extra: { ldap_host: 'dc01.ridgeline.local', app_name: 'Portal' },
    });
    const plant = Object.assign({ path: `/var/www/cc-web/x.${format}` }, field);

    assert.strictEqual(reseed.readPlantValue(plant, before), 'bak3d-Value!',
      `the ${format} reader cannot find the value the role really wrote`);

    const after = reseed.writePlantValue(plant, before, NEW);
    assert.ok(after !== null, `the ${format} writer refused a file the role really writes`);
    assert.strictEqual(reseed.readPlantValue(plant, after), NEW,
      `the ${format} rewrite did not take`);
    assert.ok(after.indexOf('bak3d-Value!') === -1,
      `the ${format} file still contains the baked password after the rewrite`);

    if (format === 'json') {
      // Structural comparison: everything but the one key is identical, and it
      // is still loadable JSON — a half-substituted JSON file is not.
      const b = JSON.parse(before);
      const a = JSON.parse(after);
      b.ad.password = NEW;
      assert.deepStrictEqual(a, b, 'the json rewrite changed something other than the password');
    } else {
      const bl = before.split('\n');
      const al = after.split('\n');
      assert.strictEqual(al.length, bl.length, `the ${format} rewrite changed the line count`);
      const moved = bl.map((l, i) => (l === al[i] ? null : i)).filter((i) => i !== null);
      assert.strictEqual(moved.length, 1,
        `the ${format} rewrite touched ${moved.length} lines: `
        + moved.map((i) => `${JSON.stringify(bl[i])} -> ${JSON.stringify(al[i])}`).join(' | '));
    }

    // Every OTHER format's descriptor must find nothing here. That is what
    // makes "the reseed used the right grammar" checkable rather than assumed.
    for (const otherFormat of Object.keys(labContent.SITE_PIVOT_FIELD)) {
      if (otherFormat === format) continue;
      const wrong = Object.assign({ path: '/x' }, labContent.SITE_PIVOT_FIELD[otherFormat]);
      assert.notStrictEqual(reseed.readPlantValue(wrong, after), NEW,
        `the ${otherFormat} descriptor also matched a ${format} file, so the two are not really `
        + 'different operations');
    }
  }
});

test('an ini rewrite stays inside the section the descriptor names', () => {
  // `password = ...` is not unique in an ini. The role writes a [directory]
  // section AND an [application] one, and a rewrite that took the first match
  // would silently depend on which came first today.
  const before = [
    '; Application configuration. Generated during provisioning.',
    '[directory]',
    'domain = RIDGELINE',
    'password = bak3d-Value!',
    '',
    '[application]',
    'password = a-different-thing',
    '',
  ].join('\n');
  const plant = {
    path: '/var/www/cc-web/config/settings.ini', op: 'ini', section: 'directory', key: 'password',
  };

  assert.strictEqual(reseed.readPlantValue(plant, before), 'bak3d-Value!');
  const after = reseed.writePlantValue(plant, before, 'NEW-value-1');
  assert.ok(after.indexOf('password = a-different-thing') !== -1,
    'the rewrite reached into [application] and changed a value it was not asked about');
  assert.strictEqual(reseed.readPlantValue(plant, after), 'NEW-value-1');

  // …and a section that is not there is a refusal, not a first match.
  const elsewhere = Object.assign({}, plant, { section: 'nowhere' });
  assert.strictEqual(reseed.readPlantValue(elsewhere, before), null);
  assert.strictEqual(reseed.writePlantValue(elsewhere, before, 'x'), null);
});

test('an escaped value round-trips through the rewrite in every escaping the site uses', () => {
  // The settings page HTML-escapes the value and the XML config escapes &, <
  // and >. A rewrite that did not escape the same way would publish a page
  // rendering a different string than the one AD honours — which looks correct
  // in a diff and fails for the student.
  const anchor = labContent.SITE_ADMIN_PASSWORD_ANCHOR;
  const page = `<table><tr>${anchor}A&amp;B&lt;C&quot;"></td></tr></table>`;
  const plant = {
    path: '/p', op: 'slot', anchor, prefix: '', suffix: '', terminator: '"', escape: 'html',
  };
  assert.strictEqual(reseed.readPlantValue(plant, page), 'A&B<C"');

  for (const value of ['plain', 'has&amp', 'has<angle>', 'has"quote', "has'apostrophe"]) {
    const after = reseed.writePlantValue(plant, page, value);
    assert.strictEqual(reseed.readPlantValue(plant, after), value,
      `the html slot did not round-trip ${JSON.stringify(value)}`);
  }
  const xp = { path: '/x', op: 'xml', element: 'password' };
  for (const value of ['plain', 'a&b', 'a<b>c']) {
    const xml = renderPivotConfig({ format: 'xml', domain: 'D', username: 'u', password: 'seed' });
    const after = reseed.writePlantValue(xp, xml, value);
    assert.strictEqual(reseed.readPlantValue(xp, after), value,
      `the xml element did not round-trip ${JSON.stringify(value)}`);
  }
  // A php value with an apostrophe has to come back out of its own escaping,
  // or the file is a parse error the student reads as a broken site.
  const pp = { path: '/x', op: 'php', key: 'ad_password' };
  const php = renderPivotConfig({ format: 'php', domain: 'D', username: 'u', password: 'seed' });
  for (const value of ["it's", 'back\\slash', 'plain']) {
    const after = reseed.writePlantValue(pp, php, value);
    assert.strictEqual(reseed.readPlantValue(pp, after), value,
      `the php array did not round-trip ${JSON.stringify(value)}`);
  }
});

test('a MISSING plant is a recorded failure and Active Directory is never touched', async () => {
  // "The reseed cannot rewrite what it cannot find." Rotating the account with
  // a publisher missing would leave whatever DOES serve the credential spelling
  // the baked value — the defect, arrived at from the other side.
  const runId = 'RUN_SITE_A_5';
  const { site, files } = bakedSite(runId);
  const missing = site.reseed.plants[0].path;
  const partial = Object.assign({}, files);
  delete partial[missing];

  const h = harness({ files: partial });
  const rec = await reseedOneLane('lane-missing-plant', h, { reseed: bakedSpec(runId).reseed });

  assert.match(rec.steps.credential, /^failed:/,
    'a publisher that is not on the lane was reported as a successful reseed');
  assert.ok(rec.error.indexOf(missing) !== -1,
    `the failure does not name the path that was missing: ${rec.error}`);
  assert.strictEqual(winCommands(h).filter((c) => /Set-ADAccountPassword/.test(c)).length, 0,
    'the account was rotated even though the website could not be updated — every lane would then '
    + 'publish a password AD no longer honours');
  assert.strictEqual(
    [...h.files.keys()].filter((k) => k.endsWith(reseed.PLANT_STAGE_SUFFIX)).length, 0,
    'a staged rewrite was left behind after the phase aborted');
  assert.strictEqual(rec.status, 'failed');
});

test('a plant that MOVED — the page still there, the value somewhere else — fails just as loudly', async () => {
  const runId = 'RUN_SITE_A_5';
  const { site, files } = bakedSite(runId);
  const pagePlant = site.reseed.plants.filter((p) => p.op === 'slot')[0];
  assert.ok(pagePlant, 'this client publishes the credential on no page at all');

  // Somebody edited the template: the row is still there, the input is not.
  const edited = Object.assign({}, files);
  edited[pagePlant.path] = files[pagePlant.path]
    .replace(labContent.SITE_ADMIN_PASSWORD_ANCHOR, '<th>Bind password</th><td><code>');

  const h = harness({ files: edited });
  const rec = await reseedOneLane('lane-moved-plant', h, { reseed: bakedSpec(runId).reseed });

  assert.match(rec.steps.credential, /^failed:/, 'a moved plant reported success');
  assert.ok(rec.error.indexOf(pagePlant.path) !== -1, rec.error);
  assert.strictEqual(winCommands(h).filter((c) => /Set-ADAccountPassword/.test(c)).length, 0,
    'AD was rotated while the page that publishes the credential was left alone');
  // The page is untouched: no half-rewrite, no corruption.
  assert.strictEqual(h.files.get(pagePlant.path), edited[pagePlant.path]);
});

test('the read-back catches a publish that reported success and did nothing', async () => {
  // (d) of the fix: verify after writing. dropCommit makes the publish exit 0
  // and change nothing, which is exactly what a bind mount pointing elsewhere,
  // an immutable file or a role re-templating the config a moment later looks
  // like from here. Without the read-back this lane is green.
  const runId = 'RUN_SITE_A_5';
  const { site, files } = bakedSite(runId);
  const target = site.reseed.plants[0].path;

  const h = harness({ files: Object.assign({}, files), dropCommit: [target] });
  const rec = await reseedOneLane('lane-noland', h, { reseed: bakedSpec(runId).reseed });

  assert.match(rec.steps.credential, /^failed:/,
    'a publish that changed nothing was reported as a successful reseed');
  assert.ok(rec.error.indexOf(target) !== -1, rec.error);
  assert.ok(/DIFFERENT credential/.test(rec.error),
    `the failure does not say the lane is still publishing the old value: ${rec.error}`);
  assert.strictEqual(rec.verified, false);
});

test('a spec that names an account but NO site plants says so, loudly, on the lane row', async () => {
  // The producer half of this seam lives in the bake. Until it emits the
  // descriptor, every lane publishes the baked password — which is exactly what
  // used to happen in silence. It still rotates (the rest of the reseed is
  // useful), but the lane row now carries the sentence an instructor needs.
  const h = harness({ files: { [reseed.DEFAULT_ENV_PATH]: `${reseed.DEFAULT_ENV_KEY}=baked\n` } });
  const rec = await reseedOneLane('lane-nosite', h);

  const warned = rec.warnings.filter((w) => /declares NO site plants/.test(w));
  assert.strictEqual(warned.length, 1,
    `a lane whose website will keep serving the baked password recorded ${rec.warnings.length} `
    + `warning(s) and none of them said so: ${JSON.stringify(rec.warnings)}`);
  assert.ok(/site\.plants/.test(warned[0]) && /generateSiteContent/.test(warned[0]),
    'the warning does not name the field or the producer that emits it');

  // And it is on the lane row, not just in the returned object.
  const write = h.laneWrites.find((w) => /UPDATE cybercore_lane/.test(w.sql));
  assert.ok(JSON.parse(write.params[1]).reseed.warnings.some((w) => /NO site plants/.test(w)));
});

test('an unrotatable publisher the bake declared is reported, never dropped', async () => {
  // The description-mirror entry publishes the same string as an AD attribute,
  // which no file rewrite can reach. Saying nothing about it would be the same
  // silent success one layer down.
  const runId = 'RUN_SITE_A_0';
  const { site, files } = bakedSite(runId);
  assert.ok(site.reseed.unrotatable.length > 0,
    'this run id no longer designs a description-mirror entry; re-pin it');

  const h = harness({ files: Object.assign({}, files) });
  const rec = await reseedOneLane('lane-mirror', h, { reseed: bakedSpec(runId).reseed });

  assert.strictEqual(rec.steps.credential, 'ok', JSON.stringify(rec));
  for (const entry of site.reseed.unrotatable) {
    assert.ok(rec.warnings.some((w) => w.indexOf(entry.where) !== -1),
      `nothing recorded that ${entry.where} still publishes the old value`);
  }
  // The page half of the mirror IS rewritable, and was rewritten.
  const dirPlant = site.reseed.plants.filter((p) => /staff-directory/.test(p.path))[0];
  assert.ok(dirPlant, 'the mirrored directory page is not in the plant list');
  assert.strictEqual(publishedValue(h, dirPlant), adPasswordFromCommands(h),
    'the mirrored staff directory still prints the baked password');
});

test('a descriptor that does not validate is a warning naming the field, not a silent skip', () => {
  const plan = reseed.resolveReseedPlan({
    spec: {
      goad: { enabled: true },
      vms: [{ name: 'WEB-01', role: 'web' }, { name: 'DC01', role: 'dc' }],
      reseed: {
        pivot: {
          sam: 'svc-webapp',
          domain: 'tuc.local',
          site: {
            plants: [
              { kind: 'app_config', path: '../../etc/shadow', op: 'ini', section: 'd', key: 'password' },
              { kind: 'app_config', path: '/var/www/x.ini', op: 'sed', key: 'password' },
              { kind: 'app_config', path: '/var/www/y.ini', op: 'ini', key: 'password' },
              { kind: 'published_page', path: '/var/www/z.html', op: 'slot', terminator: '"' },
              { kind: 'app_config', path: '/var/www/ok.ini', op: 'ini', section: 'directory', key: 'password' },
            ],
          },
        },
      },
    },
    deployedVMs: [
      { vm_id: 1, name: 'WEB-01', type: 'qemu', node: 'n1' },
      { vm_id: 2, name: 'DC01', type: 'qemu', node: 'n1' },
    ],
  });

  assert.strictEqual(plan.pivot.sitePlants.length, 1, 'a malformed descriptor was accepted');
  assert.strictEqual(plan.pivot.sitePlants[0].path, '/var/www/ok.ini');
  const text = plan.warnings.join('\n');
  for (const needle of ['plants[0]', 'plants[1]', 'plants[2]', 'plants[3]']) {
    assert.ok(text.indexOf(needle) !== -1, `nothing warned about ${needle}:\n${text}`);
  }
  assert.ok(!/plants\[4\]/.test(text), 'the usable descriptor was warned about too');
  // Every warning has to say what it costs, or it reads as noise.
  assert.strictEqual(plan.warnings.filter((w) => /keep serving the baked password/.test(w)).length, 4);
});

test('no secret reaches an argv, a staged temp path or a log, including the file rewrites', async () => {
  // The rewrite ships whole files through the guest agent, and those files
  // CONTAIN the password. Everything crosses base64-encoded for the same reason
  // the password itself does, and the staging file sits beside its target at
  // 0600 rather than anywhere world-traversable.
  const runId = 'RUN_SITE_A_5';
  const { site, files } = bakedSite(runId);
  const h = harness({ files: Object.assign({}, files) });
  const { value: rec, lines } = await withCapturedConsole(
    () => reseedOneLane('lane-web-secret', h, { reseed: bakedSpec(runId).reseed }));

  const pw = adPasswordFromCommands(h);
  assert.ok(pw, 'the fixture did not rotate anything');
  assert.strictEqual(rec.steps.credential, 'ok');

  for (const text of allCommandText(h)) {
    assert.ok(!text.includes(pw), `a cleartext password reached a guest command:\n${text.slice(0, 400)}`);
    assert.ok(!/C:\\Windows\\Temp/i.test(text), 'a command touched C:\\Windows\\Temp');
    assert.ok(!/(^|[\s'"])\/tmp\//.test(text), `a command staged into /tmp:\n${text.slice(0, 200)}`);
    assert.ok(!/(^|[\s'"])\/var\/tmp\//.test(text), 'a command staged into /var/tmp');
  }
  for (const line of lines) assert.ok(!line.includes(pw), `a log line carried the password: ${line}`);

  // Every staged path is the target's own path plus the suffix, so nothing is
  // written into a directory other users can traverse.
  const declared = [reseed.DEFAULT_ENV_PATH].concat(site.reseed.plants.map((p) => p.path));
  for (const text of shCommands(h)) {
    for (const q of text.match(/'[^']*\.ccreseed[^']*'/g) || []) {
      const staged = q.slice(1, -1);
      const base = staged.replace(/\.ccreseed(\.b64)?$/, '');
      assert.ok(declared.indexOf(base) !== -1,
        `a rewrite was staged at ${staged}, which is not beside any declared publisher`);
    }
  }
  // …and none of them survives the run.
  assert.strictEqual([...h.files.keys()].filter((k) => k.indexOf('.ccreseed') !== -1).length, 0,
    'a staged copy of the credential was left on the guest');
});

test('a file bigger than one guest command is chunked and reassembled, not truncated', () => {
  // The pages are a few kilobytes today and the chunk is 32KB, so this path is
  // not normally taken — which is exactly why it is asserted rather than
  // assumed. A silently truncated page is a config file the app cannot parse.
  const content = `x${'y'.repeat(200)}z`;
  const encoded = reseed.b64(content);
  const cmds = reseed.buildStagePlantCommands({
    path: '/var/www/cc-web/config/big.ini', encodedContent: encoded, chunkSize: 40,
  });
  assert.ok(cmds.length > 2, 'the payload was not chunked at all');

  const files = new Map();
  for (const c of cmds) assert.strictEqual(runGuestShell(files, c).exitcode, 0);
  assert.strictEqual(files.get(`/var/www/cc-web/config/big.ini${reseed.PLANT_STAGE_SUFFIX}`), content);
  assert.ok(!files.has(`/var/www/cc-web/config/big.ini${reseed.PLANT_STAGE_SUFFIX}.b64`),
    'the base64 spool was left behind beside the target');

  // One chunk is still one command, and still lands.
  const single = reseed.buildStagePlantCommands({
    path: '/var/www/cc-web/config/small.ini', encodedContent: reseed.b64('hello'),
  });
  assert.strictEqual(single.length, 1);
  const one = new Map();
  runGuestShell(one, single[0]);
  assert.strictEqual(one.get(`/var/www/cc-web/config/small.ini${reseed.PLANT_STAGE_SUFFIX}`), 'hello');
});

test('the publish is a redirect into the existing file, never a rename', () => {
  // cc_web installs the pivot config 0640 root:www-data. A `mv` from the 0600
  // root:root staging file would leave apache unable to read its own config —
  // a correctly rewritten credential nothing can serve.
  const cmd = reseed.buildCommitPlantCommand({ path: '/var/www/cc-web/config/settings.ini' });
  assert.ok(cmd.indexOf(
    "cat '/var/www/cc-web/config/settings.ini.ccreseed' > '/var/www/cc-web/config/settings.ini'"
  ) !== -1, cmd);
  assert.ok(!/\bmv\b/.test(cmd), 'the publish renames the staging file over the target');
  assert.ok(/\[ -f '[^']+\.ccreseed' \] \|\|/.test(cmd),
    'the publish does not check that anything was staged');

  // A path this module would have to quote is refused rather than escaped.
  const hostile = ["/var/www/x'; rm -rf /", 'relative/path', '/var/www/$(id)'];
  for (const bad of hostile) {
    assert.throws(() => reseed.buildCommitPlantCommand({ path: bad }), /unsafe plant path/);
    assert.throws(() => reseed.buildReadPlantCommand({ path: bad }), /unsafe plant path/);
    assert.throws(() => reseed.buildDiscardPlantCommand({ path: bad }), /unsafe plant path/);
  }
});

test('the app env file is the ONLY target this reseed is allowed to create', async () => {
  // It is the file this module owns outright. Creating a SITE plant instead
  // would be the mkdir -p anti-pattern moved one directory over: a new file
  // nothing reads, and a step that reports success either way.
  const h = harness();                     // an empty disk
  const rec = await reseedOneLane('lane-create-env', h);

  assert.strictEqual(rec.steps.credential, 'ok');
  assert.strictEqual(webPasswordFromCommands(h), adPasswordFromCommands(h));
  assert.ok(rec.warnings.some((w) => /did not exist and was created/.test(w)),
    'a lane whose app env file was not there recorded nothing about it');

  // The same lane with a site plant declared for a path that is not there gets
  // the opposite treatment.
  const h2 = harness();
  const rec2 = await reseedOneLane('lane-create-site', h2, {
    reseed: {
      pivot: {
        sam: 'svc-webapp',
        domain: 'tuc.local',
        site: {
          plants: [{
            kind: 'app_config',
            path: '/var/www/cc-web/config/settings.ini',
            op: 'ini',
            section: 'directory',
            key: 'password',
          }],
        },
      },
    },
  });
  assert.match(rec2.steps.credential, /^failed:/);
  assert.ok(!h2.files.has('/var/www/cc-web/config/settings.ini'),
    'the reseed invented a site config file nothing on the lane reads');
});

test('a publish that fails AFTER the directory was rotated says so in words', async () => {
  // The one outcome a rollback cannot reach. Set-ADAccountPassword -Reset needs
  // no old value and this run never knew the baked one, so there is nothing to
  // put back: the lane is genuinely in a disagreeing state and the record has
  // to say that rather than leave an instructor to infer it from a step name.
  const runId = 'RUN_SITE_A_5';
  const { site, files } = bakedSite(runId);
  const h = harness({
    files: Object.assign({}, files),
    failCommand: (e) => (e && e.kind === 'sh' && /^cat '[^']+\.ccreseed' > '/m.test(e.command)
      ? { exitcode: 1, stderr: 'read-only file system' } : null),
  });
  const rec = await reseedOneLane('lane-halfway', h, { reseed: bakedSpec(runId).reseed });

  assert.strictEqual(winCommands(h).filter((c) => /Set-ADAccountPassword/.test(c)).length, 1,
    'the fixture did not get as far as rotating the account');
  assert.match(rec.steps.credential, /^failed:/);
  assert.strictEqual(rec.credential_state, 'ad_rotated_not_published');
  assert.ok(rec.warnings.some((w) => /DIRECTORY WAS ALREADY ROTATED/.test(w)),
    `nothing said the lane is now serving a credential AD no longer honours: ${JSON.stringify(rec.warnings)}`);
  assert.ok(rec.warnings.some((w) => /re-run/.test(w)), 'the record does not say how to recover');
  // Nothing half-written is left lying around holding the live credential.
  assert.strictEqual([...h.files.keys()].filter((k) => k.indexOf('.ccreseed') !== -1).length, 0);
});

test('a failure BEFORE the directory is touched records that nothing changed', async () => {
  const runId = 'RUN_SITE_A_5';
  const { site, files } = bakedSite(runId);
  const partial = Object.assign({}, files);
  delete partial[site.reseed.plants[0].path];
  const h = harness({ files: partial });
  const rec = await reseedOneLane('lane-untouched', h, { reseed: bakedSpec(runId).reseed });

  assert.strictEqual(rec.credential_state, 'unchanged',
    'a reseed that stopped before the AD write did not say the lane is still consistent');
  assert.ok(!rec.warnings.some((w) => /ALREADY ROTATED/.test(w)));
});

// ════════════════════════════════════════════════════════════════════════════
// 9. THE RIGHT ACCOUNT, IN THE RIGHT DOMAIN — AND THE ONES THAT MUST NOT MOVE
// ────────────────────────────────────────────────────────────────────────────
// Everything above proves the consumer half. This section proves the SEAM: the
// spec these tests feed it is the one profile-deploy's bake overlay really
// emits, so the three producer defects are visible here rather than hidden
// behind a hand-written fixture that already knew the answer.
//
//   the account   the overlay took it off labIR.foothold_credential — the
//                 CHAIN's entry. goad-lab-content publishes the foothold only
//                 when the chain plants it web-side; for an AS-REP, a
//                 null-session, an open-share or a password-equals-username
//                 entry it deliberately publishes an inert bind account, so the
//                 reseed rotated one account while every page advertised
//                 another. Both sides reported success.
//   the domain    it took site.reseed.domain, which is the NetBIOS SHORT name.
//                 Set-ADAccountPassword -Server and ValidateCredentials want
//                 DNS, so that is a credential nothing can set on any lane.
//   the plants    site.reseed never reached the spec at all, so this module took
//                 its "declares NO site plants" branch on every lane and the
//                 website kept the baked password for the whole section.
//
// And the rule with a boundary: a credential whose VALUE carries the exercise
// (a wordlist password an AS-REP hash must crack to, a password that IS the
// account name) is never rotated, and the record says so in words.
// ════════════════════════════════════════════════════════════════════════════

/** A client whose chain enters through AS-REP: the website publishes an inert
 *  bind account, and the foothold's password is a wordlist value the student
 *  cracks offline. `RUN_SITE_A_5` (web_credential) is the opposite case. */
const ASREP_RUN = 'RUN_SITE_A_3';
/** password_equals_samaccountname — the other shape where the value is the
 *  technique, and where the website again publishes somebody else. */
const PW_EQ_SAM_RUN = 'RUN_SITE_A_4';

/** The identity Set-ADAccountPassword was actually aimed at. */
function adIdentityFromCommands(h) {
  const cmd = winCommands(h).find((c) => /Set-ADAccountPassword/.test(c));
  const m = cmd && cmd.match(/-Identity '([^']*)'/);
  return m ? m[1] : null;
}
/** The -Server it was aimed at. */
function adServerFromCommands(h) {
  const cmd = winCommands(h).find((c) => /Set-ADAccountPassword/.test(c));
  const m = cmd && cmd.match(/-Server '([^']*)'/);
  return m ? m[1] : null;
}

test('EXIT: the account the lane rotates is the one the WEBSITE publishes, in its DNS domain', async () => {
  // The headline of this fix. On this client the chain's foothold and the
  // account the site publishes are DIFFERENT PEOPLE — which is the ordinary case
  // — and the old overlay rotated the foothold. Nothing reported it: AD returned
  // 0 for an account nobody reads, and the page went on printing a password the
  // directory still honoured for somebody else.
  const { site, files, ir, baked } = bakedSite(ASREP_RUN);
  assert.notStrictEqual(site.reseed.username, ir.foothold_credential.sam,
    'this fixture no longer covers the defect: its website publishes the foothold itself');

  const h = harness({ files: Object.assign({}, files) });
  const rec = await reseedOneLane('lane-right-account', h, bakedSpec(ASREP_RUN));

  assert.strictEqual(rec.steps.credential, 'ok', JSON.stringify(rec));
  assert.strictEqual(adIdentityFromCommands(h), site.reseed.username,
    'the lane rotated an account other than the one its website advertises');
  assert.notStrictEqual(adIdentityFromCommands(h), ir.foothold_credential.sam,
    "the lane rotated the CHAIN's foothold, which no page on the box publishes");

  // The domain. `RIDGELINE` is what the settings page prints; corp.<domain> is
  // what the DC answers for.
  const server = adServerFromCommands(h);
  assert.ok(server.includes('.'), `-Server '${server}' is a NetBIOS short name`);
  assert.notStrictEqual(server, site.reseed.domain);
  assert.strictEqual(server,
    ir.principals.users.find((u) => u.sam === site.reseed.username).domain,
    'the -Server is not the domain the roster creates that account in');
  assert.strictEqual(verifyPasswordFromCommands(h), adPasswordFromCommands(h),
    'the value authenticated is not the value set');

  // Every publisher the bake declared now serves the SAME new value.
  for (const plant of site.reseed.plants) {
    const served = publishedValue(h, plant);
    assert.strictEqual(served, adPasswordFromCommands(h),
      `${plant.path} serves ${JSON.stringify(served)} and AD honours something else`);
    assert.notStrictEqual(served, baked, `${plant.path} still serves the baked password`);
  }
});

test('EXIT: and the AS-REP password the exercise depends on is NOT touched', async () => {
  // The subtle half. `Autumn2023` is drawn from CRACKABLE_PASSWORDS precisely so
  // the AS-REP hash falls to an offline crack. A 20-character CSPRNG value makes
  // the chain unsolvable, and the old code reported status 'reseeded',
  // steps.credential 'ok' while doing exactly that.
  const chainMod = require(path.join(CIAB_UTILS, 'goad-attack-chain.js'));
  const { ir, files } = bakedSite(ASREP_RUN);
  const cred = ir.foothold_credential;
  assert.strictEqual(cred.planted_at.format, 'asrep_roastable');
  assert.ok(chainMod.CRACKABLE_PASSWORDS.includes(cred.password),
    'this fixture no longer carries a crackable AS-REP password');

  const h = harness({ files: Object.assign({}, files) });
  const rec = await reseedOneLane('lane-asrep-survives', h, bakedSpec(ASREP_RUN));

  // NOTHING this lane dispatched touched that account or that value.
  for (const text of allCommandText(h)) {
    assert.ok(!text.includes(`-Identity '${cred.sam}'`),
      `a guest command aimed an AD write at ${cred.sam}: ${text.slice(0, 160)}`);
  }
  assert.ok(!allCommandText(h).some((t) => t.includes(cred.password)),
    'the crackable password reached a guest command');

  // AND THE RECORD SAYS SO. "Deliberately not rotated" and "forgotten" must not
  // read the same on a lane row.
  assert.ok(Array.isArray(rec.fixed_credentials), 'the record names no fixed credentials at all');
  const fixed = rec.fixed_credentials.find((f) => f.sam === cred.sam);
  assert.ok(fixed, `${cred.sam} is not named as a credential that must stay fixed`);
  assert.match(fixed.technique, /asrep/);
  assert.match(fixed.why, /crackable wordlist/);
  assert.strictEqual(fixed.domain, cred.domain);

  // …and where uniqueness is, and is not.
  assert.ok(rec.uniqueness.per_lane.some((v) => /pivot credential/.test(v)),
    'this lane DID rotate a credential and the record does not say so');
  assert.ok(rec.uniqueness.baked.some((v) => v.includes(cred.sam)),
    `the record does not say ${cred.sam} is identical across the section: `
    + JSON.stringify(rec.uniqueness.baked));
});

test('a credential marked rotate:false is left alone, LOUDLY, and no DC is touched', async () => {
  // The producer's verdict, honoured. Driven on a real configuration: an AD-only
  // bake has no website, so the account the reseed would rotate falls back to the
  // chain's own foothold — and on this client that is the AS-REP account whose
  // password IS the exercise.
  const { ir, bake } = bakedSite(ASREP_RUN);
  const adOnly = { ...bake, verify_report: null, spec: { ...bake.spec, cc_web: { enabled: false } } };
  const block = deployRouter.reseedBlockForBake({
    spec: {}, bake: adOnly, ir, foothold: ir.foothold_credential,
  });
  assert.strictEqual(block.pivot.rotate, false, 'the producer would rotate it after all');

  const h = harness();
  const rec = await reseedOneLane('lane-fixed-cred', h, { reseed: block });

  assert.strictEqual(rec.status, 'reseeded',
    'a deliberate decision was reported as a failure, which sends an operator hunting for a bug');
  assert.match(rec.steps.credential, /^not rotated \(deliberate\):/);
  assert.match(rec.steps.credential, /crackable wordlist/,
    'the step says it did not rotate and not WHY, which reads exactly like a forgotten credential');
  assert.strictEqual(rec.credential_state, 'deliberately_fixed');
  assert.match(rec.steps.verify, /^skipped/);
  assert.strictEqual(winCommands(h).length, 0,
    'a DC was contacted to rotate a credential the plan says must not move');
  assert.ok(!allCommandText(h).some((t) => t.includes(ir.foothold_credential.password)),
    'the fixed password reached a guest command');

  // The rest of the lane is still per-student.
  assert.strictEqual(rec.steps.flag, 'ok');
  assert.strictEqual(rec.steps.seed_data, 'ok');
  assert.ok(rec.uniqueness.per_lane.some((v) => /flag/.test(v)));
  assert.ok(!rec.uniqueness.per_lane.some((v) => /pivot credential/.test(v)),
    'the record claims per-lane uniqueness for a credential nothing rotated');
  assert.ok(rec.uniqueness.baked.some((v) => /NOT rotated per lane/.test(v)),
    'nothing states where the uniqueness guarantee stops applying');
  assert.ok(rec.warnings.some((w) => /NOT rotated per lane, on purpose/.test(w)),
    `the lane row carries no warning about the fixed credential: ${JSON.stringify(rec.warnings)}`);
});

test('the same holds for a password_equals_samaccountname entry', async () => {
  // The second shape where the VALUE is the technique: password == username is
  // only an entry while the equality holds.
  const { ir, files } = bakedSite(PW_EQ_SAM_RUN);
  const cred = ir.foothold_credential;
  assert.strictEqual(cred.password, cred.sam, 'this fixture no longer carries the equality');

  const h = harness({ files: Object.assign({}, files) });
  const rec = await reseedOneLane('lane-user-eq-pw', h, bakedSpec(PW_EQ_SAM_RUN));

  assert.strictEqual(rec.steps.credential, 'ok', JSON.stringify(rec));
  assert.notStrictEqual(adIdentityFromCommands(h), cred.sam,
    `the lane rotated ${cred.sam}, whose password IS their sAMAccountName — the technique`);
  const fixed = rec.fixed_credentials.find((f) => f.sam === cred.sam);
  assert.ok(fixed, 'the record does not name the account whose password must equal its own name');
  assert.match(fixed.why, /IS the sAMAccountName/);
});

test('a NetBIOS short name is refused by the consumer too, and says how to fix it', () => {
  // Defence in depth on the exact field a producer picks up by mistake: the
  // website prints the short name beside the account, and AD_DOMAIN_RE's
  // character class accepts it. Left to reach the DC it fails on every lane in
  // the section at once, after the staged rewrites are already on the web box.
  const plan = reseed.resolveReseedPlan({
    spec: goldenSpec({ reseed: { pivot: { sam: 'svc-webapp', domain: 'RIDGELINE' } } }),
    deployedVMs: deployedVMs('s1'),
  });
  assert.strictEqual(plan.pivot, null, 'a short name was accepted as a DNS domain');
  const warning = plan.warnings.find((w) => /RIDGELINE/.test(w));
  assert.ok(warning, `nothing reported the short name: ${JSON.stringify(plan.warnings)}`);
  assert.match(warning, /single label/);
  assert.match(warning, /principals\.users/,
    'the warning does not say where the FQDN actually comes from');

  // And the real producer's own output still passes, so the guard is not a
  // blanket refusal of the thing that works.
  const ok = reseed.resolveReseedPlan({
    spec: goldenSpec(bakedSpec(ASREP_RUN)),
    deployedVMs: deployedVMs('s1'),
  });
  assert.ok(ok.pivot, `the producer's own domain was refused: ${JSON.stringify(ok.warnings)}`);
  assert.ok(ok.pivot.domain.includes('.'));
});

test('a pivot this end REFUSES is reported as refused, not as "not declared"', async () => {
  // The same class of defect the rest of this file is about, one layer down: a
  // spec that DOES name the account, whose domain the consumer rejects, used to
  // land on the lane row as 'skipped: spec.reseed.pivot.sam is not declared'.
  // That sends an operator looking for a missing field that is sitting right
  // there in the spec, and it reads exactly like the forgotten case.
  const h = harness();
  const rec = await reseed.reseedLane({
    laneId: 'lane-declined', userId: 'user-1',
    spec: goldenSpec({ reseed: { pivot: { sam: 'svc-webapp', domain: 'RIDGELINE' } } }),
    deployedVMs: deployedVMs('s1'),
    goadSubnetBase: BAKED_BASE,
    deps: h.deps,
  });

  assert.match(rec.steps.credential, /^skipped:/);
  assert.doesNotMatch(rec.steps.credential, /is not declared/,
    'a declared-but-refused pivot was reported as one nobody declared');
  assert.match(rec.steps.credential, /RIDGELINE/, 'the step does not name the value it refused');
  assert.match(rec.steps.credential, /single label/);
  assert.strictEqual(winCommands(h).length, 0, 'a DC was touched for a pivot this end refused');

  // …and the genuinely-undeclared case still says so.
  const none = await reseed.reseedLane({
    laneId: 'lane-declined-none', userId: 'user-1',
    spec: goldenSpec({ reseed: {} }),
    deployedVMs: deployedVMs('s1'),
    goadSubnetBase: BAKED_BASE,
    deps: harness().deps,
  });
  assert.match(none.steps.credential, /is not declared/);
});

test('EXIT: two lanes differ everywhere the plan CLAIMS uniqueness, and nowhere it does not', async () => {
  // The uniqueness guarantee, checked against its own claims rather than
  // against a list this test wrote. A plan that says "the pivot credential
  // differs per lane" and hands two students the same one is the original
  // defect; a plan that quietly stops claiming it is the new one.
  const { site, files, ir } = bakedSite(ASREP_RUN);
  const overrides = bakedSpec(ASREP_RUN);
  const shared = new Map();
  const a = harness({ flagRows: shared, files: Object.assign({}, files) });
  const b = harness({ flagRows: shared, files: Object.assign({}, files) });

  const recA = await reseedOneLane('lane-uniq-a', a, overrides);
  const recB = await reseedOneLane('lane-uniq-b', b, overrides);
  assert.strictEqual(recA.steps.credential, 'ok', JSON.stringify(recA));
  assert.strictEqual(recB.steps.credential, 'ok', JSON.stringify(recB));

  // …the flag
  assert.ok(recA.uniqueness.per_lane.some((v) => /flag/.test(v)));
  assert.notStrictEqual(flagFromCommands(a), flagFromCommands(b));
  // …the seeded records
  assert.ok(recA.uniqueness.per_lane.some((v) => /seeded record identifiers/.test(v)));
  assert.notStrictEqual(recA.seed.lane_token, recB.seed.lane_token);
  assert.notStrictEqual(recA.seed.order_number_base, recB.seed.order_number_base);
  // …and the pivot credential, at every place the website publishes it
  assert.ok(recA.uniqueness.per_lane.some((v) => v.includes(site.reseed.username)));
  for (const plant of site.reseed.plants) {
    assert.notStrictEqual(publishedValue(a, plant), publishedValue(b, plant),
      `both lanes serve the same credential at ${plant.path}`);
  }
  assert.notStrictEqual(recA.pivot_fingerprint, recB.pivot_fingerprint);

  // And the one value the plan does NOT claim is per-lane really is shared —
  // which is the honest half of the guarantee, not an oversight.
  assert.ok(recA.uniqueness.baked.some((v) => v.includes(ir.foothold_credential.sam)));
  assert.deepStrictEqual(
    recA.fixed_credentials.map((f) => f.sam), recB.fixed_credentials.map((f) => f.sam),
    'two lanes from one bake disagree about which credentials are fixed');
});
