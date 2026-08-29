/**
 * ciab-quarantine.test.js — Track A3: the two CIAB-only survivors, extracted
 * from ciab/utils/lane-deploy.js and ciab/routes/profile-deploy.js so A7 can
 * delete the fourth copy of the deploy sequence without taking them with it.
 *
 *   ciab/utils/vuln-app-install.js   installs the LLM-generated vulnerable app
 *   ciab/utils/profile-students.js   mints one student account per lane
 *
 * A3 is a MOVE, so most of what is worth pinning is what must NOT have changed.
 * Two things beyond that earn a test:
 *
 *   1. The quarantine has to stay a quarantine. lane-deploy.js also carried
 *      private copies of proxmoxFormPOST / agentShellExec / waitForAgentExecReady
 *      that are byte-equivalent to the ones already in src/utils/script-executor.js.
 *      Those were NOT moved — they are imported. The guard below watches
 *      vuln-app-install.js, the file that survives A7, because that is where a
 *      "make it self-contained" edit would land; re-adding them to lane-deploy.js
 *      is already a load-time SyntaxError (the names are destructured there) and
 *      that file is deleted by A7 regardless.
 *
 *   2. The pure helpers had no coverage at all, and two of them silently rewrite
 *      what runs inside a student's lane.
 *
 * Run: node front-end/test/ciab-quarantine.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const CIAB = path.join(__dirname, '..', 'modules', 'crucible', 'plugins', 'ciab');
const VULN_APP_INSTALL = path.join(CIAB, 'utils', 'vuln-app-install.js');
const PROFILE_STUDENTS = path.join(CIAB, 'utils', 'profile-students.js');

const vulnApp = require(VULN_APP_INSTALL);
const students = require(PROFILE_STUDENTS);

const SRC_UTILS = path.join(__dirname, '..', 'src', 'utils');

/** Replace a shared-core module in the require cache — the house pattern. */
function stub(name, exports) {
  const p = require.resolve(path.join(SRC_UTILS, `${name}.js`));
  require.cache[p] = { id: p, filename: p, loaded: true, exports };
}

/** Re-require a module so it picks up the stubs installed above. */
function freshRequire(modPath) {
  delete require.cache[require.resolve(modPath)];
  return require(modPath);
}

// ── 1. the quarantine stays a quarantine ────────────────────────────────────

test('the installer imports the shared agent-exec helpers rather than copying them', () => {
  // These three are identical to src/utils/script-executor.js's, which is what
  // cle/utils/attack-runner.js and src/utils/flag-manager.js already call. A
  // private copy here would drift from them exactly the way lane-deploy.js
  // drifted from challenge-lane-deployer.js.
  const src = fs.readFileSync(VULN_APP_INSTALL, 'utf8');
  for (const fn of ['proxmoxFormPOST', 'agentShellExec', 'waitForAgentExecReady']) {
    assert.ok(!new RegExp(`function\\s+${fn}\\s*\\(`).test(src),
      `${fn} must be imported from src/utils/script-executor.js, not redefined here`);
  }
  assert.match(src, /require\('\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/src\/utils\/script-executor'\)/,
    'the shared script-executor import is what makes the above true');
});

test('the 596 workaround is documented as a workaround, not a pattern', () => {
  // The base64-chunked write exists ONLY because script-executor.guestFileWrite
  // 596s on PVE 9.1.9. If that note is ever lost, the next author reads this as
  // the house style and copies it into new code.
  const src = fs.readFileSync(VULN_APP_INSTALL, 'utf8');
  assert.match(src, /guestFileWrite/, 'the real bug must be named in this file');
  assert.match(src, /596/, 'the failure mode must be named in this file');
});

// ── 2. the pure helpers ─────────────────────────────────────────────────────

test('a non-cached Dockerfile base is rewritten to one baked into the template', () => {
  // A lane has no container DNS and no UDP-53 egress, so a FROM the web template
  // has not cached cannot be pulled and the build dies inside the student's VM.
  // The LLM is told to use only the cached bases and regularly ignores it.
  const out = vulnApp.rewriteDockerfileBases('FROM node:16-slim\nRUN echo hi', '[t]');
  assert.match(out, /^FROM node:20-alpine$/m);
  assert.match(out, /^RUN echo hi$/m, 'only FROM lines may be touched');
});

test('an already-cached base is left exactly alone', () => {
  const dockerfile = 'FROM python:3-slim\nCOPY . /app';
  assert.strictEqual(vulnApp.rewriteDockerfileBases(dockerfile, '[t]'), dockerfile);
});

test('an unrecognised base falls back to node rather than being left to fail', () => {
  const out = vulnApp.rewriteDockerfileBases('FROM totally-made-up:1', '[t]');
  assert.match(out, /^FROM node:20-alpine/m);
});

test('a multi-stage Dockerfile has every FROM rewritten', () => {
  const out = vulnApp.rewriteDockerfileBases(
    'FROM node:16 AS build\nRUN x\nFROM nginx:1.2\nCOPY --from=build /a /b', '[t]');
  assert.match(out, /^FROM node:20-alpine AS build$/m, 'the AS clause must survive');
  assert.match(out, /^FROM nginx:alpine$/m);
});

test('shellQuoteArg survives an embedded single quote', () => {
  // This value is interpolated straight into a /bin/sh -c string that runs in
  // the guest; a naive quote would end the string and run the rest as commands.
  assert.strictEqual(vulnApp.shellQuoteArg("a'b"), `'a'\\''b'`);
});

test('the prebuilt install script quotes the image tag and remaps the port', () => {
  const s = vulnApp.buildPrebuiltInstallScript({ url: 'http://o/i.tgz', imageTag: 'vuln:1' });
  assert.match(s, /docker run -d --restart=always --name vuln-app .*'vuln:1'/);
  // apache2/nginx ship enabled on the Debian web template and would hold :80,
  // making docker run fail with exit 125.
  assert.match(s, /systemctl stop "\$svc"/);
  // The app may not bind 80 even when told to; the script detects and remaps so
  // Kali can always reach it on :80.
  assert.match(s, /ACTUAL_PORT/);
});

// ── 3. student account naming ───────────────────────────────────────────────
//
// The slug is load-bearing in three places that must agree: the student's
// email, their Guacamole username (the same string), and the lane display name
// `kali-<slug>-student<N>-<vmid>`. A second spelling mints a parallel set of
// accounts on the next deploy and the first set's lanes go orphaned.

test('the group slug strips everything that is not a-z0-9', () => {
  assert.strictEqual(students.slugForGroup('Cochise 101 - Fall'), 'cochise101fall');
  assert.strictEqual(students.slugForGroup('CYBR-400'), 'cybr400');
});

test('a missing group name slugs to empty rather than throwing', () => {
  assert.strictEqual(students.slugForGroup(null), '');
  assert.strictEqual(students.slugForGroup(undefined), '');
});

test('the student login is the slug, the index, and a non-routable domain', () => {
  // .local is deliberate: src/utils/mailer.js blackholes it, so a lab account
  // can never cause mail to leave for a student who does not exist.
  assert.strictEqual(students.studentEmail('cochise101', 3), 'cochise101-student3@clinic.local');
});

test('provisionLaneStudents mints exactly the indices it is given, in order', async () => {
  // Behavioural, not a source grep. The previous version of this test asserted
  // /indices/ against the file text — which the JSDoc alone satisfies, so the
  // parameter could have been deleted from the signature and it would still
  // have passed. This is the ONLY coverage of provisionLaneStudents, and the
  // contract is on a live path: profile-deploy.js's add-lanes route passes
  // startIndex + i + 1 derived from MAX(lane_index). If that regressed to a
  // 1..n loop, adding lanes would re-mint student1..N — rotating passwords out
  // from under the first batch's already-issued credential sheet and handing
  // the new lanes to the first batch's students.
  const minted = [];
  stub('account-provisioning', {
    provisionOrRotateAccount: async (a) => {
      minted.push(a);
      return { password: `pw-${a.lastName}`, user: { user_id: `uid-${a.lastName}` } };
    },
  });
  stub('guacamole', { guacAPI: async () => ({}) });

  const { provisionLaneStudents } = freshRequire(PROFILE_STUDENTS);
  const out = await provisionLaneStudents({
    groupName: 'Cochise 101', groupId: 'g-1', indices: [4, 5], actingUserId: 'admin-1',
  });

  assert.deepStrictEqual(minted.map(a => a.email),
    ['cochise101-student4@clinic.local', 'cochise101-student5@clinic.local']);
  assert.deepStrictEqual(out.students.map(s => s.index), [4, 5]);
  assert.deepStrictEqual(out.students.map(s => s.id), ['uid-4', 'uid-5']);
  assert.strictEqual(out.groupSlug, 'cochise101');
  // The credential sheet must line up with the accounts actually minted.
  assert.deepStrictEqual(out.credentials,
    [{ email: 'cochise101-student4@clinic.local', password: 'pw-4', role: 'student' },
     { email: 'cochise101-student5@clinic.local', password: 'pw-5', role: 'student' }]);
});

test('provisionLaneStudents reproduces the account fields both old loops used', async () => {
  // A3 was a move; these are the exact values the two deleted loops passed, and
  // a drift here changes who the account IS (role, verification state) rather
  // than merely how it is named.
  const seen = [];
  stub('account-provisioning', {
    provisionOrRotateAccount: async (a) => {
      seen.push(a);
      return { password: 'pw', user: { user_id: 'uid' } };
    },
  });
  stub('guacamole', { guacAPI: async () => ({}) });

  const { provisionLaneStudents } = freshRequire(PROFILE_STUDENTS);
  await provisionLaneStudents({
    groupName: 'CYBR-400', groupId: 'g-9', indices: [2], actingUserId: 'admin-7',
  });

  assert.deepStrictEqual(seen[0], {
    email: 'cybr400-student2@clinic.local',
    username: 'cybr400-student2@clinic.local',
    firstName: 'Student',
    lastName: '2',
    organization: 'CYBR-400',
    role: 'student',
    emailVerified: true,
    mustChangePassword: false,
    provenance: { by: 'admin-7', via: 'group_deploy', ref: 'g-9' },
  });
});

test('a Guacamole outage does not fail the deploy', async () => {
  // Best-effort by design: the admin can create the Guac user by hand later,
  // and failing here would abandon a lane that is otherwise fine. Both the POST
  // and the PUT fallback must be swallowed.
  stub('account-provisioning', {
    provisionOrRotateAccount: async () => ({ password: 'pw', user: { user_id: 'uid' } }),
  });
  let calls = 0;
  stub('guacamole', { guacAPI: async () => { calls++; throw new Error('guac down'); } });

  const { provisionLaneStudents } = freshRequire(PROFILE_STUDENTS);
  const out = await provisionLaneStudents({
    groupName: 'g', groupId: 'g-1', indices: [1],
  });
  assert.strictEqual(out.students.length, 1, 'the student must still be returned');
  assert.strictEqual(calls, 2, 'POST then the PUT fallback, both swallowed');
});
