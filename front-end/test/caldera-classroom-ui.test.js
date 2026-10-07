'use strict';

/**
 * The two staff-only classroom dialogs on the Blue Team Board: "Group install
 * agents" and "Run Caldera attack" (blue-team.js showClassroomCaldera).
 *
 * WHY THE IDS IN HERE LOOK THE WAY THEY DO. Every element this file addresses is
 * named after a value the SERVER owns — a lane id, a machine key, a
 * "<lane_id>:<vm_id>" pair — because blue-team.js stopped naming them after
 * their index in the rendered list. Index-based ids (classroomLane0,
 * classroomTarget3) named a different machine the moment a search, a sort, a
 * facet or a collapsed group changed the rendered set, so the handler rebound at
 * that index installed onto somebody else's VM. cid() below reproduces
 * classroomId() character for character, including the stricter escape, so a
 * change to one of them fails here rather than silently addressing nothing.
 *
 * Run: node --test test/caldera-classroom-ui.test.js
 */

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const crypto = require('node:crypto');
const SOURCE_PATH = path.join(__dirname, '../modules/crucible/plugins/cle/public/js/blue-team.js');
const PAGE_PATH = path.join(__dirname, '../modules/crucible/plugins/cle/public/pages/courses.html');
const source = fs.readFileSync(SOURCE_PATH, 'utf8');
const clone = value => JSON.parse(JSON.stringify(value));
/**
 * escHtml, as courses.html:2034 actually implements it.
 *
 * IT DOES NOT ESCAPE QUOTES, AND THAT IS THE POINT OF REPRODUCING IT EXACTLY.
 * The page builds it out of textContent -> innerHTML, which the HTML spec says
 * escapes &, < and > only. A stub that also escaped " and ' was strictly SAFER
 * than production, which made this suite blind to the single hard constraint the
 * plan names: every attribute-position value must use escAttr(). Swapping any
 * escAttr() for escHtml() -- in the lane chip's title=, in the adversary
 * <option value=> -- left all 34 tests green here while a lane named
 * `Lab "A" onmouseover=alert(1)` would close the attribute in a real browser and
 * hang an event handler on the chip. With the quotes left alone, the id scan and
 * the tag slices below see the corrupted tag and the mutation fails immediately.
 */
const esc = value => String(value ?? '').replace(/[&<>]/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[ch]));

// ---- stable element ids -------------------------------------------------

/**
 * classroomId(kind, value), reproduced. The extra .replace() is not decoration:
 * encodeURIComponent leaves !'()*~ intact, and a single quote in an id would
 * close the attribute in markup blue-team.js builds by string concatenation.
 */
const cid = (kind, value) => `classroom${kind}-`
  + encodeURIComponent(String(value === null || value === undefined ? '' : value))
    .replace(/[!'()*~]/g, character => `%${character.charCodeAt(0).toString(16).toUpperCase()}`);
const lid = laneId => cid('Lane', laneId);
const gid = key => cid('Group', key);
const gaid = key => cid('GroupAll', key);
const mid = key => cid('Machine', key);
const moid = key => cid('MachineOs', key);
const tid = (laneId, vmId) => cid('Target', `${laneId}:${vmId}`);
const toid = (laneId, vmId) => cid('TargetOs', `${laneId}:${vmId}`);

/**
 * The ids an island actually rendered, in document order.
 *
 * The same regex the fake DOM discovers elements with, so "how many lane chips
 * are on screen" is answered by the markup rather than by a count this file
 * would have to keep in step with the fixture by hand.
 */
const idsIn = (html, prefix) => [...String(html || '').matchAll(/\bid="([^"]+)"/g)]
  .map(match => match[1]).filter(id => id.startsWith(prefix));

/** The aria-sort a header CELL carries, found through the button it wraps. */
const sortOrder = (html, key) => (String(html || '')
  .match(new RegExp(`aria-sort="([a-z]+)"><button[^>]*id="${cid('Sort', key)}"`)) || [])[1] || null;

/** The tone and text of the profile card's fit verdict. */
const fitNote = html => {
  const match = String(html || '').match(/<div class="cal-note (cal-note-[a-z]+)"><span class="cal-note-icon" aria-hidden="true">[^<]*<\/span><span>([^<]*)<\/span><\/div>/);
  return match ? { tone: match[1], text: match[2] } : null;
};

const summaryLine = html => (String(html || '').match(/<p class="cal-advcard-summary">([^<]*)<\/p>/) || [])[1] || null;

// ---- fixtures -----------------------------------------------------------

// Recent enough that the server's own `fresh` verdict is consistent with the
// timestamp beside it. classroomAgo() is minute-granular on purpose, so this
// renders as a string that does not change between two polls of the same data.
const seenAt = () => new Date(Date.now() - 90000).toISOString();

const ability = (id, name, tactic, platforms, executors, extra = {}) => ({ ability_id: id, name, tactic,
  technique_id: extra.technique_id || 'T1087', technique_name: extra.technique_name || 'Account Discovery',
  platforms, executors, description: extra.description || null });

/**
 * Two adversary profiles and the catalog behind them, shaped exactly as the
 * operations endpoint projects them.
 *
 * profile-summary deliberately carries an ability id the catalog does NOT hold
 * (ab-6) and tactic counts that sum to three against six steps, because both are
 * shapes the real endpoint sends: summary.tactics skips abilities whose tactic
 * is null, and unknown_abilities counts ids the catalog could not answer for. A
 * UI that derived the step count from the tactic totals would call a six-step
 * operation a three-step one.
 */
function profiles() {
  return {
    adversaries: [
      { adversary_id: 'profile-summary', name: 'Class discovery', description: 'Discovery and credential steps',
        ability_count: 6, ability_ids: ['ab-1', 'ab-2', 'ab-3', 'ab-4', 'ab-5', 'ab-6'],
        summary: { tactics: [{ tactic: 'discovery', count: 2 }, { tactic: 'credential-access', count: 1 }],
          platforms: { windows: 4, linux: 2, darwin: 0 }, techniques: ['T1087', 'T1003'], unknown_abilities: 1 } },
      { adversary_id: 'profile-windows', name: 'Windows only', description: 'Two Windows steps',
        ability_count: 2, ability_ids: ['ab-1', 'ab-2'],
        summary: { tactics: [{ tactic: 'discovery', count: 2 }],
          platforms: { windows: 2, linux: 0, darwin: 0 }, techniques: ['T1087'], unknown_abilities: 0 } },
    ],
    abilities: {
      'ab-1': ability('ab-1', 'Find local users', 'discovery', ['windows'], [{ platform: 'windows', name: 'psh' }],
        { description: 'Lists the local accounts on the host.' }),
      'ab-2': ability('ab-2', 'List shares', 'discovery', ['windows'], [{ platform: 'windows', name: 'cmd' }]),
      'ab-3': ability('ab-3', 'Dump credentials', 'credential-access', ['linux'], [{ platform: 'linux', name: 'sh' }],
        { technique_id: 'T1003', technique_name: 'OS Credential Dumping' }),
      'ab-4': ability('ab-4', 'Copy files', 'lateral-movement', ['windows'], [{ platform: 'windows', name: 'psh' }]),
      'ab-5': ability('ab-5', 'Run script', 'execution', ['windows', 'linux'],
        [{ platform: 'windows', name: 'psh' }, { platform: 'linux', name: 'sh' }]),
    },
  };
}

/**
 * Three lanes of one GOAD environment, carrying every field the agents endpoint
 * actually sends: identity (lane_number, family, kind), the student join, the
 * environment, and per-target machine_key / role / os / infra / agent.
 *
 * Lane three is lifecycle_eligible:false — the one honest reason a lane cannot
 * be installed on that has nothing to do with agents.
 */
function fixture() {
  const catalog = profiles();
  return { server_url: 'https://agents.example/', console_url: 'https://agents.example/',
    adversaries: [{ adversary_id: 'adversary-one', name: 'Class discovery', description: 'Discovery steps',
      ability_count: 2, ability_ids: ['ab-1', 'ab-2'],
      summary: { tactics: [{ tactic: 'discovery', count: 2 }], platforms: { windows: 2, linux: 0, darwin: 0 },
        techniques: ['T1087'], unknown_abilities: 0 } }],
    abilities: { 'ab-1': catalog.abilities['ab-1'], 'ab-2': catalog.abilities['ab-2'] },
    lanes: ['one', 'two', 'three'].map((suffix, i) => ({ lane_id: `lane-${suffix}`, name: `Lane ${suffix}`,
      group: `lane-group-${suffix}`, lane_number: 10880 + i, vxlan_id: 10880 + i, family: 'cle-cybr400',
      kind: 'goad', created_at: '2026-09-01T09:00:00Z',
      student: i < 2 ? { name: `Student ${suffix}`, email: `${suffix}@clinic.local` } : null,
      environment: { key: 'goad', label: 'GOAD Active Directory', type: 'goad', lab: 'goad-light' },
      runnable: i < 2, lifecycle_eligible: i < 2, internet_enabled: true, retained_after_failure: false,
      lane_status: i < 2 ? 'running' : 'stopped', jobs: [], operations: [],
      agents: i < 2 ? [{ paw: `paw-${suffix}`, host: 'ws01', platform: 'windows', group: `lane-group-${suffix}`,
        last_seen: seenAt(), trusted: true, fresh: true, vm_id: 100 * (i + 1) }] : [],
      targets: [
        { vm_id: 100 * (i + 1), name: i === 1 ? 'dc01' : 'DC01', type: 'qemu', node: 'pve1',
          role: 'dc', platform: 'windows', os: 'Windows Server 2019', infra: false, source: 'environment',
          slot: null, template_name: 'win2019-goad', machine_key: 'goad::dc01', machine_label: 'DC01',
          environment_key: 'goad', runnable: i < 2, power_state: i < 2 ? 'running' : 'stopped',
          agent: i === 0 ? { paw: 'paw-dc01', host: 'DC01', platform: 'windows', last_seen: seenAt(), trusted: true, fresh: true } : null,
          last_job: null },
        { vm_id: 100 * (i + 1) + 1, name: 'WS01', type: 'qemu', node: 'pve1',
          role: 'workstation', platform: null, os: 'Unknown', infra: false, source: 'environment',
          slot: null, template_name: null, machine_key: 'goad::ws01', machine_label: 'WS01',
          environment_key: 'goad', runnable: i < 2, power_state: i < 2 ? 'running' : 'stopped',
          agent: null, last_job: null },
        { vm_id: 100 * (i + 1) + 2, name: 'sensor', type: 'qemu', node: 'pve1',
          role: 'siem', platform: 'linux', os: 'Ubuntu 22.04', infra: true, source: 'environment',
          slot: null, template_name: 'ubuntu-elk', machine_key: 'goad::elk', machine_label: 'elk',
          environment_key: 'goad', runnable: false, power_state: 'stopped', agent: null, last_job: null },
      ] })) };
}

/** The standard lanes with the fuller adversary catalog attached. */
function attackFixture(overrides = {}) {
  const data = fixture();
  const catalog = profiles();
  data.adversaries = catalog.adversaries;
  data.abilities = catalog.abilities;
  return Object.assign(data, overrides);
}

const wsTarget = (index, number) => ({ vm_id: 200000 + index, name: `cle-cybr400-inperson-${number}-ws1`,
  type: 'qemu', node: 'pve1', role: 'workstation', platform: 'windows', os: 'Windows 11', infra: false,
  source: 'workstation', slot: 0, template_name: 'win11-student', machine_key: 'workstation::slot0',
  machine_label: 'Workstation 1', environment_key: 'workstation', runnable: true, power_state: 'running',
  agent: null, last_job: null });

const goadTarget = (vmId, name, role, platform, extra = {}) => Object.assign({ vm_id: vmId, name, type: 'qemu',
  node: 'pve1', role, platform, os: platform === 'windows' ? 'Windows Server 2019' : 'Ubuntu 22.04',
  infra: false, source: 'environment', slot: null, template_name: `${platform}-goad`,
  machine_key: `goad-ad::${name.toLowerCase()}`, machine_label: name, environment_key: 'goad-ad',
  runnable: true, power_state: 'running', agent: null, last_job: null }, extra);

/**
 * The real CYBR400 shape: forty-four workstation lanes whose hostnames are all
 * distinct, one GOAD lane of six machines including a SIEM and an attack box,
 * and a SECOND environment whose own DC01 must not collapse onto GOAD's.
 *
 * This is the inventory every grouping, search, facet and machine-keying claim
 * below is made against, because all of the dialog's original failures only
 * appear at this size: chips that are indistinguishable, a machine key that
 * groups nothing and collides across environments, and a lane list that pushes
 * steps 2 and 3 off the screen.
 */
function wall() {
  const base = fixture();
  const lanes = [];
  for (let i = 0; i < 44; i++) {
    const number = 10900 + i;
    lanes.push({ lane_id: `ws-${number}`, name: `cle-cybr400-inperson-${number}`, group: `lane-ws-${number}`,
      lane_number: number, vxlan_id: number, family: 'cle-cybr400-inperson', kind: 'workstation',
      created_at: '2026-09-01T09:00:00Z',
      student: { name: `Student ${i + 1}`, email: `student${i + 1}@clinic.local` },
      environment: { key: 'workstation', label: 'Student workstations', type: 'workstation', lab: null },
      runnable: true, lifecycle_eligible: true, internet_enabled: true, retained_after_failure: false,
      lane_status: 'running', jobs: [], operations: [], agents: [], targets: [wsTarget(i, number)] });
  }
  lanes.push({ lane_id: 'goad-lane', name: 'cle-cybr400-goad-10880', group: 'lane-goad',
    lane_number: 10880, vxlan_id: 10880, family: 'cle-cybr400-goad', kind: 'goad',
    created_at: '2026-09-01T09:00:00Z', student: { name: 'Student one', email: 'one@clinic.local' },
    environment: { key: 'goad-ad', label: 'GOAD Active Directory', type: 'goad', lab: 'goad-light' },
    runnable: true, lifecycle_eligible: true, internet_enabled: true, retained_after_failure: false,
    lane_status: 'running', operations: [],
    // The defect this release exists for: two Windows installs recorded as
    // failed on a timeout, one of whose agents has been beaconing all along.
    jobs: [{ job_id: 'job-dc01', vm_id: 6001, status: 'failed', platform: 'windows',
      error: 'Agent installation failed. Timed out after 120000 ms.', warnings: [], exec_incomplete: true },
    { job_id: 'job-dc02', vm_id: 6002, status: 'failed', platform: 'windows',
      error: 'Agent installation failed. Timed out after 120000 ms.', warnings: [], exec_incomplete: true }],
    agents: [{ paw: 'paw-dc02', host: 'DC02', platform: 'windows', group: 'lane-goad', last_seen: seenAt(),
      trusted: true, fresh: true, vm_id: 6002 }],
    targets: [
      goadTarget(6001, 'DC01', 'dc', 'windows'),
      goadTarget(6002, 'DC02', 'dc', 'windows', { agent: { paw: 'paw-dc02', host: 'DC02', platform: 'windows',
        last_seen: seenAt(), trusted: true, fresh: true } }),
      goadTarget(6003, 'SRV02', 'member', 'windows'),
      goadTarget(6004, 'ws01', 'workstation', 'windows'),
      goadTarget(6005, 'elk', 'siem', 'linux', { infra: true }),
      goadTarget(6006, 'kali', 'attacker', 'linux', { source: 'attack_box',
        machine_key: 'goad-ad::attack-box', machine_label: 'Attack box' }),
    ] });
  lanes.push({ lane_id: 'lab-lane', name: 'cle-cybr400-lab-10881', group: 'lane-lab',
    lane_number: 10881, vxlan_id: 10881, family: 'cle-cybr400-lab', kind: 'course-lab',
    created_at: '2026-09-01T09:00:00Z', student: { name: 'Student two', email: 'two@clinic.local' },
    environment: { key: 'cyber-lab', label: 'Course lab', type: 'course-lab', lab: null },
    runnable: true, lifecycle_eligible: true, internet_enabled: true, retained_after_failure: false,
    lane_status: 'running', jobs: [], operations: [], agents: [],
    targets: [{ vm_id: 7001, name: 'DC01', type: 'qemu', node: 'pve2', role: 'dc', platform: 'windows',
      os: 'Windows Server 2022', infra: false, source: 'challenge', slot: null, template_name: 'win2022',
      machine_key: 'cyber-lab::dc01', machine_label: 'DC01', environment_key: 'cyber-lab',
      runnable: true, power_state: 'running', agent: null, last_job: null }] });
  base.lanes = lanes;
  return base;
}

/**
 * Four attack lanes, one per honest reason a lane cannot be launched on.
 *
 * lane-noagent is the case the old gate could not express: powered on, egress
 * up, and nothing checked in. caldera-lane-operations.js folds agents.length>0
 * into `runnable`, so that lane arrives with runnable:false — which is exactly
 * why reading `runnable` first used to label it "lane not running" and send an
 * instructor off to start a lane that was already running.
 */
function attackLanes() {
  const catalog = profiles();
  const lane = (id, number, over) => Object.assign({ lane_id: id, name: `cle-cybr400-${id}`, group: `g-${id}`,
    lane_number: number, vxlan_id: number, family: 'cle-cybr400', kind: 'goad', created_at: '2026-09-01T09:00:00Z',
    student: { name: `Student ${number}`, email: `s${number}@clinic.local` },
    environment: { key: 'goad-ad', label: 'GOAD Active Directory', type: 'goad', lab: 'goad-light' },
    runnable: true, lifecycle_eligible: true, internet_enabled: true, retained_after_failure: false,
    lane_status: 'running', jobs: [], operations: [], agents: [],
    targets: [goadTarget(8000 + number, 'DC01', 'dc', 'windows')] }, over);
  return { server_url: 'https://agents.example/', console_url: 'https://agents.example/',
    adversaries: catalog.adversaries, abilities: catalog.abilities,
    lanes: [
      lane('lane-ready', 1, { agents: [{ paw: 'paw-ready', host: 'DC01', platform: 'windows',
        group: 'g-lane-ready', last_seen: seenAt(), trusted: true, fresh: true, vm_id: 8001 }] }),
      lane('lane-noagent', 2, { runnable: false }),
      lane('lane-stopped', 3, { runnable: false, lifecycle_eligible: false, lane_status: 'stopped' }),
      lane('lane-nointernet', 4, { runnable: false, internet_enabled: false,
        agents: [{ paw: 'paw-off', host: 'DC01', platform: 'windows', group: 'g-lane-nointernet',
          last_seen: seenAt(), trusted: true, fresh: true, vm_id: 8004 }] }),
    ] };
}

// ---- harness ------------------------------------------------------------

function harness(role = 'staff', { normalizeHtml = false } = {}) {
  const elements = new Map();
  const observers = new Map();
  let document;
  class Element {
    constructor(id = '') {
      this.id = id; this.value = ''; this.disabled = false; this.checked = false;
      this.textContent = ''; this.style = {}; this.handlers = {}; this.classes = new Set(); this.ids = [];
      this.classList = { contains: name => this.classes.has(name),
        add: name => { this.classes.add(name); observers.get(this)?.(); },
        remove: name => { this.classes.delete(name); observers.get(this)?.(); } };
      if (id) elements.set(id, this);
    }
    set className(value) { this.classes = new Set(value.split(/\s+/)); }
    set innerHTML(value) {
      this.html = value;
      for (const id of this.ids) elements.delete(id);
      this.ids = [];
      for (const match of value.matchAll(/\bid="([^"]+)"/g)) {
        this.ids.push(match[1]);
        const element = new Element(match[1]);
        const tag = value.slice(value.lastIndexOf('<', match.index), value.indexOf('>', match.index));
        element.disabled = /\bdisabled(?:\s|$)/.test(tag);
        element.checked = /\bchecked(?:\s|$)/.test(tag);
      }
      const first = value.match(/<option value="([^"]*)"/);
      if (first) this.value = first[1];
    }
    get innerHTML() {
      const html = this.html || '';
      return normalizeHtml ? html.replace(/\s(checked|disabled|selected)(?=[\s>])/g, ' $1=""') : html;
    }
    addEventListener(event, handler) { this.handlers[event] = handler; }
    querySelectorAll() { return []; }
    querySelector() { return null; }
    focus() { document.activeElement = this; }
    remove() { elements.delete(this.id); for (const id of this.ids) elements.delete(id); }
  }
  document = { activeElement: null, getElementById: id => elements.get(id) || null, querySelectorAll: () => [],
    createElement: () => new Element(), body: { style: {}, appendChild: el => elements.set(el.id, el) } };
  new Element('blueTeamContent');
  const timers = new Map();
  const calls = [];
  let nextTimer = 0;
  let status = fixture();
  let statusHandler = null;
  let postHandler = null;
  const context = { document, URL, AbortController, Set, Map, Promise, JSON, Date, currentCourseId: 'course-one', escHtml: esc,
    localStorage: { getItem: () => 'test-token' },
    window: { crypto, BlueTeamApi: { create: () => ({ listRuns: async () => ({ tier: role, runs: [] }) }) },
      BlueTeamBoard: { mount: () => ({ destroy() {} }) }, console: { warn() {} } },
    MutationObserver: class {
      constructor(fn) { this.fn = fn; }
      observe(el) { this.el = el; observers.set(el, this.fn); }
      disconnect() { observers.delete(this.el); }
    },
    Modal: { open(id) { elements.get(id).classList.add('active'); }, close(el) { (typeof el === 'string' ? elements.get(el) : el)?.classList.remove('active'); } },
    setTimeout(fn, delay) { const id = ++nextTimer; timers.set(id, { fn, delay }); return id; },
    clearTimeout(id) { timers.delete(id); },
    fetch: async (url, options = {}) => {
      calls.push({ url, ...options });
      if (url === '/api/caldera-authoring/status') return { ok: true, json: async () => ({ configured: false }) };
      // Split on '?' FIRST. The operations status path now carries
      // ?adversary_id=… whenever a profile is selected, and a matcher that only
      // knew the bare path would send that request down the POST branch and
      // throw "Unexpected request" instead of answering it.
      if (url.split('?')[0].endsWith('/status')) {
        const payload = statusHandler ? await statusHandler() : clone(status);
        return { ok: true, json: async () => payload };
      }
      if (options.method === 'POST') {
        const body = JSON.parse(options.body);
        const payload = postHandler ? await postHandler(url, body) : url.endsWith('/caldera-agents/batch')
          ? { results: body.targets.map(target => ({ ...target, job: { ...target, status: 'queued', message: 'Queued' } })) }
          : { batch_id: 'batch-one', results: body.lane_ids.map(lane_id => ({ lane_id, operation_id: `op-${lane_id}`, status: 'running' })) };
        return { ok: !payload.httpStatus, status: payload.httpStatus || 202, json: async () => payload };
      }
      throw new Error('Unexpected request: ' + url);
    },
  };
  vm.createContext(context); vm.runInContext(source, context);
  const api = context.window.CleBlueTeam;
  return { api, context, calls, timers, el: id => elements.get(id), setStatus(value) { status = value; },
    setStatusHandler(fn) { statusHandler = fn; }, setPostHandler(fn) { postHandler = fn; },
    html: id => elements.get(id).innerHTML,
    ids: (islandId, prefix) => idsIn(elements.get(islandId).innerHTML, prefix),
    async open(mode = 'install') { await api.load(); await api.refreshConsoleStatus(); await (mode === 'install' ? api.showGroupCalderaAgents() : api.showCalderaAttack()); },
    change(id, value) { const el = elements.get(id); if (typeof value === 'boolean') el.checked = value; else el.value = value; return el.onchange({ target: el }); },
    click(id) { const el = elements.get(id); return el.onclick ? el.onclick() : el.handlers.click(); },
    submit() { return elements.get('classroomCalderaForm').onsubmit({ preventDefault() {} }); },
    async tick(delay) { const entry = [...timers].find(([, timer]) => timer.delay === delay); assert.ok(entry, 'Expected timer at ' + delay); timers.delete(entry[0]); await entry[1].fn(); },
  };
}

// ---- staff gating and the install request -------------------------------

test('classroom actions belong to staff on the Blue Team Board and students make no classroom requests', async () => {
  const h = harness(); await h.api.load();
  assert.match(h.el('blueTeamContent').innerHTML, /Group install agents/);
  assert.match(h.el('blueTeamContent').innerHTML, /Run Caldera attack/);
  assert.match(h.el('blueTeamContent').innerHTML, /lane&rsquo;s SIEM/);
  const student = harness('student'); await student.open(); await student.api.showCalderaAttack();
  assert.equal(student.el('classroomCalderaModal'), undefined);
  assert.equal(student.calls.filter(call => /caldera-(agents|operations)/.test(call.url)).length, 0);
});

test('a machine selects its VMs across selected lanes while row overrides and OS choices shape the exact request', async () => {
  const h = harness(); await h.open(); h.click('classroomCalderaSelectLanes');
  assert.equal(h.el(lid('lane-three')).disabled, true);
  h.change(mid('goad::dc01'), true); // DC01 in two lanes, differing name case.
  h.change(mid('goad::ws01'), true); // WS01 in two lanes, unknown OS.
  assert.equal(h.el('classroomCalderaSubmit').disabled, true);
  assert.match(h.el('classroomCalderaSummary').textContent, /Choose Windows or Linux for 2/);
  h.change(moid('goad::ws01'), 'windows');
  h.change(tid('lane-two', 200), false); // deselect second lane DC01.
  assert.equal(h.el('classroomCalderaSubmit').disabled, false);
  assert.equal(h.el(tid('lane-one', 102)).disabled, true); // stopped sensor
  await h.submit();
  const request = h.calls.find(call => call.method === 'POST');
  assert.equal(request.url, '/api/cle/courses/course-one/incidents/caldera-agents/batch');
  assert.equal(request.headers.Authorization, 'Bearer test-token');
  assert.deepEqual(JSON.parse(request.body), { targets: [
    { lane_id: 'lane-one', vm_id: 100, platform: 'windows' }, { lane_id: 'lane-one', vm_id: 101, platform: 'windows' },
    { lane_id: 'lane-two', vm_id: 201, platform: 'windows' },
  ] });
  assert.equal(h.el('classroomCalderaSubmit').disabled, true);
  assert.match(h.el('classroomCalderaResults').innerHTML, /3 queued/);
  await h.submit(); assert.equal(h.calls.filter(call => call.method === 'POST').length, 1);
  h.api.closeClassroomCaldera();
});

test('one machine and several individual machines can be chosen; clearing an explicit OS blocks submission', async () => {
  const h = harness(); await h.open(); h.change(lid('lane-one'), true);
  h.change(tid('lane-one', 100), true); h.change(tid('lane-one', 101), true);
  h.change(toid('lane-one', 101), 'linux');
  assert.equal(h.el('classroomCalderaSubmit').disabled, false);
  h.change(toid('lane-one', 100), '');
  assert.equal(h.el('classroomCalderaSubmit').disabled, true);
  h.change(toid('lane-one', 100), 'windows'); await h.submit();
  assert.equal(JSON.parse(h.calls.find(call => call.method === 'POST').body).targets[1].platform, 'linux');
  h.api.closeClassroomCaldera();
});

test('individual target overrides survive adding another lane carrying the same machine', async () => {
  const h = harness(); await h.open(); h.change(lid('lane-one'), true);
  h.change(mid('goad::dc01'), true); h.change(tid('lane-one', 100), false);
  h.change(lid('lane-two'), true);
  assert.equal(h.el(tid('lane-one', 100)).checked, false);
  assert.equal(h.el(tid('lane-two', 200)).checked, true);
  await h.submit();
  assert.deepEqual(JSON.parse(h.calls.find(call => call.method === 'POST').body).targets,
    [{ lane_id: 'lane-two', vm_id: 200, platform: 'windows' }]);
  h.api.closeClassroomCaldera();
});

/**
 * The step 2 header and the step 2 checkboxes state the same fact twice, so
 * they must be computed once.
 *
 * The header used to print state.machines.size, while every row's checkbox is
 * derived from state.targets instead -- deliberately, so that unticking a
 * machine's last row down in Targets clears the machine box as well. The two
 * disagree the moment that happens: the set still holds the key the instructor
 * ticked, so the header went on reading "1 of 3 selected" above three empty
 * boxes, and there was nothing on screen left to untick to make it say zero.
 * The set itself must stay (applyClassroomMachineSelection needs it when the
 * lane selection changes), so it is the DISPLAYED count that has to come from
 * the rows' own derivation.
 */
test('the Machines header counts the boxes actually shown as ticked, not the keys the instructor once ticked', async () => {
  const h = harness(); await h.open(); h.change(lid('lane-one'), true);
  const count = () => (h.html('classroomCalderaMachines').match(/class="cal-count[^"]*">([^<]*)</) || [])[1];
  const ticked = () => h.ids('classroomCalderaMachines', 'classroomMachine-').filter(id => h.el(id).checked);
  const total = h.ids('classroomCalderaMachines', 'classroomMachine-').length;
  assert.equal(count(), `0 of ${total} selected`);

  h.change(mid('goad::dc01'), true);
  assert.equal(count(), `1 of ${total} selected`);
  assert.deepEqual(ticked(), [mid('goad::dc01')]);

  // vm 100 is DC01's ONLY available row, because lane-one is the only selected
  // lane -- so unticking it leaves the machine with no selected target at all.
  h.change(tid('lane-one', 100), false);
  assert.deepEqual(ticked(), [], 'the row derivation clears the machine box');
  assert.equal(count(), `0 of ${total} selected`,
    'and the header may not go on claiming a selection no box on screen is showing');
  assert.doesNotMatch(h.html('classroomCalderaMachines'), /cal-count is-ok/,
    'the "something is selected" styling has to follow the same number');
  h.api.closeClassroomCaldera();
});

test('browser HTML normalization does not recreate unchanged selectors during polling, but changed inventory still updates them', async () => {
  const h = harness('staff', { normalizeHtml: true });
  await h.open(); h.change(lid('lane-one'), true); h.change(mid('goad::dc01'), true);
  const os = h.el(toid('lane-one', 100));
  const checkbox = h.el(tid('lane-one', 100));
  os.focus();
  assert.match(h.el('classroomCalderaTargets').innerHTML, /checked=""/);
  await h.tick(5000);
  assert.equal(h.el(toid('lane-one', 100)), os, 'An unchanged poll must preserve the OS selector');
  assert.equal(h.el(tid('lane-one', 100)), checkbox, 'An unchanged poll must preserve the target checkbox');
  assert.equal(h.context.document.activeElement, os);
  const data = fixture(); data.lanes[0].targets[0].runnable = false; data.lanes[0].targets[0].power_state = 'stopped';
  h.setStatus(data); await h.tick(5000);
  assert.notEqual(h.el(toid('lane-one', 100)), os, 'A changed target must render the new inventory');
  assert.equal(h.el(tid('lane-one', 100)).disabled, true);
  assert.equal(h.el(tid('lane-one', 100)).checked, false);
  h.api.closeClassroomCaldera();
});

test('live status removes stopped targets from submission and busy jobs cannot be selected twice', async () => {
  const h = harness(); const data = fixture();
  data.lanes[0].jobs = [{ vm_id: 100, status: 'running' }]; h.setStatus(data);
  await h.open(); h.click('classroomCalderaSelectLanes'); h.change(mid('goad::dc01'), true);
  assert.equal(h.el(tid('lane-one', 100)).disabled, true);
  assert.match(h.el('classroomCalderaSummary').textContent, /^1 VM/);
  data.lanes[1].targets[0].runnable = false; data.lanes[1].targets[0].power_state = 'stopped';
  h.setStatus(data); await h.tick(5000);
  assert.equal(h.el('classroomCalderaSubmit').disabled, true);
  await h.submit(); assert.equal(h.calls.filter(call => call.method === 'POST').length, 0);
  h.api.closeClassroomCaldera();
});

test('partial install failures and check-in warnings are escaped and persist beside successful jobs', async () => {
  const h = harness(); await h.open(); h.click('classroomCalderaSelectLanes'); h.change(mid('goad::dc01'), true);
  h.setPostHandler(async () => ({ results: [
    { lane_id: 'lane-one', vm_id: 100, job: { vm_id: 100, status: 'completed', agent: { paw: 'paw', host: 'DC01' }, warnings: ['<img onerror=bad>'] } },
    { lane_id: 'lane-two', vm_id: 200, error: '<script>unavailable</script>' },
  ] }));
  await h.submit();
  const html = h.el('classroomCalderaResults').innerHTML;
  assert.match(html, /Caldera confirmed check-in: DC01/); assert.match(html, /&lt;img/); assert.match(html, /&lt;script/);
  assert.doesNotMatch(html, /<img|<script/); h.api.closeClassroomCaldera();
});

// ---- launching an exercise ----------------------------------------------

test('an attack launches the selected adversary only on selected lanes with ready agents', async () => {
  const h = harness(); const data = fixture(); data.lanes[1].agents = []; h.setStatus(data);
  await h.open('attack'); h.click('classroomCalderaSelectLanes'); h.change('classroomCalderaAdversary', 'adversary-one');
  assert.equal(h.el(lid('lane-two')).disabled, true); await h.submit();
  const request = h.calls.find(call => call.method === 'POST'); const body = JSON.parse(request.body);
  assert.equal(request.url, '/api/cle/courses/course-one/incidents/caldera-operations');
  assert.deepEqual(body.lane_ids, ['lane-one']); assert.equal(body.adversary_id, 'adversary-one');
  assert.match(body.request_id, /^[a-f0-9-]{36}$/); assert.equal(h.el('classroomCalderaSubmit').disabled, true);
  h.api.closeClassroomCaldera();
});

test('an ambiguous launch reuses its request id even after closing and reopening', async () => {
  const h = harness(); await h.open('attack'); h.click('classroomCalderaSelectLanes'); h.change('classroomCalderaAdversary', 'adversary-one');
  h.setPostHandler(async () => { throw new Error('Connection closed'); }); await h.submit();
  const first = JSON.parse(h.calls.find(call => call.method === 'POST').body);
  h.api.closeClassroomCaldera(); await h.api.showCalderaAttack();
  assert.match(h.el('classroomCalderaSubmit').textContent, /Retry launch request/);
  assert.equal(h.el('classroomCalderaAdversary').disabled, true);
  h.setPostHandler(null); await h.submit();
  const posts = h.calls.filter(call => call.method === 'POST'); assert.deepEqual(JSON.parse(posts[1].body), first);
  h.api.closeClassroomCaldera();
});

test('a definitive rejected launch unlocks selection so the instructor can correct and resubmit it', async () => {
  const h = harness(); await h.open('attack'); h.click('classroomCalderaSelectLanes'); h.change('classroomCalderaAdversary', 'adversary-one');
  h.setPostHandler(async () => ({ httpStatus: 409, error: 'An agent stopped checking in' })); await h.submit();
  assert.match(h.el('classroomCalderaError').textContent, /The launch was rejected/);
  assert.equal(h.el('classroomCalderaAdversary').disabled, false);
  await h.tick(1500); h.setPostHandler(null); await h.submit();
  const posts = h.calls.filter(call => call.method === 'POST').map(call => JSON.parse(call.body));
  assert.notEqual(posts[0].request_id, posts[1].request_id);
  h.api.closeClassroomCaldera();
});

test('operation status errors are visible and terminal cleanup does not offer a batch stop', async () => {
  const h = harness(); const data = fixture(); data.operations_error = 'Could not refresh operations';
  data.lanes[0].operations = [{ batch_id: 'batch-one', operation_id: 'op-one', status: 'cleanup' }];
  h.setStatus(data); await h.open('attack');
  assert.match(h.el('classroomCalderaError').textContent, /Could not refresh operations/);
  assert.equal(h.el('classroomStop0'), undefined);
  h.api.closeClassroomCaldera();
});

test('batch stop addresses only the lanes in that batch and renders current per-lane status', async () => {
  const h = harness(); const data = fixture();
  data.lanes[0].operations = [{ batch_id: 'batch-one', operation_id: 'op-one', adversary_name: '<b>Exercise</b>', status: 'running', started_at: '2026-09-06T10:00:00Z' }];
  data.lanes[1].operations = [{ batch_id: 'batch-two', operation_id: 'op-two', status: 'finished' }]; h.setStatus(data);
  await h.open('attack'); assert.match(h.el('classroomCalderaResults').innerHTML, /&lt;b&gt;Exercise/);
  // The lane cell is the shared two-line cell, not the raw lane name: one lane
  // may not read as "Student one · #10880" in the target table and as
  // "cle-cybr400-…" here.
  assert.match(h.el('classroomCalderaResults').innerHTML,
    /<span class="cal-cell-main">Student one<\/span><span class="cal-cell-sub"><span>#10880<\/span>/);
  await h.click('classroomStop0');
  const request = h.calls.find(call => call.method === 'POST');
  assert.equal(request.url, '/api/cle/courses/course-one/incidents/caldera-operations/stop');
  assert.deepEqual(JSON.parse(request.body), { lane_ids: ['lane-one'], batch_id: 'batch-one' });
  h.api.closeClassroomCaldera();
});

test('status failures block stale launches, pause polling, and can be recovered with refresh', async () => {
  const h = harness(); await h.open('attack'); h.click('classroomCalderaSelectLanes'); h.change('classroomCalderaAdversary', 'adversary-one');
  h.setStatusHandler(async () => { throw new Error('Unavailable'); }); await h.tick(5000);
  assert.equal(h.el('classroomCalderaSubmit').disabled, true); await h.tick(5000); await h.tick(5000);
  assert.match(h.el('classroomCalderaError').textContent, /Automatic updates paused/); assert.equal(h.timers.size, 0);
  h.setStatusHandler(null); await h.click('classroomCalderaRefresh'); assert.equal(h.el('classroomCalderaSubmit').disabled, false);
  h.api.closeClassroomCaldera();
});

test('shared modal close clears timers and course changes abort status without rendering stale data', async () => {
  const h = harness(); await h.open(); h.context.Modal.close(h.el('classroomCalderaModal'));
  assert.equal(h.timers.size, 0); assert.equal(h.el('classroomCalderaModal'), undefined);
  let resolveOld; h.setStatusHandler(() => new Promise(resolve => { resolveOld = resolve; }));
  const pending = h.api.showCalderaAttack(); const request = h.calls.at(-1);
  h.context.currentCourseId = 'course-two'; h.api.reset(); assert.equal(request.signal.aborted, true);
  h.setStatusHandler(null); await h.open('attack'); const newOverlay = h.el('classroomCalderaModal');
  const old = fixture(); old.lanes[0].name = 'OLD COURSE'; resolveOld(old); await pending;
  assert.equal(h.el('classroomCalderaModal'), newOverlay); assert.doesNotMatch(h.el('classroomCalderaLanes').innerHTML, /OLD COURSE/);
  h.api.closeClassroomCaldera(); assert.equal(h.timers.size, 0);
});

// ---- step 1: grouping, search and facets --------------------------------

test('forty-four workstation lanes collapse into one environment group that can be closed, reopened and turned off', async () => {
  const h = harness(); h.setStatus(wall()); await h.open();
  assert.deepEqual(h.ids('classroomCalderaLanes', 'classroomGroup-').sort(),
    [gid('env:cyber-lab'), gid('env:goad-ad'), gid('env:workstation')].sort());
  assert.equal(h.ids('classroomCalderaLanes', 'classroomLane-').length, 46);
  assert.match(h.html('classroomCalderaLanes'), /Student workstations<\/span><\/button>/);
  assert.match(h.html('classroomCalderaLanes'), /44 lanes · 44 VMs/);

  h.click(gid('env:workstation'));
  assert.equal(h.ids('classroomCalderaLanes', 'classroomLane-').length, 2, 'A collapsed group draws no chips');
  assert.equal(h.el(lid('ws-10900')), undefined);
  assert.match(h.html('classroomCalderaLanes'), /aria-expanded="false"/);

  h.click(gid('env:workstation'));
  assert.equal(h.ids('classroomCalderaLanes', 'classroomLane-').length, 46);

  h.change('classroomCalderaGroupBy', 'none');
  assert.deepEqual(h.ids('classroomCalderaLanes', 'classroomGroup-'), [], 'Group by: none draws no headers');
  assert.equal(h.ids('classroomCalderaLanes', 'classroomLane-').length, 46);
  h.api.closeClassroomCaldera();
});

/**
 * aria-controls has to name an element that exists.
 *
 * A collapsed group renders no body at all -- that is the point of collapsing
 * it, and the reason the rebinding loop may only walk the rows that were drawn
 * -- so a toggle that kept a constant aria-controls pointed at an id no element
 * carried, in exactly the state a screen-reader user is most likely to follow
 * the reference from. The attribute is emitted only alongside the body it
 * names; aria-expanded="false" carries the collapsed state by itself.
 */
test('a collapsed group drops its aria-controls instead of naming a body it did not render', async () => {
  const h = harness(); h.setStatus(wall()); await h.open();
  const markup = () => h.html('classroomCalderaLanes');
  const dangling = () => [...markup().matchAll(/aria-controls="([^"]+)"/g)]
    .map(match => match[1]).filter(id => !idsIn(markup(), cid('GroupBody', '')).includes(id));
  assert.equal(idsIn(markup(), cid('GroupBody', '')).length, 3, 'three open groups, three bodies');
  assert.deepEqual(dangling(), [], 'an open group points at the body it drew');

  h.click(gid('env:workstation'));
  assert.equal(idsIn(markup(), cid('GroupBody', '')).length, 2, 'a collapsed group renders no body element');
  assert.deepEqual(dangling(), [], 'so its toggle must not keep pointing at one');
  assert.match(markup(), new RegExp(`id="${gid('env:workstation')}" aria-expanded="false">`),
    'the collapsed toggle carries its state on aria-expanded alone');

  h.click(gid('env:workstation'));
  assert.equal(idsIn(markup(), cid('GroupBody', '')).length, 3);
  assert.deepEqual(dangling(), [], 'and reopening restores the reference');
  h.api.closeClassroomCaldera();
});

test('the group checkbox is tri-state: it ticks every eligible lane, and unticking one makes it partial', async () => {
  const h = harness(); h.setStatus(wall()); await h.open();
  h.change(gaid('env:workstation'), true);
  assert.equal(h.el(gaid('env:workstation')).checked, true);
  assert.equal(h.el(gaid('env:workstation')).indeterminate, false);
  assert.equal(h.el(lid('ws-10943')).checked, true);
  assert.doesNotMatch(h.html('classroomCalderaLanes'), /cal-gpick is-partial/);
  assert.match(h.el('classroomCalderaLaneCount').textContent, /^44 of 46 selected/);

  h.change(lid('ws-10900'), false);
  assert.equal(h.el(gaid('env:workstation')).indeterminate, true,
    'indeterminate has no HTML attribute, so the render must set it as a property');
  assert.match(h.html('classroomCalderaLanes'), /cal-gpick is-partial/, 'and the class must mirror it in the markup');
  assert.equal(h.el(gaid('env:workstation')).checked, false);
  h.api.closeClassroomCaldera();
});

test('searching narrows the chips, reports the selected lanes it is hiding, and clearing restores them', async () => {
  const h = harness(); h.setStatus(wall()); await h.open();
  h.change(gaid('env:workstation'), true);
  h.change('classroomCalderaLaneSearch', '10905');
  assert.deepEqual(h.ids('classroomCalderaLanes', 'classroomLane-'), [lid('ws-10905')]);
  assert.equal(h.el('classroomCalderaLaneShown').textContent, 'Showing 1 of 46 lanes');
  assert.equal(h.el('classroomCalderaLaneHidden').textContent, '43 selected lanes hidden by the filter');
  // A search forces its group open and SAYS so by disabling the toggle, rather
  // than letting a press do nothing behind a header that cannot close.
  assert.match(h.html('classroomCalderaLanes'), new RegExp(`id="${gid('env:workstation')}"[^>]*disabled`));
  assert.equal(h.el('classroomCalderaSelectLanes').textContent, 'All matching (0)');

  h.click('classroomCalderaLaneSearchClear');
  assert.equal(h.ids('classroomCalderaLanes', 'classroomLane-').length, 46);
  assert.equal(h.el('classroomCalderaLaneHidden').textContent, '');
  assert.equal(h.el('classroomCalderaLaneSearch').value, '');
  h.api.closeClassroomCaldera();
});

test('attack-mode lane badges name the real reason and the facet counts agree with the chips', async () => {
  const h = harness(); h.setStatus(attackLanes()); await h.open('attack');
  const html = h.html('classroomCalderaLanes');
  assert.match(html, /badge-warning">no agent checked in</,
    'A powered-on lane with no agent must not be reported as not running');
  assert.match(html, /badge-muted">lane not running</);
  assert.match(html, /badge-warning">internet off</);
  assert.equal(h.el(lid('lane-ready')).disabled, false);
  assert.equal(h.el(lid('lane-noagent')).disabled, true);
  assert.equal(h.el(lid('lane-stopped')).disabled, true);
  assert.equal(h.el(lid('lane-nointernet')).disabled, true);
  assert.equal(h.el('classroomCalderaLaneFacetCount-all').textContent, '4');
  assert.equal(h.el('classroomCalderaLaneFacetCount-ready').textContent, '1');
  assert.equal(h.el('classroomCalderaLaneFacetCount-noagent').textContent, '2');
  assert.equal(h.el('classroomCalderaLaneFacetCount-off').textContent, '3');
  h.click('classroomCalderaLaneFacet-noagent');
  assert.deepEqual(h.ids('classroomCalderaLanes', 'classroomLane-').sort(),
    [lid('lane-noagent'), lid('lane-stopped')].sort());
  h.api.closeClassroomCaldera();
});

test('a lane that cannot be used still shows whose lane it is beside the reason badge', async () => {
  const h = harness(); h.setStatus(attackLanes()); await h.open('attack');
  const html = h.html('classroomCalderaLanes');
  // The regression the two-line chip fixes: the name used to be nowrap/ellipsis
  // on one line with the meta and the badge pinned flex:none beside it, so on an
  // unavailable lane the name was squeezed away entirely.
  const chip = html.slice(html.indexOf(`id="${lid('lane-stopped')}"`), html.indexOf(`id="${lid('lane-nointernet')}"`));
  assert.match(chip, /<span class="cal-lane-name">Student 3<\/span>/);
  assert.match(chip, /<span class="cal-lane-num">#3<\/span>/);
  assert.match(chip, /<span class="cal-lane-env">GOAD Active Directory<\/span>/);
  assert.match(chip, /badge-muted">lane not running</);
  h.api.closeClassroomCaldera();
});

// ---- step 2: machines keyed on machine_key -------------------------------

test('the same machine name in two environments is two checkboxes and only one lane is submitted', async () => {
  const h = harness(); h.setStatus(wall()); await h.open();
  h.change(lid('goad-lane'), true); h.change(lid('lab-lane'), true);
  assert.notEqual(mid('goad-ad::dc01'), mid('cyber-lab::dc01'));
  assert.ok(h.el(mid('goad-ad::dc01')), 'GOAD DC01 has its own machine checkbox');
  assert.ok(h.el(mid('cyber-lab::dc01')), 'The course lab DC01 has its own machine checkbox');
  assert.match(h.html('classroomCalderaMachines'), /<div class="cal-mgroup">GOAD Active Directory<\/div>/);
  assert.match(h.html('classroomCalderaMachines'), /<div class="cal-mgroup">Course lab<\/div>/);

  h.change(mid('goad-ad::dc01'), true);
  assert.equal(h.el(tid('goad-lane', 6001)).checked, true);
  assert.equal(h.el(tid('lab-lane', 7001)).checked, false,
    'Choosing one environment’s DC01 must not reach into another environment');
  await h.submit();
  assert.deepEqual(JSON.parse(h.calls.find(call => call.method === 'POST').body).targets,
    [{ lane_id: 'goad-lane', vm_id: 6001, platform: 'windows' }]);
  h.api.closeClassroomCaldera();
});

test('forty-four distinct workstation hostnames are one machine row, not forty-four', async () => {
  const h = harness(); h.setStatus(wall()); await h.open();
  h.change(gaid('env:workstation'), true);
  assert.deepEqual(h.ids('classroomCalderaMachines', 'classroomMachine-'), [mid('workstation::slot0')]);
  assert.match(h.html('classroomCalderaMachines'), /44 of 44 lanes/);
  assert.match(h.html('classroomCalderaMachines'), /Windows &middot; from template/,
    'The server already knows the OS, so the empty option answers instead of asking');
  h.change(mid('workstation::slot0'), true);
  assert.match(h.el('classroomCalderaSummary').textContent, /^44 VMs selected in 44 lanes\./);
  h.api.closeClassroomCaldera();
});

test('infrastructure machines are listed and flagged, never ticked for you, and still tickable by hand', async () => {
  const h = harness(); h.setStatus(wall()); await h.open();
  h.change(lid('goad-lane'), true);
  assert.equal(h.el(mid('goad-ad::elk')).checked, false, 'The SIEM is never auto-selected');
  assert.equal(h.el(mid('goad-ad::elk')).disabled, false, 'The SIEM is still selectable by hand');
  assert.match(h.html('classroomCalderaMachines'), /badge-gray">not a target \(SIEM\)</);
  assert.match(h.html('classroomCalderaMachines'), /cal-role cal-role-siem">SIEM</);
  assert.equal(h.el(tid('goad-lane', 6005)).checked, false);

  h.change(mid('goad-ad::elk'), true);
  assert.equal(h.el(tid('goad-lane', 6005)).checked, true);
  h.api.closeClassroomCaldera();
});

// ---- step 3: targets, quick actions and progress -------------------------

test('"Only missing agents" drops machines that already report an agent and never selects infrastructure', async () => {
  const h = harness(); h.setStatus(wall()); await h.open();
  h.change(lid('goad-lane'), true);
  h.click('classroomCalderaTargetsShown');
  assert.equal(h.el(tid('goad-lane', 6005)).checked, true, 'Select all shown really does select everything');

  h.click('classroomCalderaTargetsMissing');
  assert.equal(h.el(tid('goad-lane', 6001)).checked, true, 'DC01 has no agent and is still a target');
  assert.equal(h.el(tid('goad-lane', 6003)).checked, true);
  assert.equal(h.el(tid('goad-lane', 6004)).checked, true);
  assert.equal(h.el(tid('goad-lane', 6002)).checked, false, 'DC02 already has a fresh agent');
  assert.equal(h.el(tid('goad-lane', 6005)).checked, false, 'elk is infrastructure');
  assert.equal(h.el(tid('goad-lane', 6006)).checked, false, 'the attack box is infrastructure');
  assert.match(h.el('classroomCalderaSummary').textContent, /^3 VMs selected in 1 lane\./);
  h.api.closeClassroomCaldera();
});

test('"Retry failed" skips a failed install whose agent has since checked in', async () => {
  const h = harness(); h.setStatus(wall()); await h.open();
  h.change(lid('goad-lane'), true);
  h.click('classroomCalderaTargetsRetry');
  assert.equal(h.el(tid('goad-lane', 6001)).checked, true);
  assert.equal(h.el(tid('goad-lane', 6002)).checked, false,
    'A job that recorded a failure while its agent was beaconing must not be reinstalled');
  assert.match(h.el('classroomCalderaSummary').textContent, /^1 VM selected in 1 lane\./);
  h.api.closeClassroomCaldera();
});

test('the Agent column reads a check-in rather than the job that claims it failed', async () => {
  const h = harness(); h.setStatus(wall()); await h.open();
  h.change(lid('goad-lane'), true);
  assert.match(h.html(cid('TargetAgent', 'goad-lane:6002')), /badge-success">checked in<\/span> <span class="cal-ago">/);
  assert.match(h.html(cid('TargetAgent', 'goad-lane:6001')), /badge-danger">install failed</);
  assert.match(h.html(cid('TargetAgent', 'goad-lane:6003')), /badge-gray">none</);
  h.api.closeClassroomCaldera();
});

test('sorting the target table moves aria-sort and toggles direction, and a poll keeps the scroll position', async () => {
  const h = harness(); await h.open(); h.change(lid('lane-one'), true);
  assert.equal(sortOrder(h.html('classroomCalderaTargets'), 'lane'), 'ascending');
  assert.equal(sortOrder(h.html('classroomCalderaTargets'), 'machine'), 'none');

  h.click(cid('Sort', 'machine'));
  assert.equal(sortOrder(h.html('classroomCalderaTargets'), 'machine'), 'ascending');
  assert.equal(sortOrder(h.html('classroomCalderaTargets'), 'lane'), 'none');
  h.click(cid('Sort', 'machine'));
  assert.equal(sortOrder(h.html('classroomCalderaTargets'), 'machine'), 'descending');

  const scroller = h.el('classroomCalderaTargetScroll');
  scroller.scrollTop = 120; scroller.scrollLeft = 40;
  const data = fixture();
  data.lanes[0].targets[2].runnable = true; data.lanes[0].targets[2].power_state = 'running';
  h.setStatus(data); await h.tick(5000);
  const after = h.el('classroomCalderaTargetScroll');
  assert.notEqual(after, scroller, 'Changed inventory really did rebuild the table');
  assert.equal(after.scrollTop, 120);
  assert.equal(after.scrollLeft, 40);
  h.api.closeClassroomCaldera();
});

test('a progress card names the student, the lane number and the machine, and reconciles a false failure', async () => {
  const h = harness(); h.setStatus(wall()); await h.open();
  const html = h.html('classroomCalderaResults');
  assert.match(html, /<strong class="cal-job-name">Student one · #10880 · DC01<\/strong>/);
  assert.match(html, /<strong class="cal-job-name">Student one · #10880 · DC02<\/strong>/);
  assert.doesNotMatch(html, /VM 6001/, 'A machine the lane still lists is never named by its Proxmox id');
  assert.match(html, /badge-success">agent checked in</);
  assert.match(html, /2 failed/);
  assert.match(html, /1 install recorded a failure but the agent has since checked in/);
  assert.match(html, /holds the script/, 'A timeout gets the detached-agent hint');
  assert.doesNotMatch(html, /<img|<svg/i);
  h.api.closeClassroomCaldera();
});

// ---- step 1 (attack): the profile card -----------------------------------

test('the profile summary sentence is assembled from the server rollup, with the step count from the ordering', async () => {
  const h = harness(); h.setStatus(attackFixture()); await h.open('attack');
  h.change('classroomCalderaAdversary', 'profile-summary');
  // Six steps against tactic counts that sum to three: summary.tactics skips
  // abilities with no tactic, so the step count can only come from ability_ids.
  assert.equal(summaryLine(h.html('classroomCalderaAdversaries')),
    '6 steps across 2 tactics: Discovery (2), Credential Access (1); '
    + 'runs on Windows (psh, cmd) and Linux (sh). 1 ability could not be described: not in the ability catalog.');
  h.api.closeClassroomCaldera();
});

test('a profile with no rollup at all says so instead of reporting zero tactics', async () => {
  const h = harness(); const data = attackFixture();
  data.adversaries[0].summary = null; data.abilities = {}; data.abilities_error = 'The ability catalog could not be read';
  h.setStatus(data); await h.open('attack');
  h.change('classroomCalderaAdversary', 'profile-summary');
  assert.equal(summaryLine(h.html('classroomCalderaAdversaries')),
    '6 steps. This server does not report tactics or platforms for profiles.');
  h.api.closeClassroomCaldera();
});

test('the ability list renders every step in order and escapes a name carrying markup', async () => {
  const h = harness(); const data = attackFixture();
  data.abilities['ab-1'].name = '<img src=x onerror=alert(1)>Find local users';
  h.setStatus(data); await h.open('attack');
  h.change(lid('lane-one'), true);
  h.change('classroomCalderaAdversary', 'profile-summary');
  const html = h.html('classroomCalderaAdversaries');
  assert.match(html, /<ol class="cal-abilities">/);
  assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;Find local users/);
  assert.doesNotMatch(html, /<img|<svg/i);
  assert.match(html, /<li class="cal-ab is-unknown">/);
  assert.match(html, /<span class="cal-ab-name">Not in the ability catalog<\/span>/);
  assert.match(html, /<span class="cal-ab-tech">ab-6<\/span>/);
  assert.match(html, /<span class="cal-plats">Windows &middot; Linux<\/span>/);
  assert.match(html, /<span class="cal-ab-tactic">Lateral Movement<\/span>/);
  assert.match(html, /<span class="cal-ab-techname">OS Credential Dumping<\/span>/);
  h.api.closeClassroomCaldera();
});

test('the fit verdict names the steps a missing platform will skip, and clears when every step can run', async () => {
  const h = harness(); h.setStatus(attackFixture()); await h.open('attack');
  h.change(lid('lane-one'), true);
  h.change('classroomCalderaAdversary', 'profile-summary');
  assert.deepEqual(fitNote(h.html('classroomCalderaAdversaries')), { tone: 'cal-note-warn',
    text: '1 of 6 steps will be skipped because no Linux agent is checked in: Dump credentials.'
      + ' 1 ability could not be checked: the catalog does not say what they run on.' });
  assert.match(h.html('classroomCalderaAdversaries'), /<li class="cal-ab is-skipped">/);

  h.change('classroomCalderaAdversary', 'profile-windows');
  assert.deepEqual(fitNote(h.html('classroomCalderaAdversaries')), { tone: 'cal-note-ok',
    text: 'Every step has an executor for the agents checked in: 1 Windows machine.' });
  assert.doesNotMatch(h.html('classroomCalderaAdversaries'), /is-skipped/);
  h.api.closeClassroomCaldera();
});

test('with no lanes chosen the card asks for lanes rather than guessing a verdict', async () => {
  const h = harness(); h.setStatus(attackFixture()); await h.open('attack');
  h.change('classroomCalderaAdversary', 'profile-windows');
  assert.deepEqual(fitNote(h.html('classroomCalderaAdversaries')), { tone: 'cal-note-info',
    text: 'Select lanes below to see which agent platforms are ready.' });
  h.api.closeClassroomCaldera();
});

test('choosing a profile asks the status endpoint for that profile, once, without adding an /api/ literal', async () => {
  const h = harness(); const data = attackFixture(); data.abilities = {}; h.setStatus(data);
  await h.open('attack');
  const before = h.calls.filter(call => /caldera-operations\/status/.test(call.url)).length;
  h.change('classroomCalderaAdversary', 'profile-summary');
  await h.tick(250);
  const statuses = h.calls.filter(call => /caldera-operations\/status/.test(call.url));
  assert.equal(statuses.length, before + 1);
  assert.equal(statuses.at(-1).url,
    '/api/cle/courses/course-one/incidents/caldera-operations/status?adversary_id=profile-summary');
  // The payload still cannot describe the profile, but it was FETCHED for it —
  // which is the condition that stops an unreadable catalog becoming a 250ms
  // poll forever.
  assert.ok([...h.timers.values()].some(timer => timer.delay === 5000),
    'A server that cannot answer is polled at the normal interval, not four times a second');
  assert.ok(![...h.timers.values()].some(timer => timer.delay === 250));
  h.api.closeClassroomCaldera();

  const literals = [...new Set(source.match(/'\/api\/[^']*'/g) || [])].sort();
  assert.deepEqual(literals, ["'/api/caldera-authoring/status'", "'/api/cle/courses/{courseId}/incidents'"],
    'Classroom requests go through laneCalderaRequest on a BASE_PATH-relative path; a query string is not a new endpoint');
});

// ---- regressions: claims the dialog must never make again ----------------

/**
 * A payload from a server that predates per-target agents: the lane sends its
 * roster and nothing else. Every roster row here is BOUND (it carries a vm_id),
 * which is what makes the hostname collision below a lie rather than a guess.
 */
const legacyLane = (laneId, kind, targets, agents) => ({ lane_id: laneId, name: laneId, group: `g-${laneId}`,
  lane_number: Number(String(laneId).replace(/\D/g, '')) || 1, vxlan_id: 1, family: 'cle-cybr400', kind,
  created_at: '2026-09-01T09:00:00Z', student: null, runnable: true, lifecycle_eligible: true,
  internet_enabled: true, retained_after_failure: false, lane_status: 'running', jobs: [], operations: [],
  agents, targets });

const bareTarget = (vmId, name) => ({ vm_id: vmId, name, type: 'qemu', node: 'pve1', role: 'dc',
  platform: 'windows', os: 'Windows Server 2019', infra: false, source: 'environment', slot: null,
  template_name: 'win2019', runnable: true, power_state: 'running', agent: null, last_job: null });

test('an agent already bound to another VM is never attached to this one by its hostname', async () => {
  const h = harness(); await h.open();
  h.change(lid('lane-one'), true);
  // lane-one's only roster agent is {paw:'paw-one', host:'ws01', vm_id:100} — the
  // server bound it to DC01. WS01 is vm 101 and arrives with agent:null, which is
  // the server's definitive answer: it checked pawFor(lane, 101) and found none.
  assert.match(h.html(cid('TargetAgent', 'lane-one:101')), /badge-gray">none</,
    'A roster row the server bound to a different VM must not be reported as this machine’s check-in');
  assert.doesNotMatch(h.html(cid('TargetAgent', 'lane-one:101')), /checked in/);
  assert.match(h.html(cid('TargetAgent', 'lane-one:100')), /badge-success">checked in</,
    'DC01’s own per-target agent is still read');
  const chip = h.html('classroomCalderaLanes');
  assert.match(chip.slice(chip.indexOf(`id="${lid('lane-one')}"`)), /3 VMs · 1 agent/,
    'One roster agent cannot be counted as two machines checked in');
  // The consequence the count only hints at: a VM with no agent that reads as
  // fresh is deselected by "Only missing agents" and skipped by "Retry failed",
  // so it silently leaves the batch and is reported as done.
  h.click('classroomCalderaTargetsMissing');
  assert.equal(h.el(tid('lane-one', 101)).checked, true, 'WS01 has no agent and must still be an install target');
  h.api.closeClassroomCaldera();
});

test('the hostname fallback still rescues an older server whose roster names no VM at all', async () => {
  const h = harness(); const data = fixture();
  // The case the fallback exists for: no per-target agent anywhere, and a roster
  // row that carries a host and no vm_id. Without it an installed class reads as
  // entirely uninstalled.
  data.lanes[0].targets.forEach(target => { target.agent = null; });
  data.lanes[0].agents = [{ paw: 'paw-one', host: 'WS01', platform: 'windows', group: 'lane-group-one',
    last_seen: seenAt(), trusted: true, fresh: true }];
  h.setStatus(data); await h.open();
  h.change(lid('lane-one'), true);
  assert.match(h.html(cid('TargetAgent', 'lane-one:101')), /badge-success">checked in</);
  assert.match(h.html(cid('TargetAgent', 'lane-one:100')), /badge-gray">none</);
  h.api.closeClassroomCaldera();
});

test('a payload with no environment groups machines the same way it keys them, so no id is rendered twice', async () => {
  const h = harness(); const data = fixture();
  // Neither lane carries `environment` or `machine_key`: the legacy shape both
  // fallbacks exist for. They used to disagree — the key said `lane::dc01` while
  // the grid filed one under `kind:goad` and the other under `kind:challenge` —
  // so the same element id was emitted twice, the bind loop resolved both to one
  // element, and the first checkbox on screen installed on the other lane's VM.
  data.lanes = [legacyLane('L1', 'goad', [bareTarget(11, 'DC01')], []),
    legacyLane('L2', 'challenge', [bareTarget(12, 'DC01')], [])];
  h.setStatus(data); await h.open();
  h.change(lid('L1'), true); h.change(lid('L2'), true);
  const ids = h.ids('classroomCalderaMachines', 'classroomMachine');
  assert.deepEqual(ids, [mid('lane::dc01'), moid('lane::dc01')]);
  assert.equal(new Set(ids).size, ids.length, 'No two machine rows may share a DOM id');
  // And the surviving checkbox means what it says: one machine across both lanes.
  h.change(mid('lane::dc01'), true);
  assert.equal(h.el(tid('L1', 11)).checked, true);
  assert.equal(h.el(tid('L2', 12)).checked, true);
  await h.submit();
  assert.deepEqual(JSON.parse(h.calls.find(call => call.method === 'POST').body).targets,
    [{ lane_id: 'L1', vm_id: 11, platform: 'windows' }, { lane_id: 'L2', vm_id: 12, platform: 'windows' }]);
  h.api.closeClassroomCaldera();
});

test('a machine key that reaches the grid from two environments is still rendered once', async () => {
  const h = harness(); const data = fixture();
  // The shape a current server can send: an attached module VM keys under the
  // MODULE's key while its lane groups under the lane's own environment, so one
  // machine key arrives from two different groups.
  const attached = vmId => Object.assign(bareTarget(vmId, 'box'), { source: 'attached',
    machine_key: 'attached::box', machine_label: 'box', environment_key: 'mod' });
  data.lanes = [
    Object.assign(legacyLane('L1', 'goad', [attached(21)], []),
      { environment: { key: 'goad-ad', label: 'GOAD Active Directory', type: 'goad', lab: null } }),
    Object.assign(legacyLane('L2', 'challenge', [attached(22)], []),
      { environment: { key: 'cyber-lab', label: 'Course lab', type: 'challenge', lab: null } })];
  h.setStatus(data); await h.open();
  h.change(lid('L1'), true); h.change(lid('L2'), true);
  const ids = h.ids('classroomCalderaMachines', 'classroomMachine');
  assert.equal(new Set(ids).size, ids.length, 'No two machine rows may share a DOM id');
  assert.deepEqual(ids, [mid('attached::box'), moid('attached::box')]);
  assert.match(h.html('classroomCalderaMachines'), /2 of 2 lanes/);
  h.api.closeClassroomCaldera();
});

test('the attack box, a firewall and the SIEM each get their own role chip instead of all reading SIEM', async () => {
  const h = harness(); const data = fixture();
  // Exactly what a real GOAD lane sends: the server sets infra from
  // INFRASTRUCTURE_ROLES, which covers attacker, firewall, router, controller and
  // the evidence plane alike, so a UI that read infra before the role labelled
  // every one of them "SIEM" — and told an instructor the wrong thing about Kali.
  const infraTarget = (vmId, name, role) => Object.assign(bareTarget(vmId, name),
    { role, platform: 'linux', os: 'Debian', infra: true, template_name: 'debian',
      machine_key: `goad::${name.toLowerCase()}`, machine_label: name, environment_key: 'goad' });
  data.lanes[0].targets = [
    Object.assign(infraTarget(900, 'Attack box', 'attacker'), { source: 'attack_box', machine_key: 'goad::attack-box' }),
    infraTarget(901, 'fw', 'firewall'),
    infraTarget(902, 'elk', 'siem'),
    Object.assign(bareTarget(903, 'plumbing'), { role: '', infra: true, machine_key: 'goad::plumbing',
      machine_label: 'plumbing', environment_key: 'goad' }),
  ];
  h.setStatus(data); await h.open();
  h.change(lid('lane-one'), true);
  const html = h.html('classroomCalderaMachines');
  assert.match(html, /cal-role cal-role-atk">Attack box</);
  assert.match(html, /cal-role cal-role-siem">SIEM</);
  assert.match(html, /cal-role cal-role-other">firewall</,
    'A role nobody anticipated is shown in the neutral tint, not renamed to SIEM');
  assert.match(html, /cal-role cal-role-siem">Infrastructure</,
    'infra with no role at all is the one case that still falls back to the SIEM tint');
  assert.match(html, /badge-gray">not a target \(Attack box\)</);
  // The flag itself is unchanged: all four are still listed, flagged and unticked.
  assert.deepEqual([900, 901, 902, 903].map(vmId => h.el(tid('lane-one', vmId)).checked), [false, false, false, false]);
  h.api.closeClassroomCaldera();
});

test('an ability catalog the server could not read is reported as an outage, never as deleted abilities', async () => {
  const h = harness(); const data = attackFixture();
  // Shape fact 5: a failed catalog read leaves summary null and abilities {}, so
  // every id in the ordering misses. Saying "Not in the ability catalog" three
  // times is a confident claim that three named abilities were deleted from the
  // stockpile, when the stockpile simply did not answer — and it is stable, not
  // transient: the detail refetch has landed and the poll is back to 5000 ms.
  data.adversaries = [{ adversary_id: 'p1', name: 'Profile one', description: 'Three steps',
    ability_count: 3, ability_ids: ['ab-1', 'ab-2', 'ab-3'], summary: null }];
  data.abilities = {};
  data.abilities_error = 'The ability catalog could not be read: connect ECONNREFUSED';
  h.setStatus(data); await h.open('attack');
  h.change('classroomCalderaAdversary', 'p1');
  await h.tick(250);
  assert.equal(h.el('classroomCalderaError').textContent,
    'The ability catalog could not be read: connect ECONNREFUSED',
    'The outage must be named somewhere on screen');
  const html = h.html('classroomCalderaAdversaries');
  assert.doesNotMatch(html, /Not in the ability catalog/,
    'An unanswered catalog is not evidence that an ability is gone');
  assert.equal((html.match(/The ability catalog could not be read<\/span>/g) || []).length, 3);
  assert.match(html, /<span class="cal-ab-tech">ab-1<\/span>/, 'The id is still shown so it can be looked up by hand');
  h.api.closeClassroomCaldera();
});

test('a catalog that answered still names the one ability it does not hold', async () => {
  const h = harness(); h.setStatus(attackFixture()); await h.open('attack');
  h.change('classroomCalderaAdversary', 'profile-summary');
  const html = h.html('classroomCalderaAdversaries');
  assert.match(html, /<span class="cal-ab-name">Not in the ability catalog<\/span>/);
  assert.doesNotMatch(html, /The ability catalog could not be read/);
  assert.equal(h.el('classroomCalderaError').textContent, '');
  h.api.closeClassroomCaldera();
});

test('Enter in the profile filter narrows the list instead of launching the exercise on every lane', async () => {
  const h = harness(); h.setStatus(attackFixture()); await h.open('attack');
  h.click('classroomCalderaSelectLanes');
  h.change('classroomCalderaAdversary', 'profile-windows');
  // The exact state the trap needs: an enabled default submit button and a text
  // input inside the same <form>. Implicit submission then runs the batch launch
  // — one Caldera operation per selected lane, with no confirmation step.
  assert.equal(h.el('classroomCalderaSubmit').disabled, false);
  const search = h.el('classroomCalderaAdversarySearch');
  assert.equal(typeof search.onkeydown, 'function',
    'Every search box in this form must swallow Enter, not only the two added first');
  let prevented = 0;
  search.onkeydown({ key: 'Enter', preventDefault: () => { prevented++; } });
  assert.equal(prevented, 1);
  search.onkeydown();  // the harness calls handlers with no event at all
  // Escape clears the filter rather than closing the dialog, but only while
  // there is something to clear.
  search.value = 'worm';
  let stopped = 0;
  search.onkeydown({ key: 'Escape', preventDefault: () => { prevented++; }, stopPropagation: () => { stopped++; } });
  assert.equal(stopped, 1);
  assert.equal(search.value, '');
  assert.equal(h.calls.filter(call => call.method === 'POST').length, 0);
  h.api.closeClassroomCaldera();
});

test('a lane name carrying a double quote cannot break out of the chip attribute it is written into', async () => {
  const h = harness(); const data = fixture();
  // escHtml() is textContent -> innerHTML: & < > and nothing else. A value in
  // attribute position therefore has to go through escAttr(), and this is the
  // assertion that notices when one stops doing so — the whole tag is compared,
  // so a raw quote that closes title= and hangs an event handler on the label
  // fails here rather than in a browser.
  data.lanes[0].name = 'Lab "A" onmouseover=alert(1)';
  data.lanes[0].student = null;
  h.setStatus(data); await h.open();
  const html = h.html('classroomCalderaLanes');
  assert.ok(html.includes('<label class="cal-lane" title="Lab &quot;A&quot; onmouseover=alert(1)">'),
    'The lane chip’s title must be attribute-escaped');
  assert.doesNotMatch(html, /title="Lab "A"/);
  assert.deepEqual(h.ids('classroomCalderaLanes', 'classroomLane-'),
    [lid('lane-one'), lid('lane-two'), lid('lane-three')]);
  assert.equal(h.el(lid('lane-one')).disabled, false, 'and the chip is still a working control');
  h.api.closeClassroomCaldera();
});

test('an adversary id carrying a double quote cannot break out of its <option value>', async () => {
  const h = harness(); const data = attackFixture();
  // The other attribute-position value in this dialog, and the one that decides
  // which profile the whole class runs. Caldera owns this string; escHtml would
  // leave the quote raw, the option would close early, and the submitted
  // adversary_id would be whatever the browser salvaged from the wreckage.
  data.adversaries[0].adversary_id = 'worm" onx="1';
  h.setStatus(data); await h.open('attack');
  const html = h.html('classroomCalderaAdversaries');
  assert.ok(html.includes('<option value="worm&quot; onx=&quot;1"'),
    'The adversary id must be attribute-escaped');
  assert.doesNotMatch(html, /<option value="worm" onx/);
  h.api.closeClassroomCaldera();
});

// ---- the stylesheet the markup above depends on --------------------------

test('the .cal-* block in courses.html keeps the fixes this dialog depends on, and no raw hex', () => {
  // LF-normalised: git checks this page out as CRLF on Windows and the slice
  // assertions below would stop matching without saying why.
  const CRLF = String.fromCharCode(13, 10);
  const LF = String.fromCharCode(10);
  const page = fs.readFileSync(PAGE_PATH, 'utf8').split(CRLF).join(LF);
  const marker = page.indexOf('CALDERA CLASSROOM MODALS');
  assert.notEqual(marker, -1, 'The classroom modal stylesheet is gone from courses.html');
  // Sliced from the '/*' that OPENS the block's header comment, not from the
  // marker inside it: starting mid-comment leaves an unmatched '*/' in the
  // slice, and the comment stripper below then pairs it with the next '/*' and
  // eats a run of real declarations — which is how a banned selector quoted in
  // the header ("Deliberately NOT used: .badge-primary") ends up being read as
  // live CSS.
  const start = page.lastIndexOf('/*', marker);
  assert.notEqual(start, -1, 'The .cal-* block has lost its header comment');
  const end = page.indexOf('.info-box {', start);
  assert.ok(end > start, 'Could not find the end of the .cal-* block');
  const block = page.slice(start, end);

  // The profile card was clipped because .cal-panel is overflow:hidden, which
  // zeroes a flex item's automatic minimum size: the panels shrank instead of
  // the body scrolling. Without flex-shrink:0 here the last child of step 1 is
  // cut off again, and nothing in the JS can tell.
  const bodyRule = (block.match(/\.cal-body > \*\s*\{[^}]*\}/) || [])[0];
  assert.ok(bodyRule, '.cal-body > * rule is missing');
  assert.match(bodyRule, /flex-shrink:\s*0/);
  assert.match(bodyRule, /min-width:\s*0/);

  for (const selector of ['.cal-lanescroll', '.cal-lane-body', '.cal-lane-sub', '.cal-lane-num', '.cal-lane-env',
    '.cal-group-head', '.cal-gpick', '.cal-abilities', '.cal-role-siem', '.cal-c-agent', '.cal-note-ok',
    '.cal-job-hint', '.cal-mgroup', '.cal-sort-ind', '.cal-cell-main']) {
    assert.ok(block.includes(selector), `${selector} is referenced by blue-team.js but has no rule`);
  }

  // A token, or a color-mix() of a token, never a literal. The tints derive from
  // --danger/--warning/--info/--success so the dark-theme swap carries them, and
  // a hex here would be a value with no dark counterpart.
  assert.deepEqual(block.match(/#[0-9a-fA-F]{3,8}\b/g), null, 'The .cal-* block must contain no raw hex colour');

  const css = block.replace(/\/\*[\s\S]*?\*\//g, ' ');
  for (const banned of ['.badge-primary', '.alert-', '--bg-card-elevated', '.form-group']) {
    assert.ok(!css.includes(banned), `${banned} has no dark-theme rule and must not be used in this dialog`);
  }
});
