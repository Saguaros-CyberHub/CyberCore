'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const crypto = require('node:crypto');
const source = fs.readFileSync(path.join(__dirname, '../modules/crucible/plugins/cle/public/js/blue-team.js'), 'utf8');
const clone = value => JSON.parse(JSON.stringify(value));
const esc = value => String(value ?? '').replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));

function fixture() {
  return { server_url: 'https://agents.example/', adversaries: [{ adversary_id: 'adversary-one', name: 'Class discovery', description: 'Discovery steps', ability_count: 2 }],
    lanes: ['one', 'two', 'three'].map((suffix, i) => ({ lane_id: `lane-${suffix}`, name: `Lane ${suffix}`, group: `lane-group-${suffix}`,
      runnable: i < 2, lifecycle_eligible: i < 2, internet_enabled: true, jobs: [], operations: [],
      agents: i < 2 ? [{ paw: `paw-${suffix}`, host: 'ws01', platform: 'windows' }] : [],
      targets: [
        { vm_id: 100 * (i + 1), name: i === 1 ? 'dc01' : 'DC01', type: 'qemu', platform: 'windows', runnable: i < 2, power_state: i < 2 ? 'running' : 'stopped' },
        { vm_id: 100 * (i + 1) + 1, name: 'WS01', type: 'qemu', platform: null, runnable: i < 2, power_state: i < 2 ? 'running' : 'stopped' },
        { vm_id: 100 * (i + 1) + 2, name: 'sensor', type: 'qemu', platform: 'linux', runnable: false, power_state: 'stopped' },
      ] })) };
}

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
      if (url.endsWith('/status')) {
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
    async open(mode = 'install') { await api.load(); await api.refreshConsoleStatus(); await (mode === 'install' ? api.showGroupCalderaAgents() : api.showCalderaAttack()); },
    change(id, value) { const el = elements.get(id); if (typeof value === 'boolean') el.checked = value; else el.value = value; return el.onchange({ target: el }); },
    click(id) { const el = elements.get(id); return el.onclick ? el.onclick() : el.handlers.click(); },
    submit() { return elements.get('classroomCalderaForm').onsubmit({ preventDefault() {} }); },
    async tick(delay) { const entry = [...timers].find(([, timer]) => timer.delay === delay); assert.ok(entry, 'Expected timer at ' + delay); timers.delete(entry[0]); await entry[1].fn(); },
  };
}

test('classroom actions belong to staff on the Blue Team Board and students make no classroom requests', async () => {
  const h = harness(); await h.api.load();
  assert.match(h.el('blueTeamContent').innerHTML, /Group install agents/);
  assert.match(h.el('blueTeamContent').innerHTML, /Run Caldera attack/);
  assert.match(h.el('blueTeamContent').innerHTML, /lane&rsquo;s SIEM/);
  const student = harness('student'); await student.open(); await student.api.showCalderaAttack();
  assert.equal(student.el('classroomCalderaModal'), undefined);
  assert.equal(student.calls.filter(call => /caldera-(agents|operations)/.test(call.url)).length, 0);
});

test('matching names select multiple VMs across selected lanes while row overrides and OS choices shape the exact request', async () => {
  const h = harness(); await h.open(); h.click('classroomCalderaSelectLanes');
  assert.equal(h.el('classroomLane2').disabled, true);
  h.change('classroomMachine0', true); // DC01 in two lanes, differing name case.
  h.change('classroomMachine2', true); // WS01 in two lanes, unknown OS.
  assert.equal(h.el('classroomCalderaSubmit').disabled, true);
  assert.match(h.el('classroomCalderaSummary').textContent, /Choose Windows or Linux for 2/);
  h.change('classroomMachineOs2', 'windows');
  h.change('classroomTarget3', false); // deselect second lane DC01.
  assert.equal(h.el('classroomCalderaSubmit').disabled, false);
  assert.equal(h.el('classroomTarget2').disabled, true); // stopped sensor
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
  const h = harness(); await h.open(); h.change('classroomLane0', true);
  h.change('classroomTarget0', true); h.change('classroomTarget1', true);
  h.change('classroomTargetOs1', 'linux');
  assert.equal(h.el('classroomCalderaSubmit').disabled, false);
  h.change('classroomTargetOs0', '');
  assert.equal(h.el('classroomCalderaSubmit').disabled, true);
  h.change('classroomTargetOs0', 'windows'); await h.submit();
  assert.equal(JSON.parse(h.calls.find(call => call.method === 'POST').body).targets[1].platform, 'linux');
  h.api.closeClassroomCaldera();
});

test('individual target overrides survive adding another lane with matching machine names', async () => {
  const h = harness(); await h.open(); h.change('classroomLane0', true);
  h.change('classroomMachine0', true); h.change('classroomTarget0', false);
  h.change('classroomLane1', true);
  assert.equal(h.el('classroomTarget0').checked, false);
  assert.equal(h.el('classroomTarget3').checked, true);
  await h.submit();
  assert.deepEqual(JSON.parse(h.calls.find(call => call.method === 'POST').body).targets,
    [{ lane_id: 'lane-two', vm_id: 200, platform: 'windows' }]);
  h.api.closeClassroomCaldera();
});

test('browser HTML normalization does not recreate unchanged selectors during polling, but changed inventory still updates them', async () => {
  const h = harness('staff', { normalizeHtml: true });
  await h.open(); h.change('classroomLane0', true); h.change('classroomMachine0', true);
  const os = h.el('classroomTargetOs0');
  const checkbox = h.el('classroomTarget0');
  os.focus();
  assert.match(h.el('classroomCalderaTargets').innerHTML, /checked=""/);
  await h.tick(5000);
  assert.equal(h.el('classroomTargetOs0'), os, 'An unchanged poll must preserve the OS selector');
  assert.equal(h.el('classroomTarget0'), checkbox, 'An unchanged poll must preserve the target checkbox');
  assert.equal(h.context.document.activeElement, os);
  const data = fixture(); data.lanes[0].targets[0].runnable = false; data.lanes[0].targets[0].power_state = 'stopped';
  h.setStatus(data); await h.tick(5000);
  assert.notEqual(h.el('classroomTargetOs0'), os, 'A changed target must render the new inventory');
  assert.equal(h.el('classroomTarget0').disabled, true);
  assert.equal(h.el('classroomTarget0').checked, false);
  h.api.closeClassroomCaldera();
});

test('live status removes stopped targets from submission and busy jobs cannot be selected twice', async () => {
  const h = harness(); const data = fixture();
  data.lanes[0].jobs = [{ vm_id: 100, status: 'running' }]; h.setStatus(data);
  await h.open(); h.click('classroomCalderaSelectLanes'); h.change('classroomMachine0', true);
  assert.equal(h.el('classroomTarget0').disabled, true);
  assert.match(h.el('classroomCalderaSummary').textContent, /^1 VM/);
  data.lanes[1].targets[0].runnable = false; data.lanes[1].targets[0].power_state = 'stopped';
  h.setStatus(data); await h.tick(5000);
  assert.equal(h.el('classroomCalderaSubmit').disabled, true);
  await h.submit(); assert.equal(h.calls.filter(call => call.method === 'POST').length, 0);
  h.api.closeClassroomCaldera();
});

test('partial install failures and check-in warnings are escaped and persist beside successful jobs', async () => {
  const h = harness(); await h.open(); h.click('classroomCalderaSelectLanes'); h.change('classroomMachine0', true);
  h.setPostHandler(async () => ({ results: [
    { lane_id: 'lane-one', vm_id: 100, job: { vm_id: 100, status: 'completed', agent: { paw: 'paw', host: 'DC01' }, warnings: ['<img onerror=bad>'] } },
    { lane_id: 'lane-two', vm_id: 200, error: '<script>unavailable</script>' },
  ] }));
  await h.submit();
  const html = h.el('classroomCalderaResults').innerHTML;
  assert.match(html, /Caldera confirmed check-in: DC01/); assert.match(html, /&lt;img/); assert.match(html, /&lt;script/);
  assert.doesNotMatch(html, /<img|<script/); h.api.closeClassroomCaldera();
});

test('an attack launches the selected adversary only on selected lanes with ready agents', async () => {
  const h = harness(); const data = fixture(); data.lanes[1].agents = []; h.setStatus(data);
  await h.open('attack'); h.click('classroomCalderaSelectLanes'); h.change('classroomCalderaAdversary', 'adversary-one');
  assert.equal(h.el('classroomLane1').disabled, true); await h.submit();
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
