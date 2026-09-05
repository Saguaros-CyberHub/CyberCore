'use strict';

// Browser behavior with a small DOM and fake server. No live Caldera or VM is
// contacted: these tests cover selection, request scope and modal lifecycle.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '../modules/crucible/plugins/cle/public/js/blue-team.js'), 'utf8');
const clone = value => JSON.parse(JSON.stringify(value));
const esc = value => String(value ?? '').replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
const fixture = () => ({
  server_url: 'https://agent.test.example/', console_url: 'https://console.test.example/',
  lanes: [{
    lane_id: 'lane-one', name: 'First lane', lane_status: 'active', internet_enabled: true,
    group: 'lane-group-one', targets: [
      { vm_id: 100, name: 'Gateway', type: 'qemu', role: 'gateway', platform: 'linux' },
      { vm_id: 101, name: 'DC01', type: 'qemu', role: 'dc', platform: 'windows' },
      { vm_id: 102, name: 'Unknown OS', type: 'qemu', role: 'workstation', platform: null },
    ], agents: [], job: null,
  }, {
    lane_id: 'lane-two', name: 'Second lane', lane_status: 'active', internet_enabled: false,
    group: 'lane-group-two', targets: [{ vm_id: 201, name: 'Linux VM', type: 'qemu', platform: 'linux' }], agents: [], job: null,
  }, {
    lane_id: 'lane-stopped', name: 'Stopped lane', lane_status: 'suspended', targets: [], agents: [], job: null,
  }],
});

function harness(role = 'staff') {
  const elements = new Map();
  const observers = new Map();
  let document;
  class Element {
    constructor(id = '') {
      this.id = id;
      this.value = '';
      this.disabled = false;
      this.textContent = '';
      this.style = {};
      this.handlers = {};
      this.classes = new Set();
      this.ids = [];
      this.classList = {
        contains: name => this.classes.has(name),
        add: name => { this.classes.add(name); observers.get(this)?.(); },
        remove: name => { this.classes.delete(name); observers.get(this)?.(); },
      };
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
      }
      const first = value.match(/<option value="([^"]*)"/);
      if (first) this.value = first[1];
    }
    get innerHTML() { return this.html || ''; }
    addEventListener(event, handler) { this.handlers[event] = handler; }
    querySelectorAll() { return []; }
    querySelector() { return null; }
    focus() { document.activeElement = this; }
    remove() { elements.delete(this.id); for (const id of this.ids) elements.delete(id); }
  }
  document = {
    activeElement: null,
    getElementById: id => elements.get(id) || null,
    querySelectorAll: () => [],
    createElement: () => new Element(),
    body: { style: {}, appendChild: el => elements.set(el.id, el) },
  };
  new Element('blueTeamContent');
  const timers = new Map();
  const calls = [];
  let nextTimer = 0;
  let status = fixture();
  let statusHandler = null;
  let installHandler = null;
  const context = {
    document, URL, AbortController, Set, Promise, JSON, Date,
    currentCourseId: 'course-one', escHtml: esc,
    localStorage: { getItem: () => 'test-token' },
    window: {
      BlueTeamApi: { create: () => ({ listRuns: async () => ({ tier: role, runs: [] }) }) },
      BlueTeamBoard: { mount: () => ({ destroy() {} }) },
      console: { warn() {} },
    },
    MutationObserver: class {
      constructor(fn) { this.fn = fn; }
      observe(el) { this.el = el; observers.set(el, this.fn); }
      disconnect() { observers.delete(this.el); }
    },
    Modal: {
      open(id) { elements.get(id).classList.add('active'); },
      close(el) { (typeof el === 'string' ? elements.get(el) : el)?.classList.remove('active'); },
    },
    setTimeout(fn, delay) { const id = ++nextTimer; timers.set(id, { fn, delay }); return id; },
    clearTimeout(id) { timers.delete(id); },
    fetch: async (url, options = {}) => {
      calls.push({ url, ...options });
      if (url === '/api/caldera-authoring/status') return { ok: true, json: async () => ({ configured: false }) };
      if (url.endsWith('/caldera-agents/status')) {
        const payload = statusHandler ? await statusHandler() : clone(status);
        return { ok: true, json: async () => payload };
      }
      if (url.endsWith('/caldera-agents') && options.method === 'POST') {
        const payload = installHandler ? await installHandler() : { job: { job_id: 'job-one', vm_id: JSON.parse(options.body).vm_id, status: 'running', message: 'Starting guest install' } };
        return { ok: true, json: async () => payload };
      }
      throw new Error('Unexpected request: ' + url);
    },
  };
  vm.createContext(context);
  vm.runInContext(source, context);
  const api = context.window.CleBlueTeam;
  return {
    api, context, calls, timers, el: id => elements.get(id),
    setStatus(value) { status = value; },
    setStatusHandler(handler) { statusHandler = handler; },
    setInstallHandler(handler) { installHandler = handler; },
    async open() { await api.load(); await api.refreshConsoleStatus(); await api.showCalderaAgents(); },
    async tick(delay) {
      const entry = [...timers].find(([, timer]) => timer.delay === delay);
      assert.ok(entry, 'Expected a timer at ' + delay + 'ms');
      timers.delete(entry[0]);
      await entry[1].fn();
    },
    async submit() { return elements.get('laneCalderaForm').onsubmit({ preventDefault() {} }); },
  };
}

test('the Board offers Caldera Agent to course staff; students never request agent status', async () => {
  const staff = harness();
  await staff.api.load();
  assert.match(staff.el('blueTeamContent').innerHTML, /id="blueTeamCalderaAgent"/);
  const student = harness('student');
  await student.open();
  assert.equal(student.api.calderaAgentsHtml(), '');
  assert.equal(student.calls.filter(call => call.url.includes('/caldera-agents')).length, 0);
  assert.equal(student.el('laneCalderaModal'), undefined);
});

test('default selection skips gateway and suspended lanes and posts only the selected target', async () => {
  const h = harness();
  await h.open();
  assert.doesNotMatch(h.el('laneCalderaLane').innerHTML, /lane-stopped/);
  assert.equal(h.el('laneCalderaLane').value, 'lane-one');
  assert.equal(h.el('laneCalderaVm').value, '101');
  assert.equal(h.el('laneCalderaPlatform').value, 'windows');
  assert.equal(h.el('laneCalderaInstall').disabled, false);
  await h.submit();
  const posted = h.calls.find(call => call.method === 'POST');
  assert.equal(posted.url, '/api/cle/courses/course-one/incidents/caldera-agents');
  assert.deepEqual(JSON.parse(posted.body), { lane_id: 'lane-one', vm_id: 101, platform: 'windows' });
  assert.equal(posted.headers.Authorization, 'Bearer test-token');
  assert.equal(h.el('laneCalderaInstall').disabled, true);
  h.api.closeCalderaAgents();
});

test('an unknown platform requires a choice; switching lanes resets target and group', async () => {
  const h = harness();
  await h.open();
  h.el('laneCalderaVm').value = '102';
  h.el('laneCalderaVm').onchange();
  assert.equal(h.el('laneCalderaPlatform').value, '');
  assert.equal(h.el('laneCalderaInstall').disabled, true);
  await h.submit();
  assert.equal(h.calls.filter(call => call.method === 'POST').length, 0);
  h.el('laneCalderaPlatform').value = 'linux';
  h.el('laneCalderaPlatform').onchange();
  assert.equal(h.el('laneCalderaInstall').disabled, false);
  h.el('laneCalderaLane').value = 'lane-two';
  h.el('laneCalderaLane').onchange();
  assert.equal(h.el('laneCalderaVm').value, '201');
  assert.match(h.el('laneCalderaConnection').innerHTML, /lane-group-two/);
  assert.match(h.el('laneCalderaNetwork').textContent, /Internet is off/);
  assert.equal(h.el('laneCalderaInstall').disabled, true);
  await h.submit();
  assert.equal(h.calls.filter(call => call.method === 'POST').length, 0);
  const enabled = fixture();
  enabled.lanes[1].internet_enabled = true;
  h.setStatus(enabled);
  await h.tick(5000);
  assert.equal(h.el('laneCalderaInstall').disabled, false);
  await h.submit();
  assert.equal(JSON.parse(h.calls.find(call => call.method === 'POST').body).lane_id, 'lane-two');
  h.api.closeCalderaAgents();
});

test('script success is distinct from a Caldera check-in; unsafe console URLs and host HTML are not links or markup', async () => {
  const h = harness();
  const data = fixture();
  data.console_url = 'javascript:alert(1)';
  data.lanes[0].job = { status: 'completed', vm_id: 101, message: 'Script complete' };
  h.setStatus(data);
  await h.open();
  assert.doesNotMatch(h.el('laneCalderaConnection').innerHTML, /<a /);
  assert.match(h.el('laneCalderaJob').innerHTML, /Install script finished/);
  assert.match(h.el('laneCalderaJob').innerHTML, /No check-in has been confirmed/);
  data.console_url = 'https://console.test.example/';
  data.lanes[0].agents = [{ paw: 'agent-one', host: '<img onerror="bad">', platform: 'windows', last_seen: '2026-09-05T01:00:00Z' }];
  data.lanes[0].job.agent = data.lanes[0].agents[0];
  h.setStatus(data);
  await h.tick(5000);
  assert.match(h.el('laneCalderaConnection').innerHTML, /href="https:\/\/console.test.example\/" target="_blank" rel="noopener noreferrer"/);
  assert.match(h.el('laneCalderaJob').innerHTML, /Caldera confirmed check-in/);
  assert.match(h.el('laneCalderaAgents').innerHTML, /&lt;img/);
  assert.doesNotMatch(h.el('laneCalderaAgents').innerHTML, /<img/);
  h.api.closeCalderaAgents();
});

test('an unavailable status request can be retried and repeated failures pause automatic polling', async () => {
  const h = harness();
  h.setStatusHandler(async () => { throw new Error('Caldera connection refused'); });
  await h.open();
  assert.match(h.el('laneCalderaError').textContent, /Caldera connection refused/);
  assert.equal(h.el('laneCalderaInstall').disabled, true);
  await h.tick(5000);
  await h.tick(5000);
  assert.match(h.el('laneCalderaError').textContent, /Automatic updates paused/);
  assert.equal(h.timers.size, 0);
  h.setStatusHandler(null);
  await h.el('laneCalderaRefresh').onclick();
  assert.equal(h.el('laneCalderaInstall').disabled, false);
  h.api.closeCalderaAgents();
});

test('closing with the shared modal controller clears timers and course changes abort in-flight requests', async () => {
  const h = harness();
  await h.open();
  assert.ok(h.timers.size);
  h.context.Modal.close(h.el('laneCalderaModal'));
  assert.equal(h.el('laneCalderaModal'), undefined);
  assert.equal(h.timers.size, 0);
  let resolveStatus;
  h.setStatusHandler(() => new Promise(resolve => { resolveStatus = resolve; }));
  const pending = h.api.showCalderaAgents();
  const request = h.calls.at(-1);
  h.context.currentCourseId = 'course-two';
  h.api.reset();
  assert.equal(request.signal.aborted, true);
  resolveStatus(fixture());
  await pending;
  assert.equal(h.el('laneCalderaModal'), undefined);
  assert.equal(h.timers.size, 0);
});

test('late status from a closed modal cannot replace the next course modal', async () => {
  const h = harness();
  await h.api.load();
  await h.api.refreshConsoleStatus();
  let resolveOld;
  h.setStatusHandler(() => new Promise(resolve => { resolveOld = resolve; }));
  const old = h.api.showCalderaAgents();
  h.api.reset();
  h.context.currentCourseId = 'course-two';
  h.setStatusHandler(null);
  await h.open();
  const overlay = h.el('laneCalderaModal');
  const stale = fixture();
  stale.lanes[0].group = 'stale-course';
  resolveOld(stale);
  await old;
  assert.equal(h.el('laneCalderaModal'), overlay);
  assert.doesNotMatch(h.el('laneCalderaConnection').innerHTML, /stale-course/);
  h.api.closeCalderaAgents();
});
