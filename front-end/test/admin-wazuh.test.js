'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../public/js/admin/admin-wazuh.js'), 'utf8');
const clone = value => JSON.parse(JSON.stringify(value));
const ident = (kind, value) => `wazuh${kind}-${encodeURIComponent(value)}`;
const targetId = (kind, lane, machine) => ident(kind, JSON.stringify([lane, String(machine)]));
function fixture() {
  const payload = { manager: 'wazuh.example', console_url: 'https://wazuh.example/', lanes: ['one', 'two', 'stopped'].map((suffix, i) => ({
    lane_id: `lane-${suffix}`, name: `Lane ${suffix}`, runnable: i < 2, internet_enabled: true, jobs: [], agents: [],
    targets: [
      { vm_id: (i + 1) * 100, name: i === 1 ? 'dc01' : 'DC01', type: 'qemu', platform: 'windows', runnable: i < 2, power_state: i < 2 ? 'running' : 'stopped' },
      { vm_id: (i + 1) * 100 + 1, name: 'WS01', type: 'qemu', platform: null, runnable: i < 2, power_state: i < 2 ? 'running' : 'stopped' },
      { vm_id: (i + 1) * 100 + 2, name: 'Connected', type: 'qemu', platform: 'linux', runnable: i < 2, power_state: 'running', agent: { id: `agent-${suffix}`, status: 'active', lastKeepAlive: '2026-09-07T12:00:00Z' } },
      { vm_id: (i + 1) * 100 + 3, name: 'Offline', type: 'qemu', platform: 'linux', runnable: false, power_state: 'stopped' },
      { vm_id: (i + 1) * 100 + 4, name: 'Container', type: 'lxc', platform: 'linux', runnable: true, power_state: 'running' },
    ],
  })) };
  // The service correlates a saved job's manager/name/id with lane.agents and
  // projects the result onto target.agent. Keep all three in this fixture so
  // connected defaults exercise the actual server contract.
  payload.lanes.forEach(lane => {
    const target = lane.targets[2];
    target.agent.name = `cc-${lane.lane_id}-${target.vm_id}`;
    lane.agents.push(clone(target.agent));
    lane.jobs.push({ job_id: `saved-${target.vm_id}`, vm_id: target.vm_id, manager: payload.manager,
      agent_id: target.agent.id, agent_name: target.agent.name, status: 'completed', last_seen: target.agent.lastKeepAlive });
  });
  return payload;
}

// A production-shaped inventory: past the 40-lane auto-collapse threshold, five
// group keys covering all four derivations (course id, group id, name family,
// and the ungroupable remainder), and one lane per failure mode.
function wall() {
  const lanes = [];
  const push = (name, count, extra) => {
    for (let i = 0; i < count; i++) {
      const suffix = 10000 + lanes.length;
      lanes.push({ lane_id: `${name}-${i}`, name: `${name}-${suffix}`, runnable: true, internet_enabled: true,
        lane_number: suffix, family: name, jobs: [], agents: [], ...extra,
        targets: [
          { vm_id: suffix * 10, name: 'DC01', type: 'qemu', platform: 'windows', runnable: true, power_state: 'running' },
          { vm_id: suffix * 10 + 1, name: 'WS01', type: 'qemu', platform: 'linux', runnable: true, power_state: 'running' },
        ] });
    }
  };
  push('cle-cybr388', 14, { course_id: 'c1', course_code: 'CYBR388', course_name: 'Network Defense', kind: 'course' });
  push('cle-cybr400', 14, { course_id: 'c2', course_code: null, course_name: 'Incident Response', kind: 'course' });
  push('cle', 6, { kind: 'course' });
  push('ciab-cochise101', 8, { group_id: 'g1', group_label: 'Cochise 101', kind: 'ciab' });
  // No context fields at all: what an older server still sends.
  push('crucible', 4, {});
  lanes[0].targets[1].agent = { id: 'a1', name: 'connected-one', status: 'active', lastKeepAlive: '2026-09-07T12:00:00Z' };
  lanes[1].runnable = false;
  lanes[2].internet_enabled = false;
  lanes[3].jobs = [{ job_id: 'failed-one', vm_id: lanes[3].targets[0].vm_id, status: 'failed', error: 'boom' }];
  lanes[15].jobs = [{ job_id: 'running-one', vm_id: lanes[15].targets[0].vm_id, status: 'running' }];
  return { manager: 'wazuh.example', console_url: 'https://wazuh.example/', lanes };
}

// The three-lane fixture with production-shaped names but no server context, so
// grouping has to fall back to parsing the trailing -<vxlanId>.
function named() {
  const payload = fixture();
  ['cle-cybr388-10447', 'cle-cybr400-10711', 'cle-10871'].forEach((name, i) => { payload.lanes[i].name = name; });
  return payload;
}

const laneIds = h => h.el('wazuhLanes').ids.filter(value => value.startsWith('wazuhLane-'));
const targetKeys = h => h.el('wazuhTargets').ids.filter(value => value.startsWith('wazuhTarget-'))
  .map(value => JSON.parse(decodeURIComponent(value.slice('wazuhTarget-'.length))));
const groupIds = h => h.el('wazuhLanes').ids.filter(value => value.startsWith('wazuhGroup-'));

// The same lightweight VM/DOM approach as caldera-classroom-ui.test.js. It
// deliberately normalizes boolean attributes to catch innerHTML cache bugs.
function harness() {
  const elements = new Map(); const observers = new Map(); let document;
  class Element {
    constructor(id = '') {
      this.id = id; this.value = ''; this.checked = false; this.disabled = false;
      this.textContent = ''; this.ids = []; this.classes = new Set();
      this.classList = { contains: name => this.classes.has(name),
        add: name => { this.classes.add(name); observers.get(this)?.(); },
        remove: name => { this.classes.delete(name); observers.get(this)?.(); } };
      if (id) elements.set(id, this);
    }
    set className(value) { this.classes = new Set(value.split(/\s+/)); }
    set innerHTML(value) {
      this.html = value;
      const forget = child => { for (const id of child.ids || []) { const nested = elements.get(id); if (nested) forget(nested); elements.delete(id); } };
      forget(this); this.ids = [];
      for (const match of value.matchAll(/\bid="([^"]+)"/g)) {
        const name = match[1].replace(/&#39;/g, "'");
        this.ids.push(name); const child = new Element(name);
        const tag = value.slice(value.lastIndexOf('<', match.index), value.indexOf('>', match.index));
        child.disabled = /\bdisabled(?:\s|$)/.test(tag); child.checked = /\bchecked(?:\s|$)/.test(tag);
      }
    }
    get innerHTML() { return (this.html || '').replace(/\s(checked|selected|disabled)(?=[\s>])/g, ' $1=""'); }
    contains(child) { return this.ids.includes(child?.id); }
    focus() { document.activeElement = this; }
  }
  document = { activeElement: null, getElementById: id => elements.get(id) || null,
    createElement: () => new Element(), body: { appendChild: element => elements.set(element.id, element) } };
  let payload = fixture(); let getHandler; let postHandler; let timerId = 0;
  const timers = new Map(); const calls = [];
  const context = { document, URL, Date, Set, Map, WeakMap, Promise, JSON, encodeURIComponent,
    window: {},
    MutationObserver: class { constructor(fn) { this.fn = fn; } observe(el) { observers.set(el, this.fn); } },
    Modal: { open(id) { elements.get(id).classList.add('active'); }, close(element) { (typeof element === 'string' ? elements.get(element) : element).classList.remove('active'); } },
    setTimeout(fn, delay) { const id = ++timerId; timers.set(id, { fn, delay }); return id; },
    clearTimeout(id) { timers.delete(id); },
    api: async (method, url, body) => {
      calls.push({ method, url, body: clone(body || null) });
      if (method === 'GET') return getHandler ? getHandler() : clone(payload);
      if (postHandler) return postHandler(body);
      const results = body.targets.map(target => ({ ...target, job: { job_id: `job-${target.vm_id}`, vm_id: target.vm_id, status: 'queued', message: 'Queued for installation' } }));
      results.forEach(result => payload.lanes.find(lane => lane.lane_id === result.lane_id).jobs.push(result.job));
      return { results };
    },
  };
  vm.createContext(context); vm.runInContext(source, context);
  return { context, calls, timers, api: context.window.AdminWazuh, el: id => elements.get(id),
    setStatus(value) { payload = value; }, setGet(fn) { getHandler = fn; }, setPost(fn) { postHandler = fn; },
    change(id, value) { const e = elements.get(id); assert.ok(e, `Missing control ${id}`); if (typeof value === 'boolean') e.checked = value; else e.value = value; return e.onchange({ target: e }); },
    click(id) { return elements.get(id).onclick(); },
    submit() { return elements.get('wazuhForm').onsubmit({ preventDefault() {} }); },
    async tick() { const entry = [...timers].find(([, timer]) => timer.delay === 5000); assert.ok(entry, 'Expected 5 second poll'); timers.delete(entry[0]); return entry[1].fn(); },
  };
}

test('Admin toolbar loads its script after api helpers and opens with no silent selections', async () => {
  const html = fs.readFileSync(path.join(__dirname, '../public/admin.html'), 'utf8');
  assert.match(html, /onclick="AdminWazuh\.open\(\)">Deploy Wazuh agents/);
  assert.ok(html.indexOf('/js/admin/admin-core.js') < html.indexOf('/js/admin/admin-wazuh.js'));
  const h = harness(); await h.api.open();
  assert.equal(h.el('wazuhSubmit').disabled, true);
  assert.match(h.el('wazuhSummary').textContent, /^0 VMs/);
  assert.equal(h.el(ident('Lane', 'lane-one')).checked, false);
  assert.equal(h.el(ident('Lane', 'lane-stopped')).disabled, true);
  assert.deepEqual(h.calls, [{ method: 'GET', url: '/wazuh-agents', body: null }]);
});

test('matching names, individual exclusions and OS overrides produce the exact batch request', async () => {
  const h = harness(); await h.api.open(); h.click('wazuhAllLanes');
  h.change(ident('Machine', 'dc01'), true);
  h.change(ident('Machine', 'ws01'), true);
  assert.equal(h.el('wazuhSubmit').disabled, true);
  h.change(ident('MachineOs', 'ws01'), 'windows');
  h.change(targetId('Target', 'lane-two', 200), false);
  h.change(targetId('TargetOs', 'lane-one', 101), 'linux');
  await h.submit();
  assert.deepEqual(h.calls.find(call => call.method === 'POST'), { method: 'POST', url: '/wazuh-agents/batch', body: { targets: [
    { lane_id: 'lane-one', vm_id: 100, platform: 'windows' }, { lane_id: 'lane-one', vm_id: 101, platform: 'linux' }, { lane_id: 'lane-two', vm_id: 201, platform: 'windows' },
  ] } });
  assert.equal(h.el('wazuhSubmit').disabled, true);
  assert.match(h.el('wazuhResults').innerHTML, /3 queued/);
  await h.submit(); assert.equal(h.calls.filter(call => call.method === 'POST').length, 1);
});

test('missing agent selection skips connected, stopped, containers and unavailable lanes', async () => {
  const h = harness(); const data = fixture(); data.lanes[1].internet_enabled = false; h.setStatus(data);
  await h.api.open(); h.click('wazuhAllLanes'); h.click('wazuhMissing');
  assert.equal(h.el(ident('Lane', 'lane-two')).checked, false);
  assert.equal(h.el(targetId('Target', 'lane-one', 102)).checked, false);
  assert.equal(h.el(targetId('Target', 'lane-one', 103)).disabled, true);
  assert.equal(h.el(targetId('Target', 'lane-one', 104)), undefined);
  assert.match(h.el('wazuhSummary').textContent, /^2 VMs/);
  h.change(targetId('TargetOs', 'lane-one', 101), 'windows');
  await h.submit(); assert.equal(h.calls.find(call => call.method === 'POST').body.targets.length, 2);
});

test('polling check-ins keeps DOM controls, focus, OS overrides and explicit exclusions', async () => {
  const h = harness(); await h.api.open(); h.change(ident('Lane', 'lane-one'), true);
  h.change(ident('Machine', 'dc01'), true); h.change(targetId('Target', 'lane-one', 100), false);
  h.change(targetId('TargetOs', 'lane-one', 101), 'linux');
  const os = h.el(targetId('TargetOs', 'lane-one', 101)); os.focus();
  const data = fixture(); data.lanes[0].targets[2].agent.lastKeepAlive = '2026-09-07T12:00:05Z'; h.setStatus(data);
  await h.tick();
  assert.equal(h.el(targetId('TargetOs', 'lane-one', 101)), os);
  assert.equal(h.context.document.activeElement, os);
  assert.equal(os.value, 'linux');
  assert.match(h.el(targetId('Status', 'lane-one', 102)).innerHTML, /12:00:05Z/);
  h.change(ident('Lane', 'lane-two'), true);
  assert.equal(h.el(targetId('Target', 'lane-one', 100)).checked, false);
  assert.equal(h.el(targetId('Target', 'lane-two', 200)).checked, true);
});

test('stale or degraded status blocks installation and recovers without losing choices', async () => {
  const h = harness(); await h.api.open(); h.change(ident('Lane', 'lane-one'), true); h.change(ident('Machine', 'dc01'), true);
  h.setGet(async () => { throw new Error('gateway unavailable'); }); await h.tick();
  assert.equal(h.el('wazuhSubmit').disabled, true); assert.match(h.el('wazuhError').textContent, /gateway unavailable/);
  await h.submit(); assert.equal(h.calls.filter(call => call.method === 'POST').length, 0);
  h.setGet(null); await h.tick(); assert.equal(h.el('wazuhSubmit').disabled, false);
  const data = fixture(); data.configuration_error = 'Configure central Wazuh'; data.agents_error = 'Manager API unavailable'; h.setStatus(data); await h.tick();
  assert.match(h.el('wazuhError').textContent, /Configure central Wazuh\nManager API unavailable/);
  assert.equal(h.el('wazuhSubmit').disabled, true);
});

test('polls remove stopped and busy targets and never silently add new inventory', async () => {
  const h = harness(); await h.api.open(); h.click('wazuhAllLanes'); h.change(ident('Machine', 'dc01'), true);
  h.el('wazuhTargetScroll').scrollTop = 75; h.el('wazuhTargetScroll').scrollLeft = 30;
  const focusId = targetId('TargetOs', 'lane-one', 101); h.el(focusId).focus();
  const data = fixture(); data.lanes[0].targets[0].runnable = false;
  data.lanes[1].jobs = [{ vm_id: 200, job_id: 'busy', status: 'running' }];
  data.lanes[1].targets.push({ vm_id: 299, name: 'DC01', type: 'qemu', platform: 'windows', runnable: true });
  h.setStatus(data); await h.tick();
  assert.equal(h.el(targetId('Target', 'lane-one', 100)).disabled, true);
  assert.equal(h.el(targetId('Target', 'lane-two', 200)).disabled, true);
  assert.equal(h.el(targetId('Target', 'lane-two', 299)).checked, false);
  assert.equal(h.el('wazuhSubmit').disabled, true);
  assert.equal(h.el('wazuhTargetScroll').scrollTop, 75);
  assert.equal(h.el('wazuhTargetScroll').scrollLeft, 30);
  assert.equal(h.context.document.activeElement, h.el(focusId));
});

test('closing stops polls and reopening retrieves persisted jobs and check-ins', async () => {
  const h = harness(); await h.api.open(); h.change(ident('Lane', 'lane-one'), true); h.change(ident('Machine', 'dc01'), true); await h.submit();
  h.api.close(); assert.equal(h.timers.size, 0);
  const data = fixture(); data.lanes[0].jobs = [{ vm_id: 100, job_id: 'job-100', status: 'completed', message: 'Connected', agent_name: 'lane-one-100', last_seen: '2026-09-07T13:00:00Z' }]; h.setStatus(data);
  await h.api.open();
  assert.match(h.el('wazuhResults').innerHTML, /Agent check-in confirmed: lane-one-100/);
  assert.match(h.el('wazuhResults').innerHTML, /2026-09-07T13:00:00Z/);
  assert.equal(h.timers.size, 1);
  h.context.Modal.close(h.el('adminWazuhModal')); assert.equal(h.timers.size, 0, 'Escape/backdrop uses shared Modal close');
});

test('partial queue failures are escaped, persist on refresh and can be selected for retry', async () => {
  const h = harness(); await h.api.open(); h.click('wazuhAllLanes'); h.change(ident('Machine', 'dc01'), true);
  h.setPost(async () => ({ results: [
    { lane_id: 'lane-one', vm_id: 100, error: '<img src=x onerror=bad>' },
    { lane_id: 'lane-two', vm_id: 200, job: { job_id: 'job-200', vm_id: 200, status: 'queued' } },
  ] })); await h.submit();
  assert.match(h.el('wazuhResults').innerHTML, /&lt;img src=x onerror=bad&gt;/);
  await h.tick(); assert.match(h.el('wazuhResults').innerHTML, /&lt;img/);
  h.click('wazuhRetry'); await h.submit();
  assert.deepEqual(h.calls.filter(call => call.method === 'POST')[1].body.targets, [{ lane_id: 'lane-one', vm_id: 100, platform: 'windows' }]);
});

test('unconfigured, empty and unsafe console URL payloads are explicit and cannot submit', async () => {
  const h = harness(); h.setStatus({ manager: '', console_url: 'javascript:alert(1)', lanes: [] }); await h.api.open();
  assert.match(h.el('wazuhManager').innerHTML, /not configured/);
  assert.doesNotMatch(h.el('wazuhManager').innerHTML, /href=/);
  assert.match(h.el('wazuhLanes').innerHTML, /No deployed lanes/);
  assert.equal(h.el('wazuhSubmit').disabled, true);
});

test('batches above 200 targets cannot be submitted', async () => {
  const h = harness(); const data = fixture(); data.lanes = [data.lanes[0]];
  data.lanes[0].targets = Array.from({ length: 201 }, (_, i) => ({ vm_id: 1000 + i, name: 'Linux', type: 'qemu', platform: 'linux', runnable: true }));
  h.setStatus(data); await h.api.open(); h.click('wazuhAllLanes'); h.click('wazuhMissing');
  assert.equal(h.el('wazuhSubmit').disabled, true); assert.match(h.el('wazuhSummary').textContent, /at most 200/);
  await h.submit(); assert.equal(h.calls.filter(call => call.method === 'POST').length, 0);
  h.change(targetId('Target', 'lane-one', 1200), false); assert.equal(h.el('wazuhSubmit').disabled, false);
});

test('a status response started before submission cannot replace newly queued jobs', async () => {
  const h = harness(); await h.api.open(); h.change(ident('Lane', 'lane-one'), true); h.change(ident('Machine', 'dc01'), true);
  let finish; h.setGet(() => new Promise(resolve => { finish = resolve; }));
  const poll = h.tick(); await h.submit();
  assert.match(h.el('wazuhResults').innerHTML, /1 queued/);
  finish(fixture()); await poll;
  assert.match(h.el('wazuhResults').innerHTML, /1 queued/);
  assert.equal(h.timers.size, 1, 'Only one poll remains after overlapping requests');
  assert.equal(h.el('wazuhSubmit').disabled, true);
});

test('lanes group by course id, then group id, then name family, with the remainder last', async () => {
  const h = harness(); h.setStatus(wall()); await h.api.open();
  h.click('wazuhExpandAll');
  ['course:c1', 'course:c2', 'group:g1', 'family:cle', 'family:crucible']
    .forEach(key => assert.ok(h.el(ident('Group', key)), `Missing group ${key}`));
  const html = h.el('wazuhLanes').innerHTML;
  assert.match(html, /CYBR388 · Network Defense/);
  assert.match(html, /Incident Response/);          // course with a blank code
  assert.match(html, /Cochise 101/);
  const ids = laneIds(h);
  assert.equal(new Set(ids).size, ids.length, 'a lane may never be emitted twice');
  assert.equal(ids.length, 46);
  // Names alone still group when the server sends no context at all.
  const plain = harness(); plain.setStatus(named()); await plain.api.open();
  ['family:cle-cybr388', 'family:cle-cybr400', 'family:cle'].forEach(key => assert.ok(plain.el(ident('Group', key))));
});

test('large inventories open collapsed except where a selection lives, and polls never re-seed', async () => {
  const h = harness(); h.setStatus(wall()); await h.api.open();
  assert.deepEqual(laneIds(h), [], 'past the threshold every group starts closed');
  assert.match(h.el('wazuhLanes').innerHTML, /aria-expanded="false"/);
  h.click(ident('Group', 'course:c1'));
  assert.ok(laneIds(h).length > 0);
  h.change(ident('Lane', 'cle-cybr388-0'), true);
  await h.tick();
  assert.ok(h.el(ident('Lane', 'cle-cybr388-0')), 'a poll must not re-collapse an opened group');
  assert.equal(h.el(ident('Group', 'course:c2')).checked, false);
  h.click('wazuhCollapseAll');
  assert.deepEqual(laneIds(h), []);
  h.click('wazuhExpandAll');
  assert.equal(laneIds(h).length, 46);
  // A small inventory is never seeded, so the existing fixtures render in full.
  const small = harness(); await small.api.open();
  assert.equal(small.el(ident('Lane', 'lane-one')).disabled, false);
});

test('lane search matches every word against names, courses, machines and VM ids', async () => {
  const h = harness(); h.setStatus(wall()); await h.api.open();
  h.change('wazuhLaneSearch', 'CYBR388 dc01');
  assert.equal(laneIds(h).length, 14, 'a search forces matching groups open');
  assert.match(h.el('wazuhLaneShown').textContent, /Showing 14 of 46 lanes/);
  assert.equal(h.el(ident('Group', 'course:c1')).disabled, true, 'toggling is meaningless while searching');
  h.change('wazuhLaneSearch', 'cochise');
  assert.equal(laneIds(h).length, 8);
  h.change('wazuhLaneSearch', '100340');
  assert.equal(laneIds(h).length, 1, 'a VM id finds its lane');
  h.change('wazuhLaneSearch', 'zzz');
  assert.match(h.el('wazuhLanes').innerHTML, /No lanes match/);
  h.click('wazuhLaneNoMatchClear');
  assert.equal(h.el('wazuhLaneSearch').value, '');
  // Clearing the box restores the collapse state the search had overridden,
  // rather than dumping all 46 lanes back into the panel.
  assert.deepEqual(laneIds(h), []);
  assert.equal(groupIds(h).length, 5);
  h.change('wazuhLaneSearch', 'cle');
  h.click('wazuhLaneSearchClear');
  assert.equal(h.el('wazuhLaneSearch').value, '');
});

test('bulk selection follows the filter while Clear stays global and hidden picks are reported', async () => {
  const h = harness(); h.setStatus(wall()); await h.api.open();
  h.change('wazuhLaneSearch', 'cybr388');
  h.click('wazuhAllLanes');
  assert.match(h.el('wazuhAllLanes').textContent, /All matching \(0\)/);
  assert.match(h.el('wazuhLaneCount').textContent, /^12 selected · 14 of 46 shown/, 'two cybr388 lanes are ineligible');
  h.change('wazuhLaneSearch', 'cochise');
  assert.match(h.el('wazuhLaneHidden').textContent, /12 selected lanes hidden by the filter/);
  h.change(ident('GroupAll', 'group:g1'), true);
  assert.equal(h.el(ident('GroupAll', 'group:g1')).checked, true);
  h.change(ident('Lane', 'ciab-cochise101-0'), false);
  assert.equal(h.el(ident('GroupAll', 'group:g1')).indeterminate, true);
  assert.match(h.el('wazuhLanes').innerHTML, /waz-gpick is-partial/);
  h.change(ident('GroupAll', 'group:g1'), false);
  assert.equal(h.el('wazuhLaneCount').textContent.startsWith('12 selected'), true);
  h.click('wazuhClearLanes');
  assert.match(h.el('wazuhLaneCount').textContent, /^0 selected/, 'Clear is never scoped to the filter');
  h.click('wazuhLaneSearchClear');
  assert.equal(h.el('wazuhAllLanes').textContent, 'All available');
});

test('status pills count over the whole inventory and filter to their own predicate', async () => {
  const h = harness(); h.setStatus(wall()); await h.api.open(); h.click('wazuhExpandAll');
  assert.equal(h.el('wazuhLaneFacetCount-all').textContent, '46');
  assert.equal(h.el('wazuhLaneFacetCount-off').textContent, '2', 'one stopped lane, one with internet off');
  assert.equal(h.el('wazuhLaneFacetCount-failed').textContent, '1');
  assert.equal(h.el('wazuhLaneFacetCount-installing').textContent, '1');
  h.click('wazuhLaneFacet-off');
  assert.equal(laneIds(h).length, 2);
  assert.ok(h.el('wazuhLaneFacet-off').classes.has('active'));
  assert.equal(h.el('wazuhLaneFacet-off').ariaPressed, 'true');
  assert.equal(h.el('wazuhLaneFacet-all').ariaPressed, 'false');
  h.click('wazuhLaneFacet-failed');
  assert.equal(laneIds(h).length, 1);
  h.click('wazuhLaneFacet-all');
  assert.equal(laneIds(h).length, 46);
});

test('lane sorting orders within groups, defaults sensibly and puts unknown values last', async () => {
  const h = harness(); h.setStatus(wall()); await h.api.open();
  h.change('wazuhGroupBy', 'none');
  h.click('wazuhExpandAll');
  const numbers = () => laneIds(h).map(value => Number(decodeURIComponent(value.slice('wazuhLane-'.length)).split('-').pop()));
  h.change('wazuhLaneSort', 'number');
  assert.equal(h.el('wazuhLaneSortDir').textContent, '↑');
  const ascending = numbers();
  h.click('wazuhLaneSortDir');
  assert.equal(h.el('wazuhLaneSortDir').textContent, '↓');
  assert.deepEqual(numbers(), ascending.slice().reverse());
  h.change('wazuhLaneSort', 'missing');
  assert.equal(h.el('wazuhLaneSortDir').textContent, '↓', '"agents needed" answers itself from the top');
  h.change('wazuhLaneSort', 'created');
  assert.equal(laneIds(h).length, 46, 'no lane carries created_at, so none may be dropped');
  h.change('wazuhLaneSort', 'name');
  assert.equal(h.el('wazuhLaneSortDir').textContent, '↑');
});

test('the lane toolbar survives a poll with its text, sort and grouping intact', async () => {
  const h = harness(); h.setStatus(wall()); await h.api.open();
  const box = h.el('wazuhLaneSearch');
  h.change('wazuhLaneSearch', 'cybr');
  h.change('wazuhGroupBy', 'kind');
  h.change('wazuhLaneSort', 'number');
  const before = laneIds(h).length;
  await h.tick();
  assert.equal(h.el('wazuhLaneSearch'), box, 'the toolbar lives in the shell, not in the polled island');
  assert.equal(box.value, 'cybr');
  assert.equal(h.el('wazuhGroupBy').value, 'kind');
  assert.equal(h.el('wazuhLaneSort').value, 'number');
  assert.equal(laneIds(h).length, before);
  assert.deepEqual(groupIds(h), [ident('Group', 'kind:course')]);
});

test('target columns sort both ways without changing the queued batch', async () => {
  const h = harness(); await h.api.open(); h.click('wazuhAllLanes');
  h.change(ident('Machine', 'dc01'), true);
  h.change(ident('Machine', 'ws01'), true);
  h.change(ident('MachineOs', 'ws01'), 'windows');
  const byPayload = targetKeys(h);
  // vm 100 is DC01, 101 WS01, 102 Connected, 103 Offline, in both lanes.
  const machines = { 100: 'dc01', 101: 'ws01', 102: 'connected', 103: 'offline' };
  const shownMachines = () => targetKeys(h).map(([, vm]) => machines[Number(vm) % 100 + 100]);
  h.click(ident('Sort', 'machine'));
  assert.match(h.el('wazuhTargets').innerHTML, /aria-sort="ascending"/);
  assert.deepEqual(shownMachines(), ['connected', 'connected', 'dc01', 'dc01', 'offline', 'offline', 'ws01', 'ws01']);
  assert.deepEqual(targetKeys(h).slice(0, 2).map(([lane]) => lane), ['lane-one', 'lane-two'],
    'equal machine names keep payload order');
  h.click(ident('Sort', 'machine'));
  assert.match(h.el('wazuhTargets').innerHTML, /aria-sort="descending"/);
  assert.deepEqual(shownMachines(), ['ws01', 'ws01', 'offline', 'offline', 'dc01', 'dc01', 'connected', 'connected']);
  assert.deepEqual(targetKeys(h).slice(0, 2).map(([lane]) => lane), ['lane-one', 'lane-two'],
    'a stable tie-break means reversing the key order does not reverse the ties');
  h.click(ident('Sort', 'vm'));
  assert.deepEqual(targetKeys(h).map(([, vm]) => Number(vm)), [100, 101, 102, 103, 200, 201, 202, 203]);
  h.click(ident('Sort', 'lane'));
  assert.deepEqual(targetKeys(h), byPayload, 'the default view is payload order');
  await h.submit();
  // The wire format is computed from the selection, never from the view.
  assert.deepEqual(h.calls.find(call => call.method === 'POST').body.targets, [
    { lane_id: 'lane-one', vm_id: 100, platform: 'windows' },
    { lane_id: 'lane-one', vm_id: 101, platform: 'windows' },
    { lane_id: 'lane-two', vm_id: 200, platform: 'windows' },
    { lane_id: 'lane-two', vm_id: 201, platform: 'windows' },
  ]);
});

test('target filters scope the header checkbox and Select missing agents, and report what they hide', async () => {
  const h = harness(); await h.api.open(); h.click('wazuhAllLanes');
  assert.equal(h.el('wazuhTargetFacetCount-connected').textContent, '2');
  assert.match(h.el('wazuhTargetShown').textContent, /^8 targets$/);
  h.click('wazuhTargetFacet-connected');
  assert.equal(targetKeys(h).length, 2);
  assert.match(h.el('wazuhTargetShown').textContent, /Showing 2 of 8 targets/);
  assert.equal(h.el('wazuhMissing').disabled, true, 'nothing on screen needs an agent');
  assert.ok(h.el('wazuhTargetFacet-connected').classes.has('active'));
  assert.equal(h.el('wazuhTargetFacet-connected').ariaPressed, 'true');
  h.click('wazuhTargetFacet-missing');
  h.change('wazuhTargetSearch', 'ws01');
  assert.equal(targetKeys(h).length, 2);
  h.click('wazuhMissing');
  assert.match(h.el('wazuhSummary').textContent, /^2 VMs/, 'only the rows on screen were selected');
  h.change('wazuhTargetSearch', 'dc01');
  assert.match(h.el('wazuhTargetHidden').textContent, /2 selected targets hidden/);
  assert.match(h.el('wazuhHiddenNote').textContent, /2 selected targets in 2 lane\(s\) are hidden/);
  h.click('wazuhTargetSearchClear');
  h.click('wazuhTargetFacet-all');
  assert.equal(h.el('wazuhTargetHidden').textContent, '');
  assert.equal(h.el('wazuhHiddenNote').textContent, '');
});

test('the target header checkbox selects what is shown and reports a partial selection', async () => {
  const h = harness(); await h.api.open(); h.change(ident('Lane', 'lane-one'), true);
  h.click('wazuhTargetFacet-missing');
  h.change('wazuhTargetAll', true);
  assert.match(h.el('wazuhSummary').textContent, /^2 VMs/);
  assert.equal(h.el('wazuhTargetAll').indeterminate, false);
  h.change(targetId('Target', 'lane-one', 100), false);
  assert.equal(h.el('wazuhTargetAll').indeterminate, true);
  assert.equal(h.el('wazuhTargetAll').checked, false);
  h.change('wazuhTargetAll', false);
  assert.match(h.el('wazuhSummary').textContent, /^0 VMs/);
});

test('an empty or unmatched target table hides its toolbar and never throws on a poll', async () => {
  const h = harness(); h.setStatus({ manager: '', console_url: '', lanes: [] }); await h.api.open();
  assert.equal(h.el('wazuhTargetTools').hidden, true);
  assert.equal(h.el('wazuhTargetShown').textContent, '');
  const live = harness(); await live.api.open(); live.change(ident('Lane', 'lane-one'), true);
  assert.equal(live.el('wazuhTargetTools').hidden, false);
  live.change('wazuhTargetSearch', 'zzz');
  assert.match(live.el('wazuhTargets').innerHTML, /No targets match/);
  assert.equal(live.el('wazuhTargetAll'), undefined, 'no table means no header checkbox to bind');
  await live.tick();
  assert.match(live.el('wazuhTargets').innerHTML, /No targets match/);
});

test('lost queue response requires status refresh before retry; persisted job prevents duplicates', async () => {
  const h = harness(); await h.api.open(); h.change(ident('Lane', 'lane-one'), true); h.change(ident('Machine', 'dc01'), true);
  const data = fixture(); data.lanes[0].jobs = [{ vm_id: 100, job_id: 'persisted', status: 'queued' }];
  h.setPost(async () => { h.setStatus(data); throw new Error('Network disconnected'); });
  await h.submit();
  assert.equal(h.el('wazuhSubmit').disabled, true);
  assert.match(h.el('wazuhError').textContent, /Refresh status before retrying/);
  await h.submit(); assert.equal(h.calls.filter(call => call.method === 'POST').length, 1);
  await h.tick(); assert.match(h.el('wazuhResults').innerHTML, /1 queued/);
  assert.equal(h.el('wazuhSubmit').disabled, true);
});
