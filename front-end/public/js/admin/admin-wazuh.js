/* global api, Modal */
// Admin counterpart of CALDERA's three-step group installer. Jobs live on the
// server; the browser owns only selections and an open dialog's status poll.
(function () {
  'use strict';
  let state = null;
  const templates = new WeakMap();
  const el = id => document.getElementById(id);
  const esc = value => String(value ?? '').replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
  const key = (lane, target) => JSON.stringify([String(lane.lane_id), String(target.vm_id)]);
  const nameKey = target => String(target.name || '').trim().toLowerCase();
  const id = (kind, value) => `wazuh${kind}-${encodeURIComponent(value)}`;
  const jobs = lane => Array.isArray(lane.jobs) ? lane.jobs : [];
  const connected = target => ['active', 'connected'].includes(String(target.agent?.status || '').toLowerCase());
  const busy = (lane, target) => stat(lane).busyIds.has(String(target.vm_id));
  const laneAvailable = lane => lane.runnable === true && lane.internet_enabled !== false;
  const available = (lane, target) => laneAvailable(lane) && target.type === 'qemu' && target.runnable === true && !busy(lane, target);
  const openNow = s => state === s && s.overlay.classList.contains('active');
  const lanes = s => Array.isArray(s.payload?.lanes) ? s.payload.lanes : [];
  const rows = s => lanes(s).filter(lane => s.lanes.has(String(lane.lane_id)))
    .flatMap(lane => (lane.targets || []).filter(target => target.type === 'qemu').map(target => ({ lane, target })));
  const platform = (s, lane, target) => s.platforms.has(key(lane, target)) ? s.platforms.get(key(lane, target))
    : s.machinePlatforms.get(nameKey(target)) || (['windows', 'linux'].includes(target.platform) ? target.platform : '');
  const selected = s => rows(s).filter(({ lane, target }) => available(lane, target) && s.targets.has(key(lane, target)))
    .map(({ lane, target }) => ({ lane_id: lane.lane_id, vm_id: target.vm_id, platform: platform(s, lane, target) }));
  const badge = status => ({ queued: 'badge-yellow', running: 'badge-blue', completed: 'badge-green', failed: 'badge-red', active: 'badge-green', connected: 'badge-green' }[status] || 'badge-gray');

  // -- Derived data ---------------------------------------------------------
  // available() is called dozens of times per lane per render, and every call
  // used to rescan that lane's job list. Each payload lane is measured once
  // into a WeakMap instead; a poll replaces the lane objects, so the entries
  // invalidate themselves. submit() mutates lane.jobs in place, so it deletes.
  const laneStats = new WeakMap();
  // Every deployer names a lane `<family>-<vxlanId>`: cle-cybr388-10447,
  // ciab-cochise101-10502, crucible-10003. The server sends `family` outright;
  // parsing the name keeps grouping working against an older server.
  const NAME_SUFFIX = /^(.*?)-(\d+)$/;
  const familyOf = lane => lane.family || (String(lane.name || '').match(NAME_SUFFIX) || [])[1] || null;
  const laneNumber = lane => Number.isSafeInteger(lane.lane_number) ? lane.lane_number
    : Number.isSafeInteger(lane.vxlan_id) ? lane.vxlan_id
      : Number((String(lane.name || '').match(NAME_SUFFIX) || [])[2]) || null;
  const tokens = query => String(query || '').toLowerCase().split(/\s+/).filter(Boolean);
  const matches = (haystack, toks) => toks.every(token => haystack.includes(token));
  const cmpText = (a, b) => String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: 'base' });
  const errorsOf = results => new Set(results.filter(result => result.error).map(result => `${result.lane_id}|${result.vm_id}`));
  const KIND_LABEL = { course: 'Course', 'course-lab': 'Course lab', ciab: 'CiAB profile', group: 'Deployed group',
    challenge: 'Challenge', goad: 'GOAD', malware: 'Malware analysis', staging: 'Staging', lane: 'Other' };

  function stat(lane) {
    const cached = laneStats.get(lane);
    if (cached) return cached;
    const qemu = (lane.targets || []).filter(target => target.type === 'qemu');
    const busyIds = new Set(jobs(lane).filter(job => ['queued', 'running'].includes(job.status)).map(job => String(job.vm_id)));
    const failedIds = new Set(jobs(lane).filter(job => job.status === 'failed').map(job => String(job.vm_id)));
    const eligible = laneAvailable(lane);
    const selectable = qemu.filter(target => eligible && target.runnable === true && !busyIds.has(String(target.vm_id)));
    const measured = { eligible,
      reason: lane.runnable !== true ? 'lane not running' : lane.internet_enabled === false ? 'internet off' : '',
      running: qemu.filter(target => target.runnable === true).length,
      selectable: selectable.length,
      missing: selectable.filter(target => !connected(target)).length,
      connectedCount: qemu.filter(connected).length,
      busy: busyIds.size, failedJobs: failedIds.size, busyIds, failedIds,
      family: familyOf(lane), number: laneNumber(lane),
      // One lowercase string per lane, so a keystroke is a substring scan rather
      // than a walk of every target. Deliberately excludes lane_id: a UUID's hex
      // makes any short numeric query match half the inventory.
      haystack: [lane.name, familyOf(lane), lane.course_code, lane.course_name, lane.group_label,
        KIND_LABEL[lane.kind], lane.vxlan_id, ...qemu.flatMap(target => [target.name, target.vm_id, target.role])]
        .filter(value => value !== null && value !== undefined && value !== '').join(' ').toLowerCase() };
    laneStats.set(lane, measured);
    return measured;
  }

  // -- Grouping -------------------------------------------------------------
  // Keys are ids, never labels: a course label can resolve one poll later (or
  // not at all), and keying on it would split one course into two groups and
  // reshuffle collapse state underneath the operator.
  function groupKeyOf(s, lane) {
    const measured = stat(lane), by = s.view.groupBy;
    if (by === 'none') return 'all';
    if (by === 'kind') return `kind:${lane.kind || 'lane'}`;
    if (by === 'family') return measured.family ? `family:${measured.family}` : 'other';
    if (lane.course_id) return `course:${String(lane.course_id).toLowerCase()}`;
    if (lane.group_id) return `group:${lane.group_id}`;
    return measured.family ? `family:${measured.family}` : 'other';
  }

  // `members` is every lane with this key in the WHOLE inventory, not the
  // filtered or sorted subset: a label derived from "the first visible lane"
  // moves when the operator sorts or types.
  function groupLabelOf(key, members) {
    if (key === 'all') return '';
    if (key === 'other') return 'Other lanes';
    if (key.startsWith('kind:')) return KIND_LABEL[key.slice(5)] || 'Other';
    if (key.startsWith('family:')) return key.slice(7);
    const withCourse = members.find(lane => lane.course_code || lane.course_name);
    if (key.startsWith('course:') && withCourse) return [withCourse.course_code, withCourse.course_name].filter(Boolean).join(' · ');
    const withGroup = members.find(lane => lane.group_label);
    if (key.startsWith('group:') && withGroup) return withGroup.group_label;
    const families = members.map(lane => stat(lane).family).filter(Boolean);
    const best = [...new Set(families)]
      .sort((a, b) => families.filter(f => f === b).length - families.filter(f => f === a).length || cmpText(a, b))[0];
    return best || (key.startsWith('course:') ? 'Course' : 'Group');
  }

  // Counts are informational, so these predicates may overlap. The filter and
  // the pill count read the same map, which is the only way they cannot drift.
  const LANE_FACETS = {
    all: () => true,
    needs: measured => measured.eligible && measured.missing > 0,
    installing: measured => measured.busy > 0,
    failed: (measured, lane, errorLanes) => measured.failedJobs > 0 || errorLanes.has(String(lane.lane_id)),
    done: measured => measured.eligible && measured.missing === 0 && measured.connectedCount > 0,
    off: measured => !measured.eligible,
  };

  function laneView(s) {
    const view = s.view;
    const cacheKey = [s.payloadRevision, view.laneQuery, view.groupBy, view.laneSort, view.laneDir, view.laneFacet].join(String.fromCharCode(0));
    if (s.laneViewKey === cacheKey) return s.laneView;
    const inventory = lanes(s), toks = tokens(view.laneQuery);
    const errorLanes = new Set([...s.resultErrors].map(entry => entry.slice(0, entry.indexOf('|'))));
    const all = inventory.map((lane, index) => ({ lane, measured: stat(lane), index, key: groupKeyOf(s, lane) }));
    const membersByKey = new Map();
    all.forEach(row => { if (!membersByKey.has(row.key)) membersByKey.set(row.key, []); membersByKey.get(row.key).push(row.lane); });
    const labels = new Map([...membersByKey].map(([key, members]) => [key, groupLabelOf(key, members)]));
    const facet = LANE_FACETS[view.laneFacet] || LANE_FACETS.all;
    const matching = all.filter(row => facet(row.measured, row.lane, errorLanes) && matches(row.measured.haystack, toks));
    const direction = view.laneDir === 'desc' ? -1 : 1;
    // `name` is deliberately null: payload order already IS name order (the
    // route sorts by name, lane_id), and localeCompare would disagree with the
    // database collation on cle-cybr388-9999 versus cle-cybr388-10447.
    const getters = { name: null, number: row => row.measured.number,
      created: row => Number.isFinite(Date.parse(row.lane.created_at)) ? Date.parse(row.lane.created_at) : null,
      vms: row => row.measured.running, missing: row => row.measured.missing };
    const get = getters[view.laneSort];
    const compare = (a, b) => {
      if (!get) return (a.index - b.index) * direction;
      const x = get(a), y = get(b);
      if (x === y) return a.index - b.index;
      if (x === null || x === undefined) return 1;      // unknowns last in BOTH directions
      if (y === null || y === undefined) return -1;
      return (x - y) * direction;
    };
    const groups = new Map();
    matching.forEach(row => {
      if (!groups.has(row.key)) groups.set(row.key, { key: row.key, label: labels.get(row.key), order: row.key === 'other' ? 1 : 0, rows: [] });
      groups.get(row.key).rows.push(row);
    });
    const list = [...groups.values()].map(group => ({ ...group, rows: group.rows.slice().sort(compare) }))
      .sort((a, b) => a.order - b.order || cmpText(a.label, b.label));
    const facetCounts = Object.fromEntries(Object.keys(LANE_FACETS)
      .map(name => [name, all.filter(row => LANE_FACETS[name](row.measured, row.lane, errorLanes)).length]));
    s.laneViewKey = cacheKey;
    s.laneView = { groups: list, matching, matchingIds: new Set(matching.map(row => String(row.lane.lane_id))),
      allGroupKeys: [...membersByKey.keys()], facetCounts };
    return s.laneView;
  }

  // Collapse only once, only for a genuinely large inventory, and never over a
  // group the operator has already selected into. Polls must not re-close a
  // group somebody opened, so any manual toggle marks the seed as spent.
  function seedCollapse(s) {
    if (s.view.seeded) return;
    if (lanes(s).length <= 40) return;
    s.view.seeded = true;
    if (s.view.groupBy === 'none') return;
    laneView(s).groups.forEach(group => {
      if (!group.rows.some(row => s.lanes.has(String(row.lane.lane_id)))) s.view.collapsed.add(group.key);
    });
  }

  function setHtml(elementId, html) {
    const element = el(elementId);
    // Compare templates, not serialized innerHTML (browsers normalize it).
    if (templates.get(element) === html) return;
    const focused = document.activeElement;
    const focusId = focused?.id && element.contains(focused) ? focused.id : null;
    element.innerHTML = html;
    templates.set(element, html);
    if (focusId && !el(focusId)?.disabled) el(focusId)?.focus({ preventScroll: true });
  }

  function options(value, placeholder) {
    return `<option value=""${value ? '' : ' selected'}>${placeholder}</option>`
      + ['windows', 'linux'].map(os => `<option value="${os}"${value === os ? ' selected' : ''}>${os === 'windows' ? 'Windows' : 'Linux'}</option>`).join('');
  }

  function applyNames(s) {
    rows(s).forEach(({ lane, target }) => {
      const vmKey = key(lane, target);
      if (s.machines.has(nameKey(target)) && !s.excluded.has(vmKey) && available(lane, target) && !connected(target)) s.targets.add(vmKey);
    });
  }

  function close() {
    if (!state) return;
    clearTimeout(state.timer);
    state.timer = null;
    Modal.close(state.overlay);
  }

  function schedule(s) {
    clearTimeout(s.timer);
    if (openNow(s) && !s.submitting) s.timer = setTimeout(() => refresh(s), 5000);
  }

  async function open() {
    if (state) {
      if (openNow(state)) return;
      state.fresh = false;
      Modal.open(state.overlay.id);
      render(state);
      return refresh(state);
    }
    const overlay = document.createElement('div');
    overlay.id = 'adminWazuhModal';
    overlay.className = 'modal-overlay';
    overlay.innerHTML = `<div class="modal waz-modal" role="dialog" aria-modal="true" aria-labelledby="wazuhTitle">
      <div class="modal-header"><h3 id="wazuhTitle">Deploy Wazuh agents</h3>
        <button type="button" id="wazuhClose" class="modal-close" aria-label="Close Wazuh deployment">&times;</button></div>
      <form id="wazuhForm" class="waz-form">
        <div class="waz-body">
          <p class="waz-lede">Install Wazuh on running lane VMs across the platform. Pick lanes, pick machine names, then review individual targets.</p>
          <div id="wazuhManager" class="waz-manager"></div>
          <details class="waz-explain"><summary>What installation does</summary>
            <p>Downloads and installs the Windows or Linux agent, enrolls it with the configured Wazuh manager, and starts its service. Existing agents pointing to another manager are not migrated automatically; those targets report an error.</p>
            <p>Queue up to 200 targets at once; up to 4 installations run concurrently. Jobs continue when this window closes. Completion confirms an agent check-in; inspect collected events in Wazuh to verify your monitoring configuration.</p></details>
          <section class="waz-panel">
            <div class="waz-panel-head"><span class="waz-step">1</span><h4 class="waz-panel-title">Running lanes</h4><span id="wazuhLaneCount" class="waz-count"></span>
              <div class="waz-panel-actions"><button type="button" class="btn btn-outline btn-sm" id="wazuhAllLanes">All available</button><button type="button" class="btn btn-outline btn-sm" id="wazuhClearLanes">Clear</button></div></div>
            <div class="waz-tools" id="wazuhLaneTools">
              <div class="waz-search"><input type="search" id="wazuhLaneSearch" class="waz-searchbox" placeholder="Search lanes, machines, VM ids" autocomplete="off" aria-label="Filter lanes by lane name, course, machine name or VM id"><button type="button" class="waz-search-clear" id="wazuhLaneSearchClear" aria-label="Clear the lane filter">&times;</button></div>
              <label class="waz-toollabel">Group by <select id="wazuhGroupBy" class="waz-select waz-select-sm"><option value="section">Course / section</option><option value="kind">Lane kind</option><option value="family">Name prefix</option><option value="none">None</option></select></label>
              <label class="waz-toollabel">Sort <select id="wazuhLaneSort" class="waz-select waz-select-sm"><option value="name">Name</option><option value="number">Lane number</option><option value="created">Newest</option><option value="vms">Running VMs</option><option value="missing">Agents needed</option></select></label>
              <button type="button" class="btn btn-outline btn-sm waz-dir" id="wazuhLaneSortDir" aria-label="Sort ascending">&uarr;</button>
              <button type="button" class="btn btn-outline btn-sm" id="wazuhExpandAll">Expand all</button>
              <button type="button" class="btn btn-outline btn-sm" id="wazuhCollapseAll">Collapse all</button></div>
            <div class="filter-pills waz-facets" role="group" aria-label="Lane status filter"><button type="button" class="filter-pill active" id="wazuhLaneFacet-all">All <span class="pill-count" id="wazuhLaneFacetCount-all">0</span></button><button type="button" class="filter-pill" id="wazuhLaneFacet-needs">Needs agent <span class="pill-count" id="wazuhLaneFacetCount-needs">0</span></button><button type="button" class="filter-pill" id="wazuhLaneFacet-installing">Installing <span class="pill-count" id="wazuhLaneFacetCount-installing">0</span></button><button type="button" class="filter-pill" id="wazuhLaneFacet-failed">Failed <span class="pill-count" id="wazuhLaneFacetCount-failed">0</span></button><button type="button" class="filter-pill" id="wazuhLaneFacet-done">All connected <span class="pill-count" id="wazuhLaneFacetCount-done">0</span></button><button type="button" class="filter-pill" id="wazuhLaneFacet-off">Unavailable <span class="pill-count" id="wazuhLaneFacetCount-off">0</span></button></div>
            <p class="waz-shown"><span id="wazuhLaneShown" role="status"></span> <span id="wazuhLaneHidden" class="waz-flagged"></span></p>
            <div id="wazuhLanes" class="waz-panel-body waz-lanescroll"></div></section>
          <div id="wazuhMachines"></div>
          <section class="waz-panel">
            <div class="waz-panel-head"><span class="waz-step">3</span><h4 class="waz-panel-title">Targets</h4><span id="wazuhTargetCount" class="waz-count"></span>
              <div class="waz-panel-actions"><button type="button" class="btn btn-outline btn-sm" id="wazuhMissing">Select missing agents</button><button type="button" class="btn btn-outline btn-sm" id="wazuhRetry">Select failed targets</button><button type="button" class="btn btn-outline btn-sm" id="wazuhClearTargets">Clear</button></div></div>
            <div id="wazuhTargets"></div></section>
          <div id="wazuhResults" class="waz-results" aria-live="polite"></div>
        </div>
        <div class="waz-footer"><p id="wazuhError" role="alert"></p>
          <div class="waz-footer-row"><div class="waz-bar-state"><p id="wazuhSummary" class="waz-bar-text" role="status" aria-live="polite"></p><p id="wazuhUpdated" class="waz-hint"></p></div>
            <div class="waz-bar-actions"><button type="button" class="btn btn-outline btn-sm" id="wazuhRefresh">Refresh status</button><button type="submit" class="btn btn-primary" id="wazuhSubmit" disabled>Install selected agents</button></div></div></div>
      </form></div>`;
    document.body.appendChild(overlay);
    const s = { overlay, payload: null, fresh: false, refreshing: false, submitting: false, error: '', timer: null,
      revision: 0, updated: '', lanes: new Set(), machines: new Set(), targets: new Set(), excluded: new Set(),
      platforms: new Map(), machinePlatforms: new Map(), results: [],
      // payloadRevision invalidates the memoized lane view; resultErrors is the
      // batch-error index failed() reads. Both are refreshed wherever s.payload
      // or s.results is assigned, so no view can outlive the data behind it.
      payloadRevision: 0, resultErrors: new Set(), laneViewKey: null, laneView: null,
      // THE VIEW LIVES HERE, NEVER IN THE DOM. A poll landing mid-keystroke
      // rewrites the lane island; anything read back out of an input at render
      // time would be lost with it (blue-team.js:1230 documents the same rule).
      view: { laneQuery: '', groupBy: 'section', laneSort: 'name', laneDir: 'asc', laneFacet: 'all',
        collapsed: new Set(), seeded: false } };
    state = s;
    el('wazuhClose').onclick = close;
    el('wazuhRefresh').onclick = () => refresh(s);
    el('wazuhForm').onsubmit = event => { event.preventDefault(); return submit(s); };
    el('wazuhAllLanes').onclick = () => {
      if (s.submitting) return;
      // Scoped to what the operator can actually see. Collapse is presentation,
      // so a matching lane inside a closed group is still selected; the button
      // relabels itself to "All matching (N)" whenever a filter is narrowing.
      laneView(s).matching.filter(row => row.measured.eligible).forEach(row => s.lanes.add(String(row.lane.lane_id)));
      applyNames(s); render(s);
    };
    // Clear stays global: an operator clearing a filtered list means all of it.
    el('wazuhClearLanes').onclick = () => { if (!s.submitting) { s.lanes.clear(); render(s); } };
    // Bound ONCE, on the shell, because #wazuhLanes is rewritten by every poll.
    // Handlers are .onX properties and read nothing but the element, so the
    // test harness can drive them; onkeydown tolerates being called bare.
    const bindSearch = (input, clearButton, field) => {
      input.oninput = input.onchange = () => { s.view[field] = input.value; render(s); };
      const clear = () => { input.value = ''; s.view[field] = ''; render(s); input.focus(); };
      clearButton.onclick = clear;
      input.onkeydown = event => {
        if (!event) return;
        // Every control here sits inside #wazuhForm, whose submit queues the
        // batch. Enter in a filter box must not install anything.
        if (event.key === 'Enter') event.preventDefault();
        // app.js closes the topmost overlay on Escape. Swallow it only while
        // there is text to clear, so an empty box still closes the dialog.
        if (event.key === 'Escape' && input.value) { event.preventDefault(); event.stopPropagation(); clear(); }
      };
    };
    bindSearch(el('wazuhLaneSearch'), el('wazuhLaneSearchClear'), 'laneQuery');
    el('wazuhGroupBy').onchange = () => {
      s.view.groupBy = el('wazuhGroupBy').value;
      // Keys change meaning on a new axis, so old collapse state is meaningless.
      s.view.collapsed = new Set(); s.view.seeded = false; render(s);
    };
    el('wazuhLaneSort').onchange = () => {
      const chosen = el('wazuhLaneSort').value;
      // "Newest", "most VMs" and "most agents needed" are questions whose useful
      // answer is at the top, so switching to one of them starts descending.
      if (chosen !== s.view.laneSort) s.view.laneDir = ['created', 'vms', 'missing'].includes(chosen) ? 'desc' : 'asc';
      s.view.laneSort = chosen; render(s);
    };
    el('wazuhLaneSortDir').onclick = () => { s.view.laneDir = s.view.laneDir === 'asc' ? 'desc' : 'asc'; render(s); };
    Object.keys(LANE_FACETS).forEach(name => { el(id('LaneFacet', name)).onclick = () => { s.view.laneFacet = name; render(s); }; });
    el('wazuhExpandAll').onclick = () => { s.view.collapsed = new Set(); s.view.seeded = true; render(s); };
    el('wazuhCollapseAll').onclick = () => {
      s.view.collapsed = new Set(laneView(s).allGroupKeys.filter(groupKey => groupKey !== 'all'));
      s.view.seeded = true; render(s);
    };
    el('wazuhMissing').onclick = () => {
      if (s.submitting) return;
      rows(s).filter(({ lane, target }) => available(lane, target) && !connected(target)).forEach(({ lane, target }) => {
        s.targets.add(key(lane, target)); s.excluded.delete(key(lane, target));
      }); render(s);
    };
    el('wazuhClearTargets').onclick = () => {
      if (s.submitting) return;
      s.targets.clear(); s.machines.clear(); s.excluded.clear(); render(s);
    };
    el('wazuhRetry').onclick = () => {
      if (s.submitting) return;
      s.targets.clear(); s.machines.clear();
      rows(s).filter(({ lane, target }) => failed(s, lane, target) && available(lane, target)).forEach(({ lane, target }) => s.targets.add(key(lane, target)));
      render(s);
    };
    // The shared Modal handles Escape, backdrop clicks, focus trapping/restore.
    // Stop polling whichever close path is used; a reopened dialog refreshes.
    s.observer = new MutationObserver(() => { if (!openNow(s)) { clearTimeout(s.timer); s.timer = null; } });
    s.observer.observe(overlay, { attributes: true, attributeFilter: ['class'] });
    Modal.open(overlay.id);
    render(s);
    return refresh(s);
  }

  function failed(s, lane, target) {
    return stat(lane).failedIds.has(String(target.vm_id)) || s.resultErrors.has(`${lane.lane_id}|${target.vm_id}`);
  }

  function render(s) {
    if (!openNow(s)) return;
    const data = s.payload || {};
    const inventory = lanes(s);
    const vmRows = rows(s);
    const locked = s.submitting;
    let manager = data.manager ? `Manager: <strong>${esc(data.manager)}</strong>` : 'Wazuh manager is not configured.';
    try {
      const url = new URL(data.console_url);
      if (['http:', 'https:'].includes(url.protocol) && !url.username && !url.password) manager += ` <a href="${esc(url.href)}" target="_blank" rel="noopener noreferrer">Open Wazuh console &nearr;</a>`;
    } catch (_) { /* Invalid or missing console URL: show the manager only. */ }
    setHtml('wazuhManager', s.payload ? manager : 'Loading Wazuh configuration and lane inventory…');
    seedCollapse(s);
    const view = laneView(s);
    const searching = !!tokens(s.view.laneQuery).length;
    const laneScroll = el('wazuhLanes').scrollTop || 0;
    // The ONLY array the rebind loop may walk. el() is unguarded throughout this
    // file, so a lane that was filtered out or left inside a collapsed group and
    // then dereferenced here would throw and abort the render half-bound.
    const rendered = [];
    const chip = ({ lane, measured }) => {
      const picked = s.lanes.has(String(lane.lane_id));
      return `<label class="waz-lane${picked ? ' is-picked' : ''}${measured.eligible ? '' : ' is-off'}" title="${esc(lane.name || lane.lane_id)}"><input type="checkbox" id="${esc(id('Lane', lane.lane_id))}"${picked ? ' checked' : ''}${locked || !measured.eligible ? ' disabled' : ''}><span class="waz-lane-name">${esc(lane.name || lane.lane_id)}</span><span class="waz-lane-meta">${measured.running} running${measured.missing ? ` · ${measured.missing} need` : ''}</span>${measured.reason ? `<span class="badge badge-gray">${measured.reason}</span>` : ''}</label>`;
    };
    const groupHtml = group => {
      // A search forces every matching group open: hiding a hit behind a closed
      // header is indistinguishable from having no hit at all. s.view.collapsed
      // is left untouched so clearing the box restores what the operator chose,
      // and the toggle is disabled meanwhile rather than silently doing nothing.
      const open = searching || !s.view.collapsed.has(group.key);
      if (open) rendered.push(...group.rows);
      const body = open ? `<div class="waz-lanegrid" id="${esc(id('GroupBody', group.key))}">${group.rows.map(chip).join('')}</div>` : '';
      if (group.key === 'all') return body;
      const eligible = group.rows.filter(row => row.measured.eligible);
      const pickedAll = group.rows.filter(row => s.lanes.has(String(row.lane.lane_id))).length;
      const pickedEligible = eligible.filter(row => s.lanes.has(String(row.lane.lane_id))).length;
      const missing = eligible.reduce((total, row) => total + row.measured.missing, 0);
      const off = group.rows.length - eligible.length;
      return `<div class="waz-group${open ? '' : ' is-collapsed'}"><div class="waz-group-head"><button type="button" class="waz-group-toggle" id="${esc(id('Group', group.key))}" aria-expanded="${open ? 'true' : 'false'}" aria-controls="${esc(id('GroupBody', group.key))}"${searching ? ' disabled' : ''}><span class="waz-chev" aria-hidden="true"></span><span class="waz-group-title">${esc(group.label)}</span></button><label class="waz-gpick${pickedEligible && pickedEligible < eligible.length ? ' is-partial' : ''}" id="${esc(id('GroupPick', group.key))}"><input type="checkbox" id="${esc(id('GroupAll', group.key))}"${eligible.length && pickedEligible === eligible.length ? ' checked' : ''}${locked || !eligible.length ? ' disabled' : ''}><span class="waz-sr-only">Select every available lane in ${esc(group.label)}</span></label><span class="waz-group-meta">${pickedAll}/${eligible.length} selected · ${group.rows.length} lane${group.rows.length === 1 ? '' : 's'}${missing ? ` · ${missing} need agents` : ''}${off ? ` · ${off} off` : ''}</span></div>${body}</div>`;
    };
    setHtml('wazuhLanes', !inventory.length
      ? `<div class="waz-empty"><strong>${s.payload ? 'No deployed lanes' : s.error ? 'Lane inventory unavailable' : 'Loading lanes…'}</strong><p>${s.payload ? 'Deploy or resume an environment, then refresh status.' : s.error ? 'Refresh status to try again.' : 'Checking running VMs and saved installation jobs.'}</p></div>`
      : !view.groups.length
        ? '<div class="waz-empty"><strong>No lanes match</strong><p>Adjust the search or status filter.</p><button type="button" class="btn btn-outline btn-sm" id="wazuhLaneNoMatchClear">Clear filters</button></div>'
        : view.groups.map(groupHtml).join(''));
    el('wazuhLanes').scrollTop = laneScroll;
    rendered.forEach(({ lane }) => {
      el(id('Lane', lane.lane_id)).onchange = event => {
        if (s.submitting || !laneAvailable(lane)) return;
        if (event.target.checked) s.lanes.add(String(lane.lane_id)); else s.lanes.delete(String(lane.lane_id));
        applyNames(s); render(s);
      };
    });
    view.groups.forEach(group => {
      if (group.key === 'all') return;
      el(id('Group', group.key)).onclick = () => {
        if (s.view.collapsed.has(group.key)) s.view.collapsed.delete(group.key); else s.view.collapsed.add(group.key);
        s.view.seeded = true; render(s);
      };
      const box = el(id('GroupAll', group.key));
      const eligible = group.rows.filter(row => row.measured.eligible);
      const pickedEligible = eligible.filter(row => s.lanes.has(String(row.lane.lane_id))).length;
      // indeterminate has no HTML attribute, so it is set here; the is-partial
      // class in the template mirrors it for anything reading the markup.
      box.indeterminate = pickedEligible > 0 && pickedEligible < eligible.length;
      box.onchange = () => {
        if (s.submitting) return;
        eligible.forEach(row => {
          if (box.checked) s.lanes.add(String(row.lane.lane_id)); else s.lanes.delete(String(row.lane.lane_id));
        });
        applyNames(s); render(s);
      };
    });
    const noMatch = el('wazuhLaneNoMatchClear');
    if (noMatch) noMatch.onclick = () => { s.view.laneQuery = ''; s.view.laneFacet = 'all'; el('wazuhLaneSearch').value = ''; render(s); };
    const pickedLanes = inventory.filter(lane => s.lanes.has(String(lane.lane_id))).length;
    const filtered = searching || s.view.laneFacet !== 'all';
    el('wazuhLaneCount').textContent = `${pickedLanes} selected${filtered ? ` · ${view.matching.length} of ${inventory.length} shown` : ''}`;
    const unpicked = view.matching.filter(row => row.measured.eligible && !s.lanes.has(String(row.lane.lane_id))).length;
    el('wazuhAllLanes').textContent = filtered ? `All matching (${unpicked})` : 'All available';
    el('wazuhAllLanes').disabled = locked || !view.matching.some(row => row.measured.eligible);
    el('wazuhClearLanes').disabled = locked || !s.lanes.size;
    el('wazuhLaneShown').textContent = !inventory.length ? ''
      : filtered ? `Showing ${view.matching.length} of ${inventory.length} lanes`
        : `${inventory.length} lane${inventory.length === 1 ? '' : 's'}`;
    // Intersected with the live payload: s.lanes keeps ids of lanes that have
    // since been torn down, and counting those would report a phantom hidden
    // selection forever, with no filter active.
    const hiddenLanes = inventory.filter(lane => s.lanes.has(String(lane.lane_id)) && !view.matchingIds.has(String(lane.lane_id))).length;
    el('wazuhLaneHidden').textContent = hiddenLanes
      ? `${hiddenLanes} selected lane${hiddenLanes === 1 ? '' : 's'} hidden by the filter` : '';
    Object.keys(LANE_FACETS).forEach(name => {
      const pill = el(id('LaneFacet', name));
      const active = s.view.laneFacet === name;
      pill.className = `filter-pill${active ? ' active' : ''}`;
      pill.ariaPressed = active ? 'true' : 'false';
      pill.disabled = locked;
      el(id('LaneFacetCount', name)).textContent = String(view.facetCounts[name]);
    });
    el('wazuhLaneSortDir').textContent = s.view.laneDir === 'asc' ? '↑' : '↓';
    el('wazuhLaneSortDir').ariaLabel = s.view.laneDir === 'asc' ? 'Sort ascending' : 'Sort descending';
    el('wazuhGroupBy').value = s.view.groupBy;
    el('wazuhLaneSort').value = s.view.laneSort;
    const grouped = s.view.groupBy !== 'none' && view.groups.length > 0;
    el('wazuhExpandAll').disabled = !grouped || searching;
    el('wazuhCollapseAll').disabled = !grouped || searching;
    renderMachines(s, vmRows);
    renderTargets(s, vmRows);
    renderResults(s, inventory);
    const targets = selected(s);
    const unknown = targets.filter(target => !['windows', 'linux'].includes(target.platform)).length;
    el('wazuhSummary').textContent = `${targets.length} VM${targets.length === 1 ? '' : 's'} selected in ${new Set(targets.map(target => target.lane_id)).size} lane(s).`
      + (unknown ? ` Choose Windows or Linux for ${unknown} target(s).` : '')
      + (targets.length > 200 ? ' Select at most 200 targets per batch.' : '');
    el('wazuhSummary').className = `waz-bar-text${unknown || targets.length > 200 ? ' is-blocked' : targets.length ? ' is-ready' : ''}`;
    el('wazuhError').textContent = [s.error, data.configuration_error, data.agents_error, data.power_error].filter(Boolean).join('\n');
    el('wazuhUpdated').textContent = s.refreshing ? 'Refreshing status…' : s.updated ? `Updated ${s.updated}. Refreshes every 5 seconds while open.` : '';
    el('wazuhRefresh').disabled = locked || s.refreshing;
    el('wazuhSubmit').disabled = locked || !s.fresh || !data.manager || !!data.configuration_error || !!data.power_error || !!data.agents_error || !targets.length || targets.length > 200 || !!unknown;
    el('wazuhSubmit').textContent = locked ? 'Queuing installations…' : targets.length ? `Install ${targets.length} agent${targets.length === 1 ? '' : 's'}` : 'Install selected agents';
  }

  function renderMachines(s, vmRows) {
    const names = [...new Set(vmRows.map(({ target }) => nameKey(target)).filter(Boolean))].sort();
    setHtml('wazuhMachines', names.length ? `<section class="waz-panel"><div class="waz-panel-head"><span class="waz-step">2</span><h4 class="waz-panel-title">Machine names</h4></div><div class="waz-panel-body"><p class="waz-hint">Select a name to pick matching VMs across selected lanes, ignoring case. Connected agents are skipped. An OS chosen here applies to every matching VM; individual targets can override it.</p><div class="waz-mgrid"><span class="waz-mgrid-h">Machine</span><span class="waz-mgrid-h">Needs agent</span><span class="waz-mgrid-h">Operating system</span>${names.map(name => {
      const matching = vmRows.filter(({ lane, target }) => nameKey(target) === name && available(lane, target) && !connected(target));
      const display = vmRows.find(({ target }) => nameKey(target) === name).target.name;
      const picked = matching.length && matching.every(({ lane, target }) => s.targets.has(key(lane, target)));
      return `<label class="waz-mpick"><input type="checkbox" id="${esc(id('Machine', name))}"${picked ? ' checked' : ''}${s.submitting || !matching.length ? ' disabled' : ''}><span class="waz-mname">${esc(display)}</span></label><span class="badge badge-gray">${matching.length}</span><label class="waz-molabel"><span class="waz-sr-only">Operating system for ${esc(display)}</span><select class="waz-select" id="${esc(id('MachineOs', name))}"${s.submitting ? ' disabled' : ''}>${options(s.machinePlatforms.get(name) || '', 'Use each VM’s own OS')}</select></label>`;
    }).join('')}</div></div></section>` : '');
    names.forEach(name => {
      el(id('Machine', name)).onchange = event => {
        if (s.submitting) return;
        if (event.target.checked) s.machines.add(name); else s.machines.delete(name);
        vmRows.filter(({ target }) => nameKey(target) === name).forEach(({ lane, target }) => {
          const vmKey = key(lane, target); s.excluded.delete(vmKey);
          if (event.target.checked && available(lane, target) && !connected(target)) s.targets.add(vmKey); else s.targets.delete(vmKey);
        }); render(s);
      };
      const os = el(id('MachineOs', name));
      os.value = s.machinePlatforms.get(name) || '';
      os.onchange = () => {
        if (s.submitting) return;
        s.machinePlatforms.set(name, os.value);
        vmRows.filter(({ target }) => nameKey(target) === name).forEach(({ lane, target }) => s.platforms.delete(key(lane, target)));
        render(s);
      };
    });
  }

  function renderTargets(s, vmRows) {
    const scroll = el('wazuhTargetScroll');
    const scrollTop = scroll?.scrollTop || 0;
    const scrollLeft = scroll?.scrollLeft || 0;
    const selectable = vmRows.filter(({ lane, target }) => available(lane, target));
    el('wazuhTargetCount').textContent = `${vmRows.length} rows · ${selectable.length} selectable`;
    el('wazuhMissing').disabled = s.submitting || !selectable.some(({ target }) => !connected(target));
    el('wazuhRetry').disabled = s.submitting || !selectable.some(({ lane, target }) => failed(s, lane, target));
    el('wazuhClearTargets').disabled = s.submitting || !s.targets.size;
    setHtml('wazuhTargets', vmRows.length ? `<div class="waz-tablewrap" id="wazuhTargetScroll"><table class="data-table waz-table"><thead><tr><th class="waz-c-pick"><span class="waz-sr-only">Install</span></th><th>Lane</th><th>Machine</th><th class="waz-c-vm">VM</th><th class="waz-c-os">Operating system</th><th class="waz-c-status">Status</th></tr></thead><tbody>${vmRows.map(({ lane, target }) => {
      const vmKey = key(lane, target);
      const eligible = available(lane, target);
      const picked = eligible && s.targets.has(vmKey);
      return `<tr class="waz-row${picked ? ' is-picked' : ''}${eligible ? '' : ' is-off'}"><td class="waz-c-pick"><label class="waz-pick"><input type="checkbox" id="${esc(id('Target', vmKey))}"${picked ? ' checked' : ''}${s.submitting || !eligible ? ' disabled' : ''}><span class="waz-sr-only">Install on ${esc(lane.name || lane.lane_id)} ${esc(target.name || target.vm_id)}</span></label></td><td>${esc(lane.name || lane.lane_id)}</td><td class="waz-mname">${esc(target.name || 'VM')}</td><td class="waz-c-vm waz-mono">${esc(target.vm_id)}</td><td class="waz-c-os"><label class="waz-molabel"><span class="waz-sr-only">Operating system for ${esc(target.name || target.vm_id)} in ${esc(lane.name || lane.lane_id)}</span><select class="waz-select" id="${esc(id('TargetOs', vmKey))}"${s.submitting || !eligible ? ' disabled' : ''}>${options(platform(s, lane, target), 'Choose OS…')}</select></label></td><td class="waz-c-status" id="${esc(id('Status', vmKey))}"></td></tr>`;
    }).join('')}</tbody></table></div>` : `<div class="waz-empty"><strong>${s.lanes.size ? 'No QEMU VMs in selected lanes' : 'No lanes selected'}</strong><p>${s.lanes.size ? 'Refresh status after the VMs finish deploying.' : 'Select lanes above to see their machines.'}</p></div>`);
    if (el('wazuhTargetScroll')) {
      el('wazuhTargetScroll').scrollTop = scrollTop;
      el('wazuhTargetScroll').scrollLeft = scrollLeft;
    }
    vmRows.forEach(({ lane, target }) => {
      const vmKey = key(lane, target);
      el(id('Target', vmKey)).onchange = event => {
        if (s.submitting || !available(lane, target)) return;
        if (event.target.checked) { s.targets.add(vmKey); s.excluded.delete(vmKey); }
        else { s.targets.delete(vmKey); s.excluded.add(vmKey); }
        render(s);
      };
      const os = el(id('TargetOs', vmKey));
      os.value = platform(s, lane, target);
      os.onchange = () => { if (!s.submitting && available(lane, target)) { s.platforms.set(vmKey, os.value); render(s); } };
      const job = jobs(lane).find(entry => String(entry.vm_id) === String(target.vm_id) && ['queued', 'running'].includes(entry.status));
      const status = job ? (job.status === 'queued' ? 'install queued' : 'installing')
        : !laneAvailable(lane) ? (lane.internet_enabled === false ? 'internet off' : 'lane unavailable')
          : target.runnable !== true ? target.power_state || 'power unknown' : connected(target) ? 'connected' : target.agent?.status || 'agent missing';
      const seen = target.agent?.lastKeepAlive || target.agent?.last_seen;
      // Status cells are separate islands: a changing check-in timestamp cannot
      // replace a focused OS selector, checkbox, or the target table scroll.
      setHtml(id('Status', vmKey), `<span class="badge ${badge(job?.status || status)}">${esc(status)}</span>${seen ? `<small class="waz-last-seen">Last seen: ${esc(seen)}</small>` : ''}`);
    });
  }

  function renderResults(s, inventory) {
    const all = inventory.flatMap(lane => jobs(lane).map(job => ({ lane, job })));
    const failures = s.results.filter(result => result.error);
    const metrics = ['queued', 'running', 'completed', 'failed'].map(status => {
      const count = all.filter(({ job }) => job.status === status).length;
      return `<span class="badge ${count ? badge(status) : 'badge-gray'}">${count} ${status}</span>`;
    }).join('');
    setHtml('wazuhResults', all.length || failures.length ? `<h4 class="waz-results-title">Installation progress</h4><div class="waz-metrics">${metrics}</div>`
      + failures.map(result => `<div class="waz-job is-bad"><strong class="waz-job-name">${esc(inventory.find(lane => String(lane.lane_id) === String(result.lane_id))?.name || result.lane_id)} · VM ${esc(result.vm_id)}</strong><p class="waz-job-msg">${esc(result.error)}</p></div>`).join('')
      + all.slice().sort((a, b) => Number(b.job.status === 'failed') - Number(a.job.status === 'failed')).map(({ lane, job }) => `<div class="waz-job is-${job.status === 'failed' ? 'bad' : job.status === 'completed' ? 'good' : 'live'}"><div class="waz-job-head"><strong class="waz-job-name">${esc(lane.name || lane.lane_id)} · VM ${esc(job.vm_id)}</strong><span class="badge ${badge(job.status)}">${esc(job.status || 'unknown')}</span></div><p class="waz-job-msg">${esc(job.error || job.message || '')}</p>${job.status === 'completed' ? `<p class="waz-job-ok">Agent check-in confirmed${job.agent_name ? `: ${esc(job.agent_name)}` : ''}.</p>` : ''}${job.last_seen ? `<p class="waz-job-msg">Last seen: ${esc(job.last_seen)}</p>` : ''}</div>`).join('') : '');
  }

  async function refresh(s) {
    if (!openNow(s) || s.refreshing || s.submitting) return;
    clearTimeout(s.timer);
    s.refreshing = true;
    const revision = s.revision;
    render(s);
    try {
      const data = await api('GET', '/wazuh-agents');
      if (revision !== s.revision) return;
      if (!data || !Array.isArray(data.lanes)) throw new Error('Invalid Wazuh inventory response. Refresh status to try again.');
      s.payload = data;
      s.payloadRevision += 1;   // new lane objects: the memoized view must rebuild
      s.fresh = true;
      s.error = '';
      s.updated = new Date().toLocaleTimeString();
      // Polls only remove unavailable targets. New machines are never silently
      // added to an operator's reviewed selection by a background refresh.
      const live = new Set(lanes(s).flatMap(lane => (lane.targets || []).filter(target => available(lane, target)).map(target => key(lane, target))));
      [...s.targets].forEach(vmKey => { if (!live.has(vmKey)) s.targets.delete(vmKey); });
    } catch (error) {
      if (revision !== s.revision) return;
      s.fresh = false;
      s.error = `Could not refresh Wazuh status: ${error.message}`;
    } finally {
      s.refreshing = false;
      if (openNow(s)) {
        render(s);
        schedule(s);
      }
    }
  }

  async function submit(s) {
    if (!openNow(s) || el('wazuhSubmit').disabled) return;
    const targets = selected(s);
    if (!targets.length || targets.length > 200 || targets.some(target => !['windows', 'linux'].includes(target.platform))) return;
    clearTimeout(s.timer);
    s.revision += 1; // Ignore any pre-submit inventory request arriving late.
    s.submitting = true;
    s.error = '';
    s.results = [];
    s.resultErrors = new Set();
    s.payloadRevision += 1;
    render(s);
    try {
      const data = await api('POST', '/wazuh-agents/batch', { targets });
      if (!data || !Array.isArray(data.results)) throw new Error('The queue response was incomplete. Refresh status to check which jobs were saved.');
      s.results = data.results;
      s.resultErrors = errorsOf(s.results);
      data.results.forEach(result => {
        const lane = lanes(s).find(entry => String(entry.lane_id) === String(result.lane_id));
        if (!lane || !result.job) return;
        lane.jobs = jobs(lane).filter(job => String(job.vm_id) !== String(result.vm_id)).concat(result.job);
        // The lane object survives this mutation, so its cached measurements
        // (busy/failed sets, counts) would otherwise describe the old job list.
        laneStats.delete(lane);
        s.targets.delete(key(lane, { vm_id: result.vm_id }));
        s.excluded.add(key(lane, { vm_id: result.vm_id }));
      });
      s.payloadRevision += 1;
    } catch (error) {
      s.fresh = false;
      s.error = `Could not confirm the deployment request: ${error.message} Refresh status before retrying.`;
    } finally {
      s.submitting = false;
      if (openNow(s)) { render(s); schedule(s); }
    }
  }

  window.AdminWazuh = { open, close };
})();
