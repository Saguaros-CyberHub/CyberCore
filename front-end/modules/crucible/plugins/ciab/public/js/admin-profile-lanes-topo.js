/**
 * admin-profile-lanes-topo.js — the live lane blueprint.
 * ============================================================================
 * Draws ONE classroom lane exactly as the cluster will build it, and redraws it
 * as the admin ticks assets and flips options.
 *
 * THE ONE RULE: THIS FILE DECIDES NOTHING ABOUT THE NETWORK.
 *
 * Every machine, every segment and every octet arrives from
 * POST /api/profile-deploy/plan, which runs the same synthesizeSpecFromProfile
 * the deploy runs. This file positions nodes and paints them; it never derives a
 * placement, never invents a machine, and never guesses an address.
 *
 * That is not fastidiousness — it is the whole reason the feature is worth
 * building. The browser's own topology-editor.deriveSegments puts a non-dmz,
 * non-GOAD machine on 'ext' under v3, while this client's applyV3Topology puts
 * everything EXCEPT the dual-homed pivot on 'int'. A client-side preview would
 * therefore draw the entire corporate network on the attacker's segment — the
 * exact inverse of the truth, on the page whose only job is to tell the truth
 * about placement. So topology-editor.js and topology-seed.js are NOT LOADED on
 * this page at all: the module that could get it wrong is not present.
 *
 * WHY THE LAYOUT IS COMPUTED HERE RATHER THAN LEFT TO cose
 * topology-render.js sets `needsLayout = runLayout || cy.nodes().some(p.x === 0
 * && p.y === 0)`, and a newly added node is positioned `n.layout || null`, which
 * is (0,0). So a single ticked checkbox would force a full force-directed pass
 * over the whole graph, and layout() ends in cy.fit(), throwing away the
 * operator's zoom and pan. placeGraph() stamps explicit coordinates on every
 * element so setData(graph, false) is an in-place add. Two hard requirements
 * follow, and both are asserted in test/admin-profile-lanes-topo.test.js:
 *   - nothing may sit at exactly (0,0), or it re-triggers the layout it avoids;
 *   - every node needs a stable id, because render() restores positions BY ID.
 *
 * MOUNT ONCE. topology-render.js registers a MutationObserver on
 * <html>[data-theme] and only destroy() disconnects it, so a create() per tab
 * entry leaks one observer per entry. mount() is idempotent and resize() is what
 * a tab re-entry calls.
 */

/* global CyberCoreTopology, Utils, apiCall, gatherAssetSelection, CURRENT_PROFILE, DEFAULT_SUBNET_SCHEME */

var LaneTopo = (function () {
  'use strict';

  var TOPO = null;          // the one Cytoscape instance
  var LAST_PLAN = null;     // last good response, kept so a failure can keep drawing
  var SEQ = 0;              // monotonic request counter
  var ABORT = null;         // in-flight AbortController
  var MOUNT_TRIES = 0;

  // ── geometry ──────────────────────────────────────────────────────────────
  // A fixed two-band layout, deliberately not a force layout: the graph is
  // strongly structured (two segments, one gateway, machines under their
  // segment) and a stable picture that an operator can re-find after ticking a
  // box is worth more than an optimally-packed one.
  var ORIGIN = 60;          // nothing may be placed at exactly (0,0)
  var COL_W = 150;
  var ROW_H = 130;
  var MACHINE_Y = 290;

  var GEO = {
    v3: {
      segments: { ext: { x: 260, y: 120 }, int: { x: 760, y: 120 } },
      gateway: { x: 510, y: 40 },
      pivot: { x: 510, y: MACHINE_Y },
      bands: { ext: { x: 140, cols: 3 }, int: { x: 640, cols: 3 } },
      ghosts: { x: 1090, cols: 2 },
    },
    flat: {
      segments: { lan: { x: 500, y: 120 } },
      gateway: { x: 500, y: 40 },
      pivot: null,
      bands: { lan: { x: 140, cols: 5 } },
      ghosts: { x: 950, cols: 2 },
    },
  };

  function el(id) { return document.getElementById(id); }

  /**
   * plan response -> { segments, gateway, nodes } with explicit {x,y} on every
   * element. Pure, and exported so a test can assert the two invariants above
   * without a browser.
   */
  function placeGraph(plan) {
    var isV3 = plan.segments.some(function (s) { return s.id === 'int'; });
    var geo = isV3 ? GEO.v3 : GEO.flat;

    var segments = plan.segments.map(function (s) {
      var p = geo.segments[s.id] || { x: 500, y: 120 };
      return {
        id: s.id, role: s.role, label: s.label, cidr: s.cidr || null,
        layout: { x: p.x + ORIGIN, y: p.y + ORIGIN },
      };
    });

    var gateway = {
      label: plan.gateway && plan.gateway.label ? plan.gateway.label : 'Lane gateway',
      layout: { x: geo.gateway.x + ORIGIN, y: geo.gateway.y + ORIGIN },
    };

    // Machines sort by octet within their band, so the picture reads in the same
    // order as the addressing — and so ticking an asset moves one node rather
    // than reshuffling a column.
    var counters = {};
    var nodes = plan.machines.slice().sort(function (a, b) {
      return (a.ip_octet || 999) - (b.ip_octet || 999);
    }).map(function (m) {
      var pos;
      if (m.is_pivot && geo.pivot) {
        pos = geo.pivot;                       // centred between the two bands
      } else {
        var band = geo.bands[m.segments[0]] || geo.bands[Object.keys(geo.bands)[0]];
        var i = counters[m.segments[0]] = (counters[m.segments[0]] || 0);
        counters[m.segments[0]] += 1;
        pos = {
          x: band.x + (i % band.cols) * COL_W,
          y: MACHINE_Y + Math.floor(i / band.cols) * ROW_H,
        };
      }
      return {
        id: m.id,
        name: m.name + (m.ip_octet ? '\n.' + m.ip_octet : ''),
        role: m.view_role || m.role || '',
        os: m.os || '',
        os_family: m.os_family || '',
        ip: m.ip_display || null,
        segments: m.segments.slice(),
        layout: { x: pos.x + ORIGIN, y: pos.y + ORIGIN },
        severity: m.severity || '',
        // Only what resolveConsolePlan named. The badge appends a literal
        // '▸ student console' to the label, so putting it on the pivot would
        // caption the web host as the machine students open.
        badge: m.is_console ? 'console' : '',
      };
    });

    // Ghosts: ticked, and no template resolved, so no VM is built. Rendered with
    // segments:[] (which paints the amber [!attached] dashed ring) PLUS
    // severity:'error' — the severity rules set colour and width but not
    // border-style, so the ring lands red AND dashed, distinct from a service
    // gap, which is a machine that IS built and IS wired.
    plan.ghosts.forEach(function (g, i) {
      nodes.push({
        id: g.id,
        name: g.name + '\n(no template)',
        role: g.role || '', os: g.os || '', os_family: '',
        segments: [],
        layout: {
          x: geo.ghosts.x + (i % geo.ghosts.cols) * COL_W + ORIGIN,
          y: MACHINE_Y + Math.floor(i / geo.ghosts.cols) * ROW_H + ORIGIN,
        },
        severity: 'error',
      });
    });

    return { segments: segments, gateway: gateway, nodes: nodes };
  }

  /**
   * A node naming a segment id the response does not carry renders attached with
   * ZERO edges and no warning ring — wrongness that looks like a tidy diagram.
   * Cheap to check, impossible to spot by eye.
   */
  function assertNoDanglingSegments(graph) {
    var ids = {};
    graph.segments.forEach(function (s) { ids[s.id] = true; });
    graph.nodes.forEach(function (n) {
      (n.segments || []).forEach(function (id) {
        if (!ids[id]) {
          throw new Error('node ' + n.id + ' names segment "' + id + '", which this lane has no');
        }
      });
    });
  }

  // ── mount / resize / destroy ──────────────────────────────────────────────

  function mount() {
    if (TOPO) { TOPO.resize(); return true; }
    if (typeof CyberCoreTopology === 'undefined') return false;
    var host = el('depTopoCanvas');
    if (!host) return false;
    // Cytoscape measures its container at create(). The tab is display:none
    // until it is .active, and a 0-height container yields an empty graph.
    if (!host.clientHeight) return false;

    var empty = el('depTopoEmpty');
    if (empty) empty.remove();
    var canvas = document.createElement('div');
    canvas.style.cssText = 'position:absolute; inset:0;';
    host.appendChild(canvas);
    TOPO = CyberCoreTopology.create(canvas, { mode: 'view' });
    return true;
  }

  function ensureMounted(then) {
    if (mount()) { then(); return; }
    // One retry on the next frame covers the tab having just become visible.
    if (MOUNT_TRIES < 2) {
      MOUNT_TRIES += 1;
      requestAnimationFrame(function () { ensureMounted(then); });
      return;
    }
    renderTextFallback();
  }

  function destroy() {
    if (!TOPO) return;
    try { TOPO.destroy(); } catch (e) { /* already gone */ }
    TOPO = null;
  }

  function onTabShown() {
    MOUNT_TRIES = 0;
    if (TOPO) { TOPO.resize(); return; }
    if (LAST_PLAN) ensureMounted(function () { draw(LAST_PLAN); });
  }

  // ── the request ───────────────────────────────────────────────────────────

  function readForm() {
    var v = function (id) { var n = el(id); return n ? n.value : ''; };
    var c = function (id) { var n = el(id); return !!(n && n.checked); };
    var diff = document.querySelector('input[name="dep-vuln-difficulty"]:checked');
    return {
      profile_id: (CURRENT_PROFILE && CURRENT_PROFILE.id) || v('profile-picker'),
      asset_selection: typeof gatherAssetSelection === 'function' ? gatherAssetSelection() : undefined,
      subnet_scheme: v('dep-subnet-scheme') || DEFAULT_SUBNET_SCHEME,
      attack_boxes: c('dep-attack-boxes'),
      vuln_app_enabled: c('dep-vuln-app'),
      vuln_app_difficulty: diff ? diff.value : 'easy',
      num_lanes: parseInt(v('dep-num-lanes'), 10) || 1,
    };
  }

  function busy(on) {
    var b = el('depTopoBusy');
    var host = el('depTopoCanvas');
    if (b) b.classList.toggle('on', !!on);
    // Dimmed, never cleared: a blank canvas mid-keystroke reads as "this will
    // build nothing", which is a different and much worse claim.
    if (host) host.classList.toggle('is-stale', !!on);
  }

  async function request() {
    var body = readForm();
    if (!body.profile_id) return;

    var mySeq = (SEQ += 1);
    if (ABORT) { try { ABORT.abort(); } catch (e) { /* best effort */ } }
    var ctrl = (typeof AbortController !== 'undefined') ? new AbortController() : null;
    ABORT = ctrl;
    busy(true);

    try {
      var plan = await apiCall('/profile-deploy/plan', {
        method: 'POST', body: body, signal: ctrl ? ctrl.signal : undefined,
      });
      // Abort is best-effort: an already-resolved fetch can still land late, so
      // the sequence number is the real guard.
      if (mySeq !== SEQ) return;
      LAST_PLAN = plan;
      // The list and the diagram are two views of ONE answer. Repainting the
      // rail from the same response is what makes the fate glyph mean exactly
      // what the canvas shows, rather than a second opinion computed here.
      if (typeof applyPlanToRail === 'function') applyPlanToRail(plan);
      ensureMounted(function () { draw(plan); });
    } catch (err) {
      if (mySeq !== SEQ || (err && err.name === 'AbortError')) return;
      failSoft(err);
    } finally {
      if (mySeq === SEQ) busy(false);
    }
  }

  var schedule = null;
  function scheduleRequest() {
    if (!schedule) {
      schedule = (typeof Utils !== 'undefined' && Utils.debounce)
        ? Utils.debounce(request, 250)
        : request;
    }
    schedule();
  }

  // ── drawing ───────────────────────────────────────────────────────────────

  function draw(plan) {
    if (!TOPO) { renderTextFallback(); return; }
    try {
      var graph = placeGraph(plan);
      assertNoDanglingSegments(graph);
      // runLayout FALSE, always: every element carries explicit coordinates, so
      // this is an in-place add that keeps the operator's zoom and pan.
      TOPO.setData(graph, false);
      renderMeta(plan);
    } catch (e) {
      var meta = el('depTopoMeta');
      if (meta) {
        meta.innerHTML = '<span style="color:var(--danger);">Could not draw this lane: '
          + esc(e.message) + '</span>';
      }
    }
  }

  function esc(v) {
    return String(v == null ? '' : v).replace(/[&<>"']/g, function (ch) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch];
    });
  }

  function renderMeta(plan) {
    var scope = el('depTopoScope');
    var n = plan.counts.num_lanes;
    if (scope) {
      scope.textContent = 'Lane 1 of ' + n + ' — every lane is built identically';
    }

    var bits = [];
    var built = plan.counts.machines_per_lane;
    bits.push(built + ' machine' + (built === 1 ? '' : 's') + ' per lane'
      + (n > 1 ? ' · ' + (built * n) + ' VMs across ' + n + ' lanes' : ''));

    var pivot = plan.machines.filter(function (m) { return m.is_pivot; })[0];
    if (pivot) {
      bits.push('<strong>' + esc(pivot.name) + '</strong> is the pivot at .'
        + pivot.ip_octet + ', the only path from External to Internal');
    } else if (plan.scheme.effective === 'v3') {
      bits.push('<span style="color:var(--warning);">no dual-homed pivot — the Internal '
        + 'segment stays empty</span>');
    }
    if (plan.console) bits.push('students open <strong>' + esc(plan.console.vm) + '</strong>');
    if (plan.counts.ghosts) {
      bits.push('<span style="color:var(--danger);">' + plan.counts.ghosts
        + ' selected asset' + (plan.counts.ghosts === 1 ? '' : 's')
        + ' cannot be built</span>');
    }
    if (plan.counts.service_gaps) {
      bits.push('<span style="color:var(--warning);">' + plan.counts.service_gaps
        + ' service gap' + (plan.counts.service_gaps === 1 ? '' : 's') + '</span>');
    }

    var problems = (plan.problems || []).filter(function (p) { return p.severity === 'error'; });
    var head = problems.length
      ? '<span style="color:var(--danger);"><strong>'
        + esc(problems[0].code) + '</strong> — ' + esc(problems[0].message) + '</span><br>'
      : '';

    var meta = el('depTopoMeta');
    if (meta) meta.innerHTML = head + bits.join(' · ');
  }

  /** No renderer, or a container that never got a size. Still answer the question. */
  function renderTextFallback() {
    var host = el('depTopoCanvas');
    if (!host || !LAST_PLAN) return;
    var rows = LAST_PLAN.machines.map(function (m) {
      return '<li><code>' + esc(m.name) + '</code> — ' + esc(m.segments.join(' + '))
        + (m.ip_octet ? ' .' + m.ip_octet : '') + '</li>';
    }).join('');
    host.innerHTML = '<div style="padding:1rem; font-size:0.85rem;">'
      + '<p class="muted">The diagram could not be drawn here, so the same machines are listed.</p>'
      + '<ul style="margin:0; padding-left:1.2rem;">' + rows + '</ul></div>';
  }

  function failSoft(err) {
    var meta = el('depTopoMeta');
    if (meta) {
      meta.innerHTML = '<span style="color:var(--danger);">'
        + (LAST_PLAN ? 'Showing the last good drawing — ' : '')
        + esc((err && err.message) || 'the lane plan could not be loaded') + '</span>';
    }
  }

  // ── wiring ────────────────────────────────────────────────────────────────
  //
  // ONE delegated listener, so a control is wired by EXISTING rather than by
  // being remembered — which is how this page drifted into fields nothing read.
  document.addEventListener('DOMContentLoaded', function () {
    var controls = el('dep-controls');
    if (controls) {
      controls.addEventListener('change', function (e) {
        if (e.target.closest('[data-plan-input]')) scheduleRequest();
      });
    }

    // The scheme select is wired SEPARATELY and deliberately: its opening tag
    // must stay exactly `<select id="dep-subnet-scheme">`. test/ciab-v3-default.js
    // regex-matches that literal tag, so an onchange= or data-* attribute on it
    // drops the match count and fails the suite.
    var scheme = el('dep-subnet-scheme');
    if (scheme) scheme.addEventListener('change', scheduleRequest);

    // Lane count changes no machine and no placement, so it must not spend a
    // round trip — it only multiplies a number already in hand.
    var lanes = el('dep-num-lanes');
    if (lanes) {
      lanes.addEventListener('input', function () {
        if (!LAST_PLAN) return;
        LAST_PLAN.counts.num_lanes = parseInt(lanes.value, 10) || 1;
        renderMeta(LAST_PLAN);
      });
    }

    window.addEventListener('pagehide', destroy);
    var t = null;
    window.addEventListener('resize', function () {
      clearTimeout(t);
      t = setTimeout(function () { if (TOPO) TOPO.resize(); }, 150);
    });
  });


  // ── Tab 2's deploy gate reads this ────────────────────────────────────────
  function ghosts() { return (LAST_PLAN && LAST_PLAN.ghosts) || []; }

  // ── the deployed lane, for Active Groups ──────────────────────────────────
  //
  // A SECOND instance, and a short-lived one. GET /api/admin/lanes/:id/topology
  // returns buildLaneTopology's payload, which is already in setData's shape —
  // real IPs read back from Proxmox, and a power_state per node. So the same
  // renderer draws the PREDICTION (POST /plan, above) and the REALITY, in one
  // visual language, and an operator can compare them.
  //
  // This one IS destroyed on close: every create() registers a MutationObserver
  // on <html>[data-theme] that only destroy() disconnects, and this modal can be
  // opened once per lane.
  var LIVE_TOPO = null;

  async function openLive(laneId, laneName) {
    var modal = el('laneTopologyModal');
    var body = el('laneTopologyCanvas');
    var meta = el('laneTopologyMeta');
    if (!modal || !body) return;

    el('laneTopologyTitle').textContent = 'Topology: ' + (laneName || laneId);
    if (meta) meta.textContent = 'Reading lane configuration from Proxmox…';
    closeLive();
    body.innerHTML = '';
    modal.classList.add('active');

    try {
      var data = await apiCall('/admin/lanes/' + encodeURIComponent(laneId) + '/topology');
      var unattached = data.nodes.filter(function (n) { return !n.segments.length; }).length;
      if (meta) {
        meta.innerHTML = '<strong>' + esc(data.lane.challenge_key || '—') + '</strong> · '
          + esc(data.lane.subnet_scheme) + ' · VXLAN ' + esc(String(data.lane.vxlan_id)) + ' · '
          + data.nodes.length + ' machine' + (data.nodes.length === 1 ? '' : 's')
          + (unattached
            ? ' · <span style="color:var(--danger);">' + unattached + ' on no known segment</span>'
            : '');
      }

      // Mounted AFTER .active — Cytoscape measures its container on init.
      var canvas = document.createElement('div');
      canvas.style.cssText = 'position:absolute; inset:0;';
      body.appendChild(canvas);
      LIVE_TOPO = CyberCoreTopology.create(canvas, { mode: 'view' });
      LIVE_TOPO.setData({
        segments: data.segments,
        gateway: data.gateway,
        nodes: data.nodes.map(function (n) {
          return {
            id: n.id, name: n.name, role: n.role, os: n.os, ip: n.ip, segments: n.segments,
            // A stopped machine reads as a problem worth seeing at a glance.
            severity: (n.power_state && n.power_state !== 'running') ? 'warning' : '',
          };
        }),
      // runLayout TRUE here, unlike the preview: a real lane carries no stored
      // positions, so there is nothing to preserve and cose is the right answer.
      }, true);
    } catch (e) {
      if (meta) meta.textContent = '';
      body.innerHTML = '<p style="padding:1rem; color:var(--danger);">' + esc(e.message) + '</p>';
    }
  }

  function closeLive() {
    if (!LIVE_TOPO) return;
    try { LIVE_TOPO.destroy(); } catch (e) { /* already gone */ }
    LIVE_TOPO = null;
  }

  function closeLiveModal() {
    closeLive();
    var m = el('laneTopologyModal');
    if (m) m.classList.remove('active');
  }

  return {
    onTabShown: onTabShown,
    request: request,
    schedule: scheduleRequest,
    placeGraph: placeGraph,
    assertNoDanglingSegments: assertNoDanglingSegments,
    destroy: destroy,
    ghosts: ghosts,
    openLive: openLive,
    closeLive: closeLiveModal,
    // Read by the tests; not part of the page's own contract.
    _state: function () { return { mounted: !!TOPO, plan: LAST_PLAN }; },
  };
}());

if (typeof module !== 'undefined' && module.exports) module.exports = LaneTopo;
