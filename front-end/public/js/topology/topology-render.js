/**
 * topology-render.js — the shared Cytoscape wrapper.
 *
 * One renderer, two callers:
 *   mode 'edit' — the challenge authoring canvas (topology-editor.js)
 *   mode 'view' — the read-only live lane topology
 *
 * ── The graph is bipartite, not nested ──────────────────────────────────────
 * Machines and network segments are both NODES; an edge is one NIC attachment.
 * A segment could have been drawn as a Cytoscape compound parent with its hosts
 * as children, which looks tidier for the simple case — but a child can only
 * have one parent, and the dual-homed pivot host that sits on BOTH segments is
 * the entire reason v3 lanes exist. Bipartite also matches the real model: a
 * VNet is a broadcast domain that NICs attach to, not a container of machines.
 *
 * ── Edge order is load-bearing ──────────────────────────────────────────────
 * The order of a machine's edges is the order of its `nics[]`, which maps
 * positionally to net0, net1, … See lane-networking.resolveVmNics.
 *
 * Requires (in order): /vendor/lodash.min.js, /vendor/cytoscape.min.js,
 * /vendor/cytoscape-edgehandles.js, /js/topology/topology-icons.js
 *
 * Global: window.CyberCoreTopology
 */
(function (global) {
  'use strict';

  var Icons = global.CyberCoreTopologyIcons;

  // ── theme ──────────────────────────────────────────────────────────────────
  // Cytoscape renders to canvas and cannot read CSS custom properties, so the
  // app's tokens are resolved to concrete values at init and re-resolved when
  // the theme flips.
  function readTheme() {
    var css = getComputedStyle(document.documentElement);
    var v = function (name, fallback) {
      return (css.getPropertyValue(name) || '').trim() || fallback;
    };
    var dark = document.documentElement.getAttribute('data-theme') === 'dark';
    return {
      dark: dark,
      text: v('--text-primary', dark ? '#f0f4fa' : '#111827'),
      textMuted: v('--text-muted', dark ? '#7286a8' : '#6b7280'),
      card: v('--bg-card', dark ? '#0c1a31' : '#ffffff'),
      cardAlt: v('--bg-card-elevated', dark ? '#182c4f' : '#f9fafb'),
      border: dark ? '#5c9fe6' : '#9ca3af',
      primary: v('--primary', dark ? '#5c9fe6' : '#0c234b'),
      danger: v('--danger', dark ? '#ef4056' : '#ab0520'),
      warning: v('--warning', '#f59e0b'),
      success: v('--success', dark ? '#70b865' : '#4f9153'),
      info: v('--info', '#378dbd'),
      // Segment tints. External is where the attacker lives; internal is the
      // protected side. Deliberately not red/green — those read as status.
      segExternal: '#f59e0b',
      segInternal: '#378dbd',
      segLan: dark ? '#7286a8' : '#6b7280'
    };
  }

  function segColor(theme, role) {
    if (role === 'external') return theme.segExternal;
    if (role === 'internal') return theme.segInternal;
    return theme.segLan;
  }

  // ── ids ────────────────────────────────────────────────────────────────────
  var uid = 0;
  function nextId(prefix) { uid += 1; return prefix + '-' + uid + '-' + (uid * 2654435761 % 100000); }

  function segEl(id) { return 'seg:' + id; }
  function vmEl(id) { return 'vm:' + id; }

  // ── stylesheet ─────────────────────────────────────────────────────────────
  function stylesheet(theme) {
    return [
      {
        selector: 'node',
        style: {
          'label': 'data(label)',
          'color': theme.text,
          'font-family': 'Inter, system-ui, sans-serif',
          'font-size': 11,
          'font-weight': 600,
          'text-valign': 'bottom',
          'text-halign': 'center',
          'text-margin-y': 6,
          'text-wrap': 'wrap',
          'text-max-width': 110,
          'overlay-opacity': 0
        }
      },
      {
        selector: 'node[kind="vm"]',
        style: {
          'shape': 'round-rectangle',
          'width': 54, 'height': 54,
          'background-color': theme.card,
          'border-width': 2,
          'border-color': theme.border,
          'background-image': 'data(icon)',
          'background-width': '55%',
          'background-height': '55%',
          'background-fit': 'none',
          'background-clip': 'none'
        }
      },
      {
        selector: 'node[kind="segment"]',
        style: {
          'shape': 'round-rectangle',
          'width': 240, 'height': 62,
          'background-color': theme.cardAlt,
          'background-opacity': theme.dark ? 0.85 : 1,
          'border-width': 2,
          'border-style': 'dashed',
          'border-color': 'data(accent)',
          'label': 'data(label)',
          'text-valign': 'center',
          'text-margin-y': 0,
          'text-max-width': 210,
          'font-size': 12,
          'color': 'data(accent)'
        }
      },
      {
        selector: 'node[kind="gateway"]',
        style: {
          'shape': 'round-diamond',
          'width': 60, 'height': 60,
          'background-color': theme.cardAlt,
          'border-width': 2,
          'border-color': theme.primary,
          'background-image': 'data(icon)',
          'background-width': '48%',
          'background-height': '48%',
          'background-fit': 'none',
          'background-clip': 'none',
          'color': theme.textMuted
        }
      },
      // The student's console machine. Placed BEFORE the severity rules on
      // purpose: a console that is also broken must still read as broken, so the
      // later rule wins on a node carrying both.
      { selector: 'node[badge="console"]', style: { 'border-color': theme.success, 'border-width': 4 } },
      // A machine on no segment. Before this rule a detached DC01 looked
      // IDENTICAL to an attached one, which is how "detach is a silent no-op"
      // stayed invisible long enough to ship. Dashed amber, so it reads as
      // "unfinished" rather than "broken" — validateTopology's `no-nic` error
      // repaints it red when the spec is actually submitted.
      { selector: 'node[kind="vm"][!attached]', style: {
          'border-color': theme.warning, 'border-width': 3, 'border-style': 'dashed' } },
      // Validation state. Painted from data so a re-validate is a data update,
      // not a restyle.
      { selector: 'node[severity="error"]',   style: { 'border-color': theme.danger,  'border-width': 3 } },
      { selector: 'node[severity="warning"]', style: { 'border-color': theme.warning, 'border-width': 3 } },
      // A machine whose placement is fixed by the GOAD lab definition.
      { selector: 'node[?locked]', style: { 'border-style': 'double', 'border-width': 4 } },

      {
        selector: 'edge',
        style: {
          'width': 2,
          'line-color': 'data(accent)',
          'curve-style': 'bezier',
          'target-arrow-shape': 'none',
          'label': 'data(label)',
          'font-size': 9,
          'color': theme.textMuted,
          'text-background-color': theme.card,
          'text-background-opacity': theme.dark ? 0.75 : 0.9,
          'text-background-padding': 2,
          'text-rotation': 'autorotate',
          'overlay-opacity': 0
        }
      },
      { selector: 'edge[kind="uplink"]', style: { 'line-style': 'dotted', 'width': 2, 'label': '' } },

      { selector: ':selected', style: { 'border-color': theme.primary, 'border-width': 4 } },
      // A NIC edge now SELECTS on tap instead of detaching (see the cxttap
      // section below), so selection has to be visible or the tap looks dead.
      { selector: 'edge:selected', style: { 'line-color': theme.primary, 'width': 4 } },
      { selector: '.eh-handle', style: {
          'background-color': theme.primary, 'width': 12, 'height': 12,
          'shape': 'ellipse', 'overlay-opacity': 0, 'border-width': 8,
          'border-opacity': 0, 'label': '' } },
      { selector: '.eh-ghost-edge, .eh-preview', style: {
          'line-color': theme.primary, 'width': 3, 'target-arrow-shape': 'none',
          'line-style': 'dashed', 'label': '' } },
      { selector: '.eh-ghost-edge.eh-preview-active', style: { 'opacity': 0 } },
      { selector: '.eh-target, .eh-source', style: {
          'border-color': theme.primary, 'border-width': 4 } }
    ];
  }

  // ── instance ───────────────────────────────────────────────────────────────

  /**
   * create(container, opts) → instance
   *
   * opts:
   *   mode       'edit' | 'view'                (default 'view')
   *   onChange   fn()          structural change happened (edit only)
   *   onSelect   fn(node|null) selection changed
   *   onContextMenu fn(ev)     right-click, edit only. ev is
   *                            { kind:'machine'|'nic'|'segment'|'background',
   *                              vmId?, segId?, nicIndex?, pageX, pageY,
   *                              renderedPosition, position }.
   *                            REPORTS ONLY — every guard lives in the editor.
   *   onEscape   fn()          Escape pressed (an edgehandles drag in flight
   *                            has already been cancelled by then)
   */
  function create(container, opts) {
    opts = opts || {};
    var mode = opts.mode === 'edit' ? 'edit' : 'view';
    var theme = readTheme();

    var state = { segments: [], nodes: [], gateway: null };

    var cy = global.cytoscape({
      container: container || undefined,
      // No container → build the graph but no canvas renderer. Production always
      // passes one; this is what lets test/topology-render.test.js exercise the
      // data → graph mapping without a browser.
      headless: !container,
      style: stylesheet(theme),
      // Machines are dragged by hand in edit mode; in view mode a layout runs,
      // because a live lane has no stored positions.
      layout: { name: 'preset' },
      minZoom: 0.25,
      maxZoom: 2.5,
      // wheelSensitivity deliberately left at the default — Cytoscape warns that
      // overriding it makes zoom behave badly on hardware other than the author's.
      boxSelectionEnabled: false,
      autoungrabify: mode === 'view',
      autounselectify: false
    });

    var eh = null;
    var onKeyDown = null;   // Escape-cancels-drag listener, removed on destroy
    var suppress = false;   // guard so programmatic rebuilds don't fire onChange

    function fireChange() { if (!suppress && opts.onChange) opts.onChange(); }

    // ── build ────────────────────────────────────────────────────────────────
    function buildElements() {
      var els = [];

      state.segments.forEach(function (seg) {
        var accent = segColor(theme, seg.role);
        els.push({
          group: 'nodes',
          data: {
            id: segEl(seg.id), kind: 'segment', segId: seg.id, role: seg.role,
            accent: accent,
            label: seg.cidr ? seg.label + '\n' + seg.cidr : seg.label
          },
          position: seg.layout || null,
          grabbable: mode === 'edit',
          selectable: false
        });
      });

      if (state.gateway) {
        els.push({
          group: 'nodes',
          data: {
            id: 'gw', kind: 'gateway',
            label: state.gateway.label || 'Lane gateway',
            icon: Icons.for({ kind: 'gateway' }, theme.primary)
          },
          position: state.gateway.layout || null,
          grabbable: mode === 'edit',
          selectable: false
        });
        // The gateway owns every segment; drawn dotted so it reads as fixed
        // infrastructure rather than something an author wired up.
        state.segments.forEach(function (seg) {
          els.push({ group: 'edges', data: {
            id: 'gw->' + segEl(seg.id), kind: 'uplink',
            source: 'gw', target: segEl(seg.id),
            accent: segColor(theme, seg.role)
          }, selectable: false });
        });
      }

      state.nodes.forEach(function (n) {
        els.push({
          group: 'nodes',
          data: {
            id: vmEl(n.id), kind: 'vm', vmId: n.id,
            label: (n.ip ? n.name + '\n' + n.ip : n.name)
                   + (n.badge === 'console' ? '\n\u25b8 student console' : ''),
            role: n.role || '', locked: !!n.locked,
            severity: n.severity || '',
            // Drives the unattached warning ring. A boolean, not a count: the
            // stylesheet selector is [!attached] and Cytoscape treats 0 and
            // false the same, but writing the boolean keeps the data readable
            // in devtools when someone is asking "why is this ring amber?".
            attached: (n.segments || []).length > 0,
            // Which machine the student's Guacamole session opens onto.
            // Deliberately NOT folded into `severity` (already used here for
            // "not running", so the two would paint the same amber and cancel
            // out) and NOT into `role` (that drives the icon via
            // Icons.glyphKey, so role:'console' would break the dmz/attacker/dc
            // glyphs).
            badge: n.badge || '',
            icon: Icons.for(n, theme.text)
          },
          position: n.layout || null,
          grabbable: mode === 'edit'
        });

        (n.segments || []).forEach(function (segId, i) {
          if (!state.segments.some(function (s) { return s.id === segId; })) return;
          els.push({
            group: 'edges',
            data: {
              id: vmEl(n.id) + '->' + segEl(segId) + ':' + i,
              kind: 'nic', vmId: n.id, segId: segId, nicIndex: i,
              source: vmEl(n.id), target: segEl(segId),
              accent: segColor(theme, (state.segments.find(function (s) { return s.id === segId; }) || {}).role),
              label: 'net' + i
            },
            selectable: mode === 'edit'
          });
        });
      });

      return els;
    }

    /** Re-render from state, preserving current positions where the caller has none. */
    function render(runLayout) {
      suppress = true;
      var kept = {};
      cy.nodes().forEach(function (n) { kept[n.id()] = n.position(); });

      cy.elements().remove();
      cy.add(buildElements());

      cy.nodes().forEach(function (n) {
        var p = n.position();
        if ((!p || (!p.x && !p.y)) && kept[n.id()]) n.position(kept[n.id()]);
      });

      var needsLayout = runLayout || cy.nodes().some(function (n) {
        var p = n.position();
        return !p || (p.x === 0 && p.y === 0);
      });
      if (needsLayout) layout();
      suppress = false;
    }

    /**
     * Auto-arrange. `cose` gives a live lane a readable shape with no stored
     * coordinates — the reason this is Cytoscape and not a pure node-editor
     * library, which would need every position supplied.
     */
    function layout() {
      cy.layout({
        name: 'cose',
        animate: false,
        padding: 40,
        nodeRepulsion: 12000,
        idealEdgeLength: 130,
        nodeDimensionsIncludeLabels: true,
        randomize: false
      }).run();
      cy.fit(undefined, 50);
    }

    // ── edit affordances ─────────────────────────────────────────────────────
    /** A NIC attaches a machine to a segment. Nothing else is a legal edge. */
    function canConnect(src, tgt) {
      if (!src || !tgt) return false;
      if (src.data('kind') !== 'vm' || tgt.data('kind') !== 'segment') return false;
      // Already attached to this segment.
      return !src.edgesTo(tgt).length;
    }

    // edgehandles is a pointer-gesture plugin and needs a real renderer, so it
    // is skipped when headless. Everything below it — the tap/drag handlers and
    // the state they mutate — is registered either way.
    if (mode === 'edit' && container) {
      eh = cy.edgehandles({
        canConnect: canConnect,
        edgeParams: function () { return { data: { kind: 'nic' } }; },
        hoverDelay: 100,
        snap: true,
        snapThreshold: 40,
        noEdgeEventsInDraw: true,
        disableBrowserGestures: true
      });

      cy.on('ehcomplete', function (evt, src, tgt) {
        var vm = findNode(src.data('vmId'));
        var segId = tgt.data('segId');
        if (vm && segId && (vm.segments || []).indexOf(segId) === -1) {
          vm.segments = (vm.segments || []).concat([segId]);
        }
        render(false);
        fireChange();
      });

      // ── Click-to-detach is RETIRED ────────────────────────────────────────
      // `cy.on('tap', 'edge[kind="nic"]', …)` used to strip the NIC right here:
      // one stray click, no confirmation, no undo, and — because an empty
      // `nics: []` is indistinguishable from "not authored" everywhere
      // downstream — the machine then deployed ATTACHED anyway while the canvas
      // showed it floating. Detach now lives in the context menu, where it can
      // be refused with a reason when it is the machine's last NIC.
      //
      // A tap on a NIC edge SELECTS it (edges are already selectable in edit
      // mode and `edge:selected` is styled above), so the gesture still does
      // something visible — it just no longer mutates the spec.

      // Escape cancels an edgehandles drag in flight. Without it the only way
      // out of a half-drawn NIC is to complete it onto some segment and then
      // detach, which is precisely the accidental edit this section removes.
      onKeyDown = function (ev) {
        if (ev.key !== 'Escape' && ev.keyCode !== 27) return;
        if (eh && eh.stop) { try { eh.stop(); } catch (e) { /* not drawing */ } }
        if (opts.onEscape) opts.onEscape();
      };
      document.addEventListener('keydown', onKeyDown);

      // ── Right-click menus ────────────────────────────────────────────────
      // Cytoscape fires `cxttap` natively on nodes, edges and the core, so no
      // context-menu plugin is vendored — public/vendor/ holds three files and
      // there is no build step, and a fourth would be maintained forever for
      // markup the editor can build in twenty lines.
      //
      // This layer only REPORTS the gesture. Every guard (last-NIC refusal,
      // GOAD name locks) lives in topology-editor.js, which is the layer that
      // knows what a machine means; the renderer knows only what was clicked.
      var menuAt = function (kind, evt, extra) {
        if (!opts.onContextMenu) return;
        var oe = evt.originalEvent || {};
        opts.onContextMenu(Object.assign({
          kind: kind,
          // Page coordinates, because the menu is positioned against <body> —
          // the canvas sits inside a grid with overflow and a menu clipped by
          // its own container is worse than no menu.
          pageX: oe.pageX != null ? oe.pageX : (oe.clientX || 0),
          pageY: oe.pageY != null ? oe.pageY : (oe.clientY || 0),
          renderedPosition: evt.renderedPosition || null,
          position: evt.position || null
        }, extra || {}));
      };

      cy.on('cxttap', 'node[kind="vm"]', function (evt) {
        // Select what was right-clicked, so the property panel and the menu are
        // never talking about different machines.
        cy.$('node:selected').unselect();
        evt.target.select();
        menuAt('machine', evt, { vmId: evt.target.data('vmId') });
      });
      cy.on('cxttap', 'edge[kind="nic"]', function (evt) {
        menuAt('nic', evt, {
          vmId: evt.target.data('vmId'),
          segId: evt.target.data('segId'),
          nicIndex: evt.target.data('nicIndex')
        });
      });
      cy.on('cxttap', 'node[kind="segment"]', function (evt) {
        menuAt('segment', evt, { segId: evt.target.data('segId') });
      });
      cy.on('cxttap', function (evt) {
        // Core only — a cxttap on an element bubbles to the core too, and
        // without this guard every machine menu would be replaced by the
        // background menu a moment later.
        if (evt.target !== cy) return;
        menuAt('background', evt, {});
      });

      cy.on('dragfree', 'node', function (evt) {
        var n = evt.target;
        var pos = n.position();
        if (n.data('kind') === 'vm') {
          var vm = findNode(n.data('vmId'));
          if (vm) vm.layout = { x: Math.round(pos.x), y: Math.round(pos.y) };
        } else if (n.data('kind') === 'segment') {
          var seg = state.segments.find(function (s) { return s.id === n.data('segId'); });
          if (seg) seg.layout = { x: Math.round(pos.x), y: Math.round(pos.y) };
        } else if (n.data('kind') === 'gateway' && state.gateway) {
          state.gateway.layout = { x: Math.round(pos.x), y: Math.round(pos.y) };
        }
        fireChange();
      });
    }

    cy.on('select unselect', 'node[kind="vm"]', function () {
      if (!opts.onSelect) return;
      var sel = cy.$('node[kind="vm"]:selected');
      opts.onSelect(sel.length ? findNode(sel[0].data('vmId')) : null);
    });

    function findNode(id) {
      return state.nodes.find(function (n) { return n.id === id; }) || null;
    }

    // ── theme reactivity ─────────────────────────────────────────────────────
    var themeObserver = new MutationObserver(function () {
      var next = readTheme();
      if (next.dark === theme.dark) return;
      theme = next;
      cy.style(stylesheet(theme));
      render(false);
    });
    themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });

    // ── public API ───────────────────────────────────────────────────────────
    return {
      cy: cy,

      /**
       * data: { segments:[{id,role,label,cidr,layout}],
       *         nodes:[{id?,name,role,os,os_family,segments:[segId],layout,
       *                 severity:'error'|'warning', badge:'console', ...}],
       *         gateway:{label,layout}|null }
       * Nodes without an `id` get a stable one, so renaming a machine never
       * orphans its attachments.
       */
      setData: function (data, runLayout) {
        state.segments = (data.segments || []).map(function (s) { return Object.assign({}, s); });
        state.gateway = data.gateway ? Object.assign({}, data.gateway) : null;
        state.nodes = (data.nodes || []).map(function (n) {
          var c = Object.assign({}, n);
          if (!c.id) c.id = nextId('vm');
          c.segments = (c.segments || []).slice();
          return c;
        });
        render(runLayout === true);
      },

      /** Deep copy of current state, positions included. */
      getData: function () {
        return JSON.parse(JSON.stringify({
          segments: state.segments, nodes: state.nodes, gateway: state.gateway
        }));
      },

      getNodes: function () { return state.nodes; },
      getNode: findNode,

      /** Add a machine, optionally at a rendered (screen) position — used by palette drops. */
      addNode: function (node, renderedPos) {
        var c = Object.assign({ segments: [] }, node);
        if (!c.id) c.id = nextId('vm');
        if (renderedPos) {
          var pan = cy.pan(), zoom = cy.zoom();
          c.layout = {
            x: Math.round((renderedPos.x - pan.x) / zoom),
            y: Math.round((renderedPos.y - pan.y) / zoom)
          };
        }
        state.nodes.push(c);
        render(false);
        fireChange();
        return c;
      },

      updateNode: function (id, patch) {
        var n = findNode(id);
        if (!n) return null;
        Object.assign(n, patch);
        render(false);
        fireChange();
        return n;
      },

      removeNode: function (id) {
        state.nodes = state.nodes.filter(function (n) { return n.id !== id; });
        render(false);
        fireChange();
      },

      /** Replace the segment list — called when the subnet scheme changes. */
      setSegments: function (segments) {
        state.segments = segments.map(function (s) { return Object.assign({}, s); });
        var valid = {};
        state.segments.forEach(function (s) { valid[s.id] = true; });
        // Drop attachments to segments that no longer exist, so switching v3→v2
        // cannot leave a machine wired to a vanished network.
        state.nodes.forEach(function (n) {
          n.segments = (n.segments || []).filter(function (s) { return valid[s]; });
        });
        render(true);
        fireChange();
      },

      /**
       * findings: [{ vm: <machine name|null>, severity: 'error'|'warning' }]
       * Errors win over warnings on the same machine.
       */
      setValidation: function (findings) {
        var bySeverity = {};
        (findings || []).forEach(function (f) {
          if (!f.vm) return;
          if (bySeverity[f.vm] !== 'error') bySeverity[f.vm] = f.severity;
        });
        state.nodes.forEach(function (n) { n.severity = bySeverity[n.name] || ''; });
        suppress = true;
        state.nodes.forEach(function (n) {
          var el = cy.$id(vmEl(n.id));
          if (el.length) el.data('severity', n.severity);
        });
        suppress = false;
      },

      fit: function () { cy.fit(undefined, 50); },
      layout: layout,
      resize: function () { cy.resize(); cy.fit(undefined, 50); },
      destroy: function () {
        themeObserver.disconnect();
        // The keydown listener is on `document`, so it outlives the canvas
        // unless it is removed here — and a stale one would call stop() on a
        // destroyed edgehandles instance on the next Escape anywhere on the page.
        if (onKeyDown) document.removeEventListener('keydown', onKeyDown);
        if (eh && eh.destroy) eh.destroy();
        cy.destroy();
      }
    };
  }

  global.CyberCoreTopology = { create: create, readTheme: readTheme };
})(window);
