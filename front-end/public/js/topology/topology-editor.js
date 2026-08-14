/**
 * topology-editor.js — the challenge authoring canvas.
 *
 * Wraps topology-render.js with the three things authoring needs: a palette of
 * VM templates to drag in, a property panel for the selected machine, and a
 * findings list from the validator.
 *
 * ── It does not own the data ────────────────────────────────────────────────
 * `templateVMs` in admin-challenges.js stays the single source of truth. This
 * module reads that array, and writes attachments (`nics`) and canvas positions
 * (`layout`) back onto the same objects. The existing table editor therefore
 * keeps working unchanged, both views stay in sync, and saveTemplate() posts the
 * same `vm_specs` it always did — just with two more keys on each row.
 *
 * Requires: topology-render.js, topology-icons.js, and a global `api(method, path)`.
 *
 * Global: window.CyberCoreTopologyEditor
 */
(function (global) {
  'use strict';

  var Icons = global.CyberCoreTopologyIcons;

  // ── segment model — mirrors lane-networking.resolveSegments ───────────────
  function segmentsForScheme(scheme) {
    if (scheme === 'v3') {
      return [
        { id: 'ext', role: 'external', label: 'External / Attacker' },
        { id: 'int', role: 'internal', label: 'Internal / Corp' }
      ];
    }
    return [{ id: 'lan', role: 'lan', label: 'Lane Network' }];
  }

  /**
   * Where a machine sits when its spec has no explicit `nics`.
   *
   * This MIRRORS lane-networking.resolveVmSegments and must not drift from it:
   * opening an existing challenge has to show where its machines actually land
   * today, not where a default would put them. The duplication is deliberate —
   * the alternative is a server round-trip before the canvas can draw anything,
   * including while the author is still editing unsaved rows.
   *
   * test/topology-editor-derive.test.js asserts the two agree.
   */
  function deriveSegments(vm, scheme, isGoadVm) {
    var explicit = (vm && Array.isArray(vm.nics)) ? vm.nics.filter(function (n) { return n && n.segment; }) : [];
    if (explicit.length) return explicit.map(function (n) { return String(n.segment); });

    var isV3 = scheme === 'v3';
    var type = (vm && vm.type) || 'qemu';
    if (isV3 && vm && vm.role === 'dmz' && type !== 'lxc') return ['ext', 'int'];
    if (isV3 && isGoadVm) return ['int'];
    return [isV3 ? 'ext' : 'lan'];
  }

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  // ── controller ───────────────────────────────────────────────────────────

  /**
   * mount(opts) → controller
   *
   * opts:
   *   canvasEl, paletteEl, panelEl, findingsEl   DOM nodes
   *   vms          array of templateVMs rows (mutated in place)
   *   subnetScheme 'v1' | 'v2' | 'v3'
   *   network      existing spec.network, or null
   *   goadHosts    array of GOAD lab host names, or null
   *   onChange     fn() — called after any structural or property edit
   */
  function mount(opts) {
    var canvasEl = opts.canvasEl;
    var paletteEl = opts.paletteEl;
    var panelEl = opts.panelEl;
    var findingsEl = opts.findingsEl;

    var vms = opts.vms || [];
    var scheme = opts.subnetScheme || 'v1';
    var network = opts.network || null;
    var goadHosts = normaliseGoad(opts.goadHosts);
    var selectedId = null;
    var catalog = [];

    function normaliseGoad(names) {
      if (!names || !names.length) return null;
      var set = {};
      names.forEach(function (n) { set[String(n).toLowerCase()] = true; });
      return set;
    }
    function isGoadVm(vm) {
      return !!(goadHosts && vm && vm.name && goadHosts[String(vm.name).toLowerCase()]);
    }

    // Cytoscape measures its container on init, so a modal that is still hidden
    // yields a 0×0 graph. Callers must mount after the modal is visible; resize()
    // exists for the case where it becomes visible later.
    var cyEl = document.createElement('div');
    cyEl.className = 'topo-cy';
    canvasEl.appendChild(cyEl);

    var topo = global.CyberCoreTopology.create(cyEl, {
      mode: 'edit',
      onChange: syncFromCanvas,
      onSelect: function (node) {
        selectedId = node ? node.id : null;
        renderPanel();
      }
    });

    // ── vms[] ⇄ canvas ─────────────────────────────────────────────────────
    // A stable per-row id survives renames, which is what keeps a machine's
    // attachments attached when its name changes. Stored on the row itself and
    // stripped before save (see stripInternal).
    var nextLocalId = 1;
    function idFor(vm) {
      if (!vm.__topoId) vm.__topoId = 'r' + (nextLocalId++);
      return vm.__topoId;
    }

    function toCanvas(runLayout) {
      var segs = segmentsForScheme(scheme);
      if (network && network.layout) {
        segs.forEach(function (s) { if (network.layout[s.id]) s.layout = network.layout[s.id]; });
      }
      topo.setData({
        segments: segs,
        gateway: { label: 'Lane gateway', layout: network && network.layout && network.layout.__gw },
        nodes: vms.map(function (vm) {
          return {
            id: idFor(vm),
            name: vm.name || '(unnamed)',
            role: vm.role || '',
            os: vm.os || '',
            os_family: vm.os_family || '',
            template_vmid: vm.template_vmid,
            type: vm.type || 'qemu',
            vm_offset: vm.vm_offset,
            layout: vm.layout || null,
            // GOAD lab hosts are placed by the lab definition, not by hand.
            locked: isGoadVm(vm),
            segments: deriveSegments(vm, scheme, isGoadVm(vm))
          };
        })
      }, runLayout === true);
    }

    /** Canvas → vms[]. Writes attachments and positions back onto the rows. */
    function syncFromCanvas() {
      var data = topo.getData();
      var byId = {};
      data.nodes.forEach(function (n) { byId[n.id] = n; });

      // Machines added by a palette drop exist on the canvas before they exist
      // in vms[]; adopt them here so there is exactly one creation path.
      data.nodes.forEach(function (n) {
        if (!vms.some(function (vm) { return vm.__topoId === n.id; })) {
          vms.push({
            __topoId: n.id, name: n.name, role: n.role || '', os: n.os || '',
            os_family: n.os_family || '', template_vmid: n.template_vmid || null,
            type: n.type || 'qemu', vm_offset: n.vm_offset, services: [], default_scripts: []
          });
        }
      });

      // Removals on the canvas remove the row.
      for (var i = vms.length - 1; i >= 0; i--) {
        if (vms[i].__topoId && !byId[vms[i].__topoId]) vms.splice(i, 1);
      }

      vms.forEach(function (vm) {
        var n = byId[vm.__topoId];
        if (!n) return;
        vm.layout = n.layout || vm.layout;
        // Only write nics[] when the placement differs from what the derivation
        // would produce anyway. Keeps untouched legacy specs byte-identical
        // rather than rewriting every row the moment the canvas is opened.
        var derived = deriveSegments({ role: vm.role, type: vm.type }, scheme, isGoadVm(vm));
        var current = n.segments || [];
        if (current.join('|') === derived.join('|')) delete vm.nics;
        else vm.nics = current.map(function (s) { return { segment: s }; });
      });

      network = network || {};
      network.version = 1;
      network.segments = segmentsForScheme(scheme);
      network.layout = {};
      data.segments.forEach(function (s) { if (s.layout) network.layout[s.id] = s.layout; });
      if (data.gateway && data.gateway.layout) network.layout.__gw = data.gateway.layout;

      renderPanel();
      if (opts.onChange) opts.onChange();
    }

    // ── palette ────────────────────────────────────────────────────────────
    function renderPalette() {
      var theme = global.CyberCoreTopology.readTheme();
      if (!catalog.length) {
        paletteEl.innerHTML =
          '<div class="topo-section-title">Machines</div>' +
          '<div class="topo-palette-empty">No active templates in the catalog. ' +
          'Add them under <strong>VM Templates</strong>, or use <em>+ Blank machine</em>.</div>' +
          blankButton();
        wirePalette();
        return;
      }

      var groups = {};
      catalog.forEach(function (t) {
        var key = t.os_family || 'other';
        (groups[key] = groups[key] || []).push(t);
      });

      var html = '';
      Object.keys(groups).sort().forEach(function (family) {
        html += '<div class="topo-section-title">' + esc(family.replace(/_/g, ' ')) + '</div>';
        groups[family]
          .sort(function (a, b) { return (b.preferred ? 1 : 0) - (a.preferred ? 1 : 0); })
          .forEach(function (t) {
            html += '<div class="topo-palette-item" draggable="true" data-vmid="' + esc(t.template_vmid) + '">' +
              '<img alt="" src="' + Icons.for({ os_family: t.os_family, os: t.os_name }, theme.text) + '">' +
              '<span class="topo-pi-name" title="' + esc(t.os_name) + '">' + esc(t.os_name) + '</span>' +
              '<span class="topo-pi-vmid">' + esc(t.template_vmid) + '</span>' +
              '</div>';
          });
      });
      paletteEl.innerHTML = html + blankButton();
      wirePalette();
    }

    function blankButton() {
      return '<div class="topo-section-title">Other</div>' +
        '<div class="topo-palette-item" draggable="true" data-vmid="">' +
        '<span class="topo-pi-name">+ Blank machine</span></div>';
    }

    function wirePalette() {
      paletteEl.querySelectorAll('.topo-palette-item').forEach(function (el) {
        el.addEventListener('dragstart', function (ev) {
          ev.dataTransfer.setData('text/plain', el.getAttribute('data-vmid') || '');
          ev.dataTransfer.effectAllowed = 'copy';
        });
      });
    }

    canvasEl.addEventListener('dragover', function (ev) { ev.preventDefault(); ev.dataTransfer.dropEffect = 'copy'; });
    canvasEl.addEventListener('drop', function (ev) {
      ev.preventDefault();
      var vmid = ev.dataTransfer.getData('text/plain');
      var tpl = catalog.find(function (t) { return String(t.template_vmid) === String(vmid); });
      var rect = canvasEl.getBoundingClientRect();

      // Next free offset in the 600000 + n*10000 band the table editor uses.
      var used = {};
      vms.forEach(function (v) { used[v.vm_offset] = true; });
      var offset = 600000;
      while (used[offset]) offset += 10000;

      var name = tpl ? uniqueName(slug(tpl.os_name)) : uniqueName('machine');
      topo.addNode({
        name: name,
        role: '',
        os: tpl ? tpl.os_name : '',
        os_family: tpl ? tpl.os_family : '',
        template_vmid: tpl ? tpl.template_vmid : null,
        type: (tpl && tpl.provider_type) || 'qemu',
        vm_offset: offset,
        // Drop onto the segment the pointer is over, else the default for the scheme.
        segments: [scheme === 'v3' ? 'ext' : 'lan']
      }, { x: ev.clientX - rect.left, y: ev.clientY - rect.top });
    });

    function slug(s) {
      return String(s || 'machine').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 20) || 'machine';
    }
    function uniqueName(base) {
      var taken = {};
      vms.forEach(function (v) { if (v.name) taken[v.name.toLowerCase()] = true; });
      if (!taken[base]) return base;
      var i = 2;
      while (taken[base + '-' + i]) i++;
      return base + '-' + i;
    }

    // ── property panel ─────────────────────────────────────────────────────
    function selectedVm() {
      return vms.find(function (v) { return v.__topoId === selectedId; }) || null;
    }

    function renderPanel() {
      var vm = selectedVm();
      if (!vm) {
        panelEl.innerHTML =
          '<div class="topo-section-title">Machine</div>' +
          '<div class="topo-panel-empty">Select a machine to edit it.<br><br>' +
          'Drag from the palette to add one. Drag from a machine\'s edge handle to a ' +
          'network to attach it; click a link to detach.</div>';
        return;
      }
      var locked = isGoadVm(vm);
      var f = function (label, key, type, attrs, hint) {
        return '<div class="topo-field"><label>' + esc(label) + '</label>' +
          '<input type="' + type + '" data-key="' + key + '" value="' + esc(vm[key] == null ? '' : vm[key]) + '" ' +
          (attrs || '') + '>' + (hint ? '<div class="topo-field-hint">' + hint + '</div>' : '') + '</div>';
      };

      panelEl.innerHTML =
        '<div class="topo-section-title">Machine</div>' +
        f('Name', 'name', 'text', locked ? 'disabled' : '',
          locked ? 'Fixed by the GOAD lab definition — renaming it here would break the domain join.' : '') +
        f('Role', 'role', 'text', '', 'dmz = dual-homed pivot · attacker = Kali · dc = domain controller') +
        f('OS', 'os', 'text', '') +
        f('Template VMID', 'template_vmid', 'number', '') +
        f('VM offset', 'vm_offset', 'number', '', 'VMID = offset + lane VXLAN id. Must be unique.') +
        '<div class="topo-field"><label>Type</label><select data-key="type">' +
          '<option value="qemu"' + (vm.type !== 'lxc' ? ' selected' : '') + '>qemu</option>' +
          '<option value="lxc"' + (vm.type === 'lxc' ? ' selected' : '') + '>lxc</option>' +
        '</select></div>' +
        '<div class="topo-field"><label>Services</label>' +
          '<input type="text" data-key="services" value="' + esc((vm.services || []).join(', ')) + '"></div>' +
        '<div class="topo-field"><label>Default scripts</label>' +
          '<input type="text" data-key="default_scripts" value="' + esc((vm.default_scripts || []).join(', ')) + '"></div>';

      panelEl.querySelectorAll('[data-key]').forEach(function (input) {
        input.addEventListener('change', function () {
          var key = input.getAttribute('data-key');
          var val = input.value;
          if (key === 'template_vmid' || key === 'vm_offset') val = parseInt(val, 10) || null;
          else if (key === 'services' || key === 'default_scripts') {
            val = val.split(',').map(function (s) { return s.trim(); }).filter(Boolean);
          }
          vm[key] = val;
          toCanvas(false);
          if (opts.onChange) opts.onChange();
        });
      });
    }

    // ── findings ───────────────────────────────────────────────────────────
    function renderFindings(result) {
      if (!findingsEl) return;
      var all = (result && result.findings) || [];
      if (!all.length) {
        findingsEl.innerHTML = '<div class="topo-findings-ok">No problems found.</div>';
        return;
      }
      findingsEl.innerHTML = '<div class="topo-findings">' + all.map(function (f) {
        return '<div class="topo-finding is-' + esc(f.severity) + '">' +
          (f.vm ? '<span class="topo-finding-vm">' + esc(f.vm) + '</span>' : '') +
          '<span>' + esc(f.message) + '</span></div>';
      }).join('') + '</div>';
    }

    // ── init ───────────────────────────────────────────────────────────────
    toCanvas(true);
    renderPanel();

    (async function loadCatalog() {
      try {
        var rows = await global.api('GET', '/workstation-templates');
        catalog = (Array.isArray(rows) ? rows : (rows && rows.templates) || [])
          .filter(function (t) { return t.is_active !== false && t.status !== 'retired'; });
      } catch (e) {
        catalog = [];
      }
      renderPalette();
    })();

    return {
      /** Re-read vms[] after the table editor or a GOAD toggle changed it. */
      refresh: function (nextVms) {
        if (nextVms) vms = nextVms;
        toCanvas(false);
        renderPanel();
      },
      setScheme: function (next) {
        if (next === scheme) return;
        scheme = next;
        topo.setSegments(segmentsForScheme(scheme));
        toCanvas(true);
      },
      setGoadHosts: function (names) { goadHosts = normaliseGoad(names); toCanvas(false); },
      getNetwork: function () { return network; },
      getVms: function () { return vms; },
      setFindings: function (result) {
        topo.setValidation((result && result.findings) || []);
        renderFindings(result);
      },
      fit: function () { topo.fit(); },
      relayout: function () { topo.layout(); },
      resize: function () { topo.resize(); },
      destroy: function () { topo.destroy(); if (cyEl.parentNode) cyEl.parentNode.removeChild(cyEl); }
    };
  }

  /**
   * Strip the editor's bookkeeping keys before a spec is saved or exported.
   * `__topoId` is a per-session handle and must never reach the database.
   */
  function stripInternal(vms) {
    return (vms || []).map(function (vm) {
      var copy = {};
      Object.keys(vm).forEach(function (k) { if (k !== '__topoId') copy[k] = vm[k]; });
      return copy;
    });
  }

  global.CyberCoreTopologyEditor = {
    mount: mount,
    segmentsForScheme: segmentsForScheme,
    deriveSegments: deriveSegments,
    stripInternal: stripInternal
  };
})(window);
