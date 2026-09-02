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

  /**
   * THE RULE THE CONTEXT MENU EXISTS TO ENFORCE, as a pure function.
   *
   * A machine must keep AT LEAST ONE NIC, and a GOAD-locked host may not be
   * renamed or removed. Both decisions live here rather than inside the menu
   * builder so they can be tested without a browser — the menu itself is DOM
   * and hit-testing, which this repo deliberately does not test headlessly.
   *
   * WHY THE LAST DETACH IS REFUSED RATHER THAN ACCEPTED. A VM with no network
   * in this platform is useless: no DHCP lease, no Guacamole target, no
   * post-clone scripts. Worse, "no NICs" cannot survive the round trip — an
   * authored `nics: []` is indistinguishable from an absent key in
   * buildSpecVm's normaliseNics, so lane-networking re-derives a placement and
   * the machine deploys ATTACHED while the canvas shows it floating. That is
   * the silent lie click-to-detach used to produce on a single stray click.
   *
   * WHY RENAME IS LOCKED. prepareGoadMacs matches AD hosts BY NAME. A rename
   * does not rename a domain controller; it converts it into a machine the
   * GOAD layer has never heard of — no deterministic MAC, no DHCP reservation,
   * no WinRM wait, no secure-channel heal — and assertGoadRoster then refuses
   * the deploy. Remove is the same statement one step on: the roster check runs
   * in BOTH directions.
   *
   * @param {{name?:string, nicCount:number, locked?:boolean}} state
   * @returns {{detach:{allowed,reason}, rename:{allowed,reason}, remove:{allowed,reason}}}
   */
  function menuGuards(state) {
    state = state || {};
    var nics = Math.max(0, Number(state.nicCount) || 0);
    var locked = !!state.locked;
    var name = state.name || 'this machine';

    var lockReason = 'Fixed by the GOAD lab: the deploy matches AD hosts by name, so renaming or ' +
      'removing this machine breaks its domain join. Untick the lab (or its extension) instead.';

    var detachReason = null;
    if (nics === 1) {
      detachReason = 'This is the only network ' + name + ' has. A machine with no NIC gets no DHCP ' +
        'lease, no console connection and no post-clone scripts — and because an empty nics list reads ' +
        'downstream as "not authored", it would deploy attached anyway while the canvas showed it ' +
        'floating. Use "Move to" instead.';
    } else if (nics < 1) {
      detachReason = name + ' is not attached to anything.';
    }

    return {
      detach: { allowed: nics >= 2, reason: detachReason },
      rename: { allowed: !locked, reason: locked ? lockReason : null },
      remove: { allowed: !locked, reason: locked ? lockReason : null }
    };
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
      },
      // The renderer reports the gesture; every guard lives in onContextMenu.
      onContextMenu: function (ev) { onContextMenu(ev); },
      onEscape: function () { closeMenu(); }
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
            // So the authoring canvas marks the console machine the same way the
            // instructor's deploy preview will — one visual language for both.
            badge: vm.console_role === 'primary' ? 'console' : '',
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

    /**
     * Add a machine from a catalog template (or blank), at a rendered position.
     *
     * ONE creation path, shared by the palette drop and the background context
     * menu's "Add machine". A second copy would be a second place to forget
     * that a new machine must be born ON a segment — see the zero-NIC rule in
     * the context-menu section.
     */
    function addFromTemplate(tpl, renderedPos) {
      // Next free offset in the 600000 + n*10000 band the table editor uses.
      var used = {};
      vms.forEach(function (v) { used[v.vm_offset] = true; });
      var offset = 600000;
      while (used[offset]) offset += 10000;

      return topo.addNode({
        name: tpl ? uniqueName(slug(tpl.os_name)) : uniqueName('machine'),
        role: '',
        os: tpl ? tpl.os_name : '',
        os_family: tpl ? tpl.os_family : '',
        template_vmid: tpl ? tpl.template_vmid : null,
        type: (tpl && tpl.provider_type) || 'qemu',
        vm_offset: offset,
        // Born attached: the default segment for the scheme.
        segments: [scheme === 'v3' ? 'ext' : 'lan']
      }, renderedPos || null);
    }

    canvasEl.addEventListener('dragover', function (ev) { ev.preventDefault(); ev.dataTransfer.dropEffect = 'copy'; });
    canvasEl.addEventListener('drop', function (ev) {
      ev.preventDefault();
      var vmid = ev.dataTransfer.getData('text/plain');
      var tpl = catalog.find(function (t) { return String(t.template_vmid) === String(vmid); });
      var rect = canvasEl.getBoundingClientRect();
      addFromTemplate(tpl, { x: ev.clientX - rect.left, y: ev.clientY - rect.top });
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
          'network to attach it. Right-click anything — machine, link, network, background — ' +
          'for what you can do to it.</div>';
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
          '<input type="text" data-key="default_scripts" value="' + esc((vm.default_scripts || []).join(', ')) + '"></div>' +

        // Console designation. Mirrors the VM table's radio — both are editors
        // of the same templateVMs row, so an author who never opens the table
        // must still be able to say which machine the student works from.
        '<div class="topo-section-title">Student console</div>' +
        '<div class="topo-field"><label>Role</label><select data-key="console_role">' +
          '<option value=""' + (!vm.console_role ? ' selected' : '') + '>Not a console</option>' +
          '<option value="primary"' + (vm.console_role === 'primary' ? ' selected' : '') + '>Primary — what the student opens</option>' +
          '<option value="secondary"' + (vm.console_role === 'secondary' ? ' selected' : '') + '>Secondary</option>' +
        '</select>' +
        '<div class="topo-field-hint">Publishes this machine on the lane gateway and gives it a Guacamole connection.</div>' +
        // A SIEM golden image is headless Ubuntu Server: no desktop, no xrdp.
        // Designating it produces a lane that deploys clean and hands the
        // student a Guacamole session that connects to nothing — the exact
        // shape of failure this codebase keeps documenting, so it is said HERE,
        // at the moment of the choice, rather than discovered after a deploy.
        (vm.console_role && String(vm.role || '').toLowerCase() === 'siem'
          ? '<div class="topo-field-hint" style="color: var(--warning);">' +
            'This is a SIEM image, and the GOAD ELK box is headless Ubuntu Server — no desktop and no ' +
            'xrdp, so it cannot serve an RDP console as baked. Students should open ws01 (a domain-joined ' +
            'analyst workstation, itself instrumented) or Kali, and browse to the SIEM on port 5601.</div>'
          : '') +
        '</div>' +
        '<div class="topo-field"><label>Console protocol</label><select data-key="console_protocol">' +
          '<option value=""' + (!vm.console_protocol ? ' selected' : '') + '>From the template catalog</option>' +
          ['rdp', 'ssh', 'vnc'].map(function (pr) {
            return '<option value="' + pr + '"' + (vm.console_protocol === pr ? ' selected' : '') + '>' + pr + '</option>';
          }).join('') +
        '</select></div>' +
        f('Console guest port', 'console_port', 'number', '', 'Blank uses the protocol default: rdp 3389, ssh 22, vnc 5900.');

      panelEl.querySelectorAll('[data-key]').forEach(function (input) {
        input.addEventListener('change', function () {
          var key = input.getAttribute('data-key');
          var val = input.value;
          if (key === 'template_vmid' || key === 'vm_offset' || key === 'console_port') {
            val = parseInt(val, 10) || null;
          } else if (key === 'services' || key === 'default_scripts') {
            val = val.split(',').map(function (s) { return s.trim(); }).filter(Boolean);
          }
          // Only ONE machine may be the primary console. The <select> cannot
          // enforce that across rows, so the previous holder is cleared here —
          // otherwise a spec saves with two primaries and the deploy throws.
          if (key === 'console_role' && val === 'primary') {
            vms.forEach(function (other) {
              if (other !== vm && other.console_role === 'primary') delete other.console_role;
            });
          }
          // An empty optional key is DELETED rather than stored as '', so a spec
          // that designates nothing stays byte-identical to one written before
          // these fields existed.
          if ((key === 'console_role' || key === 'console_protocol' || key === 'console_port') && !val) {
            delete vm[key];
          } else {
            vm[key] = val;
          }
          toCanvas(false);
          if (opts.onChange) opts.onChange();
        });
      });
    }

    // ── context menu ───────────────────────────────────────────────────────
    //
    // Built here rather than in topology-render.js because every ITEM in it is
    // a question about meaning, not about rendering: may this machine be
    // renamed (is it a GOAD host?), may this NIC be detached (is it the last
    // one?), which segments is it not on yet. The renderer reports the gesture
    // and knows none of that.
    //
    // ── THE RULE THIS MENU EXISTS TO ENFORCE ──────────────────────────────
    // A machine must keep AT LEAST ONE NIC. A VM with no network in this
    // platform is useless — no DHCP lease, no Guacamole target, no post-clone
    // scripts — and worse, "no NICs" cannot survive the round trip: an authored
    // `nics: []` is indistinguishable from an absent key in buildSpecVm, so
    // lane-networking re-derives a placement and the machine deploys ATTACHED
    // while the canvas shows it floating. So the last detach is REFUSED WITH A
    // REASON rather than accepted and silently undone later. With one NIC the
    // operation offered is "Move to…", which is what the author actually meant.

    var menuEl = null;

    function closeMenu() {
      if (menuEl && menuEl.parentNode) menuEl.parentNode.removeChild(menuEl);
      menuEl = null;
      document.removeEventListener('mousedown', onDocDown, true);
      document.removeEventListener('keydown', onMenuKey, true);
    }
    function onDocDown(ev) {
      if (menuEl && menuEl.contains(ev.target)) return;
      closeMenu();
    }
    function onMenuKey(ev) {
      if (ev.key === 'Escape' || ev.keyCode === 27) closeMenu();
    }

    /**
     * items: [{ label, disabled, reason, onClick, submenu:[…], sep:true }]
     * A DISABLED item keeps its row and prints its reason underneath — that is
     * the whole point of disabling Rename on a GOAD host rather than hiding it.
     */
    function openMenu(title, items, pageX, pageY) {
      closeMenu();
      var live = items.filter(Boolean);
      menuEl = document.createElement('div');
      menuEl.className = 'topo-ctxmenu';

      var html = title ? '<div class="topo-ctxmenu-title">' + esc(title) + '</div>' : '';
      if (!live.length) html += '<div class="topo-ctxmenu-empty">Nothing to do here.</div>';
      live.forEach(function (it, i) {
        if (it.sep) { html += '<div class="topo-ctxmenu-sep"></div>'; return; }
        html += '<div class="topo-ctxmenu-item' + (it.disabled ? ' is-disabled' : '') +
          '" data-i="' + i + '"><span>' + esc(it.label) + '</span>' +
          (it.submenu ? '<span class="topo-ctx-caret">&#9656;</span>' : '') + '</div>';
        if (it.disabled && it.reason) {
          html += '<div class="topo-ctxmenu-reason">' + esc(it.reason) + '</div>';
        }
      });
      menuEl.innerHTML = html;
      document.body.appendChild(menuEl);

      // Keep it on screen. Measured after insertion because the width depends
      // on the longest label, which depends on the lab.
      var r = menuEl.getBoundingClientRect();
      var maxX = window.scrollX + document.documentElement.clientWidth - r.width - 8;
      var maxY = window.scrollY + document.documentElement.clientHeight - r.height - 8;
      menuEl.style.left = Math.max(window.scrollX + 4, Math.min(pageX, maxX)) + 'px';
      menuEl.style.top = Math.max(window.scrollY + 4, Math.min(pageY, maxY)) + 'px';

      menuEl.querySelectorAll('.topo-ctxmenu-item').forEach(function (el) {
        el.addEventListener('click', function (ev) {
          var it = live[Number(el.getAttribute('data-i'))];
          if (!it || it.disabled) return;
          if (it.submenu) {
            // Open the submenu in place. A hover-flyout at this size is fussier
            // to get right than a second click and buys nothing.
            var rect = el.getBoundingClientRect();
            openMenu(it.label, it.submenu, window.scrollX + rect.right - 4, window.scrollY + rect.top);
            ev.stopPropagation();
            return;
          }
          closeMenu();
          it.onClick();
        });
      });

      document.addEventListener('mousedown', onDocDown, true);
      document.addEventListener('keydown', onMenuKey, true);
    }

    /** The segments a machine currently sits on, straight off the canvas. */
    function segsOf(vmId) {
      var n = topo.getNode(vmId);
      return (n && n.segments) ? n.segments.slice() : [];
    }
    function segLabel(id) {
      var s = segmentsForScheme(scheme).find(function (x) { return x.id === id; });
      return s ? s.label : id;
    }
    function setSegs(vmId, next) {
      // updateNode re-renders and fires onChange, which IS syncFromCanvas —
      // calling it again here would run the vms[] reconciliation twice per edit.
      topo.updateNode(vmId, { segments: next });
    }

    function vmByCanvasId(vmId) {
      return vms.find(function (v) { return v.__topoId === vmId; }) || null;
    }

    function buildMachineMenu(ev) {
      var vm = vmByCanvasId(ev.vmId);
      if (!vm) return;
      var on = segsOf(ev.vmId);
      var all = segmentsForScheme(scheme);
      // Every guard in this menu comes from the pure function at the top of the
      // file, so what the UI refuses and what the tests assert are one thing.
      var guards = menuGuards({ name: vm.name, nicCount: on.length, locked: isGoadVm(vm) });

      var items = [];

      items.push({
        label: 'Move to', submenu: all.map(function (s) {
          return {
            label: s.label,
            disabled: on.length === 1 && on[0] === s.id,
            reason: 'Already its only network.',
            onClick: function () { setSegs(ev.vmId, [s.id]); }
          };
        })
      });

      var free = all.filter(function (s) { return on.indexOf(s.id) === -1; });
      items.push({
        label: 'Attach to',
        disabled: !free.length,
        reason: 'Already on every segment this ' + scheme + ' lane has.',
        submenu: free.map(function (s) {
          return { label: s.label, onClick: function () { setSegs(ev.vmId, on.concat([s.id])); } };
        })
      });

      // Offered ONLY at 2+ NICs. At one NIC the honest operation is "Move to…",
      // which is above — see the rule at the top of this section.
      items.push({
        label: 'Detach from',
        disabled: !guards.detach.allowed,
        reason: guards.detach.reason,
        submenu: on.map(function (segId) {
          return {
            label: segLabel(segId),
            onClick: function () {
              setSegs(ev.vmId, on.filter(function (s) { return s !== segId; }));
            }
          };
        })
      });

      items.push({ sep: true });
      items.push({
        label: vm.console_role === 'primary' ? 'Clear student console' : 'Set as student console',
        onClick: function () {
          if (vm.console_role === 'primary') delete vm.console_role;
          else {
            // Exactly one primary. Same clearing the panel select and the table
            // radio do — the canvas cannot be the one editor that lets a spec
            // save with two, because resolveConsolePlan throws at deploy time.
            vms.forEach(function (o) { if (o.console_role === 'primary') delete o.console_role; });
            vm.console_role = 'primary';
          }
          toCanvas(false);
          renderPanel();
          if (opts.onChange) opts.onChange();
        }
      });

      items.push({
        label: 'Duplicate',
        onClick: function () {
          var used = {};
          vms.forEach(function (v) { used[v.vm_offset] = true; });
          var offset = 600000;
          while (used[offset]) offset += 10000;
          var src = topo.getNode(ev.vmId) || {};
          topo.addNode({
            name: uniqueName(slug(vm.name || 'machine')),
            role: vm.role || '', os: vm.os || '', os_family: vm.os_family || '',
            template_vmid: vm.template_vmid || null, type: vm.type || 'qemu',
            vm_offset: offset,
            // A copy that lands on no segment would be born holding the very
            // zero-NIC state this menu refuses to create by hand.
            segments: (src.segments && src.segments.length) ? src.segments.slice() : [all[0].id],
            layout: src.layout ? { x: src.layout.x + 70, y: src.layout.y + 40 } : null
          });
        }
      });

      items.push({
        label: 'Rename…',
        disabled: !guards.rename.allowed,
        reason: guards.rename.reason,
        // window.prompt/alert rather than the app's Toast/Confirm helpers: those
        // live in public/js/app.js, and this module is also loaded by the CLE
        // course page, which does not include it. A shared renderer must not
        // acquire a dependency on one page's chrome — and Confirm has no
        // text-input variant to borrow anyway.
        onClick: function () {
          var next = window.prompt('New name for "' + (vm.name || '') + '"', vm.name || '');
          if (next === null) return;
          next = String(next).trim();
          if (!next) return;
          if (vms.some(function (o) { return o !== vm && String(o.name).toLowerCase() === next.toLowerCase(); })) {
            window.alert('Another machine is already called "' + next + '".');
            return;
          }
          vm.name = next;
          toCanvas(false);
          renderPanel();
          if (opts.onChange) opts.onChange();
        }
      });

      items.push({
        label: 'Remove',
        disabled: !guards.remove.allowed,
        reason: guards.remove.reason,
        onClick: function () { topo.removeNode(ev.vmId); }
      });

      items.push({ sep: true });
      items.push({
        label: 'Properties',
        onClick: function () {
          selectedId = ev.vmId;
          renderPanel();
          if (panelEl.scrollIntoView) panelEl.scrollIntoView({ block: 'nearest' });
        }
      });

      openMenu(vm.name || 'Machine', items, ev.pageX, ev.pageY);
    }

    function buildNicMenu(ev) {
      var vm = vmByCanvasId(ev.vmId);
      if (!vm) return;
      var on = segsOf(ev.vmId);
      var guards = menuGuards({ name: vm.name, nicCount: on.length, locked: isGoadVm(vm) });
      openMenu((vm.name || 'Machine') + ' \u2192 ' + segLabel(ev.segId), [
        {
          label: 'Detach',
          disabled: !guards.detach.allowed,
          reason: guards.detach.reason,
          onClick: function () {
            setSegs(ev.vmId, on.filter(function (s) { return s !== ev.segId; }));
          }
        }
      ], ev.pageX, ev.pageY);
    }

    function buildSegmentMenu(ev) {
      var selected = topo.cy.$('node[kind="vm"]:selected').map(function (n) { return n.data('vmId'); });
      openMenu(segLabel(ev.segId), [
        {
          label: 'Attach selected machines (' + selected.length + ')',
          disabled: !selected.length,
          reason: 'Nothing is selected. Click a machine, or shift-click several.',
          onClick: function () {
            selected.forEach(function (vmId) {
              var on = segsOf(vmId);
              if (on.indexOf(ev.segId) === -1) topo.updateNode(vmId, { segments: on.concat([ev.segId]) });
            });
          }
        },
        { label: 'Auto-arrange', onClick: function () { topo.layout(); } }
      ], ev.pageX, ev.pageY);
    }

    function buildBackgroundMenu(ev) {
      var palette = catalog.slice(0, 12).map(function (t) {
        return {
          label: t.os_name + ' (' + t.template_vmid + ')',
          onClick: function () { addFromTemplate(t, ev.renderedPosition); }
        };
      });
      palette.push({ label: '+ Blank machine', onClick: function () { addFromTemplate(null, ev.renderedPosition); } });

      openMenu('Canvas', [
        { label: 'Add machine', submenu: palette },
        { sep: true },
        { label: 'Auto-arrange', onClick: function () { topo.layout(); } },
        { label: 'Fit', onClick: function () { topo.fit(); } },
        { label: 'Validate', onClick: function () { if (opts.onValidate) opts.onValidate(); } }
      ], ev.pageX, ev.pageY);
    }

    function onContextMenu(ev) {
      if (ev.kind === 'machine') return buildMachineMenu(ev);
      if (ev.kind === 'nic') return buildNicMenu(ev);
      if (ev.kind === 'segment') return buildSegmentMenu(ev);
      return buildBackgroundMenu(ev);
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
      destroy: function () {
        // The menu is appended to <body>, so tearing the canvas down does not
        // take it with it — a remount (a GOAD toggle, a seed load) would
        // otherwise leave an orphan menu wired to a destroyed graph.
        closeMenu();
        topo.destroy();
        if (cyEl.parentNode) cyEl.parentNode.removeChild(cyEl);
      }
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
    stripInternal: stripInternal,
    // Exported so the last-NIC refusal and the GOAD name locks have tests that
    // do not need a browser. See test/topology-context-menu.test.js.
    menuGuards: menuGuards
  };
})(window);
