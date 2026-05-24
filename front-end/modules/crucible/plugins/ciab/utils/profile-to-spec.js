/**
 * profile-to-spec.js — Pure synthesizer
 * ============================================================================
 * Turn an AI-generated CIAB profile into a deployable challenge `spec`,
 * plus a service-gaps report and template-misses report so the admin can
 * see what won't deploy and why.
 *
 * No DB calls — callers pre-fetch vm_template_catalog and vuln_scripts and
 * pass them in. This keeps the function unit-testable and lets the route
 * handler control caching/concurrency.
 *
 * Output `spec` shape matches what the cybercore_lane deploy orchestrator
 * already consumes (admin.js /deploy-lane and /deploy-group are the
 * reference): { vxlan_block, template_node, vms: [...], vuln_app_install }.
 */

const { resolveTemplate } = require('../../../../../src/utils/vm-template-resolver');
const { findScript } = require('../../../../../src/utils/vuln-script-resolver');

// ─── OS string parser ───────────────────────────────────────────────────────
// Profile assets carry `os` as a single human string (e.g. "Windows Server 2022",
// "Ubuntu Server 22.04 LTS"). The template resolver wants {os_family, os_version}.
function parseOs(osString) {
  const s = String(osString || '').trim();
  if (!s) return { os_family: null, os_version: null };

  const lower = s.toLowerCase();

  // Windows
  if (lower.startsWith('windows server')) {
    const m = lower.match(/windows server\s+(\d{4}(?:\s*r2)?)/);
    return { os_family: 'windows_server', os_version: m ? m[1].replace(/\s+/g, '') : null };
  }
  if (lower.startsWith('windows')) {
    const m = lower.match(/windows\s+(\d+|xp|vista|7|8|10|11)/);
    return { os_family: 'windows_client', os_version: m ? m[1] : null };
  }

  // Linux distros (parse before generic "linux")
  if (lower.includes('ubuntu')) {
    const m = lower.match(/ubuntu(?:\s+server)?\s+(\d+\.\d+)/);
    return { os_family: 'linux', os_version: m ? `ubuntu-${m[1]}` : 'ubuntu' };
  }
  if (lower.includes('debian')) {
    const m = lower.match(/debian\s+(\d+)/);
    return { os_family: 'linux', os_version: m ? `debian-${m[1]}` : 'debian' };
  }
  if (lower.includes('rocky') || lower.includes('rhel') || lower.includes('centos') || lower.includes('alma')) {
    const m = lower.match(/(\d+)/);
    return { os_family: 'linux', os_version: m ? `rhel-${m[1]}` : 'rhel' };
  }
  if (lower.includes('linux')) {
    return { os_family: 'linux', os_version: null };
  }

  // macOS / iOS / embedded — return family, version optional. Resolver will
  // typically miss these (no template), they fall into template_misses.
  if (lower.startsWith('macos') || lower.startsWith('mac os')) {
    return { os_family: 'macos', os_version: null };
  }
  if (lower.includes('embedded')) {
    return { os_family: 'embedded', os_version: null };
  }

  return { os_family: null, os_version: null };
}

// ─── Service token parser ───────────────────────────────────────────────────
// Profile services are "port/Service" strings (e.g. "445/SMB", "80/HTTP").
function parseService(token) {
  const str = String(token || '').trim();
  if (!str) return null;
  const idx = str.indexOf('/');
  if (idx === -1) return { port: null, service: str.toLowerCase() };
  const port = parseInt(str.slice(0, idx), 10);
  return {
    port: Number.isFinite(port) ? port : null,
    service: str.slice(idx + 1).trim().toLowerCase()
  };
}

// ─── Asset filter ───────────────────────────────────────────────────────────
function isIncluded(asset, assetSelection) {
  if (!Array.isArray(assetSelection) || assetSelection.length === 0) {
    // Default: only servers
    return String(asset.role || '').toLowerCase() === 'server';
  }
  const sel = assetSelection.find(s => s.hostname === asset.hostname);
  return sel ? !!sel.included : false;
}

// ─── Detect web-server asset (for vuln-app placement) ──────────────────────
function isWebServer(asset) {
  if (String(asset.role || '').toLowerCase() !== 'server') return false;
  const svcs = Array.isArray(asset.services) ? asset.services : [];
  return svcs.some(s => {
    const p = parseService(s);
    return p && (p.port === 80 || p.port === 443 || /^https?$/.test(p.service));
  });
}

// ─── VM type heuristic ──────────────────────────────────────────────────────
// QEMU for everything by default; LXC only when a template explicitly says so.
// The four-rung resolver doesn't return a type — we infer from os_family.
function inferVmType(matchedRow) {
  // If the catalog row has an explicit hint, honor it
  if (matchedRow && matchedRow.row && matchedRow.row.vm_type) return matchedRow.row.vm_type;
  return 'qemu';
}

// ─── Main synthesizer ──────────────────────────────────────────────────────
/**
 * @param {object} args
 * @param {object} args.profile               profiles row + loaded JSON. Expects
 *                                            profile.assets to be the asset array
 *                                            (callers normalize from student_view.raw.threats.network.assets).
 * @param {Array}  args.assetSelection        [{hostname, included:bool}]; falsy → default server-only.
 * @param {Array}  args.vmTemplateCatalog     vm_template_catalog rows.
 * @param {Array}  args.vulnScriptCatalog     vuln_scripts rows.
 * @param {object} [args.vulnApp]             ciab_profile_vuln_apps row (or null).
 * @param {object} [args.options]
 * @param {string} [args.options.subnetScheme='v2']
 * @param {object} [args.options.vxlanBlock]   {start, end} — defaults to {10000, 10009}
 * @param {boolean}[args.options.attackBoxes=true]
 * @param {string} [args.options.templateNode='cyberhub-node-5']
 * @returns {{
 *   spec: {
 *     vxlan_block: {start, end},
 *     subnet_scheme: string,
 *     template_node: string,
 *     vms: Array<{name, hostname, template_vmid, type, vm_offset, role, os_family, services, post_clone_scripts}>,
 *     vuln_app_install: {target_vm, mode, install_script}|null
 *   },
 *   service_gaps: Array<{vm, service, port, reason}>,
 *   template_misses: Array<{hostname, os, reason}>
 * }}
 */
function synthesizeSpecFromProfile({
  profile,
  assetSelection,
  vmTemplateCatalog,
  vulnScriptCatalog,
  vulnApp = null,
  options = {}
}) {
  const subnetScheme = options.subnetScheme || 'v2';
  const vxlanBlock = options.vxlanBlock || { start: 10000, end: 10009 };
  const attackBoxes = options.attackBoxes !== false;
  const templateNode = options.templateNode || 'cyberhub-node-5';

  const assets = Array.isArray(profile && profile.assets) ? profile.assets : [];
  const selected = assets.filter(a => isIncluded(a, assetSelection));

  const vms = [];
  const serviceGaps = [];
  const templateMisses = [];
  let webServerVmName = null;

  // Per-VM offsets follow admin's canonical convention: 600000 + idx * 10000.
  // See front-end/public/admin.html:4275, front-end/migrations/009_multi_vm_support.sql,
  // and modules/.../real-client-intake.js:512 — they all use this formula.
  for (const asset of selected) {
    const { os_family, os_version } = parseOs(asset.os);

    if (!os_family) {
      templateMisses.push({
        hostname: asset.hostname,
        os: asset.os || null,
        reason: 'unparseable_os'
      });
      continue;
    }

    const match = resolveTemplate({ os_family, os_version, role: asset.role }, vmTemplateCatalog);
    if (!match) {
      templateMisses.push({
        hostname: asset.hostname,
        os: asset.os || null,
        reason: 'no_family_match'
      });
      continue;
    }

    // Resolve post-clone scripts for each declared service. Always include any
    // 'init-setup' bootstrap if the catalog has one — keeps deployed VMs in a
    // predictable baseline state before service-specific layers go on top.
    const postCloneScripts = [];
    const seenSlugs = new Set();

    const bootstrap = vulnScriptCatalog.find(r => r.slug === 'init-setup' && r.is_active !== false);
    if (bootstrap) {
      postCloneScripts.push(bootstrap.slug);
      seenSlugs.add(bootstrap.slug);
    }

    const services = Array.isArray(asset.services) ? asset.services : [];
    for (const token of services) {
      const parsed = parseService(token);
      if (!parsed || !parsed.service) continue;

      const script = findScript({
        service: parsed.service,
        os_family,
        role: asset.role,
        prefer_type: 'vulnerable'   // for CIAB labs we want real findings
      }, vulnScriptCatalog);

      if (script) {
        if (!seenSlugs.has(script.slug)) {
          postCloneScripts.push(script.slug);
          seenSlugs.add(script.slug);
        }
      } else {
        serviceGaps.push({
          vm: asset.hostname,
          service: parsed.service,
          port: parsed.port,
          reason: 'no_installer'
        });
      }
    }

    const vmName = asset.hostname;
    vms.push({
      name: vmName,
      hostname: vmName,
      template_vmid: match.template_vmid,
      template_node: match.node || templateNode,
      type: inferVmType(match),
      vm_offset: 600000 + vms.length * 10000,
      role: asset.role,
      os_family,
      os_version,
      services,
      post_clone_scripts: postCloneScripts,
      template_match_type: match.match_type
    });

    // Remember the first web server for vuln-app placement
    if (!webServerVmName && isWebServer(asset)) {
      webServerVmName = vmName;
    }
  }

  // ─── Vuln-app install plan ────────────────────────────────────────────────
  let vulnAppInstall = null;
  if (vulnApp && vulnApp.install_script) {
    const wantedTarget = vulnApp.target_hostname || webServerVmName;
    const targetVm = wantedTarget && vms.find(v => v.name === wantedTarget);

    if (targetVm) {
      vulnAppInstall = {
        target_vm: targetVm.name,
        mode: vulnApp.delivery_mode,
        install_script: vulnApp.install_script,
        source_tree: vulnApp.source_tree || null,
        dockerfile: vulnApp.dockerfile || null
      };
    } else if (vulnApp.delivery_mode === 'standalone_vm') {
      // Caller asked for dedicated VM. Append one extra phantom VM that the
      // orchestrator will clone from a base Ubuntu template.
      vms.push({
        name: 'vuln-app',
        hostname: 'vuln-app',
        template_vmid: 1003,             // base Ubuntu per vm_template_catalog seed
        template_node: templateNode,
        type: 'qemu',
        vm_offset: 600000 + vms.length * 10000,
        role: 'server',
        os_family: 'linux',
        services: ['80/HTTP'],
        post_clone_scripts: [],
        synthetic: true
      });
      vulnAppInstall = {
        target_vm: 'vuln-app',
        mode: 'standalone_vm',
        install_script: vulnApp.install_script,
        source_tree: vulnApp.source_tree || null,
        dockerfile: vulnApp.dockerfile || null
      };
    }
    // else: no web server and not standalone_vm → silently skip; vulnApp stays
    // available in DB for next deploy that does include a web server.
  }

  return {
    spec: {
      vxlan_block: vxlanBlock,
      subnet_scheme: subnetScheme,
      template_node: templateNode,
      attack_boxes: attackBoxes,
      vms,
      vuln_app_install: vulnAppInstall
    },
    service_gaps: serviceGaps,
    template_misses: templateMisses
  };
}

module.exports = {
  synthesizeSpecFromProfile,
  parseOs,
  parseService,
  isWebServer
};
