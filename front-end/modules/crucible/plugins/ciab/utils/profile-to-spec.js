/**
 * profile-to-spec.js — Pure synthesizer
 * ============================================================================
 * Turn an AI-generated CIAB profile into a deployable challenge `spec`,
 * plus a service-gaps report and template-misses report so the admin can
 * see what won't deploy and why.
 *
 * No DB calls — callers pre-fetch cybercore_template_catalog and vuln_scripts and
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
// Matches by either: (a) declared HTTP/HTTPS service, OR (b) hostname pattern
// (any token that is exactly 'web' or 'web<digits>'). The hostname check covers
// AI-generated profiles where the services array is sometimes empty/missing
// but the hostname clearly marks a web server (e.g. 'mercury-web-01', 'web01',
// 'intranet-web'). Per the user's "every company has WEB01" convention.
function isWebServer(asset) {
  if (String(asset.role || '').toLowerCase() !== 'server') return false;

  const svcs = Array.isArray(asset.services) ? asset.services : [];
  const hasHttpService = svcs.some(s => {
    const p = parseService(s);
    return p && (p.port === 80 || p.port === 443 || /^https?$/i.test(p.service));
  });
  if (hasHttpService) return true;

  const hostname = String(asset.hostname || '').toLowerCase();
  const tokens = hostname.split(/[-_.]/);
  return tokens.some(t => /^web\d*$/.test(t));
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
 * @param {Array}  args.vmTemplateCatalog     cybercore_template_catalog rows.
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
    let { os_family, os_version } = parseOs(asset.os);

    // Force web-server hosts to Linux. The vuln-app generator emits Docker /
    // apt install scripts that only run on Linux; if the AI profile gave us a
    // Windows web-01, override the OS to Linux so the bake scripts work and
    // we don't end up with a redundant standalone vuln-app VM. See user's
    // "every company has a WEB01 server" rule.
    if (isWebServer(asset)) {
      if (os_family !== 'linux') {
        console.log(`[profile-to-spec] Forcing ${asset.hostname} to Linux (was ${os_family}) — web servers must be Linux for vuln-app installability`);
      }
      os_family = 'linux';
      os_version = null;
    }

    if (!os_family) {
      templateMisses.push({
        hostname: asset.hostname,
        os: asset.os || null,
        reason: 'unparseable_os'
      });
      continue;
    }

    // For web servers, pass role='web' so the resolver picks a template whose
    // role_hints contains 'web' (e.g. 1005 Debian-web) deterministically,
    // instead of falling back to the most-recent generic Linux template.
    const resolverRole = isWebServer(asset) ? 'web' : asset.role;
    const match = resolveTemplate({ os_family, os_version, role: resolverRole }, vmTemplateCatalog);
    if (!match) {
      console.warn(`[profile-to-spec] No template match for ${asset.hostname} (os_family=${os_family} os_version=${os_version} role=${resolverRole}). Catalog had ${vmTemplateCatalog.filter(r => r.os_family === os_family).length} ${os_family} row(s).`);
      templateMisses.push({
        hostname: asset.hostname,
        os: asset.os || null,
        reason: 'no_family_match'
      });
      continue;
    }
    console.log(`[profile-to-spec] ${asset.hostname} → template_vmid=${match.template_vmid} (${match.os_name}, match=${match.match_type}, role=${resolverRole})`);

    // Resolve post-clone scripts for each declared service. Include the
    // 'init-setup' bootstrap only if its os_target matches the VM's os_family
    // (init-setup is currently Windows-only PowerShell; running it on a Linux
    // VM 596's on every agent/exec call because powershell doesn't exist).
    const postCloneScripts = [];
    const seenSlugs = new Set();

    const lc = s => String(s || '').trim().toLowerCase();
    const bootstrap = vulnScriptCatalog.find(r =>
      r.slug === 'init-setup'
      && r.is_active !== false
      && (!r.os_target || lc(r.os_target) === lc(os_family) || lc(r.os_target) === 'any')
    );
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
  // Targeting order:
  //   1. The cached vulnApp.target_hostname (if that exact host is in vms)
  //   2. Any web-server in this lane's vms (covers asset-selection changes
  //      between profile generation and deploy — the cached target_hostname
  //      may not match the currently-selected web server hostname)
  //   3. Append a DEDICATED standalone vuln-app VM. Most realistic profiles
  //      have NO on-prem web server (small/cloud-first orgs), so this is the
  //      common case, not a rare last resort. The standalone VM is cloned from
  //      the SAME Linux web template a real web server would use, so Docker is
  //      present and the install path is identical. The orchestrator registers
  //      it in the lane's /etc/hosts so students reach the site by URL.
  // Common payload shared by both the on-host and standalone install plans.
  const vulnAppPayload = vulnApp ? {
    install_script: vulnApp.install_script,
    source_tree: vulnApp.source_tree || null,
    dockerfile: vulnApp.dockerfile || null,
    // Color palette lives in the generation_meta JSONB (no dedicated DB
    // column). Read from there with a fallback to a top-level field for
    // any in-memory callers that don't go through the DB round-trip.
    color_palette: (vulnApp.generation_meta && vulnApp.generation_meta.color_palette)
      || vulnApp.color_palette || null,
    // LLM-authored stylesheet (same JSONB round-trip as color_palette).
    // The orchestrator inlines it into every page; null falls back to the
    // themed buildBaseCss().
    app_stylesheet: (vulnApp.generation_meta && vulnApp.generation_meta.app_stylesheet)
      || vulnApp.app_stylesheet || null
  } : null;

  let vulnAppInstall = null;
  if (vulnApp && vulnApp.install_script) {
    let targetVm = vulnApp.target_hostname
      && vms.find(v => v.name === vulnApp.target_hostname);
    if (!targetVm && webServerVmName) {
      targetVm = vms.find(v => v.name === webServerVmName);
    }

    if (targetVm) {
      vulnAppInstall = {
        target_vm: targetVm.name,
        mode: vulnApp.delivery_mode || 'docker',
        ...vulnAppPayload
      };
    } else {
      // No web-server asset in this profile → give the app its own dedicated
      // VM cloned from template 1005, the canonical baked "web-01" template
      // (Debian 13 + Docker + Apache + PHP + SQLite + QEMU guest agent — see
      // scripts/bake-web-template.sh). Docker is pre-baked, so the image
      // build/run install path is identical to deploying onto a real web
      // server. 1005 is baked directly on the Proxmox node, so it's always
      // available even if the template catalog row isn't present.
      const WEB_TEMPLATE_VMID = 1005;
      const webTplRow = vmTemplateCatalog.find(t => Number(t.template_vmid) === WEB_TEMPLATE_VMID);
      vms.push({
        name: 'vuln-app',
        hostname: 'vuln-app',
        template_vmid: WEB_TEMPLATE_VMID,
        template_node: (webTplRow && webTplRow.node) || templateNode,
        type: 'qemu',
        vm_offset: 600000 + vms.length * 10000,
        // role 'server' (not 'web') so the lane's /etc/hosts builder, which
        // keys the company-domain alias off role==='server' + an HTTP service,
        // registers this VM's hostname for the company domain.
        role: 'server',
        os_family: 'linux',
        os_version: null,
        services: ['80/HTTP'],
        post_clone_scripts: [],
        synthetic: true
      });
      vulnAppInstall = {
        target_vm: 'vuln-app',
        mode: vulnApp.delivery_mode || 'docker',
        ...vulnAppPayload
      };
    }
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
