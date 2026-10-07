/**
 * profile-filler.js
 *
 * Deterministically assembles a student_view JSON from:
 *   - a real-client intake payload (anonymized)
 *   - a deployed crucible_challenge.spec (real VMs the admin built)
 *   - admin-specified filler counts by asset type
 *
 * No AI calls. Fillers only appear in the JSON/documents, never deployed.
 */

const ASSET_TEMPLATES = {
  windows_desktop:    { role: 'workstation', os: 'Windows 11 Pro',   hostnamePrefix: 'ws',     services: [] },
  windows_laptop:     { role: 'workstation', os: 'Windows 11 Pro',   hostnamePrefix: 'lt',     services: [] },
  macos:              { role: 'workstation', os: 'macOS 14',         hostnamePrefix: 'mac',    services: [] },
  linux_workstation:  { role: 'workstation', os: 'Ubuntu 22.04 LTS', hostnamePrefix: 'lnx',    services: [] },
  printer:            { role: 'peripheral',  os: 'Embedded',         hostnamePrefix: 'prn',    services: ['9100/IPP'] },
  mobile_byod:        { role: 'mobile',      os: 'iOS / Android',    hostnamePrefix: 'mob',    services: [] },
  iot:                { role: 'iot',         os: 'Embedded Linux',   hostnamePrefix: 'iot',    services: [] },
  server_windows:     { role: 'server',      os: 'Windows Server 2022', hostnamePrefix: 'wsrv', services: ['445/SMB','3389/RDP'] },
  server_linux:       { role: 'server',      os: 'Ubuntu Server 22.04', hostnamePrefix: 'lsrv', services: ['22/SSH'] }
};

/**
 * Pick a CIDR from the intake's network segments. Falls back to a sane default.
 */
function pickFillerSubnet(intake) {
  const segs = intake?.payload?.sections?.network?.segments || [];
  const first = segs.find(s => s.cidr) || {};
  return (first.cidr && /^\d+\.\d+\.\d+\.\d+\/\d+$/.test(first.cidr)) ? first.cidr : '10.200.0.0/16';
}

/**
 * Produce a simple incrementing IP allocator for the picked /24 base.
 * Accepts any CIDR — uses the first three octets and starts at .100.
 */
function makeIpAllocator(cidr) {
  const base = cidr.split('/')[0];
  const [a, b, c] = base.split('.').map(n => parseInt(n, 10) || 0);
  let host = 100;
  return () => {
    const ip = `${a}.${b}.${c}.${host}`;
    host = host < 250 ? host + 1 : 100; // wrap, best-effort
    return ip;
  };
}

/**
 * Expand challenge.spec.vms into the "real / deployed" asset list.
 */
function realAssetsFromChallenge(challenge) {
  const vms = challenge?.spec?.vms || [];
  return vms.map((vm, i) => ({
    hostname: vm.hostname || vm.name || `vm-${i+1}`,
    role: vm.role || 'server',
    os: vm.os || 'Unknown',
    services: Array.isArray(vm.services) ? vm.services : [],
    deployed: true,
    template_vmid: vm.template_vmid || null,
    ip: vm.ip || null,
    source: 'challenge'
  }));
}

/**
 * Build filler asset objects by type counts.
 */
function buildFillerAssets(filler, allocIp) {
  const out = [];
  Object.entries(filler || {}).forEach(([type, count]) => {
    const n = Math.max(0, Math.min(1000, Number(count) || 0));
    const tpl = ASSET_TEMPLATES[type];
    if (!tpl || !n) return;
    for (let i = 1; i <= n; i++) {
      const hn = `${tpl.hostnamePrefix}${String(i).padStart(3, '0')}`;
      out.push({
        hostname: hn,
        role: tpl.role,
        os: tpl.os,
        services: tpl.services.slice(),
        deployed: false,
        ip: allocIp(),
        source: 'filler',
        asset_type: type
      });
    }
  });
  return out;
}

/**
 * Map intake sections into an "it_environment" block.
 */
function buildItEnvironment(intake) {
  const s = intake?.payload?.sections || {};
  const net = s.network || {};
  const ep  = s.endpoint || {};
  const em  = s.email_web || {};
  const ax  = s.access || {};
  const dp  = s.data || {};
  const va  = s.vuln_audit || {};
  const wl  = s.wireless || {};
  return {
    directory_services: { domain_mode: net.domain_mode || 'unknown', domain: net.domain_cover || null },
    endpoint_security:  { av_vendor: ep.av_vendor || null, disk_encryption: ep.disk_encryption || null, usb_policy: ep.usb_policy || null, patch_cadence: ep.patch_cadence || null },
    email_security:     { provider: em.email_provider || null, spf: em.spf, dkim: em.dkim, dmarc: em.dmarc, web_filtering: em.web_filtering },
    access_control:     { mfa_coverage: ax.mfa_coverage, privileged_accounts: ax.priv_count_band, password_manager: ax.password_manager, lockout_policy: ax.lockout_policy, dormant_cleanup: ax.dormant_cleanup },
    data_protection:    { backup_cadence: dp.backup_cadence, offsite: dp.offsite_backup, offline: dp.offline_backup, encryption_at_rest: dp.encryption_at_rest, dlp: dp.dlp, restore_test: dp.restore_test },
    monitoring:         { vuln_scanning: va.vuln_scanning, logging_coverage: va.logging_coverage, siem: va.siem, audit_retention: va.audit_retention },
    wireless:           { ssid_count: wl.ssid_count, encryption: wl.wifi_encryption, guest_wifi: wl.guest_wifi, guest_isolated: wl.guest_isolated }
  };
}

/**
 * Build a threat-profile narrative from IG1 "no" and "partial" answers.
 */
function buildThreatProfile(intake, ig1List) {
  const ig1 = intake?.payload?.sections?.ig1 || {};
  const gaps = [];
  const partials = [];
  ig1List.forEach(sg => {
    const ans = ig1[`ig1_${sg.num}`];
    if (ans === 'no')      gaps.push({ num: sg.num, name: sg.name, control: sg.control_name });
    if (ans === 'partial') partials.push({ num: sg.num, name: sg.name, control: sg.control_name });
  });
  const threat_themes = [];
  if (gaps.some(g => g.num.startsWith('10.'))) threat_themes.push('Malware / ransomware likely to succeed');
  if (gaps.some(g => g.num.startsWith('11.'))) threat_themes.push('No reliable recovery path after a destructive incident');
  if (gaps.some(g => g.num.startsWith('6.')))  threat_themes.push('Credential abuse and unauthorized access risk');
  if (gaps.some(g => g.num.startsWith('14.'))) threat_themes.push('Phishing and social-engineering exposure');
  if (gaps.some(g => g.num.startsWith('8.')))  threat_themes.push('Incidents may go undetected due to logging gaps');
  if (gaps.some(g => g.num.startsWith('3.')))  threat_themes.push('Sensitive data exposure if assets are lost or compromised');
  return {
    ig1_gaps: gaps,
    ig1_partials: partials,
    ig1_coverage_pct: Math.round(((ig1List.length - gaps.length - partials.length) / ig1List.length) * 100),
    themes: threat_themes
  };
}

/**
 * Assemble the full student_view JSON.
 */
function buildStudentView({ intake, challenge, filler, ig1List }) {
  const cover = intake.cover_name;
  const cidr  = pickFillerSubnet(intake);
  const alloc = makeIpAllocator(cidr);
  const real   = realAssetsFromChallenge(challenge);
  const fillerAssets = buildFillerAssets(filler, alloc);

  const org = {
    company_name:   cover,
    industry:       intake?.payload?.sections?.company?.industry || 'Unknown',
    employees_band: intake?.payload?.sections?.company?.employees_band || null,
    region:         intake?.payload?.sections?.company?.region || null,
    revenue_band:   intake?.payload?.sections?.company?.revenue_band || null,
    frameworks:     intake?.payload?.sections?.company?.frameworks || [],
    domain_public:  null
  };

  const network = {
    total_assets: real.length + fillerAssets.length,
    real_count:   real.length,
    filler_count: fillerAssets.length,
    segments:     intake?.payload?.sections?.network?.segments || [],
    assets:       [...real, ...fillerAssets]
  };

  return {
    student_view: {
      quick: {
        company_name: org.company_name,
        industry: org.industry,
        employees_total: null,
        domain_public: null
      },
      raw: {
        threats: {
          organization:   org,
          network:        network,
          it_environment: buildItEnvironment(intake),
          threat_profile: buildThreatProfile(intake, ig1List),
          stakeholders:   []
        }
      },
      meta: {
        profile_source: 'real_intake',
        intake_id:      intake.id,
        cover_name:     cover,
        challenge_id:   challenge?.challenge_id || null,
        generated_at:   new Date().toISOString(),
        filler_counts:  filler || {}
      }
    }
  };
}

module.exports = { buildStudentView, ASSET_TEMPLATES };
