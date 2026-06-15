/**
 * ai/scan-documents/index.js — Profile-driven scan document generator.
 * ============================================================================
 * Generates NMAP Markdown, NESSUS XML, and ZAP HTML for a CIAB profile. Output is
 * entirely deterministic and derived from profile.assets[].services — so a
 * real `nmap` scan against the deployed lane VMs will surface the same ports
 * the fake scan claims to see.
 *
 * No LLM calls. This replaces the hardcoded fallback generators in
 * instructor.js:642-932. Pure JS, sub-second latency, no API cost.
 *
 * The previous generators always emitted MS17-010, BlueKeep, etc. regardless
 * of what services the profile declared — making fake-vs-real diffs glaring
 * the moment a student ran `nmap` themselves. This version emits findings
 * ONLY for services that appear in profile.assets[].services.
 */

const {
  parseServiceEntry,
  getBanner,
  getFindings,
  PORT_DEFAULTS
} = require('./vuln-knowledge');

// ─── helpers ───────────────────────────────────────────────────────────────

function xmlEsc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&apos;');
}
function htmlEsc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// Pick assets that would actually be scanned: servers + network appliances.
// Workstations/IoT/peripherals are excluded — the same filter our deploy
// orchestrator uses (so the fake scan can't include hosts that aren't real).
function scannableAssets(profileData) {
  const assets = Array.isArray(profileData.assets) ? profileData.assets : [];
  return assets.filter(a => {
    const role = String(a.role || '').toLowerCase();
    return role === 'server' || role === 'network';
  });
}

// Build the per-host port list: union of declared services + a small floor of
// info ports (ICMP-equivalent + closed/filtered noise). Every entry traces
// back to a profile.services token — never invented.
function buildHostPorts(asset) {
  const services = Array.isArray(asset.services) ? asset.services : [];
  const ports = [];
  const seen = new Set();

  for (const entry of services) {
    const parsed = parseServiceEntry(entry);
    if (!parsed.port && !parsed.service) continue;
    const port = parsed.port || guessPortForService(parsed.normalized);
    if (!port || seen.has(port)) continue;
    seen.add(port);
    const banner = getBanner(port, parsed.normalized);
    ports.push({
      port,
      protocol: 'tcp',
      state: 'open',
      service: banner.service,
      product: banner.product,
      version: banner.version,
      normalized: parsed.normalized
    });
  }
  return ports.sort((a, b) => a.port - b.port);
}

function guessPortForService(normalized) {
  for (const [port, info] of Object.entries(PORT_DEFAULTS)) {
    if (info.service === normalized) return parseInt(port, 10);
  }
  return null;
}

// Synthesize an IP for an asset that lacks one (phantom assets). Deterministic
// based on hostname so re-runs produce stable scan output.
function assetIp(asset) {
  if (asset.ip && asset.ip !== 'pending') return asset.ip;
  // Hash hostname → octet
  const h = String(asset.hostname || '').split('').reduce((a, c) => (a * 31 + c.charCodeAt(0)) >>> 0, 0);
  return `10.10.${(h >> 8) & 0xFF}.${(h & 0xFF) || 10}`;
}

// ─── NMAP Markdown generator ──────────────────────────────────────────────
// Emits a realistic, human-readable `nmap -sV -sC -O` text report wrapped in a
// Markdown document — the same shape an analyst would paste from a terminal.
// Every host/port/finding still traces back to profile.assets[].services, so a
// real scan of the deployed lane matches this fake report and the Nessus XML.

// Right-pad to a fixed column width (terminal-style alignment).
function pad(s, width) {
  s = String(s == null ? '' : s);
  return s.length >= width ? s + ' ' : s + ' '.repeat(width - s.length);
}

// Deterministic pseudo-random helpers seeded by a string — keeps re-runs stable
// for a given asset (no flapping MAC/latency between regenerations).
function strSeed(s) {
  return String(s || '').split('').reduce((a, c) => (a * 31 + c.charCodeAt(0)) >>> 0, 0);
}
function fakeMac(asset) {
  const seed = strSeed(asset.hostname || asset.ip || 'host');
  const byte = (n) => (((seed >> (n * 5)) & 0xFF) | 0x01).toString(16).toUpperCase().padStart(2, '0');
  const vendor = asset.role === 'network' ? '(Netgate)' : '(VMware)';
  return `${byte(0)}:${byte(1)}:${byte(2)}:${byte(3)}:${byte(4)}:${byte(5)} ${vendor}`;
}
function fakeLatency(asset) {
  const seed = strSeed(asset.hostname || asset.ip || 'host');
  return (0.05 + (seed % 400) / 100).toFixed(4); // 0.05 – 4.05 s
}

// Render the OS-detection block shown after the port table.
function osDetectionBlock(asset) {
  const os = asset.os || '';
  if (!os) return '';
  const isNet = asset.role === 'network';
  const family = guessOsFamily(os);
  const vendor = guessOsVendor(os);
  const cpePart = family === 'Windows'
    ? 'cpe:/o:microsoft:windows'
    : family === 'Linux'
      ? 'cpe:/o:linux:linux_kernel'
      : `cpe:/o:${vendor.toLowerCase()}:${family.toLowerCase()}`;
  return [
    `Device type: ${isNet ? 'firewall|switch|router' : 'general purpose'}`,
    `Running: ${os}`,
    `OS CPE: ${cpePart}`,
    `OS details: ${os}`,
    `Network Distance: 2 hops`
  ].join('\n');
}

// Map a normalized service to realistic nmap host-script (NSE) output. Vuln
// blocks reuse the CVE/severity knowledge so they stay consistent with Nessus;
// info blocks (smb-security-mode, rdp-ntlm-info, ...) mirror what -sC emits.
function nmapScriptBlocks(ports, asset, domain) {
  const blocks = [];
  const normSet = new Set(ports.map(p => p.normalized));
  const hostUpper = String(asset.hostname || 'HOST').toUpperCase();
  const fqdn = domain ? `${asset.hostname}.${domain}` : (asset.hostname || 'host');
  const netbiosDomain = (domain ? domain.split('.')[0] : 'WORKGROUP').toUpperCase().slice(0, 15);

  // Per-service VULNERABLE blocks, derived from the shared finding knowledge.
  for (const p of ports) {
    for (const f of getFindings(p.normalized)) {
      if (f.severity < 3) continue; // only High/Critical surface as nmap vuln scripts
      const scriptId = f.name.toLowerCase().includes('ms17-010') ? 'smb-vuln-ms17-010'
        : f.name.toLowerCase().includes('bluekeep') ? 'rdp-vuln-cve2019-0708'
        : `${p.normalized}-vuln-${(f.cves[0] || f.plugin_id).toLowerCase().replace(/[^a-z0-9]/g, '')}`;
      const cve = f.cves[0] || '';
      blocks.push([
        `| ${scriptId}:`,
        `|     VULNERABLE:`,
        `|     ${f.name}`,
        `|       State: VULNERABLE`,
        cve ? `|       IDs:  CVE:${cve}` : null,
        `|       Risk factor: ${severityName(f.severity).toUpperCase()}  CVSS: ${f.cvss}`,
        `|         ${f.description}`,
        cve ? `|       References:` : null,
        cve ? `|         https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cve}` : null,
        `|`
      ].filter(Boolean).join('\n'));
    }
  }

  // Standard -sC informational scripts, keyed off the services present.
  if (normSet.has('smb')) {
    blocks.push([
      `| smb-security-mode:`,
      `|     account_used: guest`,
      `|     authentication_level: user`,
      `|     challenge_response: supported`,
      `|     message_signing: disabled (dangerous, but default)`,
      `|       WARNING: SMB message signing is not enforced.`,
      `|`
    ].join('\n'));
  }
  if (normSet.has('rdp')) {
    blocks.push([
      `| rdp-ntlm-info:`,
      `|     Target_Name: ${netbiosDomain}`,
      `|     NetBIOS_Domain_Name: ${netbiosDomain}`,
      `|     NetBIOS_Computer_Name: ${hostUpper}`,
      `|     DNS_Domain_Name: ${domain || 'localdomain'}`,
      `|     DNS_Computer_Name: ${fqdn}`,
      `|     NOTE: Network Level Authentication (NLA) is NOT required`,
      `|       WARNING: Remote Desktop accessible without NLA - susceptible to MITM`,
      `|`
    ].join('\n'));
  }
  if (normSet.has('http') || normSet.has('https')) {
    blocks.push([
      `| http-methods:`,
      `|     Supported Methods: GET HEAD POST OPTIONS TRACE`,
      `|       WARNING: TRACE method is enabled.`,
      `|`,
      `| http-security-headers:`,
      `|     MISSING HEADERS:`,
      `|       X-Frame-Options: MISSING`,
      `|       Content-Security-Policy: MISSING`,
      `|       Strict-Transport-Security: MISSING`,
      `|`
    ].join('\n'));
  }
  if (normSet.has('ssh')) {
    blocks.push([
      `| ssh2-enum-algos:`,
      `|     kex_algorithms: (3)`,
      `|         curve25519-sha256`,
      `|         diffie-hellman-group14-sha256`,
      `|         diffie-hellman-group14-sha1`,
      `|     encryption_algorithms: (4)`,
      `|         chacha20-poly1305@openssh.com`,
      `|         aes256-ctr`,
      `|         aes128-cbc`,
      `|         3des-cbc`,
      `|       WARNING: Weak algorithms supported: diffie-hellman-group14-sha1, 3des-cbc, aes*-cbc`,
      `|`
    ].join('\n'));
  }
  if (normSet.has('ftp')) {
    blocks.push([
      `| ftp-anon:`,
      `|     Anonymous FTP login allowed (FTP code 230)`,
      `|`
    ].join('\n'));
  }
  return blocks;
}

// Render one host's full nmap report code block.
function nmapHostBlock(asset, domain) {
  const ip = assetIp(asset);
  const hostname = asset.hostname || 'unknown';
  const fqdn = domain ? `${hostname}.${domain}` : hostname;
  const ports = buildHostPorts(asset);

  const lines = [];
  lines.push(`Nmap scan report for ${fqdn} (${ip})`);
  lines.push(`Host is up (${fakeLatency(asset)}s latency).`);
  lines.push(`MAC Address: ${fakeMac(asset)}`);
  const shown = ports.length;
  lines.push(`Not shown: ${65535 - shown} closed tcp ports (reset)`);
  lines.push('');
  lines.push(`${pad('PORT', 11)}${pad('STATE', 9)}${pad('SERVICE', 17)}VERSION`);
  for (const p of ports) {
    const version = [p.product, p.version].filter(Boolean).join(' ');
    lines.push(`${pad(`${p.port}/${p.protocol}`, 11)}${pad(p.state, 9)}${pad(p.service, 17)}${version}`);
  }
  const osBlock = osDetectionBlock(asset);
  if (osBlock) { lines.push(''); lines.push(osBlock); }

  const scripts = nmapScriptBlocks(ports, asset, domain);
  if (scripts.length) {
    lines.push('');
    lines.push('Host script results:');
    lines.push(scripts.join('\n'));
  }

  // Traceroute through the gateway (first network asset if present).
  lines.push('');
  lines.push(`TRACEROUTE (using port ${ports[0] ? ports[0].port : 80}/tcp)`);
  lines.push(`HOP  RTT       ADDRESS`);
  lines.push(`1    ${fakeLatency(asset)}ms  ${fqdn} (${ip})`);

  return lines.join('\n');
}

function generateNmap({ profileData, companyName, domain }) {
  const targets = scannableAssets(profileData);
  const scanDate = new Date().toUTCString();
  const scanArgs = `nmap -sS -sV -sC -O -A --script=vuln,safe -T4 -p- ${domain || 'targets'}`;

  const header = [
    `# ${companyName} — Network Vulnerability Scan (NMAP)`,
    '',
    `> **Engagement:** Internal authorized vulnerability assessment`,
    `> **Scan Date:** ${scanDate}`,
    `> **Domain:** \`${domain || 'internal'}\``,
    `> **Hosts scanned:** ${targets.length}`,
    '',
    '```',
    `root@scanner:~# ${scanArgs}`,
    '',
    `Starting Nmap 7.94SVN ( https://nmap.org ) at ${scanDate}`,
    `NSE: Loaded 156 scripts for scanning.`,
    `Initiating SYN Stealth Scan`,
    `Scanning ${targets.length} hosts [65535 ports/host]`,
    '```',
    '',
    ''
  ].join('\n');

  if (targets.length === 0) {
    return header + '\n_No scannable server or network assets declared in this profile — nothing to scan._\n';
  }

  const hostSections = targets.map(asset => {
    const hostname = asset.hostname || 'unknown';
    const role = asset.role === 'network' ? 'Network Appliance' : (asset.role_label || 'Server');
    const desc = asset.description || asset.purpose || role;
    const env = asset.os ? `\n> *IT Environment:* **${hostname}** running **${asset.os}** (Role: ${desc})\n` : '';
    return [
      `### ${hostname} (${assetIp(asset)}) — ${desc} [CRITICAL]`,
      env,
      '```',
      nmapHostBlock(asset, domain),
      '```'
    ].join('\n');
  }).join('\n\n');

  const footer = [
    '',
    '',
    '```',
    `NSE: Script Post-scanning.`,
    `OS and Service detection performed.`,
    `Nmap done: ${targets.length} IP addresses (${targets.length} hosts up) scanned in 374.36 seconds`,
    '```',
    '',
    `_Simulated scan output derived from profile asset inventory for a cybersecurity training exercise._`,
    ''
  ].join('\n');

  return header + hostSections + footer;
}

function guessOsVendor(os) {
  const lower = String(os).toLowerCase();
  if (lower.includes('windows')) return 'Microsoft';
  if (lower.includes('ubuntu') || lower.includes('debian')) return 'Linux';
  if (lower.includes('rhel') || lower.includes('rocky') || lower.includes('centos') || lower.includes('alma')) return 'Linux';
  if (lower.includes('mac')) return 'Apple';
  return 'Unknown';
}
function guessOsFamily(os) {
  const lower = String(os).toLowerCase();
  if (lower.includes('windows')) return 'Windows';
  if (lower.includes('mac')) return 'macOS';
  if (lower.includes('linux') || lower.includes('ubuntu') || lower.includes('debian') ||
      lower.includes('rhel') || lower.includes('rocky') || lower.includes('centos')) return 'Linux';
  return 'Unknown';
}

// ─── NESSUS XML generator ─────────────────────────────────────────────────

function generateNessus({ profileData, companyName }) {
  const targets = scannableAssets(profileData);
  const scanName = `${companyName} - Periodic Vulnerability Scan`;
  const scanStart = new Date().toUTCString().replace('GMT', '').trim();

  const hostBlocks = targets.map(asset => {
    const ip = assetIp(asset);
    const hostname = asset.hostname || 'unknown';
    const os = asset.os || 'Unknown';
    const ports = buildHostPorts(asset);

    // Always include a few info-level baseline findings (per-host inventory)
    const baseline = [
      `      <ReportItem port="0" svc_name="general" protocol="tcp" severity="0" pluginID="19506" pluginName="Nessus Scan Information" pluginFamily="Settings">
        <plugin_name>Nessus Scan Information</plugin_name>
        <risk_factor>None</risk_factor>
        <description>This plugin displays information about the Nessus scan.</description>
      </ReportItem>`,
      `      <ReportItem port="0" svc_name="general" protocol="tcp" severity="0" pluginID="11936" pluginName="OS Identification" pluginFamily="General">
        <plugin_name>OS Identification</plugin_name>
        <risk_factor>None</risk_factor>
        <description>Remote operating system: ${xmlEsc(os)}.</description>
      </ReportItem>`
    ];

    // Per-port findings
    const findings = [];
    for (const p of ports) {
      // Always emit a service-detection info finding for each open port (mirrors Nessus 22964)
      findings.push(`      <ReportItem port="${p.port}" svc_name="${xmlEsc(p.service)}" protocol="${p.protocol}" severity="0" pluginID="22964" pluginName="Service Detection" pluginFamily="Service detection">
        <plugin_name>Service Detection</plugin_name>
        <risk_factor>None</risk_factor>
        <description>A ${xmlEsc(p.product || p.service)} server is listening on port ${p.port}.</description>
      </ReportItem>`);

      // Any service-specific known findings
      for (const f of getFindings(p.normalized)) {
        findings.push(`      <ReportItem port="${p.port}" svc_name="${xmlEsc(p.service)}" protocol="${p.protocol}" severity="${f.severity}" pluginID="${f.plugin_id}" pluginName="${xmlEsc(f.name)}" pluginFamily="${xmlEsc(guessPluginFamily(p.normalized))}">
        <plugin_name>${xmlEsc(f.name)}</plugin_name>
        <risk_factor>${severityName(f.severity)}</risk_factor>
        ${f.cvss != null ? `<cvss_base_score>${f.cvss}</cvss_base_score>` : ''}
        ${f.cves.map(c => `<cve>${xmlEsc(c)}</cve>`).join('\n        ')}
        <description>${xmlEsc(f.description)}</description>
        <solution>Apply the vendor's security update or follow CIS-recommended mitigations. Refer to the linked CVE entries for specific patch information.</solution>
      </ReportItem>`);
      }
    }

    return `    <ReportHost name="${xmlEsc(ip)}">
      <HostProperties>
        <tag name="host-ip">${xmlEsc(ip)}</tag>
        <tag name="host-fqdn">${xmlEsc(hostname)}</tag>
        <tag name="operating-system">${xmlEsc(os)}</tag>
        <tag name="HOST_START">${scanStart}</tag>
      </HostProperties>
${[...baseline, ...findings].join('\n')}
    </ReportHost>`;
  }).join('\n');

  return `<?xml version="1.0" ?>
<NessusClientData_v2>
  <Policy>
    <policyName>${xmlEsc(scanName)} Policy</policyName>
    <Preferences>
      <ServerPreferences>
        <preference><name>plugin_set</name><value>baseline_general</value></preference>
      </ServerPreferences>
    </Preferences>
  </Policy>
  <Report name="${xmlEsc(scanName)}" xmlns:cm="http://www.nessus.org/cm">
${hostBlocks}
  </Report>
</NessusClientData_v2>`;
}

function severityName(s) {
  return ['None','Low','Medium','High','Critical'][s] || 'None';
}
function guessPluginFamily(normalized) {
  if (normalized === 'smb' || normalized === 'rdp') return 'Windows';
  if (normalized === 'http' || normalized === 'https') return 'Web Servers';
  if (normalized === 'ssh' || normalized === 'ftp') return 'Misc.';
  if (normalized === 'mysql' || normalized === 'mssql' || normalized === 'postgres') return 'Databases';
  return 'General';
}

// ─── ZAP HTML generator ───────────────────────────────────────────────────
// Only emit findings if at least one scannable asset declares HTTP/HTTPS.
// Otherwise ZAP would have nothing to scan — emit an empty report.

function generateZap({ profileData, companyName, domain }) {
  const targets = scannableAssets(profileData);
  const webHosts = targets.filter(a => {
    const ports = buildHostPorts(a);
    return ports.some(p => p.normalized === 'http' || p.normalized === 'https');
  });

  const scanDate = new Date().toUTCString();
  const target = webHosts[0]
    ? (domain ? `https://${webHosts[0].hostname}.${domain}` : `http://${assetIp(webHosts[0])}`)
    : 'http://(no-web-hosts-in-profile)';

  if (webHosts.length === 0) {
    return wrapZap({
      title: `${companyName} — OWASP ZAP Scan`,
      target,
      scanDate,
      summary: { high: 0, medium: 0, low: 0, info: 0 },
      alertsHtml: '<p>No web-server assets declared in profile — nothing to scan.</p>'
    });
  }

  // Standard ZAP findings that show up on most internal web apps. Filtered
  // to only those plausibly triggered by services the profile actually has.
  const alerts = [];
  for (const host of webHosts) {
    const fqdn = domain ? `${host.hostname}.${domain}` : assetIp(host);
    const base = `http://${fqdn}`;
    alerts.push({
      risk: 'Medium', confidence: 'Medium',
      name: 'Cross-Site Scripting (Reflected)',
      url: `${base}/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E`,
      param: 'q',
      evidence: '<script>alert(1)</script>',
      description: 'Cross-site Scripting (XSS) is an attack technique that involves echoing attacker-supplied code into a user\'s browser instance.',
      solution: 'Phase: Architecture and Design — Use a vetted library or framework that does not allow this weakness to occur.'
    });
    alerts.push({
      risk: 'High', confidence: 'High',
      name: 'SQL Injection',
      url: `${base}/search?q=%27+OR+%271%27%3D%271`,
      param: 'q',
      evidence: 'SQL syntax error in response body',
      description: 'SQL injection may be possible. The page parameter appears to be vulnerable to SQL injection attacks.',
      solution: 'Do not trust client-side input even if there is client-side validation. Check user input against a positive specification.'
    });
    alerts.push({
      risk: 'Medium', confidence: 'High',
      name: 'Missing Anti-clickjacking Header',
      url: base + '/',
      param: '',
      evidence: '',
      description: 'The response does not include either Content-Security-Policy with frame-ancestors directive or X-Frame-Options.',
      solution: 'Modern web browsers support Content-Security-Policy and X-Frame-Options HTTP headers.'
    });
    alerts.push({
      risk: 'Low', confidence: 'Medium',
      name: 'Cookie Without Secure Flag',
      url: base + '/login',
      param: 'session',
      evidence: 'session=...',
      description: 'A cookie has been set without the secure flag, which means that the cookie can be accessed via unencrypted connections.',
      solution: 'Whenever a cookie contains sensitive information, set the secure flag.'
    });
    alerts.push({
      risk: 'Informational', confidence: 'Medium',
      name: 'Server Leaks Version Information via "Server" HTTP Response Header',
      url: base + '/',
      param: '',
      evidence: 'Server: Apache/2.4.52',
      description: 'The web/application server is leaking version information via the "Server" HTTP response header.',
      solution: 'Configure the web server to suppress "Server" header.'
    });
  }

  const summary = {
    high: alerts.filter(a => a.risk === 'High').length,
    medium: alerts.filter(a => a.risk === 'Medium').length,
    low: alerts.filter(a => a.risk === 'Low').length,
    info: alerts.filter(a => a.risk === 'Informational').length
  };

  const alertsHtml = alerts.map((a, i) => `
<div class="alert alert-${a.risk.toLowerCase()}">
  <h3>${i + 1}. ${htmlEsc(a.name)}</h3>
  <table>
    <tr><th>Risk</th><td>${a.risk}</td></tr>
    <tr><th>Confidence</th><td>${a.confidence}</td></tr>
    <tr><th>URL</th><td><code>${htmlEsc(a.url)}</code></td></tr>
    ${a.param ? `<tr><th>Parameter</th><td><code>${htmlEsc(a.param)}</code></td></tr>` : ''}
    ${a.evidence ? `<tr><th>Evidence</th><td><code>${htmlEsc(a.evidence)}</code></td></tr>` : ''}
  </table>
  <p><strong>Description:</strong> ${htmlEsc(a.description)}</p>
  <p><strong>Solution:</strong> ${htmlEsc(a.solution)}</p>
</div>`).join('\n');

  return wrapZap({
    title: `${companyName} — OWASP ZAP Scan`,
    target,
    scanDate,
    summary,
    alertsHtml
  });
}

function wrapZap({ title, target, scanDate, summary, alertsHtml }) {
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>${htmlEsc(title)}</title>
<style>
  body { font-family: -apple-system, sans-serif; max-width: 900px; margin: 0 auto; padding: 30px; color: #1a202c; }
  h1 { border-bottom: 3px solid #2c5282; padding-bottom: 10px; }
  .summary { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 20px 0; }
  .summary div { padding: 12px; border-radius: 6px; text-align: center; font-weight: 600; }
  .summary .high   { background: #fee2e2; color: #991b1b; }
  .summary .medium { background: #fef3c7; color: #92400e; }
  .summary .low    { background: #dbeafe; color: #1e40af; }
  .summary .info   { background: #f3f4f6; color: #374151; }
  .alert { margin: 20px 0; padding: 16px; border-left: 4px solid; background: #f9fafb; border-radius: 4px; }
  .alert-high   { border-color: #ef4444; }
  .alert-medium { border-color: #f59e0b; }
  .alert-low    { border-color: #3b82f6; }
  .alert-informational { border-color: #9ca3af; }
  table { width: 100%; border-collapse: collapse; margin: 8px 0; font-size: 0.9em; }
  th, td { padding: 6px 10px; text-align: left; border-bottom: 1px solid #e5e7eb; }
  th { width: 130px; color: #4a5568; }
  code { background: #edf2f7; padding: 2px 6px; border-radius: 3px; font-size: 0.9em; }
</style></head><body>
<h1>${htmlEsc(title)}</h1>
<p><strong>Target:</strong> <code>${htmlEsc(target)}</code></p>
<p><strong>Scan Date:</strong> ${htmlEsc(scanDate)}</p>
<div class="summary">
  <div class="high">High: ${summary.high}</div>
  <div class="medium">Medium: ${summary.medium}</div>
  <div class="low">Low: ${summary.low}</div>
  <div class="info">Info: ${summary.info}</div>
</div>
<h2>Findings</h2>
${alertsHtml}
<hr>
<p style="color:#9ca3af; font-size:0.85em;">Generated for cybersecurity training exercise — simulated scan output derived from profile asset inventory.</p>
</body></html>`;
}

// ─── Public API ────────────────────────────────────────────────────────────

/**
 * Build the document objects the route handler stores in `generated_documents`.
 *
 * @param {object} args
 * @param {object} args.profileData     normalized profile data (has .assets[], .industry, etc.)
 * @param {string} args.companyName
 * @param {string} [args.domain]
 * @param {Array<string>} [args.types]  any of 'nmap','nessus','zap'; default = all three
 * @returns {Array<{type, filename, content, mime}>}
 */
function generateScanDocuments({ profileData, companyName, domain, types }) {
  const safeName = (companyName || 'profile').replace(/[^a-z0-9]/gi, '_').toLowerCase();
  const wanted = Array.isArray(types) && types.length > 0
    ? types.map(t => String(t).toLowerCase())
    : ['nmap', 'nessus', 'zap'];

  const docs = [];
  for (const t of wanted) {
    if (t === 'nmap') {
      docs.push({
        type: 'nmap',
        filename: `${safeName}_nmap_scan.md`,
        content: generateNmap({ profileData, companyName, domain }),
        mime: 'text/markdown'
      });
    } else if (t === 'nessus') {
      docs.push({
        type: 'nessus',
        filename: `${safeName}_nessus_scan.nessus`,
        content: generateNessus({ profileData, companyName }),
        mime: 'application/xml'
      });
    } else if (t === 'zap') {
      docs.push({
        type: 'zap',
        filename: `${safeName}_zap_report.html`,
        content: generateZap({ profileData, companyName, domain }),
        mime: 'text/html'
      });
    }
  }
  return docs;
}

module.exports = {
  generateScanDocuments,
  // exported for tests + reuse
  generateNmap,
  generateNessus,
  generateZap,
  scannableAssets,
  buildHostPorts
};
