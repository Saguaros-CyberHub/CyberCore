/**
 * vuln-knowledge.js — Small built-in mapping of services to plausible
 * vulnerabilities + service banners. Used by NMAP / NESSUS / ZAP generators
 * to keep their output consistent with each other AND with what a real scan
 * against the deployed lane VMs would actually find.
 *
 * Keys = lowercased service token from profile.assets[].services entries
 * (e.g. "smb" from "445/SMB"). Match is case-insensitive substring; multiple
 * keys can map to the same vuln group.
 */

// Default port → service name table (used when assets[].services entry has no service label)
const PORT_DEFAULTS = {
  22:    { service: 'ssh',       product: 'OpenSSH',                version: '8.9p1' },
  25:    { service: 'smtp',      product: 'Postfix smtpd',          version: '3.6.4' },
  53:    { service: 'domain',    product: 'BIND',                   version: '9.18.12' },
  80:    { service: 'http',      product: 'Apache httpd',           version: '2.4.52' },
  88:    { service: 'kerberos-sec', product: 'Microsoft Windows Kerberos', version: '' },
  110:   { service: 'pop3',      product: 'Dovecot pop3d',          version: '' },
  135:   { service: 'msrpc',     product: 'Microsoft Windows RPC',  version: '' },
  139:   { service: 'netbios-ssn', product: 'Microsoft Windows netbios-ssn', version: '' },
  143:   { service: 'imap',      product: 'Dovecot imapd',          version: '' },
  389:   { service: 'ldap',      product: 'Microsoft Windows Active Directory LDAP', version: '' },
  443:   { service: 'ssl/http',  product: 'Apache httpd',           version: '2.4.52' },
  445:   { service: 'microsoft-ds', product: 'Microsoft Windows Server 2019 microsoft-ds', version: '' },
  587:   { service: 'smtp',      product: 'Postfix smtpd',          version: '3.6.4' },
  993:   { service: 'imaps',     product: 'Dovecot imapd',          version: '' },
  995:   { service: 'pop3s',     product: 'Dovecot pop3d',          version: '' },
  1433:  { service: 'ms-sql-s',  product: 'Microsoft SQL Server',   version: '2019' },
  1521:  { service: 'oracle-tns',product: 'Oracle TNS Listener',    version: '19.3.0.0.0' },
  2049:  { service: 'nfs',       product: 'Linux nfsd',             version: '4.2' },
  3306:  { service: 'mysql',     product: 'MySQL',                  version: '8.0.31' },
  3389:  { service: 'ms-wbt-server', product: 'Microsoft Terminal Services', version: '' },
  5432:  { service: 'postgresql',product: 'PostgreSQL',             version: '14.6' },
  5985:  { service: 'wsman',     product: 'Microsoft HTTPAPI httpd',version: '2.0' },
  5986:  { service: 'wsmans',    product: 'Microsoft HTTPAPI httpd',version: '2.0' },
  6379:  { service: 'redis',     product: 'Redis',                  version: '7.0.5' },
  8080:  { service: 'http-proxy',product: 'Apache Tomcat',          version: '9.0.71' },
  8443:  { service: 'ssl/http',  product: 'Apache Tomcat',          version: '9.0.71' },
  9100:  { service: 'jetdirect', product: 'HP JetDirect',           version: '' },
  27017: { service: 'mongodb',   product: 'MongoDB',                version: '5.0.14' }
};

// Service token → known vulnerability findings.
// Each finding: { plugin_id, severity, name, cvss, cves[], description }
// Severity: Critical(4) / High(3) / Medium(2) / Low(1) / Info(0)
const VULN_FINDINGS = {
  smb: [
    {
      plugin_id: '97833', severity: 4, cvss: 9.3,
      name: 'MS17-010: Microsoft Windows SMB Server Remote Code Execution (EternalBlue)',
      cves: ['CVE-2017-0143','CVE-2017-0144','CVE-2017-0145','CVE-2017-0146','CVE-2017-0148'],
      description: 'The remote Windows host is affected by the following vulnerabilities: Multiple remote code execution vulnerabilities in Microsoft Server Message Block 1.0 (SMBv1) due to improper handling of certain requests. Exploited by the WannaCry ransomware family.'
    },
    {
      plugin_id: '57608', severity: 1, cvss: 4.3,
      name: 'SMB Signing Disabled',
      cves: [],
      description: 'Signing is not required on the remote SMB server. An unauthenticated, remote attacker can exploit this to conduct man-in-the-middle attacks.'
    }
  ],
  rdp: [
    {
      plugin_id: '125313', severity: 4, cvss: 9.8,
      name: 'CVE-2019-0708: Microsoft Windows Remote Desktop Services Remote Code Execution (BlueKeep)',
      cves: ['CVE-2019-0708'],
      description: 'The remote host is affected by a remote code execution vulnerability in Remote Desktop Services (RDS). An unauthenticated, remote attacker can exploit this by sending specially crafted requests.'
    },
    {
      plugin_id: '57690', severity: 2, cvss: 5.1,
      name: 'Terminal Services Encryption Level is Medium or Low',
      cves: [],
      description: 'The encryption setting used by the remote RDP service is weak or medium. By default, this setting is "Client Compatible", which permits use of weak encryption like 56-bit DES.'
    }
  ],
  http: [
    {
      plugin_id: '11213', severity: 2, cvss: 5.0,
      name: 'HTTP TRACE / TRACK Methods Allowed',
      cves: ['CVE-2004-2320','CVE-2010-0386'],
      description: 'The remote web server supports the TRACE and/or TRACK methods. TRACE and TRACK are HTTP methods that are used to debug web server connections.'
    },
    {
      plugin_id: '10662', severity: 0, cvss: 0,
      name: 'Web Server Directory Enumeration',
      cves: [],
      description: 'This plugin attempts to determine the presence of various common directories on the remote web server.'
    }
  ],
  https: [
    {
      plugin_id: '20007', severity: 2, cvss: 5.3,
      name: 'SSL Version 2 and 3 Protocol Detection',
      cves: ['CVE-2014-3566'],
      description: 'The remote service accepts connections encrypted using SSL 2.0 and/or SSL 3.0. These versions of SSL are affected by several cryptographic flaws including POODLE.'
    },
    {
      plugin_id: '104743', severity: 2, cvss: 5.3,
      name: 'TLS Version 1.0 Protocol Detection',
      cves: [],
      description: 'The remote service accepts connections encrypted using TLS 1.0. TLS 1.0 has a number of cryptographic design flaws.'
    }
  ],
  ssh: [
    {
      plugin_id: '70658', severity: 2, cvss: 4.3,
      name: 'SSH Server CBC Mode Ciphers Enabled',
      cves: ['CVE-2008-5161'],
      description: 'The SSH server is configured to support Cipher Block Chaining (CBC) encryption. This may allow an attacker to recover the plaintext message from the ciphertext.'
    }
  ],
  ftp: [
    {
      plugin_id: '10079', severity: 3, cvss: 7.5,
      name: 'Anonymous FTP Enabled',
      cves: [],
      description: 'The remote FTP server allows anonymous logins. Any remote user may connect and authenticate without supplying a password.'
    }
  ],
  mysql: [
    {
      plugin_id: '157167', severity: 2, cvss: 5.3,
      name: 'MySQL Server Outdated Version',
      cves: ['CVE-2022-21417'],
      description: 'The version of MySQL installed on the remote host is outdated and contains multiple vulnerabilities. Upgrade to the latest version.'
    }
  ],
  mssql: [
    {
      plugin_id: '10144', severity: 3, cvss: 7.5,
      name: 'Microsoft SQL Server sa Account Default Blank Password',
      cves: [],
      description: 'The Microsoft SQL Server sa account has a blank password.'
    }
  ],
  ldap: [
    {
      plugin_id: '34324', severity: 1, cvss: 4.0,
      name: 'LDAP Anonymous Bind',
      cves: [],
      description: 'The remote LDAP server supports anonymous binds. An unauthenticated, remote attacker can use this to enumerate the directory.'
    }
  ],
  kerberos: [
    {
      plugin_id: '10773', severity: 0, cvss: 0,
      name: 'Kerberos Information Disclosure',
      cves: [],
      description: 'The remote Kerberos service responded and exposed realm/domain information.'
    }
  ]
};

// Service name normalization — maps user-supplied service tokens to canonical
// lookup keys. Keys are checked as lowercased substrings against each token.
function normalizeServiceToken(token) {
  const t = String(token || '').toLowerCase();
  if (t.includes('smb') || t.includes('netbios') || t.includes('microsoft-ds')) return 'smb';
  if (t.includes('rdp') || t.includes('ms-wbt') || t.includes('terminal')) return 'rdp';
  if (t.includes('https') || t.includes('ssl/http') || t.includes('ssl/https')) return 'https';
  if (t.includes('http')) return 'http';
  if (t === 'ssh' || t.includes('ssh')) return 'ssh';
  if (t === 'ftp' || t.includes('ftp')) return 'ftp';
  if (t.includes('mysql')) return 'mysql';
  if (t.includes('mssql') || t.includes('sqlserver') || t.includes('ms-sql')) return 'mssql';
  if (t.includes('ldap')) return 'ldap';
  if (t.includes('kerberos')) return 'kerberos';
  if (t.includes('dns') || t === 'domain') return 'dns';
  if (t.includes('postgres')) return 'postgres';
  if (t.includes('mongo')) return 'mongo';
  if (t.includes('redis')) return 'redis';
  return t;
}

/**
 * Parse one profile.assets[].services entry. Format: "port/Service" or just "Service".
 * @returns {{port:number|null, service:string, normalized:string}}
 */
function parseServiceEntry(entry) {
  const str = String(entry || '').trim();
  const slash = str.indexOf('/');
  let port = null;
  let service = str;
  if (slash !== -1) {
    const p = parseInt(str.slice(0, slash), 10);
    if (Number.isFinite(p)) port = p;
    service = str.slice(slash + 1).trim();
  } else {
    // try parse as bare number
    const p = parseInt(str, 10);
    if (Number.isFinite(p) && String(p) === str) port = p;
  }
  const normalized = normalizeServiceToken(service || (port ? String(port) : ''));
  // If service is empty but port has a default, use that
  if (!service && port && PORT_DEFAULTS[port]) service = PORT_DEFAULTS[port].service;
  return { port, service, normalized };
}

/**
 * Get the canonical service banner for a (port, service) pair.
 */
function getBanner(port, normalized) {
  if (port && PORT_DEFAULTS[port]) return PORT_DEFAULTS[port];
  // Synthesize from normalized service if no port match
  return { service: normalized || 'unknown', product: '', version: '' };
}

/**
 * Look up all known Nessus-style findings for a normalized service token.
 */
function getFindings(normalized) {
  return VULN_FINDINGS[normalized] || [];
}

module.exports = {
  PORT_DEFAULTS,
  VULN_FINDINGS,
  parseServiceEntry,
  normalizeServiceToken,
  getBanner,
  getFindings
};
