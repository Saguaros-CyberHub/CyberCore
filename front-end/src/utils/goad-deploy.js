/**
 * GOAD lane preparation, addressing and controller orchestration.
 * Preparation validates a metadata-only identity plan before allocation.
 * Each lane's controller owns its GOAD source, compiles renamed labs locally,
 * provisions Windows, verifies actual identities, and is stopped on every exit.
 * Separately generated CiAB labs retain their existing tree-delivery path.
 */

// QEMU guest-agent helpers for the controller VM. All exec into the
// controller goes through the Proxmox HTTPS API — no SSH from this app.
// The controller VM in turn SSHes into the lane gateway (192.18.0.1) to
// write DHCP reservations, using a keypair baked into both templates.
const { agentExec, agentShellExec, pollExecStatus, waitForGuestAgent } = require('./script-executor');
// pct exec/push into the lane gateway LXC (used by writeDhcpReservations to drop
// the per-lane dnsmasq reservation file). Same module attached-modules.js uses.
const nodeSsh = require('./node-ssh');
// Core planning reads identity metadata only. GOAD source stays on the controller.
const {
  preflightGoadRebrand, canonicalGoadLabName, describeRebrand, listExtensionBases, RebrandError, REBRAND_CODES,
} = require('./goad-lab-rebrand');

/**
 * Run an argv-style command inside a QEMU VM via the guest agent.
 *
 * Proxmox's agent/exec wants `command` either as a single string (executable
 * only, no args) OR multiple `command=...` form params (executable + args).
 * Our proxmoxAPI helper encodes objects as plain k=v, which collapses the
 * argv into one giant "executable path with embedded spaces" → ENOENT.
 *
 * This wrapper builds the form body by hand with `command` repeated per
 * argv element, then POSTs the raw string body. Returns { pid }.
 */
async function agentExecArgv(node, vmId, argv, proxmoxAPI) {
  const body = argv.map(a => `command=${encodeURIComponent(a)}`).join('&');
  const result = await proxmoxAPI(
    'POST',
    `/api2/json/nodes/${node}/qemu/${vmId}/agent/exec`,
    body
  );
  if (!result?.pid) {
    throw new Error(`agent/exec did not return a PID: ${JSON.stringify(result)}`);
  }
  return { pid: result.pid };
}

/**
 * Ensure the WinRM bootstrap account exists on a Windows lane VM.
 *
 * Idempotent by construction: it resets the password and re-enables on every
 * run rather than branching on "is it already right", because a half-configured
 * account (present but disabled, or present with a stale password) is exactly
 * the state a retried lane lands in, and it looks identical to a good one.
 *
 * The password MUST match inventory_overrides in the controller's run.sh --
 * these are the credentials every play after preflight-vagrant connects with.
 * Windows local policy needs 8+ chars, 3 of 4 character classes, and rejects a
 * password containing the username, which is why it is not 'vagrant'.
 */
const GOAD_BOOTSTRAP_ACCOUNT_USER = 'vagrant';
const GOAD_BOOTSTRAP_ACCOUNT_PASSWORD = 'BootstrapPwd!1';
const GOAD_BOOTSTRAP_ACCOUNT_PS = [
  "$ErrorActionPreference='Stop'",
  `$u='${GOAD_BOOTSTRAP_ACCOUNT_USER}'`,
  `$p=ConvertTo-SecureString '${GOAD_BOOTSTRAP_ACCOUNT_PASSWORD}' -AsPlainText -Force`,
  // A promoted DC has no local SAM: Get-LocalUser THROWS rather than returning
  // null. Say so and exit 0 -- the domain account is what run.sh will use.
  "try { $null = Get-LocalUser -ErrorAction Stop } catch { 'no local SAM (domain controller) - skipped'; exit 0 }",
  "$e = Get-LocalUser -Name $u -ErrorAction SilentlyContinue",
  // if/else MUST stay on ONE line and these lines MUST be joined with newlines,
  // never with '; '. A semicolon between the closing brace and `else` TERMINATES
  // the if-statement, so PowerShell then reads `else` as a command name:
  //   else : The term 'else' is not recognized as the name of a cmdlet...
  // Cost a real deploy. Both hosts reported it, both seeds no-opped.
  "if ($e) { Set-LocalUser -Name $u -Password $p -PasswordNeverExpires $true; Enable-LocalUser -Name $u } else { New-LocalUser -Name $u -Password $p -PasswordNeverExpires -AccountNeverExpires | Out-Null }",
  "if (-not (Get-LocalGroupMember -Group 'Administrators' -Member $u -ErrorAction SilentlyContinue)) { Add-LocalGroupMember -Group 'Administrators' -Member $u }",
  "if ($e) { 'reset existing ' + $u } else { 'created ' + $u }",
].join(String.fromCharCode(10));

// Template VMID for the GOAD ansible controller (Debian 13 VM with
// qemu-guest-agent, baked from infrastructure/proxmox-templates/vm-templates/bake-goad-controller-vm.sh —
// git-clones upstream GOAD on first boot via cloud-init).
const CONTROLLER_TEMPLATE_VMID = 1700;

// The GENERIC Ubuntu 22.04 image (bake-ubuntu-lab-template.sh). It carries no
// SIEM: it is the box GOAD's extension Ansible INSTALLS onto, in-lane, on a live
// lane. Named rather than spelled 1011 in four places because it is the pivot of
// the pre-baked rule below — a machine still pointing here on a pre-baked lane is
// the one combination that deploys green and does nothing.
//
// The sealed counterparts (seal-goad-elk-template.sh -> 1012,
// seal-goad-wazuh-template.sh -> 1013) DO carry the stack, which is exactly why
// pointing at one of them makes a pre-baked lane legitimate.
const PLAIN_BASE_TEMPLATE_VMID = 1011;

// Lane subnet — provided per-deploy by the caller (admin.js v1: '192.18.0'
// shared, v2: '10.<vxh>.<vxl>' unique per lane, v3: the INTERNAL segment's
// '10.<vxh|0x80>.<vxl>' — GOAD always lives on the internal subnet in v3).
// Last octets per role stay anchored to upstream GOAD's Proxmox provider
// inventories so upstream playbooks work unmodified.
//
// All IP construction goes through buildIp(base3, octet) so adding a new
// callsite forces the caller to pass the lane's base — no hidden global.
function buildIp(laneSubnetBase, octet) {
  if (!laneSubnetBase) {
    throw new Error('goad-deploy.buildIp: laneSubnetBase is required (e.g., "192.18.0" for v1, "10.39.17" for v2)');
  }
  return `${laneSubnetBase}.${octet}`;
}

// Per-lab topology. Each entry maps the lab name (matches upstream's
// ad/<name>/ directory + playbooks.yml key) to its VM list. `ipOctet`
// values mirror upstream's providers/proxmox/inventory exactly.
//
// Adding a new lab: copy the relevant ad/<name>/providers/proxmox/inventory
// values and create an entry here. The bake script (run.sh) reads the
// playbook chain from upstream's playbooks.yml at deploy time, so we don't
// need to track that here.
//
// DO NOT INDEX THIS TABLE DIRECTLY. It has exactly two legal readers:
//   resolveGoadLab(spec)  the deploy-time resolver — it also honours a
//                         spec-supplied goad.lab, which a raw GOAD_LABS[x]
//                         lookup silently ignores.
//   getLab(labName)       the catalog reader, for "what does CyberCore ship?".
// Every inlined copy of the lookup is one more chance for a site to resolve a
// different lab from its neighbours, and nothing throws when they disagree.
//
// `domains` is the FULL domain list from ad/<name>/data/config.json, root
// first. It is here because NOTHING ELSE IN THIS TABLE CAN ANSWER "is this lab
// single-domain", and the forest rename has to ask: a child domain is derived
// by dropping a label (ad-child_domain.yml looks its parent up with no default)
// and a trust partner is wired BY NAME, so renaming the root leaves both
// pointing at a forest that no longer exists. The obvious proxy is wrong —
// NHA declares TWO domains and carries `childSubdomain: null`, because its
// second is a trust partner rather than a child, so a `childSubdomain === null`
// test would have said "single domain, go ahead" for exactly the lab that
// breaks worst. test/goad-forest-rename.test.js reads each on-disk config and
// pins these lists against it.
const GOAD_LABS = {
  'GOAD-Light': {
    displayName:  'GOAD-Light (3 Win VMs, 2 domains)',
    description:  'Lighter GOAD without Essos forest. Recommended starter.',
    forestRoot:   'cybersaguaros.local',
    domains:      ['cybersaguaros.local', 'tumamoc.cybersaguaros.local'],
    // ad/GOAD-Light/data/config.json declares tumamoc.cybersaguaros.local as the
    // second domain — a CHILD (strict suffix of the root), not a trusted peer.
    childSubdomain: 'tumamoc',
    vms: [
      { name: 'DC01',  role: 'dc',     os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 10, nic_model: 'e1000' },
      { name: 'DC02',  role: 'dc',     os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 11, nic_model: 'e1000' },
      { name: 'SRV02', role: 'member', os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 22, nic_model: 'e1000' }
    ]
  },
  'GOAD': {
    displayName:  'GOAD — full (5 Win VMs, 3 domains, 2 forests)',
    description:  'Full GOAD lab with cross-forest scenarios (Essos). Heaviest variant.',
    forestRoot:   'sevenkingdoms.local',
    // Three domains in TWO forests: essos.local is reached by a trust, so it is
    // in `domains` (it is a domain the lab builds) but deliberately absent from
    // childSubdomain below.
    domains:      ['sevenkingdoms.local', 'north.sevenkingdoms.local', 'essos.local'],
    // north.sevenkingdoms.local in ad/GOAD/data/config.json. essos.local is the
    // THIRD domain and is deliberately NOT recorded here: it is a separate forest
    // reached by a trust, not a child, and ad-child_domain.yml only ever builds
    // the `<label>.<parent>` shape.
    childSubdomain: 'north',
    vms: [
      { name: 'DC01',  role: 'dc',     os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 10, nic_model: 'e1000' },
      { name: 'DC02',  role: 'dc',     os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 11, nic_model: 'e1000' },
      { name: 'DC03',  role: 'dc',     os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 12, nic_model: 'e1000' },
      { name: 'SRV02', role: 'member', os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 22, nic_model: 'e1000' },
      { name: 'SRV03', role: 'member', os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 23, nic_model: 'e1000' }
    ]
  },
  'GOAD-Mini': {
    displayName:  'GOAD-Mini (1 Win VM, single domain)',
    description:  'Minimal AD lab — just DC01. Fastest to deploy (~10 min).',
    forestRoot:   'sevenkingdoms.local',
    // One domain, which is what makes this the lab the forest rename supports.
    domains:      ['sevenkingdoms.local'],
    childSubdomain: null,      // one domain, one DC — there is no child to name
    vms: [
      { name: 'DC01', role: 'dc', os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 10, nic_model: 'e1000' }
    ]
  },
  'NHA': {
    displayName:  'NHA — No Hope Alpha (5 Win VMs, 2 domains)',
    description:  'Multi-server cross-domain lab without child domain (uses trusts).',
    // WAS 'north.sevenkingdoms.local' — a Seven Kingdoms (GOAD) domain that has
    // nothing to do with this lab, copy-pasted when the entry was added. NHA's
    // own ad/NHA/data/config.json declares exactly two domains, ninja.hack and
    // academy.ninja.lan (the second a trust of the first), so ninja.hack is the
    // forest root. Wrong here it is not cosmetic: forestRoot is what
    // /api/lab-templates hands the topology seed, so every NHA artifact named a
    // domain the lane does not have.
    forestRoot:   'ninja.hack',
    // TWO domains and a null childSubdomain — the pair that makes `domains`
    // necessary rather than derivable. academy.ninja.lan is a trust partner, so
    // it is a domain this lab builds and NOT a child of ninja.hack.
    domains:      ['ninja.hack', 'academy.ninja.lan'],
    // NULL, and this is the interesting one. NHA's second domain is
    // academy.ninja.lan, which is NOT a suffix of ninja.hack — so it is a TRUST
    // partner, not a child, and describing it as a child_subdomain would make
    // ad-child_domain.yml derive a parent domain ('ninja.lan') that does not
    // exist in lab.domains and kill the play. See ad-domain-rules.assertChild.
    childSubdomain: null,
    vms: [
      { name: 'DC01',  role: 'dc',     os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 10, nic_model: 'e1000' },
      { name: 'DC02',  role: 'dc',     os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 11, nic_model: 'e1000' },
      { name: 'SRV01', role: 'member', os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 21, nic_model: 'e1000' },
      { name: 'SRV02', role: 'member', os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 22, nic_model: 'e1000' },
      { name: 'SRV03', role: 'member', os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 23, nic_model: 'e1000' }
    ]
  },
  'SCCM': {
    displayName:  'SCCM Lab (3 Win servers + 1 workstation)',
    description:  'SCCM/MECM lab with PXE, client deployment. Long runtime (~60 min).',
    forestRoot:   'sccm.lab',
    // Single-domain, but NOT rebrandable today: sccm.lab's netbios_name is
    // SCCMLAB (not the first label), it names hosts by value inside an sccm{}
    // sub-object, and its `members` arrays carry SCCMLAB\CLIENT$. Eligibility is
    // "a vendored base tree exists", so this lab stays out until one is.
    domains:      ['sccm.lab'],
    childSubdomain: null,      // every SCCM host is in sccm.lab
    vms: [
      { name: 'DC01',  role: 'dc',          os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 40, nic_model: 'e1000' },
      { name: 'SRV01', role: 'member',      os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 41, nic_model: 'e1000' },
      { name: 'SRV02', role: 'member',      os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 42, nic_model: 'e1000' },
      // 1006 is the Windows 11 template on this cluster. Was 1002 — the same
      // stale number GOAD_EXTENSIONS.ws01 carried, from the bake script's drifted
      // FINAL_VMID default. Both Windows 11 rows in this file must name the same
      // image, or SCCM's own WS01 and the ws01 extension clone different OSes.
      { name: 'WS01',  role: 'workstation', os: 'Windows 11',          template_vmid: 1006, ipOctet: 43, nic_model: 'e1000' }
    ]
  },
  'DRACARYS': {
    displayName:  'DRACARYS (2 Win + 1 Linux VM)',
    description:  'Mixed Win+Linux lab. LX01 uses Ubuntu template (VMID 1003).',
    forestRoot:   'dracarys.lab',
    // Single-domain, and its config.json is NOT strict JSON — an illegal
    // trailing comma at line 128, which works only because ansible loads it
    // through a YAML loader. The vendor test parses it leniently for that
    // reason and nothing else does.
    domains:      ['dracarys.lab'],
    childSubdomain: null,      // single domain
    vms: [
      { name: 'DC01',  role: 'dc',     os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 10, nic_model: 'e1000' },
      { name: 'SRV01', role: 'member', os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 11, nic_model: 'e1000' },
      { name: 'LX01',  role: 'linux',  os: 'Ubuntu',              template_vmid: 1003, ipOctet: 12, nic_model: 'virtio' }
    ]
  }
};

// Reserved infrastructure IPs (apply to every lab; never collide with lab VMs).
const INFRA_IP_OCTETS = {
  gateway:    1,
  controller: 5,
  // Ext-segment attack box. .50 matches the gateway RDP DNAT (KALI_OCTET=50 in
  // infrastructure/proxmox-templates/sdn-templates/ — v2_gateway/ and
  // bake-lane-gateway-v3.sh). Note the gateway's pool is .10–.200, so .50 is
  // INSIDE it and is not excluded — it stays free because dnsmasq never hands a
  // reserved address to a client that doesn't match the reservation, so a lease
  // only lands here for the host the reservation names. Was 20 — an orphan that
  // never worked: the reservation it produced sat on the INTERNAL segment (Kali
  // lives on EXTERNAL) and the clone never carried the matching MAC, so nothing
  // was reachable at .20. .50 is what every enforcing path uses.
  Kali:       50
};

// ============================================================================
// GOAD EXTENSIONS — optional machines an authored environment can add to a lab
// ============================================================================
// Upstream GOAD ships these under GOAD-main/extensions/<key>/ as extra Ansible
// inventories layered on top of a lab, installed with `install_extension <key>`
// once the lab is up. CyberCore does the same thing, in the lane, at deploy
// time: runGoadPlaybook hands the selected keys to /opt/goad-light/run.sh as its
// optional 5th argument, and the controller layers each extension's rendered
// inventory on top of the lab's and runs extensions/<key>/ansible/install.yml.
// That is upstream's whole run_extension() — inventory layering plus one
// playbook run (GOAD-main/goad/provisioner/ansible/ansible.py:76) — and it maps
// one-for-one onto run.sh's existing `INV_FLAGS="-i A -i B"` + playbook loop.
//
// SO A TICKED EXTENSION REALLY DOES INSTALL. This comment used to say the
// opposite ("a DECLARATION OF WHAT THE IMAGES ALREADY CONTAIN … it does not
// install anything"), which described a prebaked-SIEM design that has been
// replaced. elk and wazuh now clone a PLAIN Ubuntu base and GOAD's own Ansible
// builds the stack on it in the lane.
//
// It can, because a deployed lane HAS internet — see the correction on the
// mssql fixes in runGoadPlaybook. bake-lane-gateway-v3.sh MASQUERADEs both lane
// subnets out wan0 ("internet uplink (NAT)") and ACCEPTs `-i ext0 -o wan0` and
// `-i int0 -o wan0` in FORWARD; the only DROPs are scoped `-d 100.100.0.0/16`,
// which contains traffic to the LAB BACKBONE, not to the internet.
//
// THE ONE EXCEPTION IS A PRE-BAKED LANE. spec.goad.prebaked clones golden images
// and runs no Ansible at all — no controller, no run.sh — so an extension ticked
// there would place its machine and install nothing on it. That combination is
// refused outright: see assertGoadExtensionsRunnable.
//
// Mirrors GOAD_LABS deliberately, field for field, so the same two readers
// work: getExtension(key) is the catalog reader ("what does CyberCore ship?")
// and resolveGoadLab(spec) is the deploy-time reader, which folds the `inLab`
// extensions into the lab roster.
//
// ── The two placements, and why the difference matters ──────────────────────
// `inLab: true`  the machine joins the AD forest, so it MUST appear in the lab
//                roster: prepareGoadMacs matches BY NAME, and only a roster
//                member gets a deterministic MAC + DHCP reservation, gets
//                restarted onto that reservation, gets polled for WinRM, and
//                gets the post-clone secure-channel heal.
// `inLab: false` an ordinary pinnable spec VM. Being ABSENT from goadMacs is
//                the whole point — resolveSpecAddressing skips a machine only
//                when goadMacs[name] exists, and that function is the only
//                source of the `host-record` that makes `elk.cybercore.lan`
//                resolve (challenge-lane-deployer.js:307).
//
// ── `instruments` reads two ways, on purpose ────────────────────────────────
// For a SIEM it is the inventory groups that stack COLLECTS from; for a member
// machine it is the group it JOINS. That is what makes "is this host dark?"
// computable in one expression: a machine whose group appears in no selected
// SIEM's instruments ships no telemetry at all. topology-validate's
// `siem-blind-host` is the rendering of exactly that — lx01 is [linux_domain],
// elk covers [domain] only, wazuh covers both.
//
// ── `shipsLabConfig` — declared, never probed ───────────────────────────────
// True when extensions/<key>/data/config.json exists upstream, i.e. when the
// extension carries its own copy of the domain and hostnames. Those copies do
// not follow a forest rename on their own: install.yml layers the extension's
// config over the RENAMED main lab's data and then joins the two by domain
// name, so a stale copy dies on an undefined lookup with the machine already
// cloned and booted. So a `true` here means "the forest rename must ship a
// rewritten config for this key or refuse the lane".
//
// IT IS A FLAG AND NOT AN fs.existsSync BECAUSE THE ANSWER LIVES IN A TREE THIS
// PROCESS MAY NOT HAVE. GOAD-main/ is gitignored with zero tracked files, so a
// probe against it returns "no config, nothing to rewrite" on every machine
// without the checkout — silently permissive exactly where being wrong is
// unrecoverable. That is the trap ciab/utils/goad-role-manifest.js:1-30
// documents. What IS checked at require time, below, is the other direction:
// every `true` must have tracked identity metadata identifying the controller
// recipe that rewrites it. The actual lab content stays in the GOAD fork.
const GOAD_EXTENSIONS = {
  elk: {
    key:            'elk',
    displayName:    'ELK — Elasticsearch + Kibana (SIEM)',
    description:    'Headless Ubuntu SIEM. Sysmon + winlogbeat ship to it from every Windows domain machine.',
    machine:        'elk',
    // .24, NOT the .50 that upstream's extensions/elk/inventory pins. On v3 .50
    // was free because Kali lives on the EXTERNAL segment while a SIEM sits
    // internally; on v1/v2 there is ONE flat lan0 and .50 is
    // INFRA_IP_OCTETS.Kali. Two dhcp-host lines claiming one address make
    // dnsmasq refuse to start, which takes DHCP down for the WHOLE lane.
    // .24 is free in every lab we ship.
    ipOctet:        24,
    role:           'siem',
    os:             'Ubuntu Server (headless)',
    // 1011 is the GENERIC Ubuntu 22.04 base — it carries no SIEM at all. The
    // trailing comment here used to read "the golden ELK image, registered per
    // site", which described a design that has been replaced: there is no
    // prebaked ELK image any more, and nothing is registered per site. One plain
    // image serves elk, wazuh and (probably, unverified) lx01, because
    // extensions/elk/ansible/install.yml builds Elasticsearch + Kibana on it in
    // the lane and pushes Sysmon + winlogbeat to every host in [domain].
    //
    // Upstream's extensions/elk/inventory pins this box at {{ip_range}}.50; the
    // .24 above is CyberCore's. run.sh rewrites the octet in the same sed pass
    // that already substitutes {{ip_range}}, so the vendored upstream file stays
    // pristine and the lane-addressing decision stays in the one place that owns
    // lane addressing.
    template_vmid:  1011,
    nic_model:      'virtio',
    instruments:    ['domain'],
    dns_aliases:    ['elk'],
    compatibility:  null,        // null = every lab
    inLab:          false,
    // extensions/elk/ ships NO data/config.json of its own — it reads the main
    // lab's — so a renamed forest reaches it for free. See the flag's contract
    // above GOAD_EXTENSIONS.
    shipsLabConfig: false,
    // No desktop and no xrdp in GOAD's elk role, so it cannot BE an RDP console.
    // The Designer surfaces this rather than letting an author discover it after
    // a deploy hands the student a black screen.
    headless:       true
  },
  wazuh: {
    key:            'wazuh',
    displayName:    'Wazuh — manager + SCA/FIM (SIEM)',
    description:    'All-in-one Wazuh manager. Agents on Windows AND Linux domain machines; CIS benchmarks out of the box.',
    machine:        'wazuh',
    // Upstream's own octet, and free on v2 — so no inventory edit is needed.
    // (elk's .24 is the exception, and run.sh's render pass is where it is made.)
    ipOctet:        51,
    role:           'siem',
    os:             'Ubuntu Server (headless)',
    // The SAME generic Ubuntu 22.04 base as elk — nothing about the image is
    // wazuh-specific. extensions/wazuh/ansible installs the manager in-lane and
    // pushes agents to [domain] AND [linux_domain]. Was null, which is what
    // produced the Designer's "has no template VMID, so there is nothing to
    // clone" and made the extension unusable.
    template_vmid:  1011,
    nic_model:      'virtio',
    instruments:    ['domain', 'linux_domain'],
    dns_aliases:    ['wazuh'],
    compatibility:  null,
    inLab:          false,
    shipsLabConfig: false,       // no data/config.json of its own, same as elk
    headless:       true
  },
  ws01: {
    key:            'ws01',
    displayName:    'ws01 — analyst workstation (Windows 11)',
    description:    'Domain-joined Windows 11 client. The cheapest way to make an intrusion cross hosts.',
    machine:        'ws01',
    ipOctet:        31,
    role:           'workstation',
    os:             'Windows 11',
    // 1006, NOT 1002. The Windows 11 template on this cluster is 1006. The bake
    // script (infrastructure/proxmox-templates/vm-templates/bake-win-client-template.sh)
    // still defaults FINAL_VMID to 1002 for Win11-25H2-Workstation — that default
    // has drifted away from the cluster, and the cluster is what a clone actually
    // reads. A wrong VMID here does not fail loudly: it clones whatever else lives
    // at that id, or nothing.
    template_vmid:  1006,
    nic_model:      'e1000',
    // It JOINS [domain] — upstream's extensions/ws01/inventory puts it there,
    // which is exactly the group [elk_log:children] instruments, so it arrives
    // instrumented with no extra work.
    instruments:    ['domain'],
    // Upstream declares compatibility: ["GOAD","GOAD-Light","GOAD-Mini"]. SCCM
    // already ships its own WS01, and NHA/DRACARYS have no ws01 inventory.
    compatibility:  ['GOAD', 'GOAD-Light', 'GOAD-Mini'],
    // IN the roster: domain-joined, so it needs the deterministic MAC, the
    // reserved IP, the DHCP-renew restart and the secure-channel heal.
    inLab:          true,
    // 996 bytes of its own data/config.json, and it is the reason
    // goad-ext-config-push.js exists: install.yml layers this file over the main
    // lab's data as `lab_extension` and then resolves
    // lab.domains[lab.hosts.ws01.domain].domain_password. Rename the forest and
    // leave this file alone and that lookup is undefined — the play dies with
    // the workstation already cloned and booted.
    shipsLabConfig: true,
    headless:       false
  },
  lx01: {
    key:            'lx01',
    displayName:    'lx01 — Linux domain member',
    description:    'Ubuntu joined to the domain. Covered by Wazuh only — the elk extension never touches [linux_domain].',
    machine:        'lx01',
    ipOctet:        32,
    role:           'linux',
    os:             'Ubuntu',
    // UNVERIFIED against the cluster. 1003 is inherited from GOAD_LABS.DRACARYS's
    // LX01 row and nobody has confirmed what sits there today. 1011 — the generic
    // Ubuntu 22.04 base elk and wazuh now clone — is exactly the box lx01 wants,
    // so these two may well be the same image. Not changed on a guess: cloning
    // the wrong template is silent, and one unverified number is better than two.
    template_vmid:  1003,
    nic_model:      'virtio',
    instruments:    ['linux_domain'],
    compatibility:  null,
    inLab:          false,
    // 573 bytes of its own, and one hop further than ws01: install.yml walks
    // lab.domains[domain].dc -> lab.hosts[dc].hostname to build dc_fqdn.
    shipsLabConfig: true,
    headless:       true
  }
};

// Load-time guard, not a test-only one: an extension octet that collides with
// lane infrastructure is a lane-wide DHCP outage (dnsmasq refuses to start on a
// duplicate dhcp-host), and the collision would otherwise surface for the first
// time on a real deploy. Cheap enough to pay on every require.
for (const [extKey, ext] of Object.entries(GOAD_EXTENSIONS)) {
  for (const [infra, octet] of Object.entries(INFRA_IP_OCTETS)) {
    if (ext.ipOctet === octet) {
      throw new Error(
        `GOAD_EXTENSIONS.${extKey} claims ipOctet ${octet}, which is the lane ${infra}. ` +
        'On v1/v2 there is one flat subnet, so the two would be the same address.'
      );
    }
  }
}

// Check the local identity metadata against the extension catalog without
// requiring any GOAD checkout or controller connection during application boot.
const extensionIdentityKeys = new Set(listExtensionBases());
for (const [extKey, ext] of Object.entries(GOAD_EXTENSIONS)) {
  if ((ext.shipsLabConfig === true) !== extensionIdentityKeys.has(extKey)) {
    throw new Error(`GOAD_EXTENSIONS.${extKey}.shipsLabConfig disagrees with its core identity metadata`);
  }
}

/** Catalog reader: a BUILT-IN extension by key, or null. */
function getExtension(key) {
  return GOAD_EXTENSIONS[String(key || '').toLowerCase()] || null;
}

/**
 * Which extensions may be offered for a lab, and why the rest may not.
 *
 * Three independent reasons to exclude one, each of which otherwise produces a
 * lane that looks authored and does not work:
 *   compatibility   upstream declares which labs the extension's inventory can
 *                   layer onto (ws01 has none for NHA/SCCM/DRACARYS).
 *   name collision  the lab already ships a host with that name — two machines
 *                   with one name means the second silently takes the first's
 *                   address (assertValidLabDef's own rule, one level up).
 *   octet collision same address, same subnet, dnsmasq down for the lane.
 *
 * @returns {Array<{key, ext, ok, reason}>} every extension, annotated — the UI
 *          shows the disabled ones WITH the reason rather than hiding them.
 */
function extensionsForLab(labName, labDef) {
  // getLab, not GOAD_LABS[labName]: the lab table has exactly two legal readers
  // (getLab for the catalog, resolveGoadLab for a deploy) and a source-text gate
  // in ciab-goad-lab-registration.test.js enforces it. It throws on an unknown
  // name; an unknown lab here just means "offer everything", which is what a
  // spec-supplied lab with no catalog entry should get.
  let lab = labDef || null;
  if (!lab) { try { lab = getLab(labName); } catch (e) { lab = null; } }
  const labVms = (lab && Array.isArray(lab.vms)) ? lab.vms : [];
  const takenNames = new Set(labVms.map(v => String(v.name).toLowerCase()));
  const takenOctets = new Map(labVms.map(v => [v.ipOctet, v.name]));

  // COMPATIBILITY IS ASKED OF THE BASE LAB, NOT THE DEPLOYED NAME. A forest
  // rename mints a name of its own — CC-GOADMINI-CY400TEST-1a2b3c4d — and
  // stamps `baseLab: 'GOAD-Mini'` on the lab definition it carries. ws01
  // declares compatibility ['GOAD','GOAD-Light','GOAD-Mini'], so matching the
  // minted name would drop ws01 from the roster IN SILENCE; resolveGoadLab
  // would then compose a roster without it, spec.vms would still carry the
  // machine, and assertGoadRoster would fail complaining about a stray host —
  // an error naming ws01 with nothing in it about the rename that caused it.
  // The name/octet collision checks below stay on the DEPLOYED roster, because
  // those are about the machines this lane actually builds.
  const compatLab = (lab && lab.baseLab) || labName;

  return Object.values(GOAD_EXTENSIONS).map(ext => {
    if (Array.isArray(ext.compatibility) && !ext.compatibility.includes(compatLab)) {
      return { key: ext.key, ext, ok: false,
        reason: `Upstream declares ${ext.key} compatible with ${ext.compatibility.join(', ')} only.` };
    }
    if (takenNames.has(ext.machine.toLowerCase())) {
      return { key: ext.key, ext, ok: false,
        reason: `${labName} already ships a host named ${ext.machine}.` };
    }
    if (takenOctets.has(ext.ipOctet)) {
      return { key: ext.key, ext, ok: false,
        reason: `.${ext.ipOctet} is already ${takenOctets.get(ext.ipOctet)} in ${labName}.` };
    }
    return { key: ext.key, ext, ok: true, reason: null };
  });
}

/**
 * The extensions a spec actually selected, split by placement.
 *
 * Unknown or incompatible keys are DROPPED rather than thrown on: `extensions`
 * is authored in a UI against a catalog that can move under an existing
 * challenge row, and a spec saved last term must still deploy. The Designer is
 * where a bad key is caught, while it is still an author's problem.
 *
 * @returns {{ selected: string[], inLab: object[], external: Set<string> }}
 *          inLab    — lab-roster entries, shaped like a GOAD_LABS vms[] row
 *          external — lowercased machine names that are ordinary spec VMs, so
 *                     assertGoadRoster knows they are not strays
 */
function resolveGoadExtensions(extensions, labName, labDef) {
  const wanted = Array.isArray(extensions) ? extensions : [];
  const allowed = new Map(
    extensionsForLab(labName, labDef).filter(e => e.ok).map(e => [e.key, e.ext])
  );
  const selected = [];
  const inLab = [];
  const external = new Set();
  for (const raw of wanted) {
    const ext = allowed.get(String(raw || '').trim().toLowerCase());
    if (!ext || selected.includes(ext.key)) continue;
    selected.push(ext.key);
    if (ext.inLab) {
      inLab.push({
        name:          ext.machine,
        role:          ext.role,
        os:            ext.os,
        template_vmid: ext.template_vmid,
        ipOctet:       ext.ipOctet,
        nic_model:     ext.nic_model,
        // So a reader of a composed roster can tell which hosts came from the
        // lab table and which the author added.
        extension:     ext.key
      });
    } else {
      external.add(ext.machine.toLowerCase());
    }
  }
  return { selected, inLab, external };
}

// Per-role resource defaults applied to Windows VM clones at deploy time.
// Template VMID 1004 ships with whatever it was baked at; admin.js calls
// `qemu/<vmid>/config` after clone with these values so the lane VMs end up
// correctly sized regardless of template state. Memory in MiB.
//
// Sizing rationale (revised 2026-05-19 — Tier 2 / generous):
//   GOAD's playbook is serialized at the stage level (DC1 → DC2 → member →
//   workstation), so wall-clock deploy time is dominated by the slowest VM
//   in each stage. The single largest task is the SQL Express install on
//   the member server (~8–12 min). Beyond a point, throwing more resources
//   at the DCs is wasted heat — dcpromo's database initialization is
//   fundamentally serial. The member absorbs more.
//
//   - DC: 12 GiB / 6 cores. dcpromo peaks ~5.5 GiB; 12 GiB gives generous
//     headroom + Windows file cache room. 6 cores buys ~10–15% over 4 on
//     the parallel role install steps; past 6 returns are flat.
//   - Member: 24 GiB / 10 cores. SQL Server Express install + IIS + WinRM
//     in parallel. SQL setup.exe spawns concurrent installer threads and
//     benefits materially from 10 cores; SQL buffer pool happily takes
//     12+ GiB during database create. balloon=14336 lets host reclaim
//     ~10 GiB once SQL stabilizes at idle.
//   - Workstation + DRACARYS Linux: 8 GiB / 6 cores. Light workload but
//     6 cores keeps domain join + GPO apply from queuing behind other
//     WinRM sessions on the same node.
//
// With Proxmox balloon driver (on for Windows VMs), `memory` is the per-VM
// peak budget; the host only physically commits up to `balloon` once the
// guest goes idle. So per-lane GOAD-Light (2 DC + 1 member):
//   Peak: 2*12 + 1*24 = 48 GiB
//   Idle: 2*6  + 1*14 = 26 GiB
//
// Override per-VM by setting `memory`, `balloon`, or `cores` directly on the
// vms[] entry — these defaults are applied only when the VM entry is silent.
const ROLE_RESOURCES = {
  dc:          { memory: 12288, balloon: 6144,  cores: 6  },
  member:      { memory: 24576, balloon: 14336, cores: 10 },
  workstation: { memory: 8192,  balloon: 4096,  cores: 6  },
  linux:       { memory: 8192,  balloon: 4096,  cores: 6  }
};

/**
 * Resolve memory/balloon/cores for a GOAD VM, with explicit per-VM overrides
 * winning over role defaults. Returns null fields when neither is set, so
 * the caller can leave Proxmox at template defaults.
 */
function getVmResources(vmDef) {
  const roleDefault = ROLE_RESOURCES[vmDef?.role] || {};
  return {
    memory:  vmDef?.memory  ?? roleDefault.memory  ?? null,
    balloon: vmDef?.balloon ?? roleDefault.balloon ?? null,
    cores:   vmDef?.cores   ?? roleDefault.cores   ?? null
  };
}

/**
 * Return a BUILT-IN lab definition by name, or throw if unknown.
 *
 * Catalog lookup only — it deliberately does NOT consider a spec-supplied
 * goad.lab, because its callers (the /api/lab-templates lab list, the topology
 * seed) are asking what CyberCore ships, not what one engagement is running.
 * Anything resolving a lab FOR A DEPLOY must call resolveGoadLab(spec).
 */
function getLab(labName) {
  labName = canonicalGoadLabName(labName);
  const lab = GOAD_LABS[labName];
  if (!lab) {
    throw new Error(`Unknown GOAD lab '${labName}'. Known: ${Object.keys(GOAD_LABS).join(', ')}`);
  }
  return lab;
}

/**
 * Default lab when spec.goad.version is missing (back-compat with earlier
 * specs that only had goad.enabled=true).
 */
const DEFAULT_LAB = 'GOAD-Light';

// Roles whose machines sit OUTSIDE the AD forest by design, so their absence
// from the lab table is intentional rather than a typo: 'dmz' is the v3
// dual-homed pivot (topology-seed's web01), 'attacker' is the per-lane Kali the
// GOAD preset appends to every lab. Same two names topology-validate.js exempts
// when it paints the canvas — one policy, spelled once per module because
// topology-validate already requires THIS file and the reverse edge would leave
// one of them holding a half-initialised module at load time.
const EXTERNAL_ROLES = new Set(['dmz', 'attacker']);

/**
 * Is this spec VM one the GOAD layer is supposed to own?
 *
 * Only machines that answer yes are reconciled against the lab definition, so
 * this predicate is exactly the line between "you named a host wrong" (fatal)
 * and "this box is deliberately not in the forest" (fine). Three exemptions:
 *
 *   EXTERNAL_ROLES  the Kali and the pivot above.
 *   explicit nics[] the author placed the machine on a segment by hand;
 *                   resolveVmSegments rung 1 honours that over lab membership,
 *                   so the GOAD layer must not second-guess it either.
 *   type 'lxc'      every lab host is a full QEMU clone (template 1002/1003/1004)
 *                   and an LXC takes net1 with the template owning net0, so a
 *                   container can never BE a lab host. A container that shares a
 *                   lab host's NAME is still caught — it drops out of the managed
 *                   set, which leaves that lab host missing from spec.vms.
 */
function isGoadManagedVm(vmSpec) {
  if (!vmSpec || typeof vmSpec.name !== 'string' || !vmSpec.name) return false;
  if (EXTERNAL_ROLES.has(vmSpec.role)) return false;
  if (Array.isArray(vmSpec.nics) && vmSpec.nics.some(n => n && n.segment)) return false;
  if ((vmSpec.type || 'qemu') === 'lxc') return false;
  return true;
}

/**
 * Validate a spec-supplied lab definition before anything reads it.
 *
 * Hand-rolled — there is no schema library in this repo — and deliberately
 * strict, because every field below is load-bearing at deploy time and each one
 * fails QUIETLY when it is wrong: a missing ipOctet yields a MAC ending in the
 * hex of NaN and a reservation for "<base>.undefined" that dnsmasq refuses,
 * taking DHCP down for the whole lane; a role outside ROLE_RESOURCES is never
 * filtered out of the WinRM wait, so a Linux box is polled on 5985 for the full
 * 30 minutes before the deploy finally fails.
 */
function assertValidLabDef(labDef, labName) {
  const where = `spec.goad.lab (version '${labName}')`;
  const shape = 'Shape: { forestRoot: "corp.local", vms: [{ name, role, os, template_vmid, ipOctet, nic_model }] }.';
  if (!labDef || typeof labDef !== 'object' || Array.isArray(labDef)) {
    throw new Error(`${where} must be an object. ${shape}`);
  }
  if (typeof labDef.forestRoot !== 'string' || !labDef.forestRoot.trim()) {
    throw new Error(`${where} needs a non-empty string forestRoot — it names the domain every artifact greets the lane by. ${shape}`);
  }
  if (!Array.isArray(labDef.vms) || labDef.vms.length === 0) {
    throw new Error(`${where} needs a non-empty vms[]. A lab with no hosts reconciles against an empty roster, which would make EVERY machine in spec.vms a stray. ${shape}`);
  }
  const roles = Object.keys(ROLE_RESOURCES);
  const seenName = new Map();
  const seenOctet = new Map();
  labDef.vms.forEach((v, i) => {
    const at = `${where}.vms[${i}]`;
    if (!v || typeof v !== 'object' || typeof v.name !== 'string' || !v.name.trim()) {
      throw new Error(`${at} needs a non-empty string name — the name is the ONLY thing that binds it to a machine in spec.vms.`);
    }
    if (!roles.includes(v.role)) {
      throw new Error(`${at} ('${v.name}') has role ${JSON.stringify(v.role)}; it must be one of ${roles.join(', ')}. Role picks the memory/core defaults AND decides whether the host is polled for WinRM ('linux' is skipped).`);
    }
    // 2..254: .0 is the network address, .255 the broadcast, .1 the gateway.
    if (!Number.isInteger(v.ipOctet) || v.ipOctet < 2 || v.ipOctet > 254) {
      throw new Error(`${at} ('${v.name}') needs an integer ipOctet in 2..254; got ${JSON.stringify(v.ipOctet)}. It is both the host's last octet and the last byte of its deterministic MAC.`);
    }
    const key = v.name.toLowerCase();
    if (seenName.has(key)) {
      throw new Error(`${at} repeats the name '${v.name}' (already at vms[${seenName.get(key)}]). Matching is case-insensitive, so the second entry would shadow the first and one host would silently take the other's address.`);
    }
    seenName.set(key, i);
    if (seenOctet.has(v.ipOctet)) {
      throw new Error(`${at} ('${v.name}') reuses ipOctet ${v.ipOctet}, already taken by '${seenOctet.get(v.ipOctet)}'. Two dhcp-host lines claiming one address make dnsmasq refuse to start, which takes DHCP down for the whole lane.`);
    }
    seenOctet.set(v.ipOctet, v.name);
  });
  // Kali (.50) is deliberately NOT checked: it lives on the EXTERNAL segment
  // while lab hosts live on the internal one, so on a v3 lane .50 is genuinely
  // free for a lab host. The gateway and the controller share the lab hosts'
  // subnet on every scheme, so those two are always a collision.
  for (const v of labDef.vms) {
    for (const infra of ['gateway', 'controller']) {
      if (v.ipOctet === INFRA_IP_OCTETS[infra]) {
        throw new Error(`${where}: '${v.name}' claims ipOctet ${v.ipOctet}, which is the lane ${infra}. Lab hosts share that subnet, so the ${infra} would be unreachable from inside the lane.`);
      }
    }
  }
}

/**
 * THE resolver. Every deploy-time read of a lab definition goes through here,
 * with one precedence:
 *
 *     spec.goad.lab  →  GOAD_LABS[spec.goad.version]  →  GOAD_LABS[DEFAULT_LAB]
 *
 * WHY IT IS A FUNCTION AND NOT FIVE COPIES OF ONE EXPRESSION: this module had
 * the lookup inlined at five sites, and a site that missed a term resolved a
 * DIFFERENT lab from its neighbours — the MAC table built from one lab, the
 * WinRM wait list from another. Nothing throws when those disagree; the lane
 * just comes up wrong. One reader means a new precedence rule (goad.lab is the
 * first in years) reaches every site or none.
 *
 * spec.goad.lab exists so a GENERATED engagement can describe its own forest on
 * the spec instead of requiring a commit to GOAD_LABS per engagement. Note that
 * goad.version still selects the upstream ad/<name>/ playbook chain run.sh
 * executes, so a spec-supplied lab should ALSO set a version its controller
 * knows — the definition here governs addressing and sizing, not the playbook.
 *
 * @returns {{ labName: string, labDef: object, fromSpec: boolean }}
 */
function resolveGoadLab(specArg) {
  // macFor() resolves a lab with no spec in hand at all. Normalising the shape
  // here keeps the precedence chain below written exactly once rather than once
  // per flavour of caller — which is the entire point of this function.
  const spec = (specArg && specArg.goad) ? specArg : { goad: {} };
  const labName = canonicalGoadLabName(spec.goad.version || DEFAULT_LAB);
  const supplied = spec.goad.lab;
  if (supplied) assertValidLabDef(supplied, labName);
  const lab = supplied || GOAD_LABS[labName];
  if (!lab) {
    // Preserve unknown legacy fallback while refusing a generated/renamed lab
    // whose roster would otherwise come from a different built-in identity.
    const rosterAtStake = Array.isArray(specArg && specArg.vms) && specArg.vms.length > 0;
    if (spec.goad.rename_forest === true || (spec.goad.generated_lab && rosterAtStake)) {
      throw new Error(
        `Unknown GOAD lab version '${labName}', and this spec cannot fall back to ${DEFAULT_LAB}: it `
        + `${spec.goad.rename_forest === true ? 'requests a forest rename' : 'carries a generated_lab tree'}`
        + ', so the version names the ad/<LAB> directory run.sh resolves and the playbooks.yml key it '
        + `reads the chain from, while ${DEFAULT_LAB}'s roster would silently supply this lane's `
        + 'addressing. Remedy: set spec.goad.version to a lab this build ships, or describe the lab '
        + 'on the spec itself as goad.lab = { forestRoot, vms: [...] }. Known labs: '
        + `${Object.keys(GOAD_LABS).join(', ')}.`);
    }
    console.warn(`[GOAD] Unknown lab version '${labName}' — falling back to ${DEFAULT_LAB}`);
  }
  const labDef = lab || GOAD_LABS[DEFAULT_LAB];

  // Fold in the extension machines that JOIN THE FOREST (ws01 today). They have
  // to be part of the roster the rest of this module reads, because every AD
  // affordance downstream is keyed on lab membership by NAME: the deterministic
  // MAC, the DHCP reservation, the stop/start that renews onto it, the WinRM
  // wait, and the pre-baked secure-channel heal. A domain-joined host outside
  // the roster gets none of those and comes up on a random pool lease.
  //
  // A spec with no `extensions` gets baseDef BY IDENTITY — same object, same
  // vms array — so every lane authored before this existed resolves exactly what
  // it resolved before. That matters more than it looks: assertGoadRoster checks
  // BOTH directions, so an extra roster entry that spec.vms does not carry is a
  // hard deploy failure, and quietly widening the roster for existing specs
  // would break every GOAD lane in flight.
  //
  // The line above is pinned by a source-text gate in
  // test/ciab-engagement-model.test.js (B0-107): CiAB's compiler mirrors this
  // membership decision offline, so `const labDef = lab || GOAD_LABS[DEFAULT_LAB];`
  // is read as text and must stay spelled exactly that way. The composition
  // below is therefore additive rather than a rewrite of it.
  const ext = resolveGoadExtensions(spec.goad.extensions, labName, labDef);
  const composed = ext.inLab.length
    ? { ...labDef, vms: [...labDef.vms, ...ext.inLab] }
    : labDef;

  return { labName, labDef: composed, fromSpec: !!supplied, extensions: ext };
}

/**
 * Reconcile spec.vms against the resolved lab definition, and THROW on any
 * disagreement. This is the guard the rest of this module is arranged around.
 *
 * WHAT IT PREVENTS. prepareGoadMacs used to skip past a spec VM whose name
 * matched nothing in the lab. That host then got no deterministic MAC and no
 * DHCP reservation; resolveVmSegments rung 4 dropped it onto the EXTERNAL
 * segment; it took a random pool lease; the pre-baked heal skipped it because
 * the heal tags VMs by lab name; and the WinRM wait polled the address the lab
 * table said it should have had, which nobody owned. Every one of those is
 * silent. The lane finished, reported active, and was wrong — the worst failure
 * mode in the system, because a lane that fails loudly gets retried and a lane
 * that lies gets graded.
 *
 * BOTH DIRECTIONS ARE CHECKED. A stray in spec.vms is the case above. A lab host
 * ABSENT from spec.vms is its mirror: nothing clones it, macs[name] is
 * undefined, .filter(Boolean) quietly drops it from the WinRM list, and the
 * playbook runs against a forest missing a DC — which surfaces hours later as
 * replication failures rather than as a deploy error.
 */
function assertGoadRoster(spec, labName, labDef, fromSpec, externalNames) {
  const declared = new Map(labDef.vms.map(v => [v.name.toLowerCase(), v.name]));
  // Extension machines that are NOT in the forest (elk, wazuh, lx01) are
  // ordinary spec VMs by design — see GOAD_EXTENSIONS' `inLab: false`. They
  // would otherwise read as strays here: isGoadManagedVm only exempts
  // EXTERNAL_ROLES, explicit nics[] and containers, and role 'linux' is a
  // legitimate LAB role (DRACARYS ships LX01), so it cannot be exempted
  // wholesale without punching a hole in the roster check for a real lab host.
  // The exemption is therefore per-spec — it applies only to a machine the spec
  // itself declared as an extension.
  const exempt = externalNames || new Set();
  const managed = new Map();
  const strays = [];
  for (const vm of spec.vms) {
    if (!isGoadManagedVm(vm)) continue;
    const key = vm.name.toLowerCase();
    if (exempt.has(key)) continue;
    managed.set(key, vm.name);
    if (!declared.has(key)) strays.push(vm.name);
  }
  const absent = [...declared.keys()].filter(k => !managed.has(k)).map(k => declared.get(k));
  if (strays.length === 0 && absent.length === 0) return;

  const source = fromSpec ? 'spec.goad.lab' : `the built-in '${labName}' lab`;
  const clauses = [];
  if (strays.length) {
    clauses.push(`${strays.join(', ')} ${strays.length === 1 ? 'is' : 'are'} in spec.vms but not in ${source}`);
  }
  if (absent.length) {
    clauses.push(`${absent.join(', ')} ${absent.length === 1 ? 'is' : 'are'} in ${source} but not in spec.vms`);
  }
  throw new Error(
    `GOAD lab roster mismatch: ${clauses.join('; ')}. ` +
    `Declared roster: ${labDef.vms.map(v => v.name).join(', ')}. ` +
    'Remedy — pick one: (1) rename the spec machine to the lab host it is meant to be (matching is ' +
    'case-insensitive but NOT trimmed); (2) if it belongs outside the AD forest, give it "role": "dmz" ' +
    'or "role": "attacker", or attach it to a segment explicitly with nics[]; (3) add the missing lab ' +
    'host to spec.vms; (4) for a generated lab, describe it on the spec itself as ' +
    'goad.lab = { forestRoot, vms: [{ name, role, os, template_vmid, ipOctet }] } instead of ' +
    'requiring an entry in GOAD_LABS. Refusing to deploy: an unmatched host gets no deterministic MAC ' +
    'and no DHCP reservation, lands on the EXTERNAL segment on a random pool lease, is skipped by the ' +
    'pre-baked heal, and the WinRM wait polls an address nobody owns — the lane reports active and is ' +
    'silently wrong.'
  );
}

/**
 * REFUSE a pre-baked lane that selected an extension.
 *
 * THE FORK THIS GUARDS. There are two GOAD deploy modes and only one of them
 * runs Ansible:
 *
 *   live (default)   deployController → waitForWinRM → runGoadPlaybook, which
 *                    runs /opt/goad-light/run.sh — and run.sh is the ONLY thing
 *                    that ever executes an extension's install.yml.
 *   prebaked         deployPrebakedGoadLane clones golden images and heals their
 *                    secure channels. No controller is started at all
 *                    (challenge-lane-deployer's liveGoadController is literally
 *                    `enabled && !prebaked`), so run.sh never runs.
 *
 * So on a pre-baked lane a ticked extension does every visible thing and the one
 * invisible thing not at all: the machine is cloned, given a deterministic MAC,
 * a reserved address, a DNS record and a console — and nothing is installed on
 * it. elk comes up as a bare Ubuntu box with no Elasticsearch listening; wazuh
 * the same; ws01 boots as an un-joined workstation. The lane reports ACTIVE. The
 * first person to find out is a student clicking through to an empty Kibana.
 *
 * That is precisely the silent-success shape assertGoadRoster exists to prevent,
 * so it is refused the same way and at the same funnel: prepareGoadMacs, which
 * both deploy modes call before anything is cloned. The Designer catches it
 * earlier — topology-validate's `prebaked-extension` error, at authoring time —
 * but a spec can reach a deploy without ever passing through the canvas (the
 * CiAB compiler writes specs directly), so the canvas cannot be the only gate.
 *
 * @param {object} spec       the challenge spec (reads spec.goad.prebaked)
 * @param {string[]} selected resolveGoadLab(spec).extensions.selected — already
 *                            filtered to the keys this lab can actually take
 */
function assertGoadExtensionsRunnable(spec, selected) {
  if (!spec?.goad?.prebaked) return;
  const keys = Array.isArray(selected) ? selected : [];
  if (keys.length === 0) return;

  // PRE-BAKED + EXTENSIONS IS THE INTENDED STEADY STATE, NOT AN ERROR.
  //
  // An earlier revision refused this combination outright, reasoning that a
  // pre-baked lane runs no Ansible so nothing could install the stack. True, and
  // it misses the point: the operational plan is to run the extension install
  // ONCE against a staging lab, seal the result into golden templates
  // (seal-goad-elk-template.sh, seal-goad-wazuh-template.sh), and clone those
  // forever. At that point nothing NEEDS to install — the image already carries
  // it, and pre-baked is the whole reason for sealing.
  //
  // So the question is not "is this lane pre-baked" but "does this extension's
  // machine clone an image that already has the stack on it". Exactly one answer
  // is wrong: still pointing at PLAIN_BASE_TEMPLATE_VMID, the generic Ubuntu box
  // with nothing installed. That is the silent-success case — cloned, addressed,
  // given a console and a DNS record, carrying nothing.
  //
  // A machine with NO template at all is also refused: 'nothing to clone' is a
  // different failure, but it is not one to discover on a pre-baked lane.
  const specVms = Array.isArray(spec.vms) ? spec.vms : [];
  const unbaked = [];
  for (const key of keys) {
    const ext = getExtension(key);
    const machine = String(ext ? ext.machine : key).toLowerCase();
    const row = specVms.find(v => String(v.name || '').toLowerCase() === machine);
    // Precedence matches the deploy path: the spec row's own template wins, then
    // the catalog default, then the spec-wide fallback.
    const vmid = Number(row?.template_vmid || ext?.template_vmid || spec.template_vmid || 0);
    if (!vmid || vmid === PLAIN_BASE_TEMPLATE_VMID) unbaked.push({ key, ext, vmid });
  }
  if (unbaked.length === 0) return;

  const list = unbaked.map(u => u.key).join(', ');
  const one = unbaked.length === 1;
  throw new Error(
    `GOAD extension${one ? '' : 's'} ${list} ${one ? 'is' : 'are'} selected on a PRE-BAKED lane ` +
    `(spec.goad.prebaked), but ${one ? 'its machine still clones' : 'their machines still clone'} an image ` +
    `with no stack on it: ` +
    unbaked.map(u => `${u.ext ? u.ext.machine : u.key} -> ` +
      (u.vmid ? `template ${u.vmid}, the generic Ubuntu base` : 'no template at all')).join('; ') +
    '. A pre-baked lane clones golden images and runs NO Ansible — no controller is deployed and ' +
    "/opt/goad-light/run.sh, the only thing that ever runs an extension's install.yml, never executes. " +
    `So ${one ? 'that machine' : 'those machines'} would be cloned, addressed, given a DNS record and a ` +
    `console, have nothing installed, and the lane would still report active. ` +
    'Remedy — pick one: (1) point the machine at a SEALED template that already carries the stack ' +
    '(seal-goad-elk-template.sh produces one, seal-goad-wazuh-template.sh the other) — this is the ' +
    'intended steady state, and pre-baked plus a sealed image is fully supported; (2) clear ' +
    `spec.goad.prebaked so the lab is provisioned live and run.sh installs ${list} in-lane, which is how ` +
    `you produce the image to seal in the first place; or (3) drop ${list} from spec.goad.extensions. ` +
    'Refusing to deploy.'
  );
}

/** Validate an explicit rename request; unsupported requests never deploy stock. */
function assertForestRenameDeployable(spec) {
  if (spec?.goad?.rename_forest !== true) return;
  const verdict = describeRebrand(spec);
  if (verdict.willRebrand || verdict.code === REBRAND_CODES.ALREADY_REBRANDED) return;
  throw new RebrandError(verdict.code, verdict.reason, { baseLab: verdict.baseLab });
}

/** Pure preparation shared by every deploy entry point, before allocation. */
function prepareGoadDeploymentSpec(spec) {
  if (!spec?.goad?.enabled) return spec;
  try {
    assertForestRenameDeployable(spec);
    const prepared = preflightGoadRebrand(spec);
    const { labName, labDef, fromSpec, extensions } = resolveGoadLab(prepared);
    if (!Array.isArray(prepared.vms)) throw new Error('GOAD deployment requires spec.vms to declare the complete lab roster');
    assertGoadRoster(prepared, labName, labDef, fromSpec, extensions.external);
    assertGoadExtensionsRunnable(prepared, extensions.selected);
    assertGoadExtensionsRenameSafe(prepared, extensions.selected);
    if (prepared.goad.generated_lab) resolveGeneratedLab(prepared);
    goadIdentityExpectations(prepared);
    return prepared;
  } catch (error) {
    error.status = 400;
    throw error;
  }
}

/**
 * REFUSE a renamed lane whose extension carries a domain we cannot rewrite.
 *
 * THE BREAK, TRACED. extensions/<key>/ansible/install.yml imports the MAIN
 * lab's data — our renamed tree — layers the extension's own data/config.json
 * over it as `lab_extension`, and then joins the two BY DOMAIN NAME:
 *
 *     member_domain:   "{{ lab.hosts[dict_key].domain }}"    still the stock root
 *     domain_password: "{{ lab.domains[member_domain].domain_password }}"
 *
 * After a rename, an unchanged extension would resolve a missing domain. The
 * controller compiler rewrites the selected extension with the main lab. This
 * guard checks that the plan and controller recipe support that extension.
 *
 * It reads GOAD_EXTENSIONS[key].shipsLabConfig, never the disk under GOAD-main/
 * — see the flag's contract above the catalog.
 *
 * @param {object} spec       the challenge spec
 * @param {string[]} selected resolveGoadLab(spec).extensions.selected
 */
function assertGoadExtensionsRenameSafe(spec, selected) {
  const goad = spec && spec.goad;
  if (!goad || goad.rename_forest !== true) return;
  const keys = Array.isArray(selected) ? selected : [];
  if (keys.length === 0) return;

  // Authored requests and our already-planned in-memory specs share this guard.
  const verdict = describeRebrand(spec);
  if (!verdict.willRebrand && verdict.code !== REBRAND_CODES.ALREADY_REBRANDED) return;

  const carried = (goad.generated_lab && typeof goad.generated_lab === 'object')
    ? goad.generated_lab.extension_configs
    : null;

  const unsafe = [];
  for (const key of keys) {
    const ext = getExtension(key);
    if (!ext || ext.shipsLabConfig !== true) continue;
    if (!listExtensionBases().includes(key)) {
      unsafe.push(`${key} (no identity metadata in src/data/goad-base-labs/_extensions/${key}/)`);
    } else if (goad.rename_plan && !goad.rename_plan.selected_extensions?.includes(key)) {
      unsafe.push(`${key} (the rename plan does not select this extension)`);
    } else if (goad.generated_lab && (!carried || typeof carried[key] !== 'string')) {
      // The tree was compiled without this extension's config. Pushing it would
      // deliver a renamed lab beside an extension config that still names the
      // stock forest — the two-files-disagree state, arrived at from the other
      // side.
      unsafe.push(`${key} (the compiled lab carries no rewritten config for it)`);
    }
  }
  if (unsafe.length === 0) return;

  const one = unsafe.length === 1;
  throw new RebrandError(
    REBRAND_CODES.EXTENSION,
    `This lane renames the forest root and selected ${one ? 'an extension' : 'extensions'} whose own `
    + `data/config.json cannot be rewritten: ${unsafe.join('; ')}. install.yml layers that config over `
    + 'the renamed lab and joins the two by domain name, so it would look up a domain the lab no '
    + `longer has and die with the machine already cloned and booted. Remedy — pick one: (1) drop `
    + `${unsafe.map(u => u.split(' ')[0]).join(', ')} from spec.goad.extensions; (2) clear the forest `
    + 'rename and deploy the lab under its shipped domain; or (3) add matching identity metadata and controller rewrite support so the '
    + 'rename can deliver it. Refusing to deploy.',
    { extensions: unsafe });
}

/**
 * Build a deterministic locally-administered MAC from an IP last octet.
 * Format: 02:00:CC:HH:LL:RR
 *   02      — locally-administered (and unicast)
 *   00:CC   — fixed marker for "this is a CyberHub-managed MAC"
 *   HH:LL   — vxlanId high/low bytes (uniqueness across lanes)
 *   RR      — IP last octet (matches the static IP for trivial reservation lookup)
 */
function macForOctet(ipOctet, vxlanId) {
  const hi = (vxlanId >> 8) & 0xFF;
  const lo = vxlanId & 0xFF;
  const hex = (n) => n.toString(16).padStart(2, '0').toUpperCase();
  return `02:00:CC:${hex(hi)}:${hex(lo)}:${hex(ipOctet & 0xFF)}`;
}

/**
 * Back-compat shim: old call sites used macFor('controller'|'DC01'|...).
 * Resolves the role via INFRA_IP_OCTETS first, then falls back to the DEFAULT
 * lab's VM list (the original behaviour).
 *
 * It has no spec, so it cannot honour a spec-supplied goad.lab — which is why
 * the only live caller is deployController('controller', …), an INFRA octet
 * that never reaches the lab table at all. Anything resolving a LAB HOST must
 * take the MAC from prepareGoadMacs, which does have the spec.
 */
function macFor(role, vxlanId) {
  if (INFRA_IP_OCTETS[role] !== undefined) return macForOctet(INFRA_IP_OCTETS[role], vxlanId);
  const { labDef } = resolveGoadLab(null);
  const vm = labDef.vms.find(v => v.name === role);
  if (!vm) throw new Error(`Unknown GOAD role for MAC derivation: ${role}`);
  return macForOctet(vm.ipOctet, vxlanId);
}

/**
 * Build a per-lane MAC/IP/role lookup table for the GOAD VMs in spec.vms.
 * Pure function: never mutates `spec`. Caller invokes once per lane (passing
 * that lane's vxlanId AND the lane subnet base) and uses the returned map
 * when building net0 strings and DHCP reservations.
 *
 * Returns: { '<vmName>': { mac, static_ip, role, nic_model }, ... }
 *
 * The lab comes from resolveGoadLab (spec.goad.lab, else spec.goad.version,
 * else the default). THROWS when spec.vms and that lab disagree about which
 * hosts exist — see assertGoadRoster for why a mismatch must never be survived.
 * Machines exempted by isGoadManagedVm (Kali, the dmz pivot, anything with
 * explicit nics[], containers) are simply absent from the returned map, which
 * is how the rest of the deploy learns they are not lab hosts.
 *
 * @param {object} spec
 * @param {number} vxlanId
 * @param {string} laneSubnetBase  — e.g., "192.18.0" (v1) or "10.39.17" (v2)
 */
function prepareGoadMacs(spec, vxlanId, laneSubnetBase) {
  if (!spec?.goad?.enabled) return {};
  if (!Array.isArray(spec.vms)) return {};

  const { labName, labDef, fromSpec, extensions } = resolveGoadLab(spec);

  const byName = Object.fromEntries(labDef.vms.map(v => [v.name.toLowerCase(), v]));

  // THE HARD ERROR. Before this line existed the loop below silently skipped
  // any name it could not match, and the lane came up wrong without a word.
  assertGoadRoster(spec, labName, labDef, fromSpec, extensions && extensions.external);

  // THE OTHER HARD ERROR, and it belongs here for the same reason: this function
  // is the one funnel BOTH deploy modes pass through before a single clone, so a
  // pre-baked lane that ticked an extension is stopped here rather than finishing
  // green with an empty SIEM on it.
  assertGoadExtensionsRunnable(spec, extensions && extensions.selected);

  // Reject invalid rename plans before allocating guests. Later controller
  // failures are retained as suspended lanes, but these require no I/O and
  // therefore should never consume a lane's resources.
  assertForestRenameDeployable(spec);
  assertGoadExtensionsRenameSafe(spec, extensions && extensions.selected);

  // And the generated tree's own shape, for any spec that carries one — CiAB's
  // as much as any other generated lab. resolveGeneratedLab already runs inside
  // deliverGeneratedLab; checking HERE rejects a name/version mismatch before
  // allocation rather than leaving a failed, partially built lane.
  if (spec.goad.generated_lab) resolveGeneratedLab(spec);

  const out = {};
  for (const vm of spec.vms) {
    if (!vm?.name) continue;
    const labVm = byName[vm.name.toLowerCase()];
    // Reaching this only happens for a machine assertGoadRoster has already
    // proved is EXEMPT (Kali, the pivot, an explicitly-placed box, an LXC);
    // an unmatched lab host threw above. Falling through here is deliberate:
    // those machines are addressed by the deployer's own octet band.
    if (!labVm) continue;
    // Per-VM overrides on `vm` (from the challenge spec in DB) take precedence
    // over the lab definition's own fields, which take precedence over role
    // defaults. Lets a challenge author bump just one VM without rewriting
    // the whole lab def.
    const resources = getVmResources({ ...labVm, ...vm });
    out[vm.name] = {
      mac:        macForOctet(labVm.ipOctet, vxlanId),
      static_ip:  buildIp(laneSubnetBase, labVm.ipOctet),
      role:       labVm.role,
      nic_model:  labVm.nic_model || 'e1000',
      memory:     resources.memory,
      balloon:    resources.balloon,
      cores:      resources.cores
    };
  }
  return out;
}

/**
 * Build the net0 string for a lane VM clone. Centralizes the optional macaddr
 * suffix so admin.js's three deploy paths can share one helper.
 *
 * The 4th arg `nicModel` (when provided by prepareGoadMacs) overrides the
 * default. Upstream GOAD documents that AD-joining Windows VMs MUST use
 * e1000; virtio breaks the domain join. Linux VMs (DRACARYS LX01) work on
 * virtio. Non-GOAD lanes default to virtio as before.
 */
function buildLaneNet0(vmSpec, vnetName, mac, nicModel) {
  const macStr = mac || vmSpec?.mac;
  if ((vmSpec?.type || 'qemu') === 'lxc') {
    return `name=lan0,bridge=${vnetName}` + (macStr ? `,hwaddr=${macStr}` : '');
  }
  const model = nicModel || vmSpec?.nic_model || 'virtio';
  return `${model},bridge=${vnetName}` + (macStr ? `,macaddr=${macStr}` : '');
}

/** Full reservation set needed while old controller prep/run scripts own DHCP. */
function buildGoadHostMap(spec, vxlanId, laneSubnetBase, extSubnetBase) {
  const macs = prepareGoadMacs(spec, vxlanId, laneSubnetBase);
  const triples = Object.entries(macs).map(([name, info]) => `${name}|${info.static_ip}|${info.mac}`);
  triples.push(`goad-controller|${buildIp(laneSubnetBase, INFRA_IP_OCTETS.controller)}|${macForOctet(INFRA_IP_OCTETS.controller, vxlanId)}`);
  const externalBase = extSubnetBase || laneSubnetBase;
  if (spec.goad.include_kali !== false) {
    triples.push(`kali|${buildIp(externalBase, INFRA_IP_OCTETS.Kali)}|${macForOctet(INFRA_IP_OCTETS.Kali, vxlanId)}`);
  }
  for (const key of resolveGoadLab(spec).extensions.selected) {
    const extension = getExtension(key);
    if (extension.inLab) continue;
    const vm = (spec.vms || []).find(candidate => String(candidate.name).toLowerCase() === extension.machine.toLowerCase());
    if (vm) triples.push(`${vm.name}|${buildIp(externalBase, extension.ipOctet)}|${macForOctet(extension.ipOctet, vxlanId)}`);
  }
  return triples.join(',');
}

/**
 * Write the per-lane DHCP reservations file inside the lane gateway and
 * reload dnsmasq. Called AFTER the gateway is started.
 *
 * Reads spec.vms (decorated by prepareGoadSpec) plus the controller's static
 * IP, emits a single dnsmasq config snippet at /etc/dnsmasq.d/lane-reservations.conf
 * inside the gateway LXC.
 */
async function writeDhcpReservations({ gatewayVmId, bestNode, spec, vxlanId, laneSubnetBase, extSubnetBase }) {
  if (!spec?.goad?.enabled) return;

  const { labName } = resolveGoadLab(spec);
  const lines = [`# GOAD-${labName} lane DHCP reservations — generated by goad-deploy.js`];

  // Controller — always (every lab uses one)
  lines.push(`dhcp-host=${macForOctet(INFRA_IP_OCTETS.controller, vxlanId)},${buildIp(laneSubnetBase, INFRA_IP_OCTETS.controller)},goad-controller`);

  // Optional Kali (.50 via INFRA_IP_OCTETS.Kali). Kali lives on the EXTERNAL
  // segment, so its reservation uses extSubnetBase (falls back to laneSubnetBase
  // for single-segment v1/v2). This writer is the reservation path for the
  // pre-baked ("GOAD-Like") deploy — there is no controller running prep.sh in
  // that mode, so reservations are pushed straight into the gateway here.
  if (spec.goad.include_kali !== false) {
    const kaliBase = extSubnetBase || laneSubnetBase;
    lines.push(`dhcp-host=${macForOctet(INFRA_IP_OCTETS.Kali, vxlanId)},${buildIp(kaliBase, INFRA_IP_OCTETS.Kali)},kali`);
  }

  // Lab VMs
  const macs = prepareGoadMacs(spec, vxlanId, laneSubnetBase);
  for (const [vmName, info] of Object.entries(macs)) {
    lines.push(`dhcp-host=${info.mac},${info.static_ip},${vmName}`);
  }

  const conf = lines.join('\n') + '\n';

  // SSH to the node, write the reservations file inside the LXC, reload dnsmasq.
  await nodeSsh.pctPushFromString(bestNode, gatewayVmId, conf, '/etc/dnsmasq.d/lane-reservations.conf');
  await nodeSsh.pctExec(bestNode, gatewayVmId, ['/bin/sh', '-c',
    'rc-service dnsmasq restart 2>/dev/null || /etc/init.d/dnsmasq restart 2>/dev/null || systemctl restart dnsmasq 2>/dev/null || true'
  ]);
}

/**
 * Clone GOAD controller template (1700, QEMU VM with qemu-guest-agent) onto
 * the lane VNet. Configures net0 with the controller's deterministic MAC so
 * the gateway's DHCP reservation hands it .5, plus cloud-init for hostname.
 *
 * Returns the deployed controller VMID.
 */
async function deployController({
  vxlanId, vnetName, bestNode, templateNode, lane, module, laneSubnetBase, proxmoxAPI, waitForTask
}) {
  // Controller VMID range: 200000+vxlanId (lane VMs are at 600000+, gateway at 100000+;
  // 200000 keeps controller IDs unambiguous).
  const controllerVmId = 200000 + vxlanId;
  const mac = macFor('controller', vxlanId);
  const hostname = `goad-ctrl-${vxlanId}`;

  // Clone the QEMU template
  const cloneResult = await proxmoxAPI(
    'POST',
    `/api2/json/nodes/${templateNode}/qemu/${CONTROLLER_TEMPLATE_VMID}/clone`,
    {
      newid: controllerVmId,
      name: hostname,
      full: 1,
      target: bestNode,
      description: `GOAD controller for lane ${lane.lane_id}\nModule: ${module}\nVXLAN: ${vxlanId}\nLane subnet: ${laneSubnetBase}.0/24`,
      pool: `${module}-pool`
    }
  );
  if (cloneResult) await waitForTask(templateNode, cloneResult);

  // Attach to the lane VNet with the deterministic MAC. Give the controller
  // a STATIC IP (not DHCP) so it lands on <laneSubnetBase>.5 from boot — the
  // gateway's firewall ACL only permits SSH from that one IP, and we'd hit
  // a chicken-and-egg if the controller had to wait for its own DHCP
  // reservation (which would have to be written via SSH to the gateway,
  // which would require the controller to already have the right IP).
  // virtio NIC is fine here (no domain-join sensitivity like the Win VMs).
  const controllerStaticIp = buildIp(laneSubnetBase, INFRA_IP_OCTETS.controller);   // <base>.5
  const laneGwIp           = buildIp(laneSubnetBase, INFRA_IP_OCTETS.gateway);      // <base>.1
  await proxmoxAPI('POST', `/api2/json/nodes/${bestNode}/qemu/${controllerVmId}/config`, {
    net0: `virtio,bridge=${vnetName},macaddr=${mac}`,
    ipconfig0: `ip=${controllerStaticIp}/24,gw=${laneGwIp}`,
    nameserver: laneGwIp,
    citype: 'nocloud'
  });
  // Regenerate cloud-init drive so the new hostname/network take effect on boot
  await proxmoxAPI('PUT', `/api2/json/nodes/${bestNode}/qemu/${controllerVmId}/cloudinit`).catch(() => {});

  await proxmoxAPI('POST', `/api2/json/nodes/${bestNode}/qemu/${controllerVmId}/status/start`);
  return controllerVmId;
}

/**
 * Sleep helper.
 */
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

/**
 * From inside the controller, TCP-poll port 5985 on each Windows VM until
 * they all answer (WinRM is up). Returns the IPs that responded; throws if
 * timeoutMs elapses before all are ready.
 *
 * Default 30 min: the Windows VMs go through Windows boot + cloud-init style
 * first-boot config + WinRM startup. With Tier 2 sizing (more cores/memory =
 * more first-boot device enumeration), the worst case observed is ~15 min;
 * 30 min gives comfortable headroom without pushing the per-lane deploy
 * envelope. Raise the cap if you regularly see "WinRM did not come up"
 * errors despite the lane being healthy after teardown.
 */
async function waitForWinRM({ controllerVmId, bestNode, vmIPs, proxmoxAPI, timeoutMs = 1800000 }) {
  const deadline = Date.now() + timeoutMs;
  const pending = new Set(vmIPs);
  const ready = [];

  while (pending.size > 0 && Date.now() < deadline) {
    for (const ip of [...pending]) {
      try {
        // From inside the controller VM, probe the Win VM's WinRM port via
        // qemu-guest-agent. Argv form so Proxmox parses each element as a
        // separate command-line arg (single-string form fails with 596 — see
        // agentExecArgv comment).
        const probe = `timeout 3 bash -c 'exec 3<>/dev/tcp/${ip}/5985' 2>/dev/null && echo OK`;
        const { pid } = await agentExecArgv(bestNode, controllerVmId,
          ['/bin/bash', '-c', probe], proxmoxAPI);
        const result = await pollExecStatus(bestNode, controllerVmId, pid, 10000);
        if (result.exited && (result.stdout || '').includes('OK')) {
          pending.delete(ip);
          ready.push(ip);
          console.log(`[GOAD] WinRM ready on ${ip}`);
        }
      } catch {
        // expected on any host that's not yet listening; will retry
      }
    }
    if (pending.size > 0) await sleep(10000);
  }

  if (pending.size > 0) {
    throw new Error(`WinRM did not come up on: ${[...pending].join(', ')} within ${timeoutMs}ms`);
  }
  return ready;
}

/**
 * Run /opt/goad-light/run.sh inside the controller. Blocks until the playbook
 * finishes (or fails). Returns the captured stdout/stderr.
 *
 * spec.goad.admin_user / admin_password are the INITIAL WinRM credentials the
 * run.sh preflight authenticates with. They DEFAULT to vagrant/vagrant and you
 * should almost never override them.
 *
 * Why vagrant, not the built-in Administrator: the Win Server template is
 * sysprep /generalize /oobe'd (so each clone gets a fresh SID). OOBE on a
 * generalized image DISABLES the built-in Administrator account, so connecting
 * as Administrator fails with "ntlm: the specified credentials were rejected by
 * the server" even when the password is right. GOAD bakes a SEPARATE local
 * admin account, vagrant/vagrant, which survives generalize ENABLED — so it's
 * the reliable connection identity. (vagrant is also GOAD's own ansible
 * connection identity for every subsequent play, so this just aligns the
 * preflight with the rest of the chain.) The vagrant password is ALWAYS
 * 'vagrant' on the template.
 *
 * Per-host local Administrator passwords (different per VM, preserving PTH
 * teaching value) come from upstream's config.json verbatim — we no longer
 * patch them.
 */
const CONTROLLER_HOST_MAP_PY = String.raw`import ipaddress
import re
import sys
from pathlib import Path

inventory = Path(sys.argv[1])
addresses = {}
for triple in sys.argv[2].split(','):
    fields = triple.split('|')
    if len(fields) != 3:
        raise SystemExit('Invalid HOST_MAP triple')
    name, address, _ = fields
    if not re.fullmatch(r'[A-Za-z0-9_-]+', name):
        raise SystemExit('Invalid HOST_MAP hostname')
    ipaddress.IPv4Address(address)
    addresses[name.lower()] = address

count = 0
def replace(match):
    global count
    name = match.group(1).lower()
    if name not in addresses:
        return match.group(0)
    count += 1
    return match.group(1) + match.group(2) + addresses[name]

original = inventory.read_text()
updated = re.sub(r'(?m)^([A-Za-z0-9_-]+)([^\r\n]*?\bansible_host=)(\S+)', replace, original)
if not count:
    raise SystemExit('Extension inventory has no host matching HOST_MAP')
inventory.write_text(updated)
`;

/** Adapt an existing extension-capable controller to segmented lane addresses. */
async function ensureControllerHostMap({ controllerVmId, bestNode, proxmoxAPI }) {
  const helper = Buffer.from(CONTROLLER_HOST_MAP_PY).toString('base64');
  const patch = String.raw`import base64, os, re, subprocess
from pathlib import Path
helper = Path('/opt/goad-light/apply-host-map.py')
helper.write_bytes(base64.b64decode('${helper}'))
runner = Path('/opt/goad-light/run.sh')
source = runner.read_text()
call = 'python3 /opt/goad-light/apply-host-map.py "$RUNTIME/inventory_ext_$ext" "$HOST_MAP"'
if call not in source:
    pattern = r'(?m)^([ \t]*)echo "==> Rendered extension inventory: \$RUNTIME/inventory_ext_\$ext"[ \t]*$'
    matches = list(re.finditer(pattern, source))
    if len(matches) != 1:
        raise SystemExit('Cannot safely adapt this controller run.sh extension renderer to HOST_MAP')
    match = matches[0]
    updated = source[:match.start()] + match.group(1) + call + '\n' + source[match.start():]
    temporary = runner.with_name('run.sh.cc-host-map')
    temporary.write_text(updated)
    os.chmod(temporary, runner.stat().st_mode)
    subprocess.run(['bash', '-n', str(temporary)], check=True)
    temporary.replace(runner)
print('HOST_MAP inventory support ready')
`;
  const { pid } = await agentExecArgv(bestNode, controllerVmId, ['/usr/bin/python3', '-c', patch], proxmoxAPI);
  const deadline = Date.now() + 60000;
  let result;
  while (Date.now() < deadline) {
    result = await proxmoxAPI('GET', `/api2/json/nodes/${bestNode}/qemu/${controllerVmId}/agent/exec-status?pid=${pid}`);
    if (result?.exited) break;
    await sleep(1000);
  }
  if (!result?.exited || result.exitcode !== 0) {
    throw new Error(`Controller cannot prepare extension addresses from HOST_MAP: ${String(result?.['err-data'] || result?.['out-data'] || 'patch did not complete').slice(-1500)}`);
  }
}

async function runGoadPlaybook({ controllerVmId, bestNode, spec, vxlanId, laneSubnetBase, extSubnetBase, proxmoxAPI }) {
  const goad = spec.goad || {};
  // Kali sits on the EXTERNAL segment (ext0 for v3); GOAD VMs/controller use
  // laneSubnetBase (internal for v3). Defaults to laneSubnetBase for the
  // single-segment v1/v2 case where ext == int.
  const kaliBase = extSubnetBase || laneSubnetBase;
  // labName, not labDef: run.sh takes the upstream ad/<name>/ playbook chain by
  // name. A spec-supplied goad.lab changes addressing, not which chain runs.
  //
  // `extensions.selected` comes from the SAME resolve on purpose. It is already
  // the set this lab can actually take — resolveGoadExtensions has dropped every
  // key that is incompatible with the lab, collides with a lab host's name or
  // octet, or is a duplicate, and drops unknown keys rather than throwing (a spec
  // saved last term must still deploy against a catalog that has moved). So
  // nothing downstream has to re-derive compatibility, and run.sh is never handed
  // a key whose inventory would fight the lab's.
  const { labName, extensions } = resolveGoadLab(spec);
  // initialUser / initialPass: the account run.sh's preflight uses for the first
  // WinRM connection. Default to vagrant/vagrant — the local-admin account GOAD
  // bakes, which (unlike the built-in Administrator) stays ENABLED through
  // sysprep /generalize /oobe. Overridable via spec.goad.admin_user/_password
  // but should not be needed.
  const initialUser = goad.admin_user || 'vagrant';
  const initialPass = goad.admin_password || 'vagrant';

  const hostMap = buildGoadHostMap(spec, vxlanId, laneSubnetBase, kaliBase);

  // Invoke run.sh inside the controller via qemu-guest-agent.
  //
  // Two failure modes in earlier revisions:
  //   1. QGA buffers stdout/stderr in memory and Ansible's MB of output
  //      fills the buffer, deadlocking the playbook on stdio writes.
  //   2. QGA loses track of long-running processes (SIGCHLD/reaping races):
  //      the process dies but guest-exec-status keeps reporting exited=false
  //      forever. pollExecStatus then waits the full 2h ceiling.
  //
  // Robust pattern:
  //   - Detach run.sh from QGA entirely (nohup setsid + background +
  //     /dev/null fds). QGA's exec returns immediately, and we don't care
  //     about its tracking after that.
  //   - run.sh's stdout/stderr → log file. Tail-on-failure for error context.
  //   - When run.sh exits, write its exit code to a sentinel file.
  //   - Poll for the sentinel via short-lived guest-exec calls (those work
  //     reliably; QGA only loses track of LONG-running processes).
  //
  // SCCM + full GOAD can take an hour+; give it 2h headroom.
  const logPath = `/var/log/goad-run-${vxlanId}.log`;
  const donePath = `/var/log/goad-done-${vxlanId}.txt`;
  const sq = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`;

  // THE 5TH ARGUMENT: the extension keys, comma-joined, in the order they are to
  // be installed. run.sh renders each one's inventory (substituting {{ip_range}}
  // and rewriting elk's .50 to CyberCore's .24 in the same sed pass that already
  // produces inventory_proxmox), layers it on the lab's, and runs
  // extensions/<key>/ansible/install.yml — upstream's run_extension(), which is
  // inventory layering plus one playbook run and nothing else.
  //
  // OMITTED — not passed as '' — when nothing is selected. Both spellings work
  // against a run.sh that reads `"${5:-}"`, but omission makes "an empty
  // selection behaves exactly like today" true BY CONSTRUCTION rather than by an
  // assumption about a script we do not control on this side of the boundary.
  // The controller is a BAKED TEMPLATE: every lane already in flight is running
  // the run.sh it was baked with, and there is no negotiation. An older run.sh
  // may check its own arity (`[ $# -lt 4 ]`), may echo "$@" into the log, may run
  // under `set -u`. A lane with no extensions must hand it a command line it has
  // already proved it handles — byte-identical to the four-argument one that has
  // always been sent. A lane WITH extensions is opting into the new contract, and
  // an older controller that ignores a 5th argument degrades to "lab installs,
  // extensions do not" rather than breaking the lab.
  const extArg = (extensions?.selected || []).length
    ? ` ${sq(extensions.selected.join(','))}`
    : '';

  // ---- Capability gate: does THIS controller understand argv[5]? ----------
  //
  // THE ONLY SILENT FAILURE LEFT IN THIS FEATURE, and it needs no bug — only a
  // forgotten step. The controller is a BAKED TEMPLATE (CONTROLLER_TEMPLATE_VMID).
  // A lane cloned from a template baked before extension support runs a run.sh
  // that binds $1..$4 and never reads $5. Hand it a fifth argument and it is
  // inert: the AD forest builds, run.sh exits 0, the lane reports active, and
  // there is no SIEM and no error anywhere. Every OTHER failure in this feature
  // is loud; this one deploys green and hands a student an empty Kibana.
  //
  // So ask before assuming. The controller bake writes
  // /opt/goad-light/.cc-extension-install and a firstboot runcmd DELETES it again
  // if extensions/{elk,wazuh}/ansible/install.yml did not actually land — so the
  // marker means "this controller can install extensions", not merely "this
  // template is recent". Same shape as goad-lab-push's per-lab-playbooks probe.
  //
  // Only runs when extensions are selected, so a lane that ticks none never pays
  // the round trip and never gains a new way to fail.
  if (extArg) {
    const selectedList = extensions.selected.join(', ');
    let markerPresent = false;
    try {
      // agentExecArgv + the INJECTED proxmoxAPI, not script-executor's
      // agentShellExec/pollExecStatus. Those close over script-executor's own
      // module-level client, so a caller that injected a proxmoxAPI — every test
      // in this file, and any future dry-run path — would find this one probe,
      // alone, still talking to the real cluster. runGoadPlaybook takes
      // proxmoxAPI as a parameter for exactly this reason; a new call inside it
      // that ignores the parameter quietly breaks the seam for everyone.
      const { pid } = await agentExecArgv(bestNode, controllerVmId,
        ['/bin/sh', '-c', 'test -f /opt/goad-light/.cc-extension-install && echo yes || echo no'],
        proxmoxAPI);
      const deadline = Date.now() + 60000;
      let st = null;
      while (Date.now() < deadline) {
        st = await proxmoxAPI('GET',
          `/api2/json/nodes/${bestNode}/qemu/${controllerVmId}/agent/exec-status?pid=${pid}`);
        if (st?.exited) break;
        await new Promise(r => setTimeout(r, 1000));
      }
      if (!st?.exited) throw new Error('capability probe did not exit within 60s');
      markerPresent = /\byes\b/.test(String(st['out-data'] ?? st.outData ?? ''));
    } catch (err) {
      // A probe that cannot run is NOT permission to proceed. The whole point is
      // that the failure it guards against is invisible, so an unreadable answer
      // has to be treated as the bad answer.
      throw new Error(
        `GOAD extensions (${selectedList}) were selected, but the controller capability probe failed: `
        + `${err.message}. Cannot confirm this controller's run.sh understands the extensions argument, and `
        + 'proceeding would risk a lane that reports active with nothing installed. Refusing to deploy.'
      );
    }
    if (!markerPresent) {
      throw new Error(
        `GOAD extensions (${selectedList}) were selected, but this lane's controller does not support them: `
        + '/opt/goad-light/.cc-extension-install is absent, so its /opt/goad-light/run.sh reads only four '
        + 'arguments and would IGNORE the extensions list entirely. The forest would build, the deploy would '
        + 'report success, and the lane would have no SIEM and no error. '
        + `Remedy: re-bake the GOAD controller template (VMID ${CONTROLLER_TEMPLATE_VMID}) with the current `
        + 'infrastructure/proxmox-templates/vm-templates/bake-goad-controller-vm.sh, then redeploy. '
        + `Or untick ${selectedList} to deploy the lab without them. Refusing to deploy.`
      );
    }
    console.log(`[GOAD] controller ${controllerVmId} supports extensions — installing ${selectedList}`);
    if (extSubnetBase && extSubnetBase !== laneSubnetBase
      && extensions.selected.some(key => !getExtension(key).inLab)) {
      await ensureControllerHostMap({ controllerVmId, bestNode, proxmoxAPI });
    }
  }

  // Outer detach: nohup ignores SIGHUP, setsid creates new session, &
  // backgrounds, </dev/null </dev/null 2>&1 close inherited fds so the
  // wrapper bash QGA started can exit cleanly without dragging children.
  // Inner sh -c runs the playbook + records exit code atomically.
  const innerCmd = `/opt/goad-light/run.sh ${sq(labName)} ${sq(hostMap)} ${sq(initialUser)} ${sq(initialPass)}${extArg} > ${logPath} 2>&1; echo \\$? > ${donePath}`;
  const wrappedCmd = `rm -f ${donePath}; nohup setsid sh -c "${innerCmd}" </dev/null >/dev/null 2>&1 &`;

  // ---- mssql offline-install fix (strip FULLTEXT) -----------------------
  // GOAD's mssql role renders sql_conf.ini with FEATURES=SQLENGINE,FULLTEXT.
  // Full-Text Search is NOT in Express *Core* media (SQLEXPR_x64_ENU.exe) — only
  // in *Advanced* (SQLEXPRADV). srv02 installs from the engine-only Core media we
  // stage offline in template 1004, so the SSEI bootstrapper goes looking for the
  // FullText component that media does not carry and hangs forever assembling
  // media (extracts RulesEng, never reaches setup.exe / Detail.txt) — the 2h
  // watchdog then kills the run.
  //
  // ── CORRECTION. This comment used to say "and the lane has no internet". THAT
  // IS FALSE, it was the load-bearing premise of a later design, and it cost a
  // rewrite. A deployed lane has FULL internet egress. From
  // infrastructure/proxmox-templates/sdn-templates/bake-lane-gateway-v3.sh:
  //   · wan0 is the "internet uplink (NAT)" (line 13)
  //   · iptables -t nat -A POSTROUTING -s "$NET" -o wan0 -j MASQUERADE (~line 387),
  //     for BOTH lane subnets
  //   · iptables -A FORWARD -i ext0 -o wan0 -j ACCEPT  and  -i int0 -o wan0
  //     -j ACCEPT (lines 254-255)
  // What IS contained is the LAB BACKBONE: the only DROPs (CYBERCORE-LAB-DROP,
  // lines 343-344) are scoped `-d 100.100.0.0/16`, so a lane cannot reach other
  // lanes or the orchestrator — it can reach the internet all day. That is
  // precisely why runGoadPlaybook can hand run.sh a list of extensions to install
  // in-lane at all.
  //
  // The fix below is still right; only its stated reason was wrong. GOAD doesn't
  // use full-text search, and letting the SSEI go and fetch it turns a local
  // install into a slow, retry-prone online one inside a 2h budget shared with
  // the whole playbook. Determinism, not darkness. The
  // ansible roles live under /opt/goad (the orchestration scripts are the only
  // thing under /opt/goad-light), so patch the role config there before the
  // playbook renders it. Covers MSSQL_2019 + MSSQL_2022 templates, and strips
  // FULLTEXT regardless of feature order. Idempotent; safe to re-run.
  try {
    const { pid: patchPid } = await agentExecArgv(bestNode, controllerVmId,
      ['/bin/bash', '-c',
        `find /opt/goad -name 'sql_conf.ini.MSSQL_*.j2' -exec sed -i -E -e '/^FEATURES=/s/,FULLTEXT//' -e '/^FEATURES=/s/FULLTEXT,//' {} +`],
      proxmoxAPI);
    await pollExecStatus(bestNode, controllerVmId, patchPid, 15000);
  } catch (err) {
    console.warn(`[GOAD] mssql FULLTEXT strip failed (non-fatal): ${err.message}`);
  }

  // ---- mssql offline-install fix #2: SSEI -> extracted setup.exe ----------
  // The role's "Install the database" runs sql_installer.exe (the SQL SSEI
  // bootstrapper) with /MEDIAPATH. The SSEI is an ONLINE downloader: /MEDIAPATH
  // expects the SSEI's *own* downloaded media tree, not the standalone SQLEXPR
  // self-extractor we stage, so it rejects the layout, falls back to phoning
  // home, and hangs there until the 2h watchdog (confirmed 2026-06-15).
  //
  // NOT because "the lane has no internet" — that clause was here and is FALSE;
  // see the correction on the FULLTEXT fix above. bake-lane-gateway-v3.sh
  // MASQUERADEs both lane subnets out wan0 and ACCEPTs ext0→wan0 and int0→wan0 in
  // FORWARD; the only DROPs are `-d 100.100.0.0/16`, which contains the LAB
  // BACKBONE, not the internet. The lane can reach Microsoft fine. The problem is
  // that doing so means several hundred MB over a per-lane NAT, retried silently
  // when it stalls, inside a 2h budget the whole playbook shares — while the
  // media is already sitting on the disk. Fix, proven end-to-end on
  // srv02 (SETUP_EXIT=0): extract the SQLEXPR media once (/q /x:) and run the
  // extracted setup.exe with /QUIET — fully offline. Drop /HIDEPROGRESSBAR and
  // /MEDIAPATH: both are SSEI-only flags that real setup.exe rejects ("the setting
  // 'HIDEPROGRESSBAR' specified is not recognized"). We rewrite the single
  // win_command task into a win_shell (the surrounding become/runas, retries and
  // failed_when still apply). Shipped base64-encoded so the embedded PowerShell
  // survives shell quoting; the Python edits /opt/goad before run.sh renders it.
  // Idempotent (keys off the cybercore-offline-mssql marker). Best-effort.
  try {
    const installPatchPy = `import re, sys
P = "/opt/goad/ansible/roles/mssql/tasks/main.yml"
s = open(P).read()
if "cybercore-offline-mssql" in s:
    print("mssql install task already patched"); sys.exit(0)
block = '''  win_shell: |
    # cybercore-offline-mssql: install SQL from extracted media via setup.exe (no SSEI / no network)
    $ErrorActionPreference = "Stop"
    $base  = Join-Path (Join-Path $env:SystemDrive "setup") "mssql"
    $media = Join-Path (Join-Path $base "media") "SQLEXPR_x64_ENU.exe"
    $ex    = Join-Path $base "extracted"
    $setup = Join-Path $ex "setup.exe"
    $conf  = Join-Path $base "sql_conf.ini"
    if (-not (Test-Path $media)) { Write-Error ("no offline SQL media: " + $media); exit 1 }
    if (-not (Test-Path $setup)) { Start-Process -Wait -FilePath $media -ArgumentList "/q",("/x:" + $ex) }
    if (-not (Test-Path $setup)) { Write-Error "extraction produced no setup.exe"; exit 1 }
    $proc = Start-Process -Wait -PassThru -FilePath $setup -ArgumentList ("/configurationfile=" + $conf),"/IACCEPTSQLSERVERLICENSETERMS","/QUIET"
    Write-Output ("SETUP_EXIT=" + $proc.ExitCode)
    if ($proc.ExitCode -eq 3010) { exit 0 }
    exit $proc.ExitCode'''
pat = re.compile("^ *win_command:.*sql_installer.exe.*$", re.MULTILINE)
s2, n = pat.subn(block, s)
if n != 1:
    print("WARN: expected 1 sql_installer.exe win_command, found %d - NOT patching" % n); sys.exit(0)
open(P, "w").write(s2)
print("patched mssql install task -> offline setup.exe")
`;
    const b64 = Buffer.from(installPatchPy, "utf8").toString("base64");
    const { pid: installPatchPid } = await agentExecArgv(bestNode, controllerVmId,
      ['/bin/bash', '-c',
        `echo ${b64} | base64 -d > /tmp/cc-mssql-install.py && python3 /tmp/cc-mssql-install.py`],
      proxmoxAPI);
    await pollExecStatus(bestNode, controllerVmId, installPatchPid, 20000);
  } catch (err) {
    console.warn(`[GOAD] mssql install-command patch failed (non-fatal): ${err.message}`);
  }

  // Fire-and-forget — we don't care about this PID's status afterward.
  await agentExecArgv(bestNode, controllerVmId,
    ['/bin/bash', '-c', wrappedCmd],
    proxmoxAPI);

  // Helper: read a file via a fresh short-lived guest-exec.
  async function readFile(path, timeoutMs = 10000) {
    const { pid: p } = await agentExecArgv(bestNode, controllerVmId,
      ['/bin/sh', '-c', `[ -f ${path} ] && cat ${path} || echo __MISSING__`],
      proxmoxAPI);
    const r = await pollExecStatus(bestNode, controllerVmId, p, timeoutMs);
    return (r.stdout || '').trim();
  }

  // Poll the sentinel every 15s until it appears or we hit 2h.
  const deadlineMs = Date.now() + 2 * 60 * 60 * 1000;
  let exitcode = null;
  while (Date.now() < deadlineMs) {
    await sleep(15000);
    try {
      const content = await readFile(donePath);
      if (content && content !== '__MISSING__') {
        exitcode = parseInt(content, 10);
        if (Number.isNaN(exitcode)) {
          throw new Error(`Unexpected sentinel content in ${donePath}: ${content}`);
        }
        break;
      }
    } catch {
      // transient guest-exec failure — keep polling
    }
  }

  if (exitcode === null) {
    throw new Error(`GOAD playbook did not finish within 2h — log at ${logPath} on controller ${controllerVmId}`);
  }

  if (exitcode !== 0) {
    let logTail = '';
    try { logTail = await readFile(`__tail__ ${logPath}`, 10000); } catch {}
    if (!logTail || logTail === '__MISSING__') {
      try {
        const { pid: tp } = await agentExecArgv(bestNode, controllerVmId,
          ['/bin/sh', '-c', `tail -100 ${logPath}`], proxmoxAPI);
        const tr = await pollExecStatus(bestNode, controllerVmId, tp, 10000);
        logTail = tr.stdout || '';
      } catch {}
    }
    throw new Error(`GOAD playbook exit ${exitcode}\nlog tail:\n${logTail.slice(-2000)}`);
  }

  return { exited: true, exitcode: 0, stdout: '', stderr: '' };
}

/**
 * Stop the controller after the playbook finishes (or fails). Keeps the
 * provisioning credentials off any running box during student session.
 */
async function stopController({ controllerVmId, bestNode, proxmoxAPI, waitForTask }) {
  try {
    const task = await proxmoxAPI('POST', `/api2/json/nodes/${bestNode}/qemu/${controllerVmId}/status/stop`);
    if (task && waitForTask) await waitForTask(bestNode, task);
    return { stopped: true, error: null };
  } catch (err) {
    console.warn(`[GOAD] stopController: ${err.message}`);
    return { stopped: false, error: err.message };
  }
}

// ─── Generated labs: deliver the tree, then prove what it planted ───────────
/**
 * A GENERATED lab is one CIAB compiled for a client (ad/CIAB-<hash8>), not one
 * of the built-in trees baked into controller template 1700 by
 * infrastructure/proxmox-templates/vm-templates/bake-goad-controller-vm.sh.
 * Two things have to happen for a generated lab that a built-in lane must never
 * pay for, and both hang off spec.goad.generated_lab so they are OPT-IN:
 *
 *   DELIVERY  the tree must be at /opt/goad/ad/<LAB>/ before run.sh looks for
 *             it, because the controller has never seen it. A built-in lane
 *             must NOT take this path: its tree is already on the box from the
 *             bake, and re-pushing it would swap the reference lab every other
 *             lane runs for a copy assembled by a different program — with no
 *             undo, and nothing raised if the two ever disagreed by a byte.
 *
 *   PROOF     the chain's exit code carries almost no information. An audit of
 *             the pinned role library found 20 sites where a task reports
 *             SUCCESS and does nothing, three of them shipped vulnerabilities
 *             that are simply absent afterwards. So what a generated lab claims
 *             to plant is asserted against the machines once the chain is done.
 *
 * A spec without generated_lab therefore makes exactly the calls it made before
 * this section existed, in the same order, and never even loads the two plugin
 * modules below.
 */

/**
 * The real implementations this section injects.
 *
 * LAZY, and only reached on the generated-lab path: goad-lab-push and
 * goad-postcondition-probe live in the CIAB plugin, and requiring a plugin from
 * src/ at module scope would put clinic_db's neighbourhood in the load path of
 * every deployment, including ones with the plugin disabled. server.js reaches
 * into a plugin the same way, for the same reason, and defers it to the call.
 *
 * It is a factory rather than a frozen object so a test can assert that the
 * defaults really are the shipped functions — the one property an injected-deps
 * design otherwise loses, and the one that matters here, because "wired to
 * something" and "wired to the thing that does the work" look identical from
 * every other angle.
 */
function defaultGoadDeps() {
  /* eslint-disable global-require */
  const push     = require('../../modules/crucible/plugins/ciab/utils/goad-lab-push');
  const extPush  = require('../../modules/crucible/plugins/ciab/utils/goad-ext-config-push');
  const probe    = require('../../modules/crucible/plugins/ciab/utils/goad-postcondition-probe');
  const validate = require('../../modules/crucible/plugins/ciab/utils/goad-lab-validate');
  /* eslint-enable global-require */
  return {
    pushLabTree:           push.pushLabTree,
    // The extension half of the same delivery. A separate module because
    // pushLabTree swaps a whole DIRECTORY and aiming that at extensions/<key>/
    // would delete the ansible/, inventory and providers/ beside the config —
    // but it reuses that module's transport, so the two cannot drift on retry
    // semantics.
    pushExtensionConfig:   extPush.pushExtensionConfig,
    buildExpectationSet:   probe.buildExpectationSet,
    collectLabSecrets:     probe.collectLabSecrets,
    assertNoSecrets:       probe.assertNoSecrets,
    runPostconditionProbe: probe.runPostconditionProbe,
    parseLabConfig:        validate.parseLabConfig,
    runPlaybook:           runGoadPlaybook,
    sleep,
  };
}

/** deps, with the shipped implementation filled in for anything omitted. */
function withGoadDeps(deps) {
  return { ...defaultGoadDeps(), ...(deps || {}) };
}

/**
 * THE OPT-IN. Returns null for every spec that declares no generated lab tree —
 * which is every built-in GOAD lane — and a validated descriptor for one that
 * does. Throws only on a malformed descriptor, because each field below fails
 * QUIETLY when it is wrong and the cheapest place to find out is here.
 *
 * Shape:
 *   spec.goad.generated_lab = {
 *     name:  'CIAB-3f9a2c1b',                    // the ad/<LAB> directory
 *     files: { 'data/config.json': '…', 'data/inventory': '…', … },
 *     chain: ['build.yml', 'ad-parent_domain.yml', …],
 *     root?, runShPath?, perLabPlaybooks?, chunkSize?, force?
 *   }
 *
 * WHY name MUST EQUAL spec.goad.version. runGoadPlaybook hands run.sh the
 * labName resolveGoadLab produced — i.e. spec.goad.version — and run.sh resolves
 * both ad/<that>/ and that key in playbooks.yml from it. Pushing CIAB-3f9a2c1b
 * while running GOAD-Light raises nothing anywhere: the push succeeds, the
 * playbook succeeds, and the lane is a different lab from the one the students
 * were briefed on. So the two names are reconciled here, loudly, before either
 * has run. Defaulting the name to labName would be worse than requiring it —
 * an unset version defaults to a BUILT-IN, and pushLabTree's refusal of
 * reserved names would be the only thing between a generator and ad/GOAD-Light.
 */
function resolveGeneratedLab(spec) {
  const gen = (spec && spec.goad) ? spec.goad.generated_lab : null;
  if (gen === undefined || gen === null || gen === false) return null;
  if (typeof gen !== 'object' || Array.isArray(gen)) {
    throw new Error(
      'spec.goad.generated_lab must be an object { name, files, chain } (or absent, for a lab the '
      + 'controller template already carries).');
  }

  const { labName } = resolveGoadLab(spec);
  const name = typeof gen.name === 'string' ? gen.name.trim() : '';
  if (!name) {
    throw new Error(
      'spec.goad.generated_lab.name is required — it is the ad/<LAB> directory the tree installs '
      + 'into and the playbooks.yml key run.sh resolves the chain from. It is deliberately not '
      + `defaulted: an unset spec.goad.version resolves to the built-in '${DEFAULT_LAB}', so a `
      + 'default here would aim a generated tree at a reference lab.');
  }
  if (name !== labName) {
    throw new Error(
      `spec.goad.generated_lab.name is '${name}' but this deploy runs lab '${labName}' `
      + '(spec.goad.version, which is what runGoadPlaybook passes to run.sh). The tree would be '
      + `delivered to a directory nothing executes and the lane would provision as '${labName}' `
      + `without a word. Set spec.goad.version = '${name}'.`);
  }

  const files = gen.files;
  const noFiles = !files
    || (Array.isArray(files) ? files.length === 0
      : (typeof files !== 'object' || Object.keys(files).length === 0));
  if (noFiles) {
    throw new Error(
      `spec.goad.generated_lab.files is empty for '${name}'. A lab is data/config.json plus `
      + 'data/inventory; pushing nothing would stage an empty directory and run.sh would stop at '
      + '"Lab not found" — after the whole lane had already been built.');
  }
  if (!Array.isArray(gen.chain) || gen.chain.length === 0) {
    throw new Error(
      `spec.goad.generated_lab.chain is required for '${name}'. A lab with no chain of its own falls `
      + 'through to playbooks.yml\'s `default:` key, which is the FULL 16-playbook GOAD chain — child '
      + 'domain, trusts, gmsa, laps, wait5m — run against empty inventory groups. That does not fail '
      + 'fast; it fails 15-25 minutes in, on reciprocal data it cannot make consistent.');
  }

  // The rewritten extension configs, keyed by extension. Absent on every CiAB
  // engagement and on every lab that is not renamed, which is why a missing key
  // is silence rather than a refusal. They are validated here — the same place
  // the tree is — because each one is delivered by the SAME step, and a malformed
  // entry found at push time is found on a live lane.
  const extRaw = gen.extension_configs;
  const extensionConfigs = {};
  if (extRaw !== undefined && extRaw !== null) {
    if (typeof extRaw !== 'object' || Array.isArray(extRaw)) {
      throw new Error(
        `spec.goad.generated_lab.extension_configs for '${name}' must be an object keyed by `
        + 'extension (e.g. { ws01: "{…}" }).');
    }
    for (const key of Object.keys(extRaw)) {
      const content = extRaw[key];
      if (typeof content !== 'string' || content.trim() === '') {
        throw new Error(
          `spec.goad.generated_lab.extension_configs.${key} for '${name}' must be the rewritten `
          + "config as a STRING. It is compiled at deploy and never persisted, so an empty or "
          + 'non-string value here means the transform produced nothing for an extension it was '
          + "asked about — and the extension's config would still name the stock forest root.");
      }
      extensionConfigs[key] = content;
    }
  }

  return {
    name,
    files,
    chain: gen.chain,
    extensionConfigs,
    root: gen.root,
    runShPath: gen.runShPath,
    perLabPlaybooks: gen.perLabPlaybooks,
    chunkSize: gen.chunkSize,
    force: gen.force === true,
  };
}

/** Compile the identity plan using the GOAD fork already on the controller. */
async function deliverControllerRename({ controllerVmId, bestNode, spec, proxmoxAPI, deps = {} }) {
  const plan = spec?.goad?.rename_plan;
  if (!plan) return null;
  if (plan.lab_name !== spec.goad.version || plan.base_lab !== spec.goad.lab?.baseLab) {
    throw new Error('GOAD rename plan does not match the selected lab identity');
  }
  // Only the identity plan crosses this boundary. The pinned GOAD fork and its
  // compiler already live on the controller; the application never reads them.
  const bootstrap = `import base64, json, os, subprocess, sys, tempfile
from pathlib import Path
helper = Path('/opt/goad/scripts/cybercore-rebrand.py')
if not helper.is_file():
    raise SystemExit('GOAD controller lacks scripts/cybercore-rebrand.py. Refresh or re-bake template 1700 from the pinned CyberCore GOAD fork before deploying a renamed forest.')
fd, filename = tempfile.mkstemp(prefix='cybercore-rename-', suffix='.json')
try:
    with os.fdopen(fd, 'wb') as output:
        output.write(base64.b64decode(sys.argv[1]))
    result = subprocess.run([sys.executable, str(helper), '--goad-root', '/opt/goad', '--plan', filename])
    code = result.returncode
finally:
    os.unlink(filename)
sys.exit(code)
`;
  const { pid } = await agentExecArgv(bestNode, controllerVmId,
    ['/usr/bin/python3', '-c', bootstrap, Buffer.from(JSON.stringify(plan)).toString('base64')], proxmoxAPI);
  const result = await (deps.pollExecStatus || pollExecStatus)(bestNode, controllerVmId, pid, 180000);
  const output = String(result?.['out-data'] ?? result?.outData ?? result?.stdout ?? '').trim();
  let report = null;
  try { report = JSON.parse(output); } catch (_) { /* failed helpers may only write stderr */ }
  if (!result?.exited || result.exitcode !== 0 || report?.ok === false) {
    const error = new Error(report?.error || String(result?.['err-data'] ?? result?.stderr ?? 'Controller forest rename did not complete').slice(-2000));
    error.goadDelivery = { lab: plan.lab_name, ...(report?.delivery || { failedStep: 'controller_rename' }) };
    throw error;
  }
  if (report?.lab !== plan.lab_name || !/^[a-f0-9]{64}$/i.test(report?.treeSha256 || '')) {
    const error = new Error('Controller forest rename returned an invalid identity or content hash');
    error.goadDelivery = { lab: plan.lab_name, failedStep: 'rename_report' };
    throw error;
  }
  for (const key of resolveGoadLab(spec).extensions.selected) {
    if (getExtension(key).shipsLabConfig !== true) continue;
    if (!/^[a-f0-9]{64}$/i.test(report.extensionConfigs?.[key]?.sha256 || '')) {
      const error = new Error(`Controller forest rename did not confirm rewritten config for ${key}`);
      error.goadDelivery = { ...report, failedStep: `extension_report:${key}` };
      throw error;
    }
  }
  if (!['per-lab', 'per-lab+shared'].includes(report.chainMode)
    || !Array.isArray(report.chain) || report.chain.length === 0
    || report.chain.some(play => typeof play !== 'string' || !/^[A-Za-z0-9_-]+\.ya?ml$/.test(play))) {
    const error = new Error('Controller forest rename did not confirm a valid lab playbook chain');
    error.goadDelivery = { ...report, failedStep: 'rename_chain' };
    throw error;
  }
  const expected = plan.expected_identities;
  if (!Array.isArray(expected) || !Array.isArray(report.identities)
    || report.identities.length !== expected.length
    || new Set(report.identities.map(host => String(host?.name).toLowerCase())).size !== expected.length) {
    const error = new Error('Controller forest rename returned an incomplete host roster');
    error.goadDelivery = { ...report, failedStep: 'rename_identity' };
    throw error;
  }
  for (const identity of expected) {
    const actual = report.identities?.find(host => String(host.name).toLowerCase() === identity.name.toLowerCase());
    if (!actual || String(actual.hostname).toLowerCase() !== identity.hostname.toLowerCase()
      || String(actual.domain).toLowerCase() !== identity.domain.toLowerCase()) {
      const error = new Error(`Controller forest rename disagrees with planned identity for ${identity.name}`);
      error.goadDelivery = { ...report, failedStep: 'rename_identity' };
      throw error;
    }
  }
  return report;
}

/** Deliver a separately generated CiAB tree before any Windows provisioning. */
async function deliverGeneratedLab({ controllerVmId, bestNode, spec, deps }) {
  const gen = resolveGeneratedLab(spec);
  if (!gen) return null;

  const d = withGoadDeps(deps);
  console.log(`[GOAD] Delivering generated lab ${gen.name} to controller ${controllerVmId}`);

  const opts = {
    node: bestNode,
    vmId: controllerVmId,
    lab: gen.name,
    files: gen.files,
    chain: gen.chain,
    force: gen.force,
    deps: { agentShellExec, pollExecStatus },
  };
  // Only forward the optional knobs the spec actually set: pushLabTree defaults
  // each of them, and an explicit `undefined` would override the default with
  // nothing on the ones it reads with `||`.
  if (gen.root) opts.root = gen.root;
  if (gen.runShPath) opts.runShPath = gen.runShPath;
  if (gen.perLabPlaybooks !== undefined) opts.perLabPlaybooks = gen.perLabPlaybooks;
  if (gen.chunkSize) opts.chunkSize = gen.chunkSize;

  let result;
  try {
    result = await d.pushLabTree(opts);
  } catch (error) {
    error.goadDelivery = { lab: gen.name, failedStep: 'lab_tree' };
    throw error;
  }
  console.log(`[GOAD] ${gen.name}: ${result.skipped ? 'already at' : 'installed'} `
    + `${String(result.treeSha256).slice(0, 12)} (${result.chainMode} chain)`);

  // ── THE EXTENSION CONFIGS, IN THIS STEP, AFTER THE TREE ───────────────────
  //
  // ORDER IS LOAD-BEARING TWICE OVER. The tree goes first because an extension
  // config is a FUNCTION OF the renamed main config — install.yml joins
  // lab_extension to lab by domain name — so the pair must never be half
  // installed with the halves computed from different specs. And they belong in
  // this step, not a later one, because a later step is reachable with a
  // different spec, and that disagreement is the bug this whole path fixes,
  // arrived at by another route.
  //
  // ONLY THE SELECTED EXTENSIONS. The compiled tree carries a rewritten config
  // for every extension we have vendored, because computing them all from one
  // transform is what makes them agree; pushing one for an extension this lane
  // never ticked would spend ~21s rewriting a file no play will read, and would
  // fail the lane if the controller image happened not to carry that extension.
  const extConfigs = gen.extensionConfigs || {};
  const wanted = Object.keys(extConfigs).sort();
  let extensionsPushed = null;
  if (wanted.length) {
    const selected = new Set(resolveGoadLab(spec).extensions.selected);
    for (const key of wanted) {
      if (!selected.has(key)) continue;
      // Deliberately NOT caught, exactly like the tree push above: an extension
      // whose config never arrived still names the stock forest root, so its
      // domain join fails against a forest that no longer has that domain —
      // 40 minutes later, as an ansible error naming a variable.
      let pushed;
      try {
        pushed = await d.pushExtensionConfig({
        node:      bestNode,
        vmId:      controllerVmId,
        key,
        content:   extConfigs[key],
        // The same flag the tree took. Two meanings for one word across the two
        // halves of one delivery is how a "forced" redeploy comes to refresh the
        // lab and skip the extension.
        force:     gen.force,
        ...(gen.root ? { root: gen.root } : {}),
        ...(gen.chunkSize ? { chunkSize: gen.chunkSize } : {}),
        deps: { agentShellExec, pollExecStatus },
      });
      } catch (error) {
        error.goadDelivery = { ...result, extensionConfigs: extensionsPushed || {}, failedStep: `extension:${key}` };
        throw error;
      }
      console.log(`[GOAD] ${gen.name}: ${key} config `
        + `${pushed.skipped ? 'already at' : 'installed'} ${String(pushed.sha256).slice(0, 12)}`);
      extensionsPushed = extensionsPushed || {};
      extensionsPushed[key] = {
        sha256: pushed.sha256, skipped: pushed.skipped === true, dest: pushed.dest,
      };
    }
  }
  // pushLabTree's own result is returned UNTOUCHED when nothing else was
  // delivered, so every CiAB lane — and every offline test that asserts on it —
  // sees exactly the object it saw before extension configs existed.
  return extensionsPushed ? { ...result, extensionConfigs: extensionsPushed } : result;
}

/**
 * The probe's options block, or null when this lane is not to be probed.
 * `spec.goad.probe === false` is the explicit opt-out; anything else yields an
 * options object (possibly empty) and the decision then rests on whether there
 * is a lab to grade.
 */
function probeOptionsFor(spec) {
  const p = (spec && spec.goad) ? spec.goad.probe : undefined;
  if (p === false) return null;
  return (p && typeof p === 'object' && !Array.isArray(p)) ? p : {};
}

/**
 * WHERE the lab config the probe grades against comes from, or null when there
 * is nothing to grade. Two sources, in precedence order:
 *
 *   spec.goad.probe.lab             an already-parsed inner lab object, for a
 *                                   caller that has one in hand
 *   generated_lab data/config.json  the normal case — the probe grades exactly
 *                                   the lab that was just delivered
 *
 * A built-in GOAD lane hits neither and returns null, which is what keeps it as
 * it was: no probe, no fifteen-minute wait, no new failure mode. Not probing
 * the built-ins is a decision, not a gap — their content is fixed, upstream,
 * and pinned by the controller-template contract tests.
 */
function probeConfigSource(spec) {
  const opts = probeOptionsFor(spec);
  if (!opts) return null;
  if (opts.lab && typeof opts.lab === 'object' && !Array.isArray(opts.lab)) {
    return { opts, lab: opts.lab, text: null, source: 'spec.goad.probe.lab' };
  }
  const gen = resolveGeneratedLab(spec);
  if (!gen) return null;
  const raw = Array.isArray(gen.files)
    ? ((gen.files.find(f => f && f.path === 'data/config.json') || {}).content)
    : gen.files['data/config.json'];
  if (raw === undefined || raw === null) return null;
  return {
    opts,
    lab: null,
    text: typeof raw === 'string' ? raw : String(raw),
    source: `${gen.name}/data/config.json`,
  };
}

/**
 * Is a probe EXPECTED on this lane? Answered without parsing anything and
 * without loading the plugin modules, because deployGoadLane needs it on the
 * path where the playbook failed and there is nothing to parse. It is the
 * difference between 'not probed' and 'nothing to probe', and those two must
 * never write the same lane row.
 */
function laneWantsProbe(spec) {
  try { return probeConfigSource(spec) !== null; } catch (_) { return false; }
}

/** The parsed lab, or null. Only this one loads the validator. */
function resolveProbeLab(spec, d) {
  const src = probeConfigSource(spec);
  if (!src) return null;
  if (src.lab) return { lab: src.lab, opts: src.opts };
  const { lab } = d.parseLabConfig(src.text, { source: src.source });
  return { lab, opts: src.opts };
}

/**
 * The two credentials the probe needs, taken from the lab itself.
 *
 *   become    the identity each check runs AS on the target. GOAD's inventory
 *             connects as `vagrant`, a LOCAL admin, which cannot read the
 *             directory facts most checks are about — so the probe becomes
 *             `administrator` with the domain password out of the lab config.
 *             The playbook carries ONE become credential for the whole run, so
 *             a lab whose domains use different admin passwords reports the
 *             other domain's hosts as errored rather than as absent. That is
 *             visible in the report, which is the point; pin it with
 *             become_password if a lab ever needs it.
 *
 *   per-ref   only when verify_credentials is on. buildExpectationSet emits a
 *             credential_ref for each check that must ACT as a principal ("can
 *             this user really read that share?"), and the .ps1 looks the
 *             credential up by that exact string. A ref with no entry reports
 *             INCONCLUSIVE, which parseProbeResult grades as a FAILURE — a
 *             missing password must never read as "absent, as intended".
 *
 * Everything returned here is a secret and leaves this process only as
 * runPostconditionProbe options. See runLaneVerification for the route.
 */
function resolveProbeCredentials(lab, opts, expectationSet) {
  const domains = (lab && lab.domains) ? lab.domains : {};
  // Forest root = fewest labels, ties broken alphabetically. GOAD's config.json
  // carries no forest_root flag, and its child domains are always a sub-label of
  // the parent (north.sevenkingdoms.local under sevenkingdoms.local), so this
  // picks the root on every shipped lab and is at least DETERMINISTIC on any
  // other — key order is not, and a become account that changed between two runs
  // of the same lab would be the worst kind of flake.
  const rootName = Object.keys(domains).sort((a, b) => {
    const byDepth = a.split('.').length - b.split('.').length;
    return byDepth !== 0 ? byDepth : a.localeCompare(b);
  })[0] || null;
  const root = rootName ? (domains[rootName] || {}) : {};

  const becomeUser = opts.become_user || 'administrator';
  const becomePassword = opts.become_password || root.domain_password || '';

  const credentials = {};
  for (const ref of (expectationSet.credential_refs || [])) {
    const supplied = opts.credentials ? opts.credentials[ref] : null;
    if (supplied && supplied.password) { credentials[ref] = supplied; continue; }
    // The refs buildExpectationSet derives from domain users are spelled
    // `domain\sam`; the ones it takes verbatim from vulns_vars are whatever the
    // lab author wrote. Only the first kind can be resolved from the config, and
    // a ref left unresolved reports inconclusive rather than being quietly
    // dropped — so there is deliberately no fallback here.
    const at = String(ref).indexOf('\\');
    if (at === -1) continue;
    const user = ((domains[String(ref).slice(0, at)] || {}).users || {})[String(ref).slice(at + 1)];
    if (user && user.password) credentials[ref] = { username: ref, password: user.password };
  }
  return {
    becomeUser,
    becomePassword,
    credentials: Object.keys(credentials).length > 0 ? credentials : null,
  };
}

/**
 * Run the post-condition probe and RETURN its report. IT NEVER THROWS.
 *
 * TWO RULES, both load-bearing:
 *
 * 1. THE REPORT IS DATA AT THIS LAYER, NOT A GATE. A failing probe does not
 *    fail the deploy. If it did, a lane that is genuinely broken and a probe
 *    that could not answer would produce the identical outcome — and the probe
 *    exists precisely because that ambiguity is what makes a green GOAD run
 *    meaningless. Deciding what a report MEANS belongs to the bake
 *    orchestrator's verify phase, which can tell the three cases apart
 *    (`passed: true` / `passed: false` / `passed: null`, the last being "the
 *    probe itself could not answer"). A student lane just records it.
 *
 * 2. THE CREDENTIALS NEVER TOUCH ARGV OR A WORLD-TRAVERSABLE PATH. They go in
 *    as runPostconditionProbe OPTIONS, which writes them to a 0600 file under
 *    /var/lib/goad-run/probe (root-only, umask 077 before the redirect) and
 *    hands them to the guest as win_powershell `parameters:` under no_log —
 *    never script_args, which script-executor.js interpolates UNQUOTED, and
 *    never C:\Windows\Temp, which Users can traverse. What DOES land in
 *    C:\Windows\Temp is the expectation set, so collectLabSecrets +
 *    assertNoSecrets run HERE, before the set can leave this process. The probe
 *    module asserts it again internally; being checked twice is the design and
 *    not a redundancy — this call site is the one that holds the lab.
 *
 * @returns {Promise<{ran:boolean, reason:?string, passed:?boolean, error:?string, report:?object}>}
 */
async function runLaneVerification({ controllerVmId, bestNode, spec, proxmoxAPI, deps }) {
  // `applicable` is what stops 'this lane has no probe' and 'the probe did not
  // answer' from writing the same row: only the second is worth recording, and
  // only the second is a refusal upstream.
  const notRun = (reason, error, applicable) => ({
    ran: false, applicable: applicable !== false, reason: reason || null,
    passed: null, error: error || null, report: null,
  });

  const opts = probeOptionsFor(spec);
  if (!opts) {
    return notRun('the spec opted out of post-condition probing (spec.goad.probe === false)', null, false);
  }

  let d;
  let resolved;
  try {
    // Nothing above this line loads the plugin modules, so a lane with no probe
    // target reaches the return below having done exactly what it always did.
    d = withGoadDeps(deps);
    resolved = resolveProbeLab(spec, d);
  } catch (err) {
    return notRun(null, `could not resolve a lab to probe: ${err.message}`);
  }
  if (!resolved) {
    return notRun('this lane runs a lab the controller template already carries, and the spec names no probe target', null, false);
  }

  try {
    const { labName } = resolveGoadLab(spec);
    const expectationSet = d.buildExpectationSet(resolved.lab, {
      labName,
      negatives: opts.negatives !== false,
      verifyCredentials: opts.verify_credentials === true,
      extra: Array.isArray(opts.extra) ? opts.extra : [],
    });

    // Rule 2, at the last point this process controls.
    const secrets = d.collectLabSecrets(resolved.lab);
    d.assertNoSecrets(expectationSet, secrets);

    const cred = resolveProbeCredentials(resolved.lab, opts, expectationSet);

    console.log(`[GOAD] Probing ${expectationSet.checks.length} post-condition(s) for ${labName}`);
    const report = await d.runPostconditionProbe({
      controllerVmId,
      bestNode,
      proxmoxAPI,
      labName,
      expectationSet,
      credentials: cred.credentials,
      becomeUser: cred.becomeUser,
      becomePassword: cred.becomePassword,
      // The needle list, so the module's own guard is armed rather than nominal.
      secrets,
      // undefined keeps runPostconditionProbe's own 15-minute default.
      timeoutMs: Number(opts.timeout_ms) > 0 ? Number(opts.timeout_ms) : undefined,
      // The three impure helpers the probe deliberately does not require of its
      // own accord: it takes THIS module's, which is what makes the probe travel
      // the same guest-agent path the playbook did.
      sleep: d.sleep,
      agentExecArgv,
      pollExecStatus,
    });

    const passed = report.passed === true;
    console.log(`[GOAD] Post-condition probe ${passed ? 'passed' : 'FAILED'}: `
      + `${report.summary.ok}/${report.summary.total} ok, ${report.summary.failed} failed, `
      + `${report.summary.inconclusive} inconclusive`);
    return { ran: true, applicable: true, reason: null, passed, error: null, report };
  } catch (err) {
    // Rule 1: a probe that broke is recorded as a probe that broke. Rethrowing
    // would make it indistinguishable from a lab that is missing its vulns.
    console.warn(`[GOAD] Post-condition probe could not run: ${err.message}`);
    return notRun(null, err.message);
  }
}

/**
 * The compact form that goes on the LANE row. A full report can carry hundreds
 * of checks and the lane config is polled by the admin UI, so the row gets the
 * verdict plus the failing ids while the caller gets the whole document to put
 * somewhere sized for it (the bake's verify_report jsonb).
 */
function summariseVerification(v) {
  if (!v) return null;
  const report = v.report;
  return {
    ran: v.ran,
    passed: v.passed,
    reason: v.reason,
    error: v.error,
    summary: report ? report.summary : null,
    errors: report ? report.errors : [],
    failed_checks: report ? report.checks.filter(c => !c.ok).map(c => c.id).slice(0, 50) : [],
  };
}

/** Windows identities a successful controller build must produce. */
function goadIdentityExpectations(spec) {
  if (spec?.goad?.rename_forest !== true) return null;
  const plan = spec.goad.rename_plan;
  if (plan) {
    const { labDef } = resolveGoadLab(spec);
    if (plan.lab_name !== spec.goad.version || plan.base_lab !== spec.goad.lab?.baseLab) {
      throw new Error('GOAD rename plan does not match the selected lab identity');
    }
    return labDef.vms.filter(vm => vm.role !== 'linux').map(vm => {
      const identity = plan.expected_identities?.find(host => String(host.name).toLowerCase() === vm.name.toLowerCase());
      if (!identity?.hostname || !identity?.domain || !spec.goad.lab.domains.includes(identity.domain)) {
        throw new Error(`GOAD rename plan has no valid hostname/domain for ${vm.name}`);
      }
      return { name: vm.name, hostname: identity.hostname, domain: identity.domain };
    });
  }
  throw new Error('A renamed GOAD lab requires its validated identity plan');
}

/** Read Windows identity through the guest agent without provisioning credentials. */
async function verifyGoadIdentities({ spec, deployedVMs, proxmoxAPI, deps = {} }) {
  const expected = goadIdentityExpectations(spec);
  if (!expected) return { applicable: false, passed: null, checks: [] };
  const report = { applicable: true, passed: true, checks: [] };
  const poll = deps.pollExecStatus || pollExecStatus;
  const pause = deps.sleep || sleep;
  const command = "$ErrorActionPreference='Stop'; $c=Get-CimInstance Win32_ComputerSystem; "
    + "@{hostname=$c.Name;domain=$c.Domain;joined=[bool]$c.PartOfDomain}|ConvertTo-Json -Compress";
  for (const identity of expected) {
    const check = { name: identity.name, expected: { hostname: identity.hostname, domain: identity.domain }, observed: null, ok: false };
    const vm = (deployedVMs || []).find(candidate => candidate.type === 'qemu'
      && String(candidate.name).toLowerCase() === identity.name.toLowerCase());
    if (!vm) {
      check.error = 'Windows VM is missing from the deployment inventory';
    } else {
      for (let attempt = 0; attempt < 3; attempt++) {
        try {
          const { pid } = await agentExecArgv(vm.node, vm.vm_id,
            ['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', command], proxmoxAPI);
          const result = await poll(vm.node, vm.vm_id, pid, 60000);
          if (!result?.exited || result.exitcode !== 0) throw new Error('Windows identity query did not complete successfully');
          const raw = result['out-data'] ?? result.outData ?? result.stdout ?? '';
          const observed = JSON.parse(String(raw).trim());
          // Store only these facts, never an arbitrary guest-agent response.
          check.observed = { hostname: String(observed.hostname || ''), domain: String(observed.domain || ''), joined: observed.joined === true };
          check.ok = check.observed.joined
            && check.observed.hostname.toLowerCase() === identity.hostname.toLowerCase()
            && check.observed.domain.toLowerCase() === identity.domain.toLowerCase();
          if (!check.ok) check.error = 'Windows hostname or domain membership does not match the compiled lab';
          break;
        } catch (_) {
          check.error = 'Could not read Windows identity through the guest agent';
          if (attempt < 2) await pause(5000);
        }
      }
    }
    if (!check.ok) report.passed = false;
    report.checks.push(check);
  }
  if (!report.passed) {
    const error = new Error(`GOAD identity verification failed: ${report.checks.filter(check => !check.ok).map(check => check.name).join(', ')}`);
    error.goadIdentityVerification = report;
    throw error;
  }
  return report;
}

/** Provision already-cloned lane VMs and retain cleanup ownership on failure. */
async function deployGoadLane({
  lane, spec, module, vnet, vxlanId, gatewayVmId, bestNode, templateNode,
  laneSubnetBase, extSubnetBase, deployedVMs, proxmoxAPI, waitForTask, query,
  // Optional, and empty on every production call: the generated-lab push,
  // the post-condition probe and the playbook itself, so the ORDER they run
  // in is assertable offline. Defaults are the shipped implementations —
  // see defaultGoadDeps().
  deps = {}
}) {
  if (!spec?.goad?.enabled) return null;
  if (!laneSubnetBase) {
    throw new Error('deployGoadLane: laneSubnetBase is required (admin.js passes the lane subnet — net.lan.base3 for v1/v2, net.lanInt.base3 for v3 segmented lanes)');
  }

  // Entry points plan before allocating. This also protects direct callers,
  // and accepts the same in-memory plan without minting it again.
  spec = prepareGoadDeploymentSpec(spec);

  const { labName, labDef } = resolveGoadLab(spec);
  console.log(`[GOAD] Starting ${labName} provisioning for lane ${lane.lane_id} (vxlan ${vxlanId}, subnet ${laneSubnetBase}.0/24)`);

  // Record clone intent before calling Proxmox: a timed-out clone can exist.
  const controllerVmId = 200000 + vxlanId;
  const runtime = {
    waitForGuestAgent: deps.waitForGuestAgent || waitForGuestAgent,
    pollExecStatus: deps.pollExecStatus || pollExecStatus,
    waitForWinRM: deps.waitForWinRM || waitForWinRM,
    sleep: deps.sleep || sleep,
  };
  let stage = 'controller_clone';
  let delivery = null;
  let playbookResult;
  let verification = null;
  let identityVerification = null;
  let provisioningError = null;
  let controllerStop = null;
  try {
    // 1. Deploy controller (QEMU VM with qemu-guest-agent)
    await deployController({
      vxlanId, vnetName: vnet.vnet, bestNode, templateNode, lane, module, laneSubnetBase, proxmoxAPI, waitForTask
    });
    console.log(`[GOAD] Controller deployed: VMID ${controllerVmId}`);

    // Wait for the controller's qemu-guest-agent to be ready before we try
    // to exec anything inside it. Cloud-init bake in the template installs
    // the agent and starts it on boot, but it takes ~30-60s post-power-on.
    console.log(`[GOAD] Waiting for controller guest agent...`);
    stage = 'controller_agent';
    const agentReady = await runtime.waitForGuestAgent(bestNode, controllerVmId, 180000);
    if (!agentReady) {
      throw new Error(`Controller VM ${controllerVmId} guest agent never came up within 3 min`);
    }

    // Compile on the controller before DHCP changes or Windows provisioning.
    // CiAB's independently generated trees retain their separate delivery path.
    stage = 'delivery';
    delivery = await deliverControllerRename({ controllerVmId, bestNode, spec, proxmoxAPI, deps })
      || await deliverGeneratedLab({ controllerVmId, bestNode, spec, deps });

    // 2. Run prep.sh on the controller — writes DHCP reservations on the gateway
    //    BEFORE the Windows VMs renew DHCP. Without this, Windows VMs sit on
    //    whatever dynamic IPs they happened to grab at boot, and waitForWinRM
    //    polls the wrong addresses.
    stage = 'dhcp';
    const macs = prepareGoadMacs(spec, vxlanId, laneSubnetBase);
    const hostMap = buildGoadHostMap(spec, vxlanId, laneSubnetBase, extSubnetBase);

    console.log(`[GOAD] Writing DHCP reservations on gateway via prep.sh...`);
    const { pid: prepPid } = await agentExecArgv(bestNode, controllerVmId,
      ['/opt/goad-light/prep.sh', hostMap],
      proxmoxAPI);
    const prepResult = await runtime.pollExecStatus(bestNode, controllerVmId, prepPid, 60000);
    if (!prepResult.exited || prepResult.exitcode !== 0) {
      throw new Error(`prep.sh failed (exit ${prepResult.exitcode}): ${prepResult.stderr || prepResult.stdout}`);
    }
    console.log(`[GOAD] prep.sh complete — reservations active on gateway`);

    // 3. Restart Windows VMs so they DHCP fresh and pick up the reserved IPs.
    //    They were started by admin.js earlier (before reservations existed),
    //    so they're sitting on dynamic IPs — a stop/start fixes that.
    const winVMs = (deployedVMs || []).filter(v => {
      if (v.type !== 'qemu') return false;
      const labVm = labDef.vms.find(lv => lv.name.toLowerCase() === String(v.name).toLowerCase());
      return labVm && labVm.role !== 'linux';
    });
    if (winVMs.length > 0) {
      console.log(`[GOAD] Restarting ${winVMs.length} Windows VM(s) to renew DHCP onto reserved IPs...`);
      for (const vm of winVMs) {
        try {
          await proxmoxAPI('POST', `/api2/json/nodes/${vm.node}/qemu/${vm.vm_id}/status/stop`);
        } catch (err) {
          console.warn(`[GOAD] stop ${vm.vm_id} (${vm.name}): ${err.message}`);
        }
      }
      await runtime.sleep(8000);  // let Proxmox finalize the stops
      for (const vm of winVMs) {
        await proxmoxAPI('POST', `/api2/json/nodes/${vm.node}/qemu/${vm.vm_id}/status/start`);
      }
      console.log(`[GOAD] Windows VMs restarted; waiting 60s for fresh boot + DHCP...`);
      await runtime.sleep(60000);
    }

    // 4. Wait for WinRM on every Windows VM in this lab (skip Linux)
    const winrmIPs = labDef.vms
      .filter(v => v.role !== 'linux')                  // Linux VMs don't run WinRM
      .map(v => macs[v.name]?.static_ip)
      .filter(Boolean);
    if (winrmIPs.length > 0) {
      stage = 'winrm';
      await runtime.waitForWinRM({ controllerVmId, bestNode, vmIPs: winrmIPs, proxmoxAPI });
      console.log(`[GOAD] WinRM up on ${winrmIPs.length} Windows VM(s)`);
    }

    // 3b. SEED THE BOOTSTRAP ACCOUNT ON EVERY WINDOWS VM, OVER THE GUEST AGENT.
    //
    //     run.sh's first act is to find a WinRM account that works. On a lane
    //     built only from template 1004 it always does, because that template
    //     bakes vagrant/vagrant. Template 1006 (Windows 11, the ws01 extension
    //     machine) bakes NOTHING USABLE:
    //
    //       Administrator   Enabled False   -- sysprep /generalize /oobe disables
    //                                          it, which is the whole reason 1004
    //                                          bakes a second account
    //       cactus-user     Enabled True    -- the packer BUILD account. Its
    //                                          password is reset at first boot by
    //                                          cloudbase-init with
    //                                          inject_user_password=true, and a
    //                                          GOAD spec VM is cloned WITHOUT
    //                                          ciuser/cipassword (see
    //                                          challenge-lane-deployer.js:372 --
    //                                          only cloneExtraWorkstation sets
    //                                          them), so nothing is injected and
    //                                          the password is random.
    //
    //     So the only enabled account on ws01 has a password nobody holds, not
    //     even us. Observed on a real lane: run.sh tried all four candidates for
    //     600s and refused, correctly, with "dc01: vagrant" resolved beside it.
    //
    //     THE CYCLE THIS BREAKS. preflight-vagrant.yml creates exactly the account
    //     we need -- but it is an ansible play, so it needs WinRM auth to get in,
    //     which is the thing that does not exist. The guest agent needs no
    //     credentials at all, and it demonstrably works on these hosts: the vuln
    //     script path writes 180KB+ to ws01 through it on this very deploy.
    //
    //     BEST-EFFORT, NOT A GATE. On a 1004 host this is a no-op (vagrant is
    //     already there), so a failure here must not fail a lane that would
    //     otherwise work. run.sh's per-host probe is the real gate and it names
    //     the host it could not open -- a far better error than anything this
    //     could throw.
    //
    //     ORDER: after the DHCP restart and waitForWinRM, so the VM is settled and
    //     the guest agent is answering; before run.sh, which is what needs it.
    if (winVMs.length > 0) {
      console.log(`[GOAD] Seeding bootstrap account on ${winVMs.length} Windows VM(s)...`);
      for (const vm of winVMs) {
        try {
          const { pid } = await agentExecArgv(vm.node, vm.vm_id,
            ['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', GOAD_BOOTSTRAP_ACCOUNT_PS],
            proxmoxAPI);
          const r = await runtime.pollExecStatus(vm.node, vm.vm_id, pid, 120000);
          const out = String(r?.['out-data'] ?? r?.outData ?? '').trim();
          if (r?.exited && r.exitcode === 0) {
            console.log(`[GOAD]   ${vm.name}: ${out || 'seeded'}`);
          } else {
            console.warn(`[GOAD]   ${vm.name}: bootstrap seed exit ${r?.exitcode} — ${out || r?.stderr || 'no output'}`);
          }
        } catch (err) {
          // A domain CONTROLLER has no local SAM once promoted, so Get-LocalUser
          // throws there. That is fine and expected on a re-run against a built
          // lane: the account already exists in the domain and run.sh's probe
          // will find it.
          console.warn(`[GOAD]   ${vm.name}: bootstrap seed failed — ${err.message}`);
        }
      }
    }

    stage = 'playbook';
    const runPlaybook = deps.runPlaybook || runGoadPlaybook;
    playbookResult = await runPlaybook({ controllerVmId, bestNode, spec, vxlanId, laneSubnetBase, extSubnetBase, proxmoxAPI });
    console.log(`[GOAD] Playbook completed for lane ${lane.lane_id}`);

    stage = 'identity_verification';
    identityVerification = await verifyGoadIdentities({ spec, deployedVMs, proxmoxAPI, deps: runtime });
    stage = 'verification';
    verification = await runLaneVerification({ controllerVmId, bestNode, spec, proxmoxAPI, deps });
    stage = 'complete';
  } catch (error) {
    provisioningError = error instanceof Error ? error : new Error(String(error));
    delivery = error.goadDelivery || delivery;
    identityVerification = error.goadIdentityVerification || identityVerification;
    verification = verification || {
      ran: false, applicable: laneWantsProbe(spec), passed: null, error: null, report: null,
      reason: stage === 'playbook'
        ? `the playbook failed, so there is no finished forest to grade: ${provisioningError.message}`
        : `provisioning failed during ${stage}: ${provisioningError.message}`,
    };
    console.error(`[GOAD] Lane ${lane.lane_id} failed during ${stage}: ${provisioningError.message}`);
  } finally {
    controllerStop = await stopController({ controllerVmId, bestNode, proxmoxAPI, waitForTask });
    if (!controllerStop.stopped && !provisioningError) {
      stage = 'controller_cleanup';
      provisioningError = new Error(`Controller VM ${controllerVmId} could not be stopped: ${controllerStop.error}`);
    }
  }

  const goadMeta = {
    controller_vmid: controllerVmId,
    controller_node: bestNode,
    controller_clone_attempted: true,
    controller_stop: controllerStop,
    status: provisioningError ? 'failed' : 'provisioned',
    stage,
    error: provisioningError ? provisioningError.message : null,
    provisioned_at: new Date().toISOString(),
  };
  if (delivery) {
    goadMeta.generated_lab = {
      lab: delivery.lab,
      tree_sha256: delivery.treeSha256,
      chain_mode: delivery.chainMode,
      already_present: delivery.skipped === true,
      ...(delivery.failedStep ? { failed_step: delivery.failedStep } : {}),
      ...(delivery.extensionConfigs ? { extension_configs: delivery.extensionConfigs } : {}),
    };
  }
  if (spec.goad.rename_forest === true) {
    goadMeta.forest_rename = {
      requested: true,
      compiled: Boolean(delivery?.treeSha256 && !delivery.failedStep),
      applied: identityVerification?.passed === true,
      base_lab: spec.goad.lab.baseLab,
      lab: spec.goad.version,
      forest_root: spec.goad.lab.forestRoot,
      domains: spec.goad.lab.domains,
      domain_mapping: spec.goad.lab.domainMapping,
    };
  }
  if (verification?.applicable) goadMeta.probe = summariseVerification(verification);
  if (identityVerification?.applicable) goadMeta.identities = identityVerification;
  if (query) {
    try {
      await query(
        `UPDATE cybercore_lane
         SET config = COALESCE(config, '{}'::jsonb) || $1::jsonb,
             updated_at = NOW()
         WHERE lane_id = $2`,
        [JSON.stringify({ goad: goadMeta }), lane.lane_id]
      );
    } catch (dbErr) {
      console.warn(`[GOAD] Failed to persist metadata: ${dbErr.message}`);
    }
  }
  // The caller's final inventory write is authoritative. Return the same
  // metadata even without a query function, and attach it to every failure.
  if (provisioningError) {
    provisioningError.goadMeta = goadMeta;
    provisioningError.controllerVmId = controllerVmId;
    throw provisioningError;
  }
  return { controllerVmId, playbookResult, delivery, verification, goadMeta };
}

// Full path so QEMU guest-agent CreateProcess resolves it regardless of the
// guest's PATH. Windows Server 2019 always ships PowerShell 5.1 here.
const WIN_PS = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';

/**
 * Pre-baked ("GOAD-Like") lane HEAL — runs AFTER the caller (groups.js) has
 * already (a) stripped cloud-init from the GOAD clones so their baked hostnames
 * survive, (b) written the gateway DHCP reservations, and (c) started the VMs
 * straight onto their reserved IPs. The VMs are GOLDEN IMAGES that were already
 * GOAD-provisioned, so there is NO controller and NO ansible (no ~90-min bake).
 *
 * The only thing a freshly-cloned forest needs is a DNS/replication kick: the
 * clone gave each DC a new VM-GenerationID, which resets its InvocationID and
 * leaves its SRV/_msdcs records stale, so the DCs can't locate each other until
 * they re-register and force a sync. This reproduces — automatically — the
 * sequence proven by hand on the 49010/49020 test clones:
 *   ipconfig /registerdns + nltest /dsregdns + restart Netlogon/DNS  → repadmin /syncall
 * Members need NO repair: with cloud-init stripped their baked hostname matches
 * their AD account, so the secure channel is healthy on boot (we only verify).
 *
 * REQUIRES the challenge to pin a fixed subnet (applyFixedSubnet in the caller)
 * so every lane reuses the base the golden image was baked on. Best-effort: a
 * heal step failing is logged, not thrown — the lane is already booted, and a
 * manual repadmin re-run is the fallback. Returns null for non-prebaked.
 */
async function deployPrebakedGoadLane({
  lane, spec, vxlanId, gatewayVmId, bestNode, laneSubnetBase, extSubnetBase, deployedVMs, proxmoxAPI
}) {
  if (!spec?.goad?.enabled || !spec?.goad?.prebaked) return null;
  const { labDef } = resolveGoadLab(spec);
  console.log(`[GOAD] Pre-baked lane ${lane.lane_id} (vxlan ${vxlanId}) — golden images; post-clone heal (no controller/ansible)`);

  // Tag each cloned QEMU VM with its lab role (match on lowercased name).
  const tagged = (deployedVMs || [])
    .filter(v => v.type === 'qemu')
    .map(v => ({ ...v, labVm: labDef.vms.find(lv => lv.name.toLowerCase() === String(v.name).toLowerCase()) }))
    .filter(v => v.labVm && v.labVm.role !== 'linux');
  const dcs = tagged.filter(v => v.labVm.role === 'dc');
  // 'workstation' rides the SAME repair as 'member', and leaving it out is a
  // silent bug rather than a missing feature. The heal in step 5 is not about
  // what a box does in the lab — it is about what a GOLDEN-IMAGE CLONE does to
  // machine identity: the clone resets VM-GenerationID, Netlogon tries to
  // establish the secure channel before the DCs have finished settling, fails,
  // and backs off into a broken state. Any domain-joined Windows clone needs
  // that nudge. Before ws01 existed as an extension the split was exhaustive
  // (every non-linux lab host was a dc or a member), so this filter was correct
  // by accident; adding a workstation to the roster is what makes it wrong.
  // A workstation left un-healed boots, looks fine, and cannot authenticate.
  const HEAL_ROLES = ['member', 'workstation'];
  const members = tagged.filter(v => HEAL_ROLES.includes(v.labVm.role));

  // Run a PowerShell one-liner inside a Windows clone via the guest agent.
  const winPS = async (vm, script, timeoutMs = 120000) => {
    const { pid } = await agentExecArgv(vm.node, vm.vm_id,
      [WIN_PS, '-NoProfile', '-NonInteractive', '-Command', script], proxmoxAPI);
    return pollExecStatus(vm.node, vm.vm_id, pid, timeoutMs);
  };

  // 1. Wait for each DC's guest agent, then let NTDS + DNS finish starting.
  for (const dc of dcs) {
    const ok = await waitForGuestAgent(dc.node, dc.vm_id, 300000);
    if (!ok) console.warn(`[GOAD] prebaked: DC ${dc.name} (${dc.vm_id}) guest agent not ready in 5m — heal may be incomplete`);
  }
  if (dcs.length) await sleep(90000);

  // 2. Re-publish each DC's SRV/_msdcs records (clean up the GenID-reset
  //    InvocationID so the DCs can locate each other again).
  for (const dc of dcs) {
    try {
      await winPS(dc, "ipconfig /registerdns | Out-Null; nltest /dsregdns; Restart-Service Netlogon -Force; Start-Sleep -Seconds 5; Restart-Service DNS -Force; 'reregistered'", 90000);
      console.log(`[GOAD] prebaked: ${dc.name} DNS/SRV records re-registered`);
    } catch (err) { console.warn(`[GOAD] prebaked: re-register ${dc.name} failed: ${err.message}`); }
  }
  if (dcs.length) await sleep(45000);  // let the refreshed records propagate

  // 3. Force replication both ways across every partition.
  for (const dc of dcs) {
    try { await winPS(dc, 'repadmin /syncall /AdeP', 120000); }
    catch (err) { console.warn(`[GOAD] prebaked: repadmin /syncall on ${dc.name} failed: ${err.message}`); }
  }

  // 4. Log replication health (best-effort) so a bad heal is visible in logs.
  if (dcs[0]) {
    try {
      const r = await winPS(dcs[0], 'repadmin /replsummary', 60000);
      const out = (r.stdout || '').trim();
      console.log(`[GOAD] prebaked: replication summary —\n${out}`);
      if (/[1-9]\d*\s*\/\s*\d+/.test(out.replace(/0\s*\/\s*\d+/g, ''))) {
        console.warn(`[GOAD] prebaked: replsummary shows non-zero failures — inspect ${dcs[0].name}`);
      }
    } catch (err) { console.warn(`[GOAD] prebaked: replsummary failed: ${err.message}`); }
  }

  // 5. Heal member secure channels (ACTIVE, not just a check). Members boot at
  //    the same time as the DCs, so their Netlogon tries to establish the secure
  //    channel BEFORE the DCs finish settling, fails, and backs off into a
  //    "broken" state — which is why a one-shot Test-ComputerSecureChannel was
  //    intermittently False. The machine password is valid (atomic clone, baked
  //    hostname preserved by the cloud-init strip), so we just need to FORCE
  //    Netlogon to re-establish against the now-healed DCs and retry until it
  //    takes. Restarting Netlogon rebuilds the secure channel from the stored
  //    machine password — no credentials and no reboot required.
  for (const m of members) {
    const ok = await waitForGuestAgent(m.node, m.vm_id, 180000);
    if (!ok) { console.warn(`[GOAD] prebaked: member ${m.name} guest agent not ready — skipping`); continue; }
    let healed = false;
    for (let attempt = 1; attempt <= 6 && !healed; attempt++) {
      try {
        const r = await winPS(m,
          'Restart-Service Netlogon -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 6; ' +
          '"$(hostname) sc=$(Test-ComputerSecureChannel -ErrorAction SilentlyContinue)"',
          90000);
        const out = (r.stdout || '').trim();
        if (/sc=True/i.test(out)) {
          healed = true;
          console.log(`[GOAD] prebaked: member ${m.name} secure channel OK (${out}; attempt ${attempt})`);
          break;
        }
        console.warn(`[GOAD] prebaked: member ${m.name} secure channel not up yet (attempt ${attempt}/6): ${out}`);
      } catch (err) {
        console.warn(`[GOAD] prebaked: member ${m.name} heal attempt ${attempt} errored: ${err.message}`);
      }
      if (!healed) await sleep(15000);  // let DC02 finish settling, then re-nudge
    }
    if (!healed) {
      console.warn(`[GOAD] prebaked: member ${m.name} secure channel STILL broken after 6 attempts — the machine password may have genuinely drifted; run Test-ComputerSecureChannel -Repair -Credential <domain admin> on it`);
    }
  }

  console.log(`[GOAD] prebaked: lane ${lane.lane_id} heal complete (${dcs.length} DC, ${members.length} member/workstation)`);
  return { prebaked: true, dcCount: dcs.length, memberCount: members.length };
}

module.exports = {
  // High-level
  deployGoadLane,
  deployPrebakedGoadLane,
  prepareGoadDeploymentSpec,
  goadIdentityExpectations,
  verifyGoadIdentities,
  // Generated labs: the delivery half and the proof half. Exported so the
  // ORDER deployGoadLane runs them in is assertable without a cluster, and so
  // the bake orchestrator can grade a report it did not itself produce.
  deliverGeneratedLab,
  deliverControllerRename,
  runLaneVerification,
  laneWantsProbe,
  resolveGeneratedLab,
  summariseVerification,
  // The wiring itself, so a test can prove the defaults are the shipped
  // functions rather than something merely callable.
  defaultGoadDeps,
  // Per-lane MAC/IP lookup table (called from admin.js once per lane)
  prepareGoadMacs,
  // Net0 string builder (called from admin.js inside the VM clone loop)
  buildLaneNet0,
  buildGoadHostMap,
  // Lower-level pieces (exposed for testability and partial flows)
  writeDhcpReservations,
  deployController,
  waitForWinRM,
  runGoadPlaybook,
  ensureControllerHostMap,
  CONTROLLER_HOST_MAP_PY,
  stopController,
  macFor,
  macForOctet,
  // Lab catalog (also surfaced via API endpoint for the admin UI)
  GOAD_LABS,
  DEFAULT_LAB,
  // Extension catalog + its three readers. Same split as the lab table: a
  // catalog reader for "what do we ship", a per-lab filter for "what may this
  // environment use", and a spec resolver for "what did this one select".
  GOAD_EXTENSIONS,
  getExtension,
  extensionsForLab,
  resolveGoadExtensions,
  // The single deploy-time lab reader, plus the two rules it enforces. Exported
  // so a caller outside this module can ask "what lab is this spec, really?"
  // without re-deriving the precedence — and so the guard has tests.
  resolveGoadLab,
  // The prebaked/extension fork, exported so the Designer's validator and this
  // module state the same rule from one definition rather than two that drift.
  assertGoadExtensionsRunnable,
  // The forest-rename refusals, exported for the same reason: the canvas
  // finding, the POST 400 and the PUT 400 must name the condition this module
  // enforces at deploy time, from this definition rather than a second copy.
  assertForestRenameDeployable,
  assertGoadExtensionsRenameSafe,
  isGoadManagedVm,
  EXTERNAL_ROLES,
  INFRA_IP_OCTETS,
  ROLE_RESOURCES,
  buildIp,
  getLab,
  getVmResources,
  CONTROLLER_TEMPLATE_VMID,
  // Exported so topology-validate's author-time twin of the pre-baked rule tests
  // against the same number this module enforces at deploy time, rather than a
  // second literal that can drift out of agreement with it.
  PLAIN_BASE_TEMPLATE_VMID
};
