/**
 * goad-postcondition-probe.js — after the bake, assert what is ACTUALLY TRUE.
 * ============================================================================
 * WHY THIS FILE EXISTS
 *
 * A GOAD bake is 16 separate ansible-playbook invocations over ~90 minutes, and
 * nothing in a host's `vulns` is even PARSED until roughly 95% of the way in. If
 * the chain survives to the end you get one number: the exit code. That number
 * is close to meaningless here, and not as an opinion — as an audited fact about
 * the pinned tree:
 *
 *   - `changed_when` appears exactly TWICE in the whole role library, so
 *     "changed" is whatever a module guessed.
 *   - `error_action: stop` appears SIX times, so a PowerShell payload that
 *     throws mostly still reports ok.
 *   - 20 sites were found where a task reports SUCCESS and did nothing.
 *
 * Three of those 20 are shipped VULNERABILITIES that are silently absent after a
 * fully green run, and they are the specification for this component:
 *
 *   vulns/adcs_esc7       the `if (Get-Module -ListAvailable -Name PSPKI)` guard
 *                         is INVERTED — the grant is in the else branch — and the
 *                         task immediately before it installs PSPKI. The guard is
 *                         therefore always true and ManageCA is never granted.
 *   move_to_ou            `$target_ou = Get-ADOrganizationalUnit -Identity
 *                         $ou_path > $null` redirects the SUCCESS stream, so
 *                         $target_ou is always $null and the "already in place?"
 *                         comparison is nonsense; a bad OU path throws
 *                         ADIdentityNotFoundException into a typed catch that
 *                         sets Changed=$false and returns green.
 *   vulns/no_ldap_signing writes HKLM:\SYSTEM\CurrentControlSet\Services\LDAP\
 *                         LDAPServerSigningRequirements — a path Windows does not
 *                         read. Its sibling no_ldap_integrity writes the path
 *                         Windows does read (NTDS\Parameters\LDAPServerIntegrity).
 *
 * The instructor-visible symptom of all three is identical and awful: the paper
 * scan report says the box is vulnerable, the student's tooling says it is not,
 * and there is no error message anywhere to search for.
 *
 * WHAT THIS ASSERTS, AND WHAT IT DELIBERATELY DOES NOT
 * PRECONDITIONS, not exploits. "Does khal.drogo hold GenericAll on
 * viserys.targaryen" — not "can we actually take over viserys.targaryen".
 * Executing a chain needs tooling, credentials, network position and a lot of
 * minutes, and when it fails it reports "the chain broke", not WHERE. A
 * precondition probe is cheaper by orders of magnitude and names the exact
 * missing fact. It also pays for itself against the EXISTING hand-written roles
 * before it ever validates a generated one, which is why it is worth building
 * first.
 *
 * SHAPE: PURE CORE, THIN I/O SKIN — the same split as goad-lab-validate.js.
 *   buildExpectationSet()  lab config in, expectation set out. No fs, no network.
 *   parseProbeResult()     raw probe output in, graded checks out. Never throws.
 *   runPostconditionProbe() the only impure function, and the only one that
 *                          cannot be unit-tested without a lane.
 * That split is not tidiness. The two halves that encode the KNOWLEDGE — which
 * facts to assert, and what an observation means — are exactly the two halves a
 * test can pin to a fixture, and a fixture of a green-but-empty lab is the
 * specification of why this component exists.
 *
 * THE PROBE REPORTS OBSERVATIONS; THIS FILE ASSIGNS VERDICTS.
 * data/probe/goad-postcondition.ps1 emits `present` (did the precondition hold,
 * in the positive sense) and never `ok`. Inversion for negative probes lives
 * here, in one line, and any `ok` the script might emit is IGNORED. A probe that
 * graded itself could hardcode a pass, and the entire premise of this component
 * is that "it said green" is not evidence.
 *
 * SECRETS — see script-executor.js and the enforcement in flag-manager.js.
 * The expectation set is staged as a file and reaches C:\Windows\Temp, which is
 * traversable by Users, so it carries CREDENTIAL REFERENCES (opaque names) and
 * never a password. assertNoSecrets() is a hard, testable guard on that: a
 * builder that started copying `user.password` into a check would fail the test,
 * not the lane. Credentials travel through win_powershell `parameters:` under
 * `no_log: true` (marshalled by the module, never a command line) and through
 * agentExecArgv on the controller side — never through script_args, which
 * script-executor.js interpolates UNQUOTED.
 */

const fs = require('fs');
const path = require('path');
const { aclRights, isAclRight } = require('./goad-role-manifest');

/** Bumped when the expectation-set or result-document shape changes in a way the
 *  .ps1 and this module must agree on. The script writes its own
 *  schema_version; a mismatch is reported rather than guessed at. */
const SCHEMA_VERSION = 1;

/** The staged script. Under data/ (see the .gitignore negation) because it is a
 *  data artifact shipped to a guest, not a module this process requires. */
const PROBE_SCRIPT_PATH = path.join(__dirname, '..', 'data', 'probe', 'goad-postcondition.ps1');

/**
 * Every check kind the .ps1 implements. An expectation carrying a kind outside
 * this list would be reported by the script as "not implemented" — a failure,
 * not a skip — but building one is a programming error, so the builder throws
 * instead of shipping it.
 */
const CHECK_KINDS = Object.freeze([
  'acl',
  'kerberoast',
  'asrep',
  'delegation',
  'share_read',
  'local_group',
  'group_member',
  'ou_placement',
  'registry',
  'ca_right',
  'file',
]);

/**
 * Extended-right name -> [ActiveDirectoryRights flag, ObjectType GUID].
 *
 * Mirrored verbatim from the pinned tree ($aclExtendedValueRightGUID in
 * ansible/roles/acl/tasks/main.yml and ansible/roles/vulns/acls/tasks/main.yml).
 * It lives here rather than in the manifest because the manifest records the
 * VOCABULARY (which names each role accepts) and this records the SEMANTICS
 * (what ACE each name actually produces) — the probe needs the second to know
 * what to look for on the DACL.
 *
 * The GUID is the whole meaning of these ACEs. An ExtendedRight ACE with the
 * wrong ObjectType grants a different extended right entirely, and a check that
 * compared only ActiveDirectoryRights would call that a pass.
 */
const EXTENDED_RIGHT_ACES = Object.freeze({
  'Ext-User-Force-Change-Password': Object.freeze({ ad_right: 'ExtendedRight', object_type: '00299570-246d-11d0-a768-00aa006e0529' }),
  'Ext-Write-Self-Membership': Object.freeze({ ad_right: 'WriteProperty', object_type: 'bf9679c0-0de6-11d0-a285-00aa003049e2' }),
  'Ext-Self-Self-Membership': Object.freeze({ ad_right: 'Self', object_type: 'bf9679c0-0de6-11d0-a285-00aa003049e2' }),
  'Ext-ManageCA': Object.freeze({ ad_right: 'ExtendedRight', object_type: '18e470eb-9b98-47c5-896e-146c5c77100d' }),
  'Ext-Write-SPN': Object.freeze({ ad_right: 'WriteProperty', object_type: 'f3a64788-5306-11d1-a9c5-0000f80367c1' }),
});

/**
 * Registry-effect table: for each vulns role that sets a registry value, the
 * path WINDOWS ACTUALLY READS.
 *
 * THIS TABLE IS THE no_ldap_signing CATCH, and it is worth being explicit about
 * why it is shaped as two path pairs rather than one.
 *
 *   `path`/`name`                 what Windows reads. This is what gets probed.
 *   `written_path`/`written_name` what the role writes. NOTHING probes this — a
 *                                 value sitting there proves only that the task
 *                                 ran, which Ansible already told us and which is
 *                                 exactly the claim we do not trust. It is
 *                                 recorded solely so a failure can say "the role
 *                                 wrote HKLM:\...\LDAP\LDAPServerSigningRequire-
 *                                 ments, which Windows does not read".
 *
 * Two entries below have written != effective, and both are the same family of
 * bug — a plausible-looking value name at a plausible-looking path that no
 * component consumes:
 *
 *   no_ldap_signing         Services\LDAP\LDAPServerSigningRequirements is not a
 *                           Windows-read value at all. The DC's LDAP signing
 *                           requirement lives at NTDS\Parameters\
 *                           LDAPServerIntegrity (the setting behind the "Domain
 *                           controller: LDAP server signing requirements"
 *                           policy), which is precisely what the SIBLING role
 *                           no_ldap_integrity writes. So a lab listing BOTH roles
 *                           has a satisfied precondition — this probe asserts the
 *                           STATE OF THE LAB, not the correctness of a role, and
 *                           saying otherwise would be a false positive.
 *   no_ldap_channel_binding the role writes LdapEnforceChannelBindings; the value
 *                           Microsoft documents (ADV190023) and Windows reads is
 *                           LdapEnforceChannelBinding, singular. Same silent
 *                           no-op, no sibling role to cover for it.
 *
 * Roles deliberately ABSENT from this table, so a future reader does not think
 * they were forgotten:
 *   enable_nbt-ns  NetBIOS-over-TCP is per-INTERFACE
 *                  (Services\NetBT\Parameters\Interfaces\Tcpip_<guid>\
 *                  NetbiosOptions). There is no single path to assert, and
 *                  inventing one would be worse than no check.
 *   smbv1          installs the SMB1Protocol Windows FEATURE. A registry probe
 *                  would be asserting a side effect that may or may not exist.
 *   autologon      is per-item (it iterates vulns_vars), so it is expanded in
 *                  the builder rather than being a flat entry here.
 */
const REGISTRY_EFFECTS = Object.freeze({
  no_ldap_signing: Object.freeze({
    written_path: 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LDAP',
    written_name: 'LDAPServerSigningRequirements',
    path: 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters',
    name: 'LDAPServerIntegrity',
    data_not_equal: 2,
    why: 'LDAP signing must not be required, or an unsigned bind (and every tool that does one) fails',
  }),
  no_ldap_integrity: Object.freeze({
    written_path: 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters',
    written_name: 'LDAPServerIntegrity',
    path: 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters',
    name: 'LDAPServerIntegrity',
    data_not_equal: 2,
    why: 'LDAP signing must not be required, or an unsigned bind fails',
  }),
  no_ldap_channel_binding: Object.freeze({
    written_path: 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters',
    written_name: 'LdapEnforceChannelBindings',
    path: 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters',
    name: 'LdapEnforceChannelBinding',
    data_not_equal: 2,
    why: 'channel binding must not be enforced, or LDAPS relay is not reproducible',
  }),
  enable_llmnr: Object.freeze({
    written_path: 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient',
    written_name: 'EnableMulticast',
    path: 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient',
    name: 'EnableMulticast',
    data: 1,
    why: 'LLMNR must be on for the responder/poisoning step to have anything to answer',
  }),
  ntlmdowngrade: Object.freeze({
    written_path: 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa',
    written_name: 'LmCompatibilityLevel',
    path: 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa',
    name: 'LmCompatibilityLevel',
    data: 2,
    why: 'NTLMv1 downgrade needs LmCompatibilityLevel <= 2',
  }),
  openshares: Object.freeze({
    written_path: 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters',
    written_name: 'AllowInsecureGuestAuth',
    path: 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters',
    name: 'AllowInsecureGuestAuth',
    data: 1,
    why: 'guest SMB access must be allowed or the anonymous share is not anonymous',
  }),
});

/** Directories vulns/openshares creates unconditionally. Asserted as artifacts
 *  because a share whose backing directory is missing is a share nobody can
 *  read, and the role reports green either way. */
const OPENSHARES_DIRECTORIES = Object.freeze(['C:\\shares\\public', 'C:\\shares\\all']);

/**
 * Default principals for the negative probes.
 *
 * These are the over-grants that turn a teaching lab into a walkover: a
 * GenericAll to Authenticated Users makes every intended path irrelevant because
 * every student already holds the endgame from their first shell. They cost
 * almost nothing to assert (the DACL is already fetched for the positive check
 * on the same object) and they are invisible to every other kind of validation,
 * because nothing was misconfigured — something extra was granted.
 */
const OVER_PRIVILEGED_PRINCIPALS = Object.freeze(['Authenticated Users', 'Everyone', 'Domain Users']);

/** Local-group principals that must NOT be local Administrators anywhere. */
const OVER_PRIVILEGED_LOCAL_ADMINS = Object.freeze(['Domain Users', 'Authenticated Users']);

// ─── small helpers ──────────────────────────────────────────────────────────

function isObject(v) { return v !== null && typeof v === 'object' && !Array.isArray(v); }
function asArray(v) { return Array.isArray(v) ? v : (v === null || v === undefined ? [] : [v]); }

/** Strip a `DOMAIN\` or `domain.tld\` prefix. GOAD writes principals both ways
 *  in the same file, often in the same dict. */
function bareSam(principal) {
  const s = String(principal == null ? '' : principal);
  const i = s.lastIndexOf('\\');
  return i === -1 ? s : s.slice(i + 1);
}

/** Ids appear in instructor-facing output and in test assertions, so they must
 *  be stable across runs and readable at a glance. Spaces and colons inside a
 *  segment would make the `kind:scope:name` shape ambiguous. */
function idPart(s) {
  return String(s == null ? '' : s).trim().replace(/\s+/g, '_').replace(/:/g, '-');
}

// ─── expectation set ────────────────────────────────────────────────────────

/**
 * Human-readable statement of what a check asserts. This is the `expected` half
 * of the expected/actual pair an instructor reads, so it is a sentence about the
 * ENVIRONMENT, never about the role or the YAML.
 */
function describeCheck(check) {
  // One boolean, read once. A negative probe's sentence has to stay grammatical
  // — it is what an instructor reads next to `actual` — and the two polarities
  // do not share a suffix, so each case phrases both.
  const absent = check.expect === 'absent';
  const value = () => {
    if (check.data !== undefined && check.data !== null) return ` to ${check.data}`;
    if (check.data_not_equal !== undefined && check.data_not_equal !== null) {
      return ` to anything but ${check.data_not_equal}`;
    }
    return '';
  };
  switch (check.kind) {
    case 'acl':
      return `${check.principal} ${absent ? 'does NOT hold' : 'holds'} ${check.right} on ${check.target}`
        + (check.object_type ? ` (objectType ${check.object_type})` : '');
    case 'kerberoast':
      return `${check.user} ${absent ? 'has NO' : 'has'} SPN(s) ${asArray(check.spns).join(', ')}`;
    case 'asrep':
      return `${check.user} ${absent ? 'does NOT have' : 'has'} DoesNotRequirePreAuth set`;
    case 'delegation':
      return `${check.principal} ${absent ? 'does NOT have' : 'has'} ${check.delegation} delegation`
        + (check.delegation === 'constrained' ? ` to ${asArray(check.allowed_to_delegate_to).join(', ')}` : '');
    case 'share_read':
      return `${check.path} is ${absent ? 'NOT ' : ''}readable as ${check.principal}`;
    case 'local_group':
      return `${check.member} is ${absent ? 'NOT ' : ''}a member of local ${check.group} on ${check.host}`;
    case 'group_member':
      return `${check.member} is ${absent ? 'NOT ' : ''}a direct member of ${check.group}`;
    case 'ou_placement':
      return `${check.computer} is ${absent ? 'NOT ' : ''}under ${check.ou_path}`;
    case 'registry':
      return `${check.path}\\${check.name} is ${absent ? 'NOT ' : ''}set${value()}`;
    case 'ca_right':
      return `${check.principal} ${absent ? 'does NOT hold' : 'holds'} ${check.right} on the CA`;
    case 'file':
      return `${check.path} ${absent ? 'does NOT exist' : 'exists'}`
        + (check.is_directory ? ' as a directory' : '');
    default:
      return `${check.kind} ${check.id}`;
  }
}

/**
 * Build one check, filling in the fields every kind shares and validating the
 * two that a typo would otherwise turn into a silently-skipped assertion.
 */
function makeCheck(fields) {
  if (CHECK_KINDS.indexOf(fields.kind) === -1) {
    throw new Error(`goad-postcondition-probe: unknown check kind '${fields.kind}' (known: ${CHECK_KINDS.join(', ')})`);
  }
  if (!fields.id) throw new Error(`goad-postcondition-probe: check of kind '${fields.kind}' has no id`);
  if (!fields.run_on) throw new Error(`goad-postcondition-probe: check '${fields.id}' has no run_on host`);
  const check = Object.assign({ expect: 'present' }, fields);
  if (check.expect !== 'present' && check.expect !== 'absent') {
    throw new Error(`goad-postcondition-probe: check '${check.id}' has expect '${check.expect}', must be 'present' or 'absent'`);
  }
  check.expected = describeCheck(check);
  return check;
}

/** Resolve the DC host key that owns a domain's directory queries. */
function dcForDomain(lab, domainName) {
  const domains = (lab && lab.domains) || {};
  const dom = domains[domainName];
  if (dom && dom.dc) return dom.dc;
  // Fall back to any host declared as a dc in that domain. A lab whose domain
  // block omits `dc` is malformed, but emitting no checks at all for it would be
  // a silent hole exactly like the ones this file exists to close.
  const hosts = (lab && lab.hosts) || {};
  for (const key of Object.keys(hosts)) {
    if (hosts[key] && hosts[key].type === 'dc' && hosts[key].domain === domainName) return key;
  }
  return null;
}

/**
 * Build the expectation set for a parsed GOAD lab config.
 *
 * `lab` is the INNER object (what goad-lab-validate.parseLabConfig returns as
 * `lab` — the `{"lab": …}` wrapper already unwrapped).
 *
 * Options:
 *   negatives          emit the standard over-grant probes (default true)
 *   verifyCredentials  emit the checks that must act AS a principal — the
 *                      share/file readability probes, and password verification
 *                      on kerberoast targets (default FALSE).
 *
 *                      Default false on purpose. Those checks need a credential
 *                      the runner supplies out of band, and a check that can
 *                      never be answered reports INCONCLUSIVE, which this module
 *                      grades as a failure. Emitting them unconditionally would
 *                      make every credential-free run red for a reason that is
 *                      about the probe rather than the lab — and a report that
 *                      is always red is exactly as useless as one that is always
 *                      green.
 *   extra              additional checks the lab config cannot express. GOAD
 *                      plants AS-REP roasting and delegation through freeform
 *                      ad/<LAB>/scripts/*.ps1 executed by roles/ps, not through
 *                      config vars, so those edges MUST be declared. An
 *                      undeclared edge is an unprobed edge; summary.declared
 *                      reports how many came from here so the coverage claim
 *                      stays honest.
 *
 * Returns { schema_version, lab_name, checks[], credential_refs[], warnings[] }.
 * Never touches the filesystem and never throws on lab CONTENT — only on a
 * programming error in `extra` (an unknown kind, a missing id).
 */
function buildExpectationSet(lab, options) {
  const opts = options || {};
  const negatives = opts.negatives !== false;
  const verifyCredentials = opts.verifyCredentials === true;
  const overPrivileged = opts.overPrivilegedPrincipals || OVER_PRIVILEGED_PRINCIPALS;

  const checks = [];
  const warnings = [];
  const credentialRefs = new Set();
  const seenIds = new Set();

  const push = (fields) => {
    const check = makeCheck(fields);
    if (seenIds.has(check.id)) {
      // Two checks sharing an id collapse into one on the way back through the
      // result map — one assertion silently stops being made. That is the exact
      // failure mode this component exists to catch, so it is a hard error here
      // rather than a de-duplicated surprise on a lane.
      throw new Error(`goad-postcondition-probe: duplicate check id '${check.id}'`);
    }
    seenIds.add(check.id);
    if (check.credential_ref) credentialRefs.add(check.credential_ref);
    checks.push(check);
    return check;
  };

  const hosts = (lab && lab.hosts) || {};
  const domains = (lab && lab.domains) || {};

  // ── domain-scoped facts ───────────────────────────────────────────────────
  for (const domainName of Object.keys(domains)) {
    const domain = domains[domainName] || {};
    const dc = dcForDomain(lab, domainName);
    if (!dc) {
      warnings.push(`domain '${domainName}' names no DC, so none of its directory facts can be probed`);
      continue;
    }
    const dtag = idPart(domainName);

    // ACLs (roles/acl, over ad_acls). The intended-right resolution is the point:
    // an extended right becomes a (flag, GUID) pair, and an unknown right is
    // flagged rather than dropped, because GOAD's matching is an ordinal
    // Array.Contains that writes NO ACE and still reports green.
    for (const key of Object.keys(domain.acls || {})) {
      const acl = domain.acls[key] || {};
      const right = acl.right;
      const ext = EXTENDED_RIGHT_ACES[right];
      push({
        id: `acl:${dtag}:${idPart(key)}`,
        kind: 'acl',
        run_on: dc,
        host: dc,
        domain: domainName,
        role: 'acl',
        origin: `domains.${domainName}.acls.${key}`,
        context: 'domain',
        principal: acl.for,
        target: acl.to,
        right,
        ad_right: ext ? ext.ad_right : right,
        object_type: ext ? ext.object_type : '',
        inheritance: acl.inheritance,
        known_right: isAclRight(right, 'domain'),
        why: 'the ACL edge a student is meant to walk',
      });
    }

    // Users: SPNs (kerberoast) and group membership.
    for (const sam of Object.keys(domain.users || {})) {
      const user = domain.users[sam] || {};
      const spns = asArray(user.spns);
      if (spns.length > 0) {
        push({
          id: `kerberoast:${dtag}:${idPart(sam)}`,
          kind: 'kerberoast',
          run_on: dc,
          host: dc,
          domain: domainName,
          role: 'onlyusers',
          origin: `domains.${domainName}.users.${sam}.spns`,
          user: sam,
          spns,
          // NEVER user.password. The reference is a NAME the runner resolves out
          // of band; assertNoSecrets() enforces that and the test asserts it.
          credential_ref: verifyCredentials ? `${domainName}\\${sam}` : undefined,
          supported_encryption_types: user.supported_encryption_types === undefined
            ? undefined : user.supported_encryption_types,
          why: 'no SPN means no service ticket, so there is nothing to roast',
        });
      }
      for (const group of asArray(user.groups)) {
        push({
          id: `group:${dtag}:${idPart(group)}:${idPart(sam)}`,
          kind: 'group_member',
          run_on: dc,
          host: dc,
          domain: domainName,
          role: 'onlyusers',
          origin: `domains.${domainName}.users.${sam}.groups`,
          group: bareSam(group),
          member: sam,
          nested: false,
          why: 'the membership the intended path depends on',
        });
      }
    }

    // Group nesting. Nesting is asserted separately from direct membership
    // because a path that runs THROUGH a nested group is a different finding
    // from the same principal being a direct member — and the .ps1 deliberately
    // does not use -Recursive, so the two cannot be confused.
    for (const scope of Object.keys(domain.groups || {})) {
      const scoped = domain.groups[scope] || {};
      for (const group of Object.keys(scoped)) {
        for (const member of asArray((scoped[group] || {}).members)) {
          push({
            id: `group:${dtag}:${idPart(group)}:${idPart(bareSam(member))}`,
            kind: 'group_member',
            run_on: dc,
            host: dc,
            domain: domainName,
            role: 'groups_domains',
            origin: `domains.${domainName}.groups.${scope}.${group}.members`,
            group,
            member: bareSam(member),
            nested: true,
            why: 'nested membership carries the privilege one hop further than it looks',
          });
        }
      }
    }
    for (const group of Object.keys(domain.multi_domain_groups_member || {})) {
      for (const member of asArray(domain.multi_domain_groups_member[group])) {
        push({
          id: `group:${dtag}:${idPart(group)}:${idPart(bareSam(member))}`,
          kind: 'group_member',
          run_on: dc,
          host: dc,
          domain: domainName,
          role: 'sync_domains',
          origin: `domains.${domainName}.multi_domain_groups_member.${group}`,
          group,
          member: bareSam(member),
          nested: true,
          cross_domain: true,
          why: 'a cross-domain membership is the whole trust-abuse path',
        });
      }
    }

    // Negative: nobody over-privileged holds GenericAll on an ACL target.
    if (negatives) {
      const targets = [];
      for (const key of Object.keys(domain.acls || {})) {
        const to = (domain.acls[key] || {}).to;
        if (to && targets.indexOf(to) === -1) targets.push(to);
      }
      for (const target of targets) {
        for (const principal of overPrivileged) {
          push({
            id: `neg:acl:${dtag}:${idPart(target)}:${idPart(principal)}`,
            kind: 'acl',
            expect: 'absent',
            run_on: dc,
            host: dc,
            domain: domainName,
            role: 'acl',
            origin: 'negative-probe',
            context: 'domain',
            principal,
            target,
            right: 'GenericAll',
            ad_right: 'GenericAll',
            object_type: '',
            known_right: true,
            why: 'a GenericAll to everyone hands every student the endgame from their first shell',
          });
        }
      }
    }
  }

  // ── host-scoped facts ─────────────────────────────────────────────────────
  for (const hostKey of Object.keys(hosts)) {
    const host = hosts[hostKey] || {};
    const htag = idPart(hostKey);
    const dc = dcForDomain(lab, host.domain);
    const vulns = asArray(host.vulns);
    const vulnVars = isObject(host.vulns_vars) ? host.vulns_vars : {};

    // OU placement — THE move_to_ou CATCH.
    //
    // `when` is mirrored from the role exactly: non-DC, and not a LAPS host
    // (those are moved by the LAPS OU creation instead). Emitting a check where
    // the role never runs would manufacture a failure, which is just as
    // destructive to trust in this report as missing a real one.
    if (host.type !== 'dc' && host.use_laps !== true && host.path && dc) {
      const ouPath = String(host.path);
      // Both parents the role's own comparison accepts. Reproducing its
      // semantics (rather than demanding the exact OU) is what keeps the check
      // truthful: upstream really does consider CN=Computers under the target to
      // be "already in place".
      const acceptedParents = [ouPath, `CN=Computers,${ouPath}`];
      // A path that is the domain naming context root accepts the DEFAULT
      // location, so a computer that never moved satisfies it. That is a real
      // pass, but it proves nothing about move_to_ou, so it is flagged and
      // counted separately rather than padding the coverage number.
      const trivial = /^DC=/i.test(ouPath);
      push({
        id: `ou:${htag}`,
        kind: 'ou_placement',
        run_on: dc,
        host: hostKey,
        domain: host.domain,
        role: 'move_to_ou',
        origin: `hosts.${hostKey}.path`,
        computer: host.hostname || hostKey,
        ou_path: ouPath,
        accepted_parents: acceptedParents,
        trivial,
        why: 'move_to_ou swallows a bad OU path in a typed catch and reports green',
      });
    }

    // Local group membership, including the local Administrators grants that are
    // usually the pivot's landing point.
    for (const group of Object.keys(host.local_groups || {})) {
      for (const member of asArray(host.local_groups[group])) {
        push({
          id: `localgroup:${htag}:${idPart(group)}:${idPart(bareSam(member))}`,
          kind: 'local_group',
          run_on: hostKey,
          host: hostKey,
          domain: host.domain,
          role: 'localusers',
          origin: `hosts.${hostKey}.local_groups.${group}`,
          group,
          member,
          local_admin: group === 'Administrators',
          why: 'where the pivot lands',
        });
      }
    }

    // Registry effects, from the flat table.
    for (const role of vulns) {
      const effect = REGISTRY_EFFECTS[role];
      if (!effect) continue;
      push(Object.assign({
        id: `registry:${htag}:${idPart(role)}`,
        kind: 'registry',
        run_on: hostKey,
        host: hostKey,
        domain: host.domain,
        role,
        origin: `hosts.${hostKey}.vulns[${role}]`,
      }, {
        path: effect.path,
        name: effect.name,
        data: effect.data,
        data_not_equal: effect.data_not_equal,
        written_path: effect.written_path,
        written_name: effect.written_name,
        why: effect.why,
      }));
    }
    if (vulns.indexOf('openshares') !== -1) {
      for (const dir of OPENSHARES_DIRECTORIES) {
        push({
          id: `file:${htag}:${idPart(dir)}`,
          kind: 'file',
          run_on: hostKey,
          host: hostKey,
          role: 'openshares',
          origin: `hosts.${hostKey}.vulns[openshares]`,
          path: dir,
          is_directory: true,
          why: 'a share whose backing directory is missing is a share nobody can read',
        });
      }
    }

    // ── per-item vulns_vars roles ──────────────────────────────────────────

    // files — THE dest-prefix CATCH. An edge can be perfectly present in AD and
    // still unreachable because the planted script was never delivered, and
    // nothing in AD reflects that.
    for (const key of Object.keys(vulnVars.files || {})) {
      const item = vulnVars.files[key] || {};
      if (!item.dest) continue;
      push({
        id: `file:${htag}:files:${idPart(key)}`,
        kind: 'file',
        run_on: hostKey,
        host: hostKey,
        role: 'files',
        origin: `hosts.${hostKey}.vulns_vars.files.${key}`,
        path: item.dest,
        is_directory: false,
        why: 'the planted artifact the chain reads; a wrong dest prefix breaks it invisibly',
      });
    }

    // directory — the ODD ONE OUT: dict_of_scalars, so item.value IS the path.
    // Every sibling role indexes item.value.<key>, which makes an object here
    // the easy generator bug — win_file then creates a directory literally named
    // "{'path': 'C:\\share'}". Refusing to probe that (with a warning) is more
    // honest than probing "[object Object]".
    for (const key of Object.keys(vulnVars.directory || {})) {
      const value = vulnVars.directory[key];
      if (typeof value !== 'string') {
        warnings.push(`hosts.${hostKey}.vulns_vars.directory.${key} is not a bare string path; `
          + 'vulns/directory is dict_of_scalars and consumes item.value directly, so GOAD would '
          + 'create a directory named after the stringified object. Not probed.');
        continue;
      }
      push({
        id: `file:${htag}:directory:${idPart(key)}`,
        kind: 'file',
        run_on: hostKey,
        host: hostKey,
        role: 'directory',
        origin: `hosts.${hostKey}.vulns_vars.directory.${key}`,
        path: value,
        is_directory: true,
        why: 'the staging directory the rest of the host vulns write into',
      });
    }

    // autologon — expanded per item rather than living in REGISTRY_EFFECTS,
    // because the expected DefaultUserName comes from the lab. DefaultPassword
    // is probed for EXISTENCE ONLY (`redact`): the value is a secret and must
    // never reach a result file that gets fetched back and logged.
    for (const key of Object.keys(vulnVars.autologon || {})) {
      const item = vulnVars.autologon[key] || {};
      const winlogon = 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon';
      push({
        id: `registry:${htag}:autologon:${idPart(key)}:enabled`,
        kind: 'registry',
        run_on: hostKey,
        host: hostKey,
        role: 'autologon',
        origin: `hosts.${hostKey}.vulns_vars.autologon.${key}`,
        path: winlogon,
        name: 'AutoAdminLogon',
        data: '1',
        why: 'autologon off means the credential is never used and never harvestable',
      });
      if (item.username) {
        push({
          id: `registry:${htag}:autologon:${idPart(key)}:user`,
          kind: 'registry',
          run_on: hostKey,
          host: hostKey,
          role: 'autologon',
          origin: `hosts.${hostKey}.vulns_vars.autologon.${key}`,
          path: winlogon,
          name: 'DefaultUserName',
          data: bareSam(item.username),
          why: 'the account the harvested autologon credential belongs to',
        });
      }
      push({
        id: `registry:${htag}:autologon:${idPart(key)}:secret`,
        kind: 'registry',
        run_on: hostKey,
        host: hostKey,
        role: 'autologon',
        origin: `hosts.${hostKey}.vulns_vars.autologon.${key}`,
        path: winlogon,
        name: 'DefaultPassword',
        redact: true,
        why: 'the plaintext password must actually be on disk for the harvest step to exist',
      });
    }

    // Host-context ACLs (roles/vulns/acls, over vulns_vars). Note the 'host'
    // vocabulary — it does NOT accept Ext-ManageCA or Ext-Write-SPN, and feeding
    // it one writes no ACE while the task reports green.
    for (const key of Object.keys(vulnVars.acls || {})) {
      const acl = vulnVars.acls[key] || {};
      const ext = EXTENDED_RIGHT_ACES[acl.right];
      push({
        id: `acl:${htag}:host:${idPart(key)}`,
        kind: 'acl',
        run_on: hostKey,
        host: hostKey,
        domain: host.domain,
        role: 'acls',
        origin: `hosts.${hostKey}.vulns_vars.acls.${key}`,
        context: 'host',
        principal: acl.for,
        target: acl.to,
        right: acl.right,
        ad_right: ext ? ext.ad_right : acl.right,
        object_type: ext ? ext.object_type : '',
        inheritance: acl.inheritance,
        known_right: isAclRight(acl.right, 'host'),
        why: 'the host-scoped ACL edge a student is meant to walk',
      });
    }

    // adcs_esc7 — THE CA-RIGHTS CATCH. The role's PSPKI guard is inverted, so
    // this grant is the single most reliably-absent "shipped" vulnerability in
    // the library.
    for (const key of Object.keys(vulnVars.adcs_esc7 || {})) {
      const item = vulnVars.adcs_esc7[key] || {};
      if (!item.ca_manager) continue;
      push({
        id: `ca:${htag}:${idPart(key)}`,
        kind: 'ca_right',
        run_on: hostKey,
        host: hostKey,
        domain: host.domain,
        role: 'adcs_esc7',
        origin: `hosts.${hostKey}.vulns_vars.adcs_esc7.${key}.ca_manager`,
        principal: item.ca_manager,
        right: 'ManageCA',
        why: 'ESC7 IS the ManageCA grant; without it the whole template is just a CA',
      });
    }

    // Readability AS the intended principal. Reading the path from the probe's
    // own (SYSTEM / domain admin) session would prove nothing a student can use,
    // so these are only emitted when a credential will exist to answer them.
    if (verifyCredentials) {
      for (const key of Object.keys(vulnVars.permissions || {})) {
        const item = vulnVars.permissions[key] || {};
        if (!item.path || !item.user) continue;
        push({
          id: `share:${htag}:permissions:${idPart(key)}`,
          kind: 'share_read',
          run_on: hostKey,
          host: hostKey,
          role: 'permissions',
          origin: `hosts.${hostKey}.vulns_vars.permissions.${key}`,
          path: item.path,
          via: 'winrm',
          target_host: host.hostname || hostKey,
          principal: item.user,
          credential_ref: item.user,
          why: 'a path only SYSTEM can read is not a finding a student can make',
        });
      }
      for (const key of Object.keys(vulnVars.shares || {})) {
        const item = vulnVars.shares[key] || {};
        const principals = []
          .concat(String(item.full || '').split(','))
          .concat(String(item.change || '').split(','))
          .concat(String(item.read || '').split(','))
          .map((p) => p.trim())
          .filter((p) => p && p !== 'Administrators');
        for (const principal of principals) {
          push({
            id: `share:${htag}:shares:${idPart(key)}:${idPart(principal)}`,
            kind: 'share_read',
            run_on: hostKey,
            host: hostKey,
            role: 'shares',
            origin: `hosts.${hostKey}.vulns_vars.shares.${key}`,
            path: `\\\\${host.hostname || hostKey}\\${key}`,
            via: 'smb',
            target_host: host.hostname || hostKey,
            principal,
            credential_ref: principal,
            why: 'the share must be readable by the principal the exercise names',
          });
        }
      }
    }

    // Negative: no blanket local-admin grant.
    if (negatives) {
      for (const principal of OVER_PRIVILEGED_LOCAL_ADMINS) {
        push({
          id: `neg:localgroup:${htag}:${idPart(principal)}`,
          kind: 'local_group',
          expect: 'absent',
          run_on: hostKey,
          host: hostKey,
          role: 'localusers',
          origin: 'negative-probe',
          group: 'Administrators',
          member: principal,
          local_admin: true,
          why: 'a blanket local-admin grant makes every privilege-escalation step on this host a no-op',
        });
      }
    }
  }

  // ── explicitly declared checks ────────────────────────────────────────────
  // GOAD plants AS-REP roasting, delegation and SID history through freeform
  // ad/<LAB>/scripts/*.ps1 run by roles/ps. Those are arbitrary PowerShell —
  // there is no honest way to derive an expectation from them, so they are
  // declared, and summary.declared says how many of the checks came from here.
  let declaredIndex = 0;
  for (const decl of asArray(opts.extra)) {
    declaredIndex += 1;
    push(Object.assign({
      id: `declared:${idPart(decl.kind)}:${declaredIndex}`,
      origin: 'declared',
      role: decl.role || null,
    }, decl));
  }

  return {
    schema_version: SCHEMA_VERSION,
    lab_name: opts.labName || null,
    verify_credentials: verifyCredentials,
    checks,
    credential_refs: Array.from(credentialRefs).sort(),
    warnings,
  };
}

/** Strict JSON for the staged file. Round-trips so a caller cannot ship
 *  something only a tolerant parser would accept — the .ps1 uses
 *  ConvertFrom-Json, which is strict. */
function toProbeJson(expectationSet, indent) {
  const text = JSON.stringify(expectationSet, null, indent === undefined ? 2 : indent);
  JSON.parse(text);
  return text;
}

// ─── the secrets guard ──────────────────────────────────────────────────────

/**
 * Every string in a lab that is a password.
 *
 * Used as the needle list for assertNoSecrets(). Harvested rather than
 * hand-listed because the builder walks right past all of these — users[].password
 * sits on the same object as users[].spns — and the one thing standing between
 * "read the SPN" and "copy the whole user object into the check" is a habit.
 * A test is better than a habit.
 */
function collectLabSecrets(lab) {
  const out = new Set();
  const add = (v) => { if (typeof v === 'string' && v.length >= 4) out.add(v); };
  const hosts = (lab && lab.hosts) || {};
  const domains = (lab && lab.domains) || {};
  for (const key of Object.keys(hosts)) {
    const host = hosts[key] || {};
    add(host.local_admin_password);
    const vv = isObject(host.vulns_vars) ? host.vulns_vars : {};
    for (const item of Object.values(vv.credentials || {})) {
      add((item || {}).secret);
      add((item || {}).runas_password);
    }
    for (const item of Object.values(vv.autologon || {})) add((item || {}).password);
  }
  for (const name of Object.keys(domains)) {
    const domain = domains[name] || {};
    add(domain.domain_password);
    for (const sam of Object.keys(domain.users || {})) add((domain.users[sam] || {}).password);
  }
  return Array.from(out);
}

/**
 * Throw if any secret reached the expectation set.
 *
 * The expectation set is staged to C:\Windows\Temp, which is traversable by
 * Users — the same exposure flag-manager.js refuses to accept for capture flags,
 * and for the same reason: a student holding the low-priv shell we deliberately
 * gave them can read it. Anything sensitive goes through agentExecArgv /
 * win_powershell `parameters:` under no_log instead, and this is the guard that
 * keeps that true as the builder grows.
 */
function assertNoSecrets(expectationSet, secrets) {
  const needles = asArray(secrets).filter((s) => typeof s === 'string' && s.length >= 4);
  if (needles.length === 0) return;
  const haystack = JSON.stringify(expectationSet);
  const found = needles.filter((s) => haystack.indexOf(s) !== -1);
  if (found.length > 0) {
    // Do not name the secret in the message — this error is logged.
    throw new Error(`goad-postcondition-probe: the expectation set contains ${found.length} `
      + 'lab secret(s). The set is staged in a world-traversable directory; pass a credential_ref '
      + 'and supply the value through the runner instead.');
  }
}

// ─── result parsing ─────────────────────────────────────────────────────────

/** Strip a UTF-8 BOM. PowerShell 5.1's Set-Content/Out-File add one and the
 *  controller reads the file back through `cat`; JSON.parse rejects it. */
function stripBom(text) {
  return typeof text === 'string' && text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}

/**
 * Grade a probe run against the expectation set that produced it.
 *
 * `raw` is one result document, or an array of them (one per run_on host), each
 * as a JSON string or an already-parsed object. The runGoadPlaybook readFile
 * idiom returns '__MISSING__' for an absent file, which is handled here rather
 * than at the call site.
 *
 * FAIL-CLOSED IS THE WHOLE POINT. Every path that ends in "we do not know"
 * produces ok:false:
 *
 *   - the result is missing, empty or unparseable  -> every check fails
 *   - a check has no observation                   -> that check fails
 *   - `present` is not a strict boolean            -> fails (a JSON "true"
 *                                                     string would pass a
 *                                                     truthiness test)
 *   - the query raised                             -> fails in EITHER polarity.
 *     This one is subtle and important: a negative probe whose query errored
 *     would otherwise read as "absent, as intended" — a silent success, which is
 *     the exact bug class this component exists to catch.
 *   - the check was inconclusive                   -> fails, and is counted
 *     separately so the report can say "unproven" rather than "broken".
 *
 * Any `ok` the script emitted is IGNORED. The script reports observations; the
 * verdict is computed here, from `expect`, so that a probe cannot grade itself.
 */
function parseProbeResult(raw, expectationSet) {
  const expectations = (expectationSet && Array.isArray(expectationSet.checks)) ? expectationSet.checks : [];
  const errors = [];
  const byId = new Map();
  const duplicated = new Set();
  const documents = [];

  for (const item of asArray(raw)) {
    let doc = item;
    if (typeof item === 'string') {
      const text = stripBom(item).trim();
      if (!text || text === '__MISSING__') {
        errors.push('a probe result was missing or empty');
        continue;
      }
      try {
        doc = JSON.parse(text);
      } catch (err) {
        errors.push(`a probe result was not parseable JSON: ${err.message}`);
        continue;
      }
    }
    if (!isObject(doc)) {
      errors.push('a probe result was not a JSON object');
      continue;
    }
    documents.push(doc);
    if (doc.schema_version !== undefined && doc.schema_version !== SCHEMA_VERSION) {
      errors.push(`probe result from '${doc.run_on || '?'}' declares schema_version `
        + `${doc.schema_version}, expected ${SCHEMA_VERSION}`);
    }
    if (doc.fatal) errors.push(`probe on '${doc.run_on || '?'}' reported: ${doc.fatal}`);
    // ConvertTo-Json collapses a single-element array into a bare object, so a
    // run that produced exactly one observation arrives as an object. Both
    // shapes are normalised here AND forced with @( ) in the script: a trap this
    // cheap gets belt and braces.
    for (const obs of asArray(doc.results)) {
      if (!isObject(obs) || !obs.id) continue;
      if (byId.has(obs.id)) { duplicated.add(obs.id); continue; }
      byId.set(obs.id, obs);
    }
  }

  const unparseable = documents.length === 0;
  if (unparseable && expectations.length > 0 && errors.length === 0) {
    errors.push('the probe produced no result at all');
  }

  const checks = [];
  const summary = {
    total: expectations.length,
    ok: 0,
    failed: 0,
    inconclusive: 0,
    missing: 0,
    extra: 0,
    trivial: 0,
    negative: 0,
    declared: 0,
    by_kind: {},
    by_role: {},
  };

  const tally = (bucket, key, ok) => {
    if (!key) return;
    if (!bucket[key]) bucket[key] = { total: 0, failed: 0 };
    bucket[key].total += 1;
    if (!ok) bucket[key].failed += 1;
  };

  for (const expectation of expectations) {
    const obs = byId.get(expectation.id);
    let ok = false;
    let actual = null;
    let detail;
    let inconclusive = false;

    if (duplicated.has(expectation.id)) {
      detail = `more than one host reported check '${expectation.id}' — the run_on routing is wrong, `
        + 'so it is not knowable which host was actually asked';
    } else if (!obs) {
      detail = unparseable
        ? 'the probe produced no result, so nothing about this precondition is known'
        : `no observation was reported for this check (expected from host '${expectation.run_on}')`;
      summary.missing += 1;
    } else if (typeof obs.present !== 'boolean') {
      detail = `the probe reported a non-boolean observation (${JSON.stringify(obs.present)}) — `
        + 'treated as unknown';
      actual = obs.actual === undefined ? null : obs.actual;
    } else if (obs.error) {
      actual = obs.actual === undefined ? null : obs.actual;
      detail = `${obs.detail || 'the query raised'} [error: ${obs.error}]`;
    } else if (obs.inconclusive) {
      inconclusive = true;
      summary.inconclusive += 1;
      actual = obs.actual === undefined ? null : obs.actual;
      detail = `${obs.detail || 'inconclusive'} — unproven, which is not the same as satisfied`;
    } else {
      actual = obs.actual === undefined ? null : obs.actual;
      // The one line of inversion. Everything the script said about `ok` (if it
      // said anything) is deliberately not consulted.
      ok = expectation.expect === 'absent' ? !obs.present : obs.present;
      detail = obs.detail || '';
    }

    if (ok) summary.ok += 1; else summary.failed += 1;
    if (expectation.expect === 'absent') summary.negative += 1;
    if (expectation.trivial) summary.trivial += 1;
    if (expectation.origin === 'declared') summary.declared += 1;
    tally(summary.by_kind, expectation.kind, ok);
    tally(summary.by_role, expectation.role, ok);

    checks.push({
      id: expectation.id,
      kind: expectation.kind,
      expect: expectation.expect,
      expected: expectation.expected || describeCheck(expectation),
      actual,
      ok,
      inconclusive,
      detail,
      run_on: expectation.run_on,
      host: expectation.host || null,
      role: expectation.role || null,
      why: expectation.why || null,
    });
  }

  const known = new Set(expectations.map((c) => c.id));
  for (const id of byId.keys()) {
    if (known.has(id)) continue;
    // Drift between the staged set and the set being graded. Not a pass and not
    // ignorable: it means the probe answered a question nobody asked, so the
    // questions we DID ask may not have been the ones that ran.
    summary.extra += 1;
    summary.failed += 1;
    checks.push({
      id,
      kind: 'unknown',
      expect: 'present',
      expected: 'a check in the expectation set',
      actual: (byId.get(id) || {}).actual || null,
      ok: false,
      inconclusive: false,
      detail: 'the probe reported a check id that is not in this expectation set — '
        + 'the staged set and the graded set have drifted',
      run_on: null,
      host: null,
      role: null,
      why: null,
    });
  }

  return {
    passed: summary.failed === 0 && errors.length === 0,
    schema_version: SCHEMA_VERSION,
    summary,
    errors,
    checks,
  };
}

/** The failing rows, most useful first — negatives and inconclusives last,
 *  because a missing precondition is what an instructor acts on. */
function failures(result) {
  const rows = (result && Array.isArray(result.checks)) ? result.checks.filter((c) => !c.ok) : [];
  return rows.slice().sort((a, b) => {
    const score = (c) => (c.expect === 'absent' ? 2 : 0) + (c.inconclusive ? 1 : 0);
    return score(a) - score(b);
  });
}

/** One-line-per-failure text for a log or a toast. */
function formatFailures(result) {
  return failures(result)
    .map((c) => `${c.role ? `[${c.role}] ` : ''}${c.id}: expected ${c.expected} — ${c.detail}`)
    .join('\n');
}

// ─── controller-side invocation ─────────────────────────────────────────────

/** Where the probe's files live on the controller. Alongside /var/lib/goad-run,
 *  which run.sh already owns and which is root-only. */
const CONTROLLER_PROBE_DIR = '/var/lib/goad-run/probe';

/**
 * The playbook that runs the probe over the SAME WinRM path Ansible used.
 *
 * Why via the controller at all: the controller has ansible + python3-winrm and
 * a route into the lane; the orchestrator has neither. Reusing the connection
 * ansible already proved also means a probe failure cannot be "the probe could
 * not connect" wearing a disguise.
 *
 * Two deliberate choices about where things land:
 *   - The script itself is inlined with `lookup('file', …)` rather than copied,
 *     so nothing but the expectation set touches the guest filesystem.
 *   - Credentials go through `parameters:` under `no_log: true`. win_powershell
 *     marshals parameters into the payload; they never appear on a command line,
 *     never reach script_args (which script-executor.js interpolates UNQUOTED),
 *     and never land in C:\Windows\Temp.
 * The expectation set DOES land in C:\Windows\Temp, which is traversable by
 * Users — that is exactly why assertNoSecrets() exists and why it is called
 * before this playbook is ever written.
 */
function buildProbePlaybook(options) {
  const opts = options || {};
  const stageDir = opts.stageDir || 'C:\\Windows\\Temp\\ciab-probe';
  return [
    '---',
    '- name: CIAB GOAD post-condition probe',
    '  hosts: "{{ ciab_probe_hosts }}"',
    '  gather_facts: no',
    '  tasks:',
    '    - block:',
    '        - name: Create the probe staging directory',
    '          ansible.windows.win_file:',
    `            path: ${stageDir}`,
    '            state: directory',
    '',
    '        - name: Stage the expectation set (carries credential REFERENCES, never secrets)',
    '          ansible.windows.win_copy:',
    '            src: "{{ ciab_probe_expectation }}"',
    `            dest: ${stageDir}\\expectation.json`,
    '',
    '        - name: Run the post-condition probe',
    '          ansible.windows.win_powershell:',
    "            script: \"{{ lookup('file', ciab_probe_script) }}\"",
    '            parameters:',
    `              ExpectationPath: ${stageDir}\\expectation.json`,
    `              ResultPath: ${stageDir}\\result.json`,
    '              RunOn: "{{ inventory_hostname }}"',
    "              CredentialJson: \"{{ ciab_probe_credentials | default('') }}\"",
    '          # no_log because CredentialJson is a parameter of this task. The',
    '          # probe writes its findings to a file, so nothing of value is lost.',
    '          no_log: true',
    '          vars:',
    '            ansible_become: yes',
    '            ansible_become_method: runas',
    '            ansible_become_user: "{{ ciab_probe_become_user }}"',
    '            ansible_become_password: "{{ ciab_probe_become_password }}"',
    '',
    '        - name: Fetch the result back to the controller',
    '          ansible.builtin.fetch:',
    `            src: ${stageDir}\\result.json`,
    '            dest: "{{ ciab_probe_result_dir }}/{{ inventory_hostname }}.json"',
    '            flat: yes',
    '      always:',
    '        # Leave nothing behind in a world-traversable directory, and do it in',
    '        # `always` so a failed probe cleans up too — the staged-script path in',
    '        # script-executor.js leaks precisely because its cleanup is inside the',
    '        # payload that timed out.',
    '        - name: Remove the staged probe files',
    '          ansible.windows.win_file:',
    `            path: ${stageDir}`,
    '            state: absent',
    '          ignore_errors: yes',
    '',
  ].join('\n');
}

/**
 * The ansible-playbook argv. Pure, so a test can assert that no secret is in it:
 * every credential travels in an --extra-vars FILE written with umask 077 on the
 * controller, never as an argument.
 */
function buildProbeArgv(options) {
  const opts = options || {};
  const labData = `/opt/goad/ad/${opts.labName}/data`;
  return [
    'ansible-playbook',
    '-i', `${labData}/inventory`,
    '-i', '/var/lib/goad-run/inventory_proxmox',
    '-i', '/var/lib/goad-run/inventory_overrides',
    opts.playbookPath || `${CONTROLLER_PROBE_DIR}/postcondition.yml`,
    '--extra-vars', '@/var/lib/goad-run/extra_vars.yml',
    '--extra-vars', `@${opts.varsPath || `${CONTROLLER_PROBE_DIR}/probe_vars.yml`}`,
    '--limit', asArray(opts.hosts).join(','),
  ];
}

/** The distinct hosts a set needs to run on, in a stable order. */
function probeHosts(expectationSet) {
  const seen = [];
  for (const check of ((expectationSet && expectationSet.checks) || [])) {
    if (check.run_on && seen.indexOf(check.run_on) === -1) seen.push(check.run_on);
  }
  return seen.sort();
}

/**
 * Run the probe on the lane and grade it.
 *
 * The only impure function here, and the shape is lifted deliberately from
 * runGoadPlaybook() in src/utils/goad-deploy.js, because that idiom was arrived
 * at the hard way and the failure modes have not changed:
 *
 *   - QGA buffers a long-running process's stdio in memory and deadlocks on it,
 *     and loses track of long-running PIDs entirely (guest-exec-status reports
 *     exited=false forever). So: detach with nohup setsid, redirect to a log,
 *     write the exit code to a SENTINEL file, and poll for the sentinel with
 *     short-lived guest-exec calls, which are reliable.
 *   - Reading a file back is the same `[ -f p ] && cat p || echo __MISSING__`
 *     helper, and parseProbeResult() understands __MISSING__ for that reason.
 *
 * Everything staged is written base64-encoded through agentExecArgv: argv, so
 * nothing in the payload is interpolated by a shell, and no content ever becomes
 * part of a command line.
 *
 * agentExecArgv / pollExecStatus / sleep are INJECTED rather than required at
 * the top of this file. requiring src/utils/script-executor.js would pull in the
 * proxmox client and, through it, the gitignored config/site.json — which would
 * make the pure half of this module unloadable in `node --test` without a
 * require.cache stub, for the sake of a function the tests cannot call anyway.
 * The pure core stays dependency-free; the caller (goad-deploy) already holds
 * these three and passes its own.
 */
async function runPostconditionProbe(options) {
  const {
    controllerVmId, bestNode, proxmoxAPI, labName, expectationSet,
    credentials = null, becomeUser, becomePassword,
    secrets = [], timeoutMs = 15 * 60 * 1000, sleep, agentExecArgv, pollExecStatus,
  } = options;

  // Belt and braces: the guard runs again here, at the last point before the set
  // leaves this process. A caller that skipped it does not get to stage secrets.
  assertNoSecrets(expectationSet, secrets);

  const hosts = probeHosts(expectationSet);
  if (hosts.length === 0) return parseProbeResult([], expectationSet);

  const runId = `${Date.now().toString(36)}`;
  const resultDir = `${CONTROLLER_PROBE_DIR}/${runId}`;
  const donePath = `${resultDir}/done.txt`;
  const logPath = `${resultDir}/probe.log`;

  const write = async (destPath, content, mode) => {
    const b64 = Buffer.from(content, 'utf8').toString('base64');
    // umask 077 before the redirect so the file is never briefly world-readable;
    // the explicit chmod covers a pre-existing file the redirect would truncate
    // rather than recreate.
    const { pid } = await agentExecArgv(bestNode, controllerVmId, ['/bin/sh', '-c',
      `umask 077; mkdir -p ${resultDir} && echo ${b64} | base64 -d > ${destPath} && chmod ${mode || '600'} ${destPath}`],
    proxmoxAPI);
    await pollExecStatus(bestNode, controllerVmId, pid, 20000);
  };

  await write(`${resultDir}/goad-postcondition.ps1`, fs.readFileSync(PROBE_SCRIPT_PATH, 'utf8'), '600');
  await write(`${resultDir}/expectation.json`, toProbeJson(expectationSet), '600');
  await write(`${resultDir}/postcondition.yml`, buildProbePlaybook({}), '600');
  // The become credential and any per-principal credentials live ONLY in this
  // controller-local 0600 file, and reach the guest through win_powershell
  // parameters under no_log. Never in argv, never in script_args.
  await write(`${resultDir}/probe_vars.yml`, [
    `ciab_probe_hosts: "${hosts.join(',')}"`,
    `ciab_probe_expectation: "${resultDir}/expectation.json"`,
    `ciab_probe_script: "${resultDir}/goad-postcondition.ps1"`,
    `ciab_probe_result_dir: "${resultDir}"`,
    `ciab_probe_become_user: ${JSON.stringify(becomeUser || 'administrator')}`,
    `ciab_probe_become_password: ${JSON.stringify(becomePassword || '')}`,
    `ciab_probe_credentials: ${JSON.stringify(credentials ? JSON.stringify(credentials) : '')}`,
  ].join('\n'), '600');

  const argv = buildProbeArgv({
    labName,
    hosts,
    playbookPath: `${resultDir}/postcondition.yml`,
    varsPath: `${resultDir}/probe_vars.yml`,
  });
  const quoted = argv.map((a) => `'${String(a).replace(/'/g, `'\\''`)}'`).join(' ');
  const inner = `cd /opt/goad/ansible && ANSIBLE_CONFIG=/opt/goad/ansible/ansible.cfg ${quoted} > ${logPath} 2>&1; echo \\$? > ${donePath}`;
  await agentExecArgv(bestNode, controllerVmId, ['/bin/bash', '-c',
    `rm -f ${donePath}; nohup setsid sh -c "${inner}" </dev/null >/dev/null 2>&1 &`], proxmoxAPI);

  const readFile = async (p) => {
    const { pid } = await agentExecArgv(bestNode, controllerVmId,
      ['/bin/sh', '-c', `[ -f ${p} ] && cat ${p} || echo __MISSING__`], proxmoxAPI);
    const r = await pollExecStatus(bestNode, controllerVmId, pid, 15000);
    return (r.stdout || '').trim();
  };

  const deadline = Date.now() + timeoutMs;
  let finished = false;
  while (Date.now() < deadline) {
    await sleep(10000);
    try {
      const content = await readFile(donePath);
      if (content && content !== '__MISSING__') { finished = true; break; }
    } catch (_) { /* transient guest-exec failure — keep polling */ }
  }

  // A probe that did not finish is graded anyway: parseProbeResult fails every
  // check it has no observation for, which is the correct report. Throwing here
  // would discard the partial results, and a partial probe still names real
  // missing preconditions.
  const raws = [];
  for (const host of hosts) {
    try { raws.push(await readFile(`${resultDir}/${host}.json`)); } catch (_) { raws.push('__MISSING__'); }
  }
  const result = parseProbeResult(raws, expectationSet);
  if (!finished) {
    result.passed = false;
    result.errors.push(`the probe did not finish within ${timeoutMs}ms — log at ${logPath} on controller ${controllerVmId}`);
  }
  return result;
}

module.exports = {
  SCHEMA_VERSION,
  PROBE_SCRIPT_PATH,
  CONTROLLER_PROBE_DIR,
  CHECK_KINDS,
  EXTENDED_RIGHT_ACES,
  REGISTRY_EFFECTS,
  OPENSHARES_DIRECTORIES,
  OVER_PRIVILEGED_PRINCIPALS,
  OVER_PRIVILEGED_LOCAL_ADMINS,
  buildExpectationSet,
  describeCheck,
  toProbeJson,
  collectLabSecrets,
  assertNoSecrets,
  parseProbeResult,
  failures,
  formatFailures,
  probeHosts,
  buildProbePlaybook,
  buildProbeArgv,
  runPostconditionProbe,
};
