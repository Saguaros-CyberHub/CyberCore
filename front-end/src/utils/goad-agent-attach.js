/**
 * ============================================================================
 * GOAD SIEM AGENT ATTACHMENT
 * ----------------------------------------------------------------------------
 * A ticked `elk` or `wazuh` extension has TWO halves, and until this module
 * existed CyberCore only shipped one of them.
 *
 *   SERVER half   a machine. GOAD_EXTENSIONS places it, resolveSpecAddressing
 *                 pins it, and extensions/<key>/ansible/install.yml builds
 *                 Elasticsearch+Kibana / the Wazuh manager on it in the lane.
 *   AGENT half    a package on EVERY WINDOWS HOST IN [domain]. Upstream spells
 *                 this as `[elk_log:children] domain` and
 *                 `[wazuh_agents:children] domain` in the extension inventories.
 *
 * Ship only the server half and you get the precise failure this codebase keeps
 * documenting: every clone succeeds, the lane reports active, the console
 * opens, Kibana loads — and it is EMPTY, because no host was ever told to ship
 * anything. A green deploy and a dead exercise, with nothing in any log saying
 * so. That is what this module exists to prevent.
 *
 * ── WHY THIS IS NOT A TEMPLATE BAKE ─────────────────────────────────────────
 *
 * The obvious alternative was to re-bake the shared Windows templates (1004
 * Server, 1006 Windows 11) with the agents pre-installed. That is rejected, and
 * the reasons are properties the code below has to keep:
 *
 *   blast radius     1004 and 1006 are cloned by EVERY GOAD lab on this
 *                    cluster. A bad bake breaks CYBR 480 and every red-team
 *                    lane, not just the blue-team ones that asked for a SIEM.
 *   the registration trap  a wazuh-agent snapshotted AFTER it registers bakes
 *                    ONE agent identity into every clone, so the manager sees a
 *                    single agent flapping across every lane at once. A fresh
 *                    in-lane install enrolls correctly: there is no baked
 *                    client.keys to clear and no shared identity to collide.
 *   opt-in           only a lane that ticked a SIEM pays for the agents.
 *   version drift    nothing is frozen in an image; editing the seeded script
 *                    changes the next lane.
 *   visible failure  executeScriptsOnVM writes per-script status and streams
 *                    live log output into the deployment UI, so a failed agent
 *                    install is a red row instead of a silently agent-less
 *                    golden image.
 *
 * So the agents are installed PER LANE, at deploy time, through the post-clone
 * script mechanism this platform already has: vuln_scripts rows keyed by slug,
 * fetched by challenge-lane-deployer's runVulnScripts and run by
 * script-executor's executeScriptsOnVM. The two slugs below are seeded by
 * src/utils/goad-agent-scripts.js — that module owns the script BODIES and the
 * idempotent boot-hook seed; this one owns WHICH MACHINES GET THEM. The slug
 * strings are the entire contract between them, which is why they are pinned by
 * a source-text gate in test/goad-agent-attach.test.js rather than by a require
 * (a hard require would make the deployer fail to LOAD if the seeder is ever
 * renamed or moved, trading a missing agent for a dead deploy path).
 *
 * Ordering inside the lane is already right and is worth stating, because it is
 * the reason this works at all: deployLaneVms runs GOAD provisioning at step 3
 * — which is where run.sh installs the extension and stands the SIEM up — and
 * vuln scripts at step 5. So an agent always installs against a domain that
 * exists and a manager that is already listening.
 *
 * ── WHY DEPLOY TIME AND NOT SPEC SYNTHESIS ──────────────────────────────────
 *
 * The slugs could equally have been written into spec.vms[].post_clone_scripts
 * by the Topology Designer / profile-to-spec at SYNTHESIS time, so they landed
 * in the stored row. That was the other real candidate and the two are not
 * equivalent. Deploy time wins on three counts:
 *
 *   1. A SPEC OUTLIVES ITS TELEMETRY CHOICE. `extensions` is authored in a UI
 *      and edited afterwards. Bake the slugs into the stored spec and every
 *      later edit has to remember to un-bake them: untick elk on a saved
 *      environment and all twelve hosts keep `goad-elk-agent`, so every deploy
 *      installs winlogbeat pointed at a machine the lane no longer has. It
 *      fails per host, late, in a log nobody reads — because the lane still
 *      comes up. A derivation cannot drift from the thing it derives from.
 *   2. OLD SPECS PICK IT UP FOR FREE. Every environment authored before this
 *      module existed already has `extensions: ['elk']` and no agent slugs. At
 *      synthesis time those rows stay wrong until someone re-saves each one; a
 *      deploy-time derivation makes the NEXT deploy correct with no migration
 *      and no backfill over stored JSONB.
 *   3. ONE READER, NOT THREE. Specs are synthesized in at least three places
 *      (the Designer, profile-to-spec, the bake-staging overlay). Attaching at
 *      synthesis means the rule is spelled once per synthesizer, and the fourth
 *      synthesizer written next term silently ships no agents. Attaching in the
 *      shared deployer means every caller — CiAB profile lanes, CLE, the admin
 *      group deploy, bake-staging — goes through one expression.
 *
 * WHAT SYNTHESIS TIME WOULD HAVE BOUGHT, and what is therefore given up: the
 * slugs would be VISIBLE to the author on the canvas and in the stored row, and
 * an author could hand-remove the agent from one noisy host. Nobody has asked
 * for the latter, and the answer to "does this host report?" is already
 * rendered by topology-validate's `siem-blind-host` from the same `instruments`
 * data this module reads. The per-script status rows in the deployment UI carry
 * the after-the-fact visibility.
 *
 * ── ORDERING: elk AND wazuh AT ONCE ─────────────────────────────────────────
 *
 * Ticking BOTH is legitimate — comparing two consoles against one incident is a
 * real exercise — and then a host carries both slugs. They have NO ordering
 * relationship and deliberately declare none:
 *
 *   goad-elk-agent    installs Sysmon + winlogbeat; winlogbeat ships Windows
 *                     event channels to Elasticsearch on the elk box.
 *   goad-wazuh-agent  installs wazuh-agent and enrolls it with the manager on
 *                     the wazuh box.
 *
 * Disjoint installers, disjoint services, disjoint destinations. Neither reads
 * the other's output and neither is a prerequisite for the other, so neither
 * belongs in the other's `depends_on`. That matters concretely, because
 * script-executor's sortByDependencies is a topological sort over `depends_on`
 * ONLY — with no edge between them the two run in whatever order
 * `WHERE slug = ANY($1)` happened to return, which Postgres does not promise.
 * An invented dependency would not make that order meaningful; it would only
 * make one agent's failure block the other's install.
 *
 * ── WHICH MACHINES, AND WHICH ONES MUST BE LEFT ALONE ───────────────────────
 *
 * Every Windows host in the AD roster: resolveGoadLab(spec).labDef.vms minus
 * the `linux` role. resolveGoadLab rather than GOAD_LABS[version] because it is
 * THE deploy-time reader — it honours a spec-supplied goad.lab and it composes
 * the `inLab` extension machines into the roster, so ws01 arrives instrumented
 * with no extra work here the moment it is ticked.
 *
 * Everything below must NOT receive a Windows script, and each is excluded by
 * construction rather than by a name list:
 *
 *   elk, wazuh, lx01  `inLab: false` extensions — never in labDef.vms at all.
 *                     elk and wazuh are Ubuntu; they ARE the collectors.
 *   DRACARYS's LX01   a role:'linux' host that IS in the roster, so the role
 *                     filter is doing real work rather than belt-and-braces.
 *                     `role !== 'linux'` is the same predicate deployGoadLane
 *                     already uses to decide who gets polled for WinRM.
 *   Kali, the v3 DMZ  EXTERNAL_ROLES; outside the forest and outside the roster.
 *
 * Getting this wrong is not loud. A Windows script on a Linux guest is stored
 * with os_target 'windows', so executeScriptsOnVM routes it to
 * executePowerShellViaFile and the guest agent is asked to run powershell.exe on
 * a box that has none — a failure whose message names neither this decision nor
 * the machine's OS.
 *
 * ── NO SCRIPT ARGS, EVER ────────────────────────────────────────────────────
 *
 * Nothing here passes script_args. script-executor interpolates that string
 * UNQUOTED into the PowerShell invocation stub, so anything carrying a shell
 * metacharacter is a command injection into the guest. These scripts need no
 * arguments at all: an agent finds its manager by DNS name (`elk` / `wazuh`,
 * from the dns_aliases the extension already registers with the lane's dnsmasq)
 * and enrols with the extension's own defaults. The attachment shape below
 * carries a slug and a machine name and nothing else, so there is no field for
 * a secret to leak through.
 *
 * PURE. No DB, no Proxmox, no I/O — every function here is a total function of
 * the spec, which is what makes the whole decision assertable without a cluster.
 * ============================================================================
 */

const { resolveGoadLab } = require('./goad-deploy');

/**
 * Extension key → the vuln_scripts slug that installs its agent.
 *
 * THE CONTRACT with src/utils/goad-agent-scripts.js. Both slugs must exist there
 * as active rows with os_target 'windows'; a slug named here and unseeded there
 * simply produces no rows from runVulnScripts' `SELECT ... WHERE slug = ANY($1)
 * AND is_active = true`, so the host installs nothing and says nothing.
 *
 * Only SIEM extensions appear. ws01 and lx01 are instrumented BY a SIEM, not
 * carriers of one — keying off `role === 'siem'` would be cuter and would break
 * the moment a SIEM-ish extension with no agent is added, so the mapping is
 * explicit.
 */
const GOAD_AGENT_SLUGS = Object.freeze({
  elk:   'goad-elk-agent',
  wazuh: 'goad-wazuh-agent',
});

/**
 * The roster entries that can run PowerShell.
 *
 * `role !== 'linux'` and not `role === 'windows'`: ROLE_RESOURCES' roles are
 * dc / member / workstation / linux, so Windows is the complement of one value
 * rather than a value of its own, and a new Windows role added to that table
 * would be included automatically instead of silently dropping out.
 */
function isWindowsRosterVm(v) {
  return !!v && v.role !== 'linux';
}

/**
 * What this spec's SIEM ticks imply, resolved once.
 *
 * @returns {{ slugs: string[], names: string[] }}
 *   slugs — agent slugs to install, in GOAD_AGENT_SLUGS order so two lanes with
 *           the same ticks produce the same list.
 *   names — the SPEC's own spelling of each Windows roster host. The spec's
 *           spelling, not the roster's: runVulnScripts matches with
 *           `s.vm_name === vm.name` against the deployed machine's spec name,
 *           and roster matching is case-insensitive everywhere else (see
 *           assertGoadRoster), so a spec that spells the lab's `ws01` as `WS01`
 *           deploys a machine named `WS01`, and an attachment naming `ws01`
 *           would match nothing and skip in silence.
 */
function resolveAgentPlan(spec) {
  const EMPTY = { slugs: [], names: [] };
  const goad = spec && spec.goad;
  if (!goad || !goad.enabled) return EMPTY;
  if (!Array.isArray(spec.vms) || spec.vms.length === 0) return EMPTY;

  // Cheap pre-filter BEFORE resolveGoadLab, and it is load-bearing twice over.
  // It keeps the overwhelmingly common no-SIEM deploy on exactly the code path
  // it ran before this module existed — no resolve, no allocation, the caller's
  // own objects handed straight back — and it means a spec that never ticked a
  // SIEM cannot acquire a NEW throw from assertValidLabDef by way of this
  // module.
  const wanted = Array.isArray(goad.extensions) ? goad.extensions : [];
  const ticked = new Set(wanted.map(k => String(k || '').trim().toLowerCase()));
  const slugs = Object.keys(GOAD_AGENT_SLUGS)
    .filter(k => ticked.has(k))
    .map(k => GOAD_AGENT_SLUGS[k]);
  if (slugs.length === 0) return EMPTY;

  // resolveGoadLab THROWS on a malformed spec-supplied goad.lab. Swallowed on
  // purpose: prepareGoadMacs calls the same resolver a few steps later in the
  // same deploy and throws the same assertValidLabDef message, so the lane still
  // fails loudly with the right diagnosis — it just does not fail HERE, in a
  // module whose whole job is additive. Attaching agents must never be the
  // reason a deploy dies, and it must never move an error message somewhere
  // that reads as though the agents caused it.
  let labDef;
  try {
    ({ labDef } = resolveGoadLab(spec));
  } catch (err) {
    console.warn(`[GOADAgents] Could not resolve the lab roster, so no SIEM agents were attached: ${err.message}`);
    return EMPTY;
  }

  const windowsRoster = new Set(
    (labDef.vms || []).filter(isWindowsRosterVm).map(v => String(v.name).toLowerCase())
  );

  const names = [];
  const seen = new Set();
  for (const vm of spec.vms) {
    const key = String((vm && vm.name) || '').toLowerCase();
    if (!key || seen.has(key) || !windowsRoster.has(key)) continue;
    seen.add(key);
    names.push(vm.name);
  }
  if (names.length === 0) return EMPTY;

  return { slugs, names };
}

/**
 * The flat attachments a spec's SIEM ticks imply.
 *
 * Shape matches deployChallengeLanes' `vulnScripts` exactly — [{ vm_name,
 * script_slug }] — because that is the shape runVulnScripts consumes.
 *
 * @returns {Array<{vm_name: string, script_slug: string}>} empty when no SIEM
 *          extension is selected.
 */
function goadAgentAttachments(spec) {
  const { slugs, names } = resolveAgentPlan(spec);
  const out = [];
  for (const name of names) {
    for (const slug of slugs) out.push({ vm_name: name, script_slug: slug });
  }
  return out;
}

/**
 * Append the agent slugs to spec.vms[].post_clone_scripts.
 *
 * APPEND, NEVER REPLACE. This is the sharpest edge in the whole change: CiAB
 * attaches its per-asset vuln-app planting through the same array, and dropping
 * one of those would break a completely unrelated feature with no error
 * anywhere — the lane comes up, the generated scan report describes services
 * that were never planted, and the exercise is quietly wrong. A slug already
 * present is left alone rather than repeated, so this is safe to apply twice (a
 * spec already attached to, then re-read and attached to again, is unchanged).
 *
 * NON-MUTATING, and identity-preserving wherever it can be:
 *   - nothing to attach          the SAME spec object comes back, so a deploy
 *                                that ticked no SIEM is byte-identical to what
 *                                it was before this module existed. That is the
 *                                regression bar, and the tests assert it by
 *                                identity rather than by deepEqual.
 *   - a VM that gets no slugs    the same vm object, by identity.
 *   - a VM that gets slugs       a shallow copy with a NEW post_clone_scripts
 *                                array. The caller's array is never pushed to:
 *                                a stored spec is shared with whoever else read
 *                                that row, and growing their array in place is
 *                                how one deploy's telemetry choice leaks into a
 *                                different lane.
 */
function attachGoadAgentScripts(spec) {
  const { slugs, names } = resolveAgentPlan(spec);
  if (slugs.length === 0 || names.length === 0) return spec;

  const targets = new Set(names);
  return {
    ...spec,
    vms: spec.vms.map((vm) => {
      if (!vm || !targets.has(vm.name)) return vm;
      const existing = Array.isArray(vm.post_clone_scripts) ? vm.post_clone_scripts : [];
      const missing = slugs.filter(s => !existing.includes(s));
      if (missing.length === 0) return vm;
      return { ...vm, post_clone_scripts: [...existing, ...missing] };
    }),
  };
}

/**
 * Fold the agent attachments into a caller's `vulnScripts` list.
 *
 * runVulnScripts reads the flat list and NOTHING ELSE — it never looks at
 * spec.vms[].post_clone_scripts — so this, not attachGoadAgentScripts, is what
 * actually causes an agent to be installed. Both exist because they are two
 * consumers of one decision: the spec form is what downstream readers of
 * ctx.spec see, the flat form is what runs.
 *
 * De-duplicated on (vm_name, script_slug), which makes it idempotent and makes
 * it safe for a caller that already derived the same entries from an
 * already-attached spec (CiAB's vulnScriptsFromSpec) — those arrive as exact
 * duplicates and are dropped, rather than installing the agent twice on one
 * host.
 *
 * @param {Array|null} vulnScripts the caller's list, possibly null
 * @param {object} spec
 * @returns {Array|null} the caller's own value, BY IDENTITY, when there is
 *          nothing to add — null stays null, because deployLaneVms branches on
 *          `vulnScripts && vulnScripts.length > 0` and an empty array in place
 *          of null would start writing a deployment_vuln_selections row for
 *          every lane that has no scripts at all.
 */
function withGoadAgentVulnScripts(vulnScripts, spec) {
  const additions = goadAgentAttachments(spec);
  if (additions.length === 0) return vulnScripts;

  const existing = Array.isArray(vulnScripts) ? vulnScripts : [];
  // NUL-joined so a machine literally named `a|b` cannot forge a collision with
  // a slug boundary. Cheap, and delimiter collisions in composed keys have bitten
  // this repo before.
  const key = (vmName, slug) => `${vmName}\u0000${slug}`;
  const seen = new Set(existing.map(s => key(s && s.vm_name, s && s.script_slug)));

  const merged = [...existing];
  for (const add of additions) {
    const k = key(add.vm_name, add.script_slug);
    if (seen.has(k)) continue;
    seen.add(k);
    merged.push(add);
  }
  return merged.length === existing.length ? vulnScripts : merged;
}

module.exports = {
  GOAD_AGENT_SLUGS,
  goadAgentAttachments,
  attachGoadAgentScripts,
  withGoadAgentVulnScripts,
};
