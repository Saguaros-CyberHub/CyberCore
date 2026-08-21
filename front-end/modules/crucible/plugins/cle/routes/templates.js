/**
 * CLE Plugin — Templates Routes
 * Handles VM and vulnerable machine templates available for provisioning
 */

const express = require('express');
const router = express.Router();
const { requireRole } = require('../../../../../src/middleware/auth');
const { cybercoreQuery } = require('../../../../../src/utils/cybercore-db');
const { proxmoxAPI } = require('../../../../../src/utils/proxmox');
const {
  resolveConsole, resolveNicModel, RESOURCE_LIMITS,
} = require('../../../../../src/utils/lane-deployer');
const challengeLaneDeployer = require('../../../../../src/utils/challenge-lane-deployer');
const vulnLab = require('../utils/vuln-lab-provision');
const { goadHostNames } = require('../../../../../src/utils/topology-validate');

const instructorOnly = requireRole('instructor', 'admin');

/**
 * The sizing each template ships with, so the provision form can pre-fill CPU /
 * RAM / disk with what the instructor would get if they changed nothing.
 *
 * One cluster-wide call rather than a per-template config read: the resource
 * listing already carries maxcpu/maxmem/maxdisk for every VM including
 * templates. Read-only — nothing here modifies a template; the numbers are
 * applied to each clone at provision time.
 *
 * Returns {} when Proxmox is unreachable; the picker then just offers no
 * defaults rather than failing to load.
 */
async function loadTemplateDefaults(vmids) {
  if (!vmids.length) return {};
  try {
    const resources = await proxmoxAPI('GET', '/api2/json/cluster/resources?type=vm');
    const wanted = new Set(vmids.map(Number));
    const byVmid = {};
    for (const r of (resources || [])) {
      if (!wanted.has(Number(r.vmid))) continue;
      byVmid[Number(r.vmid)] = {
        cores:     r.maxcpu ? Number(r.maxcpu) : null,
        memory_mb: r.maxmem ? Math.round(Number(r.maxmem) / 1048576) : null,
        disk_gb:   r.maxdisk ? Math.round(Number(r.maxdisk) / 1073741824) : null,
      };
    }
    return byVmid;
  } catch (err) {
    console.warn(`[CLE] Could not read template sizing from Proxmox: ${err.message}`);
    return {};
  }
}

/**
 * GET /api/cle/templates/vm — List workstation templates that can actually be
 * provisioned.
 *
 * Filters on the SAME conditions the provision endpoint validates against
 * (is_active AND status='active' AND a template_vmid). The old version listed
 * every is_active row regardless of status or VMID, so the dropdown could offer
 * a template that /provision then rejected.
 *
 * Returns the shape the picker needs to tell the instructor what they're about
 * to deploy — OS family, QEMU vs LXC, and how the student will connect.
 */
router.get('/vm', instructorOnly, async (req, res) => {
  try {
    const result = await cybercoreQuery(`
      SELECT
        id            AS template_id,
        os_name       AS name,
        template_key,
        description,
        os_family,
        os_version,
        provider_type,
        template_vmid,
        node,
        metadata,
        is_active
      FROM cybercore_template_catalog
      WHERE template_type = 'workstation'
        AND is_active     = TRUE
        AND status        = 'active'
        AND template_vmid IS NOT NULL
      ORDER BY os_name ASC
    `);

    const defaultsByVmid = await loadTemplateDefaults(result.rows.map(r => r.template_vmid));

    const templates = result.rows.map(t => {
      const con = resolveConsole(t);
      return {
        ...t,
        provider_type:    t.provider_type || 'qemu',
        console_protocol: con.protocol,
        console_port:     con.wanPort,
        nic_model:        resolveNicModel(t),
        // What this image is sized at today. The provision form seeds its
        // CPU/RAM/disk inputs from these, so "deploy unchanged" and "deploy
        // adjusted" go through the same code path.
        default_resources: defaultsByVmid[Number(t.template_vmid)] || null,
        // Where the student's login comes from. Three states, not two: keying
        // only on default_rdp_user made a template with EMPTY metadata look
        // identical to a correctly-configured one, so the misconfiguration that
        // produces an unauthenticatable console was invisible in the picker.
        //   'template'         — the image bakes both account and password
        //   'cloud-init'       — account name pinned by the image, fresh password per lane
        //   'cloud-init-guess' — nothing declared. On Windows the deploy falls back
        //                        to the standard baked account and warns; the UI
        //                        should say so, because a wrong guess reaches the
        //                        student as an RDP login failure.
        credentials:      t.metadata?.default_rdp_user ? 'template'
                          : t.metadata?.cloud_init_user ? 'cloud-init'
                          : 'cloud-init-guess',
        cloud_init_user:  t.metadata?.cloud_init_user || null,
      };
    });

    // An empty picker is ambiguous — "none exist" and "some exist but are
    // filtered out" look identical to the instructor. The most common cause is
    // a template registered with the admin form's DEFAULT status of 'draft',
    // which this endpoint (and the provision endpoint) deliberately exclude. Say
    // so rather than leaving them to guess.
    if (templates.length === 0) {
      const blocked = await cybercoreQuery(`
        SELECT os_name, status, is_active, template_vmid
          FROM cybercore_template_catalog
         WHERE template_type = 'workstation'
           AND (status <> 'active' OR is_active = FALSE OR template_vmid IS NULL)
         ORDER BY os_name ASC
      `);
      let hint = 'No workstation templates are registered yet. Add one in '
               + 'Admin -> Workstation Templates.';
      if (blocked.rows.length > 0) {
        hint = `${blocked.rows.length} workstation template(s) exist but are not `
             + 'usable yet: ' + blocked.rows.map(r => {
                 const why = r.template_vmid == null ? 'no VMID (press Verify)'
                           : !r.is_active            ? 'is_active = false'
                           : `status = ${r.status}`;
                 return `${r.os_name} (${why})`;
               }).join(', ')
             + '. Fix in Admin -> Workstation Templates.';
      }
      return res.json({ templates, hint, resource_limits: RESOURCE_LIMITS });
    }

    // Shipped alongside the templates so the form's min/max come from the same
    // constants the provision endpoint validates against, instead of a second
    // copy that can drift out of sync.
    res.json({ templates, resource_limits: RESOURCE_LIMITS });
  } catch (error) {
    console.error('[CLE] Get VM templates error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

/** Never let one unrenderable environment empty the picker for every other. */
function safeTopologyPayload(spec, subnetScheme, key) {
  try {
    return buildTopologyPayload(spec, subnetScheme);
  } catch (err) {
    console.warn(`[CLE] Could not build a topology preview for '${key}': ${err.message}`);
    return { subnet_scheme: subnetScheme, network: null, goad_host_names: [], vms: [] };
  }
}

/**
 * The drawable subset of a challenge spec: machines, their segment attachments
 * and the canvas layout, with nothing sensitive attached.
 *
 * Per-VM keys are enumerated rather than spread, so a spec key added later for
 * some other purpose cannot start leaking to instructors by accident.
 */
function buildTopologyPayload(spec, subnetScheme) {
  const vms = challengeLaneDeployer.resolveSpecVms(spec || {}, '');
  return {
    subnet_scheme: subnetScheme,
    // Canvas positions, so a hand-arranged environment draws the way its author
    // laid it out instead of being auto-arranged into a different shape.
    network: (spec && spec.network) || null,
    // goadHostNames returns NULL for a non-GOAD environment, not an empty Set —
    // and Array.from(null) throws, which took the whole endpoint down with it.
    goad_host_names: Array.from(goadHostNames(spec || {}) || []),
    vms: vms.map(v => ({
      name:             v.name,
      role:             v.role || null,
      os:               v.os || null,
      os_family:        v.os_family || null,
      type:             v.type || 'qemu',
      template_vmid:    v.template_vmid || null,
      nics:             v.nics || null,
      layout:           v.layout || null,
      console_role:     v.console_role || null,
      console_protocol: v.console_protocol || null,
    })),
  };
}

/**
 * GET /api/cle/templates/vulnerable — Vulnerable applications an instructor can
 * actually deploy, and in which mode.
 *
 * Excludes the per-course network reservations: every CLE course creates its own
 * crucible_challenge row (spec.cle = true) purely to own a VXLAN block, and
 * those were showing up here as if they were deployable labs.
 *
 * Each row carries the capability flags POST /labs/deploy validates against
 * (can_deploy_lane / can_attach plus the reason when either is false) and the
 * live free-lane count in the challenge's own VXLAN block. The picker was
 * previously a bare name list, so an instructor could select a challenge with no
 * VMs, no reserved network, or a v3 topology and only find out at deploy time.
 */
router.get('/vulnerable', instructorOnly, async (req, res) => {
  try {
    const result = await cybercoreQuery(`
      SELECT
        challenge_id  AS template_id,
        challenge_key,
        name,
        difficulty,
        description,
        subnet_scheme,
        module_key,
        spec
      FROM crucible_challenge
      WHERE status = 'active'
        AND spec->>'cle' IS DISTINCT FROM 'true'
      ORDER BY name ASC
    `);

    const usable = [];
    const blocked = [];

    for (const row of result.rows) {
      const spec = typeof row.spec === 'string' ? JSON.parse(row.spec) : (row.spec || {});
      const caps = vulnLab.describeChallenge({
        challenge_id:  row.template_id,
        challenge_key: row.challenge_key,
        name:          row.name,
        subnet_scheme: row.subnet_scheme,
        spec,
      });

      // Neither mode possible = not a deployable lab. Report it separately with
      // the reason instead of offering it.
      if (!caps.can_deploy_lane && !caps.can_attach) {
        blocked.push({ name: row.name, reason: caps.lane_blockers.join('; ') || 'not deployable' });
        continue;
      }

      // Free-lane count is only meaningful for the lane mode, and costs a query
      // each — skip it for attach-only challenges.
      let freeLanes = null;
      if (caps.can_deploy_lane) {
        freeLanes = await vulnLab.countFreeLanes(caps.vxlan_block).catch(() => null);
      }

      usable.push({
        template_id:   row.template_id,
        challenge_key: row.challenge_key,
        name:          row.name,
        difficulty:    row.difficulty,
        description:   row.description,
        module_key:    row.module_key,
        ...caps,
        free_lanes:    freeLanes,
        // Enough to DRAW the environment before it is deployed, and no more.
        //
        // Deliberately not the raw spec: that carries vxlan_block, zone,
        // template_node and spec.goad.admin_password, none of which an
        // instructor's browser has any business holding. The client re-wraps
        // this into the row shape CyberCoreTopologySeed.specToGraph expects.
        //
        // This exists because the obvious source — GET /admin/lab-templates/:id,
        // which the admin topology viewer uses — is admin-only, and an
        // instructor cannot call it.
        // Best-effort: a spec this cannot draw is still an environment that
        // deploys. Letting one bad row throw here emptied the whole picker.
        topology: safeTopologyPayload(spec, caps.subnet_scheme, row.challenge_key),
      });
    }

    // An empty picker is ambiguous — "none exist" and "some exist but are all
    // undeployable" look identical. Say which, the way GET /vm already does.
    const payload = { templates: usable };
    if (usable.length === 0) {
      payload.hint = blocked.length > 0
        ? `${blocked.length} environment(s) exist but none can be deployed: `
          + blocked.map(b => `${b.name} (${b.reason})`).join(', ')
          + '. Create one in Admin -> Environment Templates.'
        : 'No environments are registered yet. Create one in Admin -> Environment Templates.';
    } else if (blocked.length > 0) {
      payload.excluded = blocked;
    }
    res.json(payload);
  } catch (error) {
    console.error('[CLE] Get vulnerable templates error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
