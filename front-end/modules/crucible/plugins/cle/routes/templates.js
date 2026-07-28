/**
 * CLE Plugin — Templates Routes
 * Handles VM and vulnerable machine templates available for provisioning
 */

const express = require('express');
const router = express.Router();
const { requireRole } = require('../../../../../src/middleware/auth');
const { cybercoreQuery } = require('../../../../../src/utils/cybercore-db');
const { resolveConsole, resolveNicModel } = require('../../../../../src/utils/lane-deployer');

const instructorOnly = requireRole('instructor', 'admin');

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

    const templates = result.rows.map(t => {
      const con = resolveConsole(t);
      return {
        ...t,
        provider_type:    t.provider_type || 'qemu',
        console_protocol: con.protocol,
        console_port:     con.wanPort,
        nic_model:        resolveNicModel(t),
        // Whether the student gets credentials automatically. 'template' means
        // the image bakes an account; otherwise they come from cloud-init, and
        // a template with neither leaves the student at a login prompt.
        credentials:      t.metadata?.default_rdp_user ? 'template' : 'cloud-init',
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
      return res.json({ templates, hint });
    }

    res.json({ templates });
  } catch (error) {
    console.error('[CLE] Get VM templates error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

/**
 * GET /api/cle/templates/vulnerable — List available challenge/lab templates.
 *
 * Excludes the per-course network reservations: every CLE course creates its own
 * crucible_challenge row (spec.cle = true) purely to own a VXLAN block, and
 * those were showing up here as if they were deployable labs.
 */
router.get('/vulnerable', instructorOnly, async (req, res) => {
  try {
    const result = await cybercoreQuery(`
      SELECT
        challenge_id  AS template_id,
        name,
        difficulty,
        description
      FROM crucible_challenge
      WHERE status = 'active'
        AND spec->>'cle' IS DISTINCT FROM 'true'
      ORDER BY name ASC
    `);

    res.json({ templates: result.rows });
  } catch (error) {
    console.error('[CLE] Get vulnerable templates error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
