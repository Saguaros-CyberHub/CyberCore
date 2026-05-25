/**
 * ============================================================================
 * Workstation Templates — Admin CRUD
 * Manages rows in cybercore_template_catalog WHERE template_type = 'workstation'.
 * Users self-provision from these entries via their Workstations dashboard.
 * ============================================================================
 */

const express = require('express');
const router  = express.Router();
const { cybercoreQuery } = require('../../utils/cybercore-db');
const { proxmoxAPI }     = require('../../utils/proxmox');
const { authenticateToken, requireRole } = require('../../middleware/auth');

const adminOnly = requireRole('admin');

const TEMPLATE_COLS = `
  id AS template_id, template_key, os_name AS name, description, template_vmid,
  os_family, os_version, provider_type, node, module_key, max_instances, status,
  notes, metadata, is_active, created_at, updated_at
`;

/** Query Proxmox cluster resources and return the type ('qemu' or 'lxc') for a given VMID, or null. */
async function detectProviderType(vmid) {
  try {
    const resources = await proxmoxAPI('GET', '/api2/json/cluster/resources');
    const match = (resources || []).find(
      r => Number(r.vmid) === Number(vmid) && (r.type === 'qemu' || r.type === 'lxc')
    );
    return match ? match.type : null;
  } catch {
    return null;
  }
}

// GET /api/admin/workstation-templates
router.get('/workstation-templates', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { status } = req.query;
    const params = ['workstation'];
    const where  = ['template_type = $1'];
    if (status) where.push(`status = $${params.push(status)}`);

    const result = await cybercoreQuery(
      `SELECT ${TEMPLATE_COLS}
       FROM cybercore_template_catalog
       WHERE ${where.join(' AND ')}
       ORDER BY created_at DESC`,
      params
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/admin/workstation-templates/:id
router.get('/workstation-templates/:id', authenticateToken, adminOnly, async (req, res) => {
  try {
    const result = await cybercoreQuery(
      `SELECT ${TEMPLATE_COLS}
       FROM cybercore_template_catalog
       WHERE id = $1 AND template_type = 'workstation'`,
      [req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Template not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/admin/workstation-templates
router.post('/workstation-templates', authenticateToken, adminOnly, async (req, res) => {
  const { template_key, name, description, template_vmid, os_family, os_version,
          provider_type, module_key, max_instances, status, notes, metadata } = req.body;

  if (!template_key || !name || !template_vmid) {
    return res.status(400).json({ error: 'template_key, name, and template_vmid are required' });
  }
  if (provider_type && !['qemu', 'lxc'].includes(provider_type)) {
    return res.status(400).json({ error: "provider_type must be 'qemu' or 'lxc'" });
  }

  try {
    // Auto-detect type from Proxmox if not manually specified
    const resolvedType = provider_type || await detectProviderType(template_vmid);

    const result = await cybercoreQuery(
      `INSERT INTO cybercore_template_catalog
         (template_type, template_key, os_name, description, template_vmid,
          os_family, os_version, provider_type, module_key, max_instances, status, notes, metadata)
       VALUES ('workstation', $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
       RETURNING ${TEMPLATE_COLS}`,
      [
        template_key,
        name,
        description || null,
        Number(template_vmid),
        os_family || 'other',
        os_version || null,
        resolvedType || null,
        module_key || null,
        Number(max_instances) || 10,
        status || 'draft',
        notes || null,
        metadata ? JSON.stringify(metadata) : '{}',
      ]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: `Template key '${template_key}' already exists` });
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/admin/workstation-templates/:id
router.put('/workstation-templates/:id', authenticateToken, adminOnly, async (req, res) => {
  const { name, description, template_vmid, os_family, os_version, provider_type,
          module_key, max_instances, status, notes, metadata, is_active } = req.body;

  if (provider_type !== undefined && provider_type !== null && !['qemu', 'lxc'].includes(provider_type)) {
    return res.status(400).json({ error: "provider_type must be 'qemu', 'lxc', or null" });
  }

  try {
    const result = await cybercoreQuery(
      `UPDATE cybercore_template_catalog
       SET os_name       = COALESCE($1, os_name),
           description   = COALESCE($2, description),
           template_vmid = COALESCE($3, template_vmid),
           os_family     = COALESCE($4, os_family),
           os_version    = COALESCE($5, os_version),
           provider_type = COALESCE($6::varchar, provider_type),
           module_key    = COALESCE($7, module_key),
           max_instances = COALESCE($8, max_instances),
           status        = COALESCE($9, status),
           notes         = COALESCE($10, notes),
           metadata      = COALESCE($11::jsonb, metadata),
           is_active     = COALESCE($12, is_active),
           updated_at    = now()
       WHERE id = $13 AND template_type = 'workstation'
       RETURNING ${TEMPLATE_COLS}`,
      [
        name || null,
        description !== undefined ? description : null,
        template_vmid ? Number(template_vmid) : null,
        os_family || null,
        os_version !== undefined ? os_version : null,
        provider_type !== undefined ? (provider_type || null) : null,
        module_key || null,
        max_instances ? Number(max_instances) : null,
        status || null,
        notes !== undefined ? notes : null,
        metadata ? JSON.stringify(metadata) : null,
        is_active !== undefined ? Boolean(is_active) : null,
        req.params.id,
      ]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Template not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/admin/workstation-templates/:id
router.delete('/workstation-templates/:id', authenticateToken, adminOnly, async (req, res) => {
  try {
    const result = await cybercoreQuery(
      `DELETE FROM cybercore_template_catalog
       WHERE id = $1 AND template_type = 'workstation'
       RETURNING id AS template_id, os_name AS name`,
      [req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Template not found' });
    res.json({ success: true, deleted: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PATCH /api/admin/workstation-templates/:id/toggle — flip is_active
router.patch('/workstation-templates/:id/toggle', authenticateToken, adminOnly, async (req, res) => {
  try {
    const result = await cybercoreQuery(
      `UPDATE cybercore_template_catalog
       SET is_active = NOT is_active, updated_at = now()
       WHERE id = $1 AND template_type = 'workstation'
       RETURNING id AS template_id, os_name AS name, is_active`,
      [req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Template not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/admin/workstation-templates/:id/verify
// Queries live Proxmox cluster to confirm the template VMID exists and is cloneable.
// Also writes the resolved node and detected provider_type back into the catalog row.
router.get('/workstation-templates/:id/verify', authenticateToken, adminOnly, async (req, res) => {
  try {
    const tplResult = await cybercoreQuery(
      `SELECT id, template_vmid, node FROM cybercore_template_catalog
       WHERE id = $1 AND template_type = 'workstation'`,
      [req.params.id]
    );
    if (tplResult.rows.length === 0) return res.status(404).json({ error: 'Template not found' });

    const { id, template_vmid } = tplResult.rows[0];

    const resources = await proxmoxAPI('GET', '/api2/json/cluster/resources');
    const match = (resources || []).find(
      r => Number(r.vmid) === Number(template_vmid) && (r.type === 'qemu' || r.type === 'lxc')
    );

    if (!match) {
      await cybercoreQuery(
        `UPDATE cybercore_template_catalog
         SET is_active = false, status = CASE WHEN status = 'active' THEN 'draft' ELSE status END, updated_at = now()
         WHERE id = $1`,
        [id]
      );
      return res.json({
        found:         false,
        template_vmid,
        auto_disabled: true,
        message:       `VMID ${template_vmid} not found on any cluster node`,
      });
    }

    // Write node + auto-detected type back to the catalog
    await cybercoreQuery(
      `UPDATE cybercore_template_catalog
       SET node = COALESCE($1, node), provider_type = $2, updated_at = now()
       WHERE id = $3`,
      [match.node || null, match.type, id]
    );

    res.json({
      found:         true,
      template_vmid,
      node:          match.node,
      name:          match.name,
      type:          match.type,
      provider_type: match.type,
      status:        match.status,
      is_template:   match.template === 1,
      maxmem_gb:     match.maxmem  ? +(match.maxmem  / 1073741824).toFixed(1) : null,
      maxdisk_gb:    match.maxdisk ? +(match.maxdisk / 1073741824).toFixed(0) : null,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
