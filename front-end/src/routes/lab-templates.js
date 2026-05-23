/**
 * ============================================================================
 * Challenge Templates & Vuln Script Library Routes
 * ============================================================================
 * vuln_scripts → clinic_db (query)
 * crucible_challenge → cybercore_db (cybercoreQuery)
 * vm_template_catalog → cybercore_db (cybercoreQuery)
 * deployment_vuln_selections → clinic_db (query)
 */

const express = require('express');
const router = express.Router();
const { query } = require('../utils/db');
const { cybercoreQuery } = require('../utils/cybercore-db');
const { proxmoxAPI } = require('../utils/proxmox');
const { getDefaultTemplateNode } = require('../utils/site-config');
const { authenticateToken, requireRole } = require('../middleware/auth');
const goadDeploy = require('../utils/goad-deploy');

const adminOnly = requireRole('admin');

// GET /api/admin/goad/labs — single source of truth for the admin UI's
// GOAD version dropdown. Returns the lab catalog from goad-deploy.js.
router.get('/goad/labs', authenticateToken, adminOnly, (req, res) => {
  res.json({
    default_lab: goadDeploy.DEFAULT_LAB,
    // IPs shown here are ILLUSTRATIVE — the actual lane subnet is decided
    // per-deploy by the challenge's subnet_scheme (v1: 192.18.0.X shared,
    // v2: 10.<vxh>.<vxl>.X unique per lane). UI shows v1-style addresses
    // because the last-octet pattern is the relevant invariant; the /24
    // base is a deploy-time detail.
    labs: Object.entries(goadDeploy.GOAD_LABS).map(([key, lab]) => ({
      key,
      displayName: lab.displayName,
      description: lab.description,
      forestRoot:  lab.forestRoot,
      vms: lab.vms.map(v => ({
        name:          v.name,
        role:          v.role,
        os:            v.os,
        template_vmid: v.template_vmid,
        ip:            goadDeploy.buildIp('192.18.0', v.ipOctet),  // illustrative
        ip_octet:      v.ipOctet,                                  // authoritative
        nic_model:     v.nic_model
      }))
    })),
    infra_ips: Object.fromEntries(
      Object.entries(goadDeploy.INFRA_IP_OCTETS).map(([k, octet]) => [k, goadDeploy.buildIp('192.18.0', octet)])
    ),
    infra_ip_octets: goadDeploy.INFRA_IP_OCTETS  // authoritative (last-octet only)
  });
});

// ============================================================================
// VULNERABILITY SCRIPTS (clinic_db)
// ============================================================================

// GET /api/admin/vuln-scripts
router.get('/vuln-scripts', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { category, os_target, difficulty, script_type, active_only } = req.query;
    let where = [];
    let params = [];
    let idx = 1;

    if (category)    { where.push(`category = $${idx++}`);    params.push(category); }
    if (os_target)   { where.push(`os_target = $${idx++}`);   params.push(os_target); }
    if (difficulty)  { where.push(`difficulty = $${idx++}`);  params.push(difficulty); }
    if (script_type) { where.push(`script_type = $${idx++}`); params.push(script_type); }
    if (active_only !== 'false') { where.push(`is_active = true`); }

    const whereClause = where.length > 0 ? `WHERE ${where.join(' AND ')}` : '';

    // Baseline scripts sort ahead of vulnerable within each category, so the
    // admin-facing list naturally shows the "just make it work" options first.
    const result = await query(
      `SELECT id, slug, name, description, category, script_type, os_target, difficulty,
              services_exposed, depends_on, estimated_runtime_sec, is_active, created_at,
              LENGTH(script_content) AS script_length
       FROM vuln_scripts ${whereClause}
       ORDER BY category,
                CASE script_type WHEN 'baseline' THEN 0 WHEN 'vulnerable' THEN 1 ELSE 2 END,
                name`,
      params
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/admin/vuln-scripts/:id
router.get('/vuln-scripts/:id', authenticateToken, adminOnly, async (req, res) => {
  try {
    const result = await query(`SELECT * FROM vuln_scripts WHERE id = $1`, [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Script not found' });
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/admin/vuln-scripts
router.post('/vuln-scripts', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { slug, name, description, category, script_type, os_target, difficulty, script_content, services_exposed, depends_on, estimated_runtime_sec, script_args } = req.body;
    if (!slug || !name || !category || !script_content) {
      return res.status(400).json({ error: 'slug, name, category, and script_content are required' });
    }
    const type = (script_type || 'vulnerable').toLowerCase();
    if (!['baseline','vulnerable'].includes(type)) {
      return res.status(400).json({ error: `script_type must be 'baseline' or 'vulnerable' (got '${script_type}')` });
    }

    const result = await query(
      `INSERT INTO vuln_scripts (slug, name, description, category, script_type, os_target, difficulty, script_content, services_exposed, depends_on, estimated_runtime_sec, script_args)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
       RETURNING *`,
      [slug, name, description || null, category, type, os_target || 'windows', difficulty || 'intermediate',
       script_content, JSON.stringify(services_exposed || []), depends_on || [], estimated_runtime_sec || 60, script_args || '']
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    if (error.code === '23505') return res.status(409).json({ error: `Script slug '${req.body.slug}' already exists` });
    res.status(500).json({ error: error.message });
  }
});

// PUT /api/admin/vuln-scripts/:id
router.put('/vuln-scripts/:id', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { slug, name, description, category, script_type, os_target, difficulty, script_content, services_exposed, depends_on, estimated_runtime_sec, is_active, script_args } = req.body;
    if (script_type !== undefined && !['baseline','vulnerable'].includes(String(script_type).toLowerCase())) {
      return res.status(400).json({ error: `script_type must be 'baseline' or 'vulnerable' (got '${script_type}')` });
    }
    const result = await query(
      `UPDATE vuln_scripts SET
        slug = COALESCE($2, slug), name = COALESCE($3, name), description = $4,
        category = COALESCE($5, category), script_type = COALESCE($6, script_type),
        os_target = COALESCE($7, os_target),
        difficulty = COALESCE($8, difficulty), script_content = COALESCE($9, script_content),
        services_exposed = COALESCE($10, services_exposed), depends_on = COALESCE($11, depends_on),
        estimated_runtime_sec = COALESCE($12, estimated_runtime_sec), is_active = COALESCE($13, is_active),
        script_args = COALESCE($14, script_args)
       WHERE id = $1 RETURNING *`,
      [req.params.id, slug, name, description, category,
       script_type ? String(script_type).toLowerCase() : null,
       os_target, difficulty,
       script_content, services_exposed ? JSON.stringify(services_exposed) : null,
       depends_on, estimated_runtime_sec, is_active, script_args]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Script not found' });
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// DELETE /api/admin/vuln-scripts/:id
router.delete('/vuln-scripts/:id', authenticateToken, adminOnly, async (req, res) => {
  try {
    await query(`UPDATE vuln_scripts SET is_active = false WHERE id = $1`, [req.params.id]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/admin/vm-templates — list active VM templates from vm_template_catalog
router.get('/vm-templates', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { os_family, active_only } = req.query;
    const where = [];
    const params = [];
    let idx = 1;
    if (os_family) { where.push(`os_family = $${idx++}`); params.push(os_family); }
    if (active_only !== 'false') where.push(`is_active = true`);
    const whereClause = where.length ? `WHERE ${where.join(' AND ')}` : '';

    const result = await cybercoreQuery(
      `SELECT id, os_family, os_name, os_version, template_vmid, node,
              role_hints, preferred, notes, is_active, created_at
       FROM vm_template_catalog ${whereClause}
       ORDER BY os_family, os_name, os_version NULLS LAST`,
      params
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/admin/vm-templates/sync-nodes
// Queries live Proxmox cluster resources and writes the actual node for every
// template VMID back into vm_template_catalog. Safe to call repeatedly.
router.post('/vm-templates/sync-nodes', authenticateToken, adminOnly, async (req, res) => {
  try {
    const [catalogResult, resources] = await Promise.all([
      cybercoreQuery(`SELECT id, template_vmid, node FROM vm_template_catalog`),
      proxmoxAPI('GET', '/api2/json/cluster/resources')
    ]);

    const vmMap = {};
    for (const r of resources) {
      if (r.type === 'qemu' || r.type === 'lxc') vmMap[Number(r.vmid)] = r.node;
    }

    const updated = [];
    const unchanged = [];
    const not_found = [];

    for (const row of catalogResult.rows) {
      const liveNode = vmMap[Number(row.template_vmid)];
      if (!liveNode) {
        not_found.push(row.template_vmid);
        continue;
      }
      if (liveNode !== row.node) {
        await cybercoreQuery(
          `UPDATE vm_template_catalog SET node = $1 WHERE id = $2`,
          [liveNode, row.id]
        );
        updated.push({ vmid: row.template_vmid, from: row.node, to: liveNode });
      } else {
        unchanged.push(row.template_vmid);
      }
    }

    res.json({ updated, unchanged, not_found });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/admin/vuln-scripts-categories
router.get('/vuln-scripts-categories', authenticateToken, adminOnly, async (req, res) => {
  try {
    const result = await query(
      `SELECT DISTINCT category, COUNT(*) AS count FROM vuln_scripts WHERE is_active = true GROUP BY category ORDER BY category`
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// ============================================================================
// CHALLENGE MANAGEMENT (crucible_challenge in cybercore_db)
// ============================================================================

// GET /api/admin/lab-templates — list challenges as "templates"
router.get('/lab-templates', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { module } = req.query;
    const mod = (module || 'crucible').replace(/[^a-z0-9_]/gi, '');
    const result = await cybercoreQuery(
      `SELECT challenge_id AS id, challenge_key, name, description, difficulty, spec, status, created_at
       FROM ${mod}_challenge
       WHERE status = 'active'
       ORDER BY created_at DESC`
    );

    // Enrich with VM count from spec
    const rows = result.rows.map(r => {
      const spec = typeof r.spec === 'string' ? JSON.parse(r.spec) : (r.spec || {});
      return {
        ...r,
        vm_count: (spec.vms || []).length || (spec.template_vmid ? 1 : 0),
        phantom_count: (spec.phantom_assets || []).length,
        vxlan_block: spec.vxlan_block || null
      };
    });

    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/admin/lab-templates/:id
router.get('/lab-templates/:id', authenticateToken, adminOnly, async (req, res) => {
  try {
    const result = await cybercoreQuery(
      `SELECT * FROM crucible_challenge WHERE challenge_id = $1`, [req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Challenge not found' });
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// PUT /api/admin/lab-templates/:id — update challenge spec (add VMs, phantom assets, vuln defaults)
router.put('/lab-templates/:id', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { name, description, difficulty, spec } = req.body;

    const result = await cybercoreQuery(
      `UPDATE crucible_challenge SET
        name = COALESCE($2, name),
        description = COALESCE($3, description),
        difficulty = COALESCE($4, difficulty),
        spec = COALESCE($5::jsonb, spec),
        updated_at = NOW()
       WHERE challenge_id = $1
       RETURNING *`,
      [req.params.id, name, description, difficulty, spec ? JSON.stringify(spec) : null]
    );

    if (result.rows.length === 0) return res.status(404).json({ error: 'Challenge not found' });
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// DELETE /api/admin/lab-templates/:id — delete challenge + clean up SDN
router.delete('/lab-templates/:id', authenticateToken, adminOnly, async (req, res) => {
  try {
    // Get challenge info
    const chalResult = await cybercoreQuery(
      `SELECT * FROM crucible_challenge WHERE challenge_id = $1`, [req.params.id]
    );
    if (chalResult.rows.length === 0) return res.status(404).json({ error: 'Challenge not found' });

    const challenge = chalResult.rows[0];
    const spec = typeof challenge.spec === 'string' ? JSON.parse(challenge.spec) : (challenge.spec || {});
    const zoneAbbrev = spec.zone?.abbrev;
    const vxlanBlock = spec.vxlan_block;

    let vnetsRemoved = 0;
    let zoneRemoved = false;

    // Clean up VNets and SDN zone from Proxmox
    if (vxlanBlock?.start && vxlanBlock?.end) {
      // Check for active lanes using this challenge's VXLAN block
      const activeLanes = await cybercoreQuery(
        `SELECT COUNT(*) AS cnt FROM cybercore_lane
         WHERE vxlan_id BETWEEN $1 AND $2 AND status IN ('active', 'deploying')`,
        [vxlanBlock.start, vxlanBlock.end]
      );

      if (parseInt(activeLanes.rows[0].cnt) > 0) {
        return res.status(400).json({
          error: `Cannot delete: ${activeLanes.rows[0].cnt} active lane(s) are using this challenge's VXLAN block`
        });
      }

      // Remove VNets
      try {
        const vnets = await proxmoxAPI('GET', '/api2/json/cluster/sdn/vnets');
        for (const vnet of vnets) {
          if (vnet.tag >= vxlanBlock.start && vnet.tag <= vxlanBlock.end) {
            try {
              await proxmoxAPI('DELETE', `/api2/json/cluster/sdn/vnets/${vnet.vnet}`);
              vnetsRemoved++;
            } catch (e) {
              console.error(`[DeleteChallenge] Failed to remove VNet ${vnet.vnet}: ${e.message}`);
            }
          }
        }
      } catch (e) {
        console.error(`[DeleteChallenge] Failed to query VNets: ${e.message}`);
      }

      // Remove SDN zone if it exists and has no remaining VNets
      if (zoneAbbrev) {
        try {
          const remainingVnets = await proxmoxAPI('GET', '/api2/json/cluster/sdn/vnets');
          const zoneStillHasVnets = remainingVnets.some(v => v.zone === zoneAbbrev);
          if (!zoneStillHasVnets) {
            await proxmoxAPI('DELETE', `/api2/json/cluster/sdn/zones/${zoneAbbrev}`);
            zoneRemoved = true;
          }
        } catch (e) {
          console.error(`[DeleteChallenge] Failed to remove zone ${zoneAbbrev}: ${e.message}`);
        }
      }

      // Reload SDN if we changed anything
      if (vnetsRemoved > 0 || zoneRemoved) {
        try { await proxmoxAPI('PUT', '/api2/json/cluster/sdn'); } catch (_) {}
      }
    }

    // Delete the challenge record
    await cybercoreQuery(`DELETE FROM crucible_challenge WHERE challenge_id = $1`, [req.params.id]);

    console.log(`[DeleteChallenge] Deleted '${challenge.challenge_key}': ${vnetsRemoved} VNets removed, zone removed: ${zoneRemoved}`);

    res.json({
      success: true,
      challenge_key: challenge.challenge_key,
      vnets_removed: vnetsRemoved,
      zone_removed: zoneRemoved
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// ============================================================================
// CREATE CHALLENGE (DB + SDN Zone + VNets — replaces N8N workflow)
// ============================================================================

// POST /api/admin/create-lab — full challenge creation with SDN infrastructure
router.post('/create-lab', authenticateToken, adminOnly, async (req, res) => {
  try {
    const {
      name, challenge_key, description, difficulty, zone_abbrev,
      template_vmid, vms: vmsList, max_lanes, module, challenge_type,
      goad, subnet_scheme
    } = req.body;

    if (!name || !challenge_key || !max_lanes) {
      return res.status(400).json({
        error: 'name, challenge_key, and max_lanes are required'
      });
    }

    // Must have either vms array or a single template_vmid
    if ((!vmsList || vmsList.length === 0) && !template_vmid) {
      return res.status(400).json({ error: 'At least one VM with a template_vmid is required' });
    }

    // Validate zone_abbrev: 1-8 alphanumeric chars (auto-generated if not provided)
    const finalZone = (zone_abbrev || challenge_key.replace(/[^a-z0-9]/gi, '').substring(0, 8)).toLowerCase();
    if (!/^[a-z0-9]{1,8}$/.test(finalZone)) {
      return res.status(400).json({ error: 'zone_abbrev must be 1-8 alphanumeric characters' });
    }

    const moduleKey = (module || 'crucible').toLowerCase();

    // subnet_scheme: v1/v2 = single-subnet lanes; v3 = segmented "DMZ" lanes
    // (two SDN VNets per lane). Defaults to v1 for back-compat.
    const subnetScheme = ['v1', 'v2', 'v3'].includes(subnet_scheme) ? subnet_scheme : 'v1';
    // A v3 lane's internal VNet uses tag = (vxlanId + this offset).
    // MUST match V3_INTERNAL_TAG_OFFSET in front-end/src/routes/admin.js.
    const V3_INTERNAL_TAG_OFFSET = 4000000;

    const numLanes = parseInt(max_lanes);
    if (numLanes < 1 || numLanes > 200) {
      return res.status(400).json({ error: 'max_lanes must be between 1 and 200' });
    }

    // Map difficulty string to integer (matches N8N workflow convention)
    const difficultyMap = { beginner: 1, easy: 1, intermediate: 2, medium: 2, hard: 3, advanced: 3, expert: 4, impossible: 5 };
    const difficultyInt = difficultyMap[(difficulty || 'intermediate').toLowerCase()] || 2;

    const statusUpdates = [];
    const pushStatus = (msg) => { statusUpdates.push(msg); console.log(`[CreateChallenge] ${msg}`); };

    // 1. Find next available VXLAN block
    pushStatus('Querying existing VXLAN blocks...');
    const existingBlocks = await cybercoreQuery(
      `SELECT
        (spec->'vxlan_block'->>'start')::int AS vxlan_start,
        (spec->'vxlan_block'->>'end')::int AS vxlan_end
       FROM crucible_challenge
       WHERE spec->'vxlan_block'->>'start' IS NOT NULL`
    );

    let maxEnd = 9999; // Default: first block starts at 10000
    for (const row of existingBlocks.rows) {
      if (row.vxlan_end && row.vxlan_end > maxEnd) maxEnd = row.vxlan_end;
    }
    const vxlanStart = maxEnd + 1;
    const vxlanEnd = vxlanStart + numLanes - 1;
    pushStatus(`Allocated VXLAN block: ${vxlanStart}–${vxlanEnd} (${numLanes} lanes)`);

    // 2. Build spec with multi-VM support
    const resolvedZone = finalZone;

    // Build VMs array from input
    const specVMs = (vmsList && vmsList.length > 0)
      ? vmsList.map((vm, idx) => ({
          name: vm.name || `vm${idx + 1}`,
          role: vm.role || 'Server',
          os: vm.os || 'Unknown',
          template_vmid: parseInt(vm.template_vmid),
          type: vm.type || 'qemu',
          vm_offset: parseInt(vm.vm_offset) || 600000,
          services: vm.services || [],
          default_scripts: vm.default_scripts || [],
          hostname: `${vm.name || challenge_key}.local`
        }))
      : [{
          name: challenge_key,
          role: 'primary',
          os: 'Unknown',
          template_vmid: parseInt(template_vmid),
          type: 'qemu',
          vm_offset: 600000,
          hostname: `${challenge_key}.local`
        }];

    const spec = {
      zone: { abbrev: resolvedZone },
      template_vmid: specVMs[0].template_vmid, // backward compat for single-VM deploy
      template_node: getDefaultTemplateNode(),
      vxlan_block: { start: vxlanStart, end: vxlanEnd },
      vms: specVMs,
      limits: {
        max_concurrent_lanes: numLanes
      }
    };

    // GOAD: when goad.enabled=true, embed the GOAD config so deploy paths can
    // detect it and run the post-clone provisioning (controller LXC + ansible
    // playbook). Defaults match what bake-goad-controller.sh / template 1004
    // ship with so admins can toggle this on without filling in every field.
    if (goad && goad.enabled) {
      spec.goad = {
        enabled: true,
        version:          goad.version          || 'light',
        domain:           goad.domain           || 'cybersaguaros.local',
        child_subdomain:  goad.child_subdomain  || 'tumamoc',
        admin_user:       goad.admin_user       || 'Administrator',
        admin_password:   goad.admin_password   || 'vagrant',
        include_kali:     goad.include_kali !== false  // default true
      };
    }

    // 3. Insert challenge record into cybercore_db
    pushStatus('Inserting challenge record...');
    const insertResult = await cybercoreQuery(
      `INSERT INTO crucible_challenge (challenge_key, name, description, difficulty, spec, status, subnet_scheme)
       VALUES ($1, $2, $3, $4, $5::jsonb, 'active', $6)
       RETURNING challenge_id, challenge_key`,
      [challenge_key, name, description || null, difficultyInt, JSON.stringify(spec), subnetScheme]
    );
    const challengeId = insertResult.rows[0].challenge_id;
    pushStatus(`Challenge created: ${challengeId}`);

    // 4. Check if SDN zone exists, create if not
    pushStatus('Checking SDN zones...');
    const zones = await proxmoxAPI('GET', '/api2/json/cluster/sdn/zones');
    const zoneExists = zones.some(z => z.zone === finalZone);

    if (!zoneExists) {
      pushStatus(`Creating SDN zone '${finalZone}'...`);

      // Get all cluster node IPs
      const nodeList = await proxmoxAPI('GET', '/api2/json/nodes');
      const nodeNames = nodeList.map(n => n.node).join(',');

      // Build peer IPs — try to get from node status, fallback to known pattern
      const peerIps = [];
      for (const node of nodeList) {
        try {
          const nodeStatus = await proxmoxAPI('GET', `/api2/json/nodes/${node.node}/status`);
          // Try to find the IP from network info
          if (nodeStatus.network) {
            for (const [, iface] of Object.entries(nodeStatus.network)) {
              if (iface.address && !iface.address.startsWith('127.')) {
                peerIps.push(iface.address);
                break;
              }
            }
          }
        } catch (_) {}
      }

      // Fallback: use known Tailscale IPs if we couldn't get them dynamically
      const peers = peerIps.length === nodeList.length
        ? peerIps.join(',')
        : nodeList.map((_, i) => `100.100.10.${10 + i}`).join(',');

      // NOTE: deliberately NOT passing ipam: 'pve'. CyberCore manages lane IP
      // space internally (192.18.0.0/24 via dnsmasq inside each lane's gateway LXC).
      // Setting ipam: 'pve' here makes Proxmox SDN write per-VNet config files into
      // /etc/dnsmasq.d/ on every node, which collides with the host network's
      // boot-time post-up hooks and has crashed clusters at reboot. Leave ipam unset.
      await proxmoxAPI('POST', '/api2/json/cluster/sdn/zones', {
        zone: finalZone,
        type: 'vxlan',
        peers: peers
      });
      pushStatus(`SDN zone '${finalZone}' created with peers: ${peers}`);
    } else {
      pushStatus(`SDN zone '${finalZone}' already exists`);
    }

    // 5. Create VNets for each VXLAN ID in the block.
    // v1/v2: one VNet per lane. v3: two per lane — external (tag=vxlanId) and
    // internal (tag=vxlanId+offset) — so the segmented gateway can bridge them.
    pushStatus(`Creating ${numLanes} lane(s) of VNets (${subnetScheme})...`);
    let vnetsCreated = 0;

    // Base-20 encode helper for VNet naming (matches N8N workflow)
    const ALPHABET = 'abcdefghij0123456789';
    function encodeBase20(n) {
      if (n === 0) return 'a';
      let s = '';
      let x = n;
      while (x > 0) {
        s = ALPHABET[x % 20] + s;
        x = Math.floor(x / 20);
      }
      return s.padStart(8, 'a');
    }

    for (let vxlanId = vxlanStart; vxlanId <= vxlanEnd; vxlanId++) {
      // v3 lanes get a second (internal) VNet at the offset tag.
      const tags = subnetScheme === 'v3'
        ? [vxlanId, vxlanId + V3_INTERNAL_TAG_OFFSET]
        : [vxlanId];

      for (const tag of tags) {
        const vnetName = encodeBase20(tag); // 8-char unique name

        try {
          await proxmoxAPI('POST', '/api2/json/cluster/sdn/vnets', {
            vnet: vnetName,
            zone: finalZone,
            tag,
            alias: `${finalZone}-vnet-${tag}`
          });
          vnetsCreated++;
        } catch (e) {
          // VNet may already exist
          if (!e.message.includes('already exists')) {
            pushStatus(`Warning: VNet ${vnetName} (tag ${tag}): ${e.message}`);
          }
        }

        // Rate limit: Proxmox can get overwhelmed with rapid API calls
        if (vnetsCreated % 10 === 0 && vnetsCreated > 0) {
          await new Promise(r => setTimeout(r, 500));
        }
      }
    }
    pushStatus(`${vnetsCreated} VNets created`);

    // 6. Reload SDN configuration
    pushStatus('Reloading SDN...');
    await proxmoxAPI('PUT', '/api2/json/cluster/sdn');
    pushStatus('SDN reloaded');

    // 6b. The SDN apply above is ASYNCHRONOUS — Proxmox returns immediately but
    // the VNet bridges materialize on the nodes over the following seconds
    // (longer the more VNets; a v3 challenge creates 2 per lane, so a 100-lane
    // v3 challenge applies 200 VXLAN bridges). Poll until the LAST-created
    // VNet(s) actually show up as interfaces, so a lane deploy that starts
    // right after doesn't hit `bridge '<vnet>' does not exist`.
    pushStatus('Waiting for SDN to materialize VNet bridges...');
    try {
      const checkNodes = await proxmoxAPI('GET', '/api2/json/nodes');
      const checkNode = (checkNodes || [])[0] && (checkNodes || [])[0].node;
      if (checkNode) {
        const sampleVnets = [encodeBase20(vxlanEnd)];
        if (subnetScheme === 'v3') {
          sampleVnets.push(encodeBase20(vxlanEnd + V3_INTERNAL_TAG_OFFSET));
        }
        const deadline = Date.now() + 240000;   // 4 min cap
        let allUp = false;
        while (Date.now() < deadline) {
          const ifaces = await proxmoxAPI('GET', `/api2/json/nodes/${checkNode}/network`);
          const names = new Set((ifaces || []).map(i => i.iface));
          if (sampleVnets.every(v => names.has(v))) { allUp = true; break; }
          await new Promise(r => setTimeout(r, 4000));
        }
        pushStatus(allUp
          ? `SDN VNet bridges are up on ${checkNode}.`
          : 'WARNING: SDN bridges not confirmed within 4 min — run Datacenter → SDN → Apply and verify before deploying lanes.');
      }
    } catch (e) {
      pushStatus(`SDN bridge readiness check skipped: ${e.message}`);
    }

    // 7. Update challenge with final VXLAN block (in case it wasn't set during insert)
    await cybercoreQuery(
      `UPDATE crucible_challenge SET
        spec = jsonb_set(jsonb_set(COALESCE(spec, '{}'::jsonb),
          '{vxlan_block,start}', to_jsonb($2::int), true),
          '{vxlan_block,end}', to_jsonb($3::int), true),
        updated_at = NOW()
       WHERE challenge_id = $1`,
      [challengeId, vxlanStart, vxlanEnd]
    );

    pushStatus('Challenge creation complete!');

    res.json({
      success: true,
      challenge_id: challengeId,
      challenge_key,
      zone_abbrev: finalZone,
      vxlan_block: { start: vxlanStart, end: vxlanEnd },
      vnets_created: vnetsCreated,
      steps: statusUpdates
    });
  } catch (error) {
    if (error.code === '23505') {
      return res.status(409).json({ error: `Challenge '${req.body.challenge_key}' already exists` });
    }
    res.status(500).json({ error: error.message });
  }
});


// ============================================================================
// DEPLOYMENT STATUS (deployment_vuln_selections in clinic_db)
// ============================================================================

// GET /api/admin/lab-networks/:laneId/status
router.get('/lab-networks/:laneId/status', authenticateToken, adminOnly, async (req, res) => {
  try {
    const result = await query(
      `SELECT * FROM deployment_vuln_selections WHERE lane_id = $1 ORDER BY created_at DESC LIMIT 1`,
      [req.params.laneId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'No challenge deployment found for this lane' });
    }

    const deployment = result.rows[0];
    const scripts = deployment.selected_scripts || [];
    const total = scripts.length;
    const completed = scripts.filter(s => s.status === 'completed').length;
    const failed = scripts.filter(s => s.status === 'failed').length;
    const running = scripts.filter(s => s.status === 'running').length;
    const pending = scripts.filter(s => s.status === 'pending').length;

    res.json({
      ...deployment,
      script_summary: { total, completed, failed, running, pending },
      all_complete: pending === 0 && running === 0
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


module.exports = router;
