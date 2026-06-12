/**
 * ============================================================================
 * Lab Network Routes
 * Deploy/manage single-user lab networks, run vuln scripts, generate
 * lab profiles, and push files to VMs via guest agent.
 * All routes mounted at /api/admin/* via the admin aggregator.
 * ============================================================================
 */

const crypto = require('crypto');
const express = require('express');
const fs = require('fs');
const pathModule = require('path');
const router = express.Router();
const { authenticateToken, requireRole } = require('../../middleware/auth');
const { query } = require('../../utils/db');
const { cybercoreQuery } = require('../../utils/cybercore-db');
const { proxmoxAPI, waitForTask, findTemplateNode } = require('../../utils/proxmox');
const { getDefaultTemplateNode } = require('../../utils/site-config');
const { buildDeployPreview } = require('../../middleware/deployment-guards');
const { logActivity } = require('../../middleware/activity-logger');
const { waitForGuestAgent, executeScriptsOnVM, getVMIPs } = require('../../utils/script-executor');
const { selectBestNode } = require('../../utils/node-selector');
const goadDeploy = require('../../utils/goad-deploy');
const {
  V3_INTERNAL_TAG_OFFSET,
  resolveGatewayVmid,
  resolveLaneNetworking,
  formatLaneGatewayNet0,
  configureLaneTailscale
} = require('../../utils/lane-networking');

const adminOnly = requireRole('admin');


// ============================================================================
// CHALLENGE NETWORK DEPLOYMENT
// ============================================================================

router.post('/deploy-lab-network', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { template_id, user_id: targetUserId, selected_scripts, module, confirm } = req.body;
    const userId = targetUserId || req.user.userId;

    if (!template_id) {
      return res.status(400).json({ error: 'template_id is required' });
    }

    // Load challenge from cybercore_db (crucible_challenge is the source of truth)
    const challengeModule = module || 'crucible';
    const mod = challengeModule.replace(/[^a-z0-9_]/gi, '');
    const tplResult = await cybercoreQuery(
      `SELECT * FROM ${mod}_challenge WHERE challenge_id = $1 AND status = 'active'`,
      [template_id]
    );
    if (tplResult.rows.length === 0) return res.status(404).json({ error: 'Challenge not found' });
    const template = tplResult.rows[0];
    const spec = typeof template.spec === 'string' ? JSON.parse(template.spec) : (template.spec || {});
    const vmSpecs = spec.vms || (spec.template_vmid ? [{ name: template.challenge_key, template_vmid: spec.template_vmid, type: 'qemu', vm_offset: 600000 }] : []);

    if (!vmSpecs || vmSpecs.length === 0) {
      return res.status(400).json({ error: 'Template has no VM specs defined' });
    }

    // Pre-flight resource check
    if (!confirm) {
      try {
        const preview = await buildDeployPreview({
          numLanes: 1,
          attackBoxes: false,
          challengeVmCount: vmSpecs.length,
          proxmoxAPI,
          cybercoreQuery
        });
        preview.template_name = template.name;
        preview.vm_count = vmSpecs.length;
        return res.json({ preview: true, ...preview });
      } catch (err) {
        console.error('[ChallengeNetwork] Pre-flight check failed:', err.message);
      }
    }

    // Build the spec object compatible with the existing deploy-lane flow
    const subnetScheme = template.subnet_scheme || 'v1';
    const gatewayVmid = resolveGatewayVmid(challengeModule, subnetScheme, spec);
    const templateNode = await findTemplateNode(
      vmSpecs[0]?.template_vmid || spec.template_vmid,
      vmSpecs[0]?.template_node || getDefaultTemplateNode()
    );
    console.log(`[ChallengeNetwork] subnet_scheme=${subnetScheme} → gateway template=${gatewayVmid}`);
    const bestNodeInfo = await selectBestNode();
    const bestNode = bestNodeInfo.node;
    console.log(`[ChallengeNetwork] Selected node ${bestNode} for deployment (score: ${bestNodeInfo.score})`);

    // Allocate VXLAN from the challenge's VXLAN block (set at challenge creation)
    const vxlanBlock = (spec.vxlan_block?.start && spec.vxlan_block?.end)
      ? spec.vxlan_block
      : { start: 10000, end: 10009 };
    console.log(`[ChallengeNetwork] Using VXLAN block ${vxlanBlock.start}-${vxlanBlock.end} from challenge '${template.challenge_key}'`);

    const vxlanResult = await cybercoreQuery(
      `WITH used AS (
        SELECT DISTINCT vxlan_id FROM cybercore_lane
        WHERE vxlan_id IS NOT NULL AND vxlan_id BETWEEN $1 AND $2 AND status NOT IN ('error')
      )
      SELECT gs AS vxlan_id FROM generate_series($1::int, $2::int) AS gs
      LEFT JOIN used u ON u.vxlan_id = gs
      WHERE u.vxlan_id IS NULL ORDER BY gs LIMIT 1`,
      [vxlanBlock.start, vxlanBlock.end]
    );
    if (vxlanResult.rows.length === 0) {
      return res.status(503).json({ error: `No available VXLAN IDs in block ${vxlanBlock.start}-${vxlanBlock.end}` });
    }
    const vxlanId = vxlanResult.rows[0].vxlan_id;

    // Find VNet — if it doesn't exist, create the SDN zone + VNet
    let vnets = await proxmoxAPI('GET', '/api2/json/cluster/sdn/vnets');
    let vnet = vnets.find(v => v.tag === vxlanId);

    if (!vnet) {
      console.log(`[ChallengeNetwork] VNet for tag ${vxlanId} not found — creating SDN infrastructure...`);

      // Determine zone abbreviation from spec or challenge_key
      const zoneAbbrev = spec.zone?.abbrev || template.challenge_key?.substring(0, 8)?.replace(/[^a-z0-9]/gi, '').substring(0, 8) || 'chlng001';

      // Check if the SDN zone exists
      const zones = await proxmoxAPI('GET', '/api2/json/cluster/sdn/zones');
      const zoneExists = zones.some(z => z.zone === zoneAbbrev);

      if (!zoneExists) {
        // Get cluster node info for VXLAN zone creation
        const nodeList = await proxmoxAPI('GET', '/api2/json/nodes');
        const nodeNames = nodeList.map(n => n.node).join(',');
        const nodeIps = nodeList.map(n => n.ip || `100.100.10.${10 + nodeList.indexOf(n)}`).join(',');

        console.log(`[ChallengeNetwork] Creating SDN zone '${zoneAbbrev}' with nodes: ${nodeNames}`);
        await proxmoxAPI('POST', '/api2/json/cluster/sdn/zones', {
          zone: zoneAbbrev,
          type: 'vxlan',
          peers: nodeIps,
          ipam: 'pve'
        });
      }

      // Create the VNet for this VXLAN ID
      const vnetName = `${zoneAbbrev}-${vxlanId}`;
      console.log(`[ChallengeNetwork] Creating VNet '${vnetName}' with tag ${vxlanId} in zone '${zoneAbbrev}'`);
      await proxmoxAPI('POST', '/api2/json/cluster/sdn/vnets', {
        vnet: vnetName,
        zone: zoneAbbrev,
        tag: vxlanId,
        alias: `${zoneAbbrev}-vnet-${vxlanId}`
      });

      // Reload SDN so the VNet becomes active
      console.log('[ChallengeNetwork] Reloading SDN configuration...');
      await proxmoxAPI('PUT', '/api2/json/cluster/sdn');

      // Wait a moment for SDN to propagate
      await new Promise(r => setTimeout(r, 5000));

      // Re-fetch VNets
      vnets = await proxmoxAPI('GET', '/api2/json/cluster/sdn/vnets');
      vnet = vnets.find(v => v.tag === vxlanId);

      if (!vnet) {
        return res.status(503).json({ error: `Failed to create VNet for VXLAN tag ${vxlanId}. SDN may need manual reload.` });
      }

      console.log(`[ChallengeNetwork] SDN infrastructure created: zone=${zoneAbbrev}, vnet=${vnet.vnet}`);
    }

    // v3 segmented lanes need the internal VNet too (created at challenge-create
    // time alongside the external one). Don't auto-create it here — a v3
    // challenge must be made via /create-lab so both VNets exist.
    let vnetInt = null;
    if (subnetScheme === 'v3') {
      vnetInt = vnets.find(v => v.tag === vxlanId + V3_INTERNAL_TAG_OFFSET);
      if (!vnetInt) {
        return res.status(503).json({
          error: `v3 internal VNet (tag ${vxlanId + V3_INTERNAL_TAG_OFFSET}) not found — ` +
                 `create the v3 challenge via /create-lab first so both VNets exist.`
        });
      }
    }

    // Verify user exists in cybercore_user
    const userResult = await cybercoreQuery(
      `SELECT user_id, email, first_name, last_name, role FROM cybercore_user WHERE user_id = $1`, [userId]
    );
    if (userResult.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    const user = userResult.rows[0];

    // Create lane record
    const laneName = `challenge-${vnet.zone}-${vxlanId}`;
    const laneInsert = await cybercoreQuery(
      `INSERT INTO cybercore_lane (user_id, vxlan_id, name, status, config, module_key, created_at, updated_at)
       VALUES ($1, $2, $3, 'deploying', $4::jsonb, $5, NOW(), NOW())
       RETURNING lane_id`,
      [userId, vxlanId, laneName, JSON.stringify({ template_id: template.id, template_name: template.name, module: challengeModule }), challengeModule]
    );
    const laneId = laneInsert.rows[0].lane_id;

    // Build selected_scripts list for tracking
    const scriptsToRun = selected_scripts || [];
    const scriptEntries = scriptsToRun.map(s => ({
      script_slug: s.script_slug,
      vm_name: s.vm_name,
      status: 'pending',
      error: null,
      output: null
    }));

    // Create deployment tracking record (clinic_db)
    const dvsResult = await query(
      `INSERT INTO deployment_vuln_selections (lane_id, challenge_key, selected_scripts, status)
       VALUES ($1, $2, $3, 'deploying')
       RETURNING id`,
      [laneId, template.challenge_key, JSON.stringify(scriptEntries)]
    );
    const deploymentId = dvsResult.rows[0].id;

    // Respond immediately
    res.json({
      success: true,
      lane_id: laneId,
      deployment_id: deploymentId,
      vxlan_id: vxlanId,
      template: template.name,
      vm_count: vmSpecs.length,
      scripts_count: scriptEntries.length,
      message: 'Challenge network deployment started. Poll status endpoint for progress.'
    });

    logActivity(req, 'deploy_challenge_network', 'lane', laneId, {
      template_id: template.id, template_name: template.name, vxlan_id: vxlanId, vm_count: vmSpecs.length
    });

    // ---- Background deployment ----
    (async () => {
      try {
        const deployedVMs = [];

        // Per-lane networking. v1/v2: one subnet. v3: external + internal.
        const net = resolveLaneNetworking(subnetScheme, challengeModule, vxlanId);
        const isV3 = subnetScheme === 'v3';
        const vnetExtName = vnet.vnet;
        const vnetIntName = isV3 ? vnetInt.vnet : vnet.vnet;
        const laneSubnetBase = isV3 ? net.lanExt.base3 : net.lan.base3;
        const goadSubnetBase = isV3 ? net.lanInt.base3 : net.lan.base3;

        // GOAD: per-lane MAC/IP lookup. No-op for non-GOAD specs.
        const goadMacs = goadDeploy.prepareGoadMacs(spec, vxlanId, goadSubnetBase);

        // Clone all VMs
        for (const vmSpec of vmSpecs) {
          const vmId = (vmSpec.vm_offset || 600000) + vxlanId;
          const vmType = vmSpec.type || 'qemu';
          const vmTemplate = vmSpec.template_vmid;
          const vmName = vmSpec.name || `vm-${vmId}`;
          const goadMac = goadMacs[vmName]?.mac;
          const isGoadVm = !!goadMacs[vmName];
          const isDmz = vmSpec.role === 'dmz';
          // v3: GOAD VMs → internal VNet; dmz host → both; else → external.
          const vmVnet = (isV3 && isGoadVm) ? vnetIntName : vnetExtName;

          if (!vmTemplate) {
            console.error(`[ChallengeNetwork] VM ${vmName} has no template_vmid, skipping`);
            continue;
          }

          console.log(`[ChallengeNetwork] Cloning ${vmType} template ${vmTemplate} → ${vmId} (${vmName})`);

          if (vmType === 'lxc') {
            const result = await proxmoxAPI('POST', `/api2/json/nodes/${templateNode}/lxc/${vmTemplate}/clone`, {
              newid: vmId, hostname: `${laneName}-${vmName}`.replace(/[^a-z0-9-]/gi, '-').substring(0, 63).toLowerCase(), full: 1, target: bestNode,
              description: `Challenge Network: ${template.name}\nVM: ${vmName}\nLane: ${laneId}`,
            });
            if (result) await waitForTask(templateNode, result);
            await proxmoxAPI('PUT', `/api2/json/nodes/${bestNode}/lxc/${vmId}/config`, {
              net1: goadDeploy.buildLaneNet0({ type: 'lxc' }, vmVnet, goadMac)
            });
          } else {
            const result = await proxmoxAPI('POST', `/api2/json/nodes/${templateNode}/qemu/${vmTemplate}/clone`, {
              newid: vmId, name: `${laneName}-${vmName}`.replace(/[^a-z0-9-]/gi, '-').substring(0, 63).toLowerCase(), full: 1, target: bestNode,
              description: `Challenge Network: ${template.name}\nVM: ${vmName}\nLane: ${laneId}`,
            });
            if (result) await waitForTask(templateNode, result);
            if (isV3 && isDmz) {
              // v3 DMZ pivot: dual-homed (both NICs first, then cloud-init
              // static .50 on each subnet — default route via external).
              await proxmoxAPI('POST', `/api2/json/nodes/${bestNode}/qemu/${vmId}/config`, {
                net0: `virtio,bridge=${vnetExtName}`,
                net1: `virtio,bridge=${vnetIntName}`
              });
              await proxmoxAPI('POST', `/api2/json/nodes/${bestNode}/qemu/${vmId}/config`, {
                ipconfig0:  `ip=${net.lanExt.base3}.50/24,gw=${net.lanExt.gatewayIp}`,
                ipconfig1:  `ip=${net.lanInt.base3}.50/24`,
                nameserver: net.lanExt.gatewayIp,
                citype:     'nocloud'
              });
              await proxmoxAPI('PUT', `/api2/json/nodes/${bestNode}/qemu/${vmId}/cloudinit`).catch(() => {});
            } else {
              // Apply per-role resources (mirrors single + group deploy paths).
              const goadVm = goadMacs[vmName];
              const vmConfig = {
                net0: goadDeploy.buildLaneNet0(vmSpec, vmVnet, goadMac, goadVm?.nic_model)
              };
              if (goadVm?.memory)  vmConfig.memory  = goadVm.memory;
              if (goadVm?.balloon) vmConfig.balloon = goadVm.balloon;
              if (goadVm?.cores)   vmConfig.cores   = goadVm.cores;
              await proxmoxAPI('POST', `/api2/json/nodes/${bestNode}/qemu/${vmId}/config`, vmConfig);
            }
          }

          deployedVMs.push({
            vm_id: vmId, name: vmName, type: vmType, node: bestNode,
            role: vmSpec.role || '', os: vmSpec.os || '', services: vmSpec.services || [],
            default_scripts: vmSpec.default_scripts || []
          });
        }

        // Clone and start gateway
        const gatewayVmId = 100000 + vxlanId;
        // Per-lane bootstrap secret embedded as `-b<16hex>` hostname suffix.
        // firstboot greps it back and passes ?secret=… to /api/lane-bootstrap,
        // replacing source-IP gating. See utils/lane-networking.js
        // configureLaneTailscale + bake-lane-gateway-v2.sh. Hostname budget:
        // 63 chars; reserve 18 for `-b<16hex>`.
        const claimSecret = crypto.randomBytes(8).toString('hex');
        const baseHost = `${laneName}-gateway`.substring(0, 63 - 18).toLowerCase()
          .replace(/[^a-z0-9-]/g, '-').replace(/-+$/g, '');
        const gwHostname = `${baseHost}-b${claimSecret}`;

        const gwResult = await proxmoxAPI('POST', `/api2/json/nodes/${templateNode}/lxc/${gatewayVmid}/clone`, {
          newid: gatewayVmId, hostname: gwHostname, full: 1, target: bestNode,
          description: `Challenge Network Gateway\nTemplate: ${template.name}\nLane: ${laneId}`,
        });
        if (gwResult) await waitForTask(templateNode, gwResult);
        // Networking is scheme-aware:
        //   v1 → wan0 via module transit; lan0 = 192.18.0.1/24 (shared)
        //   v2 → wan0 on lab network (vmbr0); lan0 = 10.<vxh>.<vxl>.1/24 (unique)
        // `net` resolved above. v3 gateway is 3-NIC: wan0 + ext0 + int0.
        if (isV3) {
          await proxmoxAPI('PUT', `/api2/json/nodes/${bestNode}/lxc/${gatewayVmId}/config`, {
            net0: formatLaneGatewayNet0(net.wan),
            net1: `name=ext0,bridge=${vnetExtName},ip=${net.lanExt.gatewayIp}/24,type=veth`,
            net2: `name=int0,bridge=${vnetIntName},ip=${net.lanInt.gatewayIp}/24,type=veth`
          });
        } else {
          await proxmoxAPI('PUT', `/api2/json/nodes/${bestNode}/lxc/${gatewayVmId}/config`, {
            net0: formatLaneGatewayNet0(net.wan),
            net1: `name=lan0,bridge=${vnet.vnet},ip=${net.lan.gatewayIp}/24,type=veth`
          });
        }

        // v2/v3 only: mint+stage Tailscale auth key (silent no-op for v1)
        await configureLaneTailscale({
          subnetScheme,
          vxlanId,
          wanIp: net.wan.ip.split('/')[0],
          laneName,
          claimSecret,
          logTag: '[ChallengeNetwork]'
        });

        // Start gateway first
        await proxmoxAPI('POST', `/api2/json/nodes/${bestNode}/lxc/${gatewayVmId}/status/start`);
        await new Promise(r => setTimeout(r, 5000));

        // Start all challenge VMs
        for (const vm of deployedVMs) {
          const startPath = vm.type === 'lxc'
            ? `/api2/json/nodes/${vm.node}/lxc/${vm.vm_id}/status/start`
            : `/api2/json/nodes/${vm.node}/qemu/${vm.vm_id}/status/start`;
          await proxmoxAPI('POST', startPath);
        }

        console.log(`[ChallengeNetwork] All ${deployedVMs.length} VMs cloned and started`);

        // GOAD provisioning (no-op for non-GOAD specs).
        if (spec.goad?.enabled) {
          try {
            await goadDeploy.deployGoadLane({
              lane: { lane_id: laneId },
              spec, module: challengeModule, vnet: isV3 ? vnetInt : vnet, vxlanId, gatewayVmId,
              bestNode, templateNode, laneSubnetBase: goadSubnetBase, deployedVMs,
              proxmoxAPI, waitForTask, query: cybercoreQuery
            });
          } catch (goadErr) {
            console.error(`[ChallengeNetwork] GOAD provisioning failed for lane ${laneId}: ${goadErr.message}`);
          }
        }

        // Wait for guest agents on QEMU VMs, then run scripts
        await query(
          `UPDATE deployment_vuln_selections SET status = 'running_scripts', updated_at = NOW() WHERE id = $1`,
          [deploymentId]
        );

        for (const vm of deployedVMs) {
          if (vm.type !== 'qemu') continue;

          // Wait for guest agent
          console.log(`[ChallengeNetwork] Waiting for guest agent on ${vm.name} (${vm.vm_id})...`);
          const agentReady = await waitForGuestAgent(vm.node, vm.vm_id, 180000);
          if (!agentReady) {
            console.error(`[ChallengeNetwork] Guest agent not responding on ${vm.name}`);
            continue;
          }

          // Get scripts for this VM
          const vmScripts = scriptEntries
            .filter(s => s.vm_name === vm.name)
            .map(s => s.script_slug);

          if (vmScripts.length > 0) {
            // Load full script content
            const scriptResult = await query(
              `SELECT slug, script_content, os_target, depends_on, script_args FROM vuln_scripts WHERE slug = ANY($1) AND is_active = true`,
              [vmScripts]
            );
            if (scriptResult.rows.length > 0) {
              await executeScriptsOnVM(vm.node, vm.vm_id, vm.name, scriptResult.rows, deploymentId);
            }
          }
        }

        // Collect IPs from all VMs
        const networkInfo = { vms: [], gateway_vm_id: gatewayVmId, vxlan_id: vxlanId };
        for (const vm of deployedVMs) {
          const ips = vm.type === 'qemu' ? await getVMIPs(vm.node, vm.vm_id) : [];
          networkInfo.vms.push({
            ...vm,
            ips: ips,
            ip: ips[0] || null
          });
        }

        // Update lane config and deployment record
        const activeConfig = JSON.stringify({
          template_id: template.id,
          template_name: template.name,
          module: challengeModule,
          gateway_vm_id: gatewayVmId,
          node: bestNode,
          vms: deployedVMs,
          subnet_scheme: subnetScheme,
          lane_subnet_base: laneSubnetBase,
          vnet: vnetExtName,
          ...(isV3 ? {
            vnet_internal: vnetIntName,
            lane_subnet_internal: goadSubnetBase
          } : {})
        });

        await cybercoreQuery(
          `UPDATE cybercore_lane SET status = 'active', config = $2::jsonb, updated_at = NOW() WHERE lane_id = $1`,
          [laneId, activeConfig]
        );

        await query(
          `UPDATE deployment_vuln_selections SET deployed_network = $1, status = 'complete', updated_at = NOW() WHERE id = $2`,
          [JSON.stringify(networkInfo), deploymentId]
        );

        console.log(`[ChallengeNetwork] Lane ${laneId} fully deployed with ${deployedVMs.length} VMs`);

      } catch (err) {
        console.error(`[ChallengeNetwork] Deployment failed:`, err.message);
        await cybercoreQuery(
          `UPDATE cybercore_lane SET status = 'error', config = $2, updated_at = NOW() WHERE lane_id = $1`,
          [laneId, JSON.stringify({ error: err.message })]
        ).catch(() => {});
        await query(
          `UPDATE deployment_vuln_selections SET status = 'failed', updated_at = NOW() WHERE id = $1`,
          [deploymentId]
        ).catch(() => {});
      }
    })();

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// ============================================================================
// RUN SCRIPT ON CHALLENGE VM
// ============================================================================

router.post('/lab-networks/:laneId/run-script', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { vm_name, script_slug } = req.body;
    if (!vm_name || !script_slug) {
      return res.status(400).json({ error: 'vm_name and script_slug required' });
    }

    // Get lane info
    const laneResult = await cybercoreQuery(
      `SELECT config FROM cybercore_lane WHERE lane_id = $1 AND status = 'active'`,
      [req.params.laneId]
    );
    if (laneResult.rows.length === 0) return res.status(404).json({ error: 'Active lane not found' });

    const config = typeof laneResult.rows[0].config === 'string'
      ? JSON.parse(laneResult.rows[0].config) : laneResult.rows[0].config;

    // Find the target VM — support both multi-VM (config.vms[]) and legacy single-VM (config.challenge_vm_id)
    let vm = (config.vms || []).find(v => v.name === vm_name);
    if (!vm) {
      // Fallback: if there's a challenge_vm_id, use it (single-VM lane)
      const challengeVmId = config.challenge_vm_id;
      if (challengeVmId) {
        vm = { vm_id: challengeVmId, name: vm_name, type: 'qemu', node: config.node };
      }
      // Also check if vms array has exactly one entry (just use it regardless of name)
      if (!vm && config.vms?.length === 1) {
        vm = config.vms[0];
      }
    }
    if (!vm) return res.status(404).json({ error: `VM not found in lane config` });
    if (vm.type !== 'qemu') return res.status(400).json({ error: 'Script execution only supported on QEMU VMs' });

    // Load script
    const scriptResult = await query(
      `SELECT * FROM vuln_scripts WHERE slug = $1 AND is_active = true`, [script_slug]
    );
    if (scriptResult.rows.length === 0) return res.status(404).json({ error: `Script '${script_slug}' not found` });
    const script = scriptResult.rows[0];

    // Respond immediately — script runs in background
    res.json({ success: true, message: `Running '${script.name}' on ${vm_name}...`, vm_id: vm.vm_id });

    // Background: find or create tracking record, then run script
    (async () => {
    try {
    let dvsResult = await query(
      `SELECT id FROM deployment_vuln_selections WHERE lane_id = $1 ORDER BY created_at DESC LIMIT 1`,
      [req.params.laneId]
    );

    let deploymentId;
    if (dvsResult.rows.length > 0) {
      deploymentId = dvsResult.rows[0].id;
      // Append this script to existing selected_scripts
      const existing = await query(`SELECT selected_scripts FROM deployment_vuln_selections WHERE id = $1`, [deploymentId]);
      const scripts = existing.rows[0]?.selected_scripts || [];
      if (!scripts.some(s => s.script_slug === script_slug && s.vm_name === vm.name)) {
        scripts.push({ script_slug, vm_name: vm.name, status: 'pending', error: null, output: null });
        await query(`UPDATE deployment_vuln_selections SET selected_scripts = $1, updated_at = NOW() WHERE id = $2`,
          [JSON.stringify(scripts), deploymentId]);
      }
    } else {
      // Create a new record
      const newDvs = await query(
        `INSERT INTO deployment_vuln_selections (lane_id, selected_scripts, status)
         VALUES ($1, $2, 'running_scripts') RETURNING id`,
        [req.params.laneId,
         JSON.stringify([{ script_slug, vm_name: vm.name, status: 'pending', error: null, output: null }])]
      );
      deploymentId = newDvs.rows[0].id;
    }

    await executeScriptsOnVM(vm.node, vm.vm_id, vm.name, [script], deploymentId);
    } catch (err) {
      console.error(`[RunScript] Background error: ${err.message}`);
    }
    })();

  } catch (error) {
    if (!res.headersSent) res.status(500).json({ error: error.message });
  }
});


// ============================================================================
// GENERATE CHALLENGE PROFILE
// ============================================================================

router.post('/lab-networks/:laneId/generate-profile', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { client_type, industry, difficulty, company_name, llm_model } = req.body;

    // Get lane info from cybercore_db
    const laneResult = await cybercoreQuery(
      `SELECT lane_id, user_id, vxlan_id, config FROM cybercore_lane WHERE lane_id = $1 AND status = 'active'`,
      [req.params.laneId]
    );
    if (laneResult.rows.length === 0) {
      return res.status(404).json({ error: 'Active lane not found' });
    }
    const lane = laneResult.rows[0];
    const laneConfig = typeof lane.config === 'string' ? JSON.parse(lane.config) : (lane.config || {});
    const laneUserId = lane.user_id;

    // Try to get deployment tracking data (may not exist if no vuln scripts were run)
    let deployment = {};
    const dvsResult = await query(
      `SELECT * FROM deployment_vuln_selections WHERE lane_id = $1 ORDER BY created_at DESC LIMIT 1`,
      [req.params.laneId]
    );
    if (dvsResult.rows.length > 0) {
      deployment = dvsResult.rows[0];
    }

    // Build VM list from deployment_vuln_selections.deployed_network OR lane config
    const dvsNetwork = typeof deployment.deployed_network === 'string'
      ? JSON.parse(deployment.deployed_network || '{}') : (deployment.deployed_network || {});

    // Prefer deployment network data (has IPs collected after boot), fall back to lane config
    let vms = (dvsNetwork.vms && dvsNetwork.vms.length > 0)
      ? dvsNetwork.vms
      : (laneConfig.vms || []);

    // If still no VMs, try single-VM fallback
    if (vms.length === 0 && laneConfig.challenge_vm_id) {
      vms = [{
        vm_id: laneConfig.challenge_vm_id,
        name: laneConfig.challenge_key || 'challenge',
        type: 'qemu',
        node: laneConfig.node,
        role: 'Primary Target',
        os: 'Windows'
      }];
    }

    if (vms.length === 0) {
      return res.status(400).json({ error: 'No VMs found in lane config. Is the lane deployed?' });
    }

    // If VMs don't have IPs yet, try to collect them now
    for (const vm of vms) {
      if (!vm.ip && !vm.ips?.length && vm.type === 'qemu' && vm.node && vm.vm_id) {
        try {
          const ips = await getVMIPs(vm.node, vm.vm_id);
          vm.ips = ips;
          vm.ip = ips[0] || null;
        } catch (_) {}
      }
    }

    // Get phantom assets from the challenge spec in cybercore_db
    let phantoms = [];
    const challengeKey = deployment.challenge_key || laneConfig.challenge_key;
    if (challengeKey) {
      try {
        const chalResult = await cybercoreQuery(
          `SELECT spec FROM crucible_challenge WHERE challenge_key = $1`, [challengeKey]
        );
        if (chalResult.rows.length > 0) {
          const chalSpec = typeof chalResult.rows[0].spec === 'string'
            ? JSON.parse(chalResult.rows[0].spec) : chalResult.rows[0].spec;
          phantoms = chalSpec.phantom_assets || [];
        }
      } catch (_) {}
    }

    // Build asset inventory from real VMs + phantom assets
    const realAssets = vms.map(vm => ({
      hostname: vm.name,
      ip: vm.ip || vm.ips?.[0] || 'pending',
      role: vm.role || 'Server',
      os: vm.os || 'Unknown',
      services: vm.services || [],
      is_real: true
    }));

    const phantomAssets = phantoms.map(p => ({
      hostname: p.hostname,
      ip: p.ip,
      role: p.role || 'Server',
      os: p.os || 'Unknown',
      notes: p.notes,
      is_real: false
    }));

    const allAssets = [...realAssets, ...phantomAssets];

    // Get deployed vuln info for the profile
    const deployedVulns = Array.isArray(deployment.selected_scripts)
      ? deployment.selected_scripts.filter(s => s.status === 'completed').map(s => s.script_slug)
      : [];

    // Generate the challenge profile inline (challenge_network mode pins the
    // real VM hostnames/IPs into the generated network architecture).
    console.log(`[ChallengeProfile] Generating profile for lane ${req.params.laneId} with ${allAssets.length} assets`);
    console.log(`[ChallengeProfile] Real assets:`, realAssets.map(a => `${a.hostname}=${a.ip}`).join(', '));
    console.log(`[ChallengeProfile] Deployed vulns:`, deployedVulns.join(', ') || 'none');

    const { generateProfile } = require('../../../modules/crucible/plugins/ciab/ai/profile');
    const profile = await generateProfile({
      user_id: laneUserId,
      client_type: client_type || 'SMB',
      industry: industry || 'Technology',
      difficulty: difficulty || 'intermediate',
      company_name: company_name || null,
      llmModel: llm_model || undefined,
      custom_config: {
        challenge_network: {
          is_challenge: true,
          real_assets: allAssets.filter(a => a.ip && a.ip !== 'pending'),
          deployed_vulnerabilities: deployedVulns,
          lane_id: req.params.laneId,
          network_topology: {
            vxlan_id: lane.vxlan_id || dvsNetwork.vxlan_id,
            gateway_vm_id: laneConfig.gateway_vm_id || dvsNetwork.gateway_vm_id,
            total_vms: vms.length
          }
        }
      }
    });

    if (profile?.id) {
      await query(
        `UPDATE deployment_vuln_selections SET profile_id = $1, updated_at = NOW() WHERE id = $2`,
        [profile.id, deployment.id]
      );
    }

    logActivity(req, 'generate_challenge_profile', 'lane', req.params.laneId, {
      assets: allAssets.length, vulns: deployedVulns.length
    });

    res.json({
      success: true,
      profile_id: profile?.id || null,
      assets_included: allAssets.length,
      real_vms: realAssets.length,
      phantom_hosts: phantomAssets.length
    });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// ============================================================================
// FILE PUSH — Push a file from vuln-assets/ to a VM via guest agent
// ============================================================================

router.post('/push-file', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { lane_id, vm_name, filename, dest_path } = req.body;

    if (!lane_id || !filename || !dest_path) {
      return res.status(400).json({ error: 'lane_id, filename, and dest_path are required' });
    }

    const safeName = pathModule.basename(filename);
    const localPath = pathModule.join(__dirname, '../../../vuln-assets', safeName);

    if (!fs.existsSync(localPath)) {
      return res.status(404).json({ error: `File '${safeName}' not found in vuln-assets/` });
    }

    const fileSize = fs.statSync(localPath).size;
    const fileSizeMB = (fileSize / 1048576).toFixed(1);

    // Get lane info
    const laneResult = await cybercoreQuery(
      `SELECT config FROM cybercore_lane WHERE lane_id = $1 AND status = 'active'`,
      [lane_id]
    );
    if (laneResult.rows.length === 0) return res.status(404).json({ error: 'Active lane not found' });

    const config = typeof laneResult.rows[0].config === 'string'
      ? JSON.parse(laneResult.rows[0].config) : laneResult.rows[0].config;

    let vm = (config.vms || []).find(v => v.name === vm_name);
    if (!vm && config.challenge_vm_id) {
      vm = { vm_id: config.challenge_vm_id, node: config.node, type: 'qemu' };
    }
    if (!vm && config.vms?.length === 1) vm = config.vms[0];
    if (!vm) return res.status(404).json({ error: 'VM not found in lane' });

    res.json({
      success: true,
      message: `Pushing ${safeName} (${fileSizeMB} MB) to ${dest_path} on VM ${vm.vm_id}...`,
      file_size_mb: fileSizeMB
    });

    // Background: push the file to the VM via Proxmox guest-agent file-write.
    // This deliberately uses the virtio-serial channel (not TCP) so a compromised
    // target VM cannot initiate any connection back to the orchestrator — the host
    // always drives the conversation. Proxmox caps `content` at 61,440 chars of
    // base64, so we chunk at 45 KB raw (~60,000 base64 chars) and reassemble on
    // the VM with a single PowerShell call.
    (async () => {
      try {
        const https = require('https');
        const PX_URL = process.env.PROXMOX_API_URL || 'https://100.100.10.10:8006';
        const PX_TOKEN_ID = process.env.PROXMOX_TOKEN_ID || 'root@pam!clinic-app-token';
        const PX_TOKEN_SECRET = process.env.PROXMOX_TOKEN_SECRET || '';

        // Helper: write one binary chunk via the file-write JSON API.
        const writeChunk = (filePath, b64Data) => {
          return new Promise((resolve, reject) => {
            const url = new URL(`${PX_URL}/api2/json/nodes/${vm.node}/qemu/${vm.vm_id}/agent/file-write`);
            const body = JSON.stringify({ file: filePath, content: b64Data });
            const req = https.request({
              hostname: url.hostname, port: url.port || 8006, path: url.pathname, method: 'POST',
              headers: {
                'Authorization': `PVEAPIToken=${PX_TOKEN_ID}=${PX_TOKEN_SECRET}`,
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(body)
              },
              rejectUnauthorized: false,
              timeout: 30000
            }, (res) => {
              let data = '';
              res.on('data', c => data += c);
              res.on('end', () => {
                if (res.statusCode >= 400) return reject(new Error(`file-write failed (${res.statusCode}): ${data}`));
                resolve();
              });
            });
            req.on('error', reject);
            req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
            req.write(body);
            req.end();
          });
        };

        // Proxmox caps agent/file-write `content` at 61,440 chars of base64.
        // 45 KB raw -> 60,000 base64 chars, leaving headroom under the cap.
        const CHUNK_SIZE = 45 * 1024;
        const fileBuffer = fs.readFileSync(localPath);
        const totalChunks = Math.ceil(fileBuffer.length / CHUNK_SIZE);
        const tempDir = 'C:\\Windows\\Temp\\push_' + Date.now();

        console.log(`[PushFile] Pushing ${safeName} (${fileSizeMB} MB, ${totalChunks} chunks of ${CHUNK_SIZE / 1024}KB) to VM ${vm.vm_id}`);

        // Create temp dir on VM
        const { pollExecStatus } = require('../../utils/script-executor');
        const mkdirResult = await proxmoxAPI('POST',
          `/api2/json/nodes/${vm.node}/qemu/${vm.vm_id}/agent/exec`, {
            command: 'powershell.exe',
            'input-data': `New-Item -ItemType Directory -Path '${tempDir}' -Force | Out-Null\n[Environment]::Exit(0)\n`
          }
        );
        if (mkdirResult?.pid) await pollExecStatus(vm.node, vm.vm_id, mkdirResult.pid, 10000);

        // Write each chunk
        for (let i = 0; i < totalChunks; i++) {
          const start = i * CHUNK_SIZE;
          const end = Math.min(start + CHUNK_SIZE, fileBuffer.length);
          const chunkBuffer = fileBuffer.subarray(start, end);
          const b64 = chunkBuffer.toString('base64');
          const chunkPath = `${tempDir}\\chunk_${String(i).padStart(4, '0')}`;

          let retries = 3;
          while (retries > 0) {
            try {
              await writeChunk(chunkPath, b64);
              break;
            } catch (e) {
              retries--;
              if (retries === 0) throw new Error(`Chunk ${i} failed after 3 retries: ${e.message}`);
              console.log(`[PushFile] Chunk ${i} retry (${3 - retries}/3): ${e.message}`);
              await new Promise(r => setTimeout(r, 2000));
            }
          }

          if ((i + 1) % 20 === 0 || i === totalChunks - 1) {
            console.log(`[PushFile] Written ${i + 1}/${totalChunks} chunks (${Math.round((i + 1) / totalChunks * 100)}%)`);
          }
          if (i % 10 === 9) await new Promise(r => setTimeout(r, 300));
        }

        // Reassemble chunks on the VM using PowerShell
        console.log(`[PushFile] Reassembling ${totalChunks} chunks on VM...`);
        const assembleScript = `
$chunks = Get-ChildItem '${tempDir}\\chunk_*' | Sort-Object Name
$parent = Split-Path -Parent '${dest_path}'
if ($parent -and -not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
$outStream = [System.IO.File]::Create('${dest_path}')
foreach ($chunk in $chunks) {
    $b64 = [System.IO.File]::ReadAllText($chunk.FullName)
    $bytes = [Convert]::FromBase64String($b64)
    $outStream.Write($bytes, 0, $bytes.Length)
}
$outStream.Close()
Remove-Item '${tempDir}' -Recurse -Force -ErrorAction SilentlyContinue
$size = (Get-Item '${dest_path}').Length
Write-Host "File assembled: ${dest_path} ($size bytes)"
`;
        const assembleResult = await proxmoxAPI('POST',
          `/api2/json/nodes/${vm.node}/qemu/${vm.vm_id}/agent/exec`, {
            command: 'powershell.exe',
            'input-data': assembleScript + '\n[Environment]::Exit(0)\n'
          }
        );
        if (assembleResult?.pid) {
          const result = await pollExecStatus(vm.node, vm.vm_id, assembleResult.pid, 120000);
          console.log(`[PushFile] Assemble output: ${(result.stdout || '').trim()}`);
        }

        console.log(`[PushFile] Done: ${safeName} (${fileSizeMB} MB) -> ${dest_path} on VM ${vm.vm_id}`);
      } catch (err) {
        console.error(`[PushFile] Failed: ${err.message}`);
      }
    })();

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


module.exports = router;
