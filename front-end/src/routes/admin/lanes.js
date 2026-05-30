/**
 * ============================================================================
 * Lane Admin Routes
 * Single-lane deploy/teardown, attached modules, lane CRUD, internet toggle,
 * module/challenge listings.
 * ============================================================================
 */

const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const { authenticateToken, requireRole } = require('../../middleware/auth');
const { proxmoxAPI, waitForTask, forceDestroyVM, findTemplateNode } = require('../../utils/proxmox');
const { getDefaultTemplateNode } = require('../../utils/site-config');
const { cybercoreQuery } = require('../../utils/cybercore-db');
const { query } = require('../../utils/db');
const { buildDeployPreview } = require('../../middleware/deployment-guards');
const { logActivity } = require('../../middleware/activity-logger');
const { waitForGuestAgent, executeScriptsOnVM, getVMIPs } = require('../../utils/script-executor');
const { selectBestNode } = require('../../utils/node-selector');
const goadDeploy = require('../../utils/goad-deploy');
const tailscale = require('../../utils/tailscale');
const attachedModules = require('../../utils/attached-modules');
const {
  V3_INTERNAL_TAG_OFFSET,
  ATTACK_BOX_VMID_OFFSET,
  resolveGatewayVmid,
  resolveLaneNetworking,
  configureLaneTailscale,
  formatLaneGatewayNet0,
} = require('../../utils/lane-networking');

const adminOnly = requireRole('admin');

const N8N_DEPLOY_WEBHOOK = process.env.N8N_DEPLOY_LANE_WEBHOOK || 'http://100.100.20.50:5678/webhook-test/6bcb6b80-01d9-41a4-86e5-c0747fef50db';
const N8N_TEARDOWN_WEBHOOK = process.env.N8N_TEARDOWN_LANE_WEBHOOK || 'http://100.100.20.50:5678/webhook-test/60949de5-d0f9-40bc-8441-5cf4f9b08048';


// ============================================================================
// LANE DEPLOYMENT
// ============================================================================

router.post('/deploy-lane', authenticateToken, adminOnly, async (req, res) => {
  const { challenge_key, module, event_id, use_webhook, attack_boxes, confirm, vuln_scripts: selectedVulnScripts } = req.body;
  const user_id = req.body.user_id || req.user.userId;
  if (!challenge_key || !module) {
    return res.status(400).json({ error: 'challenge_key and module required' });
  }

  if (use_webhook) {
    try {
      console.log(`[Deploy] Using N8N webhook for ${challenge_key} (user: ${user_id})`);
      const webhookRes = await fetch(N8N_DEPLOY_WEBHOOK, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user_id, challenge_key, module, event_id: event_id || null })
      });
      if (!webhookRes.ok) {
        const errText = await webhookRes.text();
        throw new Error(`N8N webhook failed (${webhookRes.status}): ${errText}`);
      }
      const webhookData = await webhookRes.json();
      console.log(`[Deploy] N8N webhook response:`, webhookData);
      return res.json({
        success: true,
        method: 'webhook',
        lane_id: webhookData.lane_id || webhookData.laneId || 'pending',
        vxlan_id: webhookData.vxlan_id || webhookData.vxlanId || null,
        vnet: webhookData.vnet || null,
        challenge: challenge_key,
        message: 'Lane deployment triggered via N8N webhook.',
        webhook_response: webhookData
      });
    } catch (error) {
      console.error('[Deploy] N8N webhook error:', error.message);
      return res.status(502).json({ error: `Webhook failed: ${error.message}` });
    }
  }

  try {
    const modResult = await cybercoreQuery(
      `SELECT EXISTS (SELECT 1 FROM cybercore_module WHERE key = $1) AS is_installed`,
      [module]
    );
    if (!modResult.rows[0].is_installed) {
      return res.status(400).json({ error: `Module '${module}' is not installed` });
    }

    const userResult = await cybercoreQuery(
      `SELECT user_id, email, first_name, last_name, role, organization FROM cybercore_user WHERE user_id = $1`, [user_id]
    );
    if (userResult.rows.length === 0) {
      return res.status(400).json({ error: 'User not found' });
    }

    const laneCheck = await cybercoreQuery(
      `SELECT lane_id FROM cybercore_lane WHERE user_id = $1 AND status IN ('active', 'deploying', 'pending') LIMIT 1`,
      [user_id]
    );
    if (laneCheck.rows.length > 0) {
      return res.status(409).json({ error: 'User already has an active lane', lane_id: laneCheck.rows[0].lane_id });
    }

    const challengeResult = await cybercoreQuery(
      `SELECT challenge_id, challenge_key, name, spec, difficulty, subnet_scheme
       FROM ${module}_challenge
       WHERE challenge_key = $1 AND status = 'active'`,
      [challenge_key]
    );
    if (challengeResult.rows.length === 0) {
      return res.status(404).json({ error: `Challenge '${challenge_key}' not found or not active` });
    }
    const challenge = challengeResult.rows[0];
    const spec = typeof challenge.spec === 'string' ? JSON.parse(challenge.spec) : challenge.spec;
    const subnetScheme = challenge.subnet_scheme || 'v1';

    const specVmCount = (spec.vms || []).length || 1;
    if (!confirm) {
      try {
        const preview = await buildDeployPreview({
          numLanes: 1,
          attackBoxes: !!attack_boxes,
          challengeVmCount: specVmCount,
          proxmoxAPI,
          cybercoreQuery
        });
        return res.json({ preview: true, ...preview });
      } catch (err) {
        console.error('[Deploy] Pre-flight check failed:', err.message);
      }
    }

    const vxlanBlock = {
      start: spec.vxlan_block?.start ?? 10000,
      end: spec.vxlan_block?.end ?? 10009
    };
    const vxlanResult = await cybercoreQuery(
      `WITH used AS (
        SELECT DISTINCT vxlan_id FROM cybercore_lane
        WHERE vxlan_id IS NOT NULL
          AND vxlan_id BETWEEN $1 AND $2
          AND status NOT IN ('error')
      )
      SELECT gs AS vxlan_id
      FROM generate_series($1::int, $2::int) AS gs
      LEFT JOIN used u ON u.vxlan_id = gs
      WHERE u.vxlan_id IS NULL
      ORDER BY gs LIMIT 1`,
      [vxlanBlock.start, vxlanBlock.end]
    );
    if (vxlanResult.rows.length === 0) {
      return res.status(503).json({ error: 'No available VXLAN IDs in this challenge block' });
    }
    const vxlanId = vxlanResult.rows[0].vxlan_id;

    const vnets = await proxmoxAPI('GET', '/api2/json/cluster/sdn/vnets');
    const vnet = vnets.find(v => v.tag === vxlanId);
    if (!vnet) {
      return res.status(503).json({ error: `No VNet found with tag ${vxlanId} in Proxmox SDN` });
    }
    let vnetInt = null;
    if (subnetScheme === 'v3') {
      const intTag = vxlanId + V3_INTERNAL_TAG_OFFSET;
      vnetInt = vnets.find(v => v.tag === intTag);
      if (!vnetInt) {
        return res.status(503).json({ error: `No internal VNet found with tag ${intTag} for v3 lane (segmented topology needs both VNets)` });
      }
    }

    const templateVmid = spec.template_vmid || 1600;
    const gatewayVmid = resolveGatewayVmid(module, subnetScheme, spec);
    const templateNode = await findTemplateNode(templateVmid, spec.template_node || getDefaultTemplateNode());
    console.log(`[Deploy] subnet_scheme=${subnetScheme} → gateway template=${gatewayVmid}`);
    const bestNodeInfo = await selectBestNode();
    const bestNode = bestNodeInfo.node;
    console.log(`[Deploy] Selected node ${bestNode} for lane deployment (score: ${bestNodeInfo.score})`);

    const laneName = `${vnet.zone}-${vxlanId}`;
    const laneConfig = JSON.stringify({
      challenge_id: challenge.challenge_id,
      challenge_key: challenge.challenge_key,
      challenge_name: challenge.name,
      module
    });
    const laneInsert = await cybercoreQuery(
      `INSERT INTO cybercore_lane (user_id, vxlan_id, name, status, config, module_key, created_at, updated_at)
       VALUES ($1, $2, $3, 'deploying', $4::jsonb, $5, NOW(), NOW())
       RETURNING lane_id, user_id, vxlan_id, name, status, created_at`,
      [user_id, vxlanId, laneName, laneConfig, module]
    );
    const lane = laneInsert.rows[0];

    res.json({
      success: true,
      lane_id: lane.lane_id,
      status: 'deploying',
      vxlan_id: vxlanId,
      vnet: vnet.vnet,
      challenge: challenge.name,
      message: 'Lane deployment started. Use GET /api/admin/lanes/:id to check status.'
    });

    logActivity(req, 'deploy_lane', 'lane', lane.lane_id, { challenge_key, module, vxlan_id: vxlanId, user_id });

    (async () => {
      try {
        const net = resolveLaneNetworking(subnetScheme, module, vxlanId);
        const isV3 = subnetScheme === 'v3';
        const vnetExtName = vnet.vnet;
        const vnetIntName = isV3 ? vnetInt.vnet : vnet.vnet;
        const laneSubnetBase = isV3 ? net.lanExt.base3 : net.lan.base3;
        const goadSubnetBase = isV3 ? net.lanInt.base3 : net.lan.base3;

        const goadMacs = goadDeploy.prepareGoadMacs(spec, vxlanId, goadSubnetBase);

        const vmSpecs = spec.vms || [{ name: challenge_key, template_vmid: templateVmid, type: 'qemu', vm_offset: 600000 }];
        const deployedVMs = [];

        for (const vmSpec of vmSpecs) {
          const vmId = (vmSpec.vm_offset || 600000) + vxlanId;
          const vmType = vmSpec.type || 'qemu';
          const vmTemplate = vmSpec.template_vmid || templateVmid;
          const vmName = vmSpec.name || challenge_key;
          const goadMac = goadMacs[vmName]?.mac;
          const isGoadVm = !!goadMacs[vmName];
          const isDmz = vmSpec.role === 'dmz';
          const vmVnet = (isV3 && isGoadVm) ? vnetIntName : vnetExtName;

          console.log(`[Deploy] Cloning ${vmType} template ${vmTemplate} → ${vmId} (${vmName})`);

          if (vmType === 'lxc') {
            const cloneResult = await proxmoxAPI('POST', `/api2/json/nodes/${templateNode}/lxc/${vmTemplate}/clone`, {
              newid: vmId, hostname: `${laneName}-${vmName}`.replace(/[^a-z0-9-]/gi, '-').substring(0, 63).toLowerCase(), full: 1, target: bestNode,
              description: `Challenge: ${challenge_key}\nVM: ${vmName}\nLane: ${lane.lane_id}`,
              pool: `${module}-pool`
            });
            if (cloneResult) await waitForTask(templateNode, cloneResult);
            await proxmoxAPI('PUT', `/api2/json/nodes/${bestNode}/lxc/${vmId}/config`, {
              net1: goadDeploy.buildLaneNet0({ type: 'lxc' }, vmVnet, goadMac)
            });
          } else {
            const cloneResult = await proxmoxAPI('POST', `/api2/json/nodes/${templateNode}/qemu/${vmTemplate}/clone`, {
              newid: vmId, name: `${laneName}-${vmName}`.replace(/[^a-z0-9-]/gi, '-').substring(0, 63).toLowerCase(), full: 1, target: bestNode,
              description: `Challenge: ${challenge_key}\nVM: ${vmName}\nLane: ${lane.lane_id}`,
              pool: `${module}-pool`
            });
            if (cloneResult) await waitForTask(templateNode, cloneResult);

            if (isV3 && isDmz) {
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

          deployedVMs.push({ vm_id: vmId, name: vmName, type: vmType, node: bestNode });
        }

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

        const gwCloneResult = await proxmoxAPI('POST', `/api2/json/nodes/${templateNode}/lxc/${gatewayVmid}/clone`, {
          newid: gatewayVmId,
          hostname: gwHostname,
          full: 1,
          target: bestNode,
          description: `Challenge: ${challenge_key}\nUser ID: ${user_id}\nLane ID: ${lane.lane_id}\nModule: ${module}`,
          pool: `${module}-pool`
        });

        if (gwCloneResult) await waitForTask(templateNode, gwCloneResult);

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

        await configureLaneTailscale({
          subnetScheme,
          vxlanId,
          wanIp: net.wan.ip.split('/')[0],
          laneName,
          claimSecret,
          logTag: '[Deploy]'
        });

        await proxmoxAPI('POST', `/api2/json/nodes/${bestNode}/lxc/${gatewayVmId}/status/start`);
        await new Promise(r => setTimeout(r, 5000));

        for (const vm of deployedVMs) {
          const startPath = vm.type === 'lxc'
            ? `/api2/json/nodes/${vm.node}/lxc/${vm.vm_id}/status/start`
            : `/api2/json/nodes/${vm.node}/qemu/${vm.vm_id}/status/start`;
          await proxmoxAPI('POST', startPath);
        }

        if (spec.goad?.enabled) {
          try {
            await goadDeploy.deployGoadLane({
              lane, spec, module, vnet: isV3 ? vnetInt : vnet, vxlanId, gatewayVmId,
              bestNode, templateNode, laneSubnetBase: goadSubnetBase, deployedVMs,
              proxmoxAPI, waitForTask, query: cybercoreQuery
            });
          } catch (goadErr) {
            console.error(`[GOAD] Provisioning failed for lane ${lane.lane_id}:`, goadErr.message);
          }
        }

        if (selectedVulnScripts && selectedVulnScripts.length > 0) {
          console.log(`[Deploy] Running ${selectedVulnScripts.length} vuln scripts on lane ${lane.lane_id}...`);

          const scriptEntries = selectedVulnScripts.map(s => ({
            script_slug: s.script_slug,
            vm_name: s.vm_name || deployedVMs[0]?.name || 'default',
            status: 'pending',
            error: null
          }));

          const dvsResult = await query(
            `INSERT INTO deployment_vuln_selections (lane_id, challenge_key, selected_scripts, status)
             VALUES ($1, $2, $3, 'running_scripts')
             RETURNING id`,
            [lane.lane_id, challenge_key, JSON.stringify(scriptEntries)]
          );
          const deploymentId = dvsResult.rows[0].id;

          for (const vm of deployedVMs) {
            if (vm.type !== 'qemu') continue;
            console.log(`[Deploy] Waiting for guest agent on ${vm.name} (${vm.vm_id})...`);
            const agentReady = await waitForGuestAgent(vm.node, vm.vm_id, 180000);
            if (!agentReady) {
              console.error(`[Deploy] Guest agent not responding on ${vm.name} — skipping scripts`);
              continue;
            }
            const vmScriptSlugs = selectedVulnScripts
              .filter(s => (s.vm_name || deployedVMs[0]?.name) === vm.name)
              .map(s => s.script_slug);
            if (vmScriptSlugs.length > 0) {
              const scriptRows = await query(
                `SELECT slug, script_content, os_target, depends_on, script_args FROM vuln_scripts WHERE slug = ANY($1) AND is_active = true`,
                [vmScriptSlugs]
              );
              if (scriptRows.rows.length > 0) {
                await executeScriptsOnVM(vm.node, vm.vm_id, vm.name, scriptRows.rows, deploymentId);
              }
            }
          }

          const networkInfo = { vms: [] };
          for (const vm of deployedVMs) {
            const ips = vm.type === 'qemu' ? await getVMIPs(vm.node, vm.vm_id) : [];
            networkInfo.vms.push({ ...vm, ips, ip: ips[0] || null });
          }
          await query(
            `UPDATE deployment_vuln_selections SET deployed_network = $1, status = 'complete', updated_at = NOW() WHERE id = $2`,
            [JSON.stringify(networkInfo), deploymentId]
          );
          console.log(`[Deploy] Vuln scripts completed for lane ${lane.lane_id}`);
        }

        const primaryVm = deployedVMs[0];
        const activeConfig = JSON.stringify({
          challenge_vm_id: primaryVm?.vm_id,
          gateway_vm_id: gatewayVmId,
          node: bestNode,
          challenge_key,
          module,
          vms: deployedVMs,
          subnet_scheme: subnetScheme,
          lane_subnet_base: laneSubnetBase,
          vnet: vnet.vnet,
          ...(isV3 ? {
            vnet_internal: vnetIntName,
            lane_subnet_internal: goadSubnetBase
          } : {})
        });
        await cybercoreQuery(
          `UPDATE cybercore_lane SET status = 'active', config = $2::jsonb, updated_at = NOW() WHERE lane_id = $1`,
          [lane.lane_id, activeConfig]
        );
        console.log(`Lane ${lane.lane_id} deployed successfully (VXLAN ${vxlanId}, ${deployedVMs.length} VMs)`);
      } catch (err) {
        console.error(`Lane ${lane.lane_id} deployment failed:`, err.message);
        await cybercoreQuery(
          `UPDATE cybercore_lane SET status = 'error', config = $2, updated_at = NOW() WHERE lane_id = $1`,
          [lane.lane_id, JSON.stringify({ error: err.message })]
        ).catch(() => {});
      }
    })();

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// ============================================================================
// LANE DELETION
// ============================================================================

router.delete('/lanes/:id', authenticateToken, adminOnly, async (req, res) => {
  const useWebhook = req.query.webhook === 'true';

  try {
    const laneResult = await cybercoreQuery(
      `SELECT lane_id, user_id, vxlan_id, name, status, config FROM cybercore_lane WHERE lane_id = $1`,
      [req.params.id]
    );
    if (laneResult.rows.length === 0) {
      return res.status(404).json({ error: 'Lane not found' });
    }

    if (useWebhook) {
      const lane = laneResult.rows[0];
      try {
        console.log(`[Teardown] Using N8N webhook for lane ${lane.lane_id} (VXLAN ${lane.vxlan_id})`);
        const webhookRes = await fetch(N8N_TEARDOWN_WEBHOOK, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            lane_id: lane.lane_id,
            user_id: lane.user_id,
            vxlan_id: lane.vxlan_id,
            name: lane.name,
            config: typeof lane.config === 'string' ? JSON.parse(lane.config) : lane.config
          })
        });
        if (!webhookRes.ok) {
          const errText = await webhookRes.text();
          throw new Error(`N8N teardown webhook failed (${webhookRes.status}): ${errText}`);
        }
        const webhookData = await webhookRes.json();
        console.log(`[Teardown] N8N webhook response:`, webhookData);
        await cybercoreQuery(`DELETE FROM cybercore_lane WHERE lane_id = $1`, [lane.lane_id]);
        return res.json({
          success: true,
          method: 'webhook',
          lane_id: lane.lane_id,
          vxlan_id: lane.vxlan_id,
          webhook_response: webhookData
        });
      } catch (error) {
        console.error('[Teardown] N8N webhook error:', error.message);
        return res.status(502).json({ error: `Teardown webhook failed: ${error.message}` });
      }
    }

    const lane = laneResult.rows[0];
    if (lane.status === 'deleted') {
      return res.status(400).json({ error: 'Lane already deleted' });
    }

    const vxlanId = lane.vxlan_id;
    const laneConfig = typeof lane.config === 'string' ? JSON.parse(lane.config || '{}') : (lane.config || {});

    const vmIdsToDestroy = [];

    if (Array.isArray(laneConfig.vms) && laneConfig.vms.length > 0) {
      for (const vm of laneConfig.vms) {
        vmIdsToDestroy.push({ vmid: vm.vm_id, type: vm.type || 'qemu', label: vm.name || `VM-${vm.vm_id}` });
      }
    } else {
      const challengeVmId = laneConfig.challenge_vm_id || (600000 + vxlanId);
      vmIdsToDestroy.push({ vmid: challengeVmId, type: 'qemu', label: 'challenge' });
    }

    const gatewayVmId = laneConfig.gateway_vm_id || (100000 + vxlanId);
    vmIdsToDestroy.push({ vmid: gatewayVmId, type: 'lxc', label: 'gateway' });

    const attackBoxVmId = laneConfig.attack_box_vm_id || (ATTACK_BOX_VMID_OFFSET + vxlanId);
    vmIdsToDestroy.push({ vmid: attackBoxVmId, type: 'qemu', label: 'attack-box' });

    const goadControllerVmId = 200000 + vxlanId;
    vmIdsToDestroy.push({ vmid: goadControllerVmId, type: 'qemu', label: 'goad-controller' });

    if (Array.isArray(laneConfig.attached_modules)) {
      for (const mod of laneConfig.attached_modules) {
        for (const vm of (mod.vms || [])) {
          vmIdsToDestroy.push({
            vmid: vm.vm_id,
            type: vm.type || 'qemu',
            label: `attached:${mod.challenge_key}:${vm.name}`
          });
        }
      }
    }

    const errors = [];
    const vmNodes = {};
    const allVmIds = vmIdsToDestroy.map(v => v.vmid);
    try {
      const resources = await proxmoxAPI('GET', '/api2/json/cluster/resources?type=vm');
      for (const r of resources) {
        if (allVmIds.includes(r.vmid)) {
          vmNodes[r.vmid] = r.node;
        }
      }
    } catch (e) {
      errors.push(`Could not query cluster resources: ${e.message}`);
    }

    for (const vm of vmIdsToDestroy) {
      const destroyed = await forceDestroyVM(vm.vmid, vm.type, vmNodes[vm.vmid]);
      if (!destroyed && vmNodes[vm.vmid]) {
        errors.push(`${vm.label} (${vm.type} ${vm.vmid}): could not be destroyed`);
      }
    }

    await tailscale.deleteLaneDevices({ vxlanId }).catch(() => {});

    await cybercoreQuery(
      `DELETE FROM cybercore_lane WHERE lane_id = $1`,
      [lane.lane_id]
    );

    logActivity(req, 'delete_lane', 'lane', lane.lane_id, { vxlan_id: vxlanId, errors: errors.length });

    res.json({
      success: true,
      lane_id: lane.lane_id,
      vxlan_id: vxlanId,
      errors: errors.length > 0 ? errors : undefined
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// ============================================================================
// ATTACHED MODULES
// ============================================================================

router.get('/lanes/:laneId/modules', authenticateToken, adminOnly, async (req, res) => {
  try {
    const result = await cybercoreQuery(
      `SELECT lane_id, vxlan_id, name, status, config FROM cybercore_lane WHERE lane_id = $1`,
      [req.params.laneId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Lane not found' });
    const lane = result.rows[0];
    const cfg = typeof lane.config === 'string' ? JSON.parse(lane.config || '{}') : (lane.config || {});
    res.json({
      lane_id: lane.lane_id,
      attached_modules: Array.isArray(cfg.attached_modules) ? cfg.attached_modules : []
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/lanes/:laneId/modules', authenticateToken, adminOnly, async (req, res) => {
  const { challenge_key, module } = req.body || {};
  if (!challenge_key || !module) {
    return res.status(400).json({ error: 'challenge_key and module required' });
  }

  try {
    const laneResult = await cybercoreQuery(
      `SELECT lane_id, user_id, vxlan_id, name, status, config, module_key
       FROM cybercore_lane WHERE lane_id = $1`,
      [req.params.laneId]
    );
    if (laneResult.rows.length === 0) return res.status(404).json({ error: 'Lane not found' });
    const lane = laneResult.rows[0];
    if (lane.status !== 'active') {
      return res.status(409).json({ error: `Lane is not active (status=${lane.status})` });
    }
    const laneConfig = typeof lane.config === 'string' ? JSON.parse(lane.config || '{}') : (lane.config || {});

    const modResult = await cybercoreQuery(
      `SELECT EXISTS (SELECT 1 FROM cybercore_module WHERE key = $1) AS is_installed`,
      [module]
    );
    if (!modResult.rows[0].is_installed) {
      return res.status(400).json({ error: `Module '${module}' is not installed` });
    }

    const challengeResult = await cybercoreQuery(
      `SELECT challenge_id, challenge_key, name, spec, subnet_scheme
       FROM ${module}_challenge
       WHERE challenge_key = $1 AND status = 'active'`,
      [challenge_key]
    );
    if (challengeResult.rows.length === 0) {
      return res.status(404).json({ error: `Challenge '${challenge_key}' not found or not active` });
    }
    const challenge = challengeResult.rows[0];
    const spec = typeof challenge.spec === 'string' ? JSON.parse(challenge.spec) : challenge.spec;
    if (!spec || spec.attachable !== true) {
      return res.status(400).json({ error: `Challenge '${challenge_key}' is not attachable (spec.attachable must be true)` });
    }

    const laneSubnetScheme = laneConfig.subnet_scheme
      || (laneConfig.lane_subnet_base?.startsWith('10.') ? 'v2' : 'v1');
    const laneModule = lane.module_key || laneConfig.module || module;
    const net = resolveLaneNetworking(laneSubnetScheme, laneModule, lane.vxlan_id);
    const laneSubnetBase = (net.lanExt || net.lan).base3;
    const vnets = await proxmoxAPI('GET', '/api2/json/cluster/sdn/vnets');
    const vnet = vnets.find(v => v.tag === lane.vxlan_id);
    if (!vnet) {
      return res.status(503).json({ error: `No VNet found with tag ${lane.vxlan_id} in Proxmox SDN` });
    }

    const gatewayVmId = laneConfig.gateway_vm_id || (100000 + lane.vxlan_id);
    const bestNode = laneConfig.node;
    const templateNode = spec.template_node || getDefaultTemplateNode();
    if (!bestNode) {
      return res.status(500).json({ error: 'Lane config missing node — cannot place attached VMs' });
    }

    res.status(202).json({
      success: true,
      lane_id: lane.lane_id,
      challenge_key,
      status: 'attaching',
      message: 'Attach started. Poll GET /api/admin/lanes/:laneId/modules to watch for completion.'
    });

    logActivity(req, 'attach_module', 'lane', lane.lane_id, { challenge_key, module });

    (async () => {
      try {
        const instance = await attachedModules.attachModuleToLane({
          lane, laneConfig, challenge, spec, module: laneModule,
          laneSubnetBase, vnetName: vnet.vnet, bestNode, templateNode, gatewayVmId,
          proxmoxAPI, waitForTask
        });

        await cybercoreQuery('BEGIN');
        try {
          const cur = await cybercoreQuery(
            `SELECT config FROM cybercore_lane WHERE lane_id = $1 FOR UPDATE`,
            [lane.lane_id]
          );
          const curCfg = typeof cur.rows[0].config === 'string'
            ? JSON.parse(cur.rows[0].config || '{}')
            : (cur.rows[0].config || {});
          const list = Array.isArray(curCfg.attached_modules) ? curCfg.attached_modules : [];
          list.push(instance);
          curCfg.attached_modules = list;
          await cybercoreQuery(
            `UPDATE cybercore_lane SET config = $2::jsonb, updated_at = NOW() WHERE lane_id = $1`,
            [lane.lane_id, JSON.stringify(curCfg)]
          );
          await cybercoreQuery('COMMIT');
        } catch (txErr) {
          await cybercoreQuery('ROLLBACK').catch(() => {});
          throw txErr;
        }
        console.log(`[Attach] Module ${challenge_key} attached to lane ${lane.lane_id} as ${instance.module_instance_id}`);
      } catch (err) {
        console.error(`[Attach] Failed to attach ${challenge_key} to lane ${lane.lane_id}: ${err.message}`);
      }
    })();
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.delete('/lanes/:laneId/modules/:moduleInstanceId', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { laneId, moduleInstanceId } = req.params;
    const laneResult = await cybercoreQuery(
      `SELECT lane_id, vxlan_id, name, status, config FROM cybercore_lane WHERE lane_id = $1`,
      [laneId]
    );
    if (laneResult.rows.length === 0) return res.status(404).json({ error: 'Lane not found' });
    const lane = laneResult.rows[0];
    const laneConfig = typeof lane.config === 'string' ? JSON.parse(lane.config || '{}') : (lane.config || {});
    const list = Array.isArray(laneConfig.attached_modules) ? laneConfig.attached_modules : [];
    const instance = list.find(m => m.module_instance_id === moduleInstanceId);
    if (!instance) return res.status(404).json({ error: 'Attached module instance not found on this lane' });

    const gatewayVmId = laneConfig.gateway_vm_id || (100000 + lane.vxlan_id);
    const bestNode = laneConfig.node || (instance.vms?.[0]?.node);
    if (!bestNode) {
      return res.status(500).json({ error: 'Lane config missing node — cannot destroy attached VMs' });
    }

    const { destroyed, errors } = await attachedModules.detachModuleFromLane({
      moduleInstance: instance,
      bestNode,
      gatewayVmId,
      proxmoxAPI,
      forceDestroyVM
    });

    await cybercoreQuery('BEGIN');
    try {
      const cur = await cybercoreQuery(
        `SELECT config FROM cybercore_lane WHERE lane_id = $1 FOR UPDATE`,
        [laneId]
      );
      const curCfg = typeof cur.rows[0].config === 'string'
        ? JSON.parse(cur.rows[0].config || '{}')
        : (cur.rows[0].config || {});
      curCfg.attached_modules = (curCfg.attached_modules || [])
        .filter(m => m.module_instance_id !== moduleInstanceId);
      await cybercoreQuery(
        `UPDATE cybercore_lane SET config = $2::jsonb, updated_at = NOW() WHERE lane_id = $1`,
        [laneId, JSON.stringify(curCfg)]
      );
      await cybercoreQuery('COMMIT');
    } catch (txErr) {
      await cybercoreQuery('ROLLBACK').catch(() => {});
      throw txErr;
    }

    logActivity(req, 'detach_module', 'lane', laneId, {
      module_instance_id: moduleInstanceId,
      challenge_key: instance.challenge_key,
      destroyed_count: destroyed.length,
      error_count: errors.length
    });

    res.json({
      success: true,
      lane_id: laneId,
      module_instance_id: moduleInstanceId,
      challenge_key: instance.challenge_key,
      destroyed,
      errors: errors.length > 0 ? errors : undefined
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// ============================================================================
// LANE MANAGEMENT
// ============================================================================

router.get('/lanes', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { status } = req.query;
    let sql = `SELECT lane_id, user_id, vxlan_id, name, status, config, created_at, updated_at
               FROM cybercore_lane ORDER BY created_at DESC`;
    const params = [];
    if (status) {
      sql = `SELECT lane_id, user_id, vxlan_id, name, status, config, created_at, updated_at
             FROM cybercore_lane WHERE status = $1 ORDER BY created_at DESC`;
      params.push(status);
    }
    const result = await cybercoreQuery(sql, params);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/lanes/:id', authenticateToken, adminOnly, async (req, res) => {
  try {
    const result = await cybercoreQuery(
      `SELECT lane_id, user_id, vxlan_id, name, status, config, created_at, updated_at
       FROM cybercore_lane WHERE lane_id = $1`,
      [req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Lane not found' });
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.patch('/lanes/:id/internet', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { enabled } = req.body;
    if (typeof enabled !== 'boolean') {
      return res.status(400).json({ error: 'enabled (boolean) required' });
    }

    const laneResult = await cybercoreQuery(
      `SELECT lane_id, vxlan_id, config, status FROM cybercore_lane WHERE lane_id = $1`,
      [req.params.id]
    );
    if (laneResult.rows.length === 0) return res.status(404).json({ error: 'Lane not found' });

    const lane = laneResult.rows[0];
    if (lane.status !== 'active') {
      return res.status(400).json({ error: `Lane must be active (current: ${lane.status})` });
    }

    const config = typeof lane.config === 'string' ? JSON.parse(lane.config) : lane.config;
    const node = config?.node;
    const gatewayVmId = config?.gateway_vm_id || (100000 + lane.vxlan_id);

    if (!node) return res.status(400).json({ error: 'Lane config missing node info' });

    const cmd = enabled
      ? 'iptables -t nat -C POSTROUTING -o wan0 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o wan0 -j MASQUERADE; iptables -C FORWARD -i lan0 -o wan0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i lan0 -o wan0 -j ACCEPT; iptables -C FORWARD -i wan0 -o lan0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i wan0 -o lan0 -m state --state RELATED,ESTABLISHED -j ACCEPT; echo 1 > /proc/sys/net/ipv4/ip_forward'
      : 'iptables -t nat -D POSTROUTING -o wan0 -j MASQUERADE 2>/dev/null; iptables -D FORWARD -i lan0 -o wan0 -j ACCEPT 2>/dev/null; iptables -D FORWARD -i wan0 -o lan0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; echo 0 > /proc/sys/net/ipv4/ip_forward';

    try {
      await proxmoxAPI('POST', `/api2/json/nodes/${node}/lxc/${gatewayVmId}/exec`, {
        command: JSON.stringify(['sh', '-c', cmd])
      });
    } catch (execErr) {
      return res.status(502).json({
        error: `Could not execute command on gateway: ${execErr.message}`,
        hint: 'The Proxmox exec API may not be available.'
      });
    }

    const updatedConfig = { ...config, internet_enabled: enabled };
    await cybercoreQuery(
      `UPDATE cybercore_lane SET config = $1, updated_at = NOW() WHERE lane_id = $2`,
      [JSON.stringify(updatedConfig), lane.lane_id]
    );

    logActivity(req, 'toggle_internet', 'lane', lane.lane_id, { enabled, vxlan_id: lane.vxlan_id });

    res.json({ success: true, lane_id: lane.lane_id, internet_enabled: enabled });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// ============================================================================
// MODULES & CHALLENGES
// ============================================================================

router.get('/modules', authenticateToken, adminOnly, async (req, res) => {
  try {
    const result = await cybercoreQuery(`SELECT * FROM cybercore_module WHERE active = TRUE ORDER BY key`);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/challenges/:module', authenticateToken, adminOnly, async (req, res) => {
  try {
    const mod = req.params.module.replace(/[^a-z0-9_]/gi, '');
    const tableName = `${mod}_challenge`;

    const tableCheck = await cybercoreQuery(
      `SELECT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = $1
      )`,
      [tableName]
    );

    if (!tableCheck.rows[0].exists) {
      return res.json([]);
    }

    const result = await cybercoreQuery(
      `SELECT challenge_id, challenge_key, name, difficulty, status, spec FROM ${tableName} WHERE status = 'active' ORDER BY name`
    );
    const rows = result.rows.map(r => {
      const spec = typeof r.spec === 'string' ? (() => { try { return JSON.parse(r.spec || '{}'); } catch { return {}; } })() : (r.spec || {});
      return { ...r, spec, attachable: spec.attachable === true };
    });
    res.json(rows);
  } catch (error) {
    res.json([]);
  }
});

module.exports = router;
