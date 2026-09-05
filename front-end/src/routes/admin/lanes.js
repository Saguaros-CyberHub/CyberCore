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
const { cybercoreQuery, cybercorePool } = require('../../utils/cybercore-db');
const { query } = require('../../utils/db');
const { buildDeployPreview } = require('../../middleware/deployment-guards');
const { logActivity } = require('../../middleware/activity-logger');
const { waitForGuestAgent, executeScriptsOnVM, getVMIPs } = require('../../utils/script-executor');
const { plantFlagsForLane } = require('../../utils/flag-manager');
const { selectBestNode } = require('../../utils/node-selector');
const goadDeploy = require('../../utils/goad-deploy');
const { withGoadAgentVulnScripts } = require('../../utils/goad-agent-attach');
const { resolveGoadExternalPins, resolveSpecAddressing, writeLaneReservations,
  applyPrebakedFixedSubnet, validateGoadLaneAddressing } = require('../../utils/challenge-lane-deployer');
const tailscale = require('../../utils/tailscale');
const attachedModules = require('../../utils/attached-modules');
const { guacAPI } = require('../../utils/guacamole');
const {
  V3_INTERNAL_TAG_OFFSET,
  ATTACK_BOX_VMID_OFFSET,
  resolveGatewayVmid,
  resolveLaneNetworking,
  configureLaneTailscale,
  formatLaneGatewayNet0,
  resolveVmNics,
  resolveSegmentBridges,
} = require('../../utils/lane-networking');
const { buildLaneTopology } = require('../../utils/lane-topology');
const laneWan = require('../../utils/lane-wan-allocator');
const { claimsSql } = require('../../utils/lane-claims');
const guards = require('../../utils/reconcile-guards');
const { buildLaneVmIndex } = require('../../utils/reconcile-audit');
// The single canonical lane teardown. Required lazily-safe at module scope: this
// route file is loaded by routes/admin.js, which lane-deployer.js does not import,
// so there is no cycle.
const laneDeployer = require('../../utils/lane-deployer');

const adminOnly = requireRole('admin');


// ============================================================================
// WAN TRANSIT ADDRESS CONFLICTS
// ============================================================================

/**
 * GET /wan-conflicts — live lanes sharing a gateway WAN transit address.
 *
 * Read-only. Repairs nothing, on purpose: both lanes in a pair have running VMs
 * and a student attached to each, so which one moves is an operator decision.
 *
 * Deliberately NOT nested under /lanes. Express matches in registration order
 * and `router.get('/lanes/:id')` is registered further down this file, so
 * `/lanes/wan-conflicts` would be swallowed by it and 'wan-conflicts' passed to
 * Postgres as a UUID — a 500 with a 22P02, not a 404.
 */
router.get('/wan-conflicts', authenticateToken, adminOnly, async (req, res) => {
  try {
    const conflicts = await laneWan.findWanIpConflicts();
    res.json({
      conflicts,
      count: conflicts.length,
      lanes_affected: conflicts.reduce((n, c) => n + c.lane_count, 0),
    });
  } catch (error) {
    console.error('[Admin] WAN conflict audit error:', error.message);
    res.status(500).json({ error: error.message });
  }
});


// ============================================================================
// LANE DEPLOYMENT
// ============================================================================

router.post('/deploy-lane', authenticateToken, adminOnly, async (req, res) => {
  const { challenge_key, module, event_id, attack_boxes, confirm, vuln_scripts: selectedVulnScripts } = req.body;
  const user_id = req.body.user_id || req.user.userId;
  if (!challenge_key || !module) {
    return res.status(400).json({ error: 'challenge_key and module required' });
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
       FROM ${module.replace(/[^a-z0-9_]/gi, '')}_challenge
       WHERE challenge_key = $1 AND status = 'active'`,
      [challenge_key]
    );
    if (challengeResult.rows.length === 0) {
      return res.status(404).json({ error: `Challenge '${challenge_key}' not found or not active` });
    }
    const challenge = challengeResult.rows[0];
    const spec = goadDeploy.prepareGoadDeploymentSpec(
      typeof challenge.spec === 'string' ? JSON.parse(challenge.spec) : challenge.spec);
    const laneScripts = withGoadAgentVulnScripts(selectedVulnScripts, spec);
    const subnetScheme = challenge.subnet_scheme || 'v1';
    validateGoadLaneAddressing(spec, subnetScheme);

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
          -- Was NOT IN ('error') — see utils/lane-claims.js.
          AND ${claimsSql()}
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
    const gatewayTemplateNode = await findTemplateNode(gatewayVmid, getDefaultTemplateNode());
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
    // WAN transit address, allocated and ARP-verified before the row exists.
    // Failing here is better than a lane that deploys onto an address another
    // lane is already answering for.
    let laneWanIp = null;
    if (subnetScheme === 'v2' || subnetScheme === 'v3') {
      try {
        laneWanIp = (await laneWan.allocateLaneWanIps(1, { probeNode: bestNode }))[0].address;
      } catch (e) {
        return res.status(503).json({ error: e.message });
      }
    }

    const laneInsert = await cybercoreQuery(
      `INSERT INTO cybercore_lane (user_id, vxlan_id, name, status, config, module_key, gateway_wan_ip, created_at, updated_at)
       VALUES ($1, $2, $3, 'deploying', $4::jsonb, $5, $6::inet, NOW(), NOW())
       RETURNING lane_id, user_id, vxlan_id, name, status, created_at`,
      [user_id, vxlanId, laneName, laneConfig, module, laneWanIp]
    );
    const lane = laneInsert.rows[0];
    if (laneWanIp) await laneWan.recordLaneWanLease({ address: laneWanIp, laneId: lane.lane_id, vxlanId });

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
      let goadMeta = null;
      try {
        const net = resolveLaneNetworking(subnetScheme, module, vxlanId, { wanIp: laneWanIp });
        const isV3 = subnetScheme === 'v3';
        applyPrebakedFixedSubnet(net, isV3, spec);
        const vnetExtName = vnet.vnet;
        const vnetIntName = isV3 ? vnetInt.vnet : vnet.vnet;
        const laneSubnetBase = isV3 ? net.lanExt.base3 : net.lan.base3;
        const goadSubnetBase = isV3 ? net.lanInt.base3 : net.lan.base3;

        const goadMacs = goadDeploy.prepareGoadMacs(spec, vxlanId, goadSubnetBase);

        const vmSpecs = spec.vms || [{ name: challenge_key, template_vmid: templateVmid, type: 'qemu', vm_offset: 600000 }];
        const deployedVMs = [];
        const externalPins = resolveGoadExternalPins(spec);
        const { pinnedHosts, dnsRecords } = resolveSpecAddressing({
          specVms: vmSpecs, goadMacs, requiredIpOctets: externalPins,
          subnetScheme, laneSubnetBase, goadSubnetBase, reserved: [1, 5, 50],
        });
        await cybercoreQuery(
          `UPDATE cybercore_lane SET config = config || $2::jsonb WHERE lane_id = $1`,
          [lane.lane_id, JSON.stringify({ node: bestNode, gateway_vm_id: 100000 + vxlanId,
            vms: vmSpecs.map(v => ({ vm_id: (v.vm_offset || 600000) + vxlanId,
              name: v.name || challenge_key, type: v.type || 'qemu', node: bestNode })) })]
        );

        for (const vmSpec of vmSpecs) {
          const vmId = (vmSpec.vm_offset || 600000) + vxlanId;
          const vmType = vmSpec.type || 'qemu';
          const vmTemplate = vmSpec.template_vmid || templateVmid;
          const vmTemplateNode = await findTemplateNode(vmTemplate, spec.template_node || getDefaultTemplateNode());
          const vmName = vmSpec.name || challenge_key;
          const isGoadVm = !!goadMacs[vmName];
          // Single owner for VM→VNet attachment: explicit spec.vms[].nics when
          // the topology canvas authored them, the historical name/role
          // derivation otherwise. See utils/lane-networking.resolveVmNics.
          const { nets, dualHomed } = resolveVmNics(vmSpec, {
            subnetScheme,
            bridges: resolveSegmentBridges(subnetScheme, vnetExtName, vnetIntName),
            goadMac: goadMacs[vmName]?.mac,
            pinnedMac: goadMacs[vmName]?.mac || (externalPins[vmName] != null
              ? goadDeploy.macForOctet(externalPins[vmName], vxlanId) : null),
            goadVm: goadMacs[vmName],
            isGoadVm,
          });

          console.log(`[Deploy] Cloning ${vmType} template ${vmTemplate} → ${vmId} (${vmName})`);

          if (vmType === 'lxc') {
            const cloneResult = await proxmoxAPI('POST', `/api2/json/nodes/${vmTemplateNode}/lxc/${vmTemplate}/clone`, {
              newid: vmId, hostname: `${laneName}-${vmName}`.replace(/[^a-z0-9-]/gi, '-').substring(0, 63).toLowerCase(), full: 1, target: bestNode,
              description: `Challenge: ${challenge_key}\nVM: ${vmName}\nLane: ${lane.lane_id}`,
              pool: `${module}-pool`
            });
            if (cloneResult) await waitForTask(vmTemplateNode, cloneResult);
            await proxmoxAPI('PUT', `/api2/json/nodes/${bestNode}/lxc/${vmId}/config`, nets);
          } else {
            const cloneResult = await proxmoxAPI('POST', `/api2/json/nodes/${vmTemplateNode}/qemu/${vmTemplate}/clone`, {
              newid: vmId, name: `${laneName}-${vmName}`.replace(/[^a-z0-9-]/gi, '-').substring(0, 63).toLowerCase(), full: 1, target: bestNode,
              description: `Challenge: ${challenge_key}\nVM: ${vmName}\nLane: ${lane.lane_id}`,
              pool: `${module}-pool`
            });
            if (cloneResult) await waitForTask(vmTemplateNode, cloneResult);

            if (dualHomed) {
              await proxmoxAPI('POST', `/api2/json/nodes/${bestNode}/qemu/${vmId}/config`, nets);
              // .240, not .50 — the gateway firstboot reserves ext .50 for Kali's
              // RDP DNAT (wan0:3389 → ext.50), so a DMZ host pinned there stole
              // student RDP sessions. Matches challenge-lane-deployer.js, which
              // fixed this; this path and lab-networks.js still had the collision.
              if (isV3) {
                await proxmoxAPI('POST', `/api2/json/nodes/${bestNode}/qemu/${vmId}/config`, {
                  ipconfig0:  `ip=${net.lanExt.base3}.240/24,gw=${net.lanExt.gatewayIp}`,
                  ipconfig1:  `ip=${net.lanInt.base3}.240/24`,
                  nameserver: net.lanExt.gatewayIp,
                  citype:     'nocloud'
                });
                await proxmoxAPI('PUT', `/api2/json/nodes/${bestNode}/qemu/${vmId}/cloudinit`).catch(() => {});
              }
            } else {
              const goadVm = goadMacs[vmName];
              const vmConfig = { ...nets };
              if (goadVm?.memory)  vmConfig.memory  = goadVm.memory;
              if (goadVm?.balloon) vmConfig.balloon = goadVm.balloon;
              if (goadVm?.cores)   vmConfig.cores   = goadVm.cores;
              await proxmoxAPI('POST', `/api2/json/nodes/${bestNode}/qemu/${vmId}/config`, vmConfig);
            }
          }

          if (spec.goad?.prebaked && isGoadVm && vmType === 'qemu') {
            const ci = await laneDeployer.findCloudInitDrive(bestNode, vmId);
            if (ci) await proxmoxAPI('PUT', `/api2/json/nodes/${bestNode}/qemu/${vmId}/config`, { delete: ci });
          }
          deployedVMs.push({ vm_id: vmId, name: vmName, type: vmType, node: bestNode });
        }

        const gatewayVmId = 100000 + vxlanId;
        // Per-lane bootstrap secret embedded as `-b<16hex>` hostname suffix.
        // firstboot greps it back and passes ?secret=… to /api/lane-bootstrap,
        // replacing source-IP gating. See utils/lane-networking.js
        // configureLaneTailscale + the firstboot hook under
        // infrastructure/proxmox-templates/sdn-templates/v2_gateway/. Hostname budget:
        // 63 chars; reserve 18 for `-b<16hex>`.
        const claimSecret = crypto.randomBytes(8).toString('hex');
        const baseHost = `${laneName}-gateway`.substring(0, 63 - 18).toLowerCase()
          .replace(/[^a-z0-9-]/g, '-').replace(/-+$/g, '');
        const gwHostname = `${baseHost}-b${claimSecret}`;

        const gwCloneResult = await proxmoxAPI('POST', `/api2/json/nodes/${gatewayTemplateNode}/lxc/${gatewayVmid}/clone`, {
          newid: gatewayVmId,
          hostname: gwHostname,
          full: 1,
          target: bestNode,
          description: `Challenge: ${challenge_key}\nUser ID: ${user_id}\nLane ID: ${lane.lane_id}\nModule: ${module}`,
          pool: `${module}-pool`
        });

        if (gwCloneResult) await waitForTask(gatewayTemplateNode, gwCloneResult);

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
        const writeReservations = () => writeLaneReservations({
          gatewayVmId, node: bestNode, vxlanId, goadMacs, pinnedHosts, dnsRecords,
          spec, subnetScheme, extSubnetBase: laneSubnetBase, intSubnetBase: goadSubnetBase,
          liveGoadController: !spec.goad?.prebaked, laneId: lane.lane_id, logTag: '[Deploy]',
        });
        if (spec.goad?.enabled) await writeReservations();

        for (const vm of deployedVMs) {
          const startPath = vm.type === 'lxc'
            ? `/api2/json/nodes/${vm.node}/lxc/${vm.vm_id}/status/start`
            : `/api2/json/nodes/${vm.node}/qemu/${vm.vm_id}/status/start`;
          await proxmoxAPI('POST', startPath);
        }

        if (spec.goad?.enabled) {
          let goadError = null;
          try {
            const result = spec.goad.prebaked
              ? await goadDeploy.deployPrebakedGoadLane({
                lane, spec, vxlanId, gatewayVmId, bestNode,
                laneSubnetBase: goadSubnetBase, extSubnetBase: laneSubnetBase,
                deployedVMs, proxmoxAPI,
              })
              : await goadDeploy.deployGoadLane({
              lane, spec, module, vnet: isV3 ? vnetInt : vnet, vxlanId, gatewayVmId,
              bestNode, templateNode: await findTemplateNode(goadDeploy.CONTROLLER_TEMPLATE_VMID, getDefaultTemplateNode()),
              laneSubnetBase: goadSubnetBase,
              extSubnetBase: laneSubnetBase, deployedVMs,
              proxmoxAPI, waitForTask, query: cybercoreQuery
            });
            goadMeta = result?.goadMeta || { status: 'provisioned', prebaked: true };
            await logActivity(req, 'lane.goad_provisioned', 'lane', lane.lane_id,
              { forest_rename: result?.goadMeta?.forest_rename || null });
          } catch (goadErr) {
            console.error(`[GOAD] Provisioning failed for lane ${lane.lane_id}:`, goadErr.message);
            goadError = goadErr;
            goadMeta = goadErr.goadMeta || { status: 'failed', error: goadErr.message };
          } finally {
            if (!spec.goad.prebaked) {
              try {
                await writeReservations();
              } catch (reservationError) {
                goadMeta = { ...goadMeta, status: 'failed', dhcp_error: reservationError.message };
                goadError = goadError || reservationError;
              }
            }
          }
          if (goadError) {
            goadError.goadMeta = goadMeta;
            throw goadError;
          }
        }

        if (laneScripts && laneScripts.length > 0) {
          console.log(`[Deploy] Running ${laneScripts.length} vuln scripts on lane ${lane.lane_id}...`);

          const scriptEntries = laneScripts.map(s => ({
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
            const vmScriptSlugs = laneScripts
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

        // Plant HTB-style user/root capture flags, after any vuln scripts so a
        // script that recreates a user profile can't clobber the files.
        // Best-effort — per-flag failures are recorded as plant_status='failed'.
        try {
          await plantFlagsForLane({
            laneId: lane.lane_id,
            userId: lane.user_id,
            vms: deployedVMs,
            specVms: spec.vms || [],
            api: proxmoxAPI,
            logTag: '[Deploy][Flags]'
          });
        } catch (flagErr) {
          console.error(`[Deploy] Flag planting failed for lane ${lane.lane_id}: ${flagErr.message}`);
        }

        const primaryVm = deployedVMs[0];
        const activeConfig = JSON.stringify({
          ...(goadMeta ? { goad: goadMeta } : {}),
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
          `UPDATE cybercore_lane SET status = 'active', config = config || $2::jsonb, updated_at = NOW() WHERE lane_id = $1`,
          [lane.lane_id, activeConfig]
        );
        console.log(`Lane ${lane.lane_id} deployed successfully (VXLAN ${vxlanId}, ${deployedVMs.length} VMs)`);
      } catch (err) {
        console.error(`Lane ${lane.lane_id} deployment failed:`, err.message);
        await cybercoreQuery(
          `UPDATE cybercore_lane SET status = 'suspended', config = config || $2::jsonb, updated_at = NOW() WHERE lane_id = $1`,
          [lane.lane_id, JSON.stringify({ error: err.message,
            ...((err.goadMeta || goadMeta) ? { goad: err.goadMeta || goadMeta } : {}) })]
        ).catch(() => {});
        await logActivity(req, 'lane.provisioning_failed', 'lane', lane.lane_id,
          { provisioning_status: 'failed', forest_rename: (err.goadMeta || goadMeta)?.forest_rename || null });
      }
    })();

  } catch (error) {
    res.status(error.status || 500).json({ error: error.message });
  }
});


// ============================================================================
// LANE DELETION
// ============================================================================

router.delete('/lanes/:id', authenticateToken, adminOnly, async (req, res) => {
  try {
    const laneResult = await cybercoreQuery(
      `SELECT lane_id, user_id, vxlan_id, name, status, config FROM cybercore_lane WHERE lane_id = $1`,
      [req.params.id]
    );
    if (laneResult.rows.length === 0) {
      return res.status(404).json({ error: 'Lane not found' });
    }

    const lane = laneResult.rows[0];
    if (lane.status === 'deleted') {
      return res.status(400).json({ error: 'Lane already deleted' });
    }

    // Delegates to the ONE hardened teardown. This route used to carry its own
    // copy: it never read cfg.workstations[], so every allocated slot-1+ machine
    // leaked; it had no ownership check, no orphan retry rounds and no disk sweep;
    // and it deleted the lane row unconditionally, which orphaned any VM that
    // refused to die AND released its vxlan_id for the next deploy to collide with.
    //
    // It also derived VMIDs from a null vxlan_id — 600000 + null is 600000 — and
    // handed those to forceDestroyVM, which then scanned every node in the cluster
    // for them.
    const result = await laneDeployer.teardownLanes([lane.lane_id], {
      purgeJanitors: true,
    });

    logActivity(req, 'delete_lane', 'lane', lane.lane_id, {
      vxlan_id: lane.vxlan_id,
      vms_destroyed: result.vms_destroyed,
      lanes_deleted: result.lanes_deleted,
      kept_for_retry: result.lanes_kept_for_retry,
      errors: result.errors.length,
    });

    // KEYS ON lanes_kept_for_retry, never errors.length — teardownLanes returns
    // errors: [...errors, ...warnings], and a Guacamole 403 (which leaves nothing
    // running anywhere) lands in that array. The old route answered success:true
    // even when a VM had refused to die.
    const kept = result.lanes_kept_for_retry || 0;
    res.status(kept === 0 ? 200 : 207).json({
      success: kept === 0,
      lane_id: lane.lane_id,
      vxlan_id: lane.vxlan_id,
      vms_destroyed: result.vms_destroyed,
      orphan_disks_swept: result.orphan_disks_swept,
      // The row is kept as 'error' so the survivors stay reachable for a retry;
      // it still holds its vxlan_id, so nothing can be deployed on top of them.
      lane_kept_for_retry: kept > 0,
      survivors: result.survivors,
      ownership_skipped: result.ownership_skipped,
      contested: result.contested,
      errors: result.errors.length > 0 ? result.errors : undefined,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// ============================================================================
// ATTACHED MODULES
// ============================================================================

// ============================================================================
// PURGE A LANE
// ============================================================================
// The one-click repair for a lane the audit reports as drifted: released but
// still running, half torn down, or a tombstone whose machines never went.
//
// DELETE /lanes/:id refuses those cases by design — it 400s on an already
// 'deleted' row, and a lane whose teardown failed comes back as 'error' with no
// obvious next step. That gap is the reported symptom: a lane row that is stuck,
// with machines still on Proxmox and no button that does anything about it.
//
// Not a sixth teardown. It re-verifies, then calls the same teardownLanes()
// everything else does, so the contested-VXLAN skip, the ownership check, the
// retry rounds, the disk sweep and the row-delete gate all apply unchanged.
// ============================================================================

router.post('/lanes/:id/purge', authenticateToken, adminOnly, async (req, res) => {
  const laneId = req.params.id;
  const { confirm_vxlan, audit_job_id, dry_run, force } = req.body || {};

  try {
    await guards.requireFreshAudit(audit_job_id);
    const cluster = await guards.readTrustedClusterView();

    const laneRes = await cybercoreQuery(
      `SELECT lane_id, user_id, vxlan_id, name, status, config, created_at
         FROM cybercore_lane WHERE lane_id = $1`,
      [laneId]
    );
    if (laneRes.rows.length === 0) return res.status(404).json({ error: 'Lane not found' });
    const lane = laneRes.rows[0];

    // A lane being built right now is not drift. Deploys are fire-and-forget
    // async work inside this process with their progress in an in-memory global,
    // and that registry is the only mutex this application has.
    if (lane.status === 'deploying' && force !== true) {
      const inFlight = laneDeployer.listProgressIds()
        .some(id => JSON.stringify(laneDeployer.readProgress(id) || {}).includes(laneId));
      return res.status(409).json({
        error: inFlight
          ? 'A deploy is running for this lane right now — purging would race it. Wait for it to finish.'
          : 'This lane is marked deploying. If the deploy really is dead, retry with force.',
        deploy_in_flight: inFlight,
        needs_force: true,
      });
    }

    // A typed confirmation token, the same shape fix-zone-peers uses for its
    // peer set: the operator has to name the VXLAN they think they are freeing.
    // Both null counts as a match, for a lane that never got one.
    const claimed = lane.vxlan_id == null ? null : Number(lane.vxlan_id);
    const offered = confirm_vxlan == null ? null : Number(confirm_vxlan);
    if (claimed !== offered) {
      return res.status(409).json({
        error: `VXLAN confirmation does not match: this lane holds ${claimed === null ? 'no VXLAN' : claimed}.`,
        expected_vxlan: claimed,
      });
    }

    // Whether another live lane has already recycled this row's VXLAN. If so
    // teardownLanes will destroy NOTHING and remove the record only — which is
    // correct, and the operator has to be told, because "purge" that destroys no
    // machines otherwise reads as a failure.
    let contested = [];
    if (lane.vxlan_id != null) {
      const others = await cybercoreQuery(
        `SELECT lane_id, name, status FROM cybercore_lane
          WHERE vxlan_id = $1 AND lane_id <> $2 AND ${claimsSql()}`,
        [lane.vxlan_id, laneId]
      );
      contested = others.rows;
    }

    // Everything this lane recorded, and whether each is actually out there.
    const index = buildLaneVmIndex([lane], {
      includeWorkstations: true,
      includeNullVxlan: true,
    });
    const targets = (index.expectedByLane.get(laneId) || []).map(vmid => ({
      vmid,
      live: cluster.liveVmIds.has(vmid),
      node: cluster.vmNodeMap.get(vmid) || null,
      name: cluster.vmNameMap.get(vmid) || null,
    }));

    if (dry_run === true) {
      return res.json({
        dry_run: true,
        lane_id: laneId,
        lane_name: lane.name,
        vxlan_id: lane.vxlan_id,
        status: lane.status,
        targets,
        live_count: targets.filter(t => t.live).length,
        contested,
        // The record goes either way; only the machines are conditional.
        will_destroy_vms: contested.length === 0,
      });
    }

    const result = await laneDeployer.teardownLanes([laneId], { purgeJanitors: true });
    const kept = result.lanes_kept_for_retry || 0;

    logActivity(req, 'purge_lane', 'lane', laneId, {
      vxlan_id: lane.vxlan_id,
      prior_status: lane.status,
      vms_destroyed: result.vms_destroyed,
      orphan_disks_swept: result.orphan_disks_swept,
      kept_for_retry: kept,
      contested: contested.length,
      errors: result.errors.length,
    });

    res.status(kept === 0 ? 200 : 207).json({
      purged: kept === 0,
      lane_id: laneId,
      vxlan_id: lane.vxlan_id,
      vms_destroyed: result.vms_destroyed,
      orphan_disks_swept: result.orphan_disks_swept,
      lane_kept_for_retry: kept > 0,
      survivors: result.survivors,
      ownership_skipped: result.ownership_skipped,
      contested: result.contested,
      errors: result.errors.length > 0 ? result.errors : undefined,
    });
  } catch (error) {
    if (guards.handleGuardError(error, res)) return;
    console.error(`[Purge] Lane ${laneId}: ${error.message}`);
    res.status(500).json({ error: error.message });
  }
});


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
      // gateway_wan_ip is read back, never re-derived: the derivation was not
      // unique, so recomputing it for an existing lane can name a DIFFERENT
      // lane's gateway.
      `SELECT lane_id, user_id, vxlan_id, name, status, config, module_key, host(gateway_wan_ip) AS gateway_wan_ip
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
       FROM ${module.replace(/[^a-z0-9_]/gi, '')}_challenge
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
    const net = resolveLaneNetworking(laneSubnetScheme, laneModule, lane.vxlan_id, {
      wanIp: lane.gateway_wan_ip || laneConfig.gateway_wan_ip,
    });
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

        // Read-modify-write of config under a real row lock, on ONE PINNED
        // client. cybercoreQuery is cybercorePool.query(), which checks a client
        // out per statement and releases it, so BEGIN / SELECT … FOR UPDATE /
        // UPDATE / COMMIT ran on four unrelated backends: the lock was taken and
        // dropped inside its own implicit transaction, the UPDATE autocommitted,
        // the COMMIT landed on a connection with nothing open, and the backend
        // that ran BEGIN went back to the pool idle-in-transaction — still
        // holding the cybercore_lane row lock — to be inherited by whatever query
        // grabbed it next. Two attaches (or an attach racing a detach) on the
        // same lane would then both read the same attached_modules array and the
        // second write would drop the first, leaving that module's VMs running
        // with nothing referencing them. Same pattern as withLaneConfig() in
        // modules/crucible/plugins/cle/utils/vuln-lab-provision.js.
        const client = await cybercorePool.connect();
        try {
          await client.query('BEGIN');
          const cur = await client.query(
            `SELECT config FROM cybercore_lane WHERE lane_id = $1 FOR UPDATE`,
            [lane.lane_id]
          );
          const curCfg = typeof cur.rows[0].config === 'string'
            ? JSON.parse(cur.rows[0].config || '{}')
            : (cur.rows[0].config || {});
          const list = Array.isArray(curCfg.attached_modules) ? curCfg.attached_modules : [];
          list.push(instance);
          curCfg.attached_modules = list;
          await client.query(
            `UPDATE cybercore_lane SET config = $2::jsonb, updated_at = NOW() WHERE lane_id = $1`,
            [lane.lane_id, JSON.stringify(curCfg)]
          );
          await client.query('COMMIT');
        } catch (txErr) {
          await client.query('ROLLBACK').catch(() => {});
          throw txErr;
        } finally {
          // Exactly once, on every path — a client leaked here is a pool slot
          // gone for the life of the process.
          client.release();
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

    // Strip the instance from config ONLY when its machines are verifiably gone.
    //
    // config.attached_modules[] is the sole record of an instance's VMIDs — they
    // are 800000 + slot*10000 + vxlan, but nothing else stores which slots are in
    // use. Removing the entry while a VM survived loses the handle on it for good:
    // the reconcile audit is then the only thing that can find it, and only because
    // it recomputes the whole 8xxxxx band.
    //
    // On failure the instance stays recorded with a detach_errors key, mirroring
    // the teardown_errors that teardownLanes writes, so a retry can find the VMs.
    if (errors.length > 0) {
      await cybercoreQuery(
        `UPDATE cybercore_lane
            SET config = jsonb_set(
                  config,
                  '{attached_modules}',
                  COALESCE((
                    SELECT jsonb_agg(
                             CASE WHEN m->>'module_instance_id' = $2
                                  THEN m || $3::jsonb
                                  ELSE m END)
                      FROM jsonb_array_elements(config->'attached_modules') m
                  ), '[]'::jsonb)),
                updated_at = NOW()
          WHERE lane_id = $1`,
        [laneId, moduleInstanceId, JSON.stringify({ detach_errors: errors.slice(0, 20) })]
      ).catch(e => errors.push(`Could not record detach errors: ${e.message}`));

      console.warn(
        `[Detach] Lane ${laneId} module ${moduleInstanceId}: ${errors.length} error(s) — ` +
        `keeping the instance in config so its surviving VMs stay reachable for a retry.`
      );

      logActivity(req, 'detach_module', 'lane', laneId, {
        module_instance_id: moduleInstanceId,
        challenge_key: instance.challenge_key,
        destroyed_count: destroyed.length,
        error_count: errors.length,
        kept_for_retry: true,
      });

      return res.status(207).json({
        success: false,
        lane_id: laneId,
        module_instance_id: moduleInstanceId,
        challenge_key: instance.challenge_key,
        destroyed,
        kept_for_retry: true,
        errors,
      });
    }

    // One pinned client for the whole transaction — see the attach handler above
    // for why routing these four statements through the pool a statement at a
    // time strands an idle-in-transaction backend still holding this lane's row
    // lock, and lets a concurrent attach clobber the write.
    const client = await cybercorePool.connect();
    try {
      await client.query('BEGIN');
      const cur = await client.query(
        `SELECT config FROM cybercore_lane WHERE lane_id = $1 FOR UPDATE`,
        [laneId]
      );
      const curCfg = typeof cur.rows[0].config === 'string'
        ? JSON.parse(cur.rows[0].config || '{}')
        : (cur.rows[0].config || {});
      curCfg.attached_modules = (curCfg.attached_modules || [])
        .filter(m => m.module_instance_id !== moduleInstanceId);
      await client.query(
        `UPDATE cybercore_lane SET config = $2::jsonb, updated_at = NOW() WHERE lane_id = $1`,
        [laneId, JSON.stringify(curCfg)]
      );
      await client.query('COMMIT');
    } catch (txErr) {
      await client.query('ROLLBACK').catch(() => {});
      throw txErr;
    } finally {
      client.release();
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

/**
 * GET /api/admin/lanes/:laneId/topology
 *
 * The live shape of a deployed lane, in the same { segments, nodes } payload the
 * authoring canvas consumes — so one renderer draws both.
 *
 * The reading of Proxmox lives in utils/lane-topology.js because the CLE
 * instructor route needs the identical diagram under different authorization
 * (course-scoped rather than adminOnly). This handler is the admin door onto it:
 * any lane, no scoping.
 */
router.get('/lanes/:laneId/topology', authenticateToken, adminOnly, async (req, res) => {
  try {
    res.json(await buildLaneTopology(req.params.laneId));
  } catch (error) {
    res.status(error.status || 500).json({ error: error.message });
  }
});

module.exports = router;
