'use strict';

const express = require('express');
const { authenticateToken, requireRole } = require('../../middleware/auth');
const { eligibleLaneSql } = require('../../utils/caldera-lane-agents');

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const MAX_TARGETS = 200;

function createRouter(deps = {}) {
  const router = express.Router();
  const query = deps.query || ((...args) => require('../../utils/cybercore-db').cybercoreQuery(...args));
  const service = deps.service || require('../../utils/wazuh-lane-agents').createService();
  const audit = deps.audit || require('../../utils/audit');
  const adminOnly = requireRole('admin');

  function fail(res, error) {
    // Service errors are deliberately sanitized; unexpected infrastructure errors
    // must not disclose database connection strings or API credentials.
    const status = Number.isInteger(error.status) && error.status >= 400 && error.status < 600 ? error.status : 500;
    return res.status(status).json({ error: error.safe === true ? error.message
      : 'Could not process the Wazuh agent request. Refresh status and retry.' });
  }

  router.get('/wazuh-agents', authenticateToken, adminOnly, async (req, res) => {
    res.set('Cache-Control', 'no-store');
    try {
      // vxlan_id and created_at feed the dialog's grouping and sort controls only.
      // They are projected through wazuh-lane-agents' publicLaneContext allowlist;
      // the raw config row is never echoed back.
      const lanes = await query(`SELECT lane_id, name, status, config, vxlan_id, created_at FROM cybercore_lane
        WHERE ${eligibleLaneSql()} ORDER BY name, lane_id`);
      res.json(await service.status(lanes.rows));
    } catch (error) { fail(res, error); }
  });

  router.post('/wazuh-agents/batch', authenticateToken, adminOnly, async (req, res) => {
    res.set('Cache-Control', 'no-store');
    try {
      const raw = req.body?.targets;
      if (!Array.isArray(raw) || !raw.length || raw.length > MAX_TARGETS) {
        return res.status(400).json({ error: `Select between 1 and ${MAX_TARGETS} machines.` });
      }
      const seen = new Set();
      const targets = [];
      for (const target of raw) {
        if (!target || typeof target.lane_id !== 'string' || !UUID.test(target.lane_id)
          || !Number.isSafeInteger(target.vm_id) || target.vm_id <= 0
          || !['windows', 'linux'].includes(target.platform)) {
          return res.status(400).json({ error: 'Every target needs a lane, VM and Windows or Linux platform.' });
        }
        if (target.windows_telemetry !== undefined && (typeof target.windows_telemetry !== 'boolean'
          || (target.windows_telemetry && target.platform !== 'windows'))) {
          return res.status(400).json({ error: 'Windows telemetry must be a boolean and can only be enabled on Windows targets.' });
        }
        if (target.linux_suricata !== undefined && (typeof target.linux_suricata !== 'boolean'
          || (target.linux_suricata && target.platform !== 'linux'))) {
          return res.status(400).json({ error: 'Suricata must be a boolean and can only be enabled on Linux targets.' });
        }
        const laneId = target.lane_id.toLowerCase();
        const key = `${laneId}:${target.vm_id}`;
        if (seen.has(key)) return res.status(400).json({ error: 'A machine was selected more than once.' });
        seen.add(key);
        // Only inventory identifiers enter the service. Destinations, credentials,
        // scripts and lane configurations cannot be supplied by a browser.
        targets.push({ lane_id: laneId, vm_id: target.vm_id, platform: target.platform,
          ...(target.windows_telemetry !== undefined ? { windows_telemetry: target.windows_telemetry } : {}),
          ...(target.linux_suricata !== undefined ? { linux_suricata: target.linux_suricata } : {}) });
      }
      const laneIds = [...new Set(targets.map(target => target.lane_id))];
      // startBatch needs only lane_id/name/status/config; the status-only context
      // columns above are deliberately not selected here.
      const lanes = await query(`SELECT lane_id, name, status, config FROM cybercore_lane
        WHERE lane_id = ANY($1::uuid[]) AND ${eligibleLaneSql()}`, [laneIds]);
      if (lanes.rows.length !== laneIds.length) {
        return res.status(409).json({ error: 'A selected lane is no longer available. Refresh status and review the targets.' });
      }
      const result = await service.startBatch(lanes.rows, { targets });
      await audit.log({ req, action: 'lane.wazuh_agents_queued', source: 'core',
        metadata: { requested: targets.length, results: result.results.map(item => ({
          lane_id: item.lane_id, vm_id: item.vm_id, job_id: item.job?.job_id || null,
          status: item.job?.status || 'rejected',
          windows_telemetry: item.job?.windows_telemetry === true,
          linux_suricata: item.job?.linux_suricata === true,
        })) } });
      res.status(202).json(result);
    } catch (error) { fail(res, error); }
  });

  return router;
}

module.exports = createRouter();
module.exports.createRouter = createRouter;
