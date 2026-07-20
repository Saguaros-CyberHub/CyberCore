/**
 * ============================================================================
 * LAB NETWORK PROVISION
 * Reserve a VXLAN block + pre-create the SDN zone & VNets for a lab, keyed to
 * a crucible_challenge row. Extracted from the inline logic in
 * routes/lab-templates.js (POST /create-lab, DELETE /lab-templates/:id) so the
 * admin route AND the CLE plugin share one implementation.
 *
 *   crucible_challenge  → cybercore_db (cybercoreQuery)
 *   SDN zones / VNets   → Proxmox (proxmoxAPI)
 *
 * The SDN apply (PUT /cluster/sdn) is asynchronous: VNet bridges materialize on
 * the nodes over the following seconds. reserveLabNetwork polls until the
 * last-created VNet bridge shows up, so a lane deploy that starts right after
 * doesn't hit `bridge '<vnet>' does not exist`.
 * ============================================================================
 */

const { cybercoreQuery } = require('./cybercore-db');
const { proxmoxAPI } = require('./proxmox');

// A v3 lane's internal VNet uses tag = (vxlanId + this offset). MUST match
// V3_INTERNAL_TAG_OFFSET in utils/lane-networking.js.
const V3_INTERNAL_TAG_OFFSET = 4000000;

// Proxmox SDN zone IDs must match [a-z][a-z0-9]{0,7}: lowercase, start with a
// letter, ≤8 chars. Sanitize an arbitrary string (challenge key, UUID slice,
// admin input) into a valid zone id. A leading non-letter is prefixed with 'z'
// so UUID-derived ids (which start with a digit ~62.5% of the time) don't get
// rejected with a 400 at zone-create time.
function sanitizeZoneAbbrev(raw) {
  let s = String(raw || '').replace(/[^a-z0-9]/gi, '').toLowerCase();
  if (!/^[a-z]/.test(s)) s = `z${s}`;
  return s.substring(0, 8);
}

const ZONE_RE = /^[a-z][a-z0-9]{0,7}$/;

// Base-20 encode helper for VNet naming (matches the create-lab convention).
const _ALPHABET = 'abcdefghij0123456789';
function encodeBase20(n) {
  if (n === 0) return 'a';
  let s = '';
  let x = n;
  while (x > 0) {
    s = _ALPHABET[x % 20] + s;
    x = Math.floor(x / 20);
  }
  return s.padStart(8, 'a');
}

/**
 * Find the next free VXLAN block of `numLanes` ids by scanning the vxlan_block
 * of every existing crucible_challenge. Blocks are allocated sequentially after
 * the global max, so CLE/CIAB/crucible reservations never overlap.
 */
async function allocateVxlanBlock(numLanes) {
  const n = parseInt(numLanes, 10);
  if (!Number.isFinite(n) || n < 1) throw new Error(`numLanes must be >= 1 (got ${numLanes})`);

  const existing = await cybercoreQuery(
    `SELECT (spec->'vxlan_block'->>'end')::int AS vxlan_end
       FROM crucible_challenge
      WHERE spec->'vxlan_block'->>'end' IS NOT NULL`
  );
  let maxEnd = 9999; // first block starts at 10000
  for (const row of existing.rows) {
    if (row.vxlan_end && row.vxlan_end > maxEnd) maxEnd = row.vxlan_end;
  }
  const start = maxEnd + 1;
  return { start, end: start + n - 1 };
}

/** Count lanes currently holding a vxlan in [start,end] (active or deploying). */
async function countActiveLanesInBlock({ start, end }) {
  const res = await cybercoreQuery(
    `SELECT COUNT(*)::int AS cnt FROM cybercore_lane
      WHERE vxlan_id BETWEEN $1 AND $2 AND status IN ('active', 'deploying')`,
    [start, end]
  );
  return res.rows[0]?.cnt || 0;
}

/**
 * Ensure the SDN zone exists and create one VNet per VXLAN in the block
 * (v3 also creates the internal VNet at the offset tag), then reload SDN and
 * wait for the bridges to materialize.
 */
async function ensureSdnZoneAndVnets({ zone, vxlanStart, vxlanEnd, subnetScheme = 'v2', log = () => {} }) {
  // 1. Zone
  const zones = await proxmoxAPI('GET', '/api2/json/cluster/sdn/zones');
  let zoneCreated = false;
  if (!zones.some(z => z.zone === zone)) {
    log(`Creating SDN zone '${zone}'...`);
    const nodeList = await proxmoxAPI('GET', '/api2/json/nodes');
    const peerIps = [];
    for (const node of nodeList) {
      try {
        const nodeStatus = await proxmoxAPI('GET', `/api2/json/nodes/${node.node}/status`);
        if (nodeStatus.network) {
          for (const [, iface] of Object.entries(nodeStatus.network)) {
            if (iface.address && !iface.address.startsWith('127.')) { peerIps.push(iface.address); break; }
          }
        }
      } catch (_) {}
    }
    const peers = peerIps.length === nodeList.length
      ? peerIps.join(',')
      : nodeList.map((_, i) => `100.100.10.${10 + i}`).join(',');

    // Deliberately NOT passing ipam: 'pve' — CyberCore manages lane IP space
    // internally (dnsmasq inside each lane gateway). ipam:'pve' writes per-VNet
    // dnsmasq config on every node and has crashed clusters at reboot.
    await proxmoxAPI('POST', '/api2/json/cluster/sdn/zones', { zone, type: 'vxlan', peers });
    zoneCreated = true;
    log(`SDN zone '${zone}' created with peers: ${peers}`);
  } else {
    log(`SDN zone '${zone}' already exists`);
  }

  // 2. VNets
  // The full set of SDN tags this block must end up with. A lane deploy later
  // looks its vnet up by tag (routes/admin/lanes.js) and 503s if it's absent,
  // so every one of these must exist in the SDN config before we return.
  const expectedTags = [];
  for (let vxlanId = vxlanStart; vxlanId <= vxlanEnd; vxlanId++) {
    expectedTags.push(vxlanId);
    if (subnetScheme === 'v3') expectedTags.push(vxlanId + V3_INTERNAL_TAG_OFFSET);
  }

  // Create one VNet, retrying transient Proxmox failures. Proxmox SDN is a
  // single cluster-wide locked config; under load or during a concurrent apply
  // it returns lock-timeout / 5xx on individual POSTs, and proxmoxAPI does not
  // retry. Swallowing those (as the old code did) left silent holes in the
  // block. "already exists" is success. Returns true iff the vnet is in place.
  const createVnet = async (tag) => {
    const vnetName = encodeBase20(tag);
    const maxAttempts = 4;
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        await proxmoxAPI('POST', '/api2/json/cluster/sdn/vnets', {
          vnet: vnetName, zone, tag, alias: `${zone}-vnet-${tag}`
        });
        return true;
      } catch (e) {
        if (e.message.includes('already exists')) return true;
        if (attempt === maxAttempts) {
          log(`VNet ${vnetName} (tag ${tag}) failed after ${maxAttempts} attempts: ${e.message}`);
          return false;
        }
        await new Promise(r => setTimeout(r, 500 * attempt));
      }
    }
    return false;
  };

  // Re-list the SDN config and return the expected tags that aren't present.
  // GET /cluster/sdn/vnets includes pending (un-applied) vnets, which is exactly
  // what the deploy-time lookup keys on, so this matches the deploy's view.
  const findMissingTags = async (tags) => {
    const existing = await proxmoxAPI('GET', '/api2/json/cluster/sdn/vnets');
    const present = new Set((existing || []).map(v => v.tag));
    return tags.filter(t => !present.has(t));
  };

  let vnetsCreated = 0;
  for (let i = 0; i < expectedTags.length; i++) {
    if (await createVnet(expectedTags[i])) vnetsCreated++;
    // Rate limit on the iteration count (not successes) so pacing holds even
    // when some creates fail — Proxmox can be overwhelmed by rapid SDN calls.
    if ((i + 1) % 10 === 0) await new Promise(r => setTimeout(r, 500));
  }
  log(`${vnetsCreated}/${expectedTags.length} VNets created`);

  // 3. Reload SDN, then reconcile: recreate any expected vnet still missing and
  // reload again. A silent hole here 503s a lane deploy long after the fact, so
  // verify the whole set rather than trusting the create loop.
  log('Reloading SDN...');
  await proxmoxAPI('PUT', '/api2/json/cluster/sdn');

  let missing = await findMissingTags(expectedTags);
  for (let pass = 1; pass <= 3 && missing.length > 0; pass++) {
    log(`Reconcile pass ${pass}: ${missing.length} VNet(s) missing, recreating...`);
    for (const tag of missing) await createVnet(tag);
    await proxmoxAPI('PUT', '/api2/json/cluster/sdn');
    await new Promise(r => setTimeout(r, 1000 * pass));
    missing = await findMissingTags(expectedTags);
  }
  if (missing.length > 0) {
    // Fail loudly — reserveLabNetwork catches this and rolls back the block so
    // we never report a half-provisioned lab as ready.
    const preview = missing.slice(0, 10).map(encodeBase20).join(', ');
    const err = new Error(
      `SDN provisioning incomplete: ${missing.length}/${expectedTags.length} VNet(s) ` +
      `missing after retries (${preview}${missing.length > 10 ? ', …' : ''})`
    );
    err.missingTags = missing;
    throw err;
  }

  // 4. Wait for the VNet bridges to materialize on a node. Verify the whole
  // expected set (not just the last one) so a mid-block gap can't pass.
  let bridgesUp = false;
  try {
    const checkNodes = await proxmoxAPI('GET', '/api2/json/nodes');
    const checkNode = (checkNodes || [])[0] && (checkNodes || [])[0].node;
    if (checkNode) {
      const expectedNames = expectedTags.map(encodeBase20);
      const deadline = Date.now() + 240000; // 4 min cap
      while (Date.now() < deadline) {
        const ifaces = await proxmoxAPI('GET', `/api2/json/nodes/${checkNode}/network`);
        const names = new Set((ifaces || []).map(i => i.iface));
        if (expectedNames.every(v => names.has(v))) { bridgesUp = true; break; }
        await new Promise(r => setTimeout(r, 4000));
      }
    }
  } catch (e) {
    log(`SDN bridge readiness check skipped: ${e.message}`);
  }
  log(bridgesUp ? 'SDN VNet bridges are up.' : 'WARNING: SDN bridges not confirmed within 4 min.');

  return { vnetsCreated, zoneCreated, bridgesUp, expectedVnets: expectedTags.length };
}

/** Remove the block's VNets and (if it has no remaining VNets) its zone, then reload. */
async function teardownSdnForBlock({ zone, vxlanBlock, subnetScheme = 'v2', log = () => {} }) {
  let vnetsRemoved = 0;
  let zoneRemoved = false;
  if (!vxlanBlock?.start || !vxlanBlock?.end) return { vnetsRemoved, zoneRemoved };

  const blockMax = subnetScheme === 'v3' ? vxlanBlock.end + V3_INTERNAL_TAG_OFFSET : vxlanBlock.end;

  try {
    const vnets = await proxmoxAPI('GET', '/api2/json/cluster/sdn/vnets');
    for (const vnet of vnets) {
      const inExternal = vnet.tag >= vxlanBlock.start && vnet.tag <= vxlanBlock.end;
      const inInternal = subnetScheme === 'v3'
        && vnet.tag >= vxlanBlock.start + V3_INTERNAL_TAG_OFFSET
        && vnet.tag <= blockMax;
      if (inExternal || inInternal) {
        try { await proxmoxAPI('DELETE', `/api2/json/cluster/sdn/vnets/${vnet.vnet}`); vnetsRemoved++; }
        catch (e) { log(`Failed to remove VNet ${vnet.vnet}: ${e.message}`); }
      }
    }
  } catch (e) {
    log(`Failed to query VNets: ${e.message}`);
  }

  if (zone) {
    try {
      const remaining = await proxmoxAPI('GET', '/api2/json/cluster/sdn/vnets');
      if (!remaining.some(v => v.zone === zone)) {
        await proxmoxAPI('DELETE', `/api2/json/cluster/sdn/zones/${zone}`);
        zoneRemoved = true;
      }
    } catch (e) {
      log(`Failed to remove zone ${zone}: ${e.message}`);
    }
  }

  if (vnetsRemoved > 0 || zoneRemoved) {
    try { await proxmoxAPI('PUT', '/api2/json/cluster/sdn'); } catch (_) {}
  }
  return { vnetsRemoved, zoneRemoved };
}

/**
 * Reserve a lab: allocate a VXLAN block, insert the crucible_challenge row with
 * the caller's spec (vxlan_block + zone.abbrev merged in), then create the SDN
 * zone + VNets and wait for bridges. Returns the challenge + block + infra info.
 *
 * @param {object}  a
 * @param {string}  a.challengeKey   unique key (throws 23505 if it exists)
 * @param {string}  a.name
 * @param {string}  [a.description]
 * @param {number}  [a.difficulty=2]
 * @param {string}  [a.subnetScheme='v2']
 * @param {number}  a.maxLanes       block size = number of VNets
 * @param {object}  [a.spec={}]      caller-built spec; merged with block + zone
 * @param {string}  [a.zoneAbbrev]   defaults to a sanitized challengeKey
 * @param {string}  [a.status='active']
 * @param {Function}[a.log]
 */
async function reserveLabNetwork({
  challengeKey, name, description = null, difficulty = 2,
  subnetScheme = 'v2', maxLanes, spec = {}, zoneAbbrev, status = 'active', log = () => {},
}) {
  if (!challengeKey || !name) throw new Error('reserveLabNetwork: challengeKey and name are required');
  const scheme = ['v1', 'v2', 'v3'].includes(subnetScheme) ? subnetScheme : 'v2';
  const numLanes = parseInt(maxLanes, 10);
  if (!Number.isFinite(numLanes) || numLanes < 1 || numLanes > 200) {
    throw new Error('maxLanes must be between 1 and 200');
  }

  const zone = sanitizeZoneAbbrev(zoneAbbrev || challengeKey);
  // Final assertion — sanitizeZoneAbbrev should always satisfy this, but guard
  // against an empty/degenerate input slipping a bad name through to Proxmox.
  if (!ZONE_RE.test(zone)) {
    throw new Error('zone abbreviation must be 1-8 alphanumeric characters starting with a letter');
  }

  log('Querying existing VXLAN blocks...');
  const block = await allocateVxlanBlock(numLanes);
  log(`Allocated VXLAN block: ${block.start}-${block.end} (${numLanes} lanes)`);

  const fullSpec = {
    ...spec,
    zone: { ...(spec.zone || {}), abbrev: zone },
    vxlan_block: { start: block.start, end: block.end },
  };

  log('Inserting challenge record...');
  const ins = await cybercoreQuery(
    `INSERT INTO crucible_challenge (challenge_key, name, description, difficulty, spec, status, subnet_scheme)
     VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7)
     RETURNING challenge_id, challenge_key`,
    [challengeKey, name, description, difficulty, JSON.stringify(fullSpec), status, scheme]
  );
  const challengeId = ins.rows[0].challenge_id;
  log(`Challenge created: ${challengeId}`);

  let infra;
  try {
    infra = await ensureSdnZoneAndVnets({
      zone, vxlanStart: block.start, vxlanEnd: block.end, subnetScheme: scheme, log,
    });
  } catch (err) {
    // The challenge row (and its VXLAN block reservation) is already committed.
    // If the SDN provisioning fails, undo it so we don't leak an orphaned
    // challenge + permanently-allocated block. Best-effort: surface the
    // original error regardless of cleanup outcome.
    log(`SDN provisioning failed (${err.message}); rolling back challenge ${challengeId}`);
    await teardownLabNetwork(challengeId, { force: true, log }).catch((e) =>
      log(`Rollback of challenge ${challengeId} failed: ${e.message}`)
    );
    throw err;
  }

  return {
    challenge_id: challengeId,
    challenge_key: challengeKey,
    zone,
    vxlan_block: block,
    subnet_scheme: scheme,
    ...infra,
  };
}

/**
 * Tear down a lab's network: refuse (unless `force`) while active/deploying
 * lanes still use the block, then remove VNets + zone and delete the challenge.
 * Throws an Error with `.status = 400` when blocked by active lanes.
 */
async function teardownLabNetwork(challengeId, { force = false, log = () => {} } = {}) {
  const chal = await cybercoreQuery(`SELECT * FROM crucible_challenge WHERE challenge_id = $1`, [challengeId]);
  if (chal.rows.length === 0) {
    const err = new Error('Challenge not found');
    err.status = 404;
    throw err;
  }
  const challenge = chal.rows[0];
  const spec = typeof challenge.spec === 'string' ? JSON.parse(challenge.spec) : (challenge.spec || {});
  const zone = spec.zone?.abbrev;
  const vxlanBlock = spec.vxlan_block;
  const subnetScheme = challenge.subnet_scheme || 'v2';

  let removed = { vnetsRemoved: 0, zoneRemoved: false };
  if (vxlanBlock?.start && vxlanBlock?.end) {
    if (!force) {
      const active = await countActiveLanesInBlock(vxlanBlock);
      if (active > 0) {
        const err = new Error(`Cannot delete: ${active} active lane(s) are using this challenge's VXLAN block`);
        err.status = 400;
        throw err;
      }
    }
    removed = await teardownSdnForBlock({ zone, vxlanBlock, subnetScheme, log });
  }

  await cybercoreQuery(`DELETE FROM crucible_challenge WHERE challenge_id = $1`, [challengeId]);
  log(`Deleted '${challenge.challenge_key}': ${removed.vnetsRemoved} VNets removed, zone removed: ${removed.zoneRemoved}`);

  return { challenge_key: challenge.challenge_key, vnets_removed: removed.vnetsRemoved, zone_removed: removed.zoneRemoved };
}

module.exports = {
  V3_INTERNAL_TAG_OFFSET,
  sanitizeZoneAbbrev,
  encodeBase20,
  allocateVxlanBlock,
  countActiveLanesInBlock,
  ensureSdnZoneAndVnets,
  teardownSdnForBlock,
  reserveLabNetwork,
  teardownLabNetwork,
};
