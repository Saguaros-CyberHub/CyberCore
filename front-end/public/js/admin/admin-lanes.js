// ============================================================================
// DEPLOY LANE
// ============================================================================

async function deployLane() {
  const challenge_key = document.getElementById('deployChallengeKey').value.trim();
  const module = document.getElementById('deployModule').value;
  const event_id = document.getElementById('deployEventId').value.trim() || null;
  const useWebhook = document.getElementById('deployUseWebhook').checked;
  const attack_boxes = document.getElementById('deploySingleAttackBox').checked;
  const status = document.getElementById('deployStatus');
  const btn = document.getElementById('deployBtn');

  if (!challenge_key) {
    Toast.warning('Missing Fields', 'Challenge Key is required');
    return;
  }

  btn.disabled = true;
  btn.textContent = 'Checking resources...';
  status.textContent = 'Running pre-flight resource check...';
  status.style.color = 'var(--gray-500)';

  try {
    // Step 1: Get preview (no confirm flag)
    const preview = await api('POST', '/deploy-lane', { challenge_key, module, event_id, use_webhook: useWebhook, attack_boxes });

    if (preview.preview) {
      // Show confirmation modal
      btn.disabled = false;
      btn.textContent = 'Deploy Lane';
      status.textContent = '';
      const vulnScripts = getSelectedScripts('deploy-script');
      showDeployConfirmation(preview, () => deployLaneConfirmed(challenge_key, module, event_id, useWebhook, attack_boxes, vulnScripts));
      return;
    }

    // If no preview came back (health check failed gracefully), treat as confirmed
    handleDeployLaneSuccess(preview, challenge_key, status);
  } catch (e) {
    status.textContent = `Error: ${e.message}`;
    status.style.color = '#e53e3e';
    Toast.error('Deploy Failed', e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Deploy Lane';
  }
}

async function deployLaneConfirmed(challenge_key, module, event_id, useWebhook, attack_boxes, vulnScripts = []) {
  const status = document.getElementById('deployStatus');
  const btn = document.getElementById('deployBtn');

  btn.disabled = true;
  btn.textContent = 'Deploying...';
  const method = useWebhook ? 'N8N Webhook' : 'Native';
  const extras = attack_boxes ? ' + Kali Attack Box' : '';
  status.textContent = `Deploying lane${extras} via ${method} (cloning VMs, allocating VXLAN)...`;
  status.style.color = 'var(--gray-500)';

  try {
    const data = await api('POST', '/deploy-lane', { challenge_key, module, event_id, use_webhook: useWebhook, attack_boxes, vuln_scripts: vulnScripts, confirm: true });
    handleDeployLaneSuccess(data, challenge_key, status);
  } catch (e) {
    status.textContent = `Error: ${e.message}`;
    status.style.color = '#e53e3e';
    Toast.error('Deploy Failed', e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Deploy Lane';
  }
}

function handleDeployLaneSuccess(data, challenge_key, status) {
  const via = data.method === 'webhook' ? ' (via N8N)' : '';
  status.innerHTML = `
    <strong style="color: #38a169;">Lane deployment started${via}!</strong><br>
    Lane ID: <code style="background: #edf2f7; padding: 0.1rem 0.4rem; border-radius: 4px; font-size: 0.8rem;">${data.lane_id}</code><br>
    VXLAN: ${data.vxlan_id || 'N/A'} | VNet: ${data.vnet || 'N/A'} | Challenge: ${data.challenge || challenge_key}<br>
    <span style="font-size: 0.8rem; color: var(--gray-500);">VMs cloning in background — check Active Lanes tab for status.</span>
  `;
  Toast.success('Lane Deploying', `${data.challenge || challenge_key}${via}. VMs will be ready in ~60 seconds.`);
  loadClusterHealth();
}

// ============================================================================
// ACTIVE LANES
// ============================================================================

async function loadLanes() {
  const container = document.getElementById('lanesTable');
  if (!container) return;
  container.innerHTML = '<p style="color: var(--gray-500);">Loading lanes from CyberCore DB...</p>';

  try {
    const filter = document.getElementById('lanesFilter')?.value || '';
    const url = filter ? `/lanes?status=${filter}` : '/lanes';
    const lanes = await api('GET', url);

    if (lanes.length === 0) {
      container.innerHTML = '<div style="background: white; border-radius: 12px; padding: 2rem; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.08); color: var(--gray-500);">No lanes found.</div>';
      return;
    }

    container.innerHTML = `
      <table class="admin-table">
        <thead><tr>
          <th>Name</th>
          <th>User ID</th>
          <th>VXLAN</th>
          <th>Status</th>
          <th>Internet</th>
          <th>Created</th>
          <th>Actions</th>
        </tr></thead>
        <tbody>
          ${lanes.map(l => {
            const statusColor = {
              active: '#38a169', deploying: '#d69e2e', error: '#e53e3e',
              deleted: '#a0aec0', suspended: '#9f7aea', pending: '#4299e1'
            }[l.status] || '#718096';
            const cfg = typeof l.config === 'string' ? JSON.parse(l.config || '{}') : (l.config || {});
            const inet = cfg.internet_enabled;
            return `
              <tr>
                <td><strong>${escHtml(l.name || 'unnamed')}</strong></td>
                <td><code style="font-size: 0.75rem;">${escHtml((l.user_id || '').substring(0, 8))}...</code></td>
                <td>${l.vxlan_id || '—'}</td>
                <td><span style="display: inline-block; padding: 0.15rem 0.5rem; border-radius: 12px; font-size: 0.75rem; font-weight: 600; color: white; background: ${statusColor};">${l.status}</span></td>
                <td>
                  ${l.status === 'active' ? `
                    <label style="display: flex; align-items: center; gap: 0.3rem; cursor: pointer;">
                      <input type="checkbox" ${inet ? 'checked' : ''} onchange="toggleAdminInternet('${l.lane_id}', this.checked)" style="width: auto;">
                      <span style="font-size: 0.8rem;">${inet ? 'On' : 'Off'}</span>
                    </label>
                  ` : '<span style="font-size: 0.8rem; color: var(--gray-400);">—</span>'}
                </td>
                <td>${new Date(l.created_at).toLocaleDateString()}</td>
                <td>
                  ${l.status === 'active' ? `
                    <button class="btn btn-sm btn-outline" style="font-size: 0.75rem; padding: 0.2rem 0.5rem;" onclick="showRunScriptModal('${l.lane_id}', '${escHtml(l.name || '')}')">Run Script</button>
                    <button class="btn btn-sm btn-outline" style="font-size: 0.75rem; padding: 0.2rem 0.5rem; color: #805ad5; border-color: #805ad5;" onclick="showGenerateChallengeProfileModal('${l.lane_id}', '${escHtml(l.name || '')}')">Generate Profile</button>
                    <button class="btn btn-sm btn-outline" style="font-size: 0.75rem; padding: 0.2rem 0.5rem; color: #d69e2e; border-color: #d69e2e;" onclick="showPushFileModal('${l.lane_id}', '${escHtml(l.name || '')}')">Push File</button>
                    <button class="btn btn-sm btn-outline" style="font-size: 0.75rem; padding: 0.2rem 0.5rem; color: #319795; border-color: #319795;" onclick="showModulesModal('${l.lane_id}', '${escHtml(l.name || '')}')">Modules${Array.isArray(cfg.attached_modules) && cfg.attached_modules.length > 0 ? ` (${cfg.attached_modules.length})` : ''}</button>
                  ` : ''}
                  ${l.status !== 'deleted' ? `<button class="btn btn-sm" style="font-size: 0.75rem; padding: 0.2rem 0.5rem; border: 1px solid #e53e3e; color: #e53e3e; background: transparent;" data-lane-id="${l.lane_id}" data-lane-name="${escHtml(l.name || '')}" onclick="deleteLane(this.dataset.laneId, this.dataset.laneName)">Delete</button>` : '—'}
                </td>
              </tr>`;
          }).join('')}
        </tbody>
      </table>`;
  } catch (e) {
    container.innerHTML = `<p style="color: #e53e3e;">Error loading lanes: ${e.message}</p>`;
  }
}

// ============================================================================
// PROXMOX AUDIT / RECONCILIATION
// ============================================================================

async function runReconcile() {
  const btn = document.getElementById('btnReconcile');
  const panel = document.getElementById('reconcileResults');
  btn.disabled = true;
  btn.textContent = 'Auditing...';
  panel.style.display = 'block';
  panel.innerHTML = '<p style="color: var(--gray-500);">Querying Proxmox and DB...</p>';

  try {
    const r = await api('GET', '/reconcile');
    const s = r.summary;
    const hasIssues = s.orphaned_on_proxmox > 0 || s.stale_in_db > 0 || s.orphaned_zones > 0 || s.orphaned_vnets > 0 || (s.orphaned_disks || 0) > 0 || (s.orphaned_guac_connections || 0) > 0;
    const statusColor = hasIssues ? '#e53e3e' : '#38a169';
    const statusLabel = hasIssues ? 'Issues Found' : 'In Sync';

    let orphanRows = '';
    if (r.orphaned_on_proxmox.length) {
      orphanRows = r.orphaned_on_proxmox.map(vm => `
        <tr>
          <td><code>${vm.vmid}</code></td>
          <td>${escHtml(vm.name)}</td>
          <td>${vm.role}</td>
          <td>${vm.node}</td>
          <td><span style="color:${vm.status==='running'?'#38a169':'#a0aec0'}">${vm.status}</span></td>
          <td>VXLAN ${vm.vxlan_inferred}</td>
          <td><button class="btn btn-sm" style="font-size:0.7rem; padding:0.15rem 0.4rem; border:1px solid #e53e3e; color:#e53e3e; background:transparent;" onclick="destroyOrphanVM(${vm.vmid}, '${vm.node}', '${vm.type}', this)">Destroy</button></td>
        </tr>`).join('');
    }

    let staleRows = '';
    if (r.stale_in_db.length) {
      staleRows = r.stale_in_db.map(lane => `
        <tr>
          <td><code style="font-size:0.75rem;">${escHtml((lane.lane_id||'').substring(0,8))}...</code></td>
          <td>${escHtml(lane.name || 'unnamed')}</td>
          <td>${lane.vxlan_id || '-'}</td>
          <td>${lane.status}</td>
          <td>${new Date(lane.created_at).toLocaleDateString()}</td>
          <td><button class="btn btn-sm" style="font-size:0.7rem; padding:0.15rem 0.4rem; border:1px solid #d69e2e; color:#d69e2e; background:transparent;" onclick="markLaneDeleted('${lane.lane_id}', this)">Mark Deleted</button></td>
        </tr>`).join('');
    }

    let zoneRows = '';
    if (r.orphaned_zones?.length) {
      zoneRows = r.orphaned_zones.map(z => `
        <tr>
          <td><code>${escHtml(z.zone)}</code></td>
          <td>${z.type}</td>
          <td>${z.vnet_count}</td>
          <td><button class="btn btn-sm" style="font-size:0.7rem; padding:0.15rem 0.4rem; border:1px solid #e53e3e; color:#e53e3e; background:transparent;" onclick="destroyOrphanZone('${escHtml(z.zone)}', this)">Destroy Zone + VNets</button></td>
        </tr>`).join('');
    }

    let vnetRows = '';
    if (r.orphaned_vnets?.length) {
      vnetRows = r.orphaned_vnets.map(v => `
        <tr>
          <td><code>${escHtml(v.vnet)}</code></td>
          <td>${escHtml(v.zone)}</td>
          <td>${v.tag || '-'}</td>
          <td><button class="btn btn-sm" style="font-size:0.7rem; padding:0.15rem 0.4rem; border:1px solid #d69e2e; color:#d69e2e; background:transparent;" onclick="destroyOrphanVNet('${escHtml(v.vnet)}', this)">Delete</button></td>
        </tr>`).join('');
    }

    let guacConnRows = '';
    if (r.orphaned_guac_connections?.length) {
      guacConnRows = r.orphaned_guac_connections.map(c => `
        <tr>
          <td><code style="font-size:0.75rem;">${escHtml(c.id)}</code></td>
          <td>${escHtml(c.name)}</td>
          <td>${(c.protocol || '').toUpperCase()}</td>
          <td>${escHtml(c.parent)}</td>
          <td>${c.tracked ? '<span style="color:#e53e3e;">tracked</span>' : '<span style="color:#d69e2e;">by name</span>'}</td>
          <td><button class="btn btn-sm guac-conn-delete" data-conn-id="${escHtml(c.id)}" data-conn-name="${escHtml(c.name || '')}" style="font-size:0.7rem; padding:0.15rem 0.4rem; border:1px solid #e53e3e; color:#e53e3e; background:transparent;">Delete</button></td>
        </tr>`).join('');
    }

    let diskRows = '';
    if (r.orphaned_disks?.length) {
      diskRows = r.orphaned_disks.map(d => `
        <tr>
          <td><code>${d.vmid}</code></td>
          <td>${d.role || '-'}</td>
          <td><code style="font-size:0.75rem;">${escHtml(d.volid)}</code></td>
          <td>${escHtml(d.node)}</td>
          <td>${escHtml(d.storage)}</td>
          <td style="text-align:right;">${d.size_gb} GB</td>
          <td><button class="btn btn-sm" style="font-size:0.7rem; padding:0.15rem 0.4rem; border:1px solid #e53e3e; color:#e53e3e; background:transparent;" onclick="destroyOrphanDisk('${escHtml(d.node)}', '${escHtml(d.storage)}', '${escHtml(d.volid)}', this)">Delete</button></td>
        </tr>`).join('');
    }

    panel.innerHTML = `
      <div style="background:var(--card-bg, white); border-radius:12px; padding:1.25rem; box-shadow:0 2px 8px rgba(0,0,0,0.08); border-left:4px solid ${statusColor};">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1rem;">
          <h3 style="margin:0; font-size:1rem;">Proxmox Audit
            <span style="font-size:0.8rem; padding:0.15rem 0.5rem; border-radius:12px; color:white; background:${statusColor}; margin-left:0.5rem;">${statusLabel}</span>
          </h3>
          <span style="font-size:0.75rem; color:var(--gray-400);">${r.timestamp}</span>
        </div>
        <div style="display:grid; grid-template-columns:repeat(auto-fit,minmax(120px,1fr)); gap:0.75rem; margin-bottom:1rem;">
          <div style="text-align:center; padding:0.5rem; background:var(--bg, #f7fafc); border-radius:8px;">
            <div style="font-size:1.25rem; font-weight:700;">${s.proxmox_cyberhub_vms}</div>
            <div style="font-size:0.75rem; color:var(--gray-500);">Proxmox VMs</div>
          </div>
          <div style="text-align:center; padding:0.5rem; background:var(--bg, #f7fafc); border-radius:8px;">
            <div style="font-size:1.25rem; font-weight:700;">${s.db_active_lanes}</div>
            <div style="font-size:0.75rem; color:var(--gray-500);">DB Lanes</div>
          </div>
          <div style="text-align:center; padding:0.5rem; background:${s.orphaned_on_proxmox?'#fff5f5':'var(--bg, #f7fafc)'}; border-radius:8px;">
            <div style="font-size:1.25rem; font-weight:700; color:${s.orphaned_on_proxmox?'#e53e3e':'inherit'};">${s.orphaned_on_proxmox}</div>
            <div style="font-size:0.75rem; color:var(--gray-500);">Orphaned VMs</div>
          </div>
          <div style="text-align:center; padding:0.5rem; background:${s.stale_in_db?'#fffff0':'var(--bg, #f7fafc)'}; border-radius:8px;">
            <div style="font-size:1.25rem; font-weight:700; color:${s.stale_in_db?'#d69e2e':'inherit'};">${s.stale_in_db}</div>
            <div style="font-size:0.75rem; color:var(--gray-500);">Stale DB Records</div>
          </div>
          <div style="text-align:center; padding:0.5rem; background:${s.orphaned_zones?'#fff5f5':'var(--bg, #f7fafc)'}; border-radius:8px;">
            <div style="font-size:1.25rem; font-weight:700; color:${s.orphaned_zones?'#e53e3e':'inherit'};">${s.orphaned_zones}</div>
            <div style="font-size:0.75rem; color:var(--gray-500);">Orphaned Zones</div>
          </div>
          <div style="text-align:center; padding:0.5rem; background:${s.orphaned_vnets?'#fffff0':'var(--bg, #f7fafc)'}; border-radius:8px;">
            <div style="font-size:1.25rem; font-weight:700; color:${s.orphaned_vnets?'#d69e2e':'inherit'};">${s.orphaned_vnets}</div>
            <div style="font-size:0.75rem; color:var(--gray-500);">Orphaned VNets</div>
          </div>
          <div style="text-align:center; padding:0.5rem; background:${(s.orphaned_disks||0)?'#fff5f5':'var(--bg, #f7fafc)'}; border-radius:8px;">
            <div style="font-size:1.25rem; font-weight:700; color:${(s.orphaned_disks||0)?'#e53e3e':'inherit'};">${s.orphaned_disks || 0}</div>
            <div style="font-size:0.75rem; color:var(--gray-500);">Orphaned Disks${(s.orphaned_disks_total_gb && parseFloat(s.orphaned_disks_total_gb) > 0) ? ` (${s.orphaned_disks_total_gb} GB)` : ''}</div>
          </div>
          <div style="text-align:center; padding:0.5rem; background:${(s.orphaned_guac_connections||0)?'#fff5f5':'var(--bg, #f7fafc)'}; border-radius:8px;">
            <div style="font-size:1.25rem; font-weight:700; color:${(s.orphaned_guac_connections||0)?'#e53e3e':'inherit'};">${s.orphaned_guac_connections || 0}</div>
            <div style="font-size:0.75rem; color:var(--gray-500);">Orphaned Guac Conns</div>
          </div>
        </div>
        ${orphanRows ? `
          <h4 style="font-size:0.9rem; margin:1rem 0 0.5rem; color:#e53e3e;">Orphaned VMs (no DB lane)</h4>
          <p style="font-size:0.75rem; color:var(--gray-500); margin-bottom:0.5rem;">VMs in CyberHub ID ranges with no matching lane in the database.</p>
          <table class="admin-table" style="font-size:0.8rem;">
            <thead><tr><th>VMID</th><th>Name</th><th>Role</th><th>Node</th><th>Status</th><th>VXLAN</th><th>Action</th></tr></thead>
            <tbody>${orphanRows}</tbody>
          </table>` : ''}
        ${zoneRows ? `
          <h4 style="font-size:0.9rem; margin:1rem 0 0.5rem; color:#e53e3e;">Orphaned SDN Zones (no challenge template)</h4>
          <p style="font-size:0.75rem; color:var(--gray-500); margin-bottom:0.5rem;">VXLAN zones on Proxmox with no matching challenge template in the database. Destroying a zone also removes all its VNets.</p>
          <table class="admin-table" style="font-size:0.8rem;">
            <thead><tr><th>Zone</th><th>Type</th><th>VNets</th><th>Action</th></tr></thead>
            <tbody>${zoneRows}</tbody>
          </table>` : ''}
        ${vnetRows ? `
          <h4 style="font-size:0.9rem; margin:1rem 0 0.5rem; color:#d69e2e;">Orphaned VNets (zone deleted)</h4>
          <p style="font-size:0.75rem; color:var(--gray-500); margin-bottom:0.5rem;">VNets whose SDN zone no longer exists. Leftover from deleted zones.</p>
          <table class="admin-table" style="font-size:0.8rem;">
            <thead><tr><th>VNet</th><th>Zone</th><th>Tag</th><th>Action</th></tr></thead>
            <tbody>${vnetRows}</tbody>
          </table>` : ''}
        ${staleRows ? `
          <h4 style="font-size:0.9rem; margin:1rem 0 0.5rem; color:#d69e2e;">Stale DB Lanes (VMs gone from Proxmox)</h4>
          <p style="font-size:0.75rem; color:var(--gray-500); margin-bottom:0.5rem;">Lanes in the database whose VMs no longer exist on Proxmox.</p>
          <table class="admin-table" style="font-size:0.8rem;">
            <thead><tr><th>Lane ID</th><th>Name</th><th>VXLAN</th><th>Status</th><th>Created</th><th>Action</th></tr></thead>
            <tbody>${staleRows}</tbody>
          </table>` : ''}
        ${diskRows ? `
          <h4 style="font-size:0.9rem; margin:1rem 0 0.5rem; color:#e53e3e; display:flex; align-items:center; justify-content:space-between;">
            <span>Orphaned Disk Images (${r.orphaned_disks.length}, ${s.orphaned_disks_total_gb} GB total)</span>
            <button class="btn btn-sm" style="font-size:0.7rem; padding:0.2rem 0.6rem; border:1px solid #e53e3e; color:#e53e3e; background:transparent;" onclick="sweepAllOrphanDisks(this)">Sweep All</button>
          </h4>
          <p style="font-size:0.75rem; color:var(--gray-500); margin-bottom:0.5rem;">Disk images on Proxmox storage whose parent VM no longer exists. Common after failed teardowns on multi-disk VMs. Deletes run sequentially to avoid Ceph/cfs-lock contention.</p>
          <table class="admin-table" style="font-size:0.8rem;">
            <thead><tr><th>VMID</th><th>Role</th><th>Volume</th><th>Node</th><th>Storage</th><th>Size</th><th>Action</th></tr></thead>
            <tbody>${diskRows}</tbody>
          </table>` : ''}
        ${guacConnRows ? `
          <h4 style="font-size:0.9rem; margin:1rem 0 0.5rem; color:#e53e3e; display:flex; align-items:center; justify-content:space-between;">
            <span>Orphaned Guacamole Connections (${r.orphaned_guac_connections.length})</span>
            <button class="btn btn-sm" style="font-size:0.7rem; padding:0.2rem 0.6rem; border:1px solid #e53e3e; color:#e53e3e; background:transparent;" onclick="sweepAllOrphanGuacConns(this)">Sweep All</button>
          </h4>
          <p style="font-size:0.75rem; color:var(--gray-500); margin-bottom:0.5rem;">CyberHub-generated Guac connections whose parent group no longer exists (reparented to ROOT after group delete didn't cascade). "tracked" = matched by ID in deployed_groups.config; "by name" = heuristic match on the connection name pattern.</p>
          <table class="admin-table" style="font-size:0.8rem;">
            <thead><tr><th>ID</th><th>Name</th><th>Protocol</th><th>Parent</th><th>Match</th><th>Action</th></tr></thead>
            <tbody>${guacConnRows}</tbody>
          </table>` : ''}
        ${!hasIssues ? '<p style="color:#38a169; font-weight:600; margin-top:0.5rem;">All clear -- DB and Proxmox are in sync.</p>' : ''}
        <button class="btn btn-outline" style="margin-top:1rem; font-size:0.8rem;" onclick="document.getElementById('reconcileResults').style.display='none'">Dismiss</button>
      </div>`;
  } catch (e) {
    panel.innerHTML = `<p style="color:#e53e3e;">Audit failed: ${escHtml(e.message)}</p>`;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Audit Proxmox';
  }
}

async function destroyOrphanVM(vmid, node, type, btn) {
  if (!confirm('Destroy VM ' + vmid + ' on ' + node + '? This cannot be undone.')) return;
  btn.disabled = true;
  btn.textContent = '...';
  try {
    await api('POST', '/reconcile/destroy-vm', { vmid, node, type });
    btn.textContent = 'Destroyed';
    btn.style.color = '#38a169';
    btn.style.borderColor = '#38a169';
  } catch (e) {
    alert('Failed to destroy VM: ' + e.message);
    btn.disabled = false;
    btn.textContent = 'Destroy';
  }
}

async function destroyOrphanZone(zone, btn) {
  if (!confirm('Destroy zone "' + zone + '" and ALL its VNets? This cannot be undone.')) return;
  btn.disabled = true;
  btn.textContent = '...';
  try {
    const result = await api('POST', '/reconcile/destroy-zone', { zone });
    btn.textContent = 'Destroyed (' + result.vnets_removed + ' VNets)';
    btn.style.color = '#38a169';
    btn.style.borderColor = '#38a169';
  } catch (e) {
    alert('Failed to destroy zone: ' + e.message);
    btn.disabled = false;
    btn.textContent = 'Destroy Zone + VNets';
  }
}

async function destroyOrphanVNet(vnet, btn) {
  if (!confirm('Delete VNet "' + vnet + '"?')) return;
  btn.disabled = true;
  btn.textContent = '...';
  try {
    await api('POST', '/reconcile/destroy-vnet', { vnet });
    btn.textContent = 'Deleted';
    btn.style.color = '#38a169';
    btn.style.borderColor = '#38a169';
  } catch (e) {
    alert('Failed: ' + e.message);
    btn.disabled = false;
    btn.textContent = 'Delete';
  }
}

async function destroyOrphanDisk(node, storage, volid, btn) {
  if (!confirm('Delete disk image "' + volid + '"? This frees the storage and cannot be undone.')) return;
  btn.disabled = true;
  btn.textContent = '...';
  try {
    await api('POST', '/reconcile/destroy-disk', { node, storage, volid });
    btn.textContent = 'Deleted';
    btn.style.color = '#38a169';
    btn.style.borderColor = '#38a169';
  } catch (e) {
    alert('Failed: ' + e.message);
    btn.disabled = false;
    btn.textContent = 'Delete';
  }
}

// Delete a single orphaned Guac connection. Called from event delegation below.
async function destroyOrphanGuacConn(id, name, btn) {
  if (!confirm('Delete Guacamole connection "' + (name || id) + '"?')) return;
  btn.disabled = true;
  btn.textContent = '...';
  try {
    await api('POST', '/reconcile/destroy-guac-connection', { id, name });
    btn.textContent = 'Deleted';
    btn.style.color = '#38a169';
    btn.style.borderColor = '#38a169';
  } catch (e) {
    alert('Failed: ' + e.message);
    btn.disabled = false;
    btn.textContent = 'Delete';
  }
}

async function sweepAllOrphanGuacConns(btn) {
  const panel = document.getElementById('reconcileResults');
  const rowBtns = Array.from(panel?.querySelectorAll('button.guac-conn-delete') || []);
  if (rowBtns.length === 0) { alert('No connections to sweep.'); return; }
  if (!confirm(`Delete all ${rowBtns.length} orphaned Guac connections? This cannot be undone.`)) return;
  btn.disabled = true;
  btn.textContent = 'Sweeping...';
  let deleted = 0;
  let failed = 0;
  for (const b of rowBtns) {
    if (b.disabled) continue;
    const id = b.dataset.connId;
    const name = b.dataset.connName;
    if (!id) continue;
    try {
      await api('POST', '/reconcile/destroy-guac-connection', { id, name });
      b.textContent = 'Deleted';
      b.style.color = '#38a169';
      b.style.borderColor = '#38a169';
      b.disabled = true;
      deleted++;
    } catch (e) {
      console.warn(`Failed to delete Guac conn ${id}:`, e.message);
      failed++;
    }
  }
  btn.textContent = `Done (${deleted} deleted, ${failed} failed)`;
  if (deleted > 0) setTimeout(() => runReconcile(), 1500);
}

// Event delegation: handle clicks on any `.guac-conn-delete` button inside the reconcile panel.
// Using data attributes + delegation avoids the HTML quote-escaping nightmare of inline onclick.
document.addEventListener('click', (e) => {
  const btn = e.target.closest('button.guac-conn-delete');
  if (!btn || btn.disabled) return;
  const id = btn.dataset.connId;
  const name = btn.dataset.connName || '';
  if (!id) return;
  destroyOrphanGuacConn(id, name, btn);
});

async function sweepAllOrphanDisks(btn) {
  if (!confirm('Sweep ALL orphaned disks shown here? This runs serially and may take several minutes on Ceph/RBD storage.')) return;
  btn.disabled = true;
  btn.textContent = 'Sweeping...';
  try {
    // CyberHub range regex: VMIDs starting with 1, 6, or 7, exactly 6 digits
    const result = await api('POST', '/sweep-orphaned-disks', {
      dry_run: false,
      vmid_pattern: '^[167][0-9]{5}$'
    });
    btn.textContent = `Swept ${result.orphans_deleted}/${result.orphans_found} (${result.reclaimed_size_gb} GB)`;
    btn.style.color = '#38a169';
    btn.style.borderColor = '#38a169';
    // Re-run the audit to refresh the table
    setTimeout(() => runReconcile(), 1500);
  } catch (e) {
    alert('Sweep failed: ' + e.message);
    btn.disabled = false;
    btn.textContent = 'Sweep All';
  }
}

async function markLaneDeleted(laneId, btn) {
  if (!confirm('Mark this lane as deleted in the DB? The VXLAN will be freed for reuse.')) return;
  btn.disabled = true;
  btn.textContent = '...';
  try {
    await api('POST', '/reconcile/mark-deleted', { lane_id: laneId });
    btn.textContent = 'Cleaned';
    btn.style.color = '#38a169';
    btn.style.borderColor = '#38a169';
    loadLanes();
  } catch (e) {
    alert('Failed: ' + e.message);
    btn.disabled = false;
    btn.textContent = 'Mark Deleted';
  }
}

// ============================================================================
// VULN SCRIPT SELECTOR (reusable component)
// ============================================================================

/**
 * Render a script selector panel: VM tabs on left, scripts for selected VM on right
 * Scales to 10+ VMs and 50+ scripts without clutter
 */
// Store selections per selectorId → { vmName: Set(slugs) }
const scriptSelections = {};

// cachedVulnScripts declared here — shared with admin-vuln-scripts.js via global scope
let cachedVulnScripts = [];

// cachedChallenges declared here — shared with admin-challenges.js via global scope
let cachedChallenges = {}; // { module_key: [challenge, ...] }

async function renderScriptSelector(container, vms, selectorId, preselected = []) {
  const scripts = cachedVulnScripts.length > 0 ? cachedVulnScripts : await api('GET', '/vuln-scripts');
  cachedVulnScripts = scripts;

  // Initialize selections from defaults + preselected
  if (!scriptSelections[selectorId]) scriptSelections[selectorId] = {};
  for (const vm of vms) {
    if (!scriptSelections[selectorId][vm.name]) {
      scriptSelections[selectorId][vm.name] = new Set(vm.default_scripts || []);
    }
  }
  for (const p of preselected) {
    if (scriptSelections[selectorId][p.vm_name]) {
      scriptSelections[selectorId][p.vm_name].add(p.script_slug);
    }
  }

  const firstVm = vms[0]?.name || '';

  container.innerHTML = `
    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.75rem;">
      <strong style="font-size: 0.9rem;">Vulnerability Scripts</strong>
      <span id="${selectorId}-total" style="font-size: 0.75rem; color: var(--gray-500);">0 scripts selected</span>
    </div>
    <div style="display: flex; gap: 0; border: 1px solid #e2e8f0; border-radius: 8px; overflow: hidden; min-height: 250px;">
      <!-- VM List (left sidebar) -->
      <div id="${selectorId}-vmlist" style="width: 180px; min-width: 180px; background: #f7fafc; border-right: 1px solid #e2e8f0; overflow-y: auto; max-height: 350px;">
        ${vms.map((vm, i) => {
          const count = (scriptSelections[selectorId][vm.name] || new Set()).size;
          return `
          <div class="${selectorId}-vm-tab" data-vm="${escHtml(vm.name)}"
            onclick="selectScriptVM('${selectorId}', '${escHtml(vm.name)}')"
            style="padding: 0.6rem 0.75rem; cursor: pointer; border-bottom: 1px solid #e2e8f0; font-size: 0.8rem;
                   ${i === 0 ? 'background: white; border-left: 3px solid #4299e1;' : 'border-left: 3px solid transparent;'}">
            <div style="font-weight: 600;">${escHtml(vm.name)}</div>
            <div style="font-size: 0.7rem; color: var(--gray-500);">${escHtml(vm.role || '')}${vm.os ? ' · ' + escHtml(vm.os) : ''}</div>
            <div style="font-size: 0.65rem; color: #4299e1; margin-top: 0.15rem;" id="${selectorId}-vmcount-${escHtml(vm.name)}">${count} script${count !== 1 ? 's' : ''}</div>
          </div>`;
        }).join('')}
      </div>
      <!-- Script panel (right) -->
      <div id="${selectorId}-scriptpanel" style="flex: 1; min-width: 0; padding: 0.75rem; overflow-y: auto; overflow-x: hidden; max-height: 350px;"></div>
    </div>`;

  container.style.display = 'block';

  // Store VM and script data for rendering
  container._vms = vms;
  container._scripts = scripts;
  container._selectorId = selectorId;

  // Show first VM's scripts
  renderScriptPanelForVM(selectorId, firstVm, container);
  updateScriptTotalCount(selectorId);
}

function selectScriptVM(selectorId, vmName) {
  // Update tab styles
  document.querySelectorAll(`.${selectorId}-vm-tab`).forEach(tab => {
    const isActive = tab.dataset.vm === vmName;
    tab.style.background = isActive ? 'white' : '';
    tab.style.borderLeftColor = isActive ? '#4299e1' : 'transparent';
  });

  // Find the container
  const panel = document.getElementById(`${selectorId}-scriptpanel`);
  const container = panel?.closest('[id$="VulnScriptPanel"]') || panel?.parentElement?.parentElement;
  renderScriptPanelForVM(selectorId, vmName, container);
}

function renderScriptPanelForVM(selectorId, vmName, container) {
  const panel = document.getElementById(`${selectorId}-scriptpanel`);
  if (!panel || !container) return;

  const vms = container._vms || [];
  const scripts = container._scripts || cachedVulnScripts;
  const vm = vms.find(v => v.name === vmName);
  if (!vm) return;

  const vmOs = (vm.os || '').toLowerCase().includes('linux') ? 'linux' : 'windows';
  const compatScripts = scripts.filter(s => s.os_target === 'any' || s.os_target === vmOs);
  const selected = scriptSelections[selectorId]?.[vmName] || new Set();

  // Group by category
  const categories = {};
  compatScripts.forEach(s => {
    if (!categories[s.category]) categories[s.category] = [];
    categories[s.category].push(s);
  });

  let html = `
    <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.75rem;">
      <input type="text" id="${selectorId}-search" placeholder="Search scripts..." oninput="filterScriptPanel('${selectorId}')" style="flex: 1; padding: 0.3rem 0.6rem; border-radius: 6px; border: 1px solid #e2e8f0; font-size: 0.8rem;">
      <button style="font-size: 0.7rem; padding: 0.2rem 0.5rem; border: 1px solid #4299e1; color: #4299e1; background: transparent; border-radius: 4px; cursor: pointer;" onclick="bulkSelectScripts('${selectorId}', '${escHtml(vmName)}', 'all')">All</button>
      <button style="font-size: 0.7rem; padding: 0.2rem 0.5rem; border: 1px solid #cbd5e0; color: var(--gray-500); background: transparent; border-radius: 4px; cursor: pointer;" onclick="bulkSelectScripts('${selectorId}', '${escHtml(vmName)}', 'none')">None</button>
      <button style="font-size: 0.7rem; padding: 0.2rem 0.5rem; border: 1px solid #38a169; color: #38a169; background: transparent; border-radius: 4px; cursor: pointer;" onclick="bulkSelectScripts('${selectorId}', '${escHtml(vmName)}', 'defaults')">Defaults</button>
    </div>`;

  for (const [cat, catScripts] of Object.entries(categories).sort((a, b) => a[0].localeCompare(b[0]))) {
    html += `
      <div class="script-cat-group" data-cat="${escHtml(cat)}" style="margin-bottom: 0.75rem;">
        <div style="font-size: 0.7rem; color: var(--gray-500); font-weight: 600; text-transform: uppercase; letter-spacing: 0.03em; margin-bottom: 0.3rem; padding-bottom: 0.2rem; border-bottom: 1px solid #edf2f7;">${escHtml(cat)}</div>
        ${catScripts.map(s => {
          const isChecked = selected.has(s.slug);
          const isDefault = (vm.default_scripts || []).includes(s.slug);
          const deps = (s.depends_on || []).join(', ');
          const services = (s.services_exposed || []).join(', ');
          return `
          <label class="script-row" data-slug="${escHtml(s.slug)}" style="display: flex; align-items: flex-start; gap: 0.5rem; padding: 0.4rem 0.5rem; border-radius: 6px; cursor: pointer; transition: background 0.1s; margin-bottom: 1px;" onmouseenter="this.style.background='#f7fafc'" onmouseleave="this.style.background=''">
            <input type="checkbox" ${isChecked ? 'checked' : ''}
              onchange="toggleScript('${selectorId}', '${escHtml(vmName)}', '${escHtml(s.slug)}', this.checked)"
              style="width: auto; margin-top: 0.15rem;">
            <div style="flex: 1; min-width: 0;">
              <div style="font-size: 0.8rem; font-weight: 500; display: flex; align-items: center; gap: 0.3rem;">
                ${escHtml(s.name)}
                ${isDefault ? '<span style="font-size: 0.6rem; background: #c6f6d5; color: #22543d; padding: 0 0.3rem; border-radius: 3px;">default</span>' : ''}
              </div>
              ${s.description ? `<div style="font-size: 0.7rem; color: var(--gray-500); display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; line-height: 1.3;">${escHtml(s.description)}</div>` : ''}
              <div style="display: flex; gap: 0.5rem; margin-top: 0.1rem;">
                ${services ? `<span style="font-size: 0.6rem; color: #4299e1;">${escHtml(services)}</span>` : ''}
                ${deps ? `<span style="font-size: 0.6rem; color: var(--gray-400);">deps: ${escHtml(deps)}</span>` : ''}
              </div>
            </div>
          </label>`;
        }).join('')}
      </div>`;
  }

  if (compatScripts.length === 0) {
    html += '<p style="color: var(--gray-400); font-size: 0.85rem; text-align: center; padding: 2rem;">No compatible scripts for this OS type.</p>';
  }

  panel.innerHTML = html;
}

function toggleScript(selectorId, vmName, slug, checked) {
  if (!scriptSelections[selectorId]) scriptSelections[selectorId] = {};
  if (!scriptSelections[selectorId][vmName]) scriptSelections[selectorId][vmName] = new Set();

  if (checked) {
    scriptSelections[selectorId][vmName].add(slug);
  } else {
    scriptSelections[selectorId][vmName].delete(slug);
  }

  // Update VM tab count
  const count = scriptSelections[selectorId][vmName].size;
  const countEl = document.getElementById(`${selectorId}-vmcount-${vmName}`);
  if (countEl) countEl.textContent = `${count} script${count !== 1 ? 's' : ''}`;

  updateScriptTotalCount(selectorId);
}

function bulkSelectScripts(selectorId, vmName, mode) {
  const panel = document.getElementById(`${selectorId}-scriptpanel`);
  if (!panel) return;

  const container = panel.closest('[id$="VulnScriptPanel"]') || panel.parentElement?.parentElement;
  const vm = (container?._vms || []).find(v => v.name === vmName);
  const defaults = vm?.default_scripts || [];

  if (!scriptSelections[selectorId]) scriptSelections[selectorId] = {};

  if (mode === 'all') {
    const allSlugs = new Set();
    panel.querySelectorAll('.script-row input[type="checkbox"]').forEach(cb => {
      cb.checked = true;
      allSlugs.add(cb.closest('.script-row').dataset.slug);
    });
    scriptSelections[selectorId][vmName] = allSlugs;
  } else if (mode === 'none') {
    panel.querySelectorAll('.script-row input[type="checkbox"]').forEach(cb => { cb.checked = false; });
    scriptSelections[selectorId][vmName] = new Set();
  } else if (mode === 'defaults') {
    panel.querySelectorAll('.script-row input[type="checkbox"]').forEach(cb => {
      const slug = cb.closest('.script-row').dataset.slug;
      cb.checked = defaults.includes(slug);
    });
    scriptSelections[selectorId][vmName] = new Set(defaults);
  }

  const count = (scriptSelections[selectorId][vmName] || new Set()).size;
  const countEl = document.getElementById(`${selectorId}-vmcount-${vmName}`);
  if (countEl) countEl.textContent = `${count} script${count !== 1 ? 's' : ''}`;
  updateScriptTotalCount(selectorId);
}

function filterScriptPanel(selectorId) {
  const search = (document.getElementById(`${selectorId}-search`)?.value || '').toLowerCase();
  const panel = document.getElementById(`${selectorId}-scriptpanel`);
  if (!panel) return;

  panel.querySelectorAll('.script-row').forEach(row => {
    const text = row.textContent.toLowerCase();
    const slug = (row.dataset.slug || '').toLowerCase();
    row.style.display = (!search || text.includes(search) || slug.includes(search)) ? '' : 'none';
  });

  // Also hide empty category headers
  panel.querySelectorAll('.script-cat-group').forEach(group => {
    const visibleRows = group.querySelectorAll('.script-row:not([style*="display: none"])');
    group.style.display = visibleRows.length > 0 ? '' : 'none';
  });
}

function updateScriptTotalCount(selectorId) {
  let total = 0;
  for (const vm of Object.values(scriptSelections[selectorId] || {})) {
    total += vm.size;
  }
  const el = document.getElementById(`${selectorId}-total`);
  if (el) el.textContent = `${total} script${total !== 1 ? 's' : ''} selected`;
}

function getSelectedScripts(selectorId) {
  const selected = [];
  for (const [vmName, slugs] of Object.entries(scriptSelections[selectorId] || {})) {
    for (const slug of slugs) {
      selected.push({ vm_name: vmName, script_slug: slug });
    }
  }
  return selected;
}

// ============================================================================
// CHALLENGE SELECTION → LOAD SCRIPT SELECTOR
// ============================================================================

async function onGroupChallengeSelected() {
  const panel = document.getElementById('groupDeployVulnScriptPanel');
  const challengeKey = document.getElementById('deployGroupChallenge').value;
  const module = document.getElementById('deployGroupModule').value;

  if (!challengeKey) {
    panel.style.display = 'none';
    return;
  }

  panel.innerHTML = '<p style="color: var(--gray-500); font-size: 0.85rem;">Loading challenge VMs...</p>';
  panel.style.display = 'block';

  try {
    const challenges = cachedChallenges[module] || [];
    const challenge = challenges.find(c => c.challenge_key === challengeKey);

    if (!challenge || !challenge.challenge_id) {
      await renderScriptSelector(panel, [{ name: challengeKey, role: 'Primary', os: 'Windows' }], 'group-deploy-script', []);
      return;
    }

    const fullChallenge = await api('GET', `/lab-templates/${challenge.challenge_id}`);
    const spec = typeof fullChallenge.spec === 'string' ? JSON.parse(fullChallenge.spec) : (fullChallenge.spec || {});
    const vms = (spec.vms || []).length > 0
      ? spec.vms
      : [{ name: challengeKey, role: 'Primary', os: 'Unknown', default_scripts: [] }];

    await renderScriptSelector(panel, vms, 'group-deploy-script', []);
  } catch (e) {
    panel.innerHTML = `<p style="color: #e53e3e; font-size: 0.85rem;">Error: ${e.message}</p>`;
  }
}

async function onChallengeSelected() {
  const panel = document.getElementById('deployVulnScriptPanel');
  const challengeKey = document.getElementById('deployChallengeKey').value;
  const module = document.getElementById('deployModule').value;

  if (!challengeKey) {
    panel.style.display = 'none';
    return;
  }

  panel.innerHTML = '<p style="color: var(--gray-500); font-size: 0.85rem;">Loading challenge VMs...</p>';
  panel.style.display = 'block';

  try {
    // Look up challenge_id from cached challenges
    const challenges = cachedChallenges[module] || [];
    const challenge = challenges.find(c => c.challenge_key === challengeKey);

    if (!challenge || !challenge.challenge_id) {
      // Fallback: show a basic single-VM selector
      await renderScriptSelector(panel, [{ name: challengeKey, role: 'Primary', os: 'Windows' }], 'deploy-script', []);
      return;
    }

    // Get full challenge details with spec
    const fullChallenge = await api('GET', `/lab-templates/${challenge.challenge_id}`);
    const rawSpec = fullChallenge.spec;
    const spec = typeof rawSpec === 'string' ? JSON.parse(rawSpec) : (rawSpec || {});
    const vms = (spec.vms || []).length > 0
      ? spec.vms
      : [{ name: challengeKey, role: 'Primary', os: 'Unknown', default_scripts: [] }];

    await renderScriptSelector(panel, vms, 'deploy-script', []);
  } catch (e) {
    panel.innerHTML = `<p style="color: #e53e3e; font-size: 0.85rem;">Error: ${e.message}</p>`;
  }
}

// ============================================================================
// PUSH FILE TO VM
// ============================================================================

async function showPushFileModal(laneId, laneName) {
  const body = document.getElementById('permissionsBody');
  document.getElementById('permUsername').textContent = `Push File — ${laneName}`;

  // Get lane config for VM list
  const lane = await api('GET', `/lanes/${laneId}`);
  const cfg = typeof lane.config === 'string' ? JSON.parse(lane.config || '{}') : (lane.config || {});
  let vms = cfg.vms || [];
  if (vms.length === 0 && cfg.challenge_vm_id) {
    vms = [{ name: cfg.challenge_key || 'challenge', vm_id: cfg.challenge_vm_id }];
  }

  // Get available files from vuln-assets
  let files = [];
  try {
    files = await api('GET', '/vuln-asset-list');
  } catch (_) {}

  body.innerHTML = `
    <p style="color: var(--gray-500); font-size: 0.85rem; margin-bottom: 1rem;">
      Push a file from the server's vuln-assets/ folder directly to a VM via the guest agent. No network access needed on the VM.
    </p>
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
      <div class="form-group">
        <label>Target VM</label>
        <select id="pushFileVm">
          ${vms.map(v => `<option value="${escHtml(v.name)}">${escHtml(v.name)} (${v.vm_id || '?'})</option>`).join('')}
        </select>
      </div>
      <div class="form-group">
        <label>File</label>
        <select id="pushFileSelect">
          ${files.length > 0
            ? files.map(f => `<option value="${escHtml(f.name)}">${escHtml(f.name)} (${f.size_mb} MB)</option>`).join('')
            : '<option value="">No files in vuln-assets/</option>'}
        </select>
      </div>
    </div>
    <div class="form-group">
      <label>Destination Path on VM</label>
      <input type="text" id="pushFileDest" value="C:\\Windows\\Temp\\" placeholder="C:\\LabApps\\file.jar">
    </div>
    <button class="btn btn-primary" onclick="pushFileToVM('${laneId}')" style="width: 100%;">Push File</button>
    <div id="pushFileStatus" style="margin-top: 0.75rem; font-size: 0.85rem;"></div>`;

  // Auto-fill dest path when file is selected
  document.getElementById('pushFileSelect').onchange = function() {
    const filename = this.value;
    document.getElementById('pushFileDest').value = `C:\\LabApps\\${filename}`;
  };
  // Trigger initial fill
  if (files.length > 0) {
    document.getElementById('pushFileDest').value = `C:\\LabApps\\${files[0].name}`;
  }

  const mc = document.querySelector('#permissionsModal .modal-content');
  mc.style.maxWidth = '600px';
  document.getElementById('permissionsModal').classList.add('active');
}

async function pushFileToVM(laneId) {
  const vm_name = document.getElementById('pushFileVm').value;
  const filename = document.getElementById('pushFileSelect').value;
  const dest_path = document.getElementById('pushFileDest').value.trim();
  const status = document.getElementById('pushFileStatus');

  if (!filename || !dest_path) {
    Toast.warning('Missing', 'Select a file and enter a destination path');
    return;
  }

  status.innerHTML = '<strong style="color: var(--gray-500);">Pushing file... This may take a few minutes for large files. You can close this modal.</strong>';

  try {
    const data = await api('POST', '/push-file', { lane_id: laneId, vm_name, filename, dest_path });
    status.innerHTML = `<strong style="color: #38a169;">${escHtml(data.message)}</strong><br>
      <span style="font-size: 0.8rem; color: var(--gray-500);">Check server console for progress. Large files may take 5-10 minutes.</span>`;
    Toast.success('Push Started', `${filename} → ${vm_name}`);
  } catch (e) {
    status.innerHTML = `<strong style="color: #e53e3e;">Error:</strong> ${escHtml(e.message)}`;
    Toast.error('Failed', e.message);
  }
}

// ============================================================================
// ATTACHED MODULES — graft / remove single-purpose VMs on a running lane
// ============================================================================
// Reuses #permissionsModal as the modal container (same pattern as
// Push File / Run Script). The modal shows currently attached modules
// with per-module Detach buttons + a dropdown of attachable challenges
// with an Attach button.

async function showModulesModal(laneId, laneName) {
  const body = document.getElementById('permissionsBody');
  document.getElementById('permUsername').textContent = `Modules — ${laneName}`;
  const mc = document.querySelector('#permissionsModal .modal-content');
  mc.style.maxWidth = '720px';
  document.getElementById('permissionsModal').classList.add('active');

  body.innerHTML = `
    <p style="color: var(--gray-500); font-size: 0.85rem; margin-bottom: 1rem;">
      Graft an additional VM onto this lane (e.g., DVWA, Juice Shop) without redeploying.
      Attached VMs sit on the same VXLAN so the Kali attack box can reach them at the lane subnet.
    </p>
    <div id="modulesAttachedSection" style="margin-bottom: 1.5rem;">
      <h4 style="margin: 0 0 0.5rem 0; color: var(--gray-700); font-size: 0.95rem;">Currently attached</h4>
      <div id="modulesAttachedList" style="color: var(--gray-500); font-size: 0.85rem;">Loading...</div>
    </div>
    <div>
      <h4 style="margin: 0 0 0.5rem 0; color: var(--gray-700); font-size: 0.95rem;">Attach a new module</h4>
      <div style="display: grid; grid-template-columns: 2fr 1fr; gap: 0.5rem; align-items: end;">
        <div class="form-group" style="margin: 0;">
          <label style="font-size: 0.8rem;">Challenge (attachable only)</label>
          <select id="moduleAttachSelect" style="width: 100%;">
            <option value="">Loading...</option>
          </select>
        </div>
        <button id="moduleAttachBtn" class="btn btn-primary" style="height: fit-content;" onclick="attachModule('${laneId}', '${escHtml(laneName)}')">Attach</button>
      </div>
      <div id="moduleAttachStatus" style="margin-top: 0.5rem; font-size: 0.85rem;"></div>
    </div>`;

  await loadModulesIntoModal(laneId);
}

/**
 * Refresh the modal body with current state:
 *   - Attached list from GET /lanes/:id/modules
 *   - Attachable challenges from GET /challenges/crucible (filtered by attachable flag)
 */
async function loadModulesIntoModal(laneId) {
  const attachedDiv = document.getElementById('modulesAttachedList');
  const select = document.getElementById('moduleAttachSelect');

  // 1. Attached modules on this lane
  try {
    const data = await api('GET', `/lanes/${laneId}/modules`);
    const attached = Array.isArray(data.attached_modules) ? data.attached_modules : [];
    if (attached.length === 0) {
      attachedDiv.innerHTML = '<em style="color: var(--gray-400);">No modules attached.</em>';
    } else {
      attachedDiv.innerHTML = `
        <table style="width: 100%; font-size: 0.85rem; border-collapse: collapse;">
          <thead>
            <tr style="border-bottom: 1px solid var(--gray-200);">
              <th style="text-align: left; padding: 0.4rem 0.5rem;">Challenge</th>
              <th style="text-align: left; padding: 0.4rem 0.5rem;">VMs</th>
              <th style="text-align: left; padding: 0.4rem 0.5rem;">Attached</th>
              <th style="text-align: right; padding: 0.4rem 0.5rem;">Action</th>
            </tr>
          </thead>
          <tbody>
            ${attached.map(m => {
              const vms = (m.vms || []).map(v => `${escHtml(v.name)}@${escHtml(v.ip || '?')}`).join(', ');
              const when = m.attached_at ? new Date(m.attached_at).toLocaleString() : '—';
              return `
                <tr style="border-bottom: 1px solid var(--gray-100);">
                  <td style="padding: 0.4rem 0.5rem;"><strong>${escHtml(m.challenge_key)}</strong></td>
                  <td style="padding: 0.4rem 0.5rem; font-family: monospace; font-size: 0.75rem;">${vms || '—'}</td>
                  <td style="padding: 0.4rem 0.5rem; color: var(--gray-500); font-size: 0.75rem;">${escHtml(when)}</td>
                  <td style="padding: 0.4rem 0.5rem; text-align: right;">
                    <button class="btn btn-sm" style="font-size: 0.75rem; padding: 0.2rem 0.5rem; border: 1px solid #e53e3e; color: #e53e3e; background: transparent;"
                      onclick="detachModule('${laneId}', '${escHtml(m.module_instance_id)}', '${escHtml(m.challenge_key)}')">
                      Detach
                    </button>
                  </td>
                </tr>`;
            }).join('')}
          </tbody>
        </table>`;
    }
  } catch (e) {
    attachedDiv.innerHTML = `<span style="color: #e53e3e;">Error loading attached modules: ${escHtml(e.message)}</span>`;
  }

  // 2. Attachable challenges. We probe the crucible module (where attachable
  //    challenges currently live); the endpoint returns an empty array if
  //    the table doesn't exist or no challenges qualify.
  try {
    const challenges = await api('GET', '/challenges/crucible');
    const attachable = (challenges || []).filter(c => c.attachable === true);
    if (attachable.length === 0) {
      select.innerHTML = '<option value="">No attachable challenges found</option>';
      document.getElementById('moduleAttachBtn').disabled = true;
    } else {
      select.innerHTML = attachable
        .map(c => `<option value="${escHtml(c.challenge_key)}">${escHtml(c.name)} (${escHtml(c.challenge_key)})</option>`)
        .join('');
      document.getElementById('moduleAttachBtn').disabled = false;
    }
  } catch (e) {
    select.innerHTML = `<option value="">Error: ${escHtml(e.message)}</option>`;
    document.getElementById('moduleAttachBtn').disabled = true;
  }
}

async function attachModule(laneId, laneName) {
  const select = document.getElementById('moduleAttachSelect');
  const status = document.getElementById('moduleAttachStatus');
  const challenge_key = select.value;
  if (!challenge_key) {
    Toast.warning('Pick a challenge', 'Select an attachable challenge first.');
    return;
  }
  status.innerHTML = '<strong style="color: var(--gray-500);">Attaching... (clone runs in background, takes 30–60s)</strong>';
  try {
    const data = await api('POST', `/lanes/${laneId}/modules`, { challenge_key, module: 'crucible' });
    Toast.success('Attach Started', `${challenge_key} attaching to lane ${laneName}`);
    status.innerHTML = `<strong style="color: #38a169;">${escHtml(data.message || 'Attach started')}</strong>`;
    // Poll for completion — the new entry appears in attached_modules once
    // the background task finishes the clone + DHCP write.
    pollModulesUntilSettled(laneId, challenge_key);
  } catch (e) {
    status.innerHTML = `<strong style="color: #e53e3e;">Attach failed:</strong> ${escHtml(e.message)}`;
    Toast.error('Attach Failed', e.message);
  }
}

async function detachModule(laneId, moduleInstanceId, challengeKey) {
  if (!confirm(`Detach module "${challengeKey}" from this lane?\n\nThe attached VMs will be STOPPED and DESTROYED. The rest of the lane is untouched.`)) return;
  try {
    const data = await api('DELETE', `/lanes/${laneId}/modules/${moduleInstanceId}`);
    Toast.success('Detached', `${challengeKey} removed (${(data.destroyed || []).length} VM(s) destroyed)`);
    if (data.errors) {
      console.warn('Detach partial errors:', data.errors);
      Toast.warning('Partial Errors', `${data.errors.length} non-critical cleanup error(s)`);
    }
    await loadModulesIntoModal(laneId);
    loadLanes();
  } catch (e) {
    Toast.error('Detach Failed', e.message);
  }
}

/**
 * Poll GET /lanes/:id/modules until either the named challenge_key shows
 * up in attached_modules (success) or we exceed the budget (timeout).
 * Refreshes the modal on each tick so the user sees progress.
 */
async function pollModulesUntilSettled(laneId, challengeKey) {
  const deadline = Date.now() + 5 * 60 * 1000; // 5 min ceiling
  while (Date.now() < deadline) {
    await new Promise(r => setTimeout(r, 5000));
    try {
      const data = await api('GET', `/lanes/${laneId}/modules`);
      const found = (data.attached_modules || []).some(m => m.challenge_key === challengeKey);
      // Refresh modal if it's still open (user may have closed it).
      if (document.getElementById('permissionsModal').classList.contains('active') &&
          document.getElementById('modulesAttachedList')) {
        await loadModulesIntoModal(laneId);
      }
      if (found) {
        Toast.success('Attach Complete', `${challengeKey} is now reachable on the lane subnet`);
        loadLanes();
        return;
      }
    } catch (_) { /* keep polling on transient errors */ }
  }
  Toast.warning('Attach Slow', `${challengeKey} still not visible after 5 min — check server logs`);
}

// ============================================================================
// GENERATE CHALLENGE PROFILE
// ============================================================================

async function showGenerateChallengeProfileModal(laneId, laneName) {
  const body = document.getElementById('permissionsBody');
  document.getElementById('permUsername').textContent = `Generate Challenge Profile — ${laneName}`;

  body.innerHTML = `
    <p style="color: var(--gray-500); font-size: 0.85rem; margin-bottom: 1rem;">
      Generate an AI client profile based on this lane's deployed VMs and vulnerability scripts.
      Real VM IPs will be embedded in the profile's network diagrams and asset inventory.
    </p>
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
      <div class="form-group">
        <label>Client Type</label>
        <select id="chalProfileClientType">
          <option value="SMB">Small-Medium Business</option>
          <option value="NonProfit">Non-Profit Organization</option>
          <option value="Utility_IT_OT">Utility Company (IT/OT)</option>
          <option value="K12">K-12 School District</option>
        </select>
      </div>
      <div class="form-group">
        <label>Industry</label>
        <input type="text" id="chalProfileIndustry" value="Technology" placeholder="e.g., Healthcare, Finance">
      </div>
    </div>
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
      <div class="form-group">
        <label>Difficulty</label>
        <select id="chalProfileDifficulty">
          <option value="beginner">Beginner</option>
          <option value="intermediate" selected>Intermediate</option>
          <option value="advanced">Advanced</option>
        </select>
      </div>
      <div class="form-group">
        <label>Company Name (optional)</label>
        <input type="text" id="chalProfileCompany" placeholder="Leave blank for AI-generated">
      </div>
    </div>
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-top: 0.5rem;">
      <div class="form-group">
        <label>AI Model</label>
        <select id="chalProfileModel" onchange="updateChalProfileCost()">
          <optgroup label="Cloud APIs">
            <option value="gemini-2.5-flash" selected>Gemini 2.5 Flash (Recommended)</option>
            <option value="gemini-2.5-pro">Gemini 2.5 Pro</option>
            <option value="claude-sonnet-4-5">Claude Sonnet 4.5</option>
            <option value="claude-haiku-4-5">Claude Haiku 4.5</option>
          </optgroup>
          <optgroup label="Local (Ollama)">
            <option value="qwen3:14b">Qwen 3.0 14B</option>
            <option value="llama3.2">Llama 3.2</option>
          </optgroup>
        </select>
      </div>
      <div class="form-group">
        <label>Est. Cost</label>
        <div id="chalProfileCost" style="padding: 0.5rem; font-weight: 700; font-size: 1.1rem; color: #38a169;">< $0.01</div>
      </div>
    </div>
    <button class="btn btn-primary" onclick="generateChallengeProfileFromModal('${laneId}')" style="width: 100%; margin-top: 0.5rem;">Generate Challenge Profile</button>
    <div id="chalProfileStatus" style="margin-top: 0.75rem; font-size: 0.85rem;"></div>`;

  updateChalProfileCost();

  const mc = document.querySelector('#permissionsModal .modal-content');
  mc.style.maxWidth = '600px';
  document.getElementById('permissionsModal').classList.add('active');
}

// ─── AI Model Cost Estimation (shared across modals) ───
const AI_MODEL_INFO = {
  'claude-sonnet-4-5':   { label: 'Claude Sonnet 4.5',  input: 3.00,  output: 15.00, provider: 'anthropic' },
  'claude-haiku-4-5':    { label: 'Claude Haiku 4.5',   input: 0.80,  output: 4.00,  provider: 'anthropic' },
  'gemini-2.5-flash':    { label: 'Gemini 2.5 Flash',   input: 0.15,  output: 0.60,  provider: 'google' },
  'gemini-2.5-pro':      { label: 'Gemini 2.5 Pro',     input: 1.25,  output: 10.00, provider: 'google' },
  'qwen3:14b':           { label: 'Qwen 3.0 14B',       input: 0,     output: 0,     provider: 'ollama' },
  'llama3.2':            { label: 'Llama 3.2',           input: 0,     output: 0,     provider: 'ollama' }
};

function estimateCost(modelId, inputTokens, outputTokens) {
  const info = AI_MODEL_INFO[modelId] || { input: 0, output: 0, provider: 'unknown' };
  if (info.provider === 'ollama') return { text: 'Free (local)', color: '#38a169' };
  const total = (inputTokens / 1_000_000) * info.input + (outputTokens / 1_000_000) * info.output;
  if (total < 0.01) return { text: '< $0.01', color: '#38a169' };
  return {
    text: `~$${total.toFixed(2)}`,
    color: total > 0.50 ? '#e53e3e' : total > 0.10 ? '#d69e2e' : '#38a169'
  };
}

function updateChalProfileCost() {
  const el = document.getElementById('chalProfileCost');
  if (!el) return;
  const model = document.getElementById('chalProfileModel').value;
  // Profile generation: ~12K input + ~18K output across 3 branches
  const est = estimateCost(model, 12000, 18000);
  el.textContent = est.text;
  el.style.color = est.color;
}

async function generateChallengeProfileFromModal(laneId) {
  const client_type = document.getElementById('chalProfileClientType').value;
  const industry = document.getElementById('chalProfileIndustry').value.trim();
  const difficulty = document.getElementById('chalProfileDifficulty').value;
  const company_name = document.getElementById('chalProfileCompany').value.trim() || null;
  const llm_model = document.getElementById('chalProfileModel').value;
  const status = document.getElementById('chalProfileStatus');

  status.innerHTML = '<strong style="color: var(--gray-500);">Sending to N8N for AI generation... This may take 1-3 minutes.</strong>';

  try {
    const data = await api('POST', `/lab-networks/${laneId}/generate-profile`, {
      client_type, industry, difficulty, company_name, llm_model
    });

    status.innerHTML = `
      <strong style="color: #38a169;">Profile generation triggered!</strong><br>
      <span style="font-size: 0.8rem;">
        Assets included: ${data.assets_included} (${data.real_vms} real VMs + ${data.phantom_hosts} phantom hosts)<br>
        ${data.profile_id ? `Profile ID: <code>${data.profile_id}</code>` : 'Profile ID will be assigned when N8N completes.'}
      </span>`;

    Toast.success('Profile Generating', `${data.assets_included} assets sent to AI`);
  } catch (e) {
    status.innerHTML = `<strong style="color: #e53e3e;">Error:</strong> ${escHtml(e.message)}`;
    Toast.error('Failed', e.message);
  }
}

async function showRunScriptModal(laneId, laneName) {
  const lane = await api('GET', `/lanes/${laneId}`);
  const cfg = typeof lane.config === 'string' ? JSON.parse(lane.config || '{}') : (lane.config || {});

  // Build VM list
  let vms = cfg.vms || [];
  if (vms.length === 0 && cfg.challenge_vm_id) {
    vms = [{ name: cfg.challenge_key || 'challenge', type: 'qemu', vm_id: cfg.challenge_vm_id, role: 'Primary', os: 'Windows' }];
  }

  const body = document.getElementById('permissionsBody');
  document.getElementById('permUsername').textContent = `Run Scripts — ${laneName}`;

  // Clear previous selections for this modal
  delete scriptSelections['run-script'];

  body.innerHTML = `
    <div id="runScriptSelectorPanel"></div>
    <button class="btn btn-primary" onclick="runSelectedScriptsOnLane('${laneId}')" style="width: 100%; margin-top: 0.75rem;">Run Selected Scripts</button>
    <div id="runScriptStatus" style="margin-top: 0.75rem; font-size: 0.85rem;"></div>
    <div id="runScriptOutputs" style="margin-top: 0.5rem; max-height: 300px; overflow-y: auto;"></div>`;

  // Make modal wider for script selector
  const modalContent = document.querySelector('#permissionsModal .modal-content');
  modalContent.style.maxWidth = '850px';
  modalContent.style.width = '90%';

  document.getElementById('permissionsModal').classList.add('active');

  await renderScriptSelector(
    document.getElementById('runScriptSelectorPanel'),
    vms, 'run-script', []
  );
}

async function runSelectedScriptsOnLane(laneId) {
  const selected = getSelectedScripts('run-script');
  const modalStatus = document.getElementById('runScriptStatus');

  if (selected.length === 0) {
    Toast.warning('No Scripts', 'Select at least one script to run');
    return;
  }

  // Show the persistent panel
  const panel = document.getElementById('scriptExecPanel');
  const outputs = document.getElementById('scriptExecOutputs');
  panel.style.display = 'block';

  // Add output sections for each script
  selected.forEach(s => {
    const id = `exec-${laneId}-${s.vm_name}-${s.script_slug}`.replace(/[^a-z0-9-]/gi, '-');
    // Remove existing entry if re-running
    const existing = document.getElementById(id);
    if (existing) existing.remove();

    outputs.innerHTML += `
      <div id="${id}" style="margin-bottom: 0.75rem; border-bottom: 1px solid #edf2f7; padding-bottom: 0.75rem;">
        <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.25rem;">
          <span class="badge badge-blue" style="font-size: 0.65rem;">${escHtml(s.vm_name)}</span>
          <strong style="font-size: 0.8rem;">${escHtml(s.script_slug)}</strong>
          <span class="exec-status" data-key="${escHtml(s.vm_name)}:${escHtml(s.script_slug)}" style="font-size: 0.7rem; color: var(--gray-500);">sending...</span>
        </div>
        <pre class="exec-output" data-key="${escHtml(s.vm_name)}:${escHtml(s.script_slug)}" style="background: #1a202c; color: #e2e8f0; padding: 0.5rem; border-radius: 6px; font-size: 0.7rem; max-height: 400px; overflow: auto; white-space: pre-wrap; word-break: break-all; margin: 0;">Waiting...</pre>
      </div>`;
  });

  // Update modal status
  if (modalStatus) modalStatus.innerHTML = `<strong style="color: var(--gray-500);">Sending ${selected.length} script(s)... You can close this modal.</strong>`;

  // Send each script
  let sentCount = 0;
  for (const s of selected) {
    try {
      await api('POST', `/lab-networks/${laneId}/run-script`, { vm_name: s.vm_name, script_slug: s.script_slug });
      sentCount++;
      updateExecStatus(s.vm_name, s.script_slug, 'sent', '#4299e1');
    } catch (e) {
      updateExecStatus(s.vm_name, s.script_slug, `error: ${e.message}`, '#e53e3e');
    }
  }

  if (modalStatus) modalStatus.innerHTML = `<strong style="color: #38a169;">${sentCount}/${selected.length} sent. You can close this modal — output appears in the panel below the lanes table.</strong>`;
  Toast.success('Scripts Sent', `${sentCount} script(s) running. Track progress below the lanes table.`);

  updateExecSummary();

  // Poll in background (not tied to modal)
  pollScriptExecution(laneId, selected);
}

function updateExecStatus(vmName, slug, text, color) {
  const key = `${vmName}:${slug}`;
  document.querySelectorAll(`.exec-status[data-key="${key}"]`).forEach(el => {
    el.textContent = text;
    el.style.color = color || 'var(--gray-500)';
  });
}

function updateExecOutput(vmName, slug, text, borderColor) {
  const key = `${vmName}:${slug}`;
  document.querySelectorAll(`.exec-output[data-key="${key}"]`).forEach(el => {
    el.textContent = text;
    if (borderColor) el.style.borderLeft = `3px solid ${borderColor}`;
  });
}

function updateExecSummary() {
  const all = document.querySelectorAll('.exec-status');
  let running = 0, completed = 0, failed = 0;
  all.forEach(el => {
    const t = el.textContent;
    if (t === 'running...' || t === 'sent') running++;
    else if (t === 'completed') completed++;
    else if (t.startsWith('error') || t === 'failed') failed++;
  });
  const summary = document.getElementById('scriptExecSummary');
  if (summary) {
    const parts = [];
    if (running > 0) parts.push(`${running} running`);
    if (completed > 0) parts.push(`${completed} done`);
    if (failed > 0) parts.push(`${failed} failed`);
    summary.textContent = parts.join(' · ') || 'idle';
  }
}

function clearScriptExecPanel() {
  document.getElementById('scriptExecOutputs').innerHTML = '';
  document.getElementById('scriptExecPanel').style.display = 'none';
}

async function pollScriptExecution(laneId, scripts) {
  const remaining = new Set(scripts.map(s => `${s.vm_name}:${s.script_slug}`));

  for (let i = 0; i < 600 && remaining.size > 0; i++) {
    await new Promise(r => setTimeout(r, 5000));
    try {
      const data = await api('GET', `/lab-networks/${laneId}/status`);
      const entries = data.selected_scripts || [];

      for (const s of scripts) {
        const key = `${s.vm_name}:${s.script_slug}`;
        if (!remaining.has(key)) continue;

        const entry = entries.find(e => e.script_slug === s.script_slug && e.vm_name === s.vm_name);
        if (!entry) continue;

        if (entry.status === 'completed') {
          updateExecStatus(s.vm_name, s.script_slug, 'completed', '#38a169');
          updateExecOutput(s.vm_name, s.script_slug, entry.output || '(no output)', '#38a169');
          remaining.delete(key);
          Toast.success('Script Done', `${s.script_slug} completed`);
        } else if (entry.status === 'failed') {
          updateExecStatus(s.vm_name, s.script_slug, 'failed', '#e53e3e');
          updateExecOutput(s.vm_name, s.script_slug, `ERROR: ${entry.error || 'Unknown'}\n\n${entry.output || ''}`, '#e53e3e');
          remaining.delete(key);
          Toast.error('Script Failed', `${s.script_slug} failed`);
        } else if (entry.status === 'running') {
          updateExecStatus(s.vm_name, s.script_slug, 'running...', '#d69e2e');

          // Poll VM progress log for live updates
          try {
            const progress = await api('GET', `/vm-progress/${laneId}?vm_name=${encodeURIComponent(s.vm_name)}`);
            if (progress.log && progress.log !== 'No progress log yet' && progress.log !== 'No output') {
              updateExecOutput(s.vm_name, s.script_slug, progress.log.trim());
            }
          } catch (_) {}
        }
      }

      updateExecSummary();
    } catch (_) {}
  }
}

async function toggleAdminInternet(laneId, enabled) {
  try {
    await api('PATCH', `/lanes/${laneId}/internet`, { enabled });
    Toast.success('Internet ' + (enabled ? 'Enabled' : 'Disabled'), 'Lane updated');
  } catch (e) {
    Toast.error('Error', e.message);
    loadLanes(); // Revert checkbox state
  }
}

async function deleteLane(laneId, laneName) {
  if (!confirm(`DELETE lane "${laneName}"?\n\nThis will STOP and DESTROY the challenge VM and gateway container, then mark the lane as deleted.\n\nThis cannot be undone.`)) return;

  try {
    const data = await api('DELETE', `/lanes/${laneId}`);
    Toast.success('Lane Deleted', `Lane ${laneName} torn down (VXLAN ${data.vxlan_id})`);
    if (data.errors) {
      console.warn('Lane delete partial errors:', data.errors);
      Toast.warning('Partial Errors', `${data.errors.length} non-critical error(s) during cleanup`);
    }
    loadLanes();
  } catch (e) {
    Toast.error('Delete Failed', e.message);
  }
}

// ============================================================================
// GROUP DEPLOYMENT
// ============================================================================

function toggleLaneDeployInfo() {
  const checked = document.getElementById('deployLanes').checked;
  const options = document.getElementById('laneDeployOptions');
  const info = document.getElementById('laneCapacityInfo');
  options.style.display = checked ? 'block' : 'none';
  if (checked) {
    const numStudents = parseInt(document.getElementById('deployNumStudents').value) || 1;
    const challenge = document.getElementById('deployGroupChallenge').value.trim();
    if (!challenge) {
      info.style.background = '#fffbeb'; info.style.color = '#b7791f';
      info.textContent = 'Select a challenge above to check lane capacity.';
      return;
    }
    info.style.background = '#ebf8ff'; info.style.color = '#2b6cb0';
    info.textContent = `Will deploy ${numStudents} lanes (1 per student). Capacity checked on submit.`;
  }
}

function getGroupDeployParams() {
  return {
    group_name: document.getElementById('deployGroupName').value.trim(),
    num_instructors: document.getElementById('deployNumInstructors').value,
    num_students: document.getElementById('deployNumStudents').value,
    attack_boxes: document.getElementById('deployAttackBoxes').checked,
    challenge_key: document.getElementById('deployGroupChallenge').value.trim() || null,
    module: document.getElementById('deployGroupModule').value,
    deploy_lanes: document.getElementById('deployLanes').checked,
    use_webhook: document.getElementById('deployGroupUseWebhook').checked,
    vuln_scripts: getSelectedScripts('group-deploy-script')
  };
}

async function deployGroup() {
  const params = getGroupDeployParams();
  const status = document.getElementById('deployGroupStatus');
  const btn = document.getElementById('deployGroupBtn');

  if (!params.group_name) { Toast.warning('Missing', 'Group name is required'); return; }
  if (parseInt(params.num_students) < 1) { Toast.warning('Missing', 'At least 1 student required'); return; }
  if (params.deploy_lanes && !params.challenge_key) {
    Toast.warning('Missing', 'Challenge key is required when deploying lanes'); return;
  }

  // If deploying lanes, do pre-flight check first
  if (params.deploy_lanes) {
    btn.disabled = true;
    btn.textContent = 'Checking resources...';
    status.textContent = 'Running pre-flight resource check...';
    status.style.color = 'var(--gray-500)';

    try {
      const preview = await api('POST', '/deploy-group', params);
      if (preview.preview) {
        btn.disabled = false;
        btn.textContent = 'Deploy Group';
        status.textContent = '';
        showDeployConfirmation(preview, () => deployGroupConfirmed(params));
        return;
      }
      // If no preview (health check failed gracefully), treat as success
      handleDeployGroupSuccess(preview, status);
    } catch (e) {
      status.textContent = `Error: ${e.message}`;
      status.style.color = '#e53e3e';
      Toast.error('Deploy Failed', e.message);
      btn.disabled = false;
      btn.textContent = 'Deploy Group';
    }
    return;
  }

  // No lanes — deploy directly (no resource check needed for account-only)
  await deployGroupConfirmed(params);
}

async function deployGroupConfirmed(params) {
  const status = document.getElementById('deployGroupStatus');
  const btn = document.getElementById('deployGroupBtn');

  btn.disabled = true;
  btn.textContent = 'Deploying...';
  status.textContent = params.deploy_lanes
    ? 'Creating users, Guacamole resources, and deploying lanes...'
    : 'Creating users and Guacamole resources...';
  status.style.color = 'var(--gray-500)';

  try {
    const data = await api('POST', '/deploy-group', { ...params, confirm: true });
    handleDeployGroupSuccess(data, status);
  } catch (e) {
    status.textContent = `Error: ${e.message}`;
    status.style.color = '#e53e3e';
    Toast.error('Deploy Failed', e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Deploy Group';
  }
}

function handleDeployGroupSuccess(data, status) {
  // Build credentials table
  let credsHtml = '';
  if (data.credentials && data.credentials.length > 0) {
    credsHtml = `
      <div style="margin-top: 0.75rem; background: #fffbeb; border: 1px solid #f6e05e; border-radius: 8px; padding: 0.75rem;">
        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.5rem;">
          <strong style="font-size: 0.85rem; color: #b7791f;">Account Credentials (save these now!)</strong>
          <div style="display: flex; gap: 0.4rem;">
            <button class="btn btn-sm btn-outline" style="font-size: 0.7rem; padding: 0.15rem 0.4rem;" onclick="copyCredentials()">Copy All</button>
            <button class="btn btn-sm btn-outline" style="font-size: 0.7rem; padding: 0.15rem 0.4rem;" onclick="downloadCredentialsCSV()">Download CSV</button>
          </div>
        </div>
        <table class="admin-table" style="font-size: 0.8rem;">
          <thead><tr><th>Role</th><th>Email</th><th>Password</th></tr></thead>
          <tbody>
            ${data.credentials.map(c => `
              <tr>
                <td><span class="badge ${c.role === 'instructor' ? 'badge-blue' : 'badge-gray'}">${c.role}</span></td>
                <td><code>${escHtml(c.email)}</code></td>
                <td><code>${escHtml(c.password)}</code></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>`;
    // Store for copy/download
    window._lastCredentials = data.credentials;
  }

  status.innerHTML = `
    <strong style="color: #38a169;">Group created!</strong><br>
    ${data.instructors_created} instructors + ${data.students_created} students created<br>
    Guac users: ${data.guac_users_created} | Guac group: ${data.guac_group}
    ${credsHtml}
  `;

  const laneMsg = data.lanes_deploying > 0 ? `, ${data.lanes_deploying} lanes deploying` : '';
  Toast.success('Group Deployed', `${data.students_created} students + ${data.instructors_created} instructors${laneMsg}`);
  loadDeployedGroups();
  loadUsers();
  loadClusterHealth();

  // Start polling deployment progress if lanes are deploying
  if (data.lanes_deploying > 0 && data.group_id) {
    startDeployProgressPoll(data.group_id, data.lanes_deploying, status);
    loadLanes();
  }
}

function startDeployProgressPoll(groupId, totalLanes, statusEl) {
  const progressDiv = document.createElement('div');
  progressDiv.id = 'deployProgressTracker';
  progressDiv.style.cssText = 'margin-top: 0.75rem; background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 0.75rem;';
  statusEl.parentNode.insertBefore(progressDiv, statusEl.nextSibling);

  // Live state — updated by polls, ticked every second
  const state = {
    total: totalLanes, completed: 0, succeeded: 0, failed: 0,
    phase: 'preparing', elapsed_s: 0, eta_s: null, avg_lane_s: null,
    _lastPollTime: Date.now(), _done: false
  };

  function render() {
    const succeededPct = state.total > 0 ? Math.round((state.succeeded / state.total) * 100) : 0;
    const failedPct = state.total > 0 ? Math.round((state.failed / state.total) * 100) : 0;

    const phaseLabels = {
      preparing: 'Preparing',
      gateway_replication: 'Replicating Gateways',
      gateway_cloning: 'Cloning Gateways',
      deploying: 'Deploying VMs',
      complete: 'Complete'
    };
    const phaseLabel = phaseLabels[state.phase] || state.phase || 'Preparing';

    const etaHtml = (state.phase !== 'complete' && state.eta_s != null && state.eta_s > 0)
      ? `<span style="color: var(--gray-500); font-size: 0.8rem;"> — ETA: ${formatTime(state.eta_s)}</span>`
      : '';

    const elapsedHtml = state.elapsed_s != null
      ? `<span style="color: var(--gray-500); font-size: 0.75rem;">Elapsed: ${formatTime(state.elapsed_s)}</span>`
      : '';

    const avgHtml = state.avg_lane_s != null
      ? ` <span style="color: var(--gray-500); font-size: 0.75rem;">| Avg/lane: ${state.avg_lane_s}s</span>`
      : '';

    progressDiv.innerHTML = `
      <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.5rem;">
        <strong style="font-size: 0.85rem;">
          ${state.phase === 'complete' ? '&#10003;' : '&#9881;'} ${phaseLabel}${etaHtml}
        </strong>
        <span style="font-size: 0.85rem; font-weight: 600;">${state.completed}/${state.total} lanes</span>
      </div>
      <div style="background: var(--border); border-radius: 4px; height: 20px; overflow: hidden; margin-bottom: 0.4rem;">
        <div style="display: flex; height: 100%;">
          <div style="width: ${succeededPct}%; background: #38a169; transition: width 0.3s;"></div>
          <div style="width: ${failedPct}%; background: #e53e3e; transition: width 0.3s;"></div>
        </div>
      </div>
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <span style="font-size: 0.75rem;">
          <span style="color: #38a169; font-weight: 600;">${state.succeeded} succeeded</span>
          ${state.failed > 0 ? `<span style="color: #e53e3e; font-weight: 600; margin-left: 0.5rem;">${state.failed} failed</span>` : ''}
        </span>
        <span>${elapsedHtml}${avgHtml}</span>
      </div>
    `;

    if (state.phase === 'complete') {
      progressDiv.style.borderColor = state.failed > 0 ? '#e53e3e' : '#38a169';
    }
  }

  // Tick every second — increment elapsed, decrement ETA
  const tickInterval = setInterval(() => {
    if (state._done) return;
    state.elapsed_s++;
    if (state.eta_s != null && state.eta_s > 0) state.eta_s--;
    render();
  }, 1000);

  // Poll server every 2 seconds for actual progress
  const pollInterval = setInterval(async () => {
    try {
      const p = await api('GET', `/deploy-group/${groupId}/progress`);
      // Sync state from server (authoritative values)
      state.total = p.total;
      state.completed = p.completed;
      state.succeeded = p.succeeded;
      state.failed = p.failed;
      state.phase = p.phase;
      state.avg_lane_s = p.avg_lane_s;
      // Use server elapsed/eta as ground truth, tick interpolates between polls
      if (p.elapsed_s != null) state.elapsed_s = p.elapsed_s;
      if (p.eta_s != null) state.eta_s = p.eta_s;
      state._lastPollTime = Date.now();
      render();

      if (p.phase === 'complete' || p.completed >= p.total) {
        state._done = true;
        clearInterval(pollInterval);
        clearInterval(tickInterval);
        render();
        loadLanes();
        loadClusterHealth();
        if (p.failed > 0) {
          Toast.warning('Deployment Finished', `${p.succeeded}/${p.total} lanes deployed, ${p.failed} failed`);
        } else {
          Toast.success('Deployment Complete', `All ${p.succeeded} lanes deployed successfully`);
        }
      }
    } catch (e) {
      state._done = true;
      clearInterval(pollInterval);
      clearInterval(tickInterval);
    }
  }, 2000);

  // Initial render
  render();
}

function copyCredentials() {
  const creds = window._lastCredentials;
  if (!creds) return;
  const text = creds.map(c => `${c.role}\t${c.email}\t${c.password}`).join('\n');
  navigator.clipboard.writeText(`Role\tEmail\tPassword\n${text}`).then(() => {
    Toast.success('Copied', 'Credentials copied to clipboard');
  });
}

function downloadCredentialsCSV() {
  const creds = window._lastCredentials;
  if (!creds) return;
  const csv = 'Role,Email,Password\n' + creds.map(c =>
    `${c.role},"${c.email}","${c.password}"`
  ).join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `credentials-${Date.now()}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

function downloadGroupCredCSV(groupId) {
  api('GET', '/groups').then(groups => {
    const g = groups.find(x => x.id === groupId);
    if (!g) return;
    const cfg = typeof g.config === 'string' ? JSON.parse(g.config) : g.config;
    if (!cfg.credentials?.length) { Toast.warning('No Credentials', 'No stored credentials for this group'); return; }
    const csv = 'Role,Email,Password\n' + cfg.credentials.map(c =>
      `${c.role},"${c.email}","${c.password}"`
    ).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${g.group_name}-credentials.csv`;
    a.click();
    URL.revokeObjectURL(url);
  });
}

async function loadDeployedGroups() {
  const container = document.getElementById('deployedGroupsList');
  if (!container) return;
  container.innerHTML = '<p style="color: var(--gray-500);">Loading...</p>';

  try {
    const groups = await api('GET', '/groups');

    if (groups.length === 0) {
      container.innerHTML = '<div style="background: white; border-radius: 12px; padding: 2rem; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.08); color: var(--gray-500);">No deployed groups yet.</div>';
      return;
    }

    container.innerHTML = `
      <table class="admin-table">
        <thead><tr>
          <th>Group Name</th>
          <th>Instructors</th>
          <th>Students</th>
          <th>Guac Users</th>
          <th>Created</th>
          <th>Actions</th>
        </tr></thead>
        <tbody>
          ${groups.map(g => {
            const cfg = typeof g.config === 'string' ? JSON.parse(g.config) : g.config;
            return `
              <tr>
                <td><strong>${escHtml(g.group_name)}</strong></td>
                <td>${(cfg.instructors || []).length}</td>
                <td>${(cfg.students || []).length}</td>
                <td>${(cfg.guac_users || []).length}</td>
                <td>${new Date(g.created_at).toLocaleDateString()}</td>
                <td style="display: flex; gap: 0.4rem;">
                  <button class="btn btn-sm btn-outline" style="font-size: 0.75rem; padding: 0.2rem 0.5rem;" onclick="viewGroupDetails('${g.id}')">Details</button>
                  <button class="btn btn-sm" style="font-size: 0.75rem; padding: 0.2rem 0.5rem; border: 1px solid #e53e3e; color: #e53e3e; background: transparent;" data-group-id="${g.id}" data-group-name="${escHtml(g.group_name)}" onclick="teardownGroup(this.dataset.groupId, this.dataset.groupName)">Teardown</button>
                </td>
              </tr>`;
          }).join('')}
        </tbody>
      </table>`;
  } catch (e) {
    container.innerHTML = `<p style="color: #e53e3e;">Error: ${e.message}</p>`;
  }
}

async function teardownGroup(groupId, groupName) {
  if (!confirm(`TEARDOWN "${groupName}"?\n\nThis will DELETE all student/instructor accounts (both clinic DB and Guacamole) and the Guac connection group.\n\nThis cannot be undone.`)) return;

  try {
    const data = await api('DELETE', `/groups/${groupId}`);
    Toast.success('Group Torn Down', `${data.users_deleted} users deleted`);
    if (data.errors) {
      console.warn('Teardown partial errors:', data.errors);
    }
    loadDeployedGroups();
    loadUsers();
  } catch (e) {
    Toast.error('Teardown Failed', e.message);
  }
}

function viewGroupDetails(groupId) {
  // Fetch from the loaded groups list
  api('GET', '/groups').then(groups => {
    const g = groups.find(x => x.id === groupId);
    if (!g) return;
    const cfg = typeof g.config === 'string' ? JSON.parse(g.config) : g.config;

    const body = document.getElementById('permissionsBody');
    document.getElementById('permUsername').textContent = g.group_name;

    let html = `<p style="margin: 0 0 1rem; font-size: 0.85rem; color: var(--gray-500);">Created: ${new Date(g.created_at).toLocaleString()}</p>`;

    // Build a credential lookup map
    const credMap = {};
    if (cfg.credentials) {
      cfg.credentials.forEach(c => { credMap[c.email] = c.password; });
    }

    if (cfg.instructors?.length) {
      html += `<h4 style="margin: 0 0 0.5rem;">Instructors (${cfg.instructors.length})</h4>`;
      html += `<table class="admin-table" style="font-size: 0.85rem; margin-bottom: 1rem;">
        <thead><tr><th>Name</th><th>Email / Login</th><th>Password</th></tr></thead>
        <tbody>${cfg.instructors.map(u =>
          `<tr><td>${escHtml(u.name)}</td><td><code style="font-size: 0.8rem;">${escHtml(u.email)}</code></td><td><code style="font-size: 0.8rem;">${escHtml(credMap[u.email] || 'N/A')}</code></td></tr>`
        ).join('')}</tbody></table>`;
    }

    if (cfg.students?.length) {
      html += `<h4 style="margin: 0 0 0.5rem;">Students (${cfg.students.length})</h4>`;
      html += `<table class="admin-table" style="font-size: 0.85rem;">
        <thead><tr><th>Name</th><th>Email / Login</th><th>Password</th></tr></thead>
        <tbody>${cfg.students.map(u =>
          `<tr><td>${escHtml(u.name)}</td><td><code style="font-size: 0.8rem;">${escHtml(u.email)}</code></td><td><code style="font-size: 0.8rem;">${escHtml(credMap[u.email] || 'N/A')}</code></td></tr>`
        ).join('')}</tbody></table>`;
    }

    if (cfg.credentials?.length) {
      html += `<div style="margin-top: 0.75rem;"><button class="btn btn-sm btn-outline" onclick="downloadGroupCredCSV('${g.id}')">Download Credentials CSV</button></div>`;
    }

    body.innerHTML = html;
    document.getElementById('permissionsModal').classList.add('active');
  });
}

// ── Module & Challenge Dropdowns ──

async function loadModulesAndChallenges() {
  try {
    const modules = await api('GET', '/modules');

    // Pre-check which modules actually have challenges
    const modulesWithChallenges = [];
    for (const m of modules) {
      try {
        const challenges = await api('GET', `/challenges/${m.key}`);
        cachedChallenges[m.key] = challenges;
        if (challenges.length > 0) modulesWithChallenges.push(m);
      } catch (_) {
        // Module has no challenge table — skip it
      }
    }

    const selects = ['deployModule', 'deployGroupModule'];
    selects.forEach(selId => {
      const sel = document.getElementById(selId);
      if (!sel) return;
      sel.innerHTML = '';
      if (modulesWithChallenges.length === 0) {
        sel.innerHTML = '<option value="">No modules with challenges</option>';
        return;
      }
      modulesWithChallenges.forEach(m => {
        const opt = document.createElement('option');
        opt.value = m.key;
        opt.textContent = m.name || m.key;
        sel.appendChild(opt);
      });
      const challengeSelId = selId === 'deployModule' ? 'deployChallengeKey' : 'deployGroupChallenge';
      loadChallengesForSelect(selId, challengeSelId);
    });
  } catch (e) {
    console.error('Failed to load modules:', e);
    ['deployModule', 'deployGroupModule'].forEach(id => {
      const sel = document.getElementById(id);
      if (sel) sel.innerHTML = '<option value="crucible">Crucible (default)</option>';
    });
  }
}

async function loadChallengesForSelect(moduleSelId, challengeSelId) {
  const moduleSel = document.getElementById(moduleSelId);
  const challengeSel = document.getElementById(challengeSelId);
  if (!moduleSel || !challengeSel) return;

  const moduleKey = moduleSel.value;
  if (!moduleKey) {
    challengeSel.innerHTML = '<option value="">Select a module first...</option>';
    return;
  }

  // Check cache first
  if (cachedChallenges[moduleKey]) {
    populateChallengeSelect(challengeSel, cachedChallenges[moduleKey], challengeSelId === 'deployGroupChallenge');
    return;
  }

  challengeSel.innerHTML = '<option value="">Loading challenges...</option>';

  try {
    const challenges = await api('GET', `/challenges/${moduleKey}`);
    cachedChallenges[moduleKey] = challenges;
    populateChallengeSelect(challengeSel, challenges, challengeSelId === 'deployGroupChallenge');
  } catch (e) {
    console.error('Failed to load challenges:', e);
    challengeSel.innerHTML = '<option value="">Failed to load challenges</option>';
  }
}

function populateChallengeSelect(sel, challenges, allowEmpty) {
  sel.innerHTML = '';
  if (allowEmpty) {
    const emptyOpt = document.createElement('option');
    emptyOpt.value = '';
    emptyOpt.textContent = '— None (accounts only) —';
    sel.appendChild(emptyOpt);
  }
  if (challenges.length === 0) {
    const opt = document.createElement('option');
    opt.value = '';
    opt.textContent = 'No active challenges found';
    sel.appendChild(opt);
    return;
  }
  challenges.forEach(c => {
    const opt = document.createElement('option');
    opt.value = c.challenge_key;
    opt.textContent = `${c.name} (${c.challenge_key})${c.difficulty ? ' — Difficulty ' + c.difficulty : ''}`;
    sel.appendChild(opt);
  });
}
