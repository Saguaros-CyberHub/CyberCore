// ============================================================================
// INIT
// ============================================================================

async function refreshAll() {
  checkProxmoxStatus();
  const online = await checkGuacStatus();
  if (online) {
    loadConnections();
    loadActiveSessions();
  }
  loadDeployedGroups();
  loadLanes();
  loadModulesAndChallenges();
  loadClusterHealth();
  setInterval(loadClusterHealth, 15000);
  loadMergedUsers();
  loadChallengeTemplates();
  loadWorkstationTemplates();
  loadVulnScripts();
}

document.addEventListener('DOMContentLoaded', async () => {
  // Wait for Auth.check() to populate user from /api/auth/me
  const loggedIn = await Auth.requireAuth();
  if (!loggedIn) return;

  const user = Auth.getUser();
  if (!user || user.role !== 'admin') {
    document.querySelector('.page-content').innerHTML = `
      <div style="text-align: center; padding: 4rem;">
        <div style="font-size: 3rem; margin-bottom: 1rem;">🔒</div>
        <h2>Access Denied</h2>
        <p style="color: var(--gray-500);">This page is restricted to administrators.</p>
        <a href="/hub" class="btn btn-primary" style="margin-top: 1rem;">Back to Dashboard</a>
      </div>`;
    return;
  }

  // Load site settings to update page title
  await loadSiteSettings();

  refreshAll();

  // Load real-client intake context if ?from_intake_id=… is present.
  loadIntakeContextFromQuery();

  // Load modules on page initialization
  loadModules();
});
