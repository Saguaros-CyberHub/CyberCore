/**
 * ============================================================================
 * Public site configuration
 * ----------------------------------------------------------------------------
 * Unauthenticated branding read: site name, logo, favicon, description, and
 * whether self-registration is on. Every page in the product asks for this at
 * GET /api/site-config -- login.html, register.html, activate.html, hub.html,
 * module-placeholder.html and Layout.loadSiteBranding() in public/js/layout.js.
 *
 * It used to live inside routes/admin/settings.js, which server.js mounts at
 * '/api/admin', so the handler's real address was /api/admin/site-config and
 * every one of those callers 404'd. The failure was completely silent: each
 * caller guards on `response.ok`, so the page simply kept its hard-coded
 * defaults. That is why a configured site name, logo and description never
 * appeared anywhere, and why an admin who had once loaded the admin console
 * stayed stuck on the cached "<name> Administration" -- the fetch that would
 * have corrected it never returned a body.
 *
 * Mounted at '/api' in the CORE block of server.js. It must stay there: the
 * CIAB plugin mounts at '/' with an /api catch-all, and core routes survive
 * only by being registered before moduleLoader.loadAll().
 *
 * routes/admin/settings.js also mounts this router, so /api/admin/site-config
 * keeps answering for anything already pointed at it.
 * ============================================================================
 */

const express = require('express');
const router = express.Router();
const { cybercoreQuery } = require('../utils/cybercore-db');

router.get('/site-config', async (req, res) => {
  try {
    const siteConfig = {
      site_name: 'CyberHub',
      site_logo_url: null,
      site_favicon_url: null,
      site_description: null,
      // Lets the sign-in and registration pages stop offering something the API
      // will refuse. Read from env, not the settings table: it gates a route, and
      // a route's availability should not depend on a row anyone with the admin
      // console can edit. Authoritative check stays in POST /api/auth/register.
      self_registration_enabled: process.env.ALLOW_SELF_REGISTRATION === 'true'
    };

    try {
      const result = await cybercoreQuery('SELECT key, value FROM cybercore_site_settings');
      result.rows.forEach(row => {
        if (row.key === 'site_name') siteConfig.site_name = row.value;
        if (row.key === 'site_logo_url') siteConfig.site_logo_url = row.value;
        if (row.key === 'site_favicon_url') siteConfig.site_favicon_url = row.value;
        if (row.key === 'site_description') siteConfig.site_description = row.value;
      });
    } catch (err) {
      console.warn('[Site Config] Could not fetch settings:', err.message);
    }

    res.json(siteConfig);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
