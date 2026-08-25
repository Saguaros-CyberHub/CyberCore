const express = require('express');
const router = express.Router();
const { cybercoreQuery } = require('../utils/cybercore-db');
const { optionalAuth } = require('../middleware/auth');
const moduleLoader = require('../module-loader');

// GET /api/modules — list all active modules grouped by category
//
// optionalAuth, NOT authenticateToken. The payload is module names and subnav
// labels, not secrets, and requiring a token would break the pre-login shell and
// module-placeholder.html. optionalAuth reads the session cookie as well as the
// Authorization header, so a plain browser navigation is authenticated here.
//
// The auth matters because some modules are not for everyone: Clinic-in-a-Box is
// only for students an instructor enrolled, so it is filtered out server-side
// rather than hidden by the client. A client-side probe could only remove the
// entry AFTER it had already painted, which is precisely what the fail-closed
// comment in layout.js isEntryVisible() exists to prevent for role gating.
router.get('/', optionalAuth, async (req, res) => {
  try {
    const result = await cybercoreQuery(
      // display_order is selected as well as sorted on: the sidebar merges
      // modules and plugins into one list client-side and re-sorts by it.
      `SELECT key, name, icon, description, entry_url, category, color, display_order
       FROM cybercore_module
       WHERE active = TRUE
       ORDER BY display_order, name`
    );

    const gates = moduleLoader.getAccessGates();

    // Evaluated concurrently: a gate is a small indexed lookup, and running
    // them in series would add one round trip per gated module to every page
    // load in the app.
    const allowed = new Set();
    await Promise.all(result.rows.map(async (row) => {
      const gate = gates.get(row.key);
      if (!gate) { allowed.add(row.key); return; }
      try {
        if (await gate(req)) allowed.add(row.key);
      } catch (err) {
        // FAIL CLOSED. A gate that cannot answer must not advertise the module
        // it guards; the module's own routes will refuse the click anyway, so
        // showing it would only produce a menu entry that leads to a 403.
        console.warn(`[modules] access gate for ${row.key} failed: ${err.message}`);
      }
    }));

    const visible = result.rows.filter((r) => allowed.has(r.key));

    // Subnav configs from loaded modules (includes nested plugins), filtered by
    // the same decision. A hidden module whose submenu still shipped would hand
    // its URLs to exactly the people it was hidden from.
    const allSubnavs = moduleLoader.getAllSubnavs();
    const subnavs = {};
    for (const [key, value] of Object.entries(allSubnavs)) {
      if (!gates.has(key) || allowed.has(key)) subnavs[key] = value;
    }

    res.json({
      modules: visible.filter((r) => r.category === 'module'),
      plugins: visible.filter((r) => r.category === 'plugin'),
      subnavs,
    });
  } catch (error) {
    console.error('Error fetching modules:', error.message);
    res.status(500).json({ error: 'Failed to fetch modules' });
  }
});

module.exports = router;
