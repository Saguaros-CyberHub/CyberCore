# CyberHub Module & Plugin Guide

CyberHub's Express app ([front-end/src/server.js](../front-end/src/server.js)) discovers its feature areas at boot via [front-end/src/module-loader.js](../front-end/src/module-loader.js) — there is no separate plugin framework, CLI, or `src/core/` package. This doc describes that loader as it actually behaves.

There are two levels:

- **Modules** — top-level feature areas under [front-end/modules/](../front-end/modules/) (`crucible`, `cyberlabs`, `forge`, `library`, `university`, `cyberwiki`, `archive`).
- **Plugins** — nested under a module's own `plugins/` subdirectory, e.g. [front-end/modules/crucible/plugins/ciab/](../front-end/modules/crucible/plugins/ciab/) and `.../crucible/plugins/cle/`. Structurally identical to modules, just discovered one level deeper and tagged with `parent_module`.

## How discovery works

On every app start, `module-loader.js`:

1. Reads every directory in `front-end/modules/`. Each one **must** have a `manifest.json` or it's skipped with a warning.
2. If the manifest has a `database` block, provisions that database (creates it if missing, runs `migrations/*.sql` in filename order, then calls `setPool()` on `utils/db.js` inside that module/plugin if it exports one).
3. Upserts the manifest into the `cybercore_module` table (drives the sidebar and `GET /api/modules`).
4. Mounts each entry in `routes[]` at its `mountPath` with `app.use(...)`.
5. Serves `staticDir` at `staticMountPath` if present.
6. Recurses into `<module>/plugins/*/manifest.json` and repeats steps 2–5 for each plugin, setting `parent_module` to the owning module's directory name.

**There is no enable/disable switch, no CLI, and no hot reload.** `manifest.active` only sets the `active` column in `cybercore_module` (used to hide/show things in the UI) — routes are mounted unconditionally at startup regardless of that flag. To actually remove a module or plugin's routes, delete or rename its directory and restart the app.

## manifest.json reference

Fields actually read by the loader (see real examples: [modules/crucible/manifest.json](../front-end/modules/crucible/manifest.json), [modules/crucible/plugins/ciab/manifest.json](../front-end/modules/crucible/plugins/ciab/manifest.json)):

```jsonc
{
  "key": "my-plugin",            // unique; primary key in cybercore_module
  "name": "My Plugin",
  "icon": "🔌",                   // emoji shown in sidebar
  "description": "One-line description shown in the module grid",
  "entry_url": "/my-plugin/dashboard",
  "category": "plugin",          // "module" for top-level modules, "plugin" for nested ones
  "color": "#48bb78",
  "active": true,
  "display_order": 10,
  // "parent_module" is set automatically by the loader for plugins — don't set it by hand

  "routes": [
    { "file": "routes/pages.js", "mountPath": "/my-plugin" },
    { "file": "routes/api.js",   "mountPath": "/" }
  ],

  "staticDir": "public",
  "staticMountPath": "/my-plugin",

  "database": {                  // omit entirely if you don't need your own DB
    "name": "my_plugin_db",
    "migrations": "migrations"
  },

  "subnav": {
    "label": "My Plugin",
    "items": [
      { "label": "Dashboard", "icon": "📊", "url": "/my-plugin/dashboard", "page": "dashboard" },
      { "label": "Admin",     "icon": "🚀", "url": "/my-plugin/admin",    "page": "admin", "roles": ["admin"] }
    ]
  }
}
```

Notes:
- `routes[].mountPath` is whatever you pass to `app.use()` — mount API routes at `/` and let the router itself define paths like `/api/my-plugin/...`, or mount at a prefix directly. Look at an existing plugin's `routes/api.js` for the convention it uses.
- `subnav.items[].roles` is enforced by the frontend sidebar renderer, not the loader — always also gate the actual route handlers server-side with `requireRole`.
- Each module/plugin gets its own real Postgres **database** if it declares one (not just a table prefix) — e.g. the Crucible `ciab` plugin owns `clinic_db`, `cle` owns `cle_db`. Core platform tables (`cybercore_user`, `cybercore_module`, etc.) live in `cybercore_db`; see the main [README](../README.md#database-schema-overview).

## Creating a new module

```bash
mkdir -p front-end/modules/my-module/routes
```

`front-end/modules/my-module/manifest.json` (minimal):

```json
{
  "key": "my-module",
  "name": "My Module",
  "category": "module",
  "active": true,
  "routes": [
    { "file": "routes/pages.js", "mountPath": "/my-module" }
  ]
}
```

`front-end/modules/my-module/routes/pages.js`:

```javascript
const express = require('express');
const router = express.Router();
const { authenticateToken, requireRole } = require('../../../src/middleware/auth');

router.get('/dashboard', authenticateToken, (req, res) => {
  res.json({ success: true, userId: req.user.userId });
});

router.get('/admin', authenticateToken, requireRole('admin'), (req, res) => {
  res.json({ success: true });
});

module.exports = router;
```

Restart the app (`npm start` / restart the `cybercore-app` container) — there's no hot reload, the loader only runs at startup.

## Creating a new plugin (nested under an existing module)

Same shape, one level deeper, e.g. under `crucible`:

```bash
mkdir -p front-end/modules/crucible/plugins/my-plugin/routes
```

`front-end/modules/crucible/plugins/my-plugin/manifest.json`:

```json
{
  "key": "my-plugin",
  "name": "My Plugin",
  "category": "plugin",
  "active": true,
  "routes": [
    { "file": "routes/api.js", "mountPath": "/api/crucible/my-plugin" }
  ]
}
```

`front-end/modules/crucible/plugins/my-plugin/routes/api.js` — note the middleware path is one level deeper than a top-level module (`routes/` → plugin dir → `plugins/` → module dir → `modules/` → `front-end/`, so five `../`):

```javascript
const express = require('express');
const router = express.Router();
const { authenticateToken } = require('../../../../../src/middleware/auth');

router.get('/', authenticateToken, async (req, res) => {
  res.json({ success: true, message: 'Plugin is working!', userId: req.user.userId });
});

module.exports = router;
```

## Middleware & utils available to routes

```javascript
// front-end/src/middleware/auth.js
const { authenticateToken, requireRole, optionalAuth } = require('.../src/middleware/auth');

// front-end/src/middleware/errorHandler.js
const { asyncHandler } = require('.../src/middleware/errorHandler');

// front-end/src/middleware/activity-logger.js
const { logActivity } = require('.../src/middleware/activity-logger');

// front-end/src/utils/db.js — cybercore_db pool (core tables)
const { query } = require('.../src/utils/db');

// front-end/src/utils/cybercore-db.js — same pool, used internally by the loader
```

If your module/plugin has its own database, give it a local `utils/db.js` that exports a `setPool(pool)` function — the loader calls it automatically after running migrations, and your routes/services can then import that local `db.js` to query their own database instead of `cybercore_db`. See [modules/crucible/plugins/ciab/utils/db.js](../front-end/modules/crucible/plugins/ciab/utils/db.js) for a real example.

## Best practices

- Keep route handlers thin — push queries into a module/plugin-local `services/` or `utils/` file.
- Always gate protected routes with `authenticateToken`, and admin/instructor-only routes with `requireRole(...)`.
- Use parameterized queries (`query('... WHERE id = $1', [id])`) — never string-interpolate into SQL.
- Namespace your own tables/database by module or plugin key to avoid collisions with core `cybercore_*` tables.
- Don't hardcode secrets — read from `process.env` and document new variables in [example.env](../example.env).
