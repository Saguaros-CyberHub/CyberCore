# Plugin System - Quick Start

## What Was Built

Your CyberHub platform now has a complete, production-ready plugin system! 🎉

### 5 Core Components

1. **PluginManager** - Discovers, loads, and manages plugins
2. **Enhanced RouteLoader** - Dynamically registers plugin routes
3. **Lifecycle Hooks** - onEnable, onDisable, onInit events
4. **CLI Commands** - npm run plugin:list/enable/disable
5. **Example Plugin** - Working template to build from

---

## Try It Now

```bash
# 1. List plugins (shows example/demo-plugin is enabled)
npm run plugin:list

# 2. Check plugin status
# Output shows:
# ✅ example/demo-plugin@1.0.0

# 3. Test the example plugin
curl http://localhost:3000/api/example/demo-plugin/info

# 4. Disable plugin
npm run plugin:disable example/demo-plugin

# 5. The plugin routes now return 404

# 6. Re-enable it
npm run plugin:enable example/demo-plugin
```

---

## Create Your First Plugin (2 Minutes)

```bash
# 1️⃣  Create directory
mkdir -p src/installed-plugins/crucible-plugins/my-plugin/routes

# 2️⃣  Create manifest.json
cat > src/installed-plugins/crucible-plugins/my-plugin/manifest.json <<'EOF'
{
  "name": "my-plugin",
  "version": "1.0.0",
  "description": "My first plugin",
  "module": "crucible",
  "enabled": true
}
EOF

# 3️⃣  Create routes/index.js
cat > src/installed-plugins/crucible-plugins/my-plugin/routes/index.js <<'EOF'
const express = require('express');
const router = express.Router();
const { authenticateToken } = require('../../../core/middleware/auth');

router.get('/', authenticateToken, (req, res) => {
  res.json({ 
    success: true, 
    message: 'My plugin works!',
    userId: req.user.userId 
  });
});

module.exports = router;
EOF

# 4️⃣  Restart server
npm start

# 5️⃣  Test it
curl http://localhost:3000/api/crucible/my-plugin/
```

That's it! Routes auto-discovered and available immediately.

---

## Plugin Structure

### Minimal (Required)
```
src/installed-plugins/[module]-plugins/[plugin-name]/
├── routes/index.js          # Express router
└── manifest.json            # Plugin metadata
```

### Full-Featured (Recommended)
```
src/installed-plugins/[module]-plugins/[plugin-name]/
├── routes/index.js          # Express router
├── services/data.js         # Business logic
├── hooks.js                 # Lifecycle hooks
├── migrations/001_init.sql  # Database schema
├── manifest.json            # Metadata
└── README.md                # Documentation
```

---

## Key Features

✅ **Auto-Discovery** - Drop a plugin in and it loads  
✅ **Manifest-Driven** - Control enable/disable via manifest.json  
✅ **Smart Routes** - Only load routes from enabled plugins  
✅ **Lifecycle Hooks** - onEnable, onDisable, onInit  
✅ **CLI Management** - npm run plugin:list/enable/disable  
✅ **No Restarts** - Enable/disable without restarting  
✅ **Best Practices** - Separation of concerns built-in  
✅ **Security** - Authentication middleware available  

---

## Documentation

Complete guides available:

1. **docs/PLUGIN_GUIDE.md** ← Start here!
   - Complete development guide
   - Templates for all components
   - 10+ best practices
   - API reference
   - Troubleshooting

2. **src/installed-plugins/example-plugins/demo-plugin/**
   - Working example plugin
   - Copy to start new plugin
   - Shows all patterns

3. **PLUGIN_SYSTEM_SUMMARY.md**
   - Architecture overview
   - Implementation details
   - Design decisions

---

## Plugin Commands

```bash
# List all plugins with status
npm run plugin:list

# Enable a plugin (updates manifest)
npm run plugin:enable [module]/[plugin-name]
npm run plugin:enable crucible/my-plugin

# Disable a plugin (updates manifest)
npm run plugin:disable [module]/[plugin-name]
npm run plugin:disable example/demo-plugin
```

---

## Example: Real Plugin Checklist

```bash
# ✅ Create directory
mkdir -p src/installed-plugins/crucible-plugins/my-feature/routes
mkdir -p src/installed-plugins/crucible-plugins/my-feature/services

# ✅ Create manifest.json
# See docs/PLUGIN_GUIDE.md for template

# ✅ Create routes/index.js
# Export Express router

# ✅ Create services/data.js (optional)
# Business logic here

# ✅ Create hooks.js (optional)
# Lifecycle events

# ✅ Create migrations/ (optional)
# Database schema if needed

# ✅ Test routes
curl http://localhost:3000/api/crucible/my-feature/

# ✅ Enable/disable with
npm run plugin:enable crucible/my-feature
npm run plugin:disable crucible/my-feature
```

---

## Files Created/Modified

### New Files
- `src/core/PluginManager.js` - Plugin orchestrator
- `scripts/plugin/list.js` - List plugins
- `scripts/plugin/enable.js` - Enable plugin
- `scripts/plugin/disable.js` - Disable plugin
- `src/installed-plugins/example-plugins/demo-plugin/` - Example plugin
- `docs/PLUGIN_GUIDE.md` - Complete guide
- `PLUGIN_SYSTEM_SUMMARY.md` - Implementation summary

### Modified Files
- `src/server.js` - Added PluginManager
- `src/core/RouteLoader.js` - Enhanced for manifest support
- `package.json` - Added plugin scripts & updated name

---

## Testing

```bash
# Run the existing test
node test-plugins.js

# Output shows:
# ✅ Found plugin: example/demo-plugin (v1.0.0)
# ✅ Plugin system initialized: 1 plugin(s) found
```

---

## Next Steps

1. **Read** `docs/PLUGIN_GUIDE.md` - Complete reference
2. **Explore** `src/installed-plugins/example-plugins/demo-plugin/` - Working example
3. **Create** your first plugin using the template
4. **Copy** existing plugins (crucible, cyberlabs, forge) and convert to plugin format
5. **Share** your plugins with the community!

---

## Architecture at a Glance

```
┌─────────────────────────────────────────┐
│         Server Startup                  │
├─────────────────────────────────────────┤
│  1. PluginManager.init()                │
│     ├─ Scan installed-plugins/          │
│     ├─ Read manifest.json files         │
│     └─ Load enabled plugins             │
│                                         │
│  2. RouteLoader.loadAll()               │
│     ├─ Load core routes                 │
│     ├─ Load module routes               │
│     └─ Load ENABLED plugin routes       │
│                                         │
│  3. Server Ready                        │
│     ├─ Routes at /api/[module]/[name]   │
│     └─ CLI commands available           │
└─────────────────────────────────────────┘
```

---

## Key Commands to Remember

```bash
# Run the app
npm start

# List plugins
npm run plugin:list

# Manage plugins
npm run plugin:enable crucible/my-plugin
npm run plugin:disable crucible/my-plugin

# Test plugin system
node test-plugins.js
```

---

**You're all set! Build amazing plugins! 🚀**

See `docs/PLUGIN_GUIDE.md` for the complete reference.
