# CyberHub Plugin Development Guide

This guide covers how to create, develop, and deploy plugins for the CyberHub platform.

## Quick Start: 5-Minute Plugin

```bash
# 1. Create your plugin directory
mkdir -p src/installed-plugins/[module]-plugins/[plugin-name]

# 2. Create required files
mkdir -p src/installed-plugins/[module]-plugins/[plugin-name]/routes
mkdir -p src/installed-plugins/[module]-plugins/[plugin-name]/services

# 3. Create manifest.json
# See template below

# 4. Create routes/index.js
# See template below

# 5. Restart the server
npm start

# 6. Your plugin routes are now available at:
# /api/[module]/[plugin-name]
```

---

## Plugin Structure

### Minimal Plugin (Required)

```
src/installed-plugins/[module]-plugins/[plugin-name]/
├── routes/
│   └── index.js           # Express router (REQUIRED)
└── manifest.json          # Plugin metadata (REQUIRED)
```

### Full-Featured Plugin (Recommended)

```
src/installed-plugins/[module]-plugins/[plugin-name]/
├── routes/
│   └── index.js           # Express router
├── services/
│   ├── data.js            # Database operations
│   ├── validation.js      # Input validation
│   └── helpers.js         # Utility functions
├── ui/
│   ├── pages/
│   │   └── page.html
│   ├── css/
│   │   └── styles.css
│   └── js/
│       └── app.js
├── migrations/
│   └── 001_init.sql       # Database schema
├── hooks.js               # Lifecycle hooks
├── manifest.json          # Plugin metadata
└── README.md              # Documentation
```

---

## File Templates

### 1. manifest.json

```json
{
  "name": "my-plugin",
  "version": "1.0.0",
  "description": "My awesome plugin",
  "author": "Your Name",
  "module": "crucible",
  "enabled": true,
  
  "homepage": "https://github.com/yourusername/my-plugin",
  
  "routes": {
    "basePath": "/api/crucible/my-plugin",
    "description": "Plugin routes automatically prefixed"
  },
  
  "ui": {
    "pages": [
      { "path": "/my-page", "file": "ui/pages/my-page.html" }
    ],
    "description": "Frontend pages served by the plugin"
  },
  
  "hooks": [
    "onEnable",
    "onDisable",
    "onInit"
  ],
  
  "dependencies": {
    "core": ">=1.0.0"
  },
  
  "config": {
    "debug": false,
    "timeout": 30000
  },
  
  "keywords": [
    "crucible",
    "assessment"
  ]
}
```

### 2. routes/index.js (Minimal)

```javascript
const express = require('express');
const router = express.Router();
const { authenticateToken } = require('../../../core/middleware/auth');

/**
 * GET /api/[module]/[plugin-name]/
 */
router.get('/', authenticateToken, async (req, res) => {
  try {
    res.json({
      success: true,
      message: 'Plugin is working!',
      userId: req.user.userId
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
```

### 3. routes/index.js (Full Example)

```javascript
const express = require('express');
const router = express.Router();
const { authenticateToken, requireRole } = require('../../../core/middleware/auth');
const { getData, saveData } = require('../services/data');
const { validate } = require('../services/validation');

/**
 * GET /api/crucible/my-plugin/
 */
router.get('/', authenticateToken, async (req, res) => {
  try {
    const data = await getData(req.user.userId);
    res.json({ success: true, data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/crucible/my-plugin/save
 */
router.post('/save', authenticateToken, async (req, res) => {
  try {
    // Validate input
    const errors = await validate(req.body);
    if (errors.length > 0) {
      return res.status(400).json({ errors });
    }

    const result = await saveData(req.user.userId, req.body);
    res.json({ success: true, data: result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/crucible/my-plugin/admin/report
 * Admin-only endpoint
 */
router.get('/admin/report', requireRole('admin'), async (req, res) => {
  try {
    const report = await generateReport();
    res.json({ success: true, report });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
```

### 4. services/data.js

```javascript
const { query } = require('../../../utils/db');

/**
 * Get data for a user
 */
async function getData(userId) {
  const result = await query(
    'SELECT * FROM my_plugin_data WHERE user_id = $1',
    [userId]
  );
  return result.rows;
}

/**
 * Save data for a user
 */
async function saveData(userId, data) {
  const result = await query(
    'INSERT INTO my_plugin_data (user_id, data) VALUES ($1, $2) RETURNING *',
    [userId, JSON.stringify(data)]
  );
  return result.rows[0];
}

module.exports = { getData, saveData };
```

### 5. hooks.js

```javascript
/**
 * Called when plugin is enabled
 */
async function onEnable(manifest) {
  console.log(`✅ Plugin enabled: v${manifest.version}`);
  // Initialize resources
}

/**
 * Called when plugin is disabled
 */
async function onDisable(manifest) {
  console.log(`⏸️  Plugin disabled`);
  // Cleanup resources
}

/**
 * Called when system initializes
 */
async function onInit(app, manifest) {
  console.log(`🔌 Plugin initialized`);
}

module.exports = { onEnable, onDisable, onInit };
```

### 6. migrations/001_init.sql

```sql
CREATE TABLE IF NOT EXISTS my_plugin_data (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id),
  data JSONB,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX ON my_plugin_data(user_id);
CREATE INDEX ON my_plugin_data(created_at);
```

---

## Managing Plugins

### List All Plugins

```bash
npm run plugin:list
```

### Enable a Plugin

```bash
npm run plugin:enable crucible/my-plugin
```

### Disable a Plugin

```bash
npm run plugin:disable crucible/my-plugin
```

---

## Best Practices

### 1. **Separation of Concerns**
- Keep routes minimal (just HTTP handling)
- Move business logic to `services/`
- Keep data access in separate functions

### 2. **Authentication**
- Always use `authenticateToken` middleware on protected routes
- Use `requireRole('admin')` for admin-only endpoints
- Never skip authentication for sensitive operations

### 3. **Error Handling**
- Wrap async code in try/catch
- Return appropriate HTTP status codes
- Return `{ error: 'message' }` on failure

### 4. **Database**
- Use prepared statements (parameterized queries)
- Define schema in `migrations/`
- Use consistent naming: `plugin_name_table_name`

### 5. **Configuration**
- Use `process.env` for secrets
- Define defaults in `manifest.json`
- Document all config options

### 6. **Logging**
- Use console.log for important events
- Prefix logs with plugin name: `[my-plugin]`
- Include timestamps for debugging

### 7. **API Design**
- Use RESTful conventions (GET/POST/PUT/DELETE)
- Return consistent JSON format:
  ```json
  {
    "success": true/false,
    "data": {...},
    "error": "message"
  }
  ```
- Document all endpoints in README

---

## Example Plugin

See `src/installed-plugins/example-plugins/demo-plugin/` for a complete example:

```bash
# List plugins
npm run plugin:list

# Test the demo plugin
curl http://localhost:3000/api/example/demo-plugin/info
```

---

## Deployment Checklist

- [ ] `manifest.json` created and valid JSON
- [ ] `routes/index.js` exports Express router
- [ ] All endpoints tested and working
- [ ] Authentication applied where needed
- [ ] Error handling on all endpoints
- [ ] Database migrations created (if needed)
- [ ] README.md with documentation
- [ ] Plugin disabled by default in manifest if still beta
- [ ] No hardcoded secrets (use .env)
- [ ] Plugin key follows naming: `module/plugin-name`

---

## Troubleshooting

### Plugin Routes Not Loading

```bash
# 1. Check plugin is enabled in manifest.json
# 2. Verify directory structure: src/installed-plugins/[module]-plugins/[plugin]/routes/index.js
# 3. Restart server: npm start
# 4. Check server console for load errors
```

### Authentication Not Working

```bash
# Make sure to import and use the middleware:
const { authenticateToken } = require('../../../core/middleware/auth');
router.get('/', authenticateToken, (req, res) => { ... });
```

### Database Queries Failing

```javascript
// ✅ Correct (parameterized)
const result = await query(
  'SELECT * FROM table WHERE id = $1',
  [id]
);

// ❌ Wrong (SQL injection risk)
const result = await query(`SELECT * FROM table WHERE id = ${id}`);
```

---

## API Reference

### Middleware

```javascript
// Authentication (required token)
const { authenticateToken } = require('../../../core/middleware/auth');

// Role checking
const { requireRole } = require('../../../core/middleware/auth');

// Error handler
const { asyncHandler, AppError } = require('../../../core/middleware/errorHandler');

// Activity logging
const { logActivity } = require('../../../core/middleware/activity-logger');
```

### Database

```javascript
// Query database
const { query } = require('../../../utils/db');
const result = await query('SELECT * FROM table WHERE id = $1', [id]);
```

### Utils

```javascript
// UUID generation
const { v4: uuidv4 } = require('uuid');
const id = uuidv4();
```

---

## Getting Help

- Check the example plugin: `src/installed-plugins/example-plugins/demo-plugin/`
- Review existing plugins in `src/installed-plugins/*/`
- Look at core routes: `src/routes/`
- Check CyberHub documentation

## Contributing

Ready to share your plugin with the community? Great!

1. Create a GitHub repository
2. Add your plugin structure
3. Include comprehensive README
4. Submit PR or issue to CyberHub

---

**Happy Plugin Development! 🔌**
