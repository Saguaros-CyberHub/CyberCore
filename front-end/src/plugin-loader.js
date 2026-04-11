/**
 * ============================================================================
 * CYBERHUB PLUGIN LOADER
 * ============================================================================
 * Discovers plugins in the plugins/ directory at startup.
 * For each plugin:
 *   1. Reads plugin.json manifest
 *   2. Auto-provisions the plugin's database (if declared)
 *   3. Upserts into cybercore_module so /api/modules discovers it
 *   4. Mounts static assets and Express routes
 *   5. Stores subnav config in memory for the sidebar API
 */

const fs = require('fs');
const path = require('path');
const express = require('express');
const { Pool } = require('pg');
const { cybercorePool, cybercoreQuery } = require('./utils/cybercore-db');

const PLUGINS_DIR = path.join(__dirname, '../plugins');

// In-memory registry of loaded plugins
const registry = {};

/**
 * Load all plugins from the plugins/ directory
 */
async function loadAll(app) {
  if (!fs.existsSync(PLUGINS_DIR)) {
    console.log('[PluginLoader] No plugins/ directory found, skipping.');
    return;
  }

  const dirs = fs.readdirSync(PLUGINS_DIR, { withFileTypes: true })
    .filter(d => d.isDirectory())
    .map(d => d.name);

  for (const dirName of dirs) {
    const manifestPath = path.join(PLUGINS_DIR, dirName, 'plugin.json');
    if (!fs.existsSync(manifestPath)) {
      console.warn(`[PluginLoader] "${dirName}" has no plugin.json, skipping.`);
      continue;
    }

    try {
      const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
      const pluginDir = path.join(PLUGINS_DIR, dirName);

      console.log(`[PluginLoader] Loading plugin: ${manifest.name} (${manifest.key})`);

      // 1. Provision database if declared
      if (manifest.database) {
        await provisionDatabase(manifest, pluginDir);
      }

      // 2. Upsert into cybercore_module
      await registerModule(manifest);

      // 3. Mount static assets
      if (manifest.staticDir && manifest.staticMountPath) {
        const staticPath = path.join(pluginDir, manifest.staticDir);
        if (fs.existsSync(staticPath)) {
          app.use(manifest.staticMountPath, express.static(staticPath));
        }
      }

      // 4. Mount routes
      if (manifest.routes && Array.isArray(manifest.routes)) {
        for (const routeDef of manifest.routes) {
          const routerPath = path.join(pluginDir, routeDef.file);
          if (fs.existsSync(routerPath)) {
            const router = require(routerPath);
            app.use(routeDef.mountPath, router);
            console.log(`[PluginLoader]   Route: ${routeDef.file} → ${routeDef.mountPath}`);
          } else {
            console.warn(`[PluginLoader]   Route file not found: ${routeDef.file}`);
          }
        }
      }

      // 5. Store in registry
      registry[manifest.key] = {
        ...manifest,
        dir: pluginDir
      };

      console.log(`[PluginLoader] Plugin loaded: ${manifest.name} at ${manifest.staticMountPath || '/'}`);
    } catch (err) {
      console.error(`[PluginLoader] Failed to load plugin "${dirName}":`, err.message);
    }
  }
}

/**
 * Provision a plugin's database: create if not exists, run migrations
 */
async function provisionDatabase(manifest, pluginDir) {
  const dbName = manifest.database.name;
  const migrationsDir = path.join(pluginDir, manifest.database.migrations || 'migrations');

  // Check if database exists using the cybercore connection
  const result = await cybercoreQuery(
    `SELECT 1 FROM pg_database WHERE datname = $1`, [dbName]
  );

  if (result.rows.length === 0) {
    // Create the database — must use a connection without a specific database
    // pg doesn't allow CREATE DATABASE inside a transaction, so use cybercore connection
    console.log(`[PluginLoader]   Creating database: ${dbName}`);
    await cybercorePool.query(`CREATE DATABASE "${dbName}"`);
  }

  // Create a pool for the plugin's database
  const pluginPool = new Pool({
    host: process.env.CYBERCORE_DB_HOST || 'localhost',
    port: parseInt(process.env.CYBERCORE_DB_PORT) || 5432,
    database: dbName,
    user: process.env.CYBERCORE_DB_USER || process.env.CORE_DB_USER,
    password: process.env.CYBERCORE_DB_PASSWORD || process.env.CORE_DB_PASSWORD,
    max: 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
  });

  // Run migrations
  if (fs.existsSync(migrationsDir)) {
    const files = fs.readdirSync(migrationsDir)
      .filter(f => f.endsWith('.sql'))
      .sort();

    for (const file of files) {
      const sql = fs.readFileSync(path.join(migrationsDir, file), 'utf8');
      try {
        await pluginPool.query(sql);
        console.log(`[PluginLoader]   Migration: ${file}`);
      } catch (err) {
        console.error(`[PluginLoader]   Migration failed (${file}):`, err.message);
      }
    }
  }

  // Inject pool into the plugin's db utility
  const dbUtilPath = path.join(pluginDir, 'utils', 'db.js');
  if (fs.existsSync(dbUtilPath)) {
    const pluginDb = require(dbUtilPath);
    if (typeof pluginDb.setPool === 'function') {
      pluginDb.setPool(pluginPool);
    }
  }
}

/**
 * Upsert plugin into cybercore_module table
 */
async function registerModule(manifest) {
  await cybercoreQuery(
    `INSERT INTO cybercore_module (key, name, icon, description, entry_url, category, color, display_order, active)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, TRUE)
     ON CONFLICT (key) DO UPDATE SET
       name = EXCLUDED.name,
       icon = EXCLUDED.icon,
       description = EXCLUDED.description,
       entry_url = EXCLUDED.entry_url,
       category = EXCLUDED.category,
       color = EXCLUDED.color,
       display_order = EXCLUDED.display_order`,
    [
      manifest.key,
      manifest.name,
      manifest.icon || null,
      manifest.description || null,
      manifest.entryUrl || null,
      manifest.category || 'plugin',
      manifest.color || null,
      manifest.displayOrder || 99
    ]
  );
}

/**
 * Get the full plugin registry
 */
function getRegistry() {
  return registry;
}

/**
 * Get all subnav configs keyed by plugin key
 */
function getAllSubnavs() {
  const result = {};
  for (const [key, plugin] of Object.entries(registry)) {
    if (plugin.subnav) {
      result[key] = {
        label: plugin.name,
        items: plugin.subnav
      };
    }
  }
  return result;
}

module.exports = { loadAll, getRegistry, getAllSubnavs };
