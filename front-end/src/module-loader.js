/**
 * Module Loader
 * Discovers and loads modules from the modules/ directory
 * Each module can contain nested plugins in its plugins/ subdirectory
 */

const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');
const modulesDir = path.join(__dirname, '../modules');
const { cybercorePool } = require('./utils/cybercore-db');

let loadedModules = [];
let loadedPlugins = [];
let loadedSubnavs = {};

/**
 * Load all modules and their plugins
 */
async function loadAll(app) {
  try {
    if (!fs.existsSync(modulesDir)) {
      console.log('⚠️  modules/ directory not found');
      return [];
    }

    const moduleNames = fs.readdirSync(modulesDir).filter(f => 
      fs.statSync(path.join(modulesDir, f)).isDirectory()
    );

    console.log(`\n📦 Loading ${moduleNames.length} modules...`);

    for (const moduleName of moduleNames) {
      const modulePath = path.join(modulesDir, moduleName);
      const manifestPath = path.join(modulePath, 'manifest.json');

      if (!fs.existsSync(manifestPath)) {
        console.warn(`⚠️  No manifest.json for module: ${moduleName}`);
        continue;
      }

      const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
      
      // Log module header first
      console.log(`  ✓ Module loaded: ${manifest.name} (${manifest.key})`);
      
      // Provision database if defined
      if (manifest.database) {
        await provisionDatabase(manifest, modulePath);
      }

      // Register module in database
      await registerModule(manifest);

      // Mount routes
      if (manifest.routes && Array.isArray(manifest.routes)) {
        for (const route of manifest.routes) {
          const routePath = path.join(modulePath, route.file);
          if (fs.existsSync(routePath)) {
            const router = require(routePath);
            app.use(route.mountPath, router);
            console.log(`    ✓ routes at ${route.mountPath}`);
          }
        }
      }

      // Serve static files
      if (manifest.staticDir) {
        const staticPath = path.join(modulePath, manifest.staticDir);
        if (fs.existsSync(staticPath)) {
          app.use(manifest.staticMountPath || `/${moduleName}`, 
            require('express').static(staticPath));
        }
      }

      // Load plugins for this module
      const pluginsLoaded = await loadModulePlugins(app, moduleName, modulePath, manifest);
      if (pluginsLoaded > 0) {
        console.log(`    Loaded ${pluginsLoaded} plugin${pluginsLoaded !== 1 ? 's' : ''}`);
      }

      // Track module
      loadedModules.push(manifest);
      if (manifest.subnav) {
        loadedSubnavs[manifest.key] = {
          label: manifest.subnav.label || manifest.name,
          items: manifest.subnav.items || []
        };
      }
    }

    console.log(`✅ Loaded ${loadedModules.length} modules and ${loadedPlugins.length} plugins\n`);
    return loadedModules;

  } catch (error) {
    console.error('❌ Error loading modules:', error.message);
    throw error;
  }
}

/**
 * Load plugins from modules/[moduleName]/plugins/
 */
async function loadModulePlugins(app, moduleName, modulePath, moduleManifest) {
  const pluginsDir = path.join(modulePath, 'plugins');

  if (!fs.existsSync(pluginsDir)) {
    return [];
  }

  const pluginNames = fs.readdirSync(pluginsDir).filter(f =>
    fs.statSync(path.join(pluginsDir, f)).isDirectory()
  );

  for (const pluginName of pluginNames) {
    const pluginPath = path.join(pluginsDir, pluginName);
    const pluginManifestPath = path.join(pluginPath, 'manifest.json');

    if (!fs.existsSync(pluginManifestPath)) {
      console.warn(`  ⚠️  No manifest.json for plugin: ${pluginName}`);
      continue;
    }

    const pluginManifest = JSON.parse(fs.readFileSync(pluginManifestPath, 'utf8'));
    
    // Set parent module reference
    pluginManifest.parent_module = moduleName;

    // Provision database if defined
    if (pluginManifest.database) {
      await provisionDatabase(pluginManifest, pluginPath);
    }

    // Register plugin in database
    await registerModule(pluginManifest);

    // Mount routes
    if (pluginManifest.routes && Array.isArray(pluginManifest.routes)) {
      for (const route of pluginManifest.routes) {
        const routePath = path.join(pluginPath, route.file);
        if (fs.existsSync(routePath)) {
          const router = require(routePath);
          app.use(route.mountPath, router);
        }
      }
    }

    // Serve static files
    if (pluginManifest.staticDir) {
      const staticPath = path.join(pluginPath, pluginManifest.staticDir);
      if (fs.existsSync(staticPath)) {
        app.use(pluginManifest.staticMountPath || `/${pluginName}`,
          require('express').static(staticPath));
      }
    }

    // Track plugin
    loadedPlugins.push(pluginManifest);
    if (pluginManifest.subnav) {
      loadedSubnavs[pluginManifest.key] = {
        label: pluginManifest.subnav.label || pluginManifest.name,
        items: pluginManifest.subnav.items || []
      };
    }

    console.log(`    ✓ Plugin loaded: ${pluginManifest.name} (${pluginManifest.key})`);
  }

  return pluginNames.length;
}

/**
 * Provision database for module/plugin and inject pool into db utility
 */
async function provisionDatabase(manifest, moduleOrPluginPath) {
  const dbName = manifest.database.name;
  const migrationsDir = path.join(moduleOrPluginPath, manifest.database.migrations);

  try {
    // Create database if it doesn't exist
    const client = await cybercorePool.connect();
    
    try {
      // Check if database exists
      const result = await client.query(
        `SELECT 1 FROM pg_database WHERE datname = $1`,
        [dbName]
      );
      
      if (result.rows.length === 0) {
        await client.query(`CREATE DATABASE ${dbName}`);
        console.log(`    ✓ Created database: ${dbName}`);
      }
    } finally {
      client.release();
    }

    // Create connection pool for this database
    const dbPool = new Pool({
      host: process.env.DB_HOST || process.env.CYBERCORE_DB_HOST || 'localhost',
      port: parseInt(process.env.DB_PORT || process.env.CYBERCORE_DB_PORT) || 5432,
      user: process.env.DB_USER || process.env.CYBERCORE_DB_USER || process.env.CORE_DB_USER || 'postgres',
      password: process.env.DB_PASSWORD || process.env.CYBERCORE_DB_PASSWORD || process.env.CORE_DB_PASSWORD || '',
      database: dbName,
      max: 10,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 5000,
    });

    // Run migrations if they exist
    if (fs.existsSync(migrationsDir)) {
      const migrationFiles = fs.readdirSync(migrationsDir)
        .filter(f => f.endsWith('.sql'))
        .sort();

      for (const file of migrationFiles) {
        const sql = fs.readFileSync(path.join(migrationsDir, file), 'utf8');
        try {
          await dbPool.query(sql);
          console.log(`    ✓ Migration: ${file}`);
        } catch (err) {
          console.warn(`    ⚠️  Migration ${file}: ${err.message}`);
        }
      }
    }

    // Inject pool into the db utility module
    const dbUtilPath = path.join(moduleOrPluginPath, 'utils', 'db.js');
    if (fs.existsSync(dbUtilPath)) {
      // Clear the require cache to ensure fresh import
      delete require.cache[require.resolve(dbUtilPath)];
      
      const dbUtil = require(dbUtilPath);
      if (typeof dbUtil.setPool === 'function') {
        dbUtil.setPool(dbPool);
        console.log(`    ✓ Database pool injected for: ${dbName}`);
      }
    }

  } catch (error) {
    console.warn(`  ⚠️  Database provisioning for ${dbName}: ${error.message}`);
  }
}

/**
 * Register module/plugin in cybercore database
 */
async function registerModule(manifest) {
  try {
    const client = await cybercorePool.connect();
    
    try {
      const category = manifest.category || 'module';
      
      await client.query(
        `INSERT INTO cybercore_module (key, name, icon, description, entry_url, category, color, active, parent_module, display_order)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
         ON CONFLICT (key) DO UPDATE SET 
         name = EXCLUDED.name,
         icon = EXCLUDED.icon,
         description = EXCLUDED.description,
         entry_url = EXCLUDED.entry_url,
         category = EXCLUDED.category,
         color = EXCLUDED.color,
         active = EXCLUDED.active,
         parent_module = EXCLUDED.parent_module,
         display_order = EXCLUDED.display_order`,
        [
          manifest.key,
          manifest.name,
          manifest.icon,
          manifest.description,
          manifest.entry_url,
          category,
          manifest.color,
          manifest.active !== false,
          manifest.parent_module || null,
          manifest.display_order || 0
        ]
      );
    } finally {
      client.release();
    }
  } catch (error) {
    console.warn(`  ⚠️  Could not register module ${manifest.key}: ${error.message}`);
  }
}

/**
 * Get all subnavs from modules and plugins
 */
function getAllSubnavs() {
  return loadedSubnavs;
}

/**
 * Get all loaded modules and plugins
 */
function getAllModules() {
  return loadedModules;
}

module.exports = {
  loadAll,
  loadModulePlugins,
  getAllSubnavs,
  getAllModules,
  registerModule,
  provisionDatabase
};
