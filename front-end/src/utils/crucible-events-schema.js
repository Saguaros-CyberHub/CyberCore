'use strict';

const fs = require('node:fs');
const path = require('node:path');

// config/postgres scripts run only on fresh volumes and are not shipped in the
// app image. This small packaged SQL resource is also the hand-run migration's
// source; the schema test checks it against the fresh-install module SQL.
const EVENT_SCHEMA_SQL = fs.readFileSync(path.join(__dirname, '../schema/crucible-events.sql'), 'utf8');

async function ensureCrucibleEventSchema({ query } = {}) {
  const execute = query || require('./cybercore-db').cybercoreQuery;
  await execute(EVENT_SCHEMA_SQL);
}

module.exports = { EVENT_SCHEMA_SQL, ensureCrucibleEventSchema };

// Optional repair from the normal app container, using its existing database
// environment. No database password or SQL needs to be copied into a command.
if (require.main === module) {
  const { cybercorePool } = require('./cybercore-db');
  ensureCrucibleEventSchema()
    .then(() => console.log('Crucible event schema is ready.'))
    .catch(error => {
      console.error(`Crucible event schema repair failed: ${error.message}`);
      process.exitCode = 1;
    })
    .finally(() => cybercorePool.end());
}
