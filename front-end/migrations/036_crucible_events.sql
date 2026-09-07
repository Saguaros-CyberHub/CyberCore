-- Apply to cybercore_db with psql -v ON_ERROR_STOP=1 -f <this-file>.
-- The app also ensures this schema at startup for existing database volumes.
-- From an updated app image, the same repair is available without psql:
--   docker compose exec -T app node src/utils/crucible-events-schema.js
-- Reuse the packaged runtime SQL rather than maintaining another DDL copy.
\ir ../src/schema/crucible-events.sql
