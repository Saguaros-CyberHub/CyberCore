-- ============================================================================
-- CyberSaguaros Research Portal — database schema
-- ============================================================================
-- Loaded by bake-cybersaguaros-template.sh into the `cybersaguaros` database.
-- ============================================================================

CREATE TABLE IF NOT EXISTS users (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  username      VARCHAR(64)  NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  display_name  VARCHAR(128) NOT NULL,
  email         VARCHAR(128) NOT NULL,
  role          VARCHAR(32)  NOT NULL DEFAULT 'researcher'  -- researcher | admin
);

CREATE TABLE IF NOT EXISTS datasets (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  name        VARCHAR(160) NOT NULL,
  description TEXT,
  owner_id    INT,
  dataset_url VARCHAR(512),
  verified    TINYINT(1) NOT NULL DEFAULT 0,
  created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS chat_logs (
  id         INT AUTO_INCREMENT PRIMARY KEY,
  session_id VARCHAR(64)  NOT NULL,
  speaker    VARCHAR(16)  NOT NULL,  -- user | bot
  message    TEXT         NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS uploads (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  filename      VARCHAR(255) NOT NULL,
  original_name VARCHAR(255) NOT NULL,
  uploaded_by   VARCHAR(64),
  created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Admin sessions. The /api/internal/provision.php endpoint (localhost-only)
-- mints rows here; /admin pages authorise on the admin_session cookie.
CREATE TABLE IF NOT EXISTS admin_sessions (
  token      VARCHAR(64) PRIMARY KEY,
  label      VARCHAR(128),
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP NOT NULL
);
