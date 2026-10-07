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

-- ============================================================================
-- Portal articles. publications.php is the index; article.php renders one.
-- ============================================================================
-- author_id is the CORRESPONDING author — the byline that carries @username.
-- That disclosure is load-bearing: the portal's account names are not uniform
-- (rgreen and dvalmont are finitial+lastname, dr.wagner is not), so a student
-- who cracks the SQLi-dumped hashes learns which username goes with which hash
-- by reading the bylines, not by guessing a convention. At least one
-- PUBLISHED article must therefore byline @dr.wagner -- if the admin only
-- ever appeared on drafts, the credential route would need a login to
-- discover, which is circular.
--
-- co_authors is display-only free text, matching how the group actually
-- credits multi-author work.
--
-- status='draft' hides the row from anonymous visitors but shows it to ANY
-- signed-in portal account, so a plain researcher login (rgreen / dvalmont) is
-- worth something even though it grants no admin. Both halves of that
-- asymmetry matter: hidden anonymously AND shown to any signed-in account.
--
-- NOTE: `mysql < schema.sql` runs without --force and runcmd has no `set -e`,
-- so the FK below is the one statement here that could abort the rest of this
-- file silently. Both tables take the server defaults (InnoDB, utf8mb4, INT),
-- so it resolves — and SITE_HTTP fails the bake loudly if it ever does not.
CREATE TABLE IF NOT EXISTS articles (
  id           INT AUTO_INCREMENT PRIMARY KEY,
  slug         VARCHAR(160) NOT NULL UNIQUE,
  title        VARCHAR(200) NOT NULL,
  abstract     TEXT,
  body         MEDIUMTEXT,
  author_id    INT NOT NULL,
  co_authors   VARCHAR(255) DEFAULT NULL,
  published_on DATE,
  status       VARCHAR(16) NOT NULL DEFAULT 'published',  -- published | draft
  created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_articles_author FOREIGN KEY (author_id) REFERENCES users(id)
);
