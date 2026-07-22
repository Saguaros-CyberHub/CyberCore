<?php
// ============================================================================
// CyberSaguaros Research Portal — application config
// ============================================================================
// DB credentials match what bake-cybersaguaros-template.sh provisions in
// MariaDB. Lives outside the nginx webroot (app/includes/, not app/public/)
// so it is never web-reachable.
// ============================================================================

define('APP_NAME',   'CyberSaguaros Research Portal');
define('APP_TAGLINE','Computational botany for the Sonoran desert');

define('DB_HOST', '127.0.0.1');
define('DB_NAME', 'cybersaguaros');
define('DB_USER', 'saguaro_app');
define('DB_PASS', 'Pr1ckly-Pear-Access-2026');

// Filesystem path of the public uploads directory ("Cloud Storage").
define('UPLOAD_DIR', __DIR__ . '/../public/uploads');
