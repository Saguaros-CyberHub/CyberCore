<?php
// ============================================================================
// CyberSaguaros Research Portal — authentication helpers
// ============================================================================
// Two independent auth surfaces:
//   - Researcher login: classic PHP session, set by login.php.
//   - Admin: the `admin_session` cookie, validated against admin_sessions.
//     Tokens are minted only by /api/internal/provision.php (localhost-only).
// ============================================================================
require_once __DIR__ . '/db.php';

function start_session_once(): void {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
}

/** Returns the logged-in researcher row, or null. */
function current_researcher(): ?array {
    start_session_once();
    return $_SESSION['researcher'] ?? null;
}

function require_researcher(): void {
    if (!current_researcher()) {
        header('Location: /login.php');
        exit;
    }
}

/** True if the request carries a valid, unexpired admin_session cookie. */
function is_admin(): bool {
    global $pdo;
    $token = $_COOKIE['admin_session'] ?? '';
    if ($token === '') {
        return false;
    }
    $stmt = $pdo->prepare(
        'SELECT 1 FROM admin_sessions WHERE token = ? AND expires_at > NOW()'
    );
    $stmt->execute([$token]);
    return (bool) $stmt->fetchColumn();
}

function require_admin(): void {
    if (!is_admin()) {
        http_response_code(403);
        echo '<h1>403 Forbidden</h1><p>A valid admin session is required to '
           . 'access the CyberSaguaros control panel.</p>';
        exit;
    }
}
