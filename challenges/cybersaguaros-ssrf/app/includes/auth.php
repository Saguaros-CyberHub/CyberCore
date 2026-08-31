<?php
// ============================================================================
// CyberSaguaros Research Portal — authentication helpers
// ============================================================================
// Two ways to hold admin on this portal:
//
//   'session' — a signed-in portal user whose users.role is 'admin'.
//
//   'token'   — a valid, unexpired admin_sessions row keyed by the
//               `admin_session` cookie, as minted for on-host automation
//               by /api/internal/provision.php.
// ============================================================================
require_once __DIR__ . '/db.php';

/**
 * Start the PHP session, optionally without creating a new one.
 *
 * $create = false is for read-only callers such as render_header() on an
 * anonymous request. Without it every page view would mint a session, emit a
 * Set-Cookie and leave an empty session file behind — and because
 * render_header() echoes as it goes, a session_start() that fired after the
 * first byte of output would warn and silently drop the cookie.
 */
function start_session_once(bool $create = true): void {
    if (session_status() !== PHP_SESSION_NONE) {
        return;
    }
    if (!$create && !isset($_COOKIE[session_name()])) {
        return;
    }
    session_start();
}

/** Returns the logged-in researcher row, or null. Costs no query. */
function current_researcher(): ?array {
    start_session_once(false);
    return $_SESSION['researcher'] ?? null;
}

function require_researcher(): void {
    if (!current_researcher()) {
        header('Location: /login.php');
        exit;
    }
}

/**
 * Resolves the effective admin identity for this request, or null.
 *
 * Memoised: render_header() and require_admin() both call it on every admin
 * page, and neither $_SESSION nor the cookie can change mid-request.
 *
 * Session first because it is free — the role is already in $_SESSION. A
 * request carrying only the admin_session cookie has no PHP session at all,
 * so the token branch is still reached. An anonymous, cookie-less request
 * issues ZERO queries, which keeps the header chip off the DB on public pages.
 *
 * @return array{via:string,username:?string,display_name:string,label:string}|null
 */
function admin_identity(): ?array {
    static $cache = false;            // false = unresolved, null = not an admin
    if ($cache !== false) {
        return $cache;
    }

    $r = current_researcher();
    if ($r && ($r['role'] ?? '') === 'admin') {
        return $cache = [
            'via'          => 'session',
            'username'     => (string) $r['username'],
            'display_name' => (string) $r['display_name'],
            'label'        => 'portal sign-in',
        ];
    }

    $token = $_COOKIE['admin_session'] ?? '';
    if ($token !== '') {
        // $pdo is assigned at FILE scope by db.php. It only resolves here if
        // every require in the chain ran at file scope too — see the warning
        // on the auth.php require in layout.php.
        global $pdo;
        $stmt = $pdo->prepare(
            'SELECT label FROM admin_sessions WHERE token = ? AND expires_at > NOW()'
        );
        $stmt->execute([$token]);
        $label = $stmt->fetchColumn();
        if ($label !== false) {
            return $cache = [
                'via'          => 'token',
                'username'     => null,
                'display_name' => 'Admin session',
                'label'        => (string) $label,
            ];
        }
    }

    return $cache = null;
}

/** True if this request holds admin through EITHER surface. */
function is_admin(): bool {
    return admin_identity() !== null;
}

function require_admin(): void {
    if (!is_admin()) {
        http_response_code(403);
        echo '<h1>403 Forbidden</h1><p>A valid admin session is required to '
           . 'access the CyberSaguaros control panel.</p>';
        exit;
    }
}
