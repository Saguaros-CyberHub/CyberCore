<?php
// ============================================================================
// CyberSaguaros Research Portal — authentication helpers
// ============================================================================
// TWO independent admin surfaces, both first-class. Either one authorises
// /admin/, including the Cloud Storage upload:
//
//   'session' — a signed-in portal user whose users.role is 'admin'
//               (dr.wagner). This is the route a student takes after dumping
//               `users` through the /research.php SQLi and cracking the
//               unsalted SHA-256 hashes: legitimate functionality, abused.
//
//   'token'   — a valid, unexpired admin_sessions row keyed by the
//               `admin_session` cookie. Tokens are minted only by
//               /api/internal/provision.php, which nginx binds to loopback,
//               so in practice this route is reachable only through the
//               SaguaroBot SSRF.
//
// The two converge deliberately. What keeps the credential route from
// collapsing the REST of the chain is that hrivera is absent from `users`
// (see db/seed.sql) — so SQLi still cannot shortcut past RCE into the SSH,
// lateral-movement and privesc stages.
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
 * student on the SSRF path has no PHP session at all, so the token branch is
 * still reached. An anonymous, cookie-less request issues ZERO queries, which
 * is what keeps the new header chip off the DB on public pages.
 *
 * @return array{via:string,username:?string,display_name:string,label:string}|null
 */
function admin_identity(): ?array {
    static $cache = false;            // false = unresolved, null = not an admin
    if ($cache !== false) {
        return $cache;
    }

    $r = current_researcher();
    // *** LOAD-BEARING: the role check, not a truthiness check. ***
    // `if ($r)` here would hand admin — and therefore the Cloud Storage upload
    // RCE — to rgreen and dvalmont as well. dvalmont is also a real Linux SSH
    // account whose password is in the SQLi dump, so that single-character
    // regression would collapse a large part of the chain. If you change
    // anything here, verify by hand that rgreen / cactus still gets a 403
    // from /admin/ -- nothing in the bake asserts it for you.
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
