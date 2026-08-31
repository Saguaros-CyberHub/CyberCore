<?php
// ============================================================================
// CyberSaguaros Research Portal — shared page layout
// ============================================================================
require_once __DIR__ . '/config.php';

// *** THIS REQUIRE MUST STAY AT FILE SCOPE. ***
// db.php assigns $pdo at file scope, and PHP includes inherit the caller's
// scope. Required from here, the chain runs at global scope on every page and
// `global $pdo` inside admin_identity() resolves. Moved INSIDE render_header()
// — as render_footer() does with chatwidget.php, so the shape looks
// reasonable — db.php would execute in function scope, $pdo would become a
// local, and every page would fatal with "prepare() on null".
require_once __DIR__ . '/auth.php';

/** "Dr. Paul Wagner" -> "PW".  "Reggie Green" -> "RG". */
function initials(string $name): string {
    $parts = preg_split('/\s+/', trim($name)) ?: [];
    $parts = array_values(array_filter($parts, static function ($p) {
        return $p !== '' && !preg_match('/^(dr|mr|ms|mrs|prof)\.?$/i', $p);
    }));
    $first = isset($parts[0][0]) ? $parts[0][0] : '?';
    $last  = count($parts) > 1 ? $parts[count($parts) - 1][0] : '';
    return strtoupper($first . $last);
}

/**
 * The header identity chip. Four states, because the token admin has no user
 * row to name:
 *   1. anonymous               -> sign-in link
 *   2. researcher              -> who + log out
 *   3. admin via portal login  -> who + Admin Panel + log out
 *   4. admin via session token -> "Admin session" + Admin Panel (no log out)
 *
 * State 4 has no log-out link. logout.php destroys the PHP session, not the
 * admin_session cookie, so the link would do nothing for a token admin.
 */
function render_userchip(?array $me, ?array $admin): void {
    if (!$me && !$admin) {
        echo '<div class="userchip anon">'
           . '<a class="chip-btn" href="/login.php">Researcher sign-in</a></div>';
        return;
    }

    // Token admin with no portal session — state 4.
    if (!$me && $admin) {
        echo '<div class="userchip">'
           . '<span class="avatar">&#9881;</span>'
           . '<span class="who"><b>' . htmlspecialchars($admin['display_name']) . '</b>'
           . '<span>' . htmlspecialchars($admin['label']) . '</span></span>'
           . '<a class="chip-btn admin" href="/admin/">Admin Panel</a></div>';
        return;
    }

    // States 2 and 3.
    $sub = '@' . $me['username'] . ($admin ? ' · admin' : '');
    echo '<div class="userchip">'
       . '<span class="avatar">' . htmlspecialchars(initials((string) $me['display_name'])) . '</span>'
       . '<span class="who"><b>' . htmlspecialchars((string) $me['display_name']) . '</b>'
       . '<span>' . htmlspecialchars($sub) . '</span></span>';
    if ($admin) {
        echo '<a class="chip-btn admin" href="/admin/">Admin Panel</a>';
    }
    echo '<a class="chip-btn ghost" href="/logout.php">Log out</a></div>';
}

function render_header(string $title, string $active = ''): void {
    // Resolve identity BEFORE the first echo. current_researcher() may
    // session_start(), which sends a Set-Cookie header, and headers cannot be
    // sent once output has begun.
    $me    = current_researcher();
    $admin = admin_identity();

    // SaguaroBot (/chat.php) is not in the nav: the floating widget is on
    // every page already, so a second entry point would be redundant.
    $nav = [
        '/'                 => 'Home',
        '/about.php'        => 'About',
        '/research.php'     => 'Research',
        '/publications.php' => 'Publications',
        '/gallery.php'      => 'Gallery',
    ];
    echo '<!doctype html><html lang="en"><head><meta charset="utf-8">';
    echo '<meta name="viewport" content="width=device-width,initial-scale=1">';
    echo '<title>' . htmlspecialchars($title) . ' — ' . APP_NAME . '</title>';
    echo '<link rel="stylesheet" href="/assets/style.css"></head><body>';
    // Prefer the real transparent logo (assets/logo.png); fall back to the
    // shipped placeholder SVG until that file is committed.
    $logo = file_exists(__DIR__ . '/../public/assets/logo.png')
        ? '/assets/logo.png' : '/assets/logo.svg';
    echo '<header class="site-header"><a class="brand" href="/">';
    echo '<img class="logo" src="' . $logo . '" alt="CyberSaguaros">';
    echo '<div><strong>' . APP_NAME . '</strong>';
    echo '<small>' . APP_TAGLINE . '</small></div></a>';
    // .site-header is a two-column space-between flexbox. The nav and the chip
    // share the right-hand column so adding the chip does not strand the nav
    // in the middle of the header.
    echo '<div class="header-right"><nav>';
    foreach ($nav as $href => $label) {
        $cls = ($href === $active) ? ' class="active"' : '';
        echo '<a' . $cls . ' href="' . $href . '">' . $label . '</a>';
    }
    echo '</nav>';
    render_userchip($me, $admin);
    echo '</div></header><main>';
}

function render_footer(): void {
    echo '</main><footer><small>&copy; 2026 CyberSaguaros Research Group &middot; '
       . 'Sonoran Desert Field Station &middot; cybersaguaros.local</small></footer>';
    require __DIR__ . '/chatwidget.php';   // floating SaguaroBot widget
    echo '</body></html>';
}
