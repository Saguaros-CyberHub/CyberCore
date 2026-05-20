<?php
// ============================================================================
// CyberSaguaros Research Portal — shared page layout
// ============================================================================
require_once __DIR__ . '/config.php';

function render_header(string $title, string $active = ''): void {
    // SaguaroBot (/chat.php) is intentionally NOT in the nav — it is found
    // through directory enumeration during recon.
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
    echo '<small>' . APP_TAGLINE . '</small></div></a><nav>';
    foreach ($nav as $href => $label) {
        $cls = ($href === $active) ? ' class="active"' : '';
        echo '<a' . $cls . ' href="' . $href . '">' . $label . '</a>';
    }
    echo '</nav></header><main>';
}

function render_footer(): void {
    echo '</main><footer><small>&copy; 2026 CyberSaguaros Research Group &middot; '
       . 'Sonoran Desert Field Station &middot; cybersaguaros.local</small></footer>';
    echo '</body></html>';
}
