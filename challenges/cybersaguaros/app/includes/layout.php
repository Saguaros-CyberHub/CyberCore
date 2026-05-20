<?php
// ============================================================================
// CyberSaguaros Research Portal — shared page layout
// ============================================================================
require_once __DIR__ . '/config.php';

function render_header(string $title, string $active = ''): void {
    $nav = [
        '/'             => 'Home',
        '/research.php' => 'Research',
        '/publications.php' => 'Publications',
        '/gallery.php'  => 'Gallery',
        '/chat.php'     => 'SaguaroBot',
        '/about.php'    => 'About',
    ];
    echo '<!doctype html><html lang="en"><head><meta charset="utf-8">';
    echo '<meta name="viewport" content="width=device-width,initial-scale=1">';
    echo '<title>' . htmlspecialchars($title) . ' — ' . APP_NAME . '</title>';
    echo '<link rel="stylesheet" href="/assets/style.css"></head><body>';
    echo '<header class="site-header"><div class="brand">';
    echo '<span class="logo">&#127797;</span><div><strong>' . APP_NAME . '</strong>';
    echo '<small>' . APP_TAGLINE . '</small></div></div><nav>';
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
