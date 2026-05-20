<?php
// ============================================================================
// SaguaroBot conversation backend — canned research-assistant replies.
// Not security-relevant; the integrity-check feature lives in verify.php.
// ============================================================================
require_once __DIR__ . '/../../includes/db.php';
header('Content-Type: application/json');

$raw  = file_get_contents('php://input');
$data = json_decode($raw, true) ?: [];
$msg  = strtolower(trim($data['message'] ?? ''));

function reply(string $r): void {
    echo json_encode(['reply' => $r]);
    exit;
}

if ($msg === '') {
    reply("Ask me about CyberSaguaros datasets, publications, or submissions.");
}
if (str_contains($msg, 'verify') || str_contains($msg, 'submit')
    || str_contains($msg, 'dataset') || str_contains($msg, 'url')) {
    reply("To submit a dataset, use the 'Dataset integrity check' panel on this "
        . "page. Paste the dataset's URL and I'll fetch the file myself to "
        . "verify it before our researchers review it.");
}
if (str_contains($msg, 'bloom')) {
    reply("Bloom telemetry is one of our flagship datasets — see Research for "
        . "the latest Saguaro Bloom Telemetry set.");
}
if (str_contains($msg, 'admin') || str_contains($msg, 'login')
    || str_contains($msg, 'password')) {
    reply("Portal accounts are managed by Dr. Wagner. I can't help with "
        . "account access — but I can verify datasets for you any time.");
}
if (str_contains($msg, 'hello') || str_contains($msg, 'hi')) {
    reply("Hello! I'm SaguaroBot. How can I help with your cactus research?");
}
reply("I'm a research assistant — I help with datasets, publications, and "
    . "integrity checks. Try the dataset verification panel on the right.");
