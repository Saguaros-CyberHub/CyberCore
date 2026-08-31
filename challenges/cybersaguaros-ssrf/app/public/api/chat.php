<?php
// ============================================================================
// SaguaroBot conversation backend — canned research-assistant replies.
// ============================================================================
// The integrity-check feature lives in verify.php. Conversations are recorded
// into chat_logs and reviewed at /admin/chat.php.
//
// NOTE: verify.php has NO database dependency and must keep it that way. The
// floating widget POSTs the visitor's message here BEFORE it calls verify.php,
// so any URL a visitor pastes is already recorded by this file. Adding db.php
// to verify.php would buy nothing and would put a 500 path on an endpoint that
// has to answer cleanly.
// ============================================================================
require_once __DIR__ . '/../../includes/auth.php';   // brings db.php with it
header('Content-Type: application/json');

// The widget's fetch() is same-origin and so carries PHPSESSID; this groups a
// visitor's turns into one reviewable transcript.
start_session_once();
$chatSessionId = substr(session_id(), 0, 64);

/**
 * Record one turn. Logging must NEVER break the bot — a DB hiccup here would
 * turn the chat widget into a 500 on every page of the site.
 */
function log_chat(string $speaker, string $message): void {
    global $pdo, $chatSessionId;
    if ($chatSessionId === '' || $message === '') {
        return;
    }
    try {
        $stmt = $pdo->prepare(
            'INSERT INTO chat_logs (session_id, speaker, message) VALUES (?, ?, ?)'
        );
        $stmt->execute([$chatSessionId, $speaker, $message]);
    } catch (Throwable $e) {
        // swallow
    }
}

$raw  = file_get_contents('php://input');
$data = json_decode($raw, true) ?: [];
// Accept a form post as well as the JSON body the widget sends.
$rawMsg = trim($data['message'] ?? ($_POST['message'] ?? ''));
// Keep the RAW message for the log — the matching below lowercases, and a
// pasted URL should be recorded verbatim and case-correct.
$msg = strtolower($rawMsg);

log_chat('user', $rawMsg);

function reply(string $r): void {
    log_chat('bot', $r);          // must precede the exit
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
if (str_contains($msg, 'article') || str_contains($msg, 'publication')
    || str_contains($msg, 'paper')) {
    reply("Our published work is on the Publications page — each article lists "
        . "its corresponding author, so you can see who to contact.");
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
