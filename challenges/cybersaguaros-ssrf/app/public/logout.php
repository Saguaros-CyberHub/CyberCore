<?php
require_once __DIR__ . '/../includes/auth.php';
start_session_once();
$_SESSION = [];
session_destroy();
header('Location: /');
exit;
