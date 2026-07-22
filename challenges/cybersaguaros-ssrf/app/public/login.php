<?php
require_once __DIR__ . '/../includes/layout.php';
require_once __DIR__ . '/../includes/auth.php';

start_session_once();
$error = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    // Passwords are stored as unsalted SHA-256 (deliberately weak).
    $stmt = $pdo->prepare(
        'SELECT id, username, display_name, role
         FROM users WHERE username = ? AND password_hash = ?'
    );
    $stmt->execute([$username, hash('sha256', $password)]);
    $row = $stmt->fetch();
    if ($row) {
        $_SESSION['researcher'] = $row;
        header('Location: /chat.php');
        exit;
    }
    $error = 'Invalid researcher credentials.';
}

render_header('Sign in', '');
?>
<section class="narrow">
  <h1>Researcher sign-in</h1>
  <p class="muted">Portal accounts are issued to CyberSaguaros research staff.
     SaguaroBot is available to everyone without an account.</p>
  <?php if ($error): ?><p class="formerr"><?= htmlspecialchars($error) ?></p><?php endif; ?>
  <form method="post" class="stack">
    <label>Username <input type="text" name="username" required></label>
    <label>Password <input type="password" name="password" required></label>
    <button type="submit">Sign in</button>
  </form>
</section>
<?php render_footer(); ?>
