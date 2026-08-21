<?php
require_once __DIR__ . '/../includes/layout.php';   // pulls auth.php -> db.php
require_once __DIR__ . '/../includes/auth.php';
start_session_once();

$error = null;
$me    = current_researcher();

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !$me) {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    // Passwords are stored as unsalted SHA-256 (deliberately weak). The lookup
    // itself is a prepared statement — this form is not the injection point;
    // /research.php is. What makes these credentials reachable is that the
    // SQLi there dumps `users`, and every password is a rockyou word.
    $stmt = $pdo->prepare(
        'SELECT id, username, display_name, role
         FROM users WHERE username = ? AND password_hash = ?'
    );
    $stmt->execute([$username, hash('sha256', $password)]);
    $row = $stmt->fetch();
    if ($row) {
        session_regenerate_id(true);
        $_SESSION['researcher'] = $row;
        // Used to send everyone to /chat.php, which granted nothing and also
        // advertised a page recon is meant to discover. Administrators now
        // land on the control panel their role actually unlocks.
        header('Location: ' . ($row['role'] === 'admin' ? '/admin/' : '/'));
        exit;
    }
    // Deliberately does not distinguish a bad username from a bad password —
    // but note the account names are readable off the article bylines anyway.
    $error = 'Invalid researcher credentials.';
}

render_header('Sign in', '');
?>
<section class="narrow">
  <?php if ($me): ?>
    <h1>Signed in</h1>
    <p>You are signed in as <strong><?= htmlspecialchars((string) $me['display_name']) ?></strong>
       (@<?= htmlspecialchars((string) $me['username']) ?>).</p>
    <?php if (is_admin()): ?>
      <p><a class="btn" href="/admin/">Open the control panel</a>
         <a class="btn ghost" href="/logout.php">Log out</a></p>
    <?php else: ?>
      <p><a class="btn" href="/publications.php">Read the working papers</a>
         <a class="btn ghost" href="/logout.php">Log out</a></p>
    <?php endif; ?>
  <?php else: ?>
    <h1>Researcher sign-in</h1>
    <p class="muted">Portal accounts are issued to CyberSaguaros research staff.
       Signing in reveals unpublished working papers; administrators also get
       the research control panel. SaguaroBot is available to everyone without
       an account.</p>
    <?php if ($error): ?><p class="formerr"><?= htmlspecialchars($error) ?></p><?php endif; ?>
    <form method="post" class="stack">
      <label>Username <input type="text" name="username" required></label>
      <label>Password <input type="password" name="password" required></label>
      <button type="submit">Sign in</button>
    </form>
  <?php endif; ?>
</section>
<?php render_footer(); ?>
