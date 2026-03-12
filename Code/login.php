<?php
require_once __DIR__ . '/config.php';

if (is_logged_in()) {
    header('Location: ' . BASE_URL . '/dashboard.php');
    exit;
}

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    if ($username === '' || $password === '') {
        $error = 'Please enter both username and password.';
    } else {
        $pdo = get_db_connection();
        $stmt = $pdo->prepare('SELECT id, username, password_hash, role FROM users WHERE username = :u OR email = :u LIMIT 1');
        $stmt->execute([':u' => $username]);
        $user = $stmt->fetch();

        if ($user && password_verify($password, $user['password_hash'])) {
            $_SESSION['user_id'] = $user['id'];
            unset($_SESSION['user']); // force reload
            header('Location: ' . BASE_URL . '/dashboard.php');
            exit;
        } else {
            $error = 'Invalid credentials.';
        }
    }
}

include __DIR__ . '/layout/header.php';
?>

<div class="auth-page">
    <div class="card">
        <div class="card-header">
            <div>
                <div class="card-title">Sign in to GhostBug</div>
                <div class="card-subtitle">Access the GhostBug network IDS dashboard</div>
            </div>
        </div>

        <?php if ($error): ?>
            <div class="alert alert-error"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>

        <form method="post" class="form-grid" autocomplete="off">
            <div class="form-group">
                <label for="username">Username or Email</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <div>
                <button type="submit" class="btn-primary">Login</button>
            </div>
        </form>

        <div class="auth-footer">
            No account yet?
            <a href="<?php echo BASE_URL; ?>/register.php">Create one</a>
        </div>
    </div>
</div>

<?php include __DIR__ . '/layout/footer.php'; ?>

