<?php
require_once __DIR__ . '/config.php';
require_login();

$user = current_user();
$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $full_name = trim($_POST['full_name'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirm = $_POST['confirm_password'] ?? '';

    if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = 'Please provide a valid email.';
    } elseif ($password !== '' && $password !== $confirm) {
        $error = 'New passwords do not match.';
    } else {
        $pdo = get_db_connection();
        // Check if email is used by someone else
        $stmt = $pdo->prepare('SELECT id FROM users WHERE email = :e AND id <> :id LIMIT 1');
        $stmt->execute([':e' => $email, ':id' => $user['id']]);
        if ($stmt->fetch()) {
            $error = 'Email already in use by another account.';
        } else {
            $params = [
                ':full_name' => $full_name !== '' ? $full_name : null,
                ':email' => $email,
                ':id' => $user['id'],
            ];
            $sql = 'UPDATE users SET full_name = :full_name, email = :email';
            if ($password !== '') {
                $sql .= ', password_hash = :password_hash';
                $params[':password_hash'] = password_hash($password, PASSWORD_BCRYPT);
            }

            // Handle profile image upload if provided
            if (isset($_FILES['profile_image']) && $_FILES['profile_image']['error'] === UPLOAD_ERR_OK) {
                $img = $_FILES['profile_image'];
                $allowed = ['jpg', 'jpeg', 'png'];
                $ext = strtolower(pathinfo($img['name'], PATHINFO_EXTENSION));
                if (in_array($ext, $allowed)) {
                    $profileDir = __DIR__ . '/uploads/profile_pics';
                    if (!is_dir($profileDir)) {
                        mkdir($profileDir, 0775, true);
                    }
                    $newName = 'u' . $user['id'] . '_' . uniqid() . '.' . $ext;
                    $dest = $profileDir . DIRECTORY_SEPARATOR . $newName;
                    if (move_uploaded_file($img['tmp_name'], $dest)) {
                        $sql .= ', profile_image = :profile_image';
                        $params[':profile_image'] = $newName;
                    }
                }
            }

            $sql .= ' WHERE id = :id';
            $stmt = $pdo->prepare($sql);
            $stmt->execute($params);

            // refresh session user cache
            unset($_SESSION['user']);
            $user = current_user();
            $success = 'Profile updated successfully.';
        }
    }
}

include __DIR__ . '/layout/header.php';
?>

<div class="card">
    <div class="card-header">
        <div>
            <div class="card-title">Your GhostBug profile</div>
            <div class="card-subtitle">Profile picture and account details</div>
        </div>
    </div>

    <?php if ($error): ?>
        <div class="alert alert-error"><?php echo htmlspecialchars($error); ?></div>
    <?php endif; ?>
    <?php if ($success): ?>
        <div class="alert alert-success"><?php echo htmlspecialchars($success); ?></div>
    <?php endif; ?>

    <form method="post" class="form-grid" autocomplete="off" enctype="multipart/form-data">
        <div class="form-group">
            <label>Profile picture</label>
            <?php if (!empty($user['profile_image'])): ?>
                <div class="avatar avatar-img" style="width:64px;height:64px;">
                    <img src="<?php echo BASE_URL . '/uploads/profile_pics/' . htmlspecialchars($user['profile_image']); ?>" alt="Profile picture">
                </div>
            <?php else: ?>
                <div class="avatar" style="width:64px;height:64px;font-size:1.3rem;">
                    <?php echo strtoupper(substr($user['username'], 0, 1)); ?>
                </div>
            <?php endif; ?>
            <input type="file" name="profile_image" accept="image/png,image/jpeg">
        </div>
        <div class="form-group">
            <label>Username (read-only)</label>
            <input type="text" value="<?php echo htmlspecialchars($user['username']); ?>" disabled>
        </div>
        <div class="form-group">
            <label for="full_name">Full name</label>
            <input type="text" id="full_name" name="full_name" value="<?php echo htmlspecialchars($user['full_name'] ?? ''); ?>">
        </div>
        <div class="form-group">
            <label for="email">Email</label>
            <input type="email" id="email" name="email" required value="<?php echo htmlspecialchars($user['email']); ?>">
        </div>
        <div class="form-group">
            <label for="password">New password (leave blank to keep current)</label>
            <input type="password" id="password" name="password">
        </div>
        <div class="form-group">
            <label for="confirm_password">Confirm new password</label>
            <input type="password" id="confirm_password" name="confirm_password">
        </div>
        <div>
            <button type="submit" class="btn-primary">Save changes</button>
        </div>
    </form>
</div>

<?php include __DIR__ . '/layout/footer.php'; ?>

