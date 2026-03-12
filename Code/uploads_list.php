<?php
require_once __DIR__ . '/config.php';
require_login();

$user = current_user();
$pdo = get_db_connection();

$q = trim($_GET['q'] ?? '');

if ($user['role'] === 'admin') {
    if ($q !== '') {
        $stmt = $pdo->prepare(
            'SELECT pu.*, u.username 
             FROM pcap_uploads pu 
             JOIN users u ON pu.user_id = u.id 
             WHERE pu.original_filename LIKE :q OR u.username LIKE :q 
             ORDER BY pu.created_at DESC'
        );
        $stmt->execute([':q' => '%' . $q . '%']);
    } else {
        $stmt = $pdo->query(
            'SELECT pu.*, u.username 
             FROM pcap_uploads pu 
             JOIN users u ON pu.user_id = u.id 
             ORDER BY pu.created_at DESC'
        );
    }
} else {
    if ($q !== '') {
        $stmt = $pdo->prepare(
            'SELECT pu.*, u.username 
             FROM pcap_uploads pu 
             JOIN users u ON pu.user_id = u.id 
             WHERE pu.user_id = :uid AND pu.original_filename LIKE :q 
             ORDER BY pu.created_at DESC'
        );
        $stmt->execute([':uid' => $user['id'], ':q' => '%' . $q . '%']);
    } else {
        $stmt = $pdo->prepare(
            'SELECT pu.*, u.username 
             FROM pcap_uploads pu 
             JOIN users u ON pu.user_id = u.id 
             WHERE pu.user_id = :uid 
             ORDER BY pu.created_at DESC'
        );
        $stmt->execute([':uid' => $user['id']]);
    }
}

$uploads = $stmt->fetchAll();

include __DIR__ . '/layout/header.php';
?>

<div class="card">
    <div class="card-header">
        <div>
            <div class="card-title">GhostBug uploads</div>
            <div class="card-subtitle">Search and browse all analyzed PCAP files</div>
        </div>
    </div>

    <form method="get" class="form-grid" style="margin-bottom: 1rem;">
        <div class="form-group">
            <label for="q">Search by filename<?php echo $user['role'] === 'admin' ? ' or username' : ''; ?></label>
            <input type="text" id="q" name="q" value="<?php echo htmlspecialchars($q); ?>" placeholder="e.g. capture, ransomware, user1">
        </div>
        <div>
            <button type="submit" class="btn-primary">Search</button>
        </div>
    </form>

    <table class="table">
        <thead>
        <tr>
            <th>File</th>
            <?php if ($user['role'] === 'admin'): ?>
                <th>User</th>
            <?php endif; ?>
            <th>Status</th>
            <th>Size</th>
            <th>Uploaded</th>
        </tr>
        </thead>
        <tbody>
            <?php foreach ($uploads as $up): ?>
                <tr>
                    <td>
                        <a href="<?php echo BASE_URL; ?>/view_alerts.php?upload_id=<?php echo (int)$up['id']; ?>" style="color: #0ea5e9; text-decoration: none;">
                            <?php echo htmlspecialchars($up['original_filename']); ?>
                        </a>
                    </td>
                    <?php if ($user['role'] === 'admin'): ?>
                        <td><?php echo htmlspecialchars($up['username']); ?></td>
                    <?php endif; ?>
                    <td><?php echo htmlspecialchars($up['status']); ?></td>
                    <td><?php echo number_format($up['filesize_bytes'] / 1024, 1); ?> KB</td>
                    <td><?php echo htmlspecialchars($up['created_at']); ?></td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
</div>

<?php include __DIR__ . '/layout/footer.php'; ?>

