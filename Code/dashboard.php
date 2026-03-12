<?php
require_once __DIR__ . '/config.php';
require_login();

$user = current_user();
$pdo = get_db_connection();

// Metrics
if ($user['role'] === 'admin') {
    $totalUploads = (int)$pdo->query('SELECT COUNT(*) AS c FROM pcap_uploads')->fetch()['c'];
    $totalAlerts = (int)$pdo->query('SELECT COUNT(*) AS c FROM analysis_results')->fetch()['c'];
    $criticalAlerts = (int)$pdo->query("SELECT COUNT(*) AS c FROM analysis_results WHERE severity = 'critical'")->fetch()['c'];
} else {
    $uid = $user['id'];
    $stmt = $pdo->prepare('SELECT COUNT(*) AS c FROM pcap_uploads WHERE user_id = ?');
    $stmt->execute([$uid]);
    $totalUploads = (int)$stmt->fetch()['c'];

    $stmt = $pdo->prepare(
        'SELECT COUNT(*) AS c FROM analysis_results ar 
         JOIN pcap_uploads pu ON ar.upload_id = pu.id 
         WHERE pu.user_id = ?'
    );
    $stmt->execute([$uid]);
    $totalAlerts = (int)$stmt->fetch()['c'];

    $stmt = $pdo->prepare(
        "SELECT COUNT(*) AS c FROM analysis_results ar 
         JOIN pcap_uploads pu ON ar.upload_id = pu.id 
         WHERE pu.user_id = ? AND ar.severity = 'critical'"
    );
    $stmt->execute([$uid]);
    $criticalAlerts = (int)$stmt->fetch()['c'];
}

// Recent uploads
if ($user['role'] === 'admin') {
    $uploadsStmt = $pdo->query(
        'SELECT pu.*, u.username 
         FROM pcap_uploads pu 
         JOIN users u ON pu.user_id = u.id 
         ORDER BY pu.created_at DESC 
         LIMIT 10'
    );
} else {
    $uploadsStmt = $pdo->prepare(
        'SELECT pu.*, u.username 
         FROM pcap_uploads pu 
         JOIN users u ON pu.user_id = u.id 
         WHERE pu.user_id = ? 
         ORDER BY pu.created_at DESC 
         LIMIT 10'
    );
    $uploadsStmt->execute([$user['id']]);
}
$uploads = $uploadsStmt->fetchAll();

// Get search parameters for alerts
$search_timestamp = trim($_GET['timestamp'] ?? '');

// Recent alerts (with rule descriptions)
$alertsWhereClause = '';
$alertsParams = [];

if ($user['role'] !== 'admin') {
    $alertsWhereClause = 'WHERE pu.user_id = ?';
    $alertsParams[] = $user['id'];
}

if ($search_timestamp !== '') {
    $alertsWhereClause .= ($alertsWhereClause ? ' AND ' : 'WHERE ') . 'ar.packet_timestamp LIKE ?';
    $alertsParams[] = '%' . $search_timestamp . '%';
}

if ($user['role'] === 'admin') {
    $alertsStmt = $pdo->prepare(
        "SELECT ar.*, r.name AS rule_name, r.description AS rule_description, pu.original_filename, pu.id AS upload_id, u.username 
         FROM analysis_results ar 
         LEFT JOIN ids_rules r ON ar.rule_id = r.id 
         JOIN pcap_uploads pu ON ar.upload_id = pu.id 
         JOIN users u ON pu.user_id = u.id 
         $alertsWhereClause
         ORDER BY ar.packet_timestamp DESC, ar.created_at DESC 
         LIMIT 15"
    );
} else {
    $alertsStmt = $pdo->prepare(
        "SELECT ar.*, r.name AS rule_name, r.description AS rule_description, pu.original_filename, pu.id AS upload_id, u.username 
         FROM analysis_results ar 
         LEFT JOIN ids_rules r ON ar.rule_id = r.id 
         JOIN pcap_uploads pu ON ar.upload_id = pu.id 
         JOIN users u ON pu.user_id = u.id 
         $alertsWhereClause
         ORDER BY ar.packet_timestamp DESC, ar.created_at DESC 
         LIMIT 15"
    );
}
$alertsStmt->execute($alertsParams);
$alerts = $alertsStmt->fetchAll();

include __DIR__ . '/layout/header.php';
?>

    <div class="card" style="margin-bottom: 1.5rem;">
    <div class="card-header">
        <div>
            <div class="card-title">GhostBug overview</div>
            <div class="card-subtitle">
                <?php echo $user['role'] === 'admin' ? 'Global GhostBug network intrusion activity' : 'Your GhostBug PCAP analyses and alerts'; ?>
            </div>
        </div>
        <div style="display: flex; gap: 0.75rem; align-items: center;">
            <a href="<?php echo BASE_URL; ?>/how_it_works.php" style="font-size: 0.8rem; color: #9ca3af; text-decoration: none;">How it works</a>
            <a href="<?php echo BASE_URL; ?>/upload.php" class="btn-primary">New upload</a>
        </div>
    </div>

    <div class="metrics-grid">
        <div class="metric-card">
            <div class="metric-label">Total uploads</div>
            <div class="metric-value"><?php echo $totalUploads; ?></div>
        </div>
        <div class="metric-card">
            <div class="metric-label">Total alerts</div>
            <div class="metric-value"><?php echo $totalAlerts; ?></div>
        </div>
        <div class="metric-card">
            <div class="metric-label">Critical alerts</div>
            <div class="metric-value"><?php echo $criticalAlerts; ?></div>
        </div>
    </div>
</div>

<div class="metrics-grid">
    <div class="metric-card">
        <div class="card-header" style="padding:0; margin-bottom:0.6rem;">
            <div class="card-title" style="font-size:0.95rem;">Recent uploads</div>
        </div>
        <table class="table">
            <thead>
            <tr>
                <th>File</th>
                <?php if ($user['role'] === 'admin'): ?>
                    <th>User</th>
                <?php endif; ?>
                <th>Status</th>
                <th>Size</th>
                <th>Created</th>
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

    <div class="metric-card">
        <div class="card-header" style="padding:0; margin-bottom:0.6rem;">
            <div class="card-title" style="font-size:0.95rem;">Recent alerts</div>
        </div>
        <div style="font-size: 0.75rem; color: #9ca3af; margin-bottom: 0.5rem;">
            Rule descriptions shown below each alert. <a href="<?php echo BASE_URL; ?>/how_it_works.php" style="color: #0ea5e9;">Learn more</a>
        </div>
        
        <form method="get" class="form-grid" style="margin-bottom: 1rem;">
            <div class="form-group">
                <label for="timestamp" style="font-size: 0.8rem;">Search by TIMESTAMP</label>
                <input type="text" id="timestamp" name="timestamp" value="<?php echo htmlspecialchars($search_timestamp); ?>" placeholder="e.g. 2024-01-15 or 2024-01-15 10:30" style="font-size: 0.85rem; padding: 0.4rem;">
            </div>
            <div>
                <button type="submit" class="btn-primary" style="font-size: 0.85rem; padding: 0.4rem 0.8rem;">Search</button>
                <?php if ($search_timestamp !== ''): ?>
                    <a href="<?php echo BASE_URL; ?>/dashboard.php" class="btn-primary" style="margin-left: 0.5rem; background: #6b7280; font-size: 0.85rem; padding: 0.4rem 0.8rem;">Clear</a>
                <?php endif; ?>
            </div>
        </form>
        
        <table class="table">
            <thead>
            <tr>
                <th>Rule</th>
                <th>Severity</th>
                <th>Flow</th>
                <th>TIMESTAMP</th>
                <th>File</th>
            </tr>
            </thead>
            <tbody>
            <?php foreach ($alerts as $al): ?>
                <tr>
                    <td>
                        <div style="font-weight: 500;"><?php echo htmlspecialchars($al['rule_name'] ?? 'Ad-hoc'); ?></div>
                        <?php if (!empty($al['rule_description'])): ?>
                            <div style="font-size: 0.75rem; color: #9ca3af; margin-top: 0.25rem;">
                                <?php echo htmlspecialchars($al['rule_description']); ?>
                            </div>
                        <?php endif; ?>
                    </td>
                    <td>
                        <span class="badge <?php
                            echo $al['severity'] === 'critical' ? 'badge-critical' :
                                ($al['severity'] === 'warning' ? 'badge-warning' : 'badge-info');
                        ?>">
                            <?php echo htmlspecialchars($al['severity']); ?>
                        </span>
                    </td>
                    <td>
                        <?php echo htmlspecialchars(($al['src_ip'] ?? '?') . ' → ' . ($al['dst_ip'] ?? '?')); ?>
                        <?php if ($al['dst_port']): ?>
                            :<?php echo (int)$al['dst_port']; ?>
                        <?php endif; ?>
                    </td>
                    <td><?php echo htmlspecialchars($al['packet_timestamp'] ?? 'N/A'); ?></td>
                    <td>
                        <a href="<?php echo BASE_URL; ?>/view_alerts.php?upload_id=<?php echo (int)$al['upload_id']; ?>" style="color: #0ea5e9; text-decoration: none;">
                            <?php echo htmlspecialchars($al['original_filename']); ?>
                        </a>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>

<?php include __DIR__ . '/layout/footer.php'; ?>

