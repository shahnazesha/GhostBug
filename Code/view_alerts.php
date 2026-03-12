<?php
require_once __DIR__ . '/config.php';
require_login();

$user = current_user();
$pdo = get_db_connection();

// Get upload_id from query parameter
$upload_id = isset($_GET['upload_id']) ? (int)$_GET['upload_id'] : 0;

if ($upload_id <= 0) {
    header('Location: ' . BASE_URL . '/dashboard.php');
    exit;
}

// Verify user has access to this upload
if ($user['role'] === 'admin') {
    $uploadStmt = $pdo->prepare(
        'SELECT pu.*, u.username 
         FROM pcap_uploads pu 
         JOIN users u ON pu.user_id = u.id 
         WHERE pu.id = ?'
    );
    $uploadStmt->execute([$upload_id]);
} else {
    $uploadStmt = $pdo->prepare(
        'SELECT pu.*, u.username 
         FROM pcap_uploads pu 
         JOIN users u ON pu.user_id = u.id 
         WHERE pu.id = ? AND pu.user_id = ?'
    );
    $uploadStmt->execute([$upload_id, $user['id']]);
}

$upload = $uploadStmt->fetch();

if (!$upload) {
    header('Location: ' . BASE_URL . '/dashboard.php');
    exit;
}

// Get search parameters
$search_timestamp = trim($_GET['timestamp'] ?? '');

// Build query for alerts
$whereClause = 'ar.upload_id = ?';
$params = [$upload_id];

if ($search_timestamp !== '') {
    $whereClause .= ' AND ar.packet_timestamp LIKE ?';
    $params[] = '%' . $search_timestamp . '%';
}

if ($user['role'] === 'admin') {
    $alertsStmt = $pdo->prepare(
        "SELECT ar.*, r.name AS rule_name, r.description AS rule_description, pu.original_filename, u.username 
         FROM analysis_results ar 
         LEFT JOIN ids_rules r ON ar.rule_id = r.id 
         JOIN pcap_uploads pu ON ar.upload_id = pu.id 
         JOIN users u ON pu.user_id = u.id 
         WHERE $whereClause
         ORDER BY ar.packet_timestamp DESC, ar.created_at DESC"
    );
} else {
    $alertsStmt = $pdo->prepare(
        "SELECT ar.*, r.name AS rule_name, r.description AS rule_description, pu.original_filename, u.username 
         FROM analysis_results ar 
         LEFT JOIN ids_rules r ON ar.rule_id = r.id 
         JOIN pcap_uploads pu ON ar.upload_id = pu.id 
         JOIN users u ON pu.user_id = u.id 
         WHERE $whereClause AND pu.user_id = ?
         ORDER BY ar.packet_timestamp DESC, ar.created_at DESC"
    );
    $params[] = $user['id'];
}

$alertsStmt->execute($params);
$alerts = $alertsStmt->fetchAll();

include __DIR__ . '/layout/header.php';
?>

<div class="card" style="margin-bottom: 1.5rem;">
    <div class="card-header">
        <div>
            <div class="card-title">Alerts for: <?php echo htmlspecialchars($upload['original_filename']); ?></div>
            <div class="card-subtitle">
                <?php echo count($alerts); ?> alert(s) found
                <?php if ($user['role'] === 'admin'): ?>
                    | Uploaded by: <?php echo htmlspecialchars($upload['username']); ?>
                <?php endif; ?>
            </div>
        </div>
        <div>
            <a href="<?php echo BASE_URL; ?>/dashboard.php" class="btn-primary">Back to Dashboard</a>
        </div>
    </div>
</div>

<div class="card">
    <div class="card-header">
        <div>
            <div class="card-title">Recent alerts</div>
            <div class="card-subtitle">Alerts detected in this PCAP file</div>
        </div>
    </div>

    <form method="get" class="form-grid" style="margin-bottom: 1rem;">
        <input type="hidden" name="upload_id" value="<?php echo htmlspecialchars($upload_id); ?>">
        <div class="form-group">
            <label for="timestamp">Search by TIMESTAMP</label>
            <input type="text" id="timestamp" name="timestamp" value="<?php echo htmlspecialchars($search_timestamp); ?>" placeholder="e.g. 2024-01-15 or 2024-01-15 10:30">
        </div>
        <div>
            <button type="submit" class="btn-primary">Search</button>
            <?php if ($search_timestamp !== ''): ?>
                <a href="?upload_id=<?php echo htmlspecialchars($upload_id); ?>" class="btn-primary" style="margin-left: 0.5rem; background: #6b7280;">Clear</a>
            <?php endif; ?>
        </div>
    </form>

    <?php if (empty($alerts)): ?>
        <div style="padding: 2rem; text-align: center; color: #9ca3af;">
            <?php if ($search_timestamp !== ''): ?>
                No alerts found matching the timestamp search.
            <?php else: ?>
                No alerts found for this PCAP file.
            <?php endif; ?>
        </div>
    <?php else: ?>
        <table class="table">
            <thead>
            <tr>
                <th>Rule</th>
                <th>Severity</th>
                <th>Flow</th>
                <th>TIMESTAMP</th>
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
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
</div>

<?php include __DIR__ . '/layout/footer.php'; ?>
