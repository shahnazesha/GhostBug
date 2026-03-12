<?php
require_once __DIR__ . '/config.php';
require_login();

$user = current_user();
if ($user['role'] !== 'admin') {
    http_response_code(403);
    echo 'Access denied.';
    exit;
}

$pdo = get_db_connection();
$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name = trim($_POST['name'] ?? '');
    $description = trim($_POST['description'] ?? '');
    $severity = $_POST['severity'] ?? 'warning';
    $rule_type = $_POST['rule_type'] ?? 'dst_port';
    $match_value = trim($_POST['match_value'] ?? '');
    $enabled = isset($_POST['enabled']) ? 1 : 0;

    if ($name === '' || $match_value === '') {
        $error = 'Name and match value are required.';
    } else {
        $stmt = $pdo->prepare('INSERT INTO ids_rules (name, description, severity, enabled, rule_type, match_value) VALUES (:n, :d, :s, :e, :t, :v)');
        $stmt->execute([
            ':n' => $name,
            ':d' => $description !== '' ? $description : null,
            ':s' => $severity,
            ':e' => $enabled,
            ':t' => $rule_type,
            ':v' => $match_value,
        ]);
        $success = 'Rule added.';
    }
}

// toggle enable/disable or delete via GET parameters (simple admin actions)
if (isset($_GET['toggle'])) {
    $id = (int)$_GET['toggle'];
    $pdo->prepare('UPDATE ids_rules SET enabled = 1 - enabled WHERE id = ?')->execute([$id]);
    header('Location: ' . BASE_URL . '/rules.php');
    exit;
}

if (isset($_GET['delete'])) {
    $id = (int)$_GET['delete'];
    $pdo->prepare('DELETE FROM ids_rules WHERE id = ?')->execute([$id]);
    header('Location: ' . BASE_URL . '/rules.php');
    exit;
}

$rulesStmt = $pdo->query('SELECT * FROM ids_rules ORDER BY id DESC');
$rules = $rulesStmt->fetchAll();

include __DIR__ . '/layout/header.php';
?>

<div class="card">
    <div class="card-header">
        <div>
            <div class="card-title">IDS Rules</div>
            <div class="card-subtitle">Manage rule-based intrusion signatures</div>
        </div>
    </div>

    <?php if ($error): ?>
        <div class="alert alert-error"><?php echo htmlspecialchars($error); ?></div>
    <?php endif; ?>
    <?php if ($success): ?>
        <div class="alert alert-success"><?php echo htmlspecialchars($success); ?></div>
    <?php endif; ?>

    <form method="post" class="form-grid" style="margin-bottom: 1.25rem;">
        <div class="form-group">
            <label for="name">Rule name</label>
            <input type="text" id="name" name="name" required>
        </div>
        <div class="form-group">
            <label for="description">Description</label>
            <textarea id="description" name="description" rows="2"></textarea>
        </div>
        <div class="form-group">
            <label for="severity">Severity</label>
            <select id="severity" name="severity">
                <option value="info">Info</option>
                <option value="warning" selected>Warning</option>
                <option value="critical">Critical</option>
            </select>
        </div>
        <div class="form-group">
            <label for="rule_type">Rule type</label>
            <select id="rule_type" name="rule_type">
                <option value="src_ip">Source IP</option>
                <option value="dst_ip">Destination IP</option>
                <option value="src_port">Source port</option>
                <option value="dst_port" selected>Destination port</option>
                <option value="protocol">Protocol</option>
                <option value="payload_contains">Payload contains</option>
            </select>
        </div>
        <div class="form-group">
            <label for="match_value">Match value</label>
            <input type="text" id="match_value" name="match_value" required>
        </div>
        <div class="form-group">
            <label>
                <input type="checkbox" name="enabled" checked> Enabled
            </label>
        </div>
        <div>
            <button type="submit" class="btn-primary">Add rule</button>
        </div>
    </form>

    <table class="table">
        <thead>
        <tr>
            <th>ID</th>
            <th>Name</th>
            <th>Type</th>
            <th>Match</th>
            <th>Severity</th>
            <th>Status</th>
            <th></th>
        </tr>
        </thead>
        <tbody>
        <?php foreach ($rules as $r): ?>
            <tr>
                <td><?php echo (int)$r['id']; ?></td>
                <td><?php echo htmlspecialchars($r['name']); ?></td>
                <td><?php echo htmlspecialchars($r['rule_type']); ?></td>
                <td><?php echo htmlspecialchars($r['match_value']); ?></td>
                <td>
                    <span class="badge <?php
                        echo $r['severity'] === 'critical' ? 'badge-critical' :
                            ($r['severity'] === 'warning' ? 'badge-warning' : 'badge-info');
                    ?>">
                        <?php echo htmlspecialchars($r['severity']); ?>
                    </span>
                </td>
                <td><?php echo $r['enabled'] ? 'Enabled' : 'Disabled'; ?></td>
                <td>
                    <a href="<?php echo BASE_URL; ?>/rules.php?toggle=<?php echo (int)$r['id']; ?>">Toggle</a> |
                    <a href="<?php echo BASE_URL; ?>/rules.php?delete=<?php echo (int)$r['id']; ?>" onclick="return confirm('Delete this rule?');">Delete</a>
                </td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
</div>

<?php include __DIR__ . '/layout/footer.php'; ?>

