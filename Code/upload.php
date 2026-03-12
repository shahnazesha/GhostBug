<?php
require_once __DIR__ . '/config.php';
require_login();

$user = current_user();
$error = '';
$success = '';

// Ensure uploads directory exists
$uploadDir = __DIR__ . '/uploads';
if (!is_dir($uploadDir)) {
    mkdir($uploadDir, 0775, true);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_FILES['pcap']) || $_FILES['pcap']['error'] !== UPLOAD_ERR_OK) {
        $error = 'Please choose a PCAP file to upload.';
    } else {
        $file = $_FILES['pcap'];

        // basic validation
        $maxSize = 50 * 1024 * 1024; // 50MB
        if ($file['size'] <= 0 || $file['size'] > $maxSize) {
            $error = 'File size must be between 1 byte and 50MB.';
        } else {
            $originalName = $file['name'];
            $ext = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));
            if (!in_array($ext, ['pcap', 'pcapng'])) {
                $error = 'Only .pcap or .pcapng files are allowed.';
            } else {
                $storedName = uniqid('pcap_', true) . '.' . $ext;
                $storedPath = $uploadDir . DIRECTORY_SEPARATOR . $storedName;
                if (!move_uploaded_file($file['tmp_name'], $storedPath)) {
                    $error = 'Failed to store uploaded file.';
                } else {
                    $pdo = get_db_connection();
                    $stmt = $pdo->prepare('INSERT INTO pcap_uploads (user_id, original_filename, stored_path, filesize_bytes, status) VALUES (:uid, :orig, :path, :size, "pending")');
                    $stmt->execute([
                        ':uid' => $user['id'],
                        ':orig' => $originalName,
                        ':path' => $storedName,
                        ':size' => $file['size'],
                    ]);
                    $uploadId = (int)$pdo->lastInsertId();

                    // Call Python analyzer synchronously for simplicity
                    $pythonScript = __DIR__ . DIRECTORY_SEPARATOR . 'python' . DIRECTORY_SEPARATOR . 'analyze_pcap.py';
                    if (!is_file($pythonScript)) {
                        $error = 'Analysis script failed: analyzer script not found.';
                        $pdo->prepare('UPDATE pcap_uploads SET status = "failed" WHERE id = ?')->execute([$uploadId]);
                    }

                    $pythonExecutable = null;
                    if ($error === '') {
                        $pythonCandidates = [];
                        $envPython = getenv('NETWORK_IDS_PYTHON_EXE');
                        if (is_string($envPython) && trim($envPython) !== '') {
                            $pythonCandidates[] = trim($envPython);
                        }
                        if (defined('PYTHON_EXECUTABLE') && is_string(PYTHON_EXECUTABLE) && trim(PYTHON_EXECUTABLE) !== '') {
                            $pythonCandidates[] = trim(PYTHON_EXECUTABLE);
                        }
                        $pythonCandidates[] = 'py';
                        $pythonCandidates[] = 'python';
                        $pythonCandidates[] = 'python3';

                        foreach ($pythonCandidates as $cand) {
                            if (strpos($cand, '\\') !== false || strpos($cand, '/') !== false) {
                                if (!is_file($cand)) {
                                    continue;
                                }
                            }
                            $testCmd = escapeshellarg($cand) . ' --version';
                            $testProc = @proc_open($testCmd, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $testPipes, __DIR__);
                            if (is_resource($testProc)) {
                                @stream_get_contents($testPipes[1]);
                                @stream_get_contents($testPipes[2]);
                                @fclose($testPipes[1]);
                                @fclose($testPipes[2]);
                                $testExit = @proc_close($testProc);
                                if ($testExit === 0) {
                                    $pythonExecutable = $cand;
                                    break;
                                }
                            }
                        }

                        if ($pythonExecutable === null) {
                            $error = 'Analysis script failed: Python executable not found. Set NETWORK_IDS_PYTHON_EXE env var or PYTHON_EXECUTABLE in config.php.';
                            $pdo->prepare('UPDATE pcap_uploads SET status = "failed" WHERE id = ?')->execute([$uploadId]);
                        }
                    }

                    if ($error === '') {
                        $cmd = escapeshellarg($pythonExecutable) . ' ' .
                            escapeshellarg($pythonScript) . ' ' .
                            escapeshellarg($storedName) . ' ' .
                            escapeshellarg((string)$uploadId);

                        // pass working directory as project root so script can locate config/db params via CLI env
                        $descriptorSpec = [
                            1 => ['pipe', 'w'],
                            2 => ['pipe', 'w'],
                        ];
                        $process = proc_open($cmd, $descriptorSpec, $pipes, __DIR__);
                        if (is_resource($process)) {
                            $stdout = stream_get_contents($pipes[1]);
                            $stderr = stream_get_contents($pipes[2]);
                            fclose($pipes[1]);
                            fclose($pipes[2]);
                            $exitCode = proc_close($process);
                            if ($exitCode !== 0) {
                                $error = 'Analysis script failed: ' . htmlspecialchars($stderr);
                                // mark upload failed
                                $pdo->prepare('UPDATE pcap_uploads SET status = "failed" WHERE id = ?')->execute([$uploadId]);
                            } else {
                                $success = 'Upload and analysis completed. See results in the dashboard.';
                            }
                        } else {
                            $error = 'Failed to start analysis script.';
                            $pdo->prepare('UPDATE pcap_uploads SET status = "failed" WHERE id = ?')->execute([$uploadId]);
                        }
                    }
                }
            }
        }
    }
}

include __DIR__ . '/layout/header.php';
?>

<div class="card">
    <div class="card-header">
        <div>
            <div class="card-title">Upload PCAP</div>
            <div class="card-subtitle">Upload a capture file to run rule-based intrusion analysis</div>
        </div>
    </div>

    <?php if ($error): ?>
        <div class="alert alert-error"><?php echo $error; ?></div>
    <?php endif; ?>
    <?php if ($success): ?>
        <div class="alert alert-success"><?php echo $success; ?></div>
    <?php endif; ?>

    <form method="post" enctype="multipart/form-data" class="form-grid">
        <div class="form-group">
            <label for="pcap">PCAP file (.pcap, .pcapng, max 50MB)</label>
            <input type="file" id="pcap" name="pcap" accept=".pcap,.pcapng" required>
        </div>
        <div>
            <button type="submit" class="btn-primary">Upload &amp; Analyze</button>
        </div>
    </form>
</div>

<?php include __DIR__ . '/layout/footer.php'; ?>

