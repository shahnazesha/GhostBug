<?php
// Basic configuration for database connection and app settings

define('DB_HOST', 'localhost');
define('DB_NAME', 'network_ids');
define('DB_USER', 'root');
define('DB_PASS', '');

define('APP_NAME', 'GhostBug');
define('BASE_URL', 'http://localhost/network_ids'); // adjust if using different path

// Optional: set to an absolute python.exe path if 'py'/'python' isn't available in PATH.
// Example: define('PYTHON_EXECUTABLE', 'C:\\Python312\\python.exe');
if (!defined('PYTHON_EXECUTABLE')) {
    define('PYTHON_EXECUTABLE', '');
}

session_start();

function get_db_connection(): PDO {
    static $pdo = null;
    if ($pdo === null) {
        $dsn = 'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=utf8mb4';
        $options = [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ];
        try {
            $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
        } catch (PDOException $e) {
            die('Database connection failed: ' . htmlspecialchars($e->getMessage()));
        }
    }
    return $pdo;
}

function is_logged_in(): bool {
    return isset($_SESSION['user_id']);
}

function require_login(): void {
    if (!is_logged_in()) {
        header('Location: ' . BASE_URL . '/login.php');
        exit;
    }
}

function current_user() {
    if (!is_logged_in()) {
        return null;
    }
    if (!isset($_SESSION['user'])) {
        $pdo = get_db_connection();
        $stmt = $pdo->prepare('SELECT id, username, email, full_name, role, profile_image, created_at FROM users WHERE id = ?');
        $stmt->execute([$_SESSION['user_id']]);
        $user = $stmt->fetch();
        $_SESSION['user'] = $user;
    }
    return $_SESSION['user'];
}

