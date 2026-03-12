<?php
require_once __DIR__ . '/config.php';

if (is_logged_in()) {
    header('Location: ' . BASE_URL . '/dashboard.php');
    exit;
}

header('Location: ' . BASE_URL . '/login.php');
exit;

