<?php
/**
 * VulnForge Lab — shared DB connection helper.
 * Returns a raw mysqli connection (not PDO) intentionally,
 * so vulnerable endpoints can demonstrate raw query concatenation.
 */

// Vulnerable endpoints inspect $conn->error instead of catching exceptions.
mysqli_report(MYSQLI_REPORT_OFF);

function get_db(): mysqli {
    static $conn = null;
    if ($conn !== null) return $conn;

    $host = getenv('MYSQL_HOST') ?: 'mysql';
    $user = getenv('MYSQL_USER') ?: 'vulnlab';
    $pass = getenv('MYSQL_PASSWORD') ?: 'vulnlab_pass';
    $db   = getenv('MYSQL_DATABASE') ?: 'vulnforge';

    $conn = new mysqli($host, $user, $pass, $db);
    if ($conn->connect_error) {
        http_response_code(503);
        die(json_encode(['error' => 'DB connection failed']));
    }
    return $conn;
}

/**
 * Returns a PDO connection with prepared statement support.
 * Used by SAFE (control) endpoints.
 */
function get_pdo(): PDO {
    static $pdo = null;
    if ($pdo !== null) return $pdo;

    $host = getenv('MYSQL_HOST') ?: 'mysql';
    $user = getenv('MYSQL_USER') ?: 'vulnlab';
    $pass = getenv('MYSQL_PASSWORD') ?: 'vulnlab_pass';
    $db   = getenv('MYSQL_DATABASE') ?: 'vulnforge';

    $pdo = new PDO("mysql:host=$host;dbname=$db;charset=utf8mb4", $user, $pass, [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,
    ]);
    return $pdo;
}
