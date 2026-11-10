<?php
// @vuln id=SQLI-007 name="Header-based SQL Injection via X-Forwarded-For" cwe=CWE-89 owasp=A03:2021 type=header-injection level=2 param=X-Forwarded-For method=GET service=php-web url=/php/sqli/header_inject.php param_loc=header needs_oob=false auth=false detection=passive tags=injection,database,mysql,header proof_kind=marker proof_desc="X-Forwarded-For header value injected into access log query, error or data visible"

/**
 * SQLI-007: SQL Injection via HTTP Header (X-Forwarded-For)
 * Level: L2 — scanner must inject via headers, not standard params
 *
 * Payload: X-Forwarded-For: 1.1.1.1' OR '1'='1
 */

require_once __DIR__ . '/../common/db.php';
require_once __DIR__ . '/../common/lab.php';

header('Content-Type: application/json');

$ip      = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
$page    = basename($_SERVER['REQUEST_URI']);
$conn    = get_db();

// !! INTENTIONALLY VULNERABLE — user-controlled header in SQL !!
$sql  = "INSERT INTO sessions (id, data) VALUES ('" . session_create_id() . "', 'page=$page&ip=$ip') ON DUPLICATE KEY UPDATE data = 'page=$page&ip=$ip'";
@$conn->query($sql);

// Also read back (creates error-based oracle)
$read = "SELECT data FROM sessions WHERE data LIKE '%ip=$ip%' LIMIT 1";
$result = @$conn->query($read);

if ($conn->error) {
    lab_trigger('SQLI-007', get_request_id(), ['header' => $ip]);
    echo json_encode(['error' => $conn->error]);
    exit;
}

echo json_encode(['logged' => true, 'ip' => $ip]);
