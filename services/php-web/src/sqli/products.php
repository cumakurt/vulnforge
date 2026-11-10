<?php
// @vuln id=SQLI-001 name="Error-based SQL Injection in product lookup" cwe=CWE-89 owasp=A03:2021 type=error-based level=1 param=id method=GET service=php-web url=/php/sqli/products.php param_loc=query needs_oob=false auth=false detection=active tags=injection,database,mysql proof_kind=marker proof_desc="MySQL error message or version() output visible in response"

/**
 * SQLI-001: Error-based SQL Injection — Numeric parameter, no filter
 * Level: L1 (no filter, error messages visible)
 *
 * Vulnerable: ?id=1 OR 1=1--
 * Evidence:   MySQL error or version() in response body
 */

require_once __DIR__ . '/../common/db.php';
require_once __DIR__ . '/../common/lab.php';

header('Content-Type: application/json');

$id = $_GET['id'] ?? '1';

// !! INTENTIONALLY VULNERABLE — raw user input in SQL query !!
$conn = get_db();
$sql  = "SELECT id, name, description, price, category, stock FROM products WHERE id = $id";

$result = $conn->query($sql);  // Error message visible on failure

if ($conn->error) {
    // Intentional: expose DB error to client (CWE-209)
    http_response_code(500);
    echo json_encode([
        'error' => $conn->error,
        'query' => $sql,          // Intentional query disclosure
    ]);
    lab_trigger('SQLI-001', get_request_id(), ['payload' => $id]);
    exit;
}

$rows = [];
while ($row = $result->fetch_assoc()) {
    $rows[] = $row;
}

// Trigger marker: if attacker extracts version/data, it appears in results
if (!empty($rows)) {
    lab_trigger('SQLI-001', get_request_id(), ['rows_returned' => count($rows), 'payload' => $id]);
}

echo json_encode(['products' => $rows, 'query' => $sql]);
