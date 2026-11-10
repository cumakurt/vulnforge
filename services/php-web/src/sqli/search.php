<?php
// @vuln id=SQLI-002 name="Union-based SQL Injection in product search" cwe=CWE-89 owasp=A03:2021 type=union-based level=1 param=q method=GET service=php-web url=/php/sqli/search.php param_loc=query needs_oob=false auth=false detection=active tags=injection,database,mysql,union proof_kind=marker proof_desc="UNION SELECT output visible alongside product results"

/**
 * SQLI-002: Union-based SQL Injection — String parameter in LIKE clause
 * Level: L1 (no filter, UNION extraction works directly)
 *
 * Payload: ?q=x' UNION SELECT 1,user(),version(),4,5,6-- -
 */

require_once __DIR__ . '/../common/db.php';
require_once __DIR__ . '/../common/lab.php';

header('Content-Type: application/json');

$q = $_GET['q'] ?? '';

// !! INTENTIONALLY VULNERABLE !!
$conn = get_db();
$sql  = "SELECT id, name, description, price, category, stock FROM products WHERE name LIKE '%$q%'";

$result = $conn->query($sql);

if ($conn->error) {
    http_response_code(500);
    echo json_encode(['error' => $conn->error]);
    lab_trigger('SQLI-002', get_request_id(), ['payload' => $q]);
    exit;
}

$rows = [];
while ($row = $result->fetch_assoc()) {
    $rows[] = $row;
}

if (count($rows) > 0) {
    lab_trigger('SQLI-002', get_request_id(), ['rows_returned' => count($rows), 'payload' => $q]);
}

echo json_encode(['results' => $rows]);
