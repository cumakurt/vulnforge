<?php
// @vuln id=SQLI-003 name="Boolean-blind SQL Injection in product lookup" cwe=CWE-89 owasp=A03:2021 type=boolean-blind level=2 param=id method=GET service=php-web url=/php/sqli/blind.php param_loc=query needs_oob=false auth=false detection=active tags=injection,database,mysql,blind proof_kind=diff proof_desc="Response body differs for true vs false conditions (product found vs not found)"

/**
 * SQLI-003: Boolean-based Blind SQL Injection — Numeric parameter
 * Level: L2 (error messages suppressed, only boolean difference visible)
 *
 * Payload (true):  ?id=1 AND 1=1--     → product returned
 * Payload (false): ?id=1 AND 1=2--     → no product
 * Data exfil:      ?id=1 AND SUBSTRING(user(),1,1)='r'--
 */

require_once __DIR__ . '/../common/db.php';
require_once __DIR__ . '/../common/lab.php';

header('Content-Type: application/json');

$id = $_GET['id'] ?? '1';

// !! INTENTIONALLY VULNERABLE — no error disclosure (blind), but query is injectable !!
$conn = get_db();
$sql  = "SELECT id, name, description, price FROM products WHERE id = $id";

$result = @$conn->query($sql);  // suppress PHP warnings

if (!$result || $conn->error) {
    // Generic error — no details (makes it blind)
    echo json_encode(['product' => null]);
    lab_trigger('SQLI-003', get_request_id(), ['type' => 'error', 'payload' => $id]);
    exit;
}

$row = $result->fetch_assoc();

if ($row) {
    lab_trigger('SQLI-003', get_request_id(), ['type' => 'boolean_true', 'payload' => $id]);
}

echo json_encode(['product' => $row]);
