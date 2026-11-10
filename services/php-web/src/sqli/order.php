<?php
// @vuln id=SQLI-005 name="ORDER BY SQL Injection in product sorting" cwe=CWE-89 owasp=A03:2021 type=order-by-injection level=1 param=sort method=GET service=php-web url=/php/sqli/order.php param_loc=query needs_oob=false auth=false detection=active tags=injection,database,mysql,order-by proof_kind=marker proof_desc="Column index-based UNION or error triggers on arbitrary ORDER BY value"

/**
 * SQLI-005: ORDER BY injection — common in sort parameters
 * Level: L1 (no filter)
 *
 * Payload: ?sort=1 DESC, SLEEP(5)--
 *          ?sort=(SELECT 1 FROM (SELECT SLEEP(3))x)
 */

require_once __DIR__ . '/../common/db.php';
require_once __DIR__ . '/../common/lab.php';

header('Content-Type: application/json');

$sort = $_GET['sort'] ?? 'id';

// !! INTENTIONALLY VULNERABLE — sort column not whitelisted !!
$conn = get_db();
$sql  = "SELECT id, name, price, category FROM products ORDER BY $sort";
$result = @$conn->query($sql);

if ($conn->error) {
    echo json_encode(['error' => $conn->error]);
    lab_trigger('SQLI-005', get_request_id(), ['payload' => $sort]);
    exit;
}

$rows = [];
while ($row = $result->fetch_assoc()) {
    $rows[] = $row;
}
lab_trigger('SQLI-005', get_request_id(), ['payload' => $sort]);
echo json_encode(['products' => $rows]);
