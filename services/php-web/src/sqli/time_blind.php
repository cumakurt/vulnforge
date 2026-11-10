<?php
// @vuln id=SQLI-004 name="Time-based blind SQL Injection in product lookup" cwe=CWE-89 owasp=A03:2021 type=time-based-blind level=2 param=id method=GET service=php-web url=/php/sqli/time_blind.php param_loc=query needs_oob=false auth=false detection=active tags=injection,database,mysql,blind,time proof_kind=diff proof_desc="Response time ≥5s when condition is true (SLEEP injected)"

/**
 * SQLI-004: Time-based Blind SQL Injection
 * Level: L2 (no error, no boolean difference — only timing)
 *
 * Payload: ?id=1 AND SLEEP(5)--
 * Data exfil: ?id=1 AND IF(SUBSTRING(user(),1,1)='r',SLEEP(5),0)--
 */

require_once __DIR__ . '/../common/db.php';
require_once __DIR__ . '/../common/lab.php';

header('Content-Type: application/json');

$id    = $_GET['id'] ?? '1';
$start = microtime(true);

$conn = get_db();
$sql  = "SELECT id, name FROM products WHERE id = $id";
@$conn->query($sql);

$elapsed = microtime(true) - $start;

if ($elapsed >= 3.0) {
    lab_trigger('SQLI-004', get_request_id(), ['type' => 'time_delay', 'elapsed' => round($elapsed, 2), 'payload' => $id]);
}

// Always return the same empty-ish response (makes blind)
echo json_encode(['product' => null]);
