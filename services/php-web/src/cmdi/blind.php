<?php
// @vuln id=CMDI-002 name="Blind time-based OS command injection" cwe=CWE-78 owasp=A03:2021 type=blind-time level=2 param=host method=GET service=php-web url=/php/cmdi/blind.php param_loc=query needs_oob=false auth=false detection=active tags=injection,command,blind,time proof_kind=diff proof_desc="Response time exceeds 3 seconds when a sleep command is injected"

/**
 * CMDI-002: Blind OS command injection — no command output is returned, the
 * only observable signal is response timing.
 * Level: L2
 *
 * Payload: ?host=127.0.0.1;sleep 5
 */

require_once __DIR__ . '/../common/lab.php';

header('Content-Type: application/json');

$host  = $_GET['host'] ?? '127.0.0.1';
$start = microtime(true);

// !! INTENTIONALLY VULNERABLE — output discarded, command still concatenated !!
@shell_exec('echo ' . $host . ' >/dev/null 2>&1');

$elapsed = microtime(true) - $start;

if ($elapsed >= 3.0) {
    lab_trigger('CMDI-002', get_request_id(), [
        'elapsed' => round($elapsed, 2),
        'payload' => $host,
    ]);
}

echo json_encode(['host' => $host, 'status' => 'checked']);
