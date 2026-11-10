<?php
// @vuln id=CMDI-001 name="OS command injection in network diagnostics" cwe=CWE-78 owasp=A03:2021 type=os-command level=1 param=host method=GET service=php-web url=/php/cmdi/ping.php param_loc=query needs_oob=false auth=false detection=active tags=injection,command,rce proof_kind=marker proof_desc="Injected shell metacharacters execute and their output appears in the response"

/**
 * CMDI-001: OS command injection — user input concatenated into a shell command.
 * Level: L1 (no filtering, command output returned)
 *
 * Payloads: ?host=127.0.0.1;id      ?host=$(id)      ?host=`id`
 *
 * The lab only executes harmless echo/id commands; there is no host mount and
 * the container runs with no-new-privileges.
 */

require_once __DIR__ . '/../common/lab.php';

header('Content-Type: application/json');

$host = $_GET['host'] ?? '127.0.0.1';

// !! INTENTIONALLY VULNERABLE — unescaped input passed to the shell !!
$output = shell_exec('echo ' . $host . ' 2>&1');

if (preg_match('/[;&|`$()]/', $host)) {
    lab_trigger('CMDI-001', get_request_id(), ['payload' => $host]);
}

echo json_encode(['host' => $host, 'output' => $output]);
