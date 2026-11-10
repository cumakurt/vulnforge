<?php
// @vuln id=CONF-001 name="Detailed exception page discloses stack trace and paths" cwe=CWE-209 owasp=A05:2021 type=verbose-error level=1 param=input method=GET service=php-web url=/php/config/debug.php param_loc=query needs_oob=false auth=false detection=config tags=misconfiguration,info-leak,error-handling proof_kind=marker proof_desc="Response includes exception class, file paths and stack trace"

/**
 * CONF-001: Verbose error handling with display_errors enabled.
 * Level: L1
 *
 * Payload: ?input=boom
 */

require_once __DIR__ . '/../common/lab.php';

ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');
error_reporting(E_ALL);

$input = $_GET['input'] ?? '';

if ($input !== '') {
    lab_trigger('CONF-001', get_request_id(), ['payload' => $input]);
    throw new RuntimeException('Unhandled application error for input: ' . $input);
}

header('Content-Type: application/json');
echo json_encode(['status' => 'ok', 'hint' => 'send ?input=value']);
