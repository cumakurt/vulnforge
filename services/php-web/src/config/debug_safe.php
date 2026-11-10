<?php
// @control id=CONF-001-C twin_of=CONF-001 url=/php/config/debug_safe.php method=GET param=input service=php-web param_loc=query

/**
 * CONF-001-C: SAFE — display_errors is disabled and the client only receives a
 * generic error with a correlation id.
 */

ini_set('display_errors', '0');
error_reporting(E_ALL);

header('Content-Type: application/json');

$input = $_GET['input'] ?? '';
$correlation_id = bin2hex(random_bytes(8));

if ($input !== '') {
    error_log("[$correlation_id] input rejected");
    http_response_code(400);
    echo json_encode(['error' => 'request could not be processed', 'correlation_id' => $correlation_id]);
    exit;
}

echo json_encode(['status' => 'ok']);
