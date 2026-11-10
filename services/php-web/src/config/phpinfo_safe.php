<?php
// @control id=CONF-002-C twin_of=CONF-002 url=/php/config/phpinfo_safe.php method=GET param=section service=php-web param_loc=query

/**
 * CONF-002-C: SAFE — no diagnostic output is exposed to clients.
 */

header('Content-Type: application/json');

http_response_code(404);
echo json_encode(['error' => 'not found']);
