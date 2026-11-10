<?php
// @vuln id=CONF-002 name="phpinfo() exposed to unauthenticated users" cwe=CWE-200 owasp=A05:2021 type=info-disclosure level=1 param=section method=GET service=php-web url=/php/config/phpinfo.php param_loc=query needs_oob=false auth=false detection=config tags=misconfiguration,info-leak,phpinfo proof_kind=marker proof_desc="Full PHP configuration including modules, paths and environment is rendered"

/**
 * CONF-002: phpinfo() left reachable in the web root.
 * Level: L1
 */

require_once __DIR__ . '/../common/lab.php';

lab_trigger('CONF-002', get_request_id(), ['payload' => $_GET['section'] ?? 'all']);

phpinfo();
