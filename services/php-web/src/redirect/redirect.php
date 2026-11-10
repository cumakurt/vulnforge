<?php
// @vuln id=REDIR-001 name="Open redirect in post-login navigation" cwe=CWE-601 owasp=A01:2021 type=open-redirect level=1 param=next method=GET service=php-web url=/php/redirect/redirect.php param_loc=query needs_oob=false auth=false detection=active tags=redirect,client proof_kind=marker proof_desc="Location header points to an arbitrary external host supplied by the client"

/**
 * REDIR-001: Open redirect — the "next" parameter is used as the Location
 * header without any host validation.
 * Level: L1
 *
 * Payload: ?next=https://evil.example/
 */

require_once __DIR__ . '/../common/lab.php';

$next = $_GET['next'] ?? '/php/';

if (preg_match('#^(https?:)?//#i', $next) || str_starts_with($next, 'javascript:')) {
    lab_trigger('REDIR-001', get_request_id(), ['payload' => $next]);
}

header('Location: ' . $next, true, 302);
echo 'Redirecting to ' . htmlspecialchars($next, ENT_QUOTES, 'UTF-8');
