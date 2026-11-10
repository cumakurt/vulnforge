<?php
// @vuln id=XSS-001 name="Reflected XSS in greeting page" cwe=CWE-79 owasp=A03:2021 type=reflected level=1 param=name method=GET service=php-web url=/php/xss/reflected.php param_loc=query needs_oob=false auth=false detection=active tags=xss,client,reflected proof_kind=marker proof_desc="Raw script markup appears unencoded in the HTML response"

/**
 * XSS-001: Reflected XSS — HTML body context, no encoding.
 * Level: L1
 *
 * Payload: ?name=<script>alert(document.domain)</script>
 */

require_once __DIR__ . '/../common/lab.php';

$name = $_GET['name'] ?? 'guest';

if (preg_match('/<\s*script|onerror\s*=|onload\s*=/i', $name)) {
    lab_trigger('XSS-001', get_request_id(), ['payload' => $name]);
}
?>
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Greeting</title></head>
<body>
<h1>Hello, <?= $name ?>!</h1>
<p>Welcome to the VulnForge greeting page.</p>
</body>
</html>
