<?php
// @vuln id=LFI-001 name="Path traversal in page loader" cwe=CWE-22 owasp=A01:2021 type=path-traversal level=1 param=file method=GET service=php-web url=/php/lfi/read.php param_loc=query needs_oob=false auth=false detection=active tags=file,lfi,traversal proof_kind=marker proof_desc="Arbitrary files such as /etc/passwd can be read"

/**
 * LFI-001: Local file inclusion / path traversal.
 * Level: L1 (no normalisation, no allowlist)
 *
 * Payload: ?file=../../../etc/passwd
 */

require_once __DIR__ . '/../common/lab.php';

$file = $_GET['file'] ?? 'home.txt';
$path = __DIR__ . '/../data/pages/' . $file;

if (str_contains($file, '..') || str_starts_with($file, '/')) {
    lab_trigger('LFI-001', get_request_id(), ['payload' => $file]);
}

header('Content-Type: text/plain; charset=utf-8');

if (!is_file($path)) {
    http_response_code(404);
    echo "Page not found: $file\n";
    exit;
}

readfile($path);
