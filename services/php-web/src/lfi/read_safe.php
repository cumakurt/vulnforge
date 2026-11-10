<?php
// @control id=LFI-001-C twin_of=LFI-001 url=/php/lfi/read_safe.php method=GET param=file service=php-web param_loc=query

/**
 * LFI-001-C: SAFE — only files from a fixed allowlist in the pages directory
 * can be read. Traversal sequences are rejected before any filesystem access.
 */

$allowed = ['home.txt', 'about.txt', 'contact.txt'];
$file    = $_GET['file'] ?? 'home.txt';

header('Content-Type: text/plain; charset=utf-8');

if (!in_array($file, $allowed, true)) {
    http_response_code(400);
    echo "Invalid page.\n";
    exit;
}

readfile(__DIR__ . '/../data/pages/' . $file);
