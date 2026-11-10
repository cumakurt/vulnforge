<?php
// @vuln id=UPLOAD-001 name="Unrestricted file upload leads to code execution" cwe=CWE-434 owasp=A08:2021 type=unrestricted-upload level=1 param=file method=POST service=php-web url=/php/upload/upload.php param_loc=multipart needs_oob=false auth=false detection=active tags=file,upload,rce proof_kind=marker proof_desc="An uploaded .php file is stored under the web root and executes when requested"

/**
 * UPLOAD-001: Unrestricted file upload.
 * Level: L1 (original filename kept, no extension/MIME/magic-byte checks)
 *
 * Step 1: POST multipart file=@shell.php
 * Step 2: GET /php/uploads/shell.php?cmd=id
 */

require_once __DIR__ . '/../common/lab.php';

header('Content-Type: application/json');

if (!isset($_FILES['file'])) {
    http_response_code(400);
    echo json_encode(['error' => 'file field required']);
    exit;
}

$file = $_FILES['file'];
if ($file['error'] !== UPLOAD_ERR_OK) {
    http_response_code(400);
    echo json_encode(['error' => 'upload failed', 'code' => $file['error']]);
    exit;
}

$uploads_dir = __DIR__ . '/../uploads';
if (!is_dir($uploads_dir)) {
    mkdir($uploads_dir, 0777, true);
}

// !! INTENTIONALLY VULNERABLE — client-supplied filename is trusted !!
$destination = $uploads_dir . '/' . basename($file['name']);

if (!move_uploaded_file($file['tmp_name'], $destination)) {
    http_response_code(500);
    echo json_encode(['error' => 'could not store file']);
    exit;
}

lab_trigger('UPLOAD-001', get_request_id(), ['filename' => $file['name']]);

echo json_encode([
    'uploaded' => true,
    'filename' => $file['name'],
    'url'      => '/php/uploads/' . rawurlencode($file['name']),
]);
