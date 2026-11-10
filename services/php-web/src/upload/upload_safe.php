<?php
// @control id=UPLOAD-001-C twin_of=UPLOAD-001 url=/php/upload/upload_safe.php method=POST param=file service=php-web param_loc=multipart

/**
 * UPLOAD-001-C: SAFE — extension/MIME allowlist, generated filename, files
 * stored outside the document root. Uploaded code can never be requested.
 */

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

$allowed_ext  = ['png', 'jpg', 'jpeg', 'gif', 'pdf', 'txt'];
$allowed_mime = ['image/png', 'image/jpeg', 'image/gif', 'application/pdf', 'text/plain'];

$ext  = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
$mime = mime_content_type($file['tmp_name']) ?: '';

if (!in_array($ext, $allowed_ext, true) || !in_array($mime, $allowed_mime, true)) {
    http_response_code(400);
    echo json_encode(['error' => 'file type not allowed']);
    exit;
}

$storage_dir = '/tmp/vulnforge-uploads';
if (!is_dir($storage_dir)) {
    mkdir($storage_dir, 0700, true);
}

$stored_name = bin2hex(random_bytes(16)) . '.' . $ext;

if (!move_uploaded_file($file['tmp_name'], $storage_dir . '/' . $stored_name)) {
    http_response_code(500);
    echo json_encode(['error' => 'could not store file']);
    exit;
}

echo json_encode(['uploaded' => true, 'reference' => $stored_name]);
