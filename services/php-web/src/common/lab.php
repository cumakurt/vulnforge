<?php
/**
 * VulnForge Lab — helper to notify lab-control of triggered vulnerabilities.
 * Called by vulnerable endpoints when exploitation is detected/triggered.
 */

function lab_trigger(string $vuln_id, string $request_id = '', array $extra = []): void {
    $lab_control = getenv('LAB_CONTROL_URL') ?: 'http://lab-control:9100';

    $payload = json_encode(array_merge([
        'kind'       => 'vuln_triggered',
        'vuln_id'    => $vuln_id,
        'service'    => 'php-web',
        'request_id' => $request_id ?: ($_SERVER['HTTP_X_REQUEST_ID'] ?? ''),
        'ts'         => (new DateTimeImmutable())->format('Y-m-d\TH:i:s.uP'),
    ], $extra));

    // Fire-and-forget via non-blocking socket
    $context = stream_context_create([
        'http' => [
            'method'  => 'POST',
            'header'  => "Content-Type: application/json\r\nContent-Length: " . strlen($payload),
            'content' => $payload,
            'timeout' => 1,
            'ignore_errors' => true,
        ],
    ]);

    @file_get_contents("$lab_control/__lab/events", false, $context);
}

/**
 * Returns the unique request ID passed by the gateway.
 */
function get_request_id(): string {
    return $_SERVER['HTTP_X_REQUEST_ID'] ?? '';
}
