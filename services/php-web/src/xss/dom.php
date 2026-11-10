<?php
// @vuln id=XSS-003 name="DOM-based XSS through location.hash" cwe=CWE-79 owasp=A03:2021 type=dom level=2 param=hash method=GET service=php-web url=/php/xss/dom.php param_loc=fragment needs_oob=false auth=false detection=passive tags=xss,client,dom proof_kind=marker proof_desc="Fragment content is assigned to innerHTML without sanitisation"

/**
 * XSS-003: DOM-based XSS — the server never sees the payload.
 * Level: L2 (requires a JavaScript-capable crawler / DOM sink analysis)
 *
 * Payload: /php/xss/dom.php#<img src=x onerror=alert(1)>
 */

header('Content-Type: text/html; charset=utf-8');
?>
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Fragment viewer</title></head>
<body>
<h1>Fragment viewer</h1>
<div id="output">Nothing selected.</div>
<script>
  // !! INTENTIONALLY VULNERABLE — untrusted fragment flows into innerHTML !!
  var fragment = decodeURIComponent(window.location.hash.slice(1));
  if (fragment) {
    document.getElementById('output').innerHTML = fragment;
  }
</script>
</body>
</html>
