<?php
// @control id=XSS-003-C twin_of=XSS-003 url=/php/xss/dom_safe.php method=GET param=hash service=php-web param_loc=fragment

/**
 * XSS-003-C: SAFE — fragment is written with textContent, never parsed as HTML.
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
  var fragment = decodeURIComponent(window.location.hash.slice(1));
  if (fragment) {
    // SAFE: textContent treats the fragment as inert text.
    document.getElementById('output').textContent = fragment;
  }
</script>
</body>
</html>
