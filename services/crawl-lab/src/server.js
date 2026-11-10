// VulnForge Lab — crawl-lab
//
// A small SPA plus discovery surface used to benchmark crawler coverage:
// client-side routing, robots/sitemap hints, source maps, soft-404 pages,
// infinite pagination, WebSocket and SSE endpoints.
//
// WARNING: never expose this service outside an isolated lab.

'use strict';

const http = require('node:http');
const crypto = require('node:crypto');
const { URL } = require('node:url');

const PORT = Number(process.env.PORT || 3001);

const HIDDEN_ROUTES = [
  '/spa/#/dashboard',
  '/spa/#/settings',
  '/spa/panel',
  '/spa/api/products?page=1',
  '/spa/api/export',
  '/spa/events',
];

function labTrigger(vulnId, req, extra = {}) {
  const body = JSON.stringify({
    kind: 'vuln_triggered',
    vuln_id: vulnId,
    service: 'crawl-lab',
    request_id: req.headers['x-request-id'] || '',
    ts: new Date().toISOString(),
    ...extra,
  });

  fetch(`${process.env.LAB_CONTROL_URL || 'http://lab-control:9100'}/__lab/events`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body,
    signal: AbortSignal.timeout(1000),
  }).catch(() => {});
}

function send(res, status, body, type = 'text/html; charset=utf-8', headers = {}) {
  res.writeHead(status, { 'content-type': type, ...headers });
  res.end(body);
}

const INDEX_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>VulnForge Shop SPA</title>
<base href="/spa/">
</head>
<body>
<div id="app">Loading…</div>
<a href="#/dashboard">Dashboard</a>
<a href="#/settings">Settings</a>
<a data-href="/spa/panel">Support panel</a>
<script src="/spa/app.js"></script>
<script>
  // Route table duplicated in the bundle so scanners can recover it from JS.
  window.__ROUTES__ = ['#/dashboard', '#/settings', '#/orders'];
</script>
</body>
</html>`;

const APP_JS = `// VulnForge Shop SPA bundle
// Internal integration key used by the legacy export widget.
const INTERNAL_API_KEY = 'vulnforge_spa_internal_key_9f2c';
const INTERNAL_ENDPOINT = '/spa/panel';
const EXPORT_ENDPOINT = '/spa/api/export';

function navigate(hash) {
  document.getElementById('app').innerHTML = 'Route: ' + hash;
}

window.addEventListener('hashchange', () => navigate(location.hash));
navigate(location.hash || '#/dashboard');

fetch('/spa/api/products?page=1').then((response) => response.json()).then((data) => {
  console.log('loaded', data.count);
});

fetch(INTERNAL_ENDPOINT, { headers: { 'X-Internal-Key': INTERNAL_API_KEY } });
// sourceMappingURL=app.js.map
`;

const APP_MAP = JSON.stringify({
  version: 3,
  file: 'app.js',
  sources: ['../src/app.ts', '../src/secret/config.ts'],
  sourcesContent: [
    "const INTERNAL_API_KEY = 'vulnforge_spa_internal_key_9f2c';",
    "export const ADMIN_PANEL = '/spa/panel';\nexport const DB_PASSWORD = 'spa_debug_password';",
  ],
  mappings: '',
});

const products = Array.from({ length: 5000 }, (_, index) => ({
  id: index + 1,
  name: `SPA product ${index + 1}`,
  price: Number(((index % 90) + 1.99).toFixed(2)),
}));

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const path = url.pathname;

  if (path === '/health') {
    return send(res, 200, JSON.stringify({ status: 'ok', service: 'crawl-lab' }), 'application/json');
  }

  // @vuln id=CRAWL-001 name="robots.txt discloses hidden application paths" cwe=CWE-200 owasp=A05:2021 type=robots-disclosure level=1 param=none method=GET service=crawl-lab url=/spa/robots.txt param_loc=path needs_oob=false auth=false detection=passive tags=discovery,info-leak,robots proof_kind=marker proof_desc="Disallow entries reveal the support panel and export endpoint"
  if (path === '/spa/robots.txt' || path === '/robots.txt') {
    labTrigger('CRAWL-001', req, {});
    return send(res, 200, [
      'User-agent: *',
      'Disallow: /spa/panel',
      'Disallow: /spa/api/export',
      'Disallow: /spa/api/products',
      'Sitemap: /spa/sitemap.xml',
      '',
    ].join('\n'), 'text/plain');
  }

  // @control id=CRAWL-001-C twin_of=CRAWL-001 url=/spa/robots_safe.txt method=GET param=none service=crawl-lab param_loc=path
  if (path === '/spa/robots_safe.txt') {
    return send(res, 200, 'User-agent: *\nDisallow: /\n', 'text/plain');
  }

  if (path === '/spa/sitemap.xml') {
    return send(res, 200, `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>/spa/</loc></url>
  <url><loc>/spa/#/dashboard</loc></url>
  <url><loc>/spa/#/settings</loc></url>
  <url><loc>/spa/panel</loc></url>
</urlset>
`, 'application/xml');
  }

  // @vuln id=CRAWL-002 name="JavaScript source map exposes source code" cwe=CWE-540 owasp=A05:2021 type=source-map-exposure level=1 param=none method=GET service=crawl-lab url=/spa/app.js.map param_loc=path needs_oob=false auth=false detection=passive tags=discovery,info-leak,source-map proof_kind=marker proof_desc="The .map file serves original sources including embedded credentials"
  if (path === '/spa/app.js.map') {
    labTrigger('CRAWL-002', req, {});
    return send(res, 200, APP_MAP, 'application/json');
  }

  // @control id=CRAWL-002-C twin_of=CRAWL-002 url=/spa/app_safe.js.map method=GET param=none service=crawl-lab param_loc=path
  if (path === '/spa/app_safe.js.map') {
    return send(res, 404, '{"error":"not found"}', 'application/json');
  }

  // @vuln id=CRAWL-003 name="API key embedded in the client bundle" cwe=CWE-798 owasp=A02:2021 type=hardcoded-secret level=1 param=none method=GET service=crawl-lab url=/spa/app.js param_loc=path needs_oob=false auth=false detection=passive tags=discovery,info-leak,secret proof_kind=marker proof_desc="The bundle contains a hard-coded internal API key"
  if (path === '/spa/app.js' || path === '/app.js') {
    labTrigger('CRAWL-003', req, {});
    return send(res, 200, APP_JS, 'application/javascript');
  }

  // @control id=CRAWL-003-C twin_of=CRAWL-003 url=/spa/app_safe.js method=GET param=none service=crawl-lab param_loc=path
  if (path === '/spa/app_safe.js') {
    return send(res, 200, "const INTERNAL_ENDPOINT = '/spa/panel';\n", 'application/javascript');
  }

  // @vuln id=CRAWL-004 name="Soft 404 returns HTTP 200" cwe=CWE-391 owasp=A05:2021 type=soft-404 level=2 param=path method=GET service=crawl-lab url=/spa/this-page-does-not-exist param_loc=path needs_oob=false auth=false detection=passive tags=discovery,soft-404 proof_kind=marker proof_desc="Unknown paths return 200 with a 'not found' body, confusing crawlers"
  if (path === '/spa/this-page-does-not-exist') {
    labTrigger('CRAWL-004', req, {});
    return send(res, 200, '<html><body><h1>Page not found</h1></body></html>');
  }

  // @control id=CRAWL-004-C twin_of=CRAWL-004 url=/spa/not-found-safe-404 method=GET param=path service=crawl-lab param_loc=path
  if (path === '/spa/not-found-safe-404') {
    return send(res, 404, '<html><body><h1>Page not found</h1></body></html>');
  }

  // @vuln id=CRAWL-005 name="Unbounded pagination trap" cwe=CWE-770 owasp=A04:2021 type=infinite-pagination level=2 param=page method=GET service=crawl-lab url=/spa/api/products param_loc=query needs_oob=false auth=false detection=passive tags=discovery,pagination,dos proof_kind=marker proof_desc="page parameter has no upper bound and always returns a next page"
  if (path === '/spa/api/products') {
    const page = Number(url.searchParams.get('page') || 1);
    const size = 20;
    const start = Math.max(0, (page - 1) * size);
    const items = products.slice(start, start + size);

    if (page > 100) {
      labTrigger('CRAWL-005', req, { page });
    }

    return send(res, 200, JSON.stringify({
      page,
      items,
      next: `/spa/api/products?page=${page + 1}`,
      total: products.length,
    }), 'application/json');
  }

  // @control id=CRAWL-005-C twin_of=CRAWL-005 url=/spa/api/products_safe method=GET param=page service=crawl-lab param_loc=query
  if (path === '/spa/api/products_safe') {
    const requested = Number(url.searchParams.get('page') || 1);
    const page = Math.min(Math.max(requested, 1), 50);
    const start = (page - 1) * 20;
    return send(res, 200, JSON.stringify({
      page,
      items: products.slice(start, start + 20),
      next: page < 50 ? `/spa/api/products_safe?page=${page + 1}` : null,
    }), 'application/json');
  }

  // @vuln id=CRAWL-006 name="WebSocket upgrade accepts any Origin" cwe=CWE-346 owasp=A01:2021 type=cswsh level=2 param=Origin method=GET service=crawl-lab url=/spa/ws-ticket param_loc=header needs_oob=false auth=false detection=passive tags=websocket,cswsh,origin proof_kind=marker proof_desc="Upgrade is allowed for an arbitrary attack origin"
  if (path === '/spa/ws-ticket') {
    const origin = req.headers.origin || '';
    labTrigger('CRAWL-006', req, { origin });
    return send(res, 200, JSON.stringify({ upgrade_allowed: true, origin }), 'application/json');
  }

  // @control id=CRAWL-006-C twin_of=CRAWL-006 url=/spa/ws-ticket_safe method=GET param=Origin service=crawl-lab param_loc=header
  if (path === '/spa/ws-ticket_safe') {
    const origin = req.headers.origin || '';
    const allowed = origin === 'http://127.0.0.1:8000';
    return send(res, allowed ? 200 : 403, JSON.stringify({ upgrade_allowed: allowed }), 'application/json');
  }

  // @vuln id=CRAWL-007 name="SSE stream leaks session token to any client" cwe=CWE-200 owasp=A05:2021 type=sse-data-leak level=2 param=none method=GET service=crawl-lab url=/spa/events param_loc=path needs_oob=false auth=false detection=passive tags=discovery,sse,info-leak proof_kind=marker proof_desc="The event stream contains a reusable session token"
  if (path === '/spa/events') {
    const token = crypto.randomBytes(8).toString('hex');
    labTrigger('CRAWL-007', req, { token });
    return send(res, 200, [
      'event: session',
      `data: {"user":"admin","session_token":"${token}"}`,
      '',
      'event: heartbeat',
      'data: {"ok":true}',
      '',
    ].join('\n'), 'text/event-stream');
  }

  // @control id=CRAWL-007-C twin_of=CRAWL-007 url=/spa/events_safe method=GET param=none service=crawl-lab param_loc=path
  if (path === '/spa/events_safe') {
    return send(res, 200, 'event: heartbeat\ndata: {"ok":true}\n\n', 'text/event-stream');
  }

  // @vuln id=CRAWL-008 name="Hidden admin panel reachable without authentication" cwe=CWE-425 owasp=A01:2021 type=hidden-panel level=2 param=none method=GET service=crawl-lab url=/spa/panel param_loc=path needs_oob=false auth=false detection=active tags=discovery,access-control,hidden-endpoint proof_kind=marker proof_desc="The undocumented support panel is served to anyone who finds it"
  if (path === '/spa/panel') {
    labTrigger('CRAWL-008', req, {});
    return send(res, 200, `<!doctype html><html><body>
<h1>Internal support panel</h1>
<p>admin panel · order override · coupon reset</p>
</body></html>`);
  }

  // @control id=CRAWL-008-C twin_of=CRAWL-008 url=/spa/panel_safe method=GET param=none service=crawl-lab param_loc=path
  if (path === '/spa/panel_safe') {
    return send(res, 403, '{"error":"authentication required"}', 'application/json');
  }

  // Crawl coverage manifest (used by the scorer in later phases).
  if (path === '/spa/surface.json') {
    return send(res, 200, JSON.stringify({ surfaces: HIDDEN_ROUTES }, null, 2), 'application/json');
  }

  if (path === '/spa/' || path === '/spa' || path === '/') {
    return send(res, 200, INDEX_HTML);
  }

  // Default: soft 404 behaviour for the SPA shell.
  send(res, 200, INDEX_HTML);
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[crawl-lab] listening on ${PORT}`);
});
