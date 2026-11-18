// VulnForge Lab — node-api
// Intentionally vulnerable REST API used for scanner benchmarking.
// WARNING: never expose this service outside an isolated lab.

'use strict';

const http = require('node:http');
const crypto = require('node:crypto');
const { URL } = require('node:url');

const PORT = Number(process.env.PORT || 3000);
const LAB_CONTROL_URL = process.env.LAB_CONTROL_URL || 'http://lab-control:9100';
const JWT_SECRET = process.env.JWT_WEAK_SECRET || 'secret';

// ─── Lab event helper ────────────────────────────────────────────────────────

function labTrigger(vulnId, req, extra = {}) {
  const body = JSON.stringify({
    kind: 'vuln_triggered',
    vuln_id: vulnId,
    service: 'node-api',
    request_id: req.headers['x-request-id'] || '',
    ts: new Date().toISOString(),
    ...extra,
  });

  fetch(`${LAB_CONTROL_URL}/__lab/events`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body,
    signal: AbortSignal.timeout(1000),
  }).catch(() => {});
}

// ─── Seed data (deterministic, synthetic) ────────────────────────────────────

function seedData() {
  const users = [
    { id: 1, username: 'admin', password: 'admin123', role: 'admin', email: 'admin@vulnforge.lab', ssn: '111-11-1111', balance: 999999, apiKey: 'ak_admin_2f8c1d9e' },
    { id: 2, username: 'alice', password: 'password1', role: 'user', email: 'alice@vulnforge.lab', ssn: '222-22-2222', balance: 1200, apiKey: 'ak_alice_77aa10bc' },
    { id: 3, username: 'bob', password: 'qwerty', role: 'user', email: 'bob@vulnforge.lab', ssn: '333-33-3333', balance: 340, apiKey: 'ak_bob_99bb22cc' },
    { id: 4, username: 'diana', password: 'sunshine', role: 'moderator', email: 'diana@vulnforge.lab', ssn: '444-44-4444', balance: 50, apiKey: 'ak_diana_11cc33dd' },
  ];

  const orders = [
    { id: 1, userId: 2, total: 19.98, status: 'paid', items: ['SKU-1', 'SKU-2'] },
    { id: 2, userId: 3, total: 4.99, status: 'pending', items: ['SKU-3'] },
    { id: 3, userId: 1, total: 999.99, status: 'paid', items: ['SKU-SECRET'] },
    { id: 4, userId: 4, total: 44.97, status: 'shipped', items: ['SKU-7', 'SKU-8'] },
  ];

  const products = [];
  for (let i = 1; i <= 5000; i++) {
    products.push({
      id: i,
      name: `Product ${String(i).padStart(4, '0')}`,
      price: Number(((i % 500) + 0.99).toFixed(2)),
      category: ['widgets', 'gadgets', 'misc'][i % 3],
    });
  }

  return { users, orders, products, settings: {}, loginFailures: {}, auditLog: [] };
}

let db = seedData();

// ─── Minimal Mongo-like query evaluator ──────────────────────────────────────
// The lab simulates the operator semantics that make NoSQL injection possible
// without requiring a live MongoDB instance, which keeps reset deterministic.

function matchOperators(value, condition) {
  for (const [op, arg] of Object.entries(condition)) {
    switch (op) {
      case '$ne': if (!(value !== arg)) return false; break;
      case '$eq': if (!(value === arg)) return false; break;
      case '$gt': if (!(value > arg)) return false; break;
      case '$gte': if (!(value >= arg)) return false; break;
      case '$lt': if (!(value < arg)) return false; break;
      case '$regex': if (!new RegExp(String(arg)).test(String(value))) return false; break;
      default: return false;
    }
  }
  return true;
}

function mongoMatch(doc, query) {
  for (const [key, condition] of Object.entries(query || {})) {
    if (condition && typeof condition === 'object' && !Array.isArray(condition)) {
      if (!matchOperators(doc[key], condition)) return false;
    } else if (doc[key] !== condition) {
      return false;
    }
  }
  return true;
}

// ─── JWT helpers ─────────────────────────────────────────────────────────────

const b64url = (input) => Buffer.from(input).toString('base64url');
const fromB64url = (input) => Buffer.from(input, 'base64url').toString('utf8');

function signJwt(payload, secret = JWT_SECRET) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const body = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const signature = crypto.createHmac('sha256', secret).update(body).digest('base64url');
  return `${body}.${signature}`;
}

// !! VULNERABLE BY DESIGN — alg "none" and weak/hard-coded secrets accepted !!
function verifyJwtV1(token) {
  const parts = String(token || '').split('.');
  if (parts.length < 2) return null;

  let header;
  let payload;
  try {
    header = JSON.parse(fromB64url(parts[0]));
    payload = JSON.parse(fromB64url(parts[1]));
  } catch {
    return null;
  }

  if (header.alg === 'none') {
    return payload; // no signature required
  }

  const signingInput = `${parts[0]}.${parts[1]}`;
  const expected = crypto.createHmac('sha256', JWT_SECRET).update(signingInput).digest('base64url');
  if (parts[2] !== expected) return null;
  return payload;
}

function verifyJwtV2(token) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) return null;

  let header;
  let payload;
  try {
    header = JSON.parse(fromB64url(parts[0]));
    payload = JSON.parse(fromB64url(parts[1]));
  } catch {
    return null;
  }

  if (header.alg !== 'HS256') return null; // reject "none" and confusion attempts

  const signingInput = `${parts[0]}.${parts[1]}`;
  const expected = crypto.createHmac('sha256', JWT_SECRET).update(signingInput).digest('base64url');
  const provided = Buffer.from(String(parts[2]));
  const wanted = Buffer.from(expected);
  if (provided.length !== wanted.length || !crypto.timingSafeEqual(provided, wanted)) return null;
  if (typeof payload.exp === 'number' && payload.exp < Math.floor(Date.now() / 1000)) return null;

  return payload;
}

function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    role: user.role,
    email: user.email,
    balance: user.balance,
  };
}

// ─── HTTP plumbing ───────────────────────────────────────────────────────────

function sendJson(res, status, data, extraHeaders = {}) {
  const payload = JSON.stringify(data);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(payload),
    ...extraHeaders,
  });
  res.end(payload);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > 2 * 1024 * 1024) {
        reject(new Error('body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

async function parseBody(req) {
  const raw = await readBody(req);
  const type = String(req.headers['content-type'] || '');
  if (!raw) return {};
  if (type.includes('application/json')) {
    try {
      return JSON.parse(raw);
    } catch {
      return {};
    }
  }
  return Object.fromEntries(new URLSearchParams(raw));
}

function bearer(req) {
  const header = String(req.headers.authorization || '');
  return header.startsWith('Bearer ') ? header.slice(7) : '';
}

function findUser(id) {
  return db.users.find((user) => user.id === Number(id));
}

// ─── Routes ──────────────────────────────────────────────────────────────────

const routes = [];
const route = (method, pattern, handler) => routes.push({ method, pattern, handler });

// @vuln id=API-001 name="BOLA: any authenticated user can read any order" cwe=CWE-639 owasp=A01:2021 owasp_api=API1 type=bola level=1 param=id method=GET service=node-api url=/api/v1/orders/3 param_loc=path needs_oob=false auth=true detection=api tags=api,access-control,bola proof_kind=marker proof_desc="Order belonging to another user is returned when its sequential id is requested"
route('GET', /^\/api\/v1\/orders\/(\d+)$/, async (req, res, m) => {
  const claims = verifyJwtV1(bearer(req));
  if (!claims) return sendJson(res, 401, { error: 'authentication required' });

  // !! INTENTIONALLY VULNERABLE — ownership is never checked !!
  const order = db.orders.find((entry) => entry.id === Number(m[1]));
  if (!order) return sendJson(res, 404, { error: 'order not found' });

  if (order.userId !== claims.sub) {
    labTrigger('API-001', req, { order_id: order.id, viewer: claims.sub });
  }

  sendJson(res, 200, { order, owner: db.users.find((u) => u.id === order.userId)?.username });
});

// @control id=API-001-C twin_of=API-001 url=/api/v2/orders/1 method=GET param=id service=node-api param_loc=path
route('GET', /^\/api\/v2\/orders\/(\d+)$/, async (req, res, m) => {
  const claims = verifyJwtV2(bearer(req));
  if (!claims) return sendJson(res, 401, { error: 'authentication required' });

  const order = db.orders.find((entry) => entry.id === Number(m[1]) && entry.userId === claims.sub);
  if (!order) return sendJson(res, 404, { error: 'order not found' });
  sendJson(res, 200, { order });
});

// @vuln id=API-002 name="BOPLA: user endpoint returns password, SSN and balance" cwe=CWE-213 owasp=A01:2021 owasp_api=API3 type=excessive-data-exposure level=1 param=id method=GET service=node-api url=/api/v1/users/1 param_loc=path needs_oob=false auth=true detection=api tags=api,data-exposure,bopla proof_kind=marker proof_desc="Response contains password, ssn and apiKey fields"
route('GET', /^\/api\/v1\/users\/(\d+)$/, async (req, res, m) => {
  const claims = verifyJwtV1(bearer(req));
  if (!claims) return sendJson(res, 401, { error: 'authentication required' });

  // !! INTENTIONALLY VULNERABLE — full document returned, no field filtering !!
  const user = findUser(m[1]);
  if (!user) return sendJson(res, 404, { error: 'user not found' });

  labTrigger('API-002', req, { target_user: user.id });
  sendJson(res, 200, { user });
});

// @control id=API-002-C twin_of=API-002 url=/api/v2/users/1 method=GET param=id service=node-api param_loc=path
route('GET', /^\/api\/v2\/users\/(\d+)$/, async (req, res, m) => {
  const claims = verifyJwtV2(bearer(req));
  if (!claims) return sendJson(res, 401, { error: 'authentication required' });

  const user = findUser(m[1]);
  if (!user) return sendJson(res, 404, { error: 'user not found' });
  if (user.id !== claims.sub && claims.role !== 'admin') {
    return sendJson(res, 403, { error: 'forbidden' });
  }
  sendJson(res, 200, { user: publicUser(user) });
});

// @vuln id=API-003 name="BFLA: normal user can delete any account" cwe=CWE-285 owasp=A01:2021 owasp_api=API5 type=bfla level=1 param=id method=DELETE service=node-api url=/api/v1/users/1 param_loc=path needs_oob=false auth=true detection=api tags=api,access-control,bfla proof_kind=marker proof_desc="A standard user token deletes the administrator account"
route('DELETE', /^\/api\/v1\/users\/(\d+)$/, async (req, res, m) => {
  const claims = verifyJwtV1(bearer(req));
  if (!claims) return sendJson(res, 401, { error: 'authentication required' });

  // !! INTENTIONALLY VULNERABLE — no role check before destructive action !!
  const index = db.users.findIndex((user) => user.id === Number(m[1]));
  if (index === -1) return sendJson(res, 404, { error: 'user not found' });

  const [removed] = db.users.splice(index, 1);
  labTrigger('API-003', req, { deleted_user: removed.username, actor_role: claims.role });
  sendJson(res, 200, { deleted: removed.username });
});

// @control id=API-003-C twin_of=API-003 url=/api/v2/users/1 method=DELETE param=id service=node-api param_loc=path
route('DELETE', /^\/api\/v2\/users\/(\d+)$/, async (req, res, m) => {
  const claims = verifyJwtV2(bearer(req));
  if (!claims) return sendJson(res, 401, { error: 'authentication required' });
  if (claims.role !== 'admin') return sendJson(res, 403, { error: 'admin role required' });

  const index = db.users.findIndex((user) => user.id === Number(m[1]));
  if (index === -1) return sendJson(res, 404, { error: 'user not found' });
  db.users.splice(index, 1);
  sendJson(res, 200, { deleted: Number(m[1]) });
});

// @vuln id=API-004 name="Mass assignment allows self-service role escalation" cwe=CWE-915 owasp=A01:2021 owasp_api=API3 type=mass-assignment level=1 param=role method=PUT service=node-api url=/api/v1/users/2 param_loc=json needs_oob=false auth=true detection=api tags=api,access-control,mass-assignment proof_kind=marker proof_desc="Sending role=admin updates the account role"
route('PUT', /^\/api\/v1\/users\/(\d+)$/, async (req, res, m) => {
  const claims = verifyJwtV1(bearer(req));
  if (!claims) return sendJson(res, 401, { error: 'authentication required' });

  const body = await parseBody(req);
  const user = findUser(m[1]);
  if (!user) return sendJson(res, 404, { error: 'user not found' });

  // !! INTENTIONALLY VULNERABLE — every client field is copied onto the record !!
  Object.assign(user, body);

  if (body.role || body.balance !== undefined) {
    labTrigger('API-004', req, { fields: Object.keys(body) });
  }
  sendJson(res, 200, { user });
});

// @control id=API-004-C twin_of=API-004 url=/api/v2/users/2 method=PUT param=role service=node-api param_loc=json
route('PUT', /^\/api\/v2\/users\/(\d+)$/, async (req, res, m) => {
  const claims = verifyJwtV2(bearer(req));
  if (!claims) return sendJson(res, 401, { error: 'authentication required' });
  if (Number(m[1]) !== claims.sub) return sendJson(res, 403, { error: 'forbidden' });

  const body = await parseBody(req);
  const user = findUser(m[1]);
  if (!user) return sendJson(res, 404, { error: 'user not found' });

  // SAFE: explicit allowlist of mutable fields.
  for (const field of ['email']) {
    if (typeof body[field] === 'string') user[field] = body[field];
  }
  sendJson(res, 200, { user: publicUser(user) });
});

// @vuln id=API-005 name="NoSQL operator injection in login" cwe=CWE-943 owasp=A03:2021 owasp_api=API2 type=nosql-injection level=1 param=username method=POST service=node-api url=/api/v1/login param_loc=json needs_oob=false auth=false detection=api tags=api,injection,nosql proof_kind=marker proof_desc="JSON body with $ne operators authenticates as the administrator without a password"
route('POST', /^\/api\/v1\/login$/, async (req, res) => {
  const body = await parseBody(req);

  // !! INTENTIONALLY VULNERABLE — client JSON is used as the query document !!
  const user = db.users.find((entry) => mongoMatch(entry, {
    username: body.username,
    password: body.password,
  }));

  if (!user) {
    db.loginFailures[String(body.username)] = (db.loginFailures[String(body.username)] || 0) + 1;
    return sendJson(res, 401, { authenticated: false, error: 'invalid credentials' });
  }

  const token = signJwt({ sub: user.id, username: user.username, role: user.role, exp: Math.floor(Date.now() / 1000) + 3600 });
  if (typeof body.username !== 'string' || typeof body.password !== 'string') {
    labTrigger('API-005', req, { payload: body });
  }
  sendJson(res, 200, { authenticated: true, token, user: publicUser(user) });
});

// @control id=API-005-C twin_of=API-005 url=/api/v2/login method=POST param=username service=node-api param_loc=json
route('POST', /^\/api\/v2\/login$/, async (req, res) => {
  const body = await parseBody(req);

  // SAFE: only scalar strings are accepted, so operators never reach the query.
  const username = typeof body.username === 'string' ? body.username : '';
  const password = typeof body.password === 'string' ? body.password : '';

  const failuresKey = username.toLowerCase();
  const failures = db.loginFailures[failuresKey] || 0;
  if (failures >= 5) {
    return sendJson(res, 429, { error: 'too many failed attempts, slow down' });
  }

  const user = db.users.find((entry) => entry.username === username && entry.password === password);
  if (!user) {
    db.loginFailures[failuresKey] = failures + 1;
    return sendJson(res, 401, { authenticated: false, error: 'invalid credentials' });
  }

  db.loginFailures[failuresKey] = 0;
  const token = signJwt({ sub: user.id, username: user.username, role: user.role, exp: Math.floor(Date.now() / 1000) + 3600 });
  sendJson(res, 200, { authenticated: true, token, user: publicUser(user) });
});

// @vuln id=API-006 name="JWT algorithm confusion: alg=none accepted" cwe=CWE-347 owasp=A07:2021 owasp_api=API2 type=jwt-none-alg level=2 param=Authorization method=GET service=node-api url=/api/v1/auth/whoami param_loc=header needs_oob=false auth=true detection=api tags=api,auth,jwt proof_kind=marker proof_desc="Unsigned token with alg=none grants administrator access"
route('GET', /^\/api\/v1\/auth\/whoami$/, async (req, res) => {
  // !! INTENTIONALLY VULNERABLE — unsigned tokens are trusted !!
  const claims = verifyJwtV1(bearer(req));
  if (!claims) return sendJson(res, 401, { error: 'authentication required' });

  labTrigger('API-006', req, { alg: 'none-or-hs256', role: claims.role });
  sendJson(res, 200, { claims, isAdmin: claims.role === 'admin' });
});

// @control id=API-006-C twin_of=API-006 url=/api/v2/auth/whoami method=GET param=Authorization service=node-api param_loc=header
route('GET', /^\/api\/v2\/auth\/whoami$/, async (req, res) => {
  const claims = verifyJwtV2(bearer(req));
  if (!claims) return sendJson(res, 401, { error: 'authentication required' });
  sendJson(res, 200, { claims, isAdmin: claims.role === 'admin' });
});

// @vuln id=API-007 name="Unauthenticated token impersonation endpoint" cwe=CWE-287 owasp=A07:2021 owasp_api=API2 type=broken-authentication level=1 param=username method=GET service=node-api url=/api/v1/auth/impersonate param_loc=query needs_oob=false auth=false detection=api tags=api,auth,impersonation proof_kind=marker proof_desc="Requesting an admin token requires no credentials at all"
route('GET', /^\/api\/v1\/auth\/impersonate$/, async (req, res, m, url) => {
  const username = url.searchParams.get('username') || 'admin';
  const user = db.users.find((entry) => entry.username === username);
  if (!user) return sendJson(res, 404, { error: 'user not found' });

  // !! INTENTIONALLY VULNERABLE — debug helper left enabled in production !!
  const token = signJwt({ sub: user.id, username: user.username, role: user.role, exp: Math.floor(Date.now() / 1000) + 3600 });
  labTrigger('API-007', req, { impersonated: user.username });
  sendJson(res, 200, { token, role: user.role });
});

// @control id=API-007-C twin_of=API-007 url=/api/v2/auth/impersonate method=GET param=username service=node-api param_loc=query
route('GET', /^\/api\/v2\/auth\/impersonate$/, async (req, res) => {
  sendJson(res, 404, { error: 'not found' });
});

// @vuln id=API-008 name="Server-side prototype pollution via settings merge" cwe=CWE-1321 owasp=A08:2021 owasp_api=API8 type=prototype-pollution level=2 param=__proto__ method=POST service=node-api url=/api/v1/settings param_loc=json needs_oob=false auth=false detection=api tags=api,injection,prototype-pollution proof_kind=marker proof_desc="A __proto__ key pollutes Object.prototype and is visible on later requests"
function unsafeMerge(target, source) {
  for (const key of Object.keys(source)) {
    const value = source[key];
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      if (target[key] === undefined || typeof target[key] !== 'object') target[key] = {};
      unsafeMerge(target[key], value);
    } else {
      target[key] = value;
    }
  }
  return target;
}

route('POST', /^\/api\/v1\/settings$/, async (req, res) => {
  const body = await parseBody(req);

  // !! INTENTIONALLY VULNERABLE — __proto__ is not filtered !!
  unsafeMerge(db.settings, body);

  if (JSON.stringify(body).includes('__proto__') || JSON.stringify(body).includes('constructor')) {
    labTrigger('API-008', req, { payload: body });
  }

  sendJson(res, 200, {
    settings: db.settings,
    inherited: { polluted: ({}).polluted ?? null },
  });
});

// @control id=API-008-C twin_of=API-008 url=/api/v2/settings method=POST param=__proto__ service=node-api param_loc=json
route('POST', /^\/api\/v2\/settings$/, async (req, res) => {
  const body = await parseBody(req);

  // SAFE: null-prototype target plus explicit key denylist.
  const settings = Object.create(null);
  for (const [key, value] of Object.entries(body)) {
    if (['__proto__', 'constructor', 'prototype'].includes(key)) continue;
    if (value === null || typeof value !== 'object') settings[key] = value;
  }

  sendJson(res, 200, { settings, inherited: { polluted: Object.create(null).polluted ?? null } });
});

// @vuln id=API-009 name="SSRF in webhook fetch endpoint" cwe=CWE-918 owasp=A10:2021 owasp_api=API7 type=ssrf level=1 param=url method=POST service=node-api url=/api/v1/webhook/fetch param_loc=json needs_oob=false auth=false detection=api tags=api,ssrf proof_kind=marker proof_desc="Server fetches cloud metadata credentials from the internal network"
route('POST', /^\/api\/v1\/webhook\/fetch$/, async (req, res) => {
  const body = await parseBody(req);
  const target = String(body.url || '');

  // !! INTENTIONALLY VULNERABLE — any URL, including internal hosts !!
  try {
    const response = await fetch(target, { signal: AbortSignal.timeout(4000) });
    const text = await response.text();
    labTrigger('API-009', req, { url: target, status: response.status });
    sendJson(res, 200, { status: response.status, body: text.slice(0, 4000) });
  } catch (error) {
    sendJson(res, 502, { error: String(error.message || error) });
  }
});

// @control id=API-009-C twin_of=API-009 url=/api/v2/webhook/fetch method=POST param=url service=node-api param_loc=json
const PRIVATE_HOSTS = /^(localhost|127\.|0\.0\.0\.0|10\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|\[::1\])/i;
route('POST', /^\/api\/v2\/webhook\/fetch$/, async (req, res) => {
  const body = await parseBody(req);
  let target;
  try {
    target = new URL(String(body.url || ''));
  } catch {
    return sendJson(res, 400, { error: 'invalid url' });
  }

  if (!['http:', 'https:'].includes(target.protocol) || PRIVATE_HOSTS.test(target.hostname)) {
    return sendJson(res, 400, { error: 'destination not allowed' });
  }

  try {
    const response = await fetch(target, { signal: AbortSignal.timeout(4000) });
    sendJson(res, 200, { status: response.status });
  } catch {
    sendJson(res, 502, { error: 'upstream unavailable' });
  }
});

// @vuln id=API-010 name="Unbounded pagination allows resource exhaustion" cwe=CWE-770 owasp=A04:2021 owasp_api=API4 type=unbounded-pagination level=1 param=limit method=GET service=node-api url=/api/v1/products param_loc=query needs_oob=false auth=false detection=api tags=api,dos,pagination proof_kind=marker proof_desc="limit=5000 returns the entire catalogue in a single response"
route('GET', /^\/api\/v1\/products$/, async (req, res, m, url) => {
  // !! INTENTIONALLY VULNERABLE — no upper bound on limit !!
  const limit = Number(url.searchParams.get('limit') || 20);
  const items = db.products.slice(0, limit);
  labTrigger('API-010', req, { requested: limit, returned: items.length });
  sendJson(res, 200, { count: items.length, items });
});

// @control id=API-010-C twin_of=API-010 url=/api/v2/products method=GET param=limit service=node-api param_loc=query
route('GET', /^\/api\/v2\/products$/, async (req, res, m, url) => {
  const requested = Number(url.searchParams.get('limit') || 20);
  const limit = Number.isFinite(requested) ? Math.min(Math.max(requested, 1), 100) : 20;
  sendJson(res, 200, { count: Math.min(limit, db.products.length), items: db.products.slice(0, limit) });
});

// @vuln id=API-011 name="API key accepted in the query string" cwe=CWE-598 owasp=A02:2021 owasp_api=API2 type=api-key-in-url level=1 param=api_key method=GET service=node-api url=/api/v1/export param_loc=query needs_oob=false auth=false detection=api tags=api,auth,api-key proof_kind=marker proof_desc="A valid api_key query parameter grants access, leaking the key into logs and history"
route('GET', /^\/api\/v1\/export$/, async (req, res, m, url) => {
  // !! INTENTIONALLY VULNERABLE — credentials in the URL are accepted !!
  const key = url.searchParams.get('api_key') || req.headers['x-api-key'];
  const user = db.users.find((entry) => entry.apiKey === key);
  if (!user) return sendJson(res, 401, { error: 'invalid api key' });

  if (url.searchParams.has('api_key')) labTrigger('API-011', req, { user: user.username });
  sendJson(res, 200, { exported: db.orders.filter((order) => order.userId === user.id) });
});

// @control id=API-011-C twin_of=API-011 url=/api/v2/export method=GET param=api_key service=node-api param_loc=query
route('GET', /^\/api\/v2\/export$/, async (req, res, m, url) => {
  if (url.searchParams.has('api_key')) {
    return sendJson(res, 400, { error: 'api key must be sent in the X-API-Key header' });
  }
  const key = req.headers['x-api-key'];
  const user = typeof key === 'string' ? db.users.find((entry) => entry.apiKey === key) : null;
  if (!user) return sendJson(res, 401, { error: 'invalid api key' });
  sendJson(res, 200, { exported: db.orders.filter((order) => order.userId === user.id) });
});

// @vuln id=API-012 name="Undocumented debug endpoint exposes configuration" cwe=CWE-200 owasp=A05:2021 owasp_api=API9 type=shadow-endpoint level=1 param=none method=GET service=node-api url=/api/internal/debug param_loc=path needs_oob=false auth=false detection=config tags=api,info-leak,shadow-api proof_kind=marker proof_desc="Response lists environment variables including the JWT signing secret"
route('GET', /^\/api\/internal\/debug$/, async (req, res) => {
  labTrigger('API-012', req, {});
  sendJson(res, 200, {
    service: 'node-api',
    version: '1.4.0',
    env: {
      NODE_ENV: process.env.NODE_ENV || 'production',
      JWT_WEAK_SECRET: JWT_SECRET,
      MONGO_URI: process.env.MONGO_URI || '',
    },
    users: db.users.length,
  });
});

// @control id=API-012-C twin_of=API-012 url=/api/v2/internal/debug method=GET param=none service=node-api param_loc=path
route('GET', /^\/api\/v2\/internal\/debug$/, async (req, res) => {
  sendJson(res, 404, { error: 'not found' });
});

// @vuln id=API-013 name="CORS reflects arbitrary Origin with credentials" cwe=CWE-942 owasp=A05:2021 owasp_api=API8 type=cors-misconfig level=1 param=Origin method=GET service=node-api url=/api/v1/cors-test param_loc=header needs_oob=false auth=false detection=config tags=api,cors,misconfiguration proof_kind=marker proof_desc="Access-Control-Allow-Origin echoes an attacker origin together with Allow-Credentials: true"
route('GET', /^\/api\/v1\/cors-test$/, async (req, res) => {
  const origin = req.headers.origin || '*';
  labTrigger('API-013', req, { origin });
  sendJson(res, 200, { ok: true }, {
    'access-control-allow-origin': origin,
    'access-control-allow-credentials': 'true',
  });
});

// @control id=API-013-C twin_of=API-013 url=/api/v2/cors-test method=GET param=Origin service=node-api param_loc=header
route('GET', /^\/api\/v2\/cors-test$/, async (req, res) => {
  sendJson(res, 200, { ok: true }, {
    'access-control-allow-origin': 'http://127.0.0.1:8000',
    'vary': 'Origin',
  });
});

// @vuln id=API-014 name="No rate limiting or lockout on legacy authentication" cwe=CWE-307 owasp=A04:2021 owasp_api=API4 type=missing-rate-limit level=2 param=password method=POST service=node-api url=/api/v1/auth/login param_loc=json needs_oob=false auth=false detection=logic tags=api,authentication,rate-limit proof_kind=marker proof_desc="Unlimited failed logins are accepted and a correct password still succeeds afterwards"
route('POST', /^\/api\/v1\/auth\/login$/, async (req, res) => {
  const body = await parseBody(req);

  // !! INTENTIONALLY VULNERABLE — no failure counter, no lockout, no delay !!
  const user = db.users.find((entry) => entry.username === body.username && entry.password === body.password);
  if (!user) {
    return sendJson(res, 401, { authenticated: false, error: 'invalid credentials' });
  }

  const token = signJwt({ sub: user.id, username: user.username, role: user.role, exp: Math.floor(Date.now() / 1000) + 3600 });
  labTrigger('API-014', req, { username: user.username });
  sendJson(res, 200, { authenticated: true, token });
});

// @control id=API-014-C twin_of=API-014 url=/api/v2/auth/login method=POST param=password service=node-api param_loc=json
route('POST', /^\/api\/v2\/auth\/login$/, async (req, res) => {
  const body = await parseBody(req);
  const username = typeof body.username === 'string' ? body.username : '';
  const password = typeof body.password === 'string' ? body.password : '';
  const key = username.toLowerCase();

  const failures = db.loginFailures[key] || 0;
  if (failures >= 5) {
    return sendJson(res, 429, { error: 'too many failed attempts, slow down' });
  }

  const user = db.users.find((entry) => entry.username === username && entry.password === password);
  if (!user) {
    db.loginFailures[key] = failures + 1;
    return sendJson(res, 401, { authenticated: false, error: 'invalid credentials' });
  }

  db.loginFailures[key] = 0;
  const token = signJwt({ sub: user.id, username: user.username, role: user.role, exp: Math.floor(Date.now() / 1000) + 3600 });
  sendJson(res, 200, { authenticated: true, token });
});

// ─── Internal lab endpoints ──────────────────────────────────────────────────

route('GET', /^\/health$/, async (req, res) => {
  sendJson(res, 200, { status: 'ok', service: 'node-api' });
});

route('POST', /^\/__lab\/internal\/reset$/, async (req, res) => {
  db = seedData();
  // Clear any prototype pollution left behind by earlier exploit attempts.
  delete Object.prototype.polluted;
  sendJson(res, 200, { reset: true });
});

route('POST', /^\/__lab\/internal\/seed$/, async (req, res, m, url) => {
  db = seedData();
  const profile = url.searchParams.get('profile') || 'small';
  if (profile === 'large') {
    for (let i = 0; i < 500; i++) {
      db.users.push({
        id: 1000 + i,
        username: `bulk-api-${i}`,
        password: `pw-${i}`,
        role: 'user',
        email: `bulk-api-${i}@vulnforge.lab`,
        ssn: `900-${String(i).padStart(2, '0')}-0000`,
        balance: i,
        apiKey: `ak_bulk_${i}`,
      });
    }
  }
  sendJson(res, 200, { seeded: true, profile });
});

// ─── GraphQL routes (merged from graphql-svc) ────────────────────────────────
// GQL-001..006: introspection, field suggestion, batching, OTP bruteforce,
// alias amplification, BOLA in user resolver.

const GQL_USERS = [
  { id: 1, username: 'admin', email: 'admin@vulnforge.lab', role: 'admin', ssn: '111-11-1111', otp: '4821' },
  { id: 2, username: 'alice', email: 'alice@vulnforge.lab', role: 'user',  ssn: '222-22-2222', otp: '1111' },
  { id: 3, username: 'bob',   email: 'bob@vulnforge.lab',   role: 'user',  ssn: '333-33-3333', otp: '2222' },
];
const gqlOtpAttempts = {};

const GQL_SCHEMA = {
  queryType: { name: 'Query' },
  types: [
    { kind: 'OBJECT', name: 'User', fields: ['id','username','email','role','ssn'].map(n=>({name:n,type:'String'})) },
    { kind: 'OBJECT', name: 'Query', fields: [
      { name:'hello', type:'String' },
      { name:'user', type:'User', args:[{name:'id',type:'Int'}] },
      { name:'users', type:'User' },
      { name:'verifyOtp', type:'Boolean', args:[{name:'userId',type:'Int'},{name:'code',type:'String'}] },
    ]},
    { kind:'SCALAR', name:'Int' }, { kind:'SCALAR', name:'String' }, { kind:'SCALAR', name:'Boolean' },
  ],
};

function gqlTokenize(src) {
  return src.replace(/#[^\n]*/g,' ').match(/[_A-Za-z][_0-9A-Za-z]*|[-+]?\d+(?:\.\d+)?|"(?:[^"\\]|\\.)*"|[{}():,!$\[\]]/g)||[];
}

function gqlParseSelection(tokens, state) {
  const fields = [];
  if (tokens[state.index]!=='{') return fields;
  state.index++;
  while (state.index<tokens.length && tokens[state.index]!=='}') {
    const first=tokens[state.index++]; let alias=first, name=first;
    if (tokens[state.index]===':') { state.index++; name=tokens[state.index++]; }
    const args={};
    if (tokens[state.index]==='(') {
      state.index++;
      while (state.index<tokens.length && tokens[state.index]!==')') {
        if (tokens[state.index]===',') { state.index++; continue; }
        const k=tokens[state.index++]; if (tokens[state.index]===':') state.index++;
        const v=tokens[state.index++]; try { args[k]=JSON.parse(v); } catch { args[k]=v; }
      }
      if (tokens[state.index]===')') state.index++;
    }
    let children=null;
    if (tokens[state.index]==='{') children=gqlParseSelection(tokens,state);
    fields.push({alias,name,args,children});
  }
  if (tokens[state.index]==='}') state.index++;
  return fields;
}

function gqlExecute(source, options={}) {
  const tokens=gqlTokenize(source), state={index:0};
  if (['query','mutation'].includes(tokens[state.index])) { state.index++; if(tokens[state.index]&&!['{','('].includes(tokens[state.index])) state.index++; }
  const fields=gqlParseSelection(tokens,state);
  const ctx={schema:options.introspection===false?null:GQL_SCHEMA, viewerId:Number(options.viewerId||0), enforceOwnership:options.enforceOwnership===true, crossUserReads:[], unknownFields:[], otpResults:[]};
  const data={};
  for (const f of fields) {
    switch(f.name) {
      case '__typename': data[f.alias]='Query'; break;
      case '__schema':   data[f.alias]=ctx.schema; break;
      case '__type':     data[f.alias]=GQL_SCHEMA.types.find(t=>t.name===f.args.name)||null; break;
      case 'hello':      data[f.alias]='Hello from VulnForge GraphQL'; break;
      case 'user': {
        const id=Number(f.args.id||0), user=GQL_USERS.find(u=>u.id===id);
        if (!user) { data[f.alias]=null; break; }
        if (ctx.enforceOwnership && id!==ctx.viewerId) { data[f.alias]=null; break; }
        if (!ctx.enforceOwnership && id!==ctx.viewerId) ctx.crossUserReads.push(id);
        const row={}; for(const c of (f.children||[{name:'username'}])) { if(c.name in user) row[c.alias]=user[c.name]; }
        data[f.alias]=row; break;
      }
      case 'users': {
        const visible=ctx.enforceOwnership?GQL_USERS.filter(u=>u.id===ctx.viewerId):GQL_USERS;
        data[f.alias]=visible.map(u=>{ const r={}; for(const c of (f.children||[{name:'username'}])) { if(c.name in u) r[c.alias]=u[c.name]; } return r; }); break;
      }
      case 'verifyOtp': {
        const uid=Number(f.args.userId||0), code=String(f.args.code||''), key=`u${uid}`;
        gqlOtpAttempts[key]=(gqlOtpAttempts[key]||0)+1;
        const user=GQL_USERS.find(u=>u.id===uid);
        const ok=!!user&&user.otp===code;
        ctx.otpResults.push({userId:uid,ok,attempts:gqlOtpAttempts[key]});
        data[f.alias]=ok; break;
      }
      default: ctx.unknownFields.push(f.name); data[f.alias]=null;
    }
  }
  return {data, context:ctx, fieldCount:fields.length};
}

function gqlLevenshtein(a,b) {
  const m=Array.from({length:a.length+1},(_,i)=>[i]); for(let j=1;j<=b.length;j++) m[0][j]=j;
  for(let i=1;i<=a.length;i++) for(let j=1;j<=b.length;j++) m[i][j]=Math.min(m[i-1][j]+1,m[i][j-1]+1,m[i-1][j-1]+(a[i-1]===b[j-1]?0:1));
  return m[a.length][b.length];
}

function gqlSuggest(name) {
  const cands=GQL_SCHEMA.types.find(t=>t.name==='Query').fields.map(f=>f.name);
  let best=cands[0],bestScore=Infinity;
  for (const c of cands) { const s=gqlLevenshtein(name,c); if(s<bestScore){bestScore=s;best=c;} }
  return best;
}

function gqlBuildResponse(result, isSafe) {
  const resp={data:result.data};
  if (result.context.unknownFields.length) {
    resp.errors=result.context.unknownFields.map(n=>({message:isSafe?'unknown field':`Cannot query field "${n}" on type "Query". Did you mean "${gqlSuggest(n)}"?`}));
  }
  return resp;
}

async function handleGraphQL(req, res, isSafe) {
  const raw = await readBody(req);
  let payload;
  try { payload = raw ? JSON.parse(raw) : {}; } catch { return sendJson(res, 400, {errors:[{message:'invalid JSON body'}]}); }

  if (Array.isArray(payload)) {
    if (isSafe && payload.length > 5) return sendJson(res, 400, {errors:[{message:'batch size limit exceeded'}]});
    if (!isSafe && payload.length > 1) labTrigger('GQL-003', req, {batch_size: payload.length});
    const viewerId = req.headers['x-user-id'];
    const results = payload.map(e => gqlExecute(String(e.query||''), {introspection:!isSafe, enforceOwnership:isSafe, viewerId}));
    const totalFields = results.reduce((s,r)=>s+r.fieldCount,0);
    if (isSafe && totalFields>20) return sendJson(res, 400, {errors:[{message:'query complexity limit exceeded'}]});
    if (!isSafe && totalFields>100) labTrigger('GQL-005', req, {aliases:totalFields});
    return sendJson(res, 200, results.map(r=>gqlBuildResponse(r,isSafe)), {'x-batch-size': String(payload.length)});
  }

  const source = String(payload.query||''), viewerId = req.headers['x-user-id'];
  if (isSafe) {
    if (source.includes('__schema')||source.includes('__type')) return sendJson(res,200,{errors:[{message:'introspection is disabled'}]});
    const result=gqlExecute(source,{introspection:false,enforceOwnership:true,viewerId});
    if (result.fieldCount>20) return sendJson(res,400,{errors:[{message:'query complexity limit exceeded'}]});
    if (result.context.unknownFields.length) return sendJson(res,200,{errors:[{message:'unknown field'}]});
    if (result.context.otpResults.some(e=>e.attempts>5)) return sendJson(res,429,{errors:[{message:'too many attempts'}]});
    return sendJson(res,200,{data:result.data});
  }
  const result=gqlExecute(source,{viewerId});
  if (source.includes('__schema')||source.includes('__type')) labTrigger('GQL-001',req,{});
  if (result.fieldCount>100) labTrigger('GQL-005',req,{aliases:result.fieldCount});
  if (result.context.crossUserReads.length) labTrigger('GQL-006',req,{targets:result.context.crossUserReads});
  if (result.context.otpResults.some(e=>e.attempts>5)) labTrigger('GQL-004',req,{attempts:result.context.otpResults});
  return sendJson(res,200,gqlBuildResponse(result,false));
}

route('POST', /^\/graphql\/?$/, async (req, res) => handleGraphQL(req, res, false));
route('POST', /^\/graphql_safe\/?$/, async (req, res) => handleGraphQL(req, res, true));
route('GET', /^\/graphql\/?$/, async (req, res) => sendJson(res, 200, {service:'graphql', hint:'POST a JSON body with {query:"..."}'}));

route('POST', /^\/__lab\/internal\/reset_gql$/, async (req, res) => {
  for (const key of Object.keys(gqlOtpAttempts)) delete gqlOtpAttempts[key];
  sendJson(res, 200, {reset:true});
});

// ─── Crawl-lab routes (merged from crawl-lab service) ────────────────────────
// CRAWL-001..008: SPA crawler surface for discovery benchmarking.

const SPA_INDEX_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ShopForge SPA</title>
<base href="/spa/">
</head>
<body>
<div id="app">Loading</div>
<a href="#/dashboard">Dashboard</a>
<a href="#/settings">Settings</a>
<a data-href="/spa/panel">Support panel</a>
<script src="/spa/app.js"></script>
<script>
  window.__ROUTES__ = ['#/dashboard', '#/settings', '#/orders'];
</script>
</body>
</html>`;

const SPA_APP_JS = `// ShopForge SPA bundle
const INTERNAL_API_KEY = 'vulnforge_spa_internal_key_9f2c';
const INTERNAL_ENDPOINT = '/spa/panel';
const EXPORT_ENDPOINT = '/spa/api/export';
function navigate(hash) { document.getElementById('app').innerHTML = 'Route: ' + hash; }
window.addEventListener('hashchange', () => navigate(location.hash));
navigate(location.hash || '#/dashboard');
fetch('/spa/api/products?page=1').then(r=>r.json()).then(d=>console.log('loaded', d.count));
fetch(INTERNAL_ENDPOINT, { headers: { 'X-Internal-Key': INTERNAL_API_KEY } });
// sourceMappingURL=app.js.map
`;

const SPA_APP_MAP = JSON.stringify({
  version: 3, file: 'app.js',
  sources: ['../src/app.ts', '../src/secret/config.ts'],
  sourcesContent: [
    "const INTERNAL_API_KEY = 'vulnforge_spa_internal_key_9f2c';",
    "export const ADMIN_PANEL = '/spa/panel';\nexport const DB_PASSWORD = 'spa_debug_password';",
  ],
  mappings: '',
});

const spaProducts = Array.from({ length: 5000 }, (_, i) => ({
  id: i + 1, name: `SPA product ${i + 1}`, price: Number(((i % 90) + 1.99).toFixed(2)),
}));

function sendHtml(res, status, body, extraHeaders = {}) {
  const buf = Buffer.from(body);
  res.writeHead(status, { 'content-type': 'text/html; charset=utf-8', 'content-length': buf.length, ...extraHeaders });
  res.end(buf);
}

function sendText(res, status, body, type = 'text/plain', extraHeaders = {}) {
  const buf = Buffer.from(body);
  res.writeHead(status, { 'content-type': type, 'content-length': buf.length, ...extraHeaders });
  res.end(buf);
}

// @vuln id=CRAWL-001 name="robots.txt discloses hidden application paths" cwe=CWE-200 owasp=A05:2021 type=robots-disclosure level=1 param=none method=GET service=node-api url=/spa/robots.txt param_loc=path needs_oob=false auth=false detection=passive tags=discovery,info-leak,robots proof_kind=marker proof_desc="Disallow entries reveal the support panel and export endpoint"
route('GET', /^\/spa\/robots\.txt$/, async (req, res) => {
  labTrigger('CRAWL-001', req, {});
  sendText(res, 200, [
    'User-agent: *', 'Disallow: /spa/panel', 'Disallow: /spa/api/export',
    'Disallow: /spa/api/products', 'Sitemap: /spa/sitemap.xml', '',
  ].join('\n'));
});

// @control id=CRAWL-001-C twin_of=CRAWL-001 url=/spa/robots_safe.txt method=GET param=none service=node-api param_loc=path
route('GET', /^\/spa\/robots_safe\.txt$/, async (req, res) => {
  sendText(res, 200, 'User-agent: *\nDisallow: /\n');
});

route('GET', /^\/spa\/sitemap\.xml$/, async (req, res) => {
  sendText(res, 200, `<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>/spa/</loc></url><url><loc>/spa/#/dashboard</loc></url><url><loc>/spa/panel</loc></url></urlset>`, 'application/xml');
});

// @vuln id=CRAWL-002 name="JavaScript source map exposes source code" cwe=CWE-540 owasp=A05:2021 type=source-map-exposure level=1 param=none method=GET service=node-api url=/spa/app.js.map param_loc=path needs_oob=false auth=false detection=passive tags=discovery,info-leak,source-map proof_kind=marker proof_desc="The .map file serves original sources including embedded credentials"
route('GET', /^\/spa\/app\.js\.map$/, async (req, res) => {
  labTrigger('CRAWL-002', req, {});
  sendText(res, 200, SPA_APP_MAP, 'application/json');
});

// @control id=CRAWL-002-C twin_of=CRAWL-002 url=/spa/app_safe.js.map method=GET param=none service=node-api param_loc=path
route('GET', /^\/spa\/app_safe\.js\.map$/, async (req, res) => {
  sendJson(res, 404, { error: 'not found' });
});

// @vuln id=CRAWL-003 name="API key embedded in the client bundle" cwe=CWE-798 owasp=A02:2021 type=hardcoded-secret level=1 param=none method=GET service=node-api url=/spa/app.js param_loc=path needs_oob=false auth=false detection=passive tags=discovery,info-leak,secret proof_kind=marker proof_desc="The bundle contains a hard-coded internal API key"
route('GET', /^\/spa\/app\.js$/, async (req, res) => {
  labTrigger('CRAWL-003', req, {});
  sendText(res, 200, SPA_APP_JS, 'application/javascript');
});

// @control id=CRAWL-003-C twin_of=CRAWL-003 url=/spa/app_safe.js method=GET param=none service=node-api param_loc=path
route('GET', /^\/spa\/app_safe\.js$/, async (req, res) => {
  sendText(res, 200, "const INTERNAL_ENDPOINT = '/spa/panel';\n", 'application/javascript');
});

// @vuln id=CRAWL-004 name="Soft 404 returns HTTP 200" cwe=CWE-391 owasp=A05:2021 type=soft-404 level=2 param=path method=GET service=node-api url=/spa/this-page-does-not-exist param_loc=path needs_oob=false auth=false detection=passive tags=discovery,soft-404 proof_kind=marker proof_desc="Unknown paths return 200 with a 'not found' body, confusing crawlers"
route('GET', /^\/spa\/this-page-does-not-exist$/, async (req, res) => {
  labTrigger('CRAWL-004', req, {});
  sendHtml(res, 200, '<html><body><h1>Page not found</h1></body></html>');
});

// @control id=CRAWL-004-C twin_of=CRAWL-004 url=/spa/not-found-safe-404 method=GET param=path service=node-api param_loc=path
route('GET', /^\/spa\/not-found-safe-404$/, async (req, res) => {
  sendHtml(res, 404, '<html><body><h1>Page not found</h1></body></html>');
});

// @vuln id=CRAWL-005 name="Unbounded pagination trap" cwe=CWE-770 owasp=A04:2021 type=infinite-pagination level=2 param=page method=GET service=node-api url=/spa/api/products param_loc=query needs_oob=false auth=false detection=passive tags=discovery,pagination,dos proof_kind=marker proof_desc="page parameter has no upper bound and always returns a next page"
route('GET', /^\/spa\/api\/products$/, async (req, res, m, url) => {
  const page = Number(url.searchParams.get('page') || 1);
  const size = 20;
  const start = Math.max(0, (page - 1) * size);
  const items = spaProducts.slice(start, start + size);
  if (page > 100) labTrigger('CRAWL-005', req, { page });
  sendJson(res, 200, { page, items, next: `/spa/api/products?page=${page + 1}`, total: spaProducts.length });
});

// @control id=CRAWL-005-C twin_of=CRAWL-005 url=/spa/api/products_safe method=GET param=page service=node-api param_loc=query
route('GET', /^\/spa\/api\/products_safe$/, async (req, res, m, url) => {
  const requested = Number(url.searchParams.get('page') || 1);
  const page = Math.min(Math.max(requested, 1), 50);
  const start = (page - 1) * 20;
  sendJson(res, 200, { page, items: spaProducts.slice(start, start + 20), next: page < 50 ? `/spa/api/products_safe?page=${page + 1}` : null });
});

// @vuln id=CRAWL-006 name="WebSocket upgrade accepts any Origin" cwe=CWE-346 owasp=A01:2021 type=cswsh level=2 param=Origin method=GET service=node-api url=/spa/ws-ticket param_loc=header needs_oob=false auth=false detection=passive tags=websocket,cswsh,origin proof_kind=marker proof_desc="Upgrade is allowed for an arbitrary attack origin"
route('GET', /^\/spa\/ws-ticket$/, async (req, res) => {
  const origin = req.headers.origin || '';
  labTrigger('CRAWL-006', req, { origin });
  sendJson(res, 200, { upgrade_allowed: true, origin });
});

// @control id=CRAWL-006-C twin_of=CRAWL-006 url=/spa/ws-ticket_safe method=GET param=Origin service=node-api param_loc=header
route('GET', /^\/spa\/ws-ticket_safe$/, async (req, res) => {
  const origin = req.headers.origin || '';
  const allowed = origin === 'http://127.0.0.1:8000';
  sendJson(res, allowed ? 200 : 403, { upgrade_allowed: allowed });
});

// @vuln id=CRAWL-007 name="SSE stream leaks session token to any client" cwe=CWE-200 owasp=A05:2021 type=sse-data-leak level=2 param=none method=GET service=node-api url=/spa/events param_loc=path needs_oob=false auth=false detection=passive tags=discovery,sse,info-leak proof_kind=marker proof_desc="The event stream contains a reusable session token"
route('GET', /^\/spa\/events$/, async (req, res) => {
  const token = crypto.randomBytes(8).toString('hex');
  labTrigger('CRAWL-007', req, { token });
  const body = `event: session\ndata: {"user":"admin","session_token":"${token}"}\n\nevent: heartbeat\ndata: {"ok":true}\n\n`;
  const buf = Buffer.from(body);
  res.writeHead(200, { 'content-type': 'text/event-stream', 'content-length': buf.length });
  res.end(buf);
});

// @control id=CRAWL-007-C twin_of=CRAWL-007 url=/spa/events_safe method=GET param=none service=node-api param_loc=path
route('GET', /^\/spa\/events_safe$/, async (req, res) => {
  sendText(res, 200, 'event: heartbeat\ndata: {"ok":true}\n\n', 'text/event-stream');
});

// @vuln id=CRAWL-008 name="Hidden admin panel reachable without authentication" cwe=CWE-425 owasp=A01:2021 type=hidden-panel level=2 param=none method=GET service=node-api url=/spa/panel param_loc=path needs_oob=false auth=false detection=active tags=discovery,access-control,hidden-endpoint proof_kind=marker proof_desc="The undocumented support panel is served to anyone who finds it"
route('GET', /^\/spa\/panel$/, async (req, res) => {
  labTrigger('CRAWL-008', req, {});
  sendHtml(res, 200, `<!doctype html><html><body><h1>Internal support panel</h1><p>admin panel - order override - coupon reset</p></body></html>`);
});

// @control id=CRAWL-008-C twin_of=CRAWL-008 url=/spa/panel_safe method=GET param=none service=node-api param_loc=path
route('GET', /^\/spa\/panel_safe$/, async (req, res) => {
  sendJson(res, 403, { error: 'authentication required' });
});

route('GET', /^\/spa\/surface\.json$/, async (req, res) => {
  sendJson(res, 200, { surfaces: ['/spa/#/dashboard', '/spa/#/settings', '/spa/panel', '/spa/api/products?page=1', '/spa/events'] });
});

// SPA shell catch-all (soft-404 behaviour)
route('GET', /^\/spa(\/.*)?$/, async (req, res) => {
  sendHtml(res, 200, SPA_INDEX_HTML);
});

// ─── Server ──────────────────────────────────────────────────────────────────

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const path = url.pathname;

  // Preflight support for the CORS test routes.
  if (req.method === 'OPTIONS') {
    return sendJson(res, 204, {});
  }

  for (const entry of routes) {
    if (entry.method !== req.method) continue;
    const match = entry.pattern.exec(path);
    if (!match) continue;
    try {
      await entry.handler(req, res, match, url);
    } catch (error) {
      // Verbose error output is itself part of the lab surface.
      sendJson(res, 500, { error: String(error.message || error), stack: String(error.stack || '') });
    }
    return;
  }

  sendJson(res, 404, { error: 'not found', path });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[node-api] listening on ${PORT}`);
});
