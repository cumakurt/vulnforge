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
