// VulnForge Lab — graphql-svc
//
// Dependency-free GraphQL endpoint with intentionally weak behaviour:
// introspection, field suggestions, unbounded batching, alias brute force,
// depth amplification and broken object-level authorisation.
//
// The hardened twin is served from /graphql_safe on the same port so the
// gateway can route both paths.
//
// WARNING: never expose this service outside an isolated lab.

'use strict';

const http = require('node:http');
const { URL } = require('node:url');

const PORT = Number(process.env.PORT || 4000);
const LAB_CONTROL_URL = process.env.LAB_CONTROL_URL || 'http://lab-control:9100';

const users = [
  { id: 1, username: 'admin', email: 'admin@vulnforge.lab', role: 'admin', ssn: '111-11-1111', otp: '4821' },
  { id: 2, username: 'alice', email: 'alice@vulnforge.lab', role: 'user', ssn: '222-22-2222', otp: '1111' },
  { id: 3, username: 'bob', email: 'bob@vulnforge.lab', role: 'user', ssn: '333-33-3333', otp: '2222' },
];

const otpAttempts = {};

function labTrigger(vulnId, req, extra = {}) {
  const payload = JSON.stringify({
    kind: 'vuln_triggered',
    vuln_id: vulnId,
    service: 'graphql-svc',
    request_id: req.headers['x-request-id'] || '',
    ts: new Date().toISOString(),
    ...extra,
  });

  fetch(`${LAB_CONTROL_URL}/__lab/events`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: payload,
    signal: AbortSignal.timeout(1000),
  }).catch(() => {});
}

// ─── Minimal query parser ────────────────────────────────────────────────────

function tokenize(source) {
  return source
    .replace(/#[^\n]*/g, ' ')
    .match(/[_A-Za-z][_0-9A-Za-z]*|[-+]?\d+(?:\.\d+)?|"(?:[^"\\]|\\.)*"|[{}():,!$\[\]]/g) || [];
}

function parseSelection(tokens, state) {
  const fields = [];
  if (tokens[state.index] !== '{') return fields;
  state.index++;

  while (state.index < tokens.length && tokens[state.index] !== '}') {
    const first = tokens[state.index++];
    let alias = first;
    let name = first;

    if (tokens[state.index] === ':') {
      state.index++;
      name = tokens[state.index++];
    }

    const args = {};
    if (tokens[state.index] === '(') {
      state.index++;
      while (state.index < tokens.length && tokens[state.index] !== ')') {
        if (tokens[state.index] === ',') {
          state.index++;
          continue;
        }
        const argName = tokens[state.index++];
        if (tokens[state.index] === ':') state.index++;
        const valueToken = tokens[state.index++];
        try {
          args[argName] = JSON.parse(valueToken);
        } catch {
          args[argName] = valueToken;
        }
      }
      state.index++;
    }

    let children = null;
    if (tokens[state.index] === '{') {
      children = parseSelection(tokens, state);
    }

    fields.push({ alias, name, args, children });
  }

  if (tokens[state.index] === '}') state.index++;
  return fields;
}

function parseQuery(source) {
  const tokens = tokenize(source);
  const state = { index: 0 };

  if (['query', 'mutation'].includes(tokens[state.index])) {
    state.index++;
    if (tokens[state.index] && !['{', '('].includes(tokens[state.index])) state.index++;
  }

  return parseSelection(tokens, state);
}

// ─── Schema + resolvers ──────────────────────────────────────────────────────

const SCHEMA = {
  queryType: { name: 'Query' },
  types: [
    {
      kind: 'OBJECT',
      name: 'User',
      fields: ['id', 'username', 'email', 'role', 'ssn'].map((name) => ({ name, type: 'String' })),
    },
    {
      kind: 'OBJECT',
      name: 'Query',
      fields: [
        { name: 'hello', type: 'String' },
        { name: 'user', type: 'User', args: [{ name: 'id', type: 'Int' }] },
        { name: 'users', type: 'User' },
        { name: 'verifyOtp', type: 'Boolean', args: [{ name: 'userId', type: 'Int' }, { name: 'code', type: 'String' }] },
      ],
    },
    { kind: 'SCALAR', name: 'Int' },
    { kind: 'SCALAR', name: 'String' },
    { kind: 'SCALAR', name: 'Boolean' },
  ],
};

function projectUser(user, fields) {
  const result = {};
  for (const field of fields) {
    if (field.name === '__typename') result[field.alias] = 'User';
    else if (field.name in user) result[field.alias] = user[field.name];
  }
  return result;
}

function execute(source, options = {}) {
  const fields = parseQuery(source);
  const context = {
    schema: options.introspection === false ? null : SCHEMA,
    viewerId: Number(options.viewerId || 0),
    enforceOwnership: options.enforceOwnership === true,
    crossUserReads: [],
    unknownFields: [],
    otpResults: [],
  };

  const data = {};
  for (const field of fields) {
    switch (field.name) {
      case '__typename':
        data[field.alias] = 'Query';
        break;
      case '__schema':
        data[field.alias] = context.schema;
        break;
      case '__type':
        data[field.alias] = SCHEMA.types.find((type) => type.name === field.args.name) || null;
        break;
      case 'hello':
        data[field.alias] = 'Hello from VulnForge GraphQL';
        break;
      case 'user': {
        const id = Number(field.args.id || 0);
        const user = users.find((entry) => entry.id === id);
        if (!user) {
          data[field.alias] = null;
          break;
        }
        if (context.enforceOwnership && id !== context.viewerId) {
          data[field.alias] = null;
          break;
        }
        if (!context.enforceOwnership && id !== context.viewerId) {
          context.crossUserReads.push(id);
        }
        data[field.alias] = projectUser(user, field.children || [{ name: 'username' }]);
        break;
      }
      case 'users': {
        const visible = context.enforceOwnership
          ? users.filter((entry) => entry.id === context.viewerId)
          : users;
        data[field.alias] = visible.map((user) => projectUser(user, field.children || [{ name: 'username' }]));
        break;
      }
      case 'verifyOtp': {
        const userId = Number(field.args.userId || 0);
        const code = String(field.args.code || '');
        const key = `u${userId}`;
        otpAttempts[key] = (otpAttempts[key] || 0) + 1;
        const user = users.find((entry) => entry.id === userId);
        const ok = !!user && user.otp === code;
        context.otpResults.push({ userId, ok, attempts: otpAttempts[key] });
        data[field.alias] = ok;
        break;
      }
      default:
        context.unknownFields.push(field.name);
        data[field.alias] = null;
    }
  }

  return { data, context, fieldCount: fields.length };
}

function suggestField(name) {
  const candidates = SCHEMA.types.find((type) => type.name === 'Query').fields.map((field) => field.name);
  let best = candidates[0];
  let bestScore = Infinity;
  for (const candidate of candidates) {
    const score = levenshtein(name, candidate);
    if (score < bestScore) {
      bestScore = score;
      best = candidate;
    }
  }
  return best;
}

function levenshtein(a, b) {
  const matrix = Array.from({ length: a.length + 1 }, (_, index) => [index]);
  for (let j = 1; j <= b.length; j++) matrix[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      matrix[i][j] = Math.min(
        matrix[i - 1][j] + 1,
        matrix[i][j - 1] + 1,
        matrix[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1),
      );
    }
  }
  return matrix[a.length][b.length];
}

// ─── HTTP plumbing ───────────────────────────────────────────────────────────

function sendJson(res, status, data, headers = {}) {
  const payload = JSON.stringify(data);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(payload),
    ...headers,
  });
  res.end(payload);
}

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
  });
}

// @vuln id=GQL-001 name="GraphQL introspection enabled" cwe=CWE-200 owasp=A05:2021 owasp_api=API9 type=introspection-enabled level=1 param=query method=POST service=graphql-svc url=/graphql param_loc=json needs_oob=false auth=false detection=config tags=graphql,info-leak,introspection proof_kind=marker proof_desc="__schema returns the full type system"
// @vuln id=GQL-002 name="Field suggestion leaks hidden field names" cwe=CWE-200 owasp=A05:2021 owasp_api=API9 type=field-suggestion level=1 param=query method=POST service=graphql-svc url=/graphql param_loc=json needs_oob=false auth=false detection=config tags=graphql,info-leak proof_kind=marker proof_desc="Unknown field names produce did-you-mean hints"
// @vuln id=GQL-003 name="Unbounded query batching" cwe=CWE-770 owasp=A04:2021 owasp_api=API4 type=query-batching level=2 param=query method=POST service=graphql-svc url=/graphql param_loc=json needs_oob=false auth=false detection=logic tags=graphql,dos,batching proof_kind=marker proof_desc="A batch array with hundreds of operations is executed in one request"
// @vuln id=GQL-004 name="OTP verification without attempt limit" cwe=CWE-307 owasp=A04:2021 owasp_api=API4 type=otp-bruteforce level=2 param=code method=POST service=graphql-svc url=/graphql param_loc=json needs_oob=false auth=false detection=logic tags=graphql,auth,rate-limit proof_kind=marker proof_desc="Alias-based brute force verifies the OTP with no lockout"
// @vuln id=GQL-005 name="No query complexity limit allows alias amplification" cwe=CWE-770 owasp=A04:2021 owasp_api=API4 type=depth-dos level=2 param=query method=POST service=graphql-svc url=/graphql param_loc=json needs_oob=false auth=false detection=logic tags=graphql,dos proof_kind=marker proof_desc="A single query with hundreds of aliases is accepted and executed"
// @vuln id=GQL-006 name="BOLA in GraphQL user resolver" cwe=CWE-639 owasp=A01:2021 owasp_api=API1 type=bola level=1 param=id method=POST service=graphql-svc url=/graphql param_loc=json needs_oob=false auth=true detection=api tags=graphql,access-control,bola proof_kind=marker proof_desc="user(id:) returns another user's SSN without an ownership check"

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

  if (req.method === 'GET' && url.pathname === '/health') {
    return sendJson(res, 200, { status: 'ok', service: 'graphql-svc' });
  }

  if (req.method === 'POST' && url.pathname === '/__lab/internal/reset') {
    for (const key of Object.keys(otpAttempts)) delete otpAttempts[key];
    return sendJson(res, 200, { reset: true });
  }

  const isSafe = url.pathname === '/graphql_safe';
  if (!isSafe && url.pathname !== '/graphql' && url.pathname !== '/graphql/') {
    return sendJson(res, 404, { error: 'not found' });
  }

  const raw = await readBody(req);
  let payload;
  try {
    payload = raw ? JSON.parse(raw) : {};
  } catch {
    return sendJson(res, 400, { errors: [{ message: 'invalid JSON body' }] });
  }

  if (Array.isArray(payload)) {
    // SAFE: hard batch cap. VULNERABLE: no cap at all.
    if (isSafe && payload.length > 5) {
      return sendJson(res, 400, { errors: [{ message: 'batch size limit exceeded' }] });
    }
    if (!isSafe && payload.length > 1) {
      labTrigger('GQL-003', req, { batch_size: payload.length });
    }

    const viewerId = req.headers['x-user-id'];
    const results = payload.map((entry) => execute(String(entry.query || ''), {
      introspection: !isSafe,
      enforceOwnership: isSafe,
      viewerId,
    }));
    const totalFields = results.reduce((sum, entry) => sum + entry.fieldCount, 0);

    if (isSafe && totalFields > 20) {
      return sendJson(res, 400, { errors: [{ message: 'query complexity limit exceeded' }] });
    }
    if (!isSafe && totalFields > 100) {
      labTrigger('GQL-005', req, { aliases: totalFields });
    }

    return sendJson(res, 200, results.map((entry) => buildResponse(entry, isSafe)), {
      'x-batch-size': String(payload.length),
    });
  }

  const source = String(payload.query || '');
  const viewerId = req.headers['x-user-id'];

  if (isSafe) {
    if (source.includes('__schema') || source.includes('__type')) {
      return sendJson(res, 200, { errors: [{ message: 'introspection is disabled' }] });
    }
    const result = execute(source, { introspection: false, enforceOwnership: true, viewerId });
    if (result.fieldCount > 20) {
      return sendJson(res, 400, { errors: [{ message: 'query complexity limit exceeded' }] });
    }
    if (result.context.unknownFields.length) {
      return sendJson(res, 200, { errors: [{ message: 'unknown field' }] });
    }
    // SAFE: a bounded number of OTP attempts per user is enforced.
    if (result.context.otpResults.some((entry) => entry.attempts > 5)) {
      return sendJson(res, 429, { errors: [{ message: 'too many attempts' }] });
    }
    return sendJson(res, 200, { data: result.data });
  }

  const result = execute(source, { viewerId });

  if (source.includes('__schema') || source.includes('__type')) {
    labTrigger('GQL-001', req, {});
  }
  if (result.fieldCount > 100) {
    labTrigger('GQL-005', req, { aliases: result.fieldCount });
  }
  if (result.context.crossUserReads.length) {
    labTrigger('GQL-006', req, { targets: result.context.crossUserReads });
  }
  if (result.context.otpResults.some((entry) => entry.attempts > 5)) {
    labTrigger('GQL-004', req, { attempts: result.context.otpResults });
  }

  return sendJson(res, 200, buildResponse(result, false));
});

function buildResponse(result, isSafe) {
  const response = { data: result.data };

  if (result.context.unknownFields.length) {
    response.errors = result.context.unknownFields.map((name) => ({
      message: isSafe
        ? 'unknown field'
        // !! INTENTIONALLY VULNERABLE — suggestions reveal hidden field names !!
        : `Cannot query field "${name}" on type "Query". Did you mean "${suggestField(name)}"?`,
    }));
  }

  return response;
}

// @control id=GQL-001-C twin_of=GQL-001 url=/graphql_safe method=POST param=query service=graphql-svc param_loc=json
// @control id=GQL-002-C twin_of=GQL-002 url=/graphql_safe method=POST param=query service=graphql-svc param_loc=json
// @control id=GQL-003-C twin_of=GQL-003 url=/graphql_safe method=POST param=query service=graphql-svc param_loc=json
// @control id=GQL-004-C twin_of=GQL-004 url=/graphql_safe method=POST param=code service=graphql-svc param_loc=json
// @control id=GQL-005-C twin_of=GQL-005 url=/graphql_safe method=POST param=query service=graphql-svc param_loc=json
// @control id=GQL-006-C twin_of=GQL-006 url=/graphql_safe method=POST param=id service=graphql-svc param_loc=json

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[graphql-svc] listening on ${PORT}`);
});
