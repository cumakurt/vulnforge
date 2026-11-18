# ShopForge store and scanner setup

ShopForge is the storefront served by the gateway at `/`. With the installer
option `--port 18000`, open `http://127.0.0.1:18000/`; otherwise use the configured
`GATEWAY_HTTP_PORT`. Nginx and the Python store run in the same gateway
container. No additional database container is required for the store.

## Working store flows

| Area | Behavior |
|---|---|
| Accounts | Register, sign in, sign out, edit a profile and change a password |
| Catalog | Browse and search products; open individual product pages |
| Shopping | Add products to a cart or wishlist, update quantities and remove items |
| Checkout | Create an order from the cart, record shipping details and update stock |
| Orders | View the signed-in customer's saved order history |
| Support | Submit and track support requests |
| Content | Read blog articles, submit comments and subscribe to the newsletter |
| Administration | Manage users and products, review orders and handle support requests |

Checkout records orders locally. It does not charge a payment card, contact a
payment provider or send real shipments. Support requests and newsletter
subscriptions are saved locally; they do not send external mail.

The public pages use ordinary storefront language. Vulnerability annotations,
payload examples, lab credentials and links to harness diagnostics belong in
repository documentation, rather than in storefront text, scripts or HTML
comments. Administrative controls require an administrator session.

## Synthetic accounts and sessions

The first initialization creates these local lab accounts:

| Username | Role | Default synthetic password |
|---|---|---|
| `admin` | Administrator | `admin123` |
| `alice` | Customer | `alice123` |
| `bob` | Customer | `alice123` |

Set `SHOPFORGE_ADMIN_PASSWORD` and `SHOPFORGE_USER_PASSWORD` before the first
initialization to override the seeded passwords. These variables initialize
new databases; they do not change passwords in an existing store. Use account
settings or user management to change a saved password.

For an authenticated scan, submit the normal `/login` form and retain the
session cookie. Register a separate account for repeatable customer scans.
Use the administrator account in a separate scan session when administrative
coverage is required. Include hidden form fields and the current CSRF token
when replaying forms; do not assume a captured token remains valid after
sign-in or sign-out.

The store's customer records and sessions are independent of the legacy lab
services. A ShopForge account does not create a PHP or Node API account, and a
legacy JWT does not authenticate a ShopForge browser session. Existing legacy
accounts are listed in the README and their respective service documentation.

## Store read API

The storefront also exposes normal JSON read endpoints. Their cookie-based
identity is the same as the browser session:

| Method and path | Response |
|---|---|
| `GET /store-api/products` | Current product catalog; no sign-in required |
| `GET /store-api/me` | Signed-in customer's public account fields |
| `GET /store-api/orders` | Signed-in customer's saved orders |

Use the normal HTML forms for mutations. `/store-api/` serves the persistent
ShopForge database; `/api/` is the separate Node lab fixture service.

## Persistence and initialization

`SHOPFORGE_DB` selects the SQLite file. Docker uses
`/app/shopforge/data/shopforge.sqlite3`, stored in the `shopforge_data` Compose
volume (`vulnforge_shopforge_data`). The catalog JSON is a seed, not the live
source of product records. Product edits, new accounts and other saved store
changes survive gateway restart, image rebuild and container recreation.
Initialization must not restore deleted products or accounts on later starts.

Rebuild and start the gateway after updating its source:

```bash
docker compose up -d --build --no-deps gateway
```

This command updates the storefront without recreating the other lab services.
Normal `docker compose down` preserves named volumes. Avoid `down -v` when you
intend to preserve state: it also removes the MySQL volume.

`POST http://127.0.0.1:9100/__lab/reset` and `make reset` reset legacy fixtures
and lab events. They do **not** reset the ShopForge SQLite database.

To deliberately discard all ShopForge records and recreate its initial seed,
stop the gateway, remove only the store volume and start the gateway again.
Back up any records you want to keep first. This operation deletes the store's
users, sessions, cart contents, orders and other saved records.

```bash
docker compose stop gateway
docker compose rm -f gateway
docker volume rm vulnforge_shopforge_data
docker compose up -d --no-deps gateway
```

The removal above is an explicit reset procedure, not part of an ordinary
upgrade. It leaves the MySQL volume and unrelated containers untouched.

## Scanner scope and findings

A scan starting at `/` follows normal customer and account flows. It should
not receive a list of known vulnerabilities from the storefront. Keep normal
navigation discovery separate from a benchmark scan seeded with every known
fixture URL.

The existing backend fixtures remain available at these gateway paths:

| Prefix | Fixture implementation | Reference |
|---|---|---|
| `/php/` | PHP and MySQL | SQL injection, XSS, command injection, upload, auth, CSRF, IDOR |
| `/api/` | Node API | BOLA, BOPLA, BFLA, mass assignment, JWT, NoSQL injection, SSRF |
| `/graphql` | Node API | GraphQL introspection, batching and authorization |
| `/spa/` | Node API | Browser routes, source maps and crawl behavior |
| `/py/` | Flask | Template injection, deserialization, traversal, SSRF and diagnostics |
| `/auth/` | Flask | OAuth, OIDC and SAML fixtures |
| `/legacy/` | Flask | Legacy components, backups and authentication |
| `/java/` | Java | XML, deserialization, expression injection and crypto fixtures |
| `/go/` | Go | SSRF, concurrent business operations, traversal and OTP fixtures |

The [vulnerability catalog](vulnerability-catalog.md) supplies individual
paths, parameters, IDs and safe controls. The [scanner integration guide](scanner-integration.md)
describes lab sessions, event collection and scoring. Ground truth and control
plane endpoints on port `9100`, and the callback collector on port `9000`,
belong outside the scanner target scope.

The raw passive fixture responses remain at
`/scan-fixtures/{case}/{variant}`. Supported cases are `version-header`,
`error-detail` and `internal-hostname`; each accepts `sample-a` and `sample-b`.
The version pair returns 200 with identical bodies; only sample A includes
`X-Powered-By: ShopForge-Demo/0.0.0`. The error pair returns 500; only sample A
includes a synthetic traceback. The hostname pair returns 200; only sample A
includes `inventory.internal.shopforge.invalid`.

There is no public fixture index: `/scan-fixtures` returns 404. Supply the six
response URLs directly to a scanner when comparing these passive signals.
The storefront does not advertise them. Exclude `/scan-fixtures/` from a scored
catalog run because these findings are not catalog vulnerability IDs.

Store operations persist independently of the legacy fixture datasets. Finding
an issue in the store does not automatically create a ground-truth event for a
legacy vulnerability ID. Report store observations separately from the
catalog's scored fixture findings.

## Verification

Run the isolated store workflow suite without Docker. It creates a temporary
SQLite database and uses FastAPI's test client:

```bash
pip install -r services/shopforge/requirements.txt
python3 -m unittest discover -s tests -p 'test_shopforge_workflows.py' -v
```

Run portal checks against the configured gateway address:

```bash
BASE_URL=http://127.0.0.1:18000 python3 tests/test_shopforge.py
```

Legacy smoke and control suites remain separate:

```bash
make test BASE_URL=http://127.0.0.1:18000
```

Use disposable customer accounts and products for state-changing scanner
runs. Preserve the scanner configuration, authentication role, initial store
state and lab version alongside the report so later runs can be compared.
