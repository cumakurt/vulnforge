-- VulnForge Lab — MySQL seed data (synthetic only, no real PII)
-- Applied automatically on first container start.

CREATE DATABASE IF NOT EXISTS vulnforge;
USE vulnforge;

-- ── Users ───────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    username    VARCHAR(64) NOT NULL UNIQUE,
    password    VARCHAR(255) NOT NULL COMMENT 'Intentionally weak hash for testing',
    email       VARCHAR(128),
    role        ENUM('user','admin','moderator') DEFAULT 'user',
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Intentionally MD5-hashed passwords (CWE-916, A02)
INSERT IGNORE INTO users (id, username, password, email, role) VALUES
  (1,  'admin',   MD5('admin123'),    'admin@vulnforge.lab',      'admin'),
  (2,  'alice',   MD5('password1'),   'alice@vulnforge.lab',      'user'),
  (3,  'bob',     MD5('qwerty'),      'bob@vulnforge.lab',        'user'),
  (4,  'charlie', MD5('letmein'),     'charlie@vulnforge.lab',    'user'),
  (5,  'diana',   MD5('sunshine'),    'diana@vulnforge.lab',      'moderator'),
  (6,  'eve',     MD5('monkey'),      'eve@vulnforge.lab',        'user'),
  (7,  'frank',   MD5('123456'),      'frank@vulnforge.lab',      'user'),
  (8,  'grace',   MD5('iloveyou'),    'grace@vulnforge.lab',      'user'),
  (9,  'hector',  MD5('dragon'),      'hector@vulnforge.lab',     'user'),
  (10, 'ivan',    MD5('master'),      'ivan@vulnforge.lab',       'user');

-- ── Products ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS products (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    name        VARCHAR(128) NOT NULL,
    description TEXT,
    price       DECIMAL(10,2),
    category    VARCHAR(64),
    stock       INT DEFAULT 0,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT IGNORE INTO products (id, name, description, price, category, stock) VALUES
  (1,  'Widget Alpha',   'Standard widget for testing',       9.99,  'widgets',   100),
  (2,  'Gadget Beta',    'Advanced gadget with features',    19.99,  'gadgets',    50),
  (3,  'Doohickey Gamma','Mystery device',                    4.99,  'misc',      200),
  (4,  'Thingamajig',   'Unknown purpose item',              14.99,  'misc',       75),
  (5,  'Whatchamacallit','Hard to describe object',           7.49,  'widgets',   150),
  (6,  'Secret Item',   'Only admins should see this',      999.99,  'admin',       1);

-- ── Comments (for Stored XSS) ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS comments (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    product_id  INT,
    user_id     INT,
    username    VARCHAR(64),
    body        TEXT,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
);

INSERT IGNORE INTO comments (product_id, user_id, username, body) VALUES
  (1, 2, 'alice',   'Great widget! Highly recommended.'),
  (1, 3, 'bob',     'Works as expected.'),
  (2, 4, 'charlie', 'The gadget is a bit pricey but worth it.'),
  (3, 5, 'diana',   'What does this even do?');

-- ── Orders (for IDOR) ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS orders (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    user_id     INT,
    product_id  INT,
    quantity    INT DEFAULT 1,
    total       DECIMAL(10,2),
    status      ENUM('pending','paid','shipped','cancelled') DEFAULT 'pending',
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT IGNORE INTO orders (id, user_id, product_id, quantity, total, status) VALUES
  (1, 2, 1, 2, 19.98, 'paid'),
  (2, 2, 3, 1,  4.99, 'shipped'),
  (3, 3, 2, 1, 19.99, 'pending'),
  (4, 4, 4, 3, 44.97, 'paid'),
  (5, 1, 6, 1, 999.99, 'paid');   -- admin's secret order

-- ── Sessions (for session fixation / session management tests) ───────────────
CREATE TABLE IF NOT EXISTS sessions (
    id          VARCHAR(128) PRIMARY KEY,
    user_id     INT,
    data        TEXT,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at  TIMESTAMP
);

-- ── Password reset tokens ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS password_resets (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    user_id     INT,
    token       VARCHAR(64),
    used        TINYINT DEFAULT 0,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ── File uploads ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS uploads (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    user_id     INT,
    filename    VARCHAR(255),
    mime_type   VARCHAR(128),
    path        VARCHAR(512),
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ── CSRF tokens (safe implementation reference) ──────────────────────────────
CREATE TABLE IF NOT EXISTS csrf_tokens (
    token       VARCHAR(64) PRIMARY KEY,
    user_id     INT,
    action      VARCHAR(64),
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at  TIMESTAMP
);
