"""Persistent ShopForge records, isolated from the vulnerability fixtures."""

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from contextlib import contextmanager
from pathlib import Path

APP_DIR = Path(__file__).parent
DB_PATH = Path(
    os.environ.get("SHOPFORGE_DB", str(APP_DIR / "data" / "shopforge.sqlite3"))
)


def password_hash(password):
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), 120000
    ).hex()
    return f"{salt}:{digest}"


def password_matches(password, stored):
    salt, expected = stored.split(":", 1)
    actual = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), 120000
    ).hex()
    return hmac.compare_digest(actual, expected)


@contextmanager
def database(write=False):
    connection = sqlite3.connect(DB_PATH, timeout=15)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    try:
        if write:
            connection.execute("BEGIN IMMEDIATE")
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with database() as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.executescript("""
        CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE, password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')),
            phone TEXT NOT NULL DEFAULT '', address TEXT NOT NULL DEFAULT '');
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT, token TEXT NOT NULL UNIQUE,
            csrf TEXT NOT NULL, user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            expires INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, category TEXT NOT NULL,
            price_cents INTEGER NOT NULL CHECK(price_cents>=0), description TEXT NOT NULL,
            stock INTEGER NOT NULL CHECK(stock>=0));
        CREATE TABLE IF NOT EXISTS cart (
            session_id INTEGER REFERENCES sessions(id) ON DELETE CASCADE,
            product_id INTEGER REFERENCES products(id) ON DELETE CASCADE,
            quantity INTEGER NOT NULL CHECK(quantity BETWEEN 1 AND 99),
            PRIMARY KEY(session_id,product_id));
        CREATE TABLE IF NOT EXISTS wishlist (
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            product_id INTEGER REFERENCES products(id) ON DELETE CASCADE,
            PRIMARY KEY(user_id,product_id));
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            total INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'pending', address TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS order_lines (
            id INTEGER PRIMARY KEY AUTOINCREMENT, order_id INTEGER REFERENCES orders(id) ON DELETE CASCADE,
            product_id INTEGER REFERENCES products(id) ON DELETE SET NULL,
            name TEXT NOT NULL, unit_price INTEGER NOT NULL, quantity INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            subject TEXT NOT NULL, body TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open',
            reply TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, slug TEXT NOT NULL UNIQUE,
            title TEXT NOT NULL, body TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE,
            product_id INTEGER REFERENCES products(id) ON DELETE CASCADE,
            body TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS subscribers (email TEXT PRIMARY KEY COLLATE NOCASE);
        """)
    with database(write=True) as db:
        if db.execute("SELECT 1 FROM settings WHERE key='seeded'").fetchone():
            return
        admin_password = os.environ.get("SHOPFORGE_ADMIN_PASSWORD", "admin123")
        user_password = os.environ.get("SHOPFORGE_USER_PASSWORD", "alice123")
        for username, role in (("admin", "admin"), ("alice", "user"), ("bob", "user")):
            db.execute(
                "INSERT INTO users(username,email,password,role,address) VALUES(?,?,?,?,?)",
                (
                    username,
                    f"{username}@shopforge.example",
                    password_hash(admin_password if role == "admin" else user_password),
                    role,
                    "24 Cedar Street, Harbor City",
                ),
            )
        for product in json.loads((APP_DIR / "catalog.json").read_text()):
            db.execute(
                "INSERT INTO products(id,name,category,price_cents,description,stock) VALUES(?,?,?,?,?,?)",
                (
                    product["id"],
                    product["name"],
                    product["category"],
                    int(round(float(product["price"]) * 100)),
                    product["description"],
                    25,
                ),
            )
        for slug, title, body in (
            (
                "how-we-built-our-api",
                "Meet the new ShopForge",
                "Browse our latest collection of electronics and accessories. Save your favorites and manage your orders in one place.",
            ),
            (
                "security-update-2024",
                "Taking care of your account",
                "Keep your contact details current so our team can help with your orders. You can update your password from your account settings.",
            ),
            (
                "legacy-migration",
                "A fresh shopping experience",
                "Our store has a new look. Explore the catalog and contact our support team if you need help choosing a product.",
            ),
        ):
            db.execute(
                "INSERT INTO posts(slug,title,body) VALUES(?,?,?)", (slug, title, body)
            )
        order = db.execute(
            "INSERT INTO orders(user_id,total,status,address) VALUES(2,11900,'shipped','24 Cedar Street, Harbor City')"
        ).lastrowid
        db.execute(
            "INSERT INTO order_lines(order_id,product_id,name,unit_price,quantity) VALUES(?,5,'CedarJet M220 Printer',11900,1)",
            (order,),
        )
        db.execute(
            "INSERT INTO tickets(user_id,subject,body,reply,status) VALUES(2,'Delivery instructions','Please leave my parcel at reception.','We have updated the delivery instructions.','closed')"
        )
        db.execute(
            "INSERT INTO comments(user_id,product_id,body) VALUES(2,5,'Easy to set up and a good fit for my desk.')"
        )
        db.execute("INSERT INTO settings VALUES('seeded','1')")


def product_record(row):
    product = dict(row)
    product["price"] = f"{product['price_cents'] / 100:.2f}"
    return product


def cart_items(db, session_id):
    return [
        dict(row)
        for row in db.execute(
            "SELECT p.id AS product_id,p.name,p.price_cents AS price,p.stock,c.quantity,"
            "p.price_cents*c.quantity AS subtotal FROM cart c JOIN products p ON p.id=c.product_id "
            "WHERE c.session_id=? ORDER BY p.id",
            (session_id,),
        )
    ]


def order_records(db, user_id=None):
    condition = " WHERE user_id=?" if user_id is not None else ""
    orders = [
        dict(row)
        for row in db.execute(
            "SELECT * FROM orders" + condition + " ORDER BY id DESC",
            (user_id,) if user_id is not None else (),
        )
    ]
    lines = {}
    for row in db.execute(
        "SELECT l.* FROM order_lines l JOIN orders o ON o.id=l.order_id"
        + (" WHERE o.user_id=?" if user_id is not None else ""),
        (user_id,) if user_id is not None else (),
    ):
        lines.setdefault(row["order_id"], []).append(dict(row))
    for order in orders:
        order["lines"] = lines.get(order["id"], [])
    return orders


def cancel_order(db, order_id):
    order = db.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
    if order is None:
        raise ValueError("Order not found.")
    if order["status"] == "cancelled":
        return
    if order["status"] != "pending":
        raise ValueError("Only pending orders can be cancelled.")
    for line in db.execute("SELECT * FROM order_lines WHERE order_id=?", (order_id,)):
        db.execute(
            "UPDATE products SET stock=stock+? WHERE id=?",
            (line["quantity"], line["product_id"]),
        )
    db.execute("UPDATE orders SET status='cancelled' WHERE id=?", (order_id,))
