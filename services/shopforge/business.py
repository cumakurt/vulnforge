"""Storefront routes and ordinary account and administration workflows."""

import hmac
import re
import secrets
import sqlite3
import time
from decimal import Decimal, InvalidOperation
from urllib.parse import parse_qs

from fastapi import Request
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.concurrency import run_in_threadpool

from store import (
    cancel_order,
    cart_items,
    database,
    order_records,
    password_hash,
    password_matches,
    product_record,
)

SESSION_TTL = 7 * 24 * 60 * 60
PUBLIC_USER_FIELDS = "id,username,email,role,phone,address"


class StoreError(Exception):
    def __init__(self, message, status=400):
        self.message = message
        self.status = status


def require_user(request, admin=False):
    user = request.state.user
    if not user:
        raise StoreError("Please sign in to continue.", 401)
    if admin and user["role"] != "admin":
        raise StoreError("You do not have access to this page.", 403)
    return user


async def form_values(request):
    body = await request.body()
    if len(body) > 65536:
        raise StoreError("The submitted form is too large.", 413)
    values = {
        key: items[-1]
        for key, items in parse_qs(
            body.decode("utf-8", errors="replace"), keep_blank_values=True
        ).items()
    }
    if not hmac.compare_digest(
        values.get("csrf_token", "").encode(), request.state.csrf.encode()
    ):
        raise StoreError("This form has expired. Reload the page and try again.", 403)
    return values


def text_field(values, key, maximum=200, required=True):
    value = values.get(key, "").strip()
    if (required and not value) or len(value) > maximum:
        raise StoreError(
            f"Enter a valid {key.replace('_', ' ')} (up to {maximum} characters)."
        )
    return value


def email_field(values):
    value = text_field(values, "email", 254).lower()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value):
        raise StoreError("Enter a valid email address.")
    return value


def password_field(values, key="password"):
    password = values.get(key, "")
    if not 8 <= len(password) <= 128:
        raise StoreError("Use a password between 8 and 128 characters.")
    return password


def integer_field(values, key, minimum=0, maximum=1000000):
    try:
        value = int(values.get(key, ""))
    except ValueError:
        raise StoreError(f"Enter a valid {key.replace('_', ' ')}.") from None
    if not minimum <= value <= maximum:
        raise StoreError(
            f"{key.replace('_', ' ').capitalize()} must be between {minimum} and {maximum}."
        )
    return value


def product_fields(values):
    try:
        price = Decimal(values.get("price", ""))
        if (
            not price.is_finite()
            or price < 0
            or price > 1000000
            or price != price.quantize(Decimal("0.01"))
        ):
            raise InvalidOperation
        cents = int(price * 100)
    except (InvalidOperation, ValueError):
        raise StoreError(
            "Enter a price with no more than two decimal places."
        ) from None
    return (
        text_field(values, "name"),
        text_field(values, "category", 80),
        cents,
        text_field(values, "description", 4000),
        integer_field(values, "stock"),
    )


def redirect(path):
    return RedirectResponse(path, status_code=303)


def existing(db, table, record_id):
    # SQLite INTEGER parameters are signed 64-bit values.
    if not 1 <= record_id <= 2**63 - 1:
        raise StoreError("The requested record was not found.", 404)
    # Table names are supplied by route implementations, never by request input.
    row = db.execute(f"SELECT * FROM {table} WHERE id=?", (record_id,)).fetchone()
    if row is None:
        raise StoreError("The requested record was not found.", 404)
    return row


def install(app, templates):
    def render(request, page, status=200, **context):
        with database() as db:
            count = db.execute(
                "SELECT COALESCE(SUM(quantity),0) FROM cart WHERE session_id=?",
                (request.state.sid,),
            ).fetchone()[0]
        notices = {
            "registered": "Your account is ready. Please sign in.",
            "saved": "Your changes have been saved.",
            "placed": "Thank you. Your order has been placed.",
            "created": "Your support request has been sent.",
        }
        context.setdefault(
            "message",
            next(
                (
                    message
                    for key, message in notices.items()
                    if request.query_params.get(key) == "1"
                ),
                "",
            ),
        )
        return templates.TemplateResponse(
            request=request,
            name="commerce.html",
            context={
                "request": request,
                "page": page,
                "current_user": request.state.user,
                "user": request.state.user,
                "csrf_token": request.state.csrf,
                "cart_count": count,
                **context,
            },
            status_code=status,
        )

    @app.middleware("http")
    async def session_context(request: Request, call_next):
        if request.url.path in {
            "/health",
            "/robots.txt",
            "/sitemap.xml",
        } or request.url.path.startswith("/scan-fixtures"):
            return await call_next(request)
        token = request.cookies.get("sf_session", "")
        now = int(time.time())
        with database(write=True) as db:
            session = db.execute(
                "SELECT * FROM sessions WHERE token=? AND expires>?", (token, now)
            ).fetchone()
            is_new = session is None
            if is_new:
                db.execute("DELETE FROM sessions WHERE expires<=?", (now,))
                token = secrets.token_urlsafe(32)
                csrf = secrets.token_urlsafe(32)
                sid = db.execute(
                    "INSERT INTO sessions(token,csrf,expires) VALUES(?,?,?)",
                    (token, csrf, now + SESSION_TTL),
                ).lastrowid
                user_id = None
            else:
                sid, csrf, user_id = session["id"], session["csrf"], session["user_id"]
            user = db.execute(
                f"SELECT {PUBLIC_USER_FIELDS} FROM users WHERE id=?", (user_id,)
            ).fetchone()
        request.state.sid = sid
        request.state.csrf = csrf
        request.state.user = dict(user) if user else None
        request.state.token = token
        response = await call_next(request)
        if is_new or request.state.token != token:
            response.set_cookie(
                "sf_session",
                request.state.token,
                httponly=True,
                samesite="lax",
                secure=request.url.scheme == "https",
                max_age=SESSION_TTL,
            )
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(StoreError)
    async def store_error(request, error):
        if request.url.path.startswith("/store-api/"):
            return JSONResponse({"detail": error.message}, status_code=error.status)
        if error.status == 401:
            return redirect("/login")
        return render(request, "error", status=error.status, error=error.message)

    @app.exception_handler(sqlite3.IntegrityError)
    async def duplicate_error(request, error):
        return render(
            request,
            "error",
            status=409,
            error="This username, email address or page address is already in use.",
        )

    def catalog_records(q="", category="", sort="name"):
        order_by = {
            "name": "name",
            "price_asc": "price_cents ASC",
            "price_desc": "price_cents DESC",
        }.get(sort, "name")
        with database() as db:
            return [
                product_record(row)
                for row in db.execute(
                    "SELECT * FROM products WHERE (name LIKE ? OR description LIKE ? OR category LIKE ?) "
                    "AND (?='' OR category=? COLLATE NOCASE) ORDER BY " + order_by,
                    (f"%{q}%", f"%{q}%", f"%{q}%", category, category),
                )
            ]

    @app.get("/")
    async def home(request: Request):
        with database() as db:
            count = db.execute(
                "SELECT COALESCE(SUM(quantity),0) FROM cart WHERE session_id=?",
                (request.state.sid,),
            ).fetchone()[0]
            posts = [
                dict(row)
                for row in db.execute("SELECT * FROM posts ORDER BY id DESC LIMIT 3")
            ]
        return templates.TemplateResponse(
            request=request,
            name="home.html",
            context={
                "request": request,
                "catalog": catalog_records()[:8],
                "posts": posts,
                "csrf_token": request.state.csrf,
                "current_user": request.state.user,
                "cart_count": count,
            },
        )

    @app.get("/products")
    @app.get("/search")
    async def products(
        request: Request,
        q: str = "",
        category: str = "",
        sort: str = "name",
        name: str = "",
    ):
        query = (q or name)[:200]
        return render(
            request,
            "products",
            catalog=catalog_records(query, category, sort),
            q=query,
            category=category,
            sort=sort,
        )

    @app.get("/product/{pid}")
    async def detail(request: Request, pid: int):
        with database() as db:
            product = product_record(existing(db, "products", pid))
            reviews = [
                dict(row)
                for row in db.execute(
                    "SELECT c.id,c.body,COALESCE(u.username,'Former member') AS username FROM comments c LEFT JOIN users u ON u.id=c.user_id WHERE c.product_id=? ORDER BY c.id DESC",
                    (pid,),
                )
            ]
        return render(request, "detail", product=product, pid=pid, reviews=reviews)

    @app.get("/login")
    @app.get("/admin/login")
    async def login_page(request: Request):
        return render(request, "login")

    @app.post("/login")
    async def login(request: Request):
        values = await form_values(request)
        username = text_field(values, "username")
        with database() as db:
            user = db.execute(
                "SELECT * FROM users WHERE username=? OR email=?", (username, username)
            ).fetchone()
        valid = user and await run_in_threadpool(
            password_matches, values.get("password", "")[:129], user["password"]
        )
        if not valid:
            return render(
                request,
                "login",
                status=400,
                error="The username or password is incorrect.",
            )
        token = secrets.token_urlsafe(32)
        with database(write=True) as db:
            db.execute(
                "UPDATE sessions SET user_id=?,token=?,csrf=?,expires=? WHERE id=?",
                (
                    user["id"],
                    token,
                    secrets.token_urlsafe(32),
                    int(time.time()) + SESSION_TTL,
                    request.state.sid,
                ),
            )
        request.state.token = token
        return redirect("/admin" if user["role"] == "admin" else "/profile")

    @app.post("/logout")
    async def logout(request: Request):
        await form_values(request)
        with database(write=True) as db:
            db.execute("DELETE FROM sessions WHERE id=?", (request.state.sid,))
        response = redirect("/")
        response.delete_cookie("sf_session")
        return response

    @app.get("/register")
    async def register_page(request: Request):
        return render(request, "register")

    @app.post("/register")
    async def register(request: Request):
        values = await form_values(request)
        username = text_field(values, "username", 40)
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,40}", username):
            raise StoreError(
                "Use 3–40 letters, numbers, dots, hyphens or underscores for your username."
            )
        email = email_field(values)
        password = password_field(values)
        if password != values.get("password_confirm"):
            raise StoreError("The passwords do not match.")
        hashed = await run_in_threadpool(password_hash, password)
        with database(write=True) as db:
            db.execute(
                "INSERT INTO users(username,email,password) VALUES(?,?,?)",
                (username, email, hashed),
            )
        return redirect("/login?registered=1")

    @app.get("/profile")
    async def profile(request: Request):
        require_user(request)
        return render(request, "profile")

    @app.post("/profile")
    async def profile_update(request: Request):
        user = require_user(request)
        values = await form_values(request)
        fields = (
            email_field(values),
            text_field(values, "phone", 40, False),
            text_field(values, "address", 500, False),
        )
        with database(write=True) as db:
            db.execute(
                "UPDATE users SET email=?,phone=?,address=? WHERE id=?",
                (*fields, user["id"]),
            )
        return redirect("/profile?saved=1")

    @app.post("/profile/password")
    async def change_password(request: Request):
        user = require_user(request)
        values = await form_values(request)
        password = password_field(values, "new_password")
        with database() as db:
            stored = existing(db, "users", user["id"])["password"]
        if not await run_in_threadpool(
            password_matches, values.get("current_password", "")[:129], stored
        ):
            raise StoreError("The current password is incorrect.")
        hashed = await run_in_threadpool(password_hash, password)
        with database(write=True) as db:
            db.execute("UPDATE users SET password=? WHERE id=?", (hashed, user["id"]))
            db.execute(
                "DELETE FROM sessions WHERE user_id=? AND id<>?",
                (user["id"], request.state.sid),
            )
        return redirect("/profile?saved=1")

    @app.get("/cart")
    @app.get("/checkout")
    async def cart_page(request: Request):
        page = request.url.path.lstrip("/")
        if page == "checkout":
            require_user(request)
        with database() as db:
            items = cart_items(db, request.state.sid)
        return render(
            request, page, items=items, total=sum(item["subtotal"] for item in items)
        )

    @app.post("/cart/add")
    @app.post("/cart/update")
    @app.post("/cart/remove")
    async def cart_update(request: Request):
        values = await form_values(request)
        pid = integer_field(values, "product_id", 1)
        quantity = (
            0
            if request.url.path.endswith("remove")
            else integer_field(values, "quantity", 0, 99)
        )
        with database(write=True) as db:
            product = existing(db, "products", pid)
            if request.url.path.endswith("add"):
                previous = db.execute(
                    "SELECT quantity FROM cart WHERE session_id=? AND product_id=?",
                    (request.state.sid, pid),
                ).fetchone()
                quantity += previous["quantity"] if previous else 0
            if quantity > min(product["stock"], 99):
                raise StoreError("The requested quantity is not available.")
            if quantity:
                db.execute(
                    "INSERT INTO cart VALUES(?,?,?) ON CONFLICT(session_id,product_id) DO UPDATE SET quantity=excluded.quantity",
                    (request.state.sid, pid, quantity),
                )
            else:
                db.execute(
                    "DELETE FROM cart WHERE session_id=? AND product_id=?",
                    (request.state.sid, pid),
                )
        return redirect("/cart")

    @app.post("/checkout")
    async def checkout(request: Request):
        user = require_user(request)
        values = await form_values(request)
        address = text_field(values, "address", 500)
        with database(write=True) as db:
            items = cart_items(db, request.state.sid)
            if not items:
                raise StoreError("Your cart is empty.")
            if any(item["quantity"] > item["stock"] for item in items):
                raise StoreError(
                    "Some items are no longer available in the requested quantity."
                )
            total = sum(item["subtotal"] for item in items)
            order_id = db.execute(
                "INSERT INTO orders(user_id,total,address) VALUES(?,?,?)",
                (user["id"], total, address),
            ).lastrowid
            for item in items:
                db.execute(
                    "INSERT INTO order_lines(order_id,product_id,name,unit_price,quantity) VALUES(?,?,?,?,?)",
                    (
                        order_id,
                        item["product_id"],
                        item["name"],
                        item["price"],
                        item["quantity"],
                    ),
                )
                db.execute(
                    "UPDATE products SET stock=stock-? WHERE id=?",
                    (item["quantity"], item["product_id"]),
                )
            db.execute("DELETE FROM cart WHERE session_id=?", (request.state.sid,))
        return redirect("/orders?placed=1")

    @app.get("/orders")
    async def orders(request: Request):
        user = require_user(request)
        with database() as db:
            records = order_records(db, user["id"])
        return render(request, "orders", orders=records)

    @app.post("/orders/{order_id}/cancel")
    async def order_cancel(request: Request, order_id: int):
        user = require_user(request)
        await form_values(request)
        with database(write=True) as db:
            order = existing(db, "orders", order_id)
            if order["user_id"] != user["id"]:
                raise StoreError("Order not found.", 404)
            try:
                cancel_order(db, order_id)
            except ValueError as exc:
                raise StoreError(str(exc)) from exc
        return redirect("/orders")

    @app.get("/wishlist")
    async def wishlist(request: Request):
        user = require_user(request)
        with database() as db:
            catalog = [
                product_record(row)
                for row in db.execute(
                    "SELECT p.* FROM products p JOIN wishlist w ON w.product_id=p.id WHERE w.user_id=? ORDER BY p.name",
                    (user["id"],),
                )
            ]
        return render(request, "wishlist", catalog=catalog)

    @app.post("/wishlist/add")
    @app.post("/wishlist/remove")
    async def wishlist_update(request: Request):
        user = require_user(request)
        values = await form_values(request)
        pid = integer_field(values, "product_id", 1)
        with database(write=True) as db:
            existing(db, "products", pid)
            if request.url.path.endswith("add"):
                db.execute(
                    "INSERT OR IGNORE INTO wishlist VALUES(?,?)", (user["id"], pid)
                )
            else:
                db.execute(
                    "DELETE FROM wishlist WHERE user_id=? AND product_id=?",
                    (user["id"], pid),
                )
        return redirect("/wishlist")

    @app.get("/support")
    @app.get("/support/tickets")
    async def support(request: Request):
        user = request.state.user
        with database() as db:
            tickets = (
                [
                    dict(row)
                    for row in db.execute(
                        "SELECT * FROM tickets WHERE user_id=? ORDER BY id DESC",
                        (user["id"],),
                    )
                ]
                if user
                else []
            )
        return render(request, "support", tickets=tickets)

    @app.post("/support")
    async def create_ticket(request: Request):
        user = require_user(request)
        values = await form_values(request)
        subject, body = text_field(values, "subject"), text_field(values, "body", 4000)
        with database(write=True) as db:
            db.execute(
                "INSERT INTO tickets(user_id,subject,body) VALUES(?,?,?)",
                (user["id"], subject, body),
            )
        return redirect("/support?created=1")

    @app.get("/newsletter")
    async def newsletter(request: Request, email: str = "", subscribed: bool = False):
        return render(request, "newsletter", email=email, subscribed=subscribed)

    @app.post("/newsletter")
    async def subscribe(request: Request):
        values = await form_values(request)
        email = email_field(values)
        with database(write=True) as db:
            db.execute("INSERT OR IGNORE INTO subscribers VALUES(?)", (email,))
        return redirect("/newsletter?subscribed=true")

    @app.get("/blog")
    async def blog(request: Request):
        with database() as db:
            posts = [
                dict(row) for row in db.execute("SELECT * FROM posts ORDER BY id DESC")
            ]
        return render(request, "blog", posts=posts)

    @app.get("/blog/{slug}")
    async def blog_post(request: Request, slug: str):
        with database() as db:
            post = db.execute("SELECT * FROM posts WHERE slug=?", (slug,)).fetchone()
            if post is None:
                raise StoreError("Article not found.", 404)
            comments = [
                dict(row)
                for row in db.execute(
                    "SELECT c.id,c.body,COALESCE(u.username,'Former member') AS username FROM comments c LEFT JOIN users u ON u.id=c.user_id WHERE c.post_id=? ORDER BY c.id DESC",
                    (post["id"],),
                )
            ]
        return render(request, "post", post=dict(post), comments=comments)

    @app.post("/blog/{slug}/comments")
    @app.post("/product/{pid}/reviews")
    async def comment_create(request: Request, slug: str = "", pid: int = 0):
        user = require_user(request)
        values = await form_values(request)
        body = text_field(values, "body", 2000)
        with database(write=True) as db:
            if pid:
                existing(db, "products", pid)
                db.execute(
                    "INSERT INTO comments(user_id,product_id,body) VALUES(?,?,?)",
                    (user["id"], pid, body),
                )
            else:
                post = db.execute(
                    "SELECT id FROM posts WHERE slug=?", (slug,)
                ).fetchone()
                if post is None:
                    raise StoreError("Article not found.", 404)
                db.execute(
                    "INSERT INTO comments(user_id,post_id,body) VALUES(?,?,?)",
                    (user["id"], post["id"], body),
                )
        return redirect(f"/product/{pid}" if pid else f"/blog/{slug}")

    @app.get("/admin")
    async def admin(request: Request):
        require_user(request, admin=True)
        with database() as db:
            counts = {
                table: db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in ("users", "products", "orders", "tickets")
            }
        return render(request, "admin", counts=counts)

    @app.get("/admin/{section}")
    async def admin_section(request: Request, section: str):
        require_user(request, admin=True)
        if section not in {"users", "products", "orders", "tickets", "posts"}:
            raise StoreError("Page not found.", 404)
        with database() as db:
            if section == "orders":
                context = {"orders": order_records(db)}
            elif section == "products":
                context = {
                    "catalog": [
                        product_record(row)
                        for row in db.execute("SELECT * FROM products ORDER BY id")
                    ]
                }
            elif section == "users":
                context = {
                    "users": [
                        dict(row)
                        for row in db.execute(
                            f"SELECT {PUBLIC_USER_FIELDS} FROM users ORDER BY id"
                        )
                    ]
                }
            else:
                context = {
                    section: [
                        dict(row)
                        for row in db.execute(
                            f"SELECT * FROM {section} ORDER BY id DESC"
                        )
                    ]
                }
        return render(request, f"admin_{section}", **context)

    @app.post("/admin/users/create")
    async def admin_create_user(request: Request):
        require_user(request, admin=True)
        values = await form_values(request)
        username = text_field(values, "username", 40)
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,40}", username):
            raise StoreError(
                "Use 3–40 letters, numbers, dots, hyphens or underscores for your username."
            )
        email, role = email_field(values), values.get("role", "user")
        if role not in {"user", "admin"}:
            raise StoreError("Choose a valid role.")
        hashed = await run_in_threadpool(password_hash, password_field(values))
        with database(write=True) as db:
            db.execute(
                "INSERT INTO users(username,email,password,role) VALUES(?,?,?,?)",
                (username, email, hashed, role),
            )
        return redirect("/admin/users")

    @app.post("/admin/users/{uid}/update")
    @app.post("/admin/users/{uid}/delete")
    async def admin_update_user(request: Request, uid: int):
        actor = require_user(request, admin=True)
        values = await form_values(request)
        deleting = request.url.path.endswith("delete")
        role = values.get("role", "user")
        if not deleting and role not in {"user", "admin"}:
            raise StoreError("Choose a valid role.")
        fields = (
            None
            if deleting
            else (
                email_field(values),
                text_field(values, "phone", 40, False),
                text_field(values, "address", 500, False),
                role,
            )
        )
        hashed = (
            await run_in_threadpool(password_hash, password_field(values))
            if values.get("password") and not deleting
            else None
        )
        with database(write=True) as db:
            target = existing(db, "users", uid)
            if deleting and uid == actor["id"]:
                raise StoreError("You cannot delete your own account.")
            if (
                target["role"] == "admin"
                and (deleting or role != "admin")
                and db.execute(
                    "SELECT COUNT(*) FROM users WHERE role='admin'"
                ).fetchone()[0]
                <= 1
            ):
                raise StoreError("Keep at least one administrator account.")
            if deleting:
                db.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
                db.execute("DELETE FROM users WHERE id=?", (uid,))
            else:
                db.execute(
                    "UPDATE users SET email=?,phone=?,address=?,role=? WHERE id=?",
                    (*fields, uid),
                )
                if hashed:
                    db.execute("UPDATE users SET password=? WHERE id=?", (hashed, uid))
                    db.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
        return redirect("/admin/users")

    @app.post("/admin/products/create")
    async def admin_create_product(request: Request):
        require_user(request, admin=True)
        values = await form_values(request)
        fields = product_fields(values)
        with database(write=True) as db:
            db.execute(
                "INSERT INTO products(name,category,price_cents,description,stock) VALUES(?,?,?,?,?)",
                fields,
            )
        return redirect("/admin/products")

    @app.post("/admin/products/{pid}/update")
    @app.post("/admin/products/{pid}/delete")
    async def admin_update_product(request: Request, pid: int):
        require_user(request, admin=True)
        values = await form_values(request)
        deleting = request.url.path.endswith("delete")
        fields = None if deleting else product_fields(values)
        with database(write=True) as db:
            existing(db, "products", pid)
            if deleting:
                db.execute("DELETE FROM products WHERE id=?", (pid,))
            else:
                db.execute(
                    "UPDATE products SET name=?,category=?,price_cents=?,description=?,stock=? WHERE id=?",
                    (*fields, pid),
                )
        return redirect("/admin/products")

    @app.post("/admin/orders/{order_id}/status")
    async def admin_order_status(request: Request, order_id: int):
        require_user(request, admin=True)
        values = await form_values(request)
        status = values.get("status", "")
        allowed = {
            "pending": {"processing", "cancelled"},
            "processing": {"shipped"},
            "shipped": {"completed"},
            "completed": set(),
            "cancelled": set(),
        }
        with database(write=True) as db:
            order = existing(db, "orders", order_id)
            if status != order["status"] and status not in allowed.get(
                order["status"], set()
            ):
                raise StoreError("This order status transition is not available.")
            if status == "cancelled":
                cancel_order(db, order_id)
            else:
                db.execute("UPDATE orders SET status=? WHERE id=?", (status, order_id))
        return redirect("/admin/orders")

    @app.post("/admin/tickets/{ticket_id}/update")
    async def admin_ticket_update(request: Request, ticket_id: int):
        require_user(request, admin=True)
        values = await form_values(request)
        status, reply = (
            values.get("status", ""),
            text_field(values, "reply", 4000, False),
        )
        if status not in {"open", "closed"}:
            raise StoreError("Choose a valid ticket status.")
        with database(write=True) as db:
            existing(db, "tickets", ticket_id)
            db.execute(
                "UPDATE tickets SET status=?,reply=? WHERE id=?",
                (status, reply, ticket_id),
            )
        return redirect("/admin/tickets")

    @app.post("/admin/posts/create")
    async def admin_post_create(request: Request):
        require_user(request, admin=True)
        values = await form_values(request)
        slug = text_field(values, "slug", 100)
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", slug):
            raise StoreError(
                "Use lowercase letters, numbers and hyphens for the page address."
            )
        title, body = text_field(values, "title"), text_field(values, "body", 10000)
        with database(write=True) as db:
            db.execute(
                "INSERT INTO posts(slug,title,body) VALUES(?,?,?)", (slug, title, body)
            )
        return redirect("/admin/posts")

    @app.post("/admin/posts/{post_id}/update")
    @app.post("/admin/posts/{post_id}/delete")
    async def admin_post_update(request: Request, post_id: int):
        require_user(request, admin=True)
        values = await form_values(request)
        deleting = request.url.path.endswith("delete")
        fields = (
            None
            if deleting
            else (text_field(values, "title"), text_field(values, "body", 10000))
        )
        with database(write=True) as db:
            existing(db, "posts", post_id)
            if deleting:
                db.execute("DELETE FROM posts WHERE id=?", (post_id,))
            else:
                db.execute(
                    "UPDATE posts SET title=?,body=? WHERE id=?", (*fields, post_id)
                )
        return redirect("/admin/posts")

    @app.get("/api-docs")
    async def api_docs(request: Request):
        return render(request, "api_docs")

    @app.get("/store-api/products")
    async def product_api():
        return {"products": catalog_records()}

    @app.get("/store-api/me")
    async def account_api(request: Request):
        return require_user(request)

    @app.get("/store-api/orders")
    async def order_api(request: Request):
        user = require_user(request)
        with database() as db:
            return {"orders": order_records(db, user["id"])}

    @app.get("/about")
    @app.get("/download")
    @app.get("/redirect")
    async def about(request: Request):
        return render(request, "about")
