"""Isolated HTTP tests for the persistent storefront and customer workflows."""

import os
import re
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient


SERVICE_DIR = Path(__file__).resolve().parents[1] / "services" / "shopforge"
sys.path.insert(0, str(SERVICE_DIR))

import main as shopforge  # noqa: E402
import store  # noqa: E402


ADMIN_PASSWORD = "Administrator-test-2026"
CUSTOMER_PASSWORD = "Customer-test-2026"
NEW_PASSWORD = "Updated-customer-2026"


class StorefrontWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.resources = ExitStack()
        self.addCleanup(self.resources.close)
        directory = self.resources.enter_context(tempfile.TemporaryDirectory())
        self.resources.enter_context(
            patch.object(store, "DB_PATH", Path(directory) / "store.sqlite3")
        )
        self.resources.enter_context(
            patch.dict(
                os.environ,
                {
                    "SHOPFORGE_ADMIN_PASSWORD": ADMIN_PASSWORD,
                    "SHOPFORGE_USER_PASSWORD": CUSTOMER_PASSWORD,
                },
            )
        )
        self.client = self.new_client()

    def new_client(self):
        return self.resources.enter_context(
            TestClient(shopforge.app, follow_redirects=False)
        )

    def csrf(self, client=None):
        client = client or self.client
        response = client.get("/")
        self.assertEqual(response.status_code, 200)
        match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
        self.assertIsNotNone(match, "Storefront forms must include a CSRF token")
        return match.group(1)

    def submit(self, path, values=None, expected=303, client=None):
        client = client or self.client
        response = client.post(
            path, data={"csrf_token": self.csrf(client), **(values or {})}
        )
        self.assertEqual(response.status_code, expected, response.text[:600])
        return response

    def login(self, username="alice", password=CUSTOMER_PASSWORD, client=None):
        return self.submit(
            "/login", {"username": username, "password": password}, client=client
        )

    def products(self, client=None):
        return (client or self.client).get("/store-api/products").json()["products"]

    def product(self, product_id, client=None):
        return next(
            product for product in self.products(client) if product["id"] == product_id
        )

    def admin(self):
        self.login("admin", ADMIN_PASSWORD)

    def place_order(self, product_id=5, quantity=2, client=None):
        self.submit(
            "/cart/add", {"product_id": product_id, "quantity": quantity}, client=client
        )
        self.submit(
            "/checkout", {"address": "42 Harbor Avenue, Cedar City"}, client=client
        )
        orders = (client or self.client).get("/store-api/orders").json()["orders"]
        return orders[0]

    def test_registration_profile_password_and_logout(self):
        account = {
            "username": "charlie",
            "email": "charlie@example.test",
            "password": CUSTOMER_PASSWORD,
            "password_confirm": CUSTOMER_PASSWORD,
        }
        self.submit("/register", account)
        self.submit("/register", account, expected=409)
        self.login("charlie")
        self.submit(
            "/profile",
            {
                "email": "charlie.updated@example.test",
                "phone": "+1-555-0142",
                "address": "8 Juniper Road",
                "role": "admin",
            },
        )
        profile = self.client.get("/store-api/me").json()
        self.assertEqual(profile["email"], "charlie.updated@example.test")
        self.assertEqual(profile["phone"], "+1-555-0142")
        self.assertEqual(profile["address"], "8 Juniper Road")
        self.assertEqual(profile["role"], "user")
        self.assertNotIn("password", profile)
        self.submit(
            "/profile/password",
            {"current_password": "incorrect", "new_password": NEW_PASSWORD},
            expected=400,
        )
        self.submit(
            "/profile/password",
            {"current_password": CUSTOMER_PASSWORD, "new_password": NEW_PASSWORD},
        )
        self.submit("/logout")
        self.assertEqual(self.client.get("/store-api/me").status_code, 401)
        self.submit(
            "/login",
            {"username": "charlie", "password": CUSTOMER_PASSWORD},
            expected=400,
        )
        self.login("charlie", NEW_PASSWORD)
        self.assertEqual(self.client.get("/store-api/me").json()["username"], "charlie")

    def test_authentication_csrf_and_admin_permissions(self):
        guest = self.client.get("/admin")
        self.assertEqual(guest.status_code, 303)
        self.assertEqual(guest.headers["location"], "/login")
        self.assertEqual(self.client.get("/store-api/orders").status_code, 401)
        self.assertEqual(
            self.client.post("/register", data={"username": "ignored"}).status_code, 403
        )
        self.login()
        self.assertEqual(self.client.get("/admin").status_code, 403)
        self.submit("/admin/products/create", {}, expected=403)
        self.assertEqual(
            self.client.post(
                "/cart/add",
                data={"csrf_token": "expired", "product_id": 5, "quantity": 1},
            ).status_code,
            403,
        )

    def test_malformed_tokens_and_out_of_range_record_ids_are_rejected(self):
        self.submit(
            "/newsletter",
            {
                "csrf_token": "é",
                "email": "reader@example.test",
            },
            expected=403,
        )
        oversized_id = 2**63
        self.assertEqual(self.client.get(f"/product/{oversized_id}").status_code, 404)
        self.admin()
        self.submit(f"/admin/users/{oversized_id}/delete", expected=404)
        self.submit(f"/admin/products/{oversized_id}/delete", expected=404)

    def test_administrator_can_create_edit_and_delete_customer(self):
        self.admin()
        self.submit(
            "/admin/users/create",
            {
                "username": "newcustomer",
                "email": "newcustomer@example.test",
                "password": CUSTOMER_PASSWORD,
                "role": "user",
            },
        )
        customer = self.new_client()
        self.login("newcustomer", client=customer)
        user_id = customer.get("/store-api/me").json()["id"]
        self.submit(
            f"/admin/users/{user_id}/update",
            {
                "email": "changed@example.test",
                "phone": "+1-555-0111",
                "address": "14 Pine Lane",
                "role": "admin",
                "password": "",
            },
        )
        profile = customer.get("/store-api/me").json()
        self.assertEqual(profile["email"], "changed@example.test")
        self.assertEqual(profile["role"], "admin")
        self.assertEqual(customer.get("/admin").status_code, 200)
        self.submit(f"/admin/users/{user_id}/delete")
        self.assertEqual(customer.get("/store-api/me").status_code, 401)
        self.submit(
            "/login",
            {"username": "newcustomer", "password": CUSTOMER_PASSWORD},
            expected=400,
            client=customer,
        )
        administrator_id = self.client.get("/store-api/me").json()["id"]
        self.submit(f"/admin/users/{administrator_id}/delete", expected=400)
        self.submit(
            f"/admin/users/{administrator_id}/update",
            {
                "email": "admin@shopforge.example",
                "phone": "",
                "address": "",
                "role": "user",
            },
            expected=400,
        )

    def test_product_crud_filters_and_persistence_after_restart(self):
        self.admin()
        fields = {
            "name": "Harbor Test Speaker",
            "category": "Accessories",
            "price": "12.34",
            "description": "Compact desk speaker.",
            "stock": 3,
        }
        self.submit("/admin/products/create", fields)
        created = next(
            product for product in self.products() if product["name"] == fields["name"]
        )
        self.assertEqual(created["price"], "12.34")
        detail = self.client.get(f"/product/{created['id']}")
        self.assertIn("Compact desk speaker.", detail.text)
        self.submit(
            f"/admin/products/{created['id']}/update",
            {**fields, "name": "Updated Harbor Speaker", "price": "15.75", "stock": 8},
        )
        self.assertEqual(self.product(created["id"])["price"], "15.75")
        search = self.client.get("/search?q=Updated+Harbor")
        self.assertIn("Updated Harbor Speaker", search.text)
        self.assertNotIn("CedarJet M220 Printer", search.text)
        category = self.client.get("/products?category=software")
        self.assertIn("SecureVPN Annual License", category.text)
        self.assertNotIn("CedarJet M220 Printer", category.text)
        self.submit(
            f"/admin/products/{created['id']}/update",
            {**fields, "price": "NaN"},
            expected=400,
        )
        self.submit("/admin/products/5/delete")
        restarted = self.new_client()
        self.assertEqual(restarted.get("/product/5").status_code, 404)
        self.assertEqual(self.product(created["id"], restarted)["stock"], 8)
        self.assertNotIn(5, [product["id"] for product in self.products(restarted)])
        self.submit(f"/admin/products/{created['id']}/delete")
        self.assertEqual(self.client.get(f"/product/{created['id']}").status_code, 404)

    def test_cart_checkout_stock_ownership_and_repeat_cancellation(self):
        self.login()
        initial_stock = self.product(5)["stock"]
        self.submit("/cart/add", {"product_id": 5, "quantity": 99}, expected=400)
        self.submit("/cart/add", {"product_id": 5, "quantity": 1})
        self.submit("/cart/update", {"product_id": 5, "quantity": 2})
        self.assertIn("$238.00", self.client.get("/cart").text)
        self.submit("/checkout", {"address": "42 Harbor Avenue"})
        order = self.client.get("/store-api/orders").json()["orders"][0]
        self.assertEqual(order["total"], 23800)
        self.assertEqual(order["lines"][0]["quantity"], 2)
        self.assertEqual(self.product(5)["stock"], initial_stock - 2)
        self.assertIn("Your cart is empty", self.client.get("/cart").text)
        self.submit("/checkout", {"address": "42 Harbor Avenue"}, expected=400)
        other_customer = self.new_client()
        self.login("bob", client=other_customer)
        self.assertNotIn(
            order["id"],
            [
                item["id"]
                for item in other_customer.get("/store-api/orders").json()["orders"]
            ],
        )
        self.submit(
            f"/orders/{order['id']}/cancel", expected=404, client=other_customer
        )
        self.submit(f"/orders/{order['id']}/cancel")
        self.submit(f"/orders/{order['id']}/cancel")
        self.assertEqual(self.product(5)["stock"], initial_stock)
        self.assertEqual(
            self.client.get("/store-api/orders").json()["orders"][0]["status"],
            "cancelled",
        )

    def test_order_status_progression_preserves_order_snapshot(self):
        customer = self.new_client()
        self.login(client=customer)
        order = self.place_order(client=customer)
        self.admin()
        self.submit(
            f"/admin/orders/{order['id']}/status", {"status": "completed"}, expected=400
        )
        for status in ("processing", "shipped", "completed"):
            self.submit(f"/admin/orders/{order['id']}/status", {"status": status})
        self.submit(f"/orders/{order['id']}/cancel", expected=400, client=customer)
        self.submit("/admin/products/5/delete")
        retained = customer.get("/store-api/orders").json()["orders"][0]
        self.assertEqual(retained["status"], "completed")
        self.assertEqual(retained["lines"][0]["name"], "CedarJet M220 Printer")
        self.assertEqual(retained["total"], 23800)

    def test_support_request_and_administrator_reply(self):
        self.login()
        self.submit(
            "/support",
            {
                "subject": "Change delivery instructions",
                "body": "Please deliver after noon.",
            },
        )
        page = self.client.get("/support").text
        self.assertIn("Please deliver after noon.", page)
        ticket_id = int(
            re.search(
                r'action="/admin/tickets/(\d+)/update"', self.admin_ticket_page()
            ).group(1)
        )
        self.submit(
            f"/admin/tickets/{ticket_id}/update",
            {"status": "closed", "reply": "Your instructions have been updated."},
        )
        self.submit("/logout")
        self.login()
        self.assertIn(
            "Your instructions have been updated.", self.client.get("/support").text
        )
        other = self.new_client()
        self.login("bob", client=other)
        self.assertNotIn("Please deliver after noon.", other.get("/support").text)

    def admin_ticket_page(self):
        self.submit("/logout")
        self.admin()
        return self.client.get("/admin/tickets").text

    def test_wishlist_reviews_journal_and_newsletter(self):
        self.login()
        self.submit("/wishlist/add", {"product_id": 5})
        self.assertIn("CedarJet M220 Printer", self.client.get("/wishlist").text)
        self.submit("/wishlist/remove", {"product_id": 5})
        self.assertNotIn("CedarJet M220 Printer", self.client.get("/wishlist").text)
        review = "Useful printer <script>alert('review')</script>"
        self.submit("/product/5/reviews", {"body": review})
        detail = self.client.get("/product/5").text
        self.assertIn("Useful printer", detail)
        self.assertNotIn("<script>alert('review')</script>", detail)
        self.submit(
            "/blog/how-we-built-our-api/comments",
            {"body": "A useful update for our office."},
        )
        self.assertIn(
            "A useful update for our office.",
            self.client.get("/blog/how-we-built-our-api").text,
        )
        self.submit("/newsletter", {"email": "reader@example.test"})
        self.submit("/newsletter", {"email": "reader@example.test"})
        self.assertIn(
            "You're subscribed", self.client.get("/newsletter?subscribed=true").text
        )
        self.submit("/newsletter", {"email": "invalid"}, expected=400)
        self.submit("/logout")
        self.admin()
        self.submit(
            "/admin/posts/create",
            {
                "slug": "harbor-office",
                "title": "Harbor Office",
                "body": "Our latest office collection.",
            },
        )
        self.assertIn(
            "Our latest office collection.", self.client.get("/blog/harbor-office").text
        )
        posts = self.client.get("/admin/posts").text
        post_id = int(re.search(r'action="/admin/posts/(\d+)/update"', posts).group(1))
        self.submit(
            f"/admin/posts/{post_id}/update",
            {"title": "Harbor Office Update", "body": "New office arrivals."},
        )
        self.assertIn(
            "New office arrivals.", self.client.get("/blog/harbor-office").text
        )
        self.submit(f"/admin/posts/{post_id}/delete")
        self.assertEqual(self.client.get("/blog/harbor-office").status_code, 404)

    def test_storefront_and_admin_pages_do_not_reveal_lab_hints(self):
        prohibited = (
            "admin123",
            "alice123",
            "vulnerability",
            "scanner",
            "sqli-",
            "ssrf",
            "bola",
            "evil.example",
            "/scan-fixtures",
            "/php/",
            "/py/",
            "/go/",
            "/java/",
            "impersonate",
            "payload",
        )
        public_pages = (
            "/",
            "/products",
            "/search?q=printer",
            "/product/5",
            "/login",
            "/register",
            "/cart",
            "/support",
            "/newsletter",
            "/blog",
            "/blog/how-we-built-our-api",
            "/about",
            "/api-docs",
            "/robots.txt",
            "/sitemap.xml",
        )
        for path in public_pages:
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)
                for hint in prohibited:
                    self.assertNotIn(hint, response.text.lower())
        self.admin()
        for path in (
            "/profile",
            "/orders",
            "/wishlist",
            "/checkout",
            "/admin",
            "/admin/users",
            "/admin/products",
            "/admin/orders",
            "/admin/tickets",
            "/admin/posts",
        ):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)
                for hint in prohibited:
                    self.assertNotIn(hint, response.text.lower())


if __name__ == "__main__":
    unittest.main()
