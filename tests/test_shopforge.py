import json
import os
import unittest
from urllib.error import HTTPError
from urllib.request import urlopen


BASE_URL = os.environ.get("BASE_URL", "http://127.0.0.1:8000").rstrip("/")


class ShopForgeTest(unittest.TestCase):
    def page(self, path):
        with urlopen(f"{BASE_URL}{path}", timeout=5) as response:
            return response.read().decode("utf-8")

    def test_gateway_serves_shopforge(self):
        self.assertIn("ShopForge", self.page("/"))
        self.assertIn("VulnForge Lab Gateway", self.page("/__status"))

    def test_catalog_and_detail_share_the_synthetic_product(self):
        catalog = self.page("/products")
        detail = self.page("/product/5")
        self.assertIn("16 items", catalog)
        for text in ("CedarJet M220 Printer", "Electronics", "$119.00",
                     "Compact duplex printer with a 150-sheet tray."):
            with self.subTest(text=text):
                self.assertIn(text, catalog)
                self.assertIn(text, detail)

    def test_product_outside_demo_catalog_keeps_its_detail_page(self):
        self.assertIn("Product 0099", self.page("/product/99"))

    def fixture_response(self, case, sample, expected_status=200):
        try:
            response = urlopen(f"{BASE_URL}/scan-fixtures/{case}/{sample}", timeout=5)
        except HTTPError as error:
            response = error
        with response:
            self.assertEqual(response.code, expected_status)
            return response.headers, response.read().decode("utf-8")

    def test_portal_links_to_all_six_fixture_responses(self):
        self.assertIn('href="/scan-fixtures"', self.page("/"))
        index = self.page("/scan-fixtures")
        for case in ("version-header", "error-detail", "internal-hostname"):
            for sample in ("sample-a", "sample-b"):
                self.assertIn(f'href="/scan-fixtures/{case}/{sample}"', index)

    def test_version_header_only_appears_in_sample_a(self):
        headers_a, body_a = self.fixture_response("version-header", "sample-a")
        headers_b, body_b = self.fixture_response("version-header", "sample-b")
        self.assertEqual(body_a, body_b)
        self.assertEqual(headers_a["X-Powered-By"], "ShopForge-Demo/0.0.0")
        self.assertNotIn("X-Powered-By", headers_b)

    def test_error_detail_only_appears_in_sample_a(self):
        _, body_a = self.fixture_response("error-detail", "sample-a", expected_status=500)
        _, body_b = self.fixture_response("error-detail", "sample-b", expected_status=500)
        signal, control = json.loads(body_a), json.loads(body_b)
        self.assertIn("Traceback", signal.pop("diagnostic"))
        self.assertEqual(signal, control)

    def test_internal_hostname_only_appears_in_sample_a(self):
        _, body_a = self.fixture_response("internal-hostname", "sample-a")
        _, body_b = self.fixture_response("internal-hostname", "sample-b")
        signal, control = json.loads(body_a), json.loads(body_b)
        self.assertEqual(signal.pop("backend"), "inventory.internal.shopforge.invalid")
        self.assertEqual(signal, control)

    def test_unknown_fixture_case_and_variant_return_404(self):
        self.fixture_response("unknown", "sample-a", expected_status=404)
        self.fixture_response("version-header", "unknown", expected_status=404)


if __name__ == "__main__":
    unittest.main()
