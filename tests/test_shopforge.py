import os
import unittest
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


if __name__ == "__main__":
    unittest.main()
