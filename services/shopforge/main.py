"""ShopForge storefront and independent passive-response fixtures."""

from contextlib import asynccontextmanager
from pathlib import Path
from xml.sax.saxutils import escape

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from fastapi.templating import Jinja2Templates

from business import install
from store import database, initialize

APP_DIR = Path(__file__).parent


@asynccontextmanager
async def lifespan(app):
    initialize()
    yield


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
templates = Jinja2Templates(directory=APP_DIR / "src" / "templates")

PASSIVE_FIXTURES = {
    "version-header": "Technology version header",
    "error-detail": "Error response detail",
    "internal-hostname": "Internal hostname disclosure",
}


@app.get("/scan-fixtures/{case}/{variant}")
async def scan_fixture(case: str, variant: str):
    if case not in PASSIVE_FIXTURES or variant not in {"sample-a", "sample-b"}:
        raise HTTPException(status_code=404, detail="Fixture not found")

    headers = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}
    has_signal = variant == "sample-a"

    if case == "version-header":
        if has_signal:
            headers["X-Powered-By"] = "ShopForge-Demo/0.0.0"
        return PlainTextResponse("Status: available\n", headers=headers)

    if case == "error-detail":
        body = {"message": "The report could not be generated."}
        if has_signal:
            body["diagnostic"] = (
                "Traceback (most recent call last):\n"
                '  File "/synthetic/shopforge/report_fixture.py", line 12, in build_report\n'
                "SyntheticReportError: sample report unavailable"
            )
        return JSONResponse(body, status_code=500, headers=headers)

    body = {"status": "unavailable"}
    if has_signal:
        body["backend"] = "inventory.internal.shopforge.invalid"
    return JSONResponse(body, headers=headers)


@app.get("/health")
def health():
    return {"status": "ok", "service": "shopforge"}


@app.get("/robots.txt")
async def robots():
    return PlainTextResponse(
        "User-agent: *\nDisallow: /admin\nDisallow: /profile\nDisallow: /orders\nSitemap: /sitemap.xml\n"
    )


@app.get("/sitemap.xml")
async def sitemap(request: Request):
    paths = ["/", "/products", "/blog", "/support", "/about", "/login", "/register"]
    with database() as db:
        paths += [
            f"/product/{row['id']}" for row in db.execute("SELECT id FROM products")
        ]
        paths += [
            f"/blog/{row['slug']}" for row in db.execute("SELECT slug FROM posts")
        ]
    base = str(request.base_url).rstrip("/")
    urls = "".join(f"<url><loc>{escape(base + path)}</loc></url>" for path in paths)
    return Response(
        '<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        + urls
        + "</urlset>",
        media_type="application/xml",
    )


install(app, templates)
