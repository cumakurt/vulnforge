"""
ShopForge — a realistic e-commerce web application that intentionally exposes
all VulnForge vulnerability endpoints as natural site features.

A web scanner crawling this site from / will discover every vulnerability
through realistic links, forms, JavaScript and API references.

WARNING: intentionally vulnerable — run in an isolated lab only.
"""

import json
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

APP_DIR = Path(__file__).parent
CATALOG = json.loads((APP_DIR / "catalog.json").read_text(encoding="utf-8"))
PRODUCTS_BY_ID = {str(product["id"]): product for product in CATALOG}

app = FastAPI(docs_url=None, redoc_url=None)
templates = Jinja2Templates(directory=APP_DIR / "src" / "templates")


@app.get("/health")
def health():
    return {"status": "ok", "service": "shopforge"}


# Every page passes request to template so Jinja2 url_for works
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("home.html", {"request": request})


@app.get("/products", response_class=HTMLResponse)
async def products(request: Request, id: str = "1", q: str = ""):
    return templates.TemplateResponse(
        "products.html", {"request": request, "id": id, "q": q, "catalog": CATALOG}
    )


@app.get("/product/{pid}", response_class=HTMLResponse)
async def product_detail(request: Request, pid: str = "1"):
    return templates.TemplateResponse(
        "product_detail.html",
        {"request": request, "pid": pid, "product": PRODUCTS_BY_ID.get(pid)},
    )


@app.get("/search", response_class=HTMLResponse)
async def search(request: Request, q: str = "", name: str = ""):
    return templates.TemplateResponse("search.html", {"request": request, "q": q, "name": name})


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})


@app.get("/profile", response_class=HTMLResponse)
async def profile(request: Request, user: str = "alice"):
    return templates.TemplateResponse("profile.html", {"request": request, "user": user})


@app.get("/orders", response_class=HTMLResponse)
async def orders(request: Request):
    return templates.TemplateResponse("orders.html", {"request": request})


@app.get("/cart", response_class=HTMLResponse)
async def cart(request: Request):
    return templates.TemplateResponse("cart.html", {"request": request})


@app.get("/checkout", response_class=HTMLResponse)
async def checkout(request: Request):
    return templates.TemplateResponse("checkout.html", {"request": request})


@app.get("/support", response_class=HTMLResponse)
async def support(request: Request):
    return templates.TemplateResponse("support.html", {"request": request})


@app.get("/blog", response_class=HTMLResponse)
async def blog(request: Request):
    return templates.TemplateResponse("blog.html", {"request": request})


@app.get("/blog/{slug}", response_class=HTMLResponse)
async def blog_post(request: Request, slug: str = ""):
    return templates.TemplateResponse("blog_post.html", {"request": request, "slug": slug})


@app.get("/admin", response_class=HTMLResponse)
async def admin(request: Request):
    return templates.TemplateResponse("admin.html", {"request": request})


@app.get("/admin/login", response_class=HTMLResponse)
async def admin_login(request: Request):
    return templates.TemplateResponse("admin_login.html", {"request": request})


@app.get("/about", response_class=HTMLResponse)
async def about(request: Request):
    return templates.TemplateResponse("about.html", {"request": request})


@app.get("/download", response_class=HTMLResponse)
async def download_page(request: Request, file: str = "catalogue.pdf"):
    return templates.TemplateResponse("download.html", {"request": request, "file": file})


@app.get("/redirect", response_class=HTMLResponse)
async def redir_page(request: Request):
    return templates.TemplateResponse("redirect.html", {"request": request})


@app.get("/newsletter", response_class=HTMLResponse)
async def newsletter(request: Request, email: str = ""):
    return templates.TemplateResponse("newsletter.html", {"request": request, "email": email})


@app.get("/api-docs", response_class=HTMLResponse)
async def api_docs(request: Request):
    return templates.TemplateResponse("api_docs.html", {"request": request})


@app.get("/robots.txt")
async def robots():
    # CRAWL-001 style — discloses hidden paths to scanners
    content = "\n".join([
        "User-agent: *",
        "Disallow: /admin/",
        "Disallow: /api/internal/",
        "Disallow: /backup/",
        "Disallow: /config/",
        "Disallow: /support/tickets",
        "Disallow: /py/console",
        "Sitemap: /sitemap.xml",
        "",
    ])
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse(content)


@app.get("/sitemap.xml")
async def sitemap():
    content = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>/</loc></url>
  <url><loc>/products</loc></url>
  <url><loc>/search</loc></url>
  <url><loc>/login</loc></url>
  <url><loc>/register</loc></url>
  <url><loc>/profile</loc></url>
  <url><loc>/orders</loc></url>
  <url><loc>/support</loc></url>
  <url><loc>/blog</loc></url>
  <url><loc>/admin</loc></url>
  <url><loc>/api/v1/products</loc></url>
  <url><loc>/graphql</loc></url>
  <url><loc>/spa/</loc></url>
  <url><loc>/legacy/</loc></url>
  <url><loc>/auth/</loc></url>
</urlset>"""
    from fastapi.responses import Response
    return Response(content=content, media_type="application/xml")
