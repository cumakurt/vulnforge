"""
VulnForge Lab — Portal Service
Unified scanner portal accessible at /__portal via the gateway.

Endpoints:
  GET  /health                Health check
  GET  /                      Redirect to /__portal
  GET  /__portal              Main portal UI (HTML)
  GET  /__portal/api/vulns    All vulns from lab-control (proxied + enriched)
  GET  /__portal/api/health   Health of all services
  GET  /__portal/api/events   Recent triggered events (proxied)
  GET  /__portal/api/session  Active session info
  POST /__portal/api/session/start   Start a scan session
  POST /__portal/api/session/stop    Stop scan session
  POST /__portal/api/reset    Reset the lab
  GET  /__portal/api/waf      Get WAF profile
  POST /__portal/api/waf      Set WAF profile
  POST /__portal/api/scan/:id Run a single vuln smoke test
  POST /__portal/api/scan/all Run all smoke tests
"""

import asyncio
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel

LAB_CONTROL_URL = os.environ.get("LAB_CONTROL_URL", "http://lab-control:9100")
GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://gateway:8000")
TESTS_DIR = Path(os.environ.get("TESTS_DIR", "/app/tests"))
TRUTH_DIR = Path(os.environ.get("TRUTH_DIR", "/app/lab/truth"))

app = FastAPI(title="VulnForge Portal", docs_url=None, redoc_url=None)

# ─── Service colour mapping ───────────────────────────────────────────────────

SERVICE_META: dict[str, dict] = {
    "php-web":     {"label": "PHP Web",      "prefix": "/php/",     "color": "#6366f1"},
    "node-api":    {"label": "Node API",     "prefix": "/api/",     "color": "#0ea5e9"},
    "flask-svc":   {"label": "Flask / PY",   "prefix": "/py/",      "color": "#10b981"},
    "spring-svc":  {"label": "Spring / Java","prefix": "/java/",    "color": "#f59e0b"},
    "go-svc":      {"label": "Go",           "prefix": "/go/",      "color": "#ef4444"},
    "graphql-svc": {"label": "GraphQL",      "prefix": "/graphql",  "color": "#8b5cf6"},
    "crawl-lab":   {"label": "Crawl Lab",    "prefix": "/spa/",     "color": "#ec4899"},
    "legacy-svc":  {"label": "Legacy",       "prefix": "/legacy/",  "color": "#64748b"},
    "auth-svc":    {"label": "Auth / OAuth", "prefix": "/auth/",    "color": "#f97316"},
}

OWASP_LABELS: dict[str, str] = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable & Outdated Components",
    "A07": "Authentication Failures",
    "A08": "Software & Data Integrity Failures",
    "A09": "Security Logging Failures",
    "A10": "SSRF",
    "API1": "BOLA",
    "API2": "Broken Authentication",
    "API3": "Excessive Data Exposure",
    "API4": "Lack of Resources",
    "API5": "BFLA",
    "API6": "Unrestricted Access to Business Flows",
    "API7": "SSRF",
    "API8": "Security Misconfiguration",
    "API9": "Improper Inventory Management",
}


# ─── Helpers ─────────────────────────────────────────────────────────────────

async def lab_get(path: str, params: dict | None = None) -> dict | list:
    async with httpx.AsyncClient(timeout=5.0) as client:
        r = await client.get(f"{LAB_CONTROL_URL}{path}", params=params)
        r.raise_for_status()
        return r.json()


async def lab_post(path: str, json: dict | None = None) -> dict:
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.post(f"{LAB_CONTROL_URL}{path}", json=json or {})
        r.raise_for_status()
        return r.json()


async def lab_put(path: str, json: dict) -> dict:
    async with httpx.AsyncClient(timeout=5.0) as client:
        r = await client.put(f"{LAB_CONTROL_URL}{path}", json=json)
        r.raise_for_status()
        return r.json()


# ─── Scan runner (calls run_tests.py inside container) ───────────────────────

def _run_tests(mode: str = "smoke", vuln_id: str | None = None) -> dict:
    """
    Run the Python smoke/controls test suite.
    Returns {"passed": int, "failed": int, "results": [{id, status, message}]}
    """
    cmd = [
        sys.executable,
        str(TESTS_DIR / "run_tests.py"),
        "--mode", mode,
        "--base-url", GATEWAY_URL.replace("gateway:8000", "gateway:8000"),
        "--lab-control", LAB_CONTROL_URL,
        "--output", "json",
    ]
    if vuln_id:
        cmd += ["--filter", vuln_id]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
        # run_tests.py outputs JSON when --output json is passed
        output = result.stdout.strip()
        if output.startswith("{") or output.startswith("["):
            return json.loads(output)
        # fallback: parse plain text output
        return _parse_text_output(result.stdout)
    except subprocess.TimeoutExpired:
        return {"passed": 0, "failed": 0, "error": "timeout", "results": []}
    except Exception as exc:
        return {"passed": 0, "failed": 0, "error": str(exc), "results": []}


def _parse_text_output(text: str) -> dict:
    """Parse the PASS/FAIL lines from run_tests.py plain-text output."""
    results = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("PASS "):
            parts = line.split(":", 1)
            vuln = parts[0].replace("PASS ", "").strip()
            msg = parts[1].strip() if len(parts) > 1 else "ok"
            results.append({"id": vuln, "status": "pass", "message": msg})
        elif line.startswith("FAIL "):
            parts = line.split(":", 1)
            vuln = parts[0].replace("FAIL ", "").strip()
            msg = parts[1].strip() if len(parts) > 1 else "failed"
            results.append({"id": vuln, "status": "fail", "message": msg})

    passed = sum(1 for r in results if r["status"] == "pass")
    failed = sum(1 for r in results if r["status"] == "fail")
    return {"passed": passed, "failed": failed, "total": len(results), "results": results}


# ─── Routes ──────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "service": "portal-svc"}


@app.get("/")
def root():
    return RedirectResponse("/__portal")


@app.get("/__portal/api/vulns")
async def api_vulns():
    try:
        vulns = await lab_get("/__lab/vulns")
    except Exception as exc:
        raise HTTPException(502, f"lab-control unavailable: {exc}")

    # Enrich with service metadata
    for v in vulns:
        svc = v.get("service", "")
        meta = SERVICE_META.get(svc, {})
        v["service_label"] = meta.get("label", svc)
        v["service_color"] = meta.get("color", "#94a3b8")
        v["gateway_url"] = meta.get("prefix", "") + v.get("url", "").lstrip("/")
        owasp = v.get("owasp_web_2021") or v.get("owasp_api_2023") or ""
        v["owasp_label"] = OWASP_LABELS.get(str(owasp), owasp)

    return vulns


@app.get("/__portal/api/health")
async def api_health():
    try:
        return await lab_get("/__lab/health")
    except Exception as exc:
        raise HTTPException(502, str(exc))


@app.get("/__portal/api/events")
async def api_events(limit: int = 50, vuln_id: str | None = None):
    params: dict = {"limit": limit}
    if vuln_id:
        params["vuln_id"] = vuln_id
    try:
        return await lab_get("/__lab/events", params)
    except Exception as exc:
        raise HTTPException(502, str(exc))


@app.get("/__portal/api/session")
async def api_session():
    try:
        return await lab_get("/__lab/mode")
    except Exception as exc:
        raise HTTPException(502, str(exc))


class SessionStartBody(BaseModel):
    scanner_name: str = "manual"
    notes: str = ""


@app.post("/__portal/api/session/start")
async def session_start(body: SessionStartBody):
    try:
        return await lab_post("/__lab/session/start", body.model_dump())
    except Exception as exc:
        raise HTTPException(502, str(exc))


@app.post("/__portal/api/session/stop")
async def session_stop():
    try:
        return await lab_post("/__lab/session/stop")
    except Exception as exc:
        raise HTTPException(502, str(exc))


@app.post("/__portal/api/reset")
async def api_reset():
    try:
        return await lab_post("/__lab/reset")
    except Exception as exc:
        raise HTTPException(502, str(exc))


@app.get("/__portal/api/waf")
async def api_waf_get():
    try:
        return await lab_get("/__lab/waf")
    except Exception as exc:
        raise HTTPException(502, str(exc))


class WafBody(BaseModel):
    profile: str


@app.post("/__portal/api/waf")
async def api_waf_set(body: WafBody):
    try:
        return await lab_put("/__lab/waf", {"profile": body.profile})
    except Exception as exc:
        raise HTTPException(502, str(exc))


@app.post("/__portal/api/scan/all")
async def scan_all():
    """Run the full smoke suite and return structured results."""
    result = _run_tests(mode="smoke")
    return result


@app.post("/__portal/api/scan/{vuln_id}")
async def scan_one(vuln_id: str):
    """Run the smoke test for a single vulnerability ID."""
    result = _run_tests(mode="smoke", vuln_id=vuln_id.upper())
    return result


# ─── Portal HTML UI ──────────────────────────────────────────────────────────

PORTAL_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VulnForge — Scanner Portal</title>
<style>
  :root {
    --bg: #0f1117;
    --surface: #1a1d2e;
    --surface2: #252840;
    --border: #2e3155;
    --text: #e2e8f0;
    --muted: #94a3b8;
    --accent: #6366f1;
    --green: #10b981;
    --red: #ef4444;
    --yellow: #f59e0b;
    --radius: 8px;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; }

  /* ── Layout ── */
  .layout { display: grid; grid-template-columns: 260px 1fr; min-height: 100vh; }
  .sidebar { background: var(--surface); border-right: 1px solid var(--border); padding: 20px 16px; display: flex; flex-direction: column; gap: 8px; position: sticky; top: 0; height: 100vh; overflow-y: auto; }
  .main { padding: 24px 28px; overflow-y: auto; }

  /* ── Sidebar ── */
  .logo { font-size: 18px; font-weight: 700; color: var(--accent); margin-bottom: 12px; display: flex; align-items: center; gap: 8px; }
  .logo svg { width: 24px; height: 24px; }
  .nav-section { font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: .08em; color: var(--muted); margin: 12px 0 4px; }
  .nav-btn { display: flex; align-items: center; gap: 8px; padding: 8px 10px; border-radius: 6px; cursor: pointer; border: none; background: none; color: var(--text); font-size: 13px; width: 100%; text-align: left; transition: background .15s; }
  .nav-btn:hover, .nav-btn.active { background: var(--surface2); color: var(--accent); }
  .nav-btn .dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }

  /* ── Top bar ── */
  .topbar { display: flex; align-items: center; justify-content: space-between; margin-bottom: 24px; }
  .topbar h1 { font-size: 20px; font-weight: 600; }
  .topbar .actions { display: flex; gap: 8px; }

  /* ── Cards ── */
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 16px; }
  .card-title { font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); margin-bottom: 12px; }

  /* ── Stat grid ── */
  .stat-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); gap: 12px; margin-bottom: 24px; }
  .stat { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 14px 16px; }
  .stat .value { font-size: 28px; font-weight: 700; line-height: 1; }
  .stat .label { font-size: 11px; color: var(--muted); margin-top: 4px; }

  /* ── Buttons ── */
  .btn { display: inline-flex; align-items: center; gap: 6px; padding: 7px 14px; border-radius: 6px; border: none; cursor: pointer; font-size: 13px; font-weight: 500; transition: opacity .15s; }
  .btn:disabled { opacity: .45; cursor: not-allowed; }
  .btn-primary { background: var(--accent); color: #fff; }
  .btn-secondary { background: var(--surface2); color: var(--text); border: 1px solid var(--border); }
  .btn-danger { background: var(--red); color: #fff; }
  .btn-success { background: var(--green); color: #fff; }
  .btn-sm { padding: 4px 10px; font-size: 12px; }

  /* ── Badges ── */
  .badge { display: inline-flex; align-items: center; padding: 2px 7px; border-radius: 999px; font-size: 11px; font-weight: 500; }
  .badge-pass { background: rgba(16,185,129,.18); color: #34d399; }
  .badge-fail { background: rgba(239,68,68,.18); color: #f87171; }
  .badge-pending { background: rgba(148,163,184,.12); color: var(--muted); }
  .badge-running { background: rgba(99,102,241,.18); color: #818cf8; }
  .badge-up   { background: rgba(16,185,129,.15); color: #34d399; }
  .badge-down { background: rgba(239,68,68,.15); color: #f87171; }

  /* ── Difficulty dots ── */
  .diff { display: inline-flex; gap: 3px; align-items: center; }
  .diff-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--border); }
  .diff-dot.on { background: var(--yellow); }

  /* ── Table ── */
  .tbl { width: 100%; border-collapse: collapse; }
  .tbl th { text-align: left; font-size: 11px; font-weight: 600; text-transform: uppercase; color: var(--muted); padding: 8px 10px; border-bottom: 1px solid var(--border); }
  .tbl td { padding: 9px 10px; border-bottom: 1px solid var(--border); vertical-align: middle; }
  .tbl tr:last-child td { border-bottom: none; }
  .tbl tr:hover td { background: rgba(255,255,255,.025); }

  /* ── Service pill ── */
  .svc-pill { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 500; }

  /* ── Method badge ── */
  .method { font-size: 11px; font-weight: 700; padding: 1px 6px; border-radius: 4px; font-family: monospace; }
  .method-GET    { background: rgba(16,185,129,.18); color: #34d399; }
  .method-POST   { background: rgba(99,102,241,.18); color: #818cf8; }
  .method-PUT    { background: rgba(245,158,11,.18); color: #fcd34d; }
  .method-DELETE { background: rgba(239,68,68,.18); color: #f87171; }

  /* ── URL code ── */
  code { font-family: 'JetBrains Mono', 'Cascadia Code', monospace; font-size: 12px; color: #94a3b8; }
  code a { color: #818cf8; text-decoration: none; }
  code a:hover { text-decoration: underline; }

  /* ── Filter bar ── */
  .filter-bar { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin-bottom: 16px; }
  .filter-bar input, .filter-bar select { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 6px 10px; color: var(--text); font-size: 13px; outline: none; }
  .filter-bar input:focus, .filter-bar select:focus { border-color: var(--accent); }
  .filter-bar input { width: 220px; }

  /* ── Events feed ── */
  .event-feed { font-family: monospace; font-size: 12px; max-height: 400px; overflow-y: auto; display: flex; flex-direction: column; gap: 2px; }
  .event-item { padding: 5px 8px; border-radius: 4px; background: var(--surface2); display: flex; gap: 10px; align-items: flex-start; }
  .event-item .ets { color: var(--muted); flex-shrink: 0; }
  .event-item .eid { color: #818cf8; font-weight: 600; }
  .event-item .ekind { color: #34d399; }

  /* ── Service health grid ── */
  .svc-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 10px; }
  .svc-card { background: var(--surface2); border: 1px solid var(--border); border-radius: 6px; padding: 12px 14px; display: flex; align-items: center; gap: 10px; }
  .svc-card .svc-icon { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }
  .svc-card .svc-name { font-size: 13px; font-weight: 500; }
  .svc-card .svc-status { font-size: 11px; color: var(--muted); margin-top: 1px; }

  /* ── WAF selector ── */
  .waf-grid { display: flex; gap: 8px; flex-wrap: wrap; }
  .waf-opt { padding: 6px 14px; border-radius: 999px; border: 1px solid var(--border); cursor: pointer; font-size: 12px; font-weight: 500; color: var(--muted); background: var(--surface2); transition: all .15s; }
  .waf-opt:hover { border-color: var(--accent); color: var(--accent); }
  .waf-opt.active { background: var(--accent); border-color: var(--accent); color: #fff; }

  /* ── Toast ── */
  #toast-container { position: fixed; bottom: 20px; right: 20px; display: flex; flex-direction: column; gap: 8px; z-index: 9999; }
  .toast { padding: 10px 16px; border-radius: 6px; font-size: 13px; max-width: 320px; animation: slideIn .2s ease; }
  .toast-success { background: rgba(16,185,129,.9); color: #fff; }
  .toast-error   { background: rgba(239,68,68,.9);  color: #fff; }
  .toast-info    { background: rgba(99,102,241,.9);  color: #fff; }
  @keyframes slideIn { from { transform: translateX(40px); opacity: 0; } to { transform: none; opacity: 1; } }

  /* ── Progress bar ── */
  .progress-bar { height: 6px; border-radius: 3px; background: var(--border); overflow: hidden; margin-top: 8px; }
  .progress-fill { height: 100%; border-radius: 3px; background: var(--accent); transition: width .3s; }

  /* ── Tabs ── */
  .tabs { display: flex; gap: 2px; margin-bottom: 20px; border-bottom: 1px solid var(--border); }
  .tab { padding: 8px 16px; cursor: pointer; border-bottom: 2px solid transparent; color: var(--muted); font-size: 13px; font-weight: 500; transition: all .15s; }
  .tab.active { color: var(--accent); border-bottom-color: var(--accent); }

  /* ── Section ── */
  .section { display: none; }
  .section.visible { display: block; }

  /* ── Spinner ── */
  .spin { animation: spin 1s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }

  /* ── Responsive ── */
  @media (max-width: 768px) {
    .layout { grid-template-columns: 1fr; }
    .sidebar { display: none; }
  }
</style>
</head>
<body>
<div class="layout">

<!-- ── Sidebar ── -->
<aside class="sidebar">
  <div class="logo">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
    VulnForge
  </div>
  <div style="font-size:11px;color:var(--muted);margin-bottom:8px;">Scanner Portal</div>

  <div class="nav-section">Navigation</div>
  <button class="nav-btn active" onclick="showSection('dashboard')">
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
    Dashboard
  </button>
  <button class="nav-btn" onclick="showSection('vulns')">
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
    Vulnerabilities
  </button>
  <button class="nav-btn" onclick="showSection('scan')">
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
    Scan Runner
  </button>
  <button class="nav-btn" onclick="showSection('events')">
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 20V10"/><path d="M12 20V4"/><path d="M6 20v-6"/></svg>
    Live Events
  </button>
  <button class="nav-btn" onclick="showSection('settings')">
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.07 4.93l-1.41 1.41M4.93 4.93l1.41 1.41M19.07 19.07l-1.41-1.41M4.93 19.07l1.41-1.41M20 12h2M2 12h2M12 20v2M12 2v2"/></svg>
    Settings
  </button>

  <div class="nav-section" style="margin-top:16px;">Services</div>
  <div id="sidebar-services" style="display:flex;flex-direction:column;gap:4px;"></div>

  <div style="margin-top:auto;padding-top:16px;border-top:1px solid var(--border);font-size:11px;color:var(--muted);">
    <div>Gateway: <span id="sidebar-gw" style="color:var(--green);">checking…</span></div>
    <div style="margin-top:4px;">Lab: <a href="http://localhost:9100/__lab/docs" target="_blank" style="color:var(--accent);">API docs ↗</a></div>
  </div>
</aside>

<!-- ── Main ── -->
<main class="main">

<!-- Dashboard -->
<div id="section-dashboard" class="section visible">
  <div class="topbar">
    <h1>Dashboard</h1>
    <div class="actions">
      <button class="btn btn-secondary btn-sm" onclick="loadAll()">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
        Refresh
      </button>
      <button class="btn btn-danger btn-sm" onclick="resetLab()">Reset Lab</button>
    </div>
  </div>

  <div class="stat-grid" id="stats"></div>

  <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:20px;">
    <div class="card">
      <div class="card-title">Service Health</div>
      <div class="svc-grid" id="health-grid"></div>
    </div>
    <div class="card">
      <div class="card-title">Vulnerabilities by Category</div>
      <div id="category-chart" style="display:flex;flex-direction:column;gap:6px;max-height:280px;overflow-y:auto;"></div>
    </div>
  </div>

  <div class="card">
    <div class="card-title">Recent Triggered Events <span id="event-count" style="color:var(--muted);font-weight:400;"></span></div>
    <div class="event-feed" id="event-feed-dash"></div>
  </div>
</div>

<!-- Vulnerabilities -->
<div id="section-vulns" class="section">
  <div class="topbar">
    <h1>Vulnerabilities <span id="vuln-count" style="font-size:14px;color:var(--muted);font-weight:400;"></span></h1>
    <div class="actions">
      <button class="btn btn-primary btn-sm" onclick="showSection('scan')">Run All Tests</button>
    </div>
  </div>

  <div class="filter-bar">
    <input id="vuln-search" placeholder="Search ID, name, URL…" oninput="filterVulns()">
    <select id="vuln-service" onchange="filterVulns()">
      <option value="">All services</option>
      <option value="php-web">PHP Web</option>
      <option value="node-api">Node API</option>
      <option value="flask-svc">Flask / PY</option>
      <option value="spring-svc">Spring / Java</option>
      <option value="go-svc">Go</option>
      <option value="graphql-svc">GraphQL</option>
      <option value="crawl-lab">Crawl Lab</option>
      <option value="legacy-svc">Legacy</option>
      <option value="auth-svc">Auth / OAuth</option>
    </select>
    <select id="vuln-owasp" onchange="filterVulns()">
      <option value="">All OWASP</option>
      <option value="A01">A01 Broken Access Control</option>
      <option value="A02">A02 Cryptographic Failures</option>
      <option value="A03">A03 Injection</option>
      <option value="A04">A04 Insecure Design</option>
      <option value="A05">A05 Misconfiguration</option>
      <option value="A06">A06 Outdated Components</option>
      <option value="A07">A07 Auth Failures</option>
      <option value="A08">A08 Integrity Failures</option>
      <option value="A10">A10 SSRF</option>
    </select>
    <select id="vuln-diff" onchange="filterVulns()">
      <option value="">All levels</option>
      <option value="1">Level 1</option>
      <option value="2">Level 2</option>
      <option value="3">Level 3+</option>
    </select>
  </div>

  <div class="card" style="overflow-x:auto;">
    <table class="tbl">
      <thead>
        <tr>
          <th>ID</th>
          <th>Name</th>
          <th>Service</th>
          <th>Method</th>
          <th>URL</th>
          <th>OWASP</th>
          <th>Level</th>
          <th>Scan</th>
        </tr>
      </thead>
      <tbody id="vuln-tbody"></tbody>
    </table>
  </div>
</div>

<!-- Scan Runner -->
<div id="section-scan" class="section">
  <div class="topbar">
    <h1>Scan Runner</h1>
  </div>

  <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:20px;">
    <div class="card">
      <div class="card-title">Full Smoke Suite</div>
      <p style="color:var(--muted);font-size:13px;margin-bottom:14px;">
        Runs all 78 smoke tests against every vulnerability. Tests call the gateway endpoints directly and verify exploit proof.
      </p>
      <div id="scan-progress" style="display:none;">
        <div style="font-size:13px;color:var(--muted);margin-bottom:6px;" id="scan-status-text">Running…</div>
        <div class="progress-bar"><div class="progress-fill" id="scan-progress-fill" style="width:0%"></div></div>
      </div>
      <div style="display:flex;gap:8px;margin-top:14px;">
        <button class="btn btn-primary" id="btn-scan-all" onclick="runScanAll()">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>
          Run All Tests
        </button>
      </div>
    </div>
    <div class="card">
      <div class="card-title">Scan Summary</div>
      <div id="scan-summary" style="display:none;">
        <div style="display:flex;gap:20px;margin-bottom:12px;">
          <div class="stat" style="flex:1"><div class="value" id="sum-pass" style="color:var(--green)">—</div><div class="label">Passed</div></div>
          <div class="stat" style="flex:1"><div class="value" id="sum-fail" style="color:var(--red)">—</div><div class="label">Failed</div></div>
          <div class="stat" style="flex:1"><div class="value" id="sum-total">—</div><div class="label">Total</div></div>
        </div>
        <div class="progress-bar" style="margin-top:0;">
          <div class="progress-fill" id="summary-fill" style="width:0%;background:var(--green)"></div>
        </div>
      </div>
      <div id="scan-empty" style="color:var(--muted);font-size:13px;">No scan run yet.</div>
    </div>
  </div>

  <div class="card" id="scan-results-card" style="display:none;overflow-x:auto;">
    <div class="card-title">Test Results</div>
    <table class="tbl">
      <thead>
        <tr><th>ID</th><th>Status</th><th>Message</th><th>Action</th></tr>
      </thead>
      <tbody id="scan-tbody"></tbody>
    </table>
  </div>
</div>

<!-- Live Events -->
<div id="section-events" class="section">
  <div class="topbar">
    <h1>Live Events</h1>
    <div class="actions">
      <button class="btn btn-secondary btn-sm" onclick="loadEvents()">Refresh</button>
      <button class="btn btn-secondary btn-sm" id="btn-auto-refresh" onclick="toggleAutoRefresh()">Auto-refresh: OFF</button>
    </div>
  </div>

  <div class="filter-bar">
    <input id="event-filter-id" placeholder="Filter by vuln ID…" oninput="filterEvents()">
    <select id="event-filter-kind" onchange="filterEvents()">
      <option value="">All kinds</option>
      <option value="vuln_triggered">vuln_triggered</option>
      <option value="reset">reset</option>
      <option value="mode_change">mode_change</option>
      <option value="waf_change">waf_change</option>
    </select>
  </div>

  <div class="card">
    <div class="card-title">Events <span id="events-total" style="color:var(--muted);font-weight:400;"></span></div>
    <div class="event-feed" id="event-feed-main" style="max-height:600px;"></div>
  </div>
</div>

<!-- Settings -->
<div id="section-settings" class="section">
  <div class="topbar"><h1>Settings</h1></div>

  <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">
    <div class="card">
      <div class="card-title">WAF Profile</div>
      <p style="color:var(--muted);font-size:13px;margin-bottom:14px;">Changes the active WAF ruleset in the Nginx gateway.</p>
      <div class="waf-grid" id="waf-grid"></div>
      <div style="margin-top:14px;font-size:12px;color:var(--muted);">Current: <strong id="waf-current">loading…</strong></div>
    </div>
    <div class="card">
      <div class="card-title">Lab Actions</div>
      <div style="display:flex;flex-direction:column;gap:10px;">
        <div>
          <div style="font-size:13px;margin-bottom:6px;">Reset all databases to seed state</div>
          <button class="btn btn-danger btn-sm" onclick="resetLab()">Reset Lab</button>
        </div>
        <div style="border-top:1px solid var(--border);padding-top:10px;">
          <div style="font-size:13px;margin-bottom:6px;">Scan session management</div>
          <div style="display:flex;gap:8px;">
            <button class="btn btn-secondary btn-sm" onclick="startSession()">Start Session</button>
            <button class="btn btn-secondary btn-sm" onclick="stopSession()">Stop Session</button>
          </div>
        </div>
        <div style="border-top:1px solid var(--border);padding-top:10px;">
          <div style="font-size:13px;margin-bottom:6px;">Gateway target URL</div>
          <code id="gateway-url" style="color:var(--accent);">http://127.0.0.1:PORT</code>
        </div>
      </div>
    </div>
  </div>
</div>

</main>
</div>

<!-- Toast container -->
<div id="toast-container"></div>

<script>
// ── State ──────────────────────────────────────────────────────────────────
let vulns = [];
let scanResults = [];
let autoRefreshTimer = null;
const BASE = '/__portal/api';
const GW = window.location.origin;

// ── Init ──────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  loadAll();
  document.getElementById('gateway-url').textContent = GW;
  document.getElementById('sidebar-gw').textContent = GW;
});

async function loadAll() {
  await Promise.all([loadVulns(), loadHealth(), loadEvents(), loadWaf()]);
}

// ── Navigation ────────────────────────────────────────────────────────────
function showSection(id) {
  document.querySelectorAll('.section').forEach(s => s.classList.remove('visible'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('section-' + id).classList.add('visible');
  event?.target?.closest('.nav-btn')?.classList.add('active');
}

// ── API helpers ───────────────────────────────────────────────────────────
async function api(path, opts = {}) {
  const r = await fetch(BASE + path, opts);
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
  return r.json();
}

// ── Toast ─────────────────────────────────────────────────────────────────
function toast(msg, type = 'info') {
  const el = document.createElement('div');
  el.className = `toast toast-${type}`;
  el.textContent = msg;
  document.getElementById('toast-container').appendChild(el);
  setTimeout(() => el.remove(), 3500);
}

// ── Vulns ─────────────────────────────────────────────────────────────────
async function loadVulns() {
  try {
    vulns = await api('/vulns');
    renderVulns(vulns);
    renderStats(vulns);
    renderCategoryChart(vulns);
  } catch(e) { toast('Failed to load vulnerabilities: ' + e.message, 'error'); }
}

function renderVulns(list) {
  const tbody = document.getElementById('vuln-tbody');
  document.getElementById('vuln-count').textContent = `(${list.length})`;
  tbody.innerHTML = list.map(v => `
    <tr>
      <td><code style="color:var(--accent)">${v.id}</code></td>
      <td style="max-width:260px;white-space:normal;line-height:1.4;">${v.name}</td>
      <td><span class="svc-pill" style="background:${v.service_color}22;color:${v.service_color};">${v.service_label}</span></td>
      <td><span class="method method-${v.method}">${v.method}</span></td>
      <td><code><a href="${v.url}" target="_blank">${v.url}</a></code></td>
      <td style="font-size:12px;color:var(--muted);">${v.owasp_label || v.owasp_web_2021 || ''}</td>
      <td>${diffDots(v.difficulty)}</td>
      <td>
        <button class="btn btn-secondary btn-sm" onclick="runScanOne('${v.id}')">Test</button>
      </td>
    </tr>
  `).join('');

  // Sidebar services
  const svcs = [...new Set(vulns.map(v => v.service))];
  document.getElementById('sidebar-services').innerHTML = svcs.map(s => {
    const meta = {
      'php-web':{'label':'PHP','color':'#6366f1'},'node-api':{'label':'Node API','color':'#0ea5e9'},
      'flask-svc':{'label':'Flask','color':'#10b981'},'spring-svc':{'label':'Spring','color':'#f59e0b'},
      'go-svc':{'label':'Go','color':'#ef4444'},'graphql-svc':{'label':'GraphQL','color':'#8b5cf6'},
      'crawl-lab':{'label':'Crawl','color':'#ec4899'},'legacy-svc':{'label':'Legacy','color':'#64748b'},
      'auth-svc':{'label':'Auth','color':'#f97316'}
    }[s] || {label:s,color:'#94a3b8'};
    const count = vulns.filter(v=>v.service===s).length;
    return `<button class="nav-btn" onclick="filterByService('${s}')">
      <span class="dot" style="background:${meta.color}"></span>
      ${meta.label} <span style="margin-left:auto;color:var(--muted);font-size:11px;">${count}</span>
    </button>`;
  }).join('');
}

function filterByService(svc) {
  document.getElementById('vuln-service').value = svc;
  showSection('vulns');
  filterVulns();
}

function filterVulns() {
  const q = document.getElementById('vuln-search').value.toLowerCase();
  const svc = document.getElementById('vuln-service').value;
  const owasp = document.getElementById('vuln-owasp').value;
  const diff = document.getElementById('vuln-diff').value;

  const filtered = vulns.filter(v => {
    if (q && !(v.id+v.name+v.url+v.type).toLowerCase().includes(q)) return false;
    if (svc && v.service !== svc) return false;
    if (owasp && v.owasp_web_2021 !== owasp && v.owasp_api_2023 !== owasp) return false;
    if (diff) {
      const d = Number(diff);
      if (d === 3 && v.difficulty < 3) return false;
      if (d < 3 && v.difficulty !== d) return false;
    }
    return true;
  });
  renderVulns(filtered);
}

function diffDots(n) {
  return `<span class="diff">${[1,2,3,4].map(i => `<span class="diff-dot ${i<=n?'on':''}"></span>`).join('')}</span>`;
}

function renderStats(list) {
  const byService = {};
  list.forEach(v => { byService[v.service] = (byService[v.service]||0)+1; });
  const owasp = [...new Set(list.map(v=>v.owasp_web_2021||v.owasp_api_2023))].filter(Boolean);

  document.getElementById('stats').innerHTML = `
    <div class="stat"><div class="value" style="color:var(--accent)">${list.length}</div><div class="label">Total Vulnerabilities</div></div>
    <div class="stat"><div class="value">${Object.keys(byService).length}</div><div class="label">Services</div></div>
    <div class="stat"><div class="value">${owasp.length}</div><div class="label">OWASP Categories</div></div>
    <div class="stat"><div class="value" style="color:var(--red)">${list.filter(v=>v.difficulty>=3).length}</div><div class="label">Level 3+ Vulns</div></div>
  `;
}

function renderCategoryChart(list) {
  const counts = {};
  list.forEach(v => {
    const cat = v.owasp_label || (v.owasp_web_2021||v.owasp_api_2023) || 'Other';
    counts[cat] = (counts[cat]||0)+1;
  });
  const max = Math.max(...Object.values(counts));
  const sorted = Object.entries(counts).sort((a,b)=>b[1]-a[1]);
  document.getElementById('category-chart').innerHTML = sorted.map(([cat, n]) => `
    <div>
      <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:3px;">
        <span style="color:var(--muted);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${cat}</span>
        <span style="color:var(--text)">${n}</span>
      </div>
      <div class="progress-bar" style="margin-top:0;height:4px;">
        <div class="progress-fill" style="width:${(n/max*100).toFixed(0)}%"></div>
      </div>
    </div>
  `).join('');
}

// ── Health ─────────────────────────────────────────────────────────────────
async function loadHealth() {
  try {
    const data = await api('/health');
    const svcs = data.services || {};
    document.getElementById('health-grid').innerHTML = Object.entries(svcs).map(([name, s]) => {
      const up = s.status === 'up';
      return `<div class="svc-card">
        <div class="svc-icon" style="background:${up?'var(--green)':'var(--red)'}"></div>
        <div>
          <div class="svc-name">${name}</div>
          <div class="svc-status badge ${up?'badge-up':'badge-down'}">${s.status}</div>
        </div>
      </div>`;
    }).join('');
  } catch(e) { console.warn('health check failed', e); }
}

// ── Events ────────────────────────────────────────────────────────────────
let allEvents = [];

async function loadEvents() {
  try {
    allEvents = await api('/events?limit=200');
    renderEventsMain(allEvents);
    renderEventsDash(allEvents.slice(0, 10));
  } catch(e) { console.warn('events failed', e); }
}

function renderEventsDash(list) {
  document.getElementById('event-count').textContent = `(${list.length})`;
  document.getElementById('event-feed-dash').innerHTML = renderEventItems(list) || '<div style="color:var(--muted);font-size:12px;padding:4px;">No events yet. Run a scan to trigger vulnerabilities.</div>';
}

function renderEventsMain(list) {
  document.getElementById('events-total').textContent = `(${list.length})`;
  document.getElementById('event-feed-main').innerHTML = renderEventItems(list) || '<div style="color:var(--muted);font-size:12px;padding:4px;">No events recorded.</div>';
}

function renderEventItems(list) {
  return [...list].reverse().map(e => {
    const ts = e.ts ? new Date(e.ts).toLocaleTimeString() : '';
    const vid = e.vuln_id ? `<span class="eid">${e.vuln_id}</span>` : '';
    const kind = `<span class="ekind">${e.kind||''}</span>`;
    const extra = Object.entries(e).filter(([k])=>!['ts','kind','vuln_id','service','request_id'].includes(k)).map(([k,v])=>`${k}=${JSON.stringify(v)}`).join(' ');
    return `<div class="event-item"><span class="ets">${ts}</span>${kind} ${vid} <span style="color:var(--muted)">${e.service||''}</span> <span style="color:#64748b">${extra}</span></div>`;
  }).join('');
}

function filterEvents() {
  const idFilter = document.getElementById('event-filter-id').value.toLowerCase();
  const kindFilter = document.getElementById('event-filter-kind').value;
  const filtered = allEvents.filter(e => {
    if (idFilter && !(e.vuln_id||'').toLowerCase().includes(idFilter)) return false;
    if (kindFilter && e.kind !== kindFilter) return false;
    return true;
  });
  renderEventsMain(filtered);
}

let autoRefreshOn = false;
function toggleAutoRefresh() {
  autoRefreshOn = !autoRefreshOn;
  document.getElementById('btn-auto-refresh').textContent = `Auto-refresh: ${autoRefreshOn ? 'ON' : 'OFF'}`;
  if (autoRefreshOn) {
    autoRefreshTimer = setInterval(loadEvents, 3000);
    toast('Auto-refresh enabled (3s)', 'info');
  } else {
    clearInterval(autoRefreshTimer);
  }
}

// ── WAF ───────────────────────────────────────────────────────────────────
const WAF_PROFILES = ['waf-off','waf-low','waf-high','ratelimit','flaky'];
let currentWaf = 'waf-off';

async function loadWaf() {
  try {
    const data = await api('/waf');
    currentWaf = data.profile;
    renderWaf();
  } catch(e) {}
}

function renderWaf() {
  document.getElementById('waf-current').textContent = currentWaf;
  document.getElementById('waf-grid').innerHTML = WAF_PROFILES.map(p =>
    `<div class="waf-opt ${p===currentWaf?'active':''}" onclick="setWaf('${p}')">${p}</div>`
  ).join('');
}

async function setWaf(profile) {
  try {
    await api('/waf', { method: 'POST', headers: {'content-type':'application/json'}, body: JSON.stringify({profile}) });
    currentWaf = profile;
    renderWaf();
    toast(`WAF profile set to "${profile}"`, 'success');
  } catch(e) { toast('WAF change failed: ' + e.message, 'error'); }
}

// ── Lab actions ───────────────────────────────────────────────────────────
async function resetLab() {
  if (!confirm('Reset all databases to seed state? All manual state will be lost.')) return;
  try {
    const r = await api('/reset', { method: 'POST' });
    toast('Lab reset ' + (r.status || 'ok'), 'success');
    loadEvents();
  } catch(e) { toast('Reset failed: ' + e.message, 'error'); }
}

async function startSession() {
  try {
    await api('/session/start', { method: 'POST', headers: {'content-type':'application/json'}, body: JSON.stringify({scanner_name:'manual'}) });
    toast('Scan session started', 'success');
  } catch(e) { toast('Session start failed: ' + e.message, 'error'); }
}

async function stopSession() {
  try {
    const r = await api('/session/stop', { method: 'POST' });
    toast('Session stopped. Triggered: ' + (r.triggered_count || 0), 'success');
  } catch(e) { toast('Session stop failed: ' + e.message, 'error'); }
}

// ── Scan runner ───────────────────────────────────────────────────────────
let scanRunning = false;

async function runScanAll() {
  if (scanRunning) return;
  scanRunning = true;
  const btn = document.getElementById('btn-scan-all');
  btn.disabled = true;
  btn.innerHTML = '<svg class="spin" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg> Running…';

  document.getElementById('scan-progress').style.display = 'block';
  document.getElementById('scan-status-text').textContent = 'Running all 78 smoke tests…';
  document.getElementById('scan-progress-fill').style.width = '15%';

  showSection('scan');

  try {
    // Animate progress while waiting
    let pct = 15;
    const ticker = setInterval(() => {
      pct = Math.min(pct + 2, 90);
      document.getElementById('scan-progress-fill').style.width = pct + '%';
    }, 1500);

    const result = await fetch(BASE + '/scan/all', {method:'POST'}).then(r=>r.json());
    clearInterval(ticker);

    document.getElementById('scan-progress-fill').style.width = '100%';
    document.getElementById('scan-status-text').textContent = 'Complete.';

    renderScanResults(result);
    toast(`Scan complete: ${result.passed} passed, ${result.failed} failed`, result.failed===0?'success':'error');
  } catch(e) {
    toast('Scan failed: ' + e.message, 'error');
  } finally {
    scanRunning = false;
    btn.disabled = false;
    btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg> Run All Tests';
  }
}

async function runScanOne(id) {
  toast(`Testing ${id}…`, 'info');
  try {
    const result = await fetch(BASE + `/scan/${id}`, {method:'POST'}).then(r=>r.json());
    if (result.results && result.results.length > 0) {
      const r = result.results[0];
      toast(`${id}: ${r.status.toUpperCase()} — ${r.message}`, r.status==='pass'?'success':'error');
    }
    // Update the scan results table row if visible
    const existing = document.getElementById(`scan-row-${id}`);
    if (existing && result.results?.[0]) {
      const r = result.results[0];
      existing.querySelector('.scan-status').innerHTML = `<span class="badge badge-${r.status}">${r.status}</span>`;
      existing.querySelector('.scan-msg').textContent = r.message;
    }
    loadEvents();
  } catch(e) { toast('Test failed: ' + e.message, 'error'); }
}

function renderScanResults(result) {
  const { passed=0, failed=0, total=0, results=[] } = result;
  const pct = total > 0 ? Math.round(passed/total*100) : 0;

  document.getElementById('scan-summary').style.display = 'block';
  document.getElementById('scan-empty').style.display = 'none';
  document.getElementById('sum-pass').textContent = passed;
  document.getElementById('sum-fail').textContent = failed;
  document.getElementById('sum-total').textContent = total;
  document.getElementById('summary-fill').style.width = pct + '%';

  document.getElementById('scan-results-card').style.display = 'block';
  document.getElementById('scan-tbody').innerHTML = results.map(r => {
    const vuln = vulns.find(v => v.id === r.id) || {};
    return `<tr id="scan-row-${r.id}">
      <td><code style="color:var(--accent)">${r.id}</code></td>
      <td class="scan-status"><span class="badge badge-${r.status}">${r.status}</span></td>
      <td class="scan-msg" style="color:${r.status==='pass'?'var(--green)':'var(--red)'};font-size:12px;">${r.message}</td>
      <td><button class="btn btn-secondary btn-sm" onclick="runScanOne('${r.id}')">Re-test</button></td>
    </tr>`;
  }).join('');

  loadEvents();
}
</script>
</body>
</html>
"""


@app.get("/__portal", response_class=HTMLResponse)
async def portal():
    return HTMLResponse(content=PORTAL_HTML)


@app.get("/__portal/", response_class=HTMLResponse)
async def portal_slash():
    return HTMLResponse(content=PORTAL_HTML)
