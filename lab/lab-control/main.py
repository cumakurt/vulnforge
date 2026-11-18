"""
VulnForge Lab — lab-control service
Listens on 127.0.0.1:9100 (scope-excluded from scanner target).

Endpoints:
  POST /__lab/reset             Reset all DBs to seed state
  POST /__lab/seed?profile=...  Choose seed data volume
  GET  /__lab/vulns             Return vulns.json
  GET  /__lab/controls          Return controls.json
  GET  /__lab/mode              Get active mode filter
  PUT  /__lab/mode              Set mode filter (service, owasp category, max level)
  GET  /__lab/waf               Get current WAF profile
  PUT  /__lab/waf               Change WAF profile
  GET  /__lab/events            Stream recent vuln_triggered / scanner events
  POST /__lab/events            Record an event (called by services internally)
  POST /__lab/session/start     Start a timed scan session
  POST /__lab/session/stop      Stop scan session and return stats
  GET  /__lab/health            Health of all services
"""

import asyncio
import json
import os
import subprocess
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# ─── Configuration ────────────────────────────────────────────────────────────

TRUTH_DIR = Path(os.environ.get("TRUTH_DIR", "/app/lab/truth"))
COMPOSE_PROJECT = os.environ.get("COMPOSE_PROJECT_NAME", "vulnforge")

# Internal service health endpoints (via compose service names)
SERVICES: dict[str, str] = {
    "php-web":       "http://php-web/health.php",
    "node-api":      "http://node-api:3000/health",
    "flask-svc":     "http://flask-svc:5000/health",
    "spring-svc":    "http://spring-svc:8080/health",
    "go-svc":        "http://go-svc:8090/health",
    "oob-collector": "http://oob-collector:9000/health",
}

# In-memory event log (bounded)
MAX_EVENTS = 10_000
event_log: deque[dict] = deque(maxlen=MAX_EVENTS)

# Mutable state
state: dict[str, Any] = {
    "waf_profile": os.environ.get("WAF_PROFILE", "waf-off"),
    "mode": {
        "services": [],       # [] = all
        "owasp": [],          # [] = all categories
        "max_level": 4,
        "min_level": 0,
    },
    "seed_profile": os.environ.get("SEED_PROFILE", "small"),
    "session": None,
}

app = FastAPI(
    title="VulnForge Lab Control",
    version="0.1.0",
    docs_url="/__lab/docs",
    redoc_url=None,
)

# ─── Helpers ─────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=500, detail=f"JSON parse error in {path}: {e}")


def _record_event(kind: str, data: dict) -> None:
    event_log.append({"ts": _now_iso(), "kind": kind, **data})


def _parse_ts(value: str | None) -> datetime | None:
    """Parse ISO-8601 timestamps with or without microseconds."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


# ─── Routes ──────────────────────────────────────────────────────────────────

@app.get("/__lab/about")
def about():
    """Project and author metadata."""
    return {
        "name": "VulnForge Lab",
        "version": "1.0.0",
        "description": "Intentionally vulnerable web suite for scanner benchmarking",
        "author": "Cuma KURT",
        "email": "cumakurt@gmail.com",
        "linkedin": "https://www.linkedin.com/in/cuma-kurt-34414917/",
        "github": "https://github.com/cumakurt/vulnforge",
        "license": "AGPL-3.0-only",
        "warning": "Deliberately insecure. Run only in an isolated local environment.",
    }


@app.get("/__lab/health")
async def health():
    """Check health of all lab services."""
    results: dict[str, Any] = {}

    async with httpx.AsyncClient(timeout=1.5) as client:
        names = list(SERVICES)
        responses = await asyncio.gather(
            *(client.get(url) for url in SERVICES.values()),
            return_exceptions=True,
        )

    for name, response in zip(names, responses):
        if isinstance(response, Exception):
            results[name] = {"status": "down", "error": str(response)}
        else:
            results[name] = {"status": "up", "code": response.status_code}

    overall = "healthy" if all(v["status"] == "up" for v in results.values()) else "degraded"
    return {"overall": overall, "services": results, "ts": _now_iso()}


@app.post("/__lab/reset")
async def reset():
    """
    Trigger reset for all services.
    Each service exposes POST /__lab/internal/reset which wipes and re-seeds its DB.
    """
    _record_event("reset", {"triggered_by": "lab-control"})
    errors: list[str] = []

    async with httpx.AsyncClient(timeout=30.0) as client:
        reset_urls = {
            "php-web":    "http://php-web/__lab/internal/reset.php",
            "node-api":   "http://node-api:3000/__lab/internal/reset",
            "flask-svc":  "http://flask-svc:5000/__lab/internal/reset",
            "spring-svc": "http://spring-svc:8080/__lab/internal/reset",
            "go-svc":     "http://go-svc:8090/__lab/internal/reset",
        }
        for svc, url in reset_urls.items():
            try:
                r = await client.post(url)
                if r.status_code != 200:
                    errors.append(f"{svc}: HTTP {r.status_code}")
            except Exception as e:
                errors.append(f"{svc}: {e}")

    # Clear OOB events
    event_log.clear()

    return {
        "status": "ok" if not errors else "partial",
        "errors": errors,
        "ts": _now_iso(),
    }


class SeedRequest(BaseModel):
    profile: str = "small"


@app.post("/__lab/seed")
async def seed(profile: str = Query("small", pattern="^(small|large)$")):
    """Re-seed databases with specified data volume."""
    state["seed_profile"] = profile
    _record_event("seed", {"profile": profile})

    async with httpx.AsyncClient(timeout=60.0) as client:
        seed_urls = {
            "php-web":     f"http://php-web/__lab/internal/seed.php?profile={profile}",
            "node-api":    f"http://node-api:3000/__lab/internal/seed?profile={profile}",
            "flask-svc":   f"http://flask-svc:5000/__lab/internal/seed?profile={profile}",
            "go-svc":      f"http://go-svc:8090/__lab/internal/seed?profile={profile}",
            "graphql-svc": f"http://graphql-svc:4000/__lab/internal/seed?profile={profile}",
        }
        results = {}
        for svc, url in seed_urls.items():
            try:
                r = await client.post(url)
                results[svc] = r.status_code
            except Exception as e:
                results[svc] = str(e)

    return {"status": "ok", "profile": profile, "results": results}


@app.get("/__lab/vulns")
def get_vulns():
    """Return the generated vulns.json (ground truth)."""
    vulns = _load_json(TRUTH_DIR / "vulns.json")
    mode = state["mode"]

    # Apply mode filters
    if mode["services"]:
        vulns = [v for v in vulns if v.get("service") in mode["services"]]
    if mode["owasp"]:
        vulns = [
            v for v in vulns
            if v.get("owasp_web_2021") in mode["owasp"] or v.get("owasp_api_2023") in mode["owasp"]
        ]
    vulns = [
        v for v in vulns
        if mode["min_level"] <= v.get("difficulty", 0) <= mode["max_level"]
    ]

    return vulns


@app.get("/__lab/controls")
def get_controls():
    """Return the generated controls.json (safe twins)."""
    return _load_json(TRUTH_DIR / "controls.json")


@app.get("/__lab/mode")
def get_mode():
    return state["mode"]


class ModeRequest(BaseModel):
    services: list[str] = []
    owasp: list[str] = []
    min_level: int = 0
    max_level: int = 4


@app.put("/__lab/mode")
def set_mode(body: ModeRequest):
    state["mode"] = body.model_dump()
    _record_event("mode_change", body.model_dump())
    return {"status": "ok", "mode": state["mode"]}


@app.get("/__lab/waf")
def get_waf():
    return {"profile": state["waf_profile"]}


class WafRequest(BaseModel):
    profile: str


@app.put("/__lab/waf")
def set_waf(body: WafRequest):
    valid = {"waf-off", "waf-low", "waf-high", "ratelimit", "flaky", "waf-honeypot"}
    if body.profile not in valid:
        raise HTTPException(400, f"Unknown profile '{body.profile}'. Valid: {sorted(valid)}")
    state["waf_profile"] = body.profile
    _record_event("waf_change", {"profile": body.profile})
    # In a real deployment this would signal Nginx to reload with the new config
    return {"status": "ok", "profile": state["waf_profile"]}


@app.get("/__lab/events")
def get_events(
    kind: str | None = Query(None, description="Filter by event kind"),
    vuln_id: str | None = Query(None, description="Filter by vuln id"),
    since: str | None = Query(None, description="ISO8601 timestamp lower bound"),
    limit: int = Query(200, le=1000),
):
    """Return recent lab events (vuln_triggered, oob, scanner, etc.)."""
    events = list(event_log)

    if kind:
        events = [e for e in events if e.get("kind") == kind]
    if vuln_id:
        events = [e for e in events if e.get("vuln_id") == vuln_id]
    if since:
        since_ts = _parse_ts(since)
        if since_ts is not None:
            since_ts = since_ts.replace(microsecond=0)
            events = [
                e for e in events
                if (_parse_ts(e.get("ts")) or datetime.min.replace(tzinfo=timezone.utc)) >= since_ts
            ]

    return events[-limit:]


@app.post("/__lab/events")
async def post_event(request: Request):
    """
    Record an event emitted by an internal service.
    Body: {"kind": "vuln_triggered", "vuln_id": "SQLI-001", "request_id": "...", ...}
    """
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON body")

    if "kind" not in body:
        raise HTTPException(400, "'kind' field required")

    _record_event(body.pop("kind"), body)
    return {"status": "recorded"}


class SessionStartRequest(BaseModel):
    scanner_name: str = "unknown"
    scanner_version: str = ""
    notes: str = ""


@app.post("/__lab/session/start")
def session_start(body: SessionStartRequest):
    if state["session"] is not None:
        raise HTTPException(409, "A session is already active. Stop it first.")
    state["session"] = {
        "id": f"session-{int(time.time())}",
        "started_at": _now_iso(),
        "scanner_name": body.scanner_name,
        "scanner_version": body.scanner_version,
        "notes": body.notes,
        "event_count_at_start": len(event_log),
    }
    _record_event("session_start", {"session_id": state["session"]["id"]})
    return state["session"]


@app.post("/__lab/session/stop")
def session_stop():
    if state["session"] is None:
        raise HTTPException(409, "No active session.")
    sess = state["session"]
    sess["ended_at"] = _now_iso()
    start_ts = _parse_ts(sess["started_at"])
    if start_ts is not None:
        start_ts = start_ts.replace(microsecond=0)
    session_events = [
        e for e in event_log
        if start_ts is not None
        and (_parse_ts(e.get("ts")) or datetime.min.replace(tzinfo=timezone.utc)) >= start_ts
    ]
    triggered_ids = [e["vuln_id"] for e in session_events if e.get("kind") == "vuln_triggered" and "vuln_id" in e]
    sess["triggered_vuln_ids"] = list(set(triggered_ids))
    sess["event_count"] = len(session_events)
    state["session"] = None
    _record_event("session_stop", {"session_id": sess["id"]})
    return sess


# ═══════════════════════════════════════════════════════════════════════════════
# INTERNAL METADATA SERVICE (absorbed from infra/internal-metadata)
# Simulates AWS EC2 IMDSv1 for SSRF testing.
# Accessible via Docker network internal_net at 169.254.169.100:80.
# ═══════════════════════════════════════════════════════════════════════════════

_FAKE_IAM = """{
  "Code": "Success",
  "LastUpdated": "2024-01-01T00:00:00Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "Token": "AQoXnyc4lcK4w4OIaYnuFT5//////////wEaoAK1wvxJY12r2IKwFhZg==",
  "Expiration": "2099-01-01T00:00:00Z"
}"""

_FAKE_META: dict[str, str] = {
    "ami-id": "ami-deadbeef",
    "hostname": "ip-10-0-1-42.ec2.internal",
    "instance-id": "i-deadbeef12345678",
    "instance-type": "t3.micro",
    "local-ipv4": "10.0.1.42",
    "public-ipv4": "1.2.3.4",
    "placement/availability-zone": "us-east-1a",
    "placement/region": "us-east-1",
    "security-groups": "default",
    "iam/security-credentials/": "vulnforge-role",
}

from fastapi.responses import PlainTextResponse as _PlainText


@app.get("/latest/meta-data/")
def imds_list():
    return _PlainText("\n".join(_FAKE_META.keys()))


@app.get("/latest/meta-data/{path:path}")
def imds_get(path: str):
    if path == "iam/security-credentials/vulnforge-role":
        return _PlainText(_FAKE_IAM)
    value = _FAKE_META.get(path)
    if value is None:
        raise HTTPException(404, "Not found")
    return _PlainText(str(value))


@app.get("/latest/user-data")
def imds_userdata():
    return _PlainText(
        "#!/bin/bash\nexport DB_PASSWORD=vulnforge_ssrf_test_password\n"
        "export API_KEY=vulnforge_ssrf_test_api_key_12345\n"
        "echo 'VulnForge SSRF test successful'\n"
    )
