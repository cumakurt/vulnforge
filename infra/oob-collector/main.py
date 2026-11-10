"""
VulnForge Lab — OOB (Out-of-Band) Collector

Collects two types of callbacks used to prove blind vulnerability exploitation:
  1. HTTP callbacks  — blind SQLi exfil, blind CMDi, blind SSRF, etc.
  2. DNS callbacks   — blind XXE OOB, JNDI lookup simulation, DNS exfil

Each callback is tagged with a unique token that ties it back to a vuln_id
in vulns.json.  The lab-control service (and scorer) query this service to
confirm exploitation evidence.

HTTP server  : 0.0.0.0:9000
DNS server   : 0.0.0.0:5353/UDP

Token encoding in DNS:  <token>.<subdomain>.oob.lab.local
Token encoding in HTTP: GET /oob/<token>  or  POST /oob/<token>
"""

import asyncio
import logging
import re
import socket
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Optional

import uvicorn
from dnslib import DNSRecord, QTYPE, RR, A
from fastapi import FastAPI, Path as FPath, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger("oob-collector")
logging.basicConfig(level=logging.INFO)

# ─── In-memory store ─────────────────────────────────────────────────────────

MAX_EVENTS = 50_000

class OOBStore:
    def __init__(self):
        self._events: deque[dict] = deque(maxlen=MAX_EVENTS)
        self._lock = threading.Lock()

    def record(self, protocol: str, token: str, source_ip: str, raw: str = "") -> dict:
        event = {
            "id": f"{protocol}-{int(time.time()*1000)}",
            "protocol": protocol,
            "token": token,
            "source_ip": source_ip,
            "raw": raw[:500],
            "ts": datetime.now(timezone.utc).isoformat(),
        }
        with self._lock:
            self._events.append(event)
        logger.info(f"OOB {protocol} callback: token={token} src={source_ip}")
        return event

    def query(
        self,
        token: Optional[str] = None,
        protocol: Optional[str] = None,
        since: Optional[str] = None,
        limit: int = 200,
    ) -> list[dict]:
        with self._lock:
            events = list(self._events)

        if token:
            events = [e for e in events if e["token"] == token]
        if protocol:
            events = [e for e in events if e["protocol"] == protocol]
        if since:
            events = [e for e in events if e["ts"] >= since]

        return events[-limit:]

    def has_token(self, token: str) -> bool:
        with self._lock:
            return any(e["token"] == token for e in self._events)


store = OOBStore()

# ─── HTTP collector ───────────────────────────────────────────────────────────

app = FastAPI(title="VulnForge OOB Collector", docs_url="/docs")


@app.get("/health")
def health():
    return {"status": "ok", "service": "oob-collector"}


@app.get("/oob/{token}")
@app.post("/oob/{token}")
async def oob_callback(
    request: Request,
    token: str = FPath(..., min_length=1, max_length=200),
):
    """Receive an OOB HTTP callback from a blind vulnerability exploit."""
    client_ip = request.client.host if request.client else "unknown"
    body = ""
    try:
        body = (await request.body()).decode("utf-8", errors="replace")
    except Exception:
        pass

    event = store.record(
        protocol="http",
        token=token,
        source_ip=client_ip,
        raw=f"{request.method} {request.url} body={body[:200]}",
    )
    return {"received": True, "event_id": event["id"]}


@app.get("/oob/events")
def get_events(
    token: Optional[str] = None,
    protocol: Optional[str] = None,
    since: Optional[str] = None,
    limit: int = 200,
):
    """Query recorded OOB events."""
    return store.query(token=token, protocol=protocol, since=since, limit=limit)


@app.get("/oob/check/{token}")
def check_token(token: str = FPath(...)):
    """Return true if at least one callback was received for this token."""
    return {"token": token, "received": store.has_token(token)}


# ─── DNS collector ───────────────────────────────────────────────────────────

OOB_DOMAIN = "oob.lab.local"
# Token is the leftmost label(s): <token>.oob.lab.local
TOKEN_RE = re.compile(r'^([a-zA-Z0-9_-]+)\..*$')

DNS_RESPONSE_IP = "127.0.0.1"


class OOBDNSHandler:
    """Simple UDP DNS server that records queries and returns a loopback A record."""

    def __init__(self, host: str = "0.0.0.0", port: int = 5353):
        self.host = host
        self.port = port
        self._sock: Optional[socket.socket] = None
        self._running = False

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._running = True
        logger.info(f"DNS OOB collector listening on UDP {self.host}:{self.port}")
        while self._running:
            try:
                data, addr = self._sock.recvfrom(512)
                self._handle(data, addr)
            except OSError:
                break

    def stop(self):
        self._running = False
        if self._sock:
            self._sock.close()

    def _handle(self, data: bytes, addr: tuple):
        try:
            request = DNSRecord.parse(data)
        except Exception as e:
            logger.warning(f"DNS parse error from {addr}: {e}")
            return

        for question in request.questions:
            qname = str(question.qname).rstrip(".")
            if OOB_DOMAIN not in qname:
                continue

            # Extract token from subdomain
            # Format: <token>.oob.lab.local
            sub = qname[: -len(OOB_DOMAIN) - 1]  # strip ".oob.lab.local"
            m = TOKEN_RE.match(sub)
            token = m.group(1) if m else sub

            store.record(
                protocol="dns",
                token=token,
                source_ip=addr[0],
                raw=f"QTYPE={QTYPE[question.qtype]} NAME={qname}",
            )

            # Send a valid DNS response
            reply = request.reply()
            reply.add_answer(
                RR(
                    rname=question.qname,
                    rtype=QTYPE.A,
                    rdata=A(DNS_RESPONSE_IP),
                    ttl=1,
                )
            )
            try:
                self._sock.sendto(reply.pack(), addr)
            except Exception as e:
                logger.warning(f"DNS reply error: {e}")


def run_dns_server():
    handler = OOBDNSHandler()
    try:
        handler.start()
    except PermissionError:
        logger.error(
            "Cannot bind DNS on port 5353 (permission denied). "
            "Run as root or use port > 1024."
        )


# ─── Entry point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Start DNS server in a background thread
    dns_thread = threading.Thread(target=run_dns_server, daemon=True)
    dns_thread.start()

    # Start HTTP server
    uvicorn.run(app, host="0.0.0.0", port=9000, log_level="info")
