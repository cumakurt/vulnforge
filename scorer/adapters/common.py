"""Shared helpers for scanner adapters."""

from urllib.parse import urlsplit


def normalize_cwe(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        value = value[0] if value else None
    if not value:
        return None
    text = str(value).strip().upper()
    if text.startswith("CWE-"):
        digits = text[4:]
    else:
        digits = text
    if not digits.isdigit():
        return None
    return f"CWE-{int(digits)}"


def path_only(url: str) -> str:
    """Drop scheme/host but keep path and query."""
    if not url:
        return "/"
    parts = urlsplit(url)
    path = parts.path or "/"
    if parts.query:
        return f"{path}?{parts.query}"
    return path


def make_finding(url, method="GET", parameter="", cwe=None, vtype=None, evidence="") -> dict:
    return {
        "url": path_only(str(url)),
        "method": str(method or "GET").upper(),
        "parameter": str(parameter or ""),
        "cwe": normalize_cwe(cwe),
        "type": str(vtype).lower() if vtype else None,
        "evidence": str(evidence or ""),
    }
