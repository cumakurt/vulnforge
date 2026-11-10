"""Scanner output adapters.

Every adapter returns a list of findings in the internal shape:

    {
        "url": "/php/sqli/products.php",
        "method": "GET",
        "parameter": "id",
        "cwe": "CWE-89" | None,
        "type": "sqli" | None,
        "evidence": "..."
    }

Adapters must not raise on malformed individual entries; they should skip them
and keep the rest of the report usable.
"""

from . import custom_json, nuclei, sarif, zap

ADAPTERS = {
    "custom_json": custom_json.load,
    "sarif": sarif.load,
    "zap": zap.load,
    "nuclei": nuclei.load,
}


def load(adapter: str, path: str) -> list[dict]:
    if adapter not in ADAPTERS:
        raise ValueError(f"unknown adapter '{adapter}'. Available: {sorted(ADAPTERS)}")
    return ADAPTERS[adapter](path)
