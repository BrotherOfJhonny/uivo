from __future__ import annotations

import ssl
import socket
from datetime import datetime
from typing import Dict, Any, List, Optional


def _get_certificate(hostname: str, port: int = 443, timeout: float = 5.0) -> Optional[dict]:
    context = ssl.create_default_context()
    conn = context.wrap_socket(
        socket.socket(socket.AF_INET),
        server_hostname=hostname,
    )
    conn.settimeout(timeout)

    try:
        conn.connect((hostname, port))
        cert = conn.getpeercert()
    except Exception:
        cert = None
    finally:
        try:
            conn.close()
        except Exception:
            pass

    return cert


def _parse_date(value: str) -> Optional[str]:
    if not value:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%Y%m%d%H%M%SZ"):
        try:
            dt = datetime.strptime(value, fmt)
            return dt.isoformat()
        except Exception:
            continue
    return value


def get_ssl_information(domain: str, port: int = 443, timeout: float = 5.0) -> Dict[str, Any]:
    cert = _get_certificate(domain, port=port, timeout=timeout)
    if cert is None:
        return {"error": "ssl_connection_failed", "valid": False}

    info: Dict[str, Any] = {}
    info["subject"] = {k: v for sub in cert.get("subject", []) for (k, v) in sub}
    info["issuer"] = {k: v for sub in cert.get("issuer", []) for (k, v) in sub}
    info["serial_number"] = cert.get("serialNumber")
    info["version"] = cert.get("version")
    info["not_before"] = _parse_date(cert.get("notBefore", ""))
    info["not_after"] = _parse_date(cert.get("notAfter", ""))

    san_entries: List[str] = []
    for typ, vals in cert.get("subjectAltName", []):
        if typ.lower() == "dns":
            san_entries.append(vals)
    info["san"] = san_entries

    try:
        if info["not_after"]:
            exp = datetime.fromisoformat(info["not_after"])
            info["valid"] = exp > datetime.utcnow()
        else:
            info["valid"] = False
    except Exception:
        info["valid"] = False

    return info
