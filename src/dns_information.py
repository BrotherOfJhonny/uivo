from __future__ import annotations

from typing import Dict, Any, List
from datetime import datetime

import dns.resolver
import dns.exception
import whois


def _query_record(domain: str, rtype: str, timeout: float = 3.0) -> List[str]:
    records = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    try:
        answers = resolver.resolve(domain, rtype)
        for rdata in answers:
            records.append(rdata.to_text())
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout,
            dns.resolver.NoNameservers, dns.exception.DNSException):
        pass

    return records


def get_dns_information(domain: str, timeout: float = 3.0) -> Dict[str, Any]:
    data: Dict[str, Any] = {}

    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
        data[rtype] = _query_record(domain, rtype, timeout=timeout)

    spf_record = None
    for txt in data.get("TXT", []):
        if "v=spf1" in txt.lower():
            spf_record = txt
            break

    dmarc_record = None
    dmarc_txt = _query_record("_dmarc." + domain, "TXT", timeout=timeout)
    for txt in dmarc_txt:
        if "v=dmarc1" in txt.lower():
            dmarc_record = txt
            break

    data["SPF"] = spf_record
    data["DMARC"] = dmarc_record
    return data


def _normalize_whois_value(value):
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (list, tuple)):
        return [_normalize_whois_value(v) for v in value]
    return value


def get_whois_information(domain: str) -> Dict[str, Any]:
    try:
        w = whois.whois(domain)
    except Exception:
        return {"error": "whois_lookup_failed"}

    raw = dict(w)
    data: Dict[str, Any] = {}
    for k, v in raw.items():
        data[str(k)] = _normalize_whois_value(v)
    return data
