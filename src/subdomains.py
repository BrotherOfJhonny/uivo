import requests
import socket
from concurrent.futures import ThreadPoolExecutor


def enum_crtsh(domain: str, timeout: float = 15.0) -> list[str]:
    url = "https://crt.sh/?q={d}&output=json".format(d=domain)
    subs = set()

    try:
        r = requests.get(url, timeout=timeout)
        if r.status_code != 200:
            return []
        try:
            data = r.json()
        except Exception:
            return []
        for item in data:
            name = item.get("name_value", "")
            for s in name.split("\n"):
                s = s.strip().lower()
                if s.endswith(domain) and s:
                    subs.add(s)
    except Exception:
        return sorted(subs)

    return sorted(subs)


def _dns_resolve(host: str) -> str | None:
    try:
        socket.gethostbyname(host)
        return host
    except Exception:
        return None


def brute_force_subdomains(domain: str, wordlist: str | None = None, threads: int = 10) -> list[str]:
    subs = []
    wl = []

    if wordlist:
        try:
            with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
                wl = [line.strip() for line in f if line.strip()]
        except Exception:
            wl = []

    if not wl:
        wl = ["www", "mail", "api", "dev", "stage", "vpn", "test", "admin"]

    def worker(prefix: str):
        fqdn = ("%s.%s" % (prefix, domain)).lower()
        if _dns_resolve(fqdn):
            subs.append(fqdn)

    with ThreadPoolExecutor(max_workers=threads) as executor:
        executor.map(worker, wl)

    return sorted(set(subs))
