from __future__ import annotations
import requests

from .plugins import UivoPlugin, register_plugin
from .context import ReconContext


@register_plugin
class HTTPPlugin(UivoPlugin):
    slug = "http"
    name = "HTTP Headers"
    description = "Collects basic HTTP response headers."
    order = 30

    def should_run(self, args) -> bool:
        return getattr(args, "all", False) or getattr(args, "http", False) or bool(getattr(args, "modules", None))

    def run(self, ctx: ReconContext, args) -> dict:
        url = "http://" + ctx.domain
        info = {"url": url, "headers": {}, "status": None}
        print("[*] Requesting", url, "...")
        try:
            r = requests.get(url, timeout=5)
            info["status"] = r.status_code
            info["headers"] = dict(r.headers)
        except Exception as e:
            info["error"] = str(e)

        ctx.results["http"] = info
        return {"http": info}
