from __future__ import annotations

from .plugins import UivoPlugin, register_plugin
from .context import ReconContext

from src.ssl_information import get_ssl_information


@register_plugin
class SSLPlugin(UivoPlugin):
    slug = "ssl"
    name = "SSL/TLS"
    description = "Gets basic TLS certificate information."
    order = 20

    @classmethod
    def register_arguments(cls, parser) -> None:
        parser.add_argument(
            "--ssl-port",
            type=int,
            default=443,
            help="TLS port (default: 443)",
        )
        parser.add_argument(
            "--ssl-timeout",
            type=float,
            default=5.0,
            help="TLS connection timeout (seconds)",
        )

    def should_run(self, args) -> bool:
        return getattr(args, "all", False) or getattr(args, "ssl", False) or bool(getattr(args, "modules", None))

    def run(self, ctx: ReconContext, args) -> dict:
        port = getattr(args, "ssl_port", 443)
        timeout = getattr(args, "ssl_timeout", 5.0)

        print("[*] Collecting SSL/TLS information ...")
        ssl_info = get_ssl_information(ctx.domain, port=port, timeout=timeout)
        ctx.results["ssl"] = ssl_info
        return {"ssl": ssl_info}
