from __future__ import annotations

from .plugins import UivoPlugin, register_plugin
from .context import ReconContext

from src.dns_information import get_dns_information, get_whois_information


@register_plugin
class DNSPlugin(UivoPlugin):
    slug = "dns"
    name = "DNS & WHOIS"
    description = "Collects DNS records and WHOIS."
    order = 10

    @classmethod
    def register_arguments(cls, parser) -> None:
        parser.add_argument(
            "--dns-timeout",
            type=float,
            default=3.0,
            help="Timeout (seconds) for DNS/WHOIS lookups",
        )

    def should_run(self, args) -> bool:
        return getattr(args, "all", False) or getattr(args, "dns", False) or bool(getattr(args, "modules", None))

    def run(self, ctx: ReconContext, args) -> dict:
        timeout = getattr(args, "dns_timeout", 3.0)
        print("[*] Gathering DNS information ...")
        dns_info = get_dns_information(ctx.domain, timeout=timeout)
        print("[*] Running WHOIS ...")
        whois_info = get_whois_information(ctx.domain)

        ctx.results["dns"] = dns_info
        ctx.results["whois"] = whois_info
        return {"dns": dns_info, "whois": whois_info}
