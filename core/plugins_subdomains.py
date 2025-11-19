from __future__ import annotations
from pathlib import Path
from typing import List

from .plugins import UivoPlugin, register_plugin
from .context import ReconContext

from src.subdomains import enum_crtsh, brute_force_subdomains


@register_plugin
class SubdomainsPlugin(UivoPlugin):
    slug = "subdomains"
    name = "Subdomains"
    description = "crt.sh enumeration + optional brute force wordlist."
    order = 5

    def should_run(self, args) -> bool:
        if getattr(args, "all", False):
            return True
        if getattr(args, "subdomains", False):
            return True
        modules = getattr(args, "modules", "") or ""
        return "subdomains" in [m.strip() for m in modules.split(",") if m.strip()]

    def run(self, ctx: ReconContext, args) -> dict:
        subs: List[str] = []

        print("[*] Enumerating subdomains via crt.sh ...")
        subs_crt = enum_crtsh(ctx.domain)
        subs.extend(subs_crt)

        wordlist_path: Path | None = None
        wl_arg = getattr(args, "subs_wordlist", None)
        if wl_arg:
            p = Path(wl_arg).expanduser()
            if p.is_file():
                wordlist_path = p
            else:
                print("[!] Wordlist not found: %s (using internal list)." % p)

        threads = getattr(args, "subs_threads", ctx.threads)

        print("[*] Starting brute force of subdomains ...")
        subs_brute = brute_force_subdomains(
            ctx.domain,
            wordlist=str(wordlist_path) if wordlist_path else None,
            threads=threads,
        )

        for s in subs_brute:
            if s not in subs:
                subs.append(s)

        subs_sorted = sorted(subs)
        ctx.results["subdomains"] = subs_sorted

        print("[+] Total subdomains:", len(subs_sorted))
        return {"subdomains": subs_sorted}
