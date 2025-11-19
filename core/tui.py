from __future__ import annotations
from typing import List, Type
from .plugins import UivoPlugin


def tui_select_plugins(plugin_classes: List[Type[UivoPlugin]]) -> List[str]:
    print("\n===== UIVO TUI - Module Selection =====\n")
    for idx, cls in enumerate(plugin_classes, start=1):
        print("[{num:02}] {slug:<12} - {name}".format(num=idx, slug=cls.slug, name=cls.name))
    print("\nEnter numbers separated by comma (ex: 1,3,5)")
    print("Or just press ENTER to run ALL.\n")

    choice = input("Your choice: ").strip()
    if not choice:
        return [cls.slug for cls in plugin_classes]

    selected = []
    for part in choice.split(","):
        part = part.strip()
        if not part.isdigit():
            continue
        idx = int(part) - 1
        if 0 <= idx < len(plugin_classes):
            selected.append(plugin_classes[idx].slug)

    if not selected:
        return [cls.slug for cls in plugin_classes]
    return selected
