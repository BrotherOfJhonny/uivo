from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Dict, List, Type

from .context import ReconContext


class UivoPlugin(ABC):
    slug: str = "base"
    name: str = "Base Plugin"
    description: str = ""
    order: int = 100

    @classmethod
    def register_arguments(cls, parser) -> None:
        return

    @abstractmethod
    def should_run(self, args) -> bool:
        raise NotImplementedError

    @abstractmethod
    def run(self, ctx: ReconContext, args) -> dict | None:
        raise NotImplementedError


_PLUGIN_REGISTRY: Dict[str, Type[UivoPlugin]] = {}


def register_plugin(plugin_cls: Type[UivoPlugin]) -> Type[UivoPlugin]:
    _PLUGIN_REGISTRY[plugin_cls.slug] = plugin_cls
    return plugin_cls


def get_all_plugins() -> List[Type[UivoPlugin]]:
    return sorted(_PLUGIN_REGISTRY.values(), key=lambda c: c.order)


def get_plugin_by_slug(slug: str) -> Type[UivoPlugin] | None:
    return _PLUGIN_REGISTRY.get(slug)
