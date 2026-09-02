"""Plugin auto-discovery.

Any module in this package that defines a BasePlugin subclass is registered by
its `slug`. To add a tool, drop a new file here — no wiring required.
"""
from __future__ import annotations

import importlib
import inspect
import pkgutil

from .base import BasePlugin

_registry: dict[str, BasePlugin] = {}


def _discover() -> None:
    package = __name__
    for _finder, module_name, _ispkg in pkgutil.iter_modules(__path__):
        if module_name == "base":
            continue
        module = importlib.import_module(f"{package}.{module_name}")
        for _name, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, BasePlugin) and obj is not BasePlugin:
                instance = obj()
                if instance.slug:
                    _registry[instance.slug] = instance


def get(slug: str) -> BasePlugin | None:
    return _registry.get(slug)


def all_plugins() -> list[BasePlugin]:
    return list(_registry.values())


def catalogue() -> list[dict]:
    return [p.describe() for p in _registry.values()]


_discover()
