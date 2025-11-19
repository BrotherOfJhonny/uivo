from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Callable, Optional
from functools import wraps
import threading

_LOCK = threading.Lock()


class DiskCache:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self._write_raw({})

    def _read_raw(self) -> dict:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
        except Exception:
            pass
        return {}

    def _write_raw(self, data: dict) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self.path)

    def get(self, key: str) -> Optional[Any]:
        with _LOCK:
            data = self._read_raw()
            return data.get(key)

    def set(self, key: str, value: Any) -> None:
        with _LOCK:
            data = self._read_raw()
            data[key] = value
            self._write_raw(data)


def cacheable(cache: DiskCache, key_builder: Callable[..., str]):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            key = key_builder(*args, **kwargs)
            cached = cache.get(key)
            if cached is not None:
                return cached
            result = fn(*args, **kwargs)
            cache.set(key, result)
            return result
        return wrapper
    return decorator
