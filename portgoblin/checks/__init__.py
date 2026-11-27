"""Follow-up checks. Each module here holds one check group; see base.py."""

from __future__ import annotations

import importlib
import inspect
import pkgutil

from portgoblin.checks.base import BaseCheck, DirectCheck, ScriptCheck

_SKIP = {"base"}


def load_checks() -> list[BaseCheck]:
    """Instantiate every check class defined in this package, in module then class order."""
    checks: list[BaseCheck] = []
    for info in sorted(pkgutil.iter_modules(__path__), key=lambda i: i.name):
        if info.name in _SKIP or info.name.startswith("_"):
            continue
        module = importlib.import_module(f"{__name__}.{info.name}")
        classes = [
            obj
            for _, obj in inspect.getmembers(module, inspect.isclass)
            if issubclass(obj, (ScriptCheck, DirectCheck))
            and obj not in (ScriptCheck, DirectCheck)
            and obj.__module__ == module.__name__
            and not inspect.isabstract(obj)
            and getattr(obj, "check_id", None)
        ]
        classes.sort(key=lambda c: inspect.getsourcelines(c)[1])
        checks.extend(cls() for cls in classes)
    return checks
