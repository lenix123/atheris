"""
Небезопасная десериализация.

Находка, если данные фаззера переданы в десериализатор, способный
создавать произвольные объекты / вызывать код:

    pickle.loads, marshal.loads, dill.loads, cloudpickle.loads,
    jsonpickle.decode, yaml.unsafe_load, yaml.load с небезопасным Loader.

Критерий — taint на входе, а не факт вызова опасной функции внутри
pickle: сильнее (находится сразу), но шумнее. pickle.load(file) не
проверяется: содержимое файла не несёт метку.
"""

from __future__ import annotations

import importlib
import importlib.util

from functools import wraps
from typing import Any

from .core import SanitizerIssue, guard_function, patch, report, tainted_check
from .taint import contains_taint


class UnsafeDeserialization(SanitizerIssue):
    pass


# (модуль, функция, позиция данных, имя параметра)
_SINKS = (
    ("pickle", "loads", 0, "data"),
    ("_pickle", "loads", 0, "data"),
    ("marshal", "loads", 0, "bytes"),
    ("dill", "loads", 0, "str"),
    ("cloudpickle", "loads", 0, "str"),
    ("jsonpickle", "decode", 0, "string"),
)


def _import_optional(name: str):

    if importlib.util.find_spec(name) is None:
        return None

    try:
        return importlib.import_module(name)

    except ImportError:
        return None


def _install_yaml() -> None:

    yaml = _import_optional("yaml")

    if yaml is None:
        return

    safe_loaders = tuple(
        getattr(yaml, name)
        for name in ("SafeLoader", "CSafeLoader", "BaseLoader")
        if hasattr(yaml, name)
    )

    reason = "tainted data passed to an unsafe YAML loader"

    if hasattr(yaml, "unsafe_load"):
        guard_function(
            yaml, "unsafe_load", UnsafeDeserialization,
            tainted_check(reason), kwname="stream"
        )

    for name in ("load", "load_all"):

        original = getattr(yaml, name, None)

        if original is None:
            continue

        def make(original, name):

            @wraps(original)
            def wrapper(stream, *args, **kwargs):

                loader = kwargs.get("Loader", args[0] if args else None)

                if contains_taint(stream) and not (
                    isinstance(loader, type)
                    and issubclass(loader, safe_loaders)
                ):
                    report(UnsafeDeserialization, f"yaml.{name}", reason)

                return original(stream, *args, **kwargs)

            return wrapper

        patch(yaml, name, make(original, name))


def install() -> None:

    for module_name, function, argpos, kwname in _SINKS:

        module = _import_optional(module_name)

        if module is None or not hasattr(module, function):
            continue

        guard_function(
            module, function, UnsafeDeserialization,
            tainted_check("tainted data passed to an unsafe deserializer"),
            argpos=argpos, kwname=kwname
        )

    _install_yaml()
