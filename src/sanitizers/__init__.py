"""
Taint-санитайзеры для Atheris.

В форке Atheris этот пакет доступен как `atheris.sanitizers` и
включается автоматически при `import atheris` (см. atheris_glue.py).

Выбор санитайзеров — переменная окружения ATHERIS_SANITIZERS:

    (не задана) / all   — все
    none                — выключить
    command,path,sql    — только перечисленные
"""

from __future__ import annotations

import os

from collections.abc import Iterable

from . import command, deserialization, models, path, sql, ssrf, code_injection
from .core import STATS, SanitizerIssue, guard_function, reset, set_stream
from .taint import (
    contains_taint,
    is_tainted,
    mark_tainted,
    propagate_taint,
    taint_sources,
    untaint,
)

ENV_VAR = "ATHERIS_SANITIZERS"

SANITIZERS = {
    "command": command.install,
    "path": path.install,
    "sql": sql.install,
    "deserialization": deserialization.install,
    "ssrf": ssrf.install,
    "code": code_injection.install,
}

_installed: list[str] = []


def parse_selection(value: str | None) -> list[str]:

    value = (value or "all").strip().lower()

    if value == "all":
        return list(SANITIZERS)

    if value in ("none", "0", "off", ""):
        return []

    names = [name.strip() for name in value.split(",") if name.strip()]

    unknown = [name for name in names if name not in SANITIZERS]

    if unknown:
        raise ValueError(
            f"Unknown sanitizers: {unknown}; available: {sorted(SANITIZERS)}"
        )

    return names


def install(names: Iterable[str] | None = None) -> list[str]:
    """
    Устанавливает санитайзеры (повторный вызов ничего не делает).
    names=None — берём из ATHERIS_SANITIZERS.
    Возвращает список включённых санитайзеров.
    """

    if _installed:
        return list(_installed)

    selected = (
        parse_selection(os.environ.get(ENV_VAR))
        if names is None
        else parse_selection(",".join(names) or "none")
    )

    if not selected:
        return []

    models.install()

    for name in selected:
        SANITIZERS[name]()

    _installed.extend(selected)

    return list(_installed)


def uninstall() -> None:
    """Откатывает патчи и обработчики (для тестов и отладки)."""

    reset()
    _installed.clear()


def installed() -> list[str]:
    return list(_installed)
