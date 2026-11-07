"""
Общая инфраструктура санитайзеров.

* SanitizerIssue — базовое исключение находки; Atheris трактует
  необработанное исключение как crash и сохраняет входной файл.
* Один общий audit hook: Python не умеет удалять hooks, поэтому
  санитайзеры регистрируют обработчики событий, а не свои hooks.
* patch() / guard_function() — установка обёрток вокруг sink'ов с
  возможностью полностью откатить (для тестов и отладки).
"""

from __future__ import annotations

import sys

from collections import Counter, defaultdict
from functools import wraps
from threading import Lock
from typing import Any, Callable, TextIO

from .taint import contains_taint


class SanitizerIssue(RuntimeError):
    """Базовый класс находки санитайзера."""


STATS: Counter[str] = Counter()

_stream: TextIO | None = None
_lock = Lock()


def set_stream(stream: TextIO | None) -> None:
    """Куда печатать сообщения о находках (по умолчанию sys.stderr)."""

    global _stream
    _stream = stream


def report(issue: type[SanitizerIssue], sink: str, reason: str) -> None:
    """Фиксирует находку и бросает исключение."""

    with _lock:
        STATS[issue.__name__] += 1

    message = f"{reason} (sink: {sink})"

    # Содержимое данных намеренно не печатаем.
    print(
        f"[SANITIZER] {issue.__name__}: {message}",
        file=_stream or sys.stderr,
        flush=True
    )

    raise issue(message)


# ============================================================
# Audit events
# ============================================================

_audit_handlers: dict[str, list[Callable[[tuple], None]]] = defaultdict(list)
_hook_installed = False


def _audit_hook(event: str, args: tuple) -> None:

    handlers = _audit_handlers.get(event)

    if handlers:
        for handler in tuple(handlers):
            handler(args)


def on_audit(event: str, handler: Callable[[tuple], None]) -> None:

    global _hook_installed

    _audit_handlers[event].append(handler)

    if not _hook_installed:
        sys.addaudithook(_audit_hook)
        _hook_installed = True


# ============================================================
# Патчинг
# ============================================================

_patches: list[tuple[Any, str, Any]] = []


def patch(owner: Any, name: str, replacement: Any) -> None:

    _patches.append((owner, name, getattr(owner, name)))

    setattr(owner, name, replacement)


def reset() -> None:
    """Откатывает все патчи и обработчики (audit hook остаётся, но пуст)."""

    for owner, name, original in reversed(_patches):
        setattr(owner, name, original)

    _patches.clear()
    _audit_handlers.clear()


_MISSING = object()


def tainted_check(reason: str) -> Callable[[Any], str | None]:
    """Проверка по умолчанию: любой taint в аргументе — находка."""

    return lambda value: reason if contains_taint(value) else None


def guard_function(
    owner: Any,
    name: str,
    issue: type[SanitizerIssue],
    check: Callable[[Any], str | None],
    *,
    argpos: int = 0,
    kwname: str | None = None,
    sink: str | None = None
) -> None:
    """
    Оборачивает owner.name: перед вызовом проверяет один аргумент.

    argpos — индекс среди позиционных аргументов (для методов self = 0);
    kwname — имя того же аргумента при передаче по ключу;
    check(value) -> причина | None.
    """

    original = getattr(owner, name)

    label = sink or f"{getattr(owner, '__name__', owner)}.{name}"

    @wraps(original)
    def wrapper(*args, **kwargs):

        value = _MISSING

        if kwname is not None and kwname in kwargs:
            value = kwargs[kwname]

        elif len(args) > argpos:
            value = args[argpos]

        if value is not _MISSING:

            reason = check(value)

            if reason:
                report(issue, label, reason)

        return original(*args, **kwargs)

    patch(owner, name, wrapper)
