"""
Taint-типы и распространение taint-меток.

Модель данных
-------------
Метку (множество источников) несут только скалярные типы:
TaintedStr, TaintedBytes, TaintedInt, TaintedFloat.

Контейнеры (list, tuple, dict, set) остаются обычными: taint "живёт"
в их элементах, а contains_taint() / taint_sources() обходят контейнеры
рекурсивно. Благодаря этому не ломается семантика изменяемых объектов
(идентичность, мутации), а код сокращается в разы.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from functools import wraps
from typing import Any

DEFAULT_SOURCE = "unknown"

_FULL_SLICE = slice(None)


# ============================================================
# 1. Tainted-типы
# ============================================================

class Tainted:
    """Миксин: хранит множество источников в __taint_sources__."""

    __taint_sources__: frozenset[str] = frozenset()

    def __new__(cls, *args, sources: Iterable[str] = (DEFAULT_SOURCE,)):
        obj = super().__new__(cls, *args)
        obj.__taint_sources__ = frozenset(sources)
        return obj


class TaintedStr(Tainted, str):
    pass


class TaintedBytes(Tainted, bytes):
    pass


class TaintedInt(Tainted, int):
    pass


class TaintedFloat(Tainted, float):
    pass


# bool идёт отдельно (его нельзя наследовать), int — после bool.
_TAINTED_BY_BASE = (
    (str, TaintedStr),
    (bytes, TaintedBytes),
    (float, TaintedFloat),
    (int, TaintedInt),
)

# Получение "чистой" копии значения без taint-типа.
# Вызываем методы базовых типов напрямую, мимо наших обёрток.
_PLAIN_COPY = {
    str: lambda v: str.__getitem__(v, _FULL_SLICE),
    bytes: lambda v: bytes.__getitem__(v, _FULL_SLICE),
    float: float.__pos__,
    int: int.__pos__,
}


# ============================================================
# 2. Обход значений и запросы
# ============================================================

def _walk(value: Any, _seen: set[int] | None = None) -> Iterator[Tainted]:
    """Выдаёт все tainted-объекты, достижимые из value."""

    if isinstance(value, Tainted):
        yield value
        return

    if isinstance(value, (str, bytes, int, float)):
        return

    if _seen is None:
        _seen = set()

    if id(value) in _seen:
        return

    _seen.add(id(value))

    if isinstance(value, Mapping):
        for key, item in value.items():
            yield from _walk(key, _seen)
            yield from _walk(item, _seen)

    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            yield from _walk(item, _seen)


def is_tainted(value: Any) -> bool:
    """Несёт ли сам объект taint-метку."""

    return isinstance(value, Tainted)


def contains_taint(value: Any) -> bool:
    """
    Содержит ли объект (или вложенные объекты) tainted-данные.

    Основная функция для санитайзеров.
    """

    return next(_walk(value), None) is not None


def taint_sources(value: Any) -> frozenset[str]:
    """Все источники taint, связанные с объектом."""

    sources: set[str] = set()

    for item in _walk(value):
        sources |= item.__taint_sources__

    return frozenset(sources)


# ============================================================
# 3. Пометка и распространение
# ============================================================

def _mark_scalar(value: Any, sources: frozenset[str]) -> Any:

    existing = (
        value.__taint_sources__
        if isinstance(value, Tainted)
        else frozenset()
    )

    merged = existing | sources

    # Уже помечено теми же источниками: объект не трогаем.
    if isinstance(value, Tainted) and merged == existing:
        return value

    for base, tainted_type in _TAINTED_BY_BASE:

        if isinstance(value, base):
            return tainted_type(
                _PLAIN_COPY[base](value),
                sources=merged
            )

    return value


def _mark(value: Any, sources: frozenset[str]) -> Any:
    """Помечает результат операции. Неизвестные типы возвращает как есть."""

    if not sources or isinstance(value, bool):
        return value

    if isinstance(value, (str, bytes, int, float)):
        return _mark_scalar(value, sources)

    if type(value) is list:
        return [_mark(item, sources) for item in value]

    if type(value) is tuple:
        return tuple(_mark(item, sources) for item in value)

    if isinstance(value, Iterator):
        return (_mark(item, sources) for item in value)

    return value


def propagate_taint(value: Any, *origins: Any) -> Any:
    """Переносит метки из origins на только что созданный результат."""

    return _mark(value, taint_sources(origins))


def mark_tainted(value: Any, source: str = "atheris") -> Any:
    """Помечает входное значение фаззера (str, bytes, int, float, list, tuple)."""

    if not isinstance(source, str) or not source:
        raise ValueError("source must be a non-empty string")

    supported = (str, bytes, int, float, list, tuple)

    if not isinstance(value, supported) or isinstance(value, bool):
        raise TypeError(
            f"Unsupported taint source type: {type(value).__name__}"
        )

    return _mark(value, frozenset({source}))


def untaint(value: Any) -> Any:
    """
    Снимает метку ("declassification").

    Нужна для функций-очистителей (например, shlex.quote), результат
    которых безопасно передавать в sink.
    """

    for base, _ in _TAINTED_BY_BASE:
        if isinstance(value, base) and not isinstance(value, bool):
            return _PLAIN_COPY[base](value)

    if type(value) is list:
        return [untaint(item) for item in value]

    if type(value) is tuple:
        return tuple(untaint(item) for item in value)

    return value


# ============================================================
# 4. Автоматическое распространение через методы
# ============================================================

# Публичные методы str/bytes, возвращающие данные (не bool и не индексы).
TEXT_METHODS = frozenset({
    "capitalize", "casefold", "center", "decode", "encode", "expandtabs",
    "format", "format_map", "hex", "join", "ljust", "lower", "lstrip",
    "partition", "removeprefix", "removesuffix", "replace", "rjust",
    "rpartition", "rsplit", "rstrip", "split", "splitlines", "strip",
    "swapcase", "title", "translate", "upper", "zfill",
})

_TEXT_DUNDERS = (
    "__add__", "__mul__", "__rmul__", "__mod__", "__rmod__",
    "__getitem__", "__iter__", "__format__", "__str__", "__repr__",
)

_NUMBER_DUNDERS = tuple(
    f"__{prefix}{op}__"
    for op in (
        "add", "sub", "mul", "truediv", "floordiv", "mod", "divmod",
        "pow", "lshift", "rshift", "and", "or", "xor",
    )
    for prefix in ("", "r")
) + ("__neg__", "__pos__", "__abs__", "__invert__")


def _propagating(method):

    @wraps(method)
    def wrapper(self, *args, **kwargs):
        return propagate_taint(
            method(self, *args, **kwargs),
            self,
            args,
            kwargs
        )

    return wrapper


def _install(tainted_type: type, base: type, names: Iterable[str]) -> None:

    for name in names:

        method = getattr(base, name, None)

        if method is not None:
            setattr(tainted_type, name, _propagating(method))


def _make_radd(base: type):
    """`"prefix" + tainted` — str не знает про taint, нужен __radd__."""

    def __radd__(self, other):

        if not isinstance(other, base):
            return NotImplemented

        return propagate_taint(base.__add__(other, self), other, self)

    return __radd__


for _tainted, _base in ((TaintedStr, str), (TaintedBytes, bytes)):
    _install(_tainted, _base, TEXT_METHODS | set(_TEXT_DUNDERS))
    _tainted.__radd__ = _make_radd(_base)

for _tainted, _base in ((TaintedInt, int), (TaintedFloat, float)):
    _install(_tainted, _base, _NUMBER_DUNDERS)

del _tainted, _base
