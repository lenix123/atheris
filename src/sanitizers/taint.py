"""
Taint-типы и распространение taint-меток.

Модель данных
-------------
Метку (множество источников) несут скалярные типы:
TaintedStr, TaintedBytes, TaintedInt, TaintedFloat.
Контейнеры остаются обычными: taint "живёт" в элементах, а
contains_taint() / taint_sources() обходят контейнеры рекурсивно.

clean_prefix
------------
Для TaintedStr дополнительно хранится `__clean_prefix__`: сколько ПЕРВЫХ
символов заведомо не получены от фаззера. Всё, что правее, считается
потенциально tainted.

    "https://api.example.com/?q=" + user   ->  clean_prefix == 27

Это даёт санитайзерам нужную точность (например, SSRF: контролирует ли
пользователь хост или только query) без полноценного посимвольного
отслеживания. Операции, для которых префикс не вычисляется, безопасно
сбрасывают его в 0 ("tainted с первого символа").
"""

from __future__ import annotations

import operator
from collections.abc import Iterable, Iterator, Mapping
from functools import wraps
from typing import Any

DEFAULT_SOURCE = "unknown"

_FULL_SLICE = slice(None)


# ============================================================
# 1. Tainted-типы
# ============================================================

class Tainted:
    """Миксин: источники и clean_prefix."""

    __taint_sources__: frozenset[str] = frozenset()
    __clean_prefix__: int = 0

    def __new__(
        cls,
        *args,
        sources: Iterable[str] = (DEFAULT_SOURCE,),
        clean_prefix: int = 0
    ):
        obj = super().__new__(cls, *args)
        obj.__taint_sources__ = frozenset(sources)
        obj.__clean_prefix__ = clean_prefix
        return obj


class TaintedStr(Tainted, str):
    pass


class TaintedBytes(Tainted, bytes):
    pass


class TaintedInt(Tainted, int):
    pass


class TaintedFloat(Tainted, float):
    pass


# bool нельзя наследовать; int проверяется после bool.
_TAINTED_BY_BASE = (
    (str, TaintedStr),
    (bytes, TaintedBytes),
    (float, TaintedFloat),
    (int, TaintedInt),
)

# "Чистая" копия значения — методами базовых типов, мимо наших обёрток.
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
    return isinstance(value, Tainted)


def contains_taint(value: Any) -> bool:
    """Есть ли tainted-данные в объекте или во вложенных объектах."""

    return next(_walk(value), None) is not None


def taint_sources(value: Any) -> frozenset[str]:

    sources: set[str] = set()

    for item in _walk(value):
        sources |= item.__taint_sources__

    return frozenset(sources)


def clean_prefix_of(value: str) -> int:
    """Длина заведомо чистого префикса (для обычной str — вся длина)."""

    if isinstance(value, Tainted):
        return value.__clean_prefix__

    return len(value)


# ============================================================
# 3. Пометка и распространение
# ============================================================

def make_tainted_str(text: str, sources: Iterable[str], prefix: int = 0) -> str:
    """
    Создаёт tainted-строку. Если весь текст лежит в чистом префиксе,
    возвращает обычную str: данных фаззера в нём нет.
    """

    plain = _PLAIN_COPY[str](text)

    if prefix >= len(plain):
        return plain

    return TaintedStr(plain, sources=sources, clean_prefix=max(prefix, 0))


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
            return tainted_type(_PLAIN_COPY[base](value), sources=merged)

    return value


def _mark(value: Any, sources: frozenset[str]) -> Any:
    """Помечает результат операции. Неизвестные типы возвращает как есть."""

    if not sources or isinstance(value, bool):
        return value

    if isinstance(value, (str, bytes, int, float)):
        return _mark_scalar(value, sources)

    kind = type(value)

    if kind is list:
        return [_mark(item, sources) for item in value]

    if kind is tuple:
        return tuple(_mark(item, sources) for item in value)

    if kind in (set, frozenset):
        return kind(_mark(item, sources) for item in value)

    if kind is dict:
        return {
            _mark(key, sources): _mark(item, sources)
            for key, item in value.items()
        }

    if isinstance(value, Iterator):
        return (_mark(item, sources) for item in value)

    return value


def propagate_taint(value: Any, *origins: Any) -> Any:
    """Переносит метки из origins на только что созданный результат."""

    return _mark(value, taint_sources(origins))


def mark_tainted(value: Any, source: str = "atheris") -> Any:
    """Помечает входное значение фаззера."""

    if not isinstance(source, str) or not source:
        raise ValueError("source must be a non-empty string")

    supported = (
        str, bytes, int, float, list, tuple, dict, set, frozenset
    )

    if not isinstance(value, supported) or isinstance(value, bool):
        raise TypeError(
            f"Unsupported taint source type: {type(value).__name__}"
        )

    return _mark(value, frozenset({source}))


def untaint(value: Any) -> Any:
    """
    Снимает метку ("declassification"). Нужна для функций-очистителей
    (shlex.quote, валидация по allowlist и т.п.).
    """

    for base, _ in _TAINTED_BY_BASE:
        if isinstance(value, base) and not isinstance(value, bool):
            return _PLAIN_COPY[base](value)

    kind = type(value)

    if kind in (list, tuple, set, frozenset):
        return kind(untaint(item) for item in value)

    if kind is dict:
        return {untaint(k): untaint(v) for k, v in value.items()}

    return value


# ============================================================
# 4. Распространение через методы str / bytes / int / float
# ============================================================

# Публичные методы, возвращающие данные (не bool и не индексы).
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

_CASE_METHODS = frozenset({
    "lower", "upper", "casefold", "swapcase", "title", "capitalize",
})


def _prefix_after(name: str, self: TaintedStr, result: str, args, kwargs) -> int:
    """Clean-префикс результата метода str (0, если неизвестно)."""

    if contains_taint((args, kwargs)):
        return 0

    prefix = self.__clean_prefix__

    if str.__eq__(result, self):           # метод ничего не изменил
        return prefix

    if name in ("rstrip", "removesuffix"):
        return prefix

    if name in ("lstrip", "removeprefix"):
        return max(0, prefix - (len(self) - len(result)))

    if name == "strip":
        removed = len(self) - len(str.lstrip(self, *args))
        return max(0, prefix - removed)

    if name in _CASE_METHODS and len(result) == len(self):
        return prefix

    return 0


def _propagating(method, name: str):

    @wraps(method)
    def wrapper(self, *args, **kwargs):

        result = method(self, *args, **kwargs)

        out = propagate_taint(result, self, args, kwargs)

        if (
            type(out) is TaintedStr
            and type(self) is TaintedStr
            and self.__clean_prefix__
        ):
            prefix = _prefix_after(name, self, result, args, kwargs)

            if prefix:
                out = make_tainted_str(
                    result, out.__taint_sources__, prefix
                )

        return out

    return wrapper


def _install(tainted_type: type, base: type, names: Iterable[str]) -> None:

    for name in names:

        method = getattr(base, name, None)

        if method is not None:
            setattr(tainted_type, name, _propagating(method, name))


# ---- Точные реализации для TaintedStr (с clean_prefix) --------

def _str_concat(left: str, right: str) -> str:

    result = str.__add__(left, right)

    sources = taint_sources((left, right))

    if not sources:
        return result

    left_prefix = clean_prefix_of(left)

    prefix = (
        left_prefix
        if left_prefix < len(left)
        else len(left) + clean_prefix_of(right)
    )

    return make_tainted_str(result, sources, prefix)


def _str_add(self, other):

    if not isinstance(other, str):
        return NotImplemented

    return _str_concat(self, other)


def _str_radd(self, other):

    if not isinstance(other, str):
        return NotImplemented

    return _str_concat(other, self)


def _str_getitem(self: TaintedStr, key):

    result = str.__getitem__(self, key)

    sources = self.__taint_sources__
    prefix = self.__clean_prefix__

    if isinstance(key, slice):

        if key.step in (None, 1):
            start = key.indices(len(self))[0]
            return make_tainted_str(result, sources, max(0, prefix - start))

        return make_tainted_str(result, sources, 0)

    index = operator.index(key)

    if index < 0:
        index += len(self)

    return make_tainted_str(result, sources, 1 if index < prefix else 0)


def _str_iter(self: TaintedStr):

    sources = self.__taint_sources__
    prefix = self.__clean_prefix__

    return (
        make_tainted_str(char, sources, 1 if index < prefix else 0)
        for index, char in enumerate(str.__iter__(self))
    )


def _bytes_radd(self, other):
    """`b"prefix" + tainted` — у bytes нет clean_prefix, метка полная."""

    if not isinstance(other, bytes):
        return NotImplemented

    return propagate_taint(bytes.__add__(other, self), other, self)


_install(TaintedStr, str, TEXT_METHODS | set(_TEXT_DUNDERS))
TaintedStr.__add__ = _str_add
TaintedStr.__radd__ = _str_radd
TaintedStr.__getitem__ = _str_getitem
TaintedStr.__iter__ = _str_iter

_install(TaintedBytes, bytes, TEXT_METHODS | set(_TEXT_DUNDERS))
TaintedBytes.__radd__ = _bytes_radd

_install(TaintedInt, int, _NUMBER_DUNDERS)
_install(TaintedFloat, float, _NUMBER_DUNDERS)
