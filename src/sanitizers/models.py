"""
"Модели" функций стандартной библиотеки.

Stdlib не инструментируется, а многие её функции собирают результат через
`"".join(...)`, regex или C-код — и метка теряется. Здесь для выбранных
функций результат помечается, если tainted был любой аргумент.

Не оборачиваем функции, которые уже корректно распространяют taint
через str-операции (например, urllib.parse.urlsplit): обёртка пометила бы
результат целиком и уничтожила бы информацию о clean_prefix.
"""

from __future__ import annotations

import base64
import binascii
import json
import os.path
import re
import urllib.parse

from functools import wraps
from typing import Any

from .core import patch
from .taint import (
    clean_prefix_of,
    make_tainted_str,
    propagate_taint,
    taint_sources,
    untaint,
)


def _propagating(function):

    @wraps(function)
    def wrapper(*args, **kwargs):
        return propagate_taint(function(*args, **kwargs), args, kwargs)

    return wrapper


def _model_path_join(function):
    """os.path.join: чистая часть первого аргумента сохраняется."""

    @wraps(function)
    def join(first, *rest):

        result = function(first, *rest)

        sources = taint_sources((first, rest))

        if not sources or not isinstance(result, str):
            return propagate_taint(result, first, rest)

        # Если результат начинается с first, этот префикс не изменился
        # (последующий абсолютный компонент вытеснил бы его).
        if isinstance(first, str) and str.startswith(untaint(result), untaint(first)):
            prefix = clean_prefix_of(first)
        else:
            prefix = 0

        return make_tainted_str(untaint(result), sources, prefix)

    return join


def _patch_functions(owner: Any, names: tuple[str, ...]) -> None:

    for name in names:

        function = getattr(owner, name, None)

        if function is not None:
            patch(owner, name, _propagating(function))


def install() -> None:

    _patch_functions(os.path, (
        "normpath", "abspath", "realpath", "relpath", "expanduser",
        "expandvars", "dirname", "basename", "split", "splitext",
        "normcase",
    ))

    patch(os.path, "join", _model_path_join(os.path.join))

    _patch_functions(urllib.parse, (
        "quote", "quote_plus", "unquote", "unquote_plus", "urljoin",
        "parse_qs", "parse_qsl",
    ))

    _patch_functions(base64, (
        "b64decode", "b64encode", "urlsafe_b64decode",
        "urlsafe_b64encode", "standard_b64decode", "standard_b64encode",
        "b32decode", "b32encode", "b16decode", "b16encode",
    ))

    _patch_functions(binascii, (
        "hexlify", "unhexlify", "a2b_base64", "b2a_base64",
    ))

    _patch_functions(json, ("loads",))

    # Результат подстановок/разбиения содержит данные из string и repl.
    # Не моделируются: re.match/search (Match-объекты) и методы
    # скомпилированных Pattern (C-тип, методы не подменить).
    _patch_functions(re, ("sub", "subn", "split", "findall"))