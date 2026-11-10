"""
Загрузка нативного кода (ctypes).

Находка, если данные фаззера выбирают, КАКУЮ библиотеку загрузить
(dlopen) или КАКУЮ функцию получить (dlsym): это произвольный нативный код.

dlopen: метка сохраняется в audit event `ctypes.dlopen`.
dlsym: в audit event имя приходит как новая str без метки, поэтому
защищён CDLL.__getitem__ (через него идут и lib.name, и lib["name"]).

Правило: tainted с первого символа (пользователь выбирает всё имя) или
компонент `..` в tainted-части. `"lib" + variant + ".so"` без `..`
находкой не считается.
"""

from __future__ import annotations

import ctypes
import os
import re

from typing import Any

from .core import SanitizerIssue, guard_function, on_audit, report
from .taint import clean_prefix_of, contains_taint, untaint


class NativeCodeLoading(SanitizerIssue):
    pass


_SEPARATORS = re.compile(r"[\\/]+")


def find_native_issue(name: Any) -> str | None:

    if not contains_taint(name) or not isinstance(name, (str, bytes)):
        return None

    prefix = clean_prefix_of(name) if isinstance(name, str) else 0

    if prefix == 0:
        return "tainted data selects the whole library/symbol name"

    text = os.fsdecode(untaint(name))

    if ".." in _SEPARATORS.split(text[max(prefix - 1, 0):]):
        return "tainted library path contains '..' component"

    return None


def _on_dlopen(args: tuple) -> None:

    reason = find_native_issue(args[0])

    if reason:
        report(NativeCodeLoading, "ctypes.dlopen", reason)


def install() -> None:

    on_audit("ctypes.dlopen", _on_dlopen)

    guard_function(
        ctypes.CDLL, "__getitem__", NativeCodeLoading, find_native_issue,
        argpos=1, sink="ctypes.dlsym"
    )
