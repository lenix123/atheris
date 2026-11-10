"""
Подмена переменных окружения.

Находка, если данные фаззера:
  1. выбирают ИМЯ переменной целиком (атакующий может задать LD_PRELOAD,
     PATH, ...), или
  2. попадают в ЗНАЧЕНИЕ чувствительной переменной (LD_PRELOAD, PATH,
     PYTHONPATH, BASH_ENV, *_PROXY, ...).

Перехват: обёртки над os.environ.__setitem__ (видит исходную str-пару до
кодирования в bytes) и над os.putenv (прямые вызовы; метка в audit event
os.putenv теряется). Вложенный putenv из __setitem__ не проверяется
повторно.
"""

from __future__ import annotations

import os
import threading

from functools import wraps
from typing import Any

from .core import SanitizerIssue, patch, report
from .taint import clean_prefix_of, contains_taint, untaint


class EnvironmentTampering(SanitizerIssue):
    pass


SENSITIVE_NAMES = frozenset({
    "PATH", "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONINSPECT",
    "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "BASH_ENV", "ENV", "IFS",
    "PERL5OPT", "PERL5LIB", "RUBYOPT", "NODE_OPTIONS", "GIT_SSH_COMMAND",
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
})

_SENSITIVE_PREFIXES = ("LD_", "DYLD_")

_local = threading.local()


def _plain_name(key: Any) -> str:

    return os.fsdecode(untaint(key)).upper()


def find_env_issue(key: Any, value: Any) -> str | None:

    if contains_taint(key):

        prefix = clean_prefix_of(key) if isinstance(key, str) else 0

        if prefix == 0:
            return "tainted data selects the environment variable name"

    if contains_taint(value) and isinstance(key, (str, bytes)):

        name = _plain_name(key)

        if name in SENSITIVE_NAMES or name.startswith(_SENSITIVE_PREFIXES):
            return f"tainted value for sensitive variable {name}"

    return None


def _check(key: Any, value: Any, sink: str) -> None:

    reason = find_env_issue(key, value)

    if reason:
        report(EnvironmentTampering, sink, reason)


def install() -> None:

    original_setitem = os._Environ.__setitem__

    @wraps(original_setitem)
    def setitem(self, key, value):

        _check(key, value, "os.environ")

        _local.inside = True

        try:
            return original_setitem(self, key, value)

        finally:
            _local.inside = False

    patch(os._Environ, "__setitem__", setitem)

    original_putenv = os.putenv

    @wraps(original_putenv)
    def putenv(key, value):

        if not getattr(_local, "inside", False):
            _check(key, value, "os.putenv")

        return original_putenv(key, value)

    patch(os, "putenv", putenv)
