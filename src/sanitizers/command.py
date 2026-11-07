"""
Command injection.

* subprocess.Popen, os.exec*, os.posix_spawn, os.spawn — audit hook:
  интерпретатор передаёт исходные объекты аргументов, taint сохраняется,
  а перехват работает при любом стиле импорта.
* os.system — обёртка: CPython превращает command в bytes ДО генерации
  audit event, и метка теряется.

Находка, если tainted-данные попали:
  1. в команду, запускаемую через shell (shell=True или ['sh', '-c', ...]);
  2. в путь исполняемого файла / argv[0];
  3. в os.system().

shell=False с данными фаззера только в обычных аргументах разрешён.
Windows: при shell=True команда собирается через str.format внутри stdlib
и taint теряется — не поддерживается.
"""

from __future__ import annotations

import os
import re
import shlex

from functools import wraps
from typing import Any

from .core import SanitizerIssue, on_audit, patch, report
from .taint import contains_taint, untaint


class CommandInjection(SanitizerIssue):
    pass


SHELL_NAMES = frozenset({
    "sh", "bash", "dash", "zsh", "ksh", "fish",
    "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe",
})

_POSIX_COMMAND_FLAG = re.compile(r"-[a-z]*c[a-z]*")
_OTHER_COMMAND_FLAGS = frozenset({"/c", "/k", "-command"})


def is_shell_invocation(argv: Any) -> bool:
    """Распознаёт ['/bin/sh', '-c', ...], ['bash', '-lc', ...] и т.п."""

    if not isinstance(argv, (list, tuple)) or not argv:
        return False

    try:
        items = [os.fsdecode(item).lower() for item in argv]

    except (TypeError, ValueError):
        return False

    return (
        os.path.basename(items[0]) in SHELL_NAMES
        and any(
            flag in _OTHER_COMMAND_FLAGS
            or _POSIX_COMMAND_FLAG.fullmatch(flag)
            for flag in items[1:]
        )
    )


def _find_reason(path: Any, argv: Any) -> str | None:

    if contains_taint(path):
        return "tainted executable"

    if isinstance(argv, (list, tuple)) and argv and contains_taint(argv[0]):
        return "tainted argv[0]"

    if is_shell_invocation(argv) and contains_taint(argv):
        return "tainted shell command"

    return None


# audit event -> индексы (путь к программе, argv) в аргументах события
_EXEC_EVENTS = {
    "subprocess.Popen": (0, 1),   # executable, args, cwd, env
    "os.exec": (0, 1),            # path, args, env
    "os.posix_spawn": (0, 1),     # path, argv, env
    "os.spawn": (1, 2),           # mode, path, args, env
}


def _make_handler(event: str, path_index: int, argv_index: int):

    def handler(args: tuple) -> None:

        reason = _find_reason(args[path_index], args[argv_index])

        if reason:
            report(CommandInjection, event, reason)

    return handler


def install() -> None:

    for event, (path_index, argv_index) in _EXEC_EVENTS.items():
        on_audit(event, _make_handler(event, path_index, argv_index))

    original_system = os.system

    @wraps(original_system)
    def guarded_system(command: Any) -> int:

        if contains_taint(command):
            report(CommandInjection, "os.system", "tainted command")

        return original_system(command)

    patch(os, "system", guarded_system)

    # shlex.quote — штатный очиститель для shell.
    original_quote = shlex.quote

    @wraps(original_quote)
    def quote(value):
        return untaint(original_quote(value))

    patch(shlex, "quote", quote)
