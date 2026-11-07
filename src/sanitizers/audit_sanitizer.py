"""
Санитайзер запуска команд: ищет попадание tainted-данных в sink'и.

Как это работает
----------------
* subprocess.Popen, os.exec*, os.posix_spawn, os.spawn — через audit hook.
  Интерпретатор передаёт в событие исходные объекты аргументов, поэтому
  taint сохраняется, а перехват работает при любом стиле импорта
  (`from subprocess import Popen` тоже).
* os.system — через обёртку: CPython превращает command в bytes ДО
  генерации audit event, и метка теряется.

Блокируется:
  1. tainted в команде, запускаемой через shell
     (shell=True или явно ['sh', '-c', cmd]);
  2. tainted в пути исполняемого файла / argv[0];
  3. tainted в os.system().

Вызовы с shell=False и данными фаззера только в обычных аргументах
разрешены.
"""

from __future__ import annotations

import os
import re
import sys

from collections import Counter
from functools import wraps
from threading import Lock
from typing import Any, TextIO

from taint_tracking import contains_taint


class CommandExecutionBlocked(RuntimeError):
    """Tainted-данные достигли опасной операции."""


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


def _exec_target(event: str, args: tuple) -> tuple[Any, Any]:
    """Достаёт (путь к программе, argv) из аргументов audit event."""

    if event == "os.spawn":          # (mode, path, args, env)
        return args[1], args[2]

    # subprocess.Popen: (executable, args, cwd, env)
    # os.exec / os.posix_spawn: (path, argv, env)
    return args[0], args[1]


_AUDIT_EVENTS = frozenset({
    "subprocess.Popen", "os.exec", "os.posix_spawn", "os.spawn",
})


class AuditCommandSanitizer:

    def __init__(self, *, stream: TextIO | None = None) -> None:

        self._stream = stream or sys.stderr
        self._lock = Lock()
        self._installed = False

        self._blocked: Counter[str] = Counter()
        self._observed: Counter[str] = Counter()

    @property
    def installed(self) -> bool:
        return self._installed

    def install(self) -> None:
        """
        Устанавливает hook и обёртку os.system.

        Audit hook нельзя удалить, поэтому устанавливать санитайзер
        нужно один раз за процесс — и ДО импорта целевого кода, если тот
        делает `from os import system`.
        """

        if self._installed:
            raise RuntimeError("AuditCommandSanitizer is already installed")

        original_system = os.system

        @wraps(original_system)
        def guarded_system(command: Any) -> int:

            self._observe("os.system")

            if contains_taint(command):
                self._block("os.system", "tainted command")

            return original_system(command)

        os.system = guarded_system

        sys.addaudithook(self._audit_hook)

        self._installed = True

    def counts(self) -> dict[str, dict[str, int]]:

        with self._lock:
            return {
                "blocked": dict(self._blocked),
                "observed": dict(self._observed),
            }

    # --------------------------------------------------------

    def _audit_hook(self, event: str, args: tuple[Any, ...]) -> None:

        if event not in _AUDIT_EVENTS:
            return

        self._observe(event)

        path, argv = _exec_target(event, args)

        reason = self._find_reason(path, argv)

        if reason:
            self._block(event, reason)

    @staticmethod
    def _find_reason(path: Any, argv: Any) -> str | None:

        if contains_taint(path):
            return "tainted executable"

        if isinstance(argv, (list, tuple)) and argv and contains_taint(argv[0]):
            return "tainted argv[0]"

        if is_shell_invocation(argv) and contains_taint(argv):
            return "tainted shell command"

        return None

    def _observe(self, event: str) -> None:

        with self._lock:
            self._observed[event] += 1

    def _block(self, event: str, reason: str) -> None:

        with self._lock:
            self._blocked[event] += 1
            number = self._blocked[event]

        # Содержимое команды намеренно не печатаем.
        print(
            f"[SANITIZER] BLOCKED {reason} at sink={event!r} "
            f"occurrence={number}",
            file=self._stream,
            flush=True
        )

        raise CommandExecutionBlocked(f"{reason} reached {event}")
