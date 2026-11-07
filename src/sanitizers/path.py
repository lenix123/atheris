"""
Path traversal.

Перехват через audit events: интерпретатор передаёт исходный объект пути,
поэтому taint сохраняется.

Находка, если путь, содержащий данные фаззера:
  1. содержит компонент `..` в потенциально tainted части, или
  2. абсолютный и tainted с первого символа (пользователь выбирает корень:
     `open(user_input)` с "/etc/passwd").

Известные ограничения: pathlib.Path теряет метку при str(); нормализующие
функции (os.path.normpath/abspath/realpath) сбрасывают clean_prefix,
поэтому абсолютные пути после них считаются tainted с первого символа.
"""

from __future__ import annotations

import os
import re

from typing import Any

from .core import SanitizerIssue, on_audit, report
from .taint import clean_prefix_of, contains_taint, untaint


class PathTraversal(SanitizerIssue):
    pass


# audit event -> индексы аргументов-путей
_PATH_EVENTS = {
    "open": (0,),
    "os.listdir": (0,),
    "os.scandir": (0,),
    "os.remove": (0,),
    "os.rename": (0, 1),
    "os.mkdir": (0,),
    "os.rmdir": (0,),
    "os.chmod": (0,),
    "os.chown": (0,),
    "os.chdir": (0,),
    "os.truncate": (0,),
    "os.symlink": (0, 1),
    "os.link": (0, 1),
    "shutil.copyfile": (0, 1),
    "shutil.copytree": (0, 1),
    "shutil.move": (0, 1),
    "shutil.rmtree": (0,),
}

_SEPARATORS = re.compile(r"[\\/]+")


def find_path_issue(path: Any) -> str | None:
    """Описание проблемы или None."""

    try:
        raw = os.fspath(path)

    except TypeError:                 # файловый дескриптор и т.п.
        return None

    if not contains_taint(raw):
        return None

    prefix = clean_prefix_of(raw) if isinstance(raw, str) else 0

    text = os.fsdecode(untaint(raw))

    # Компонент ".." может начаться в последнем символе чистого префикса.
    region = text[max(prefix - 1, 0):]

    if ".." in _SEPARATORS.split(region):
        return "tainted path contains '..' component"

    if prefix == 0 and os.path.isabs(text):
        return "tainted absolute path (attacker chooses the location)"

    return None


def _make_handler(event: str, indexes: tuple[int, ...]):

    def handler(args: tuple) -> None:

        for index in indexes:

            if index < len(args):

                reason = find_path_issue(args[index])

                if reason:
                    report(PathTraversal, event, reason)

    return handler


def install() -> None:

    for event, indexes in _PATH_EVENTS.items():
        on_audit(event, _make_handler(event, indexes))
