"""
Динамический импорт по имени из данных фаззера.

    importlib.import_module(tainted), __import__(tainted)

Атакующий выбирает, какой модуль загрузить и выполнить (импорт
исполняет код модуля). Аналог ReflectiveCall в Jazzer.

Перехват: обёртки над builtins.__import__ и importlib.import_module
(audit event `import` не срабатывает для уже загруженных модулей, а
import_module его не генерирует).

Правило: tainted с первого символа. `import_module("plugins." + name)`
находкой не считается — пакет зафиксирован разработчиком.
"""

from __future__ import annotations

import builtins
import importlib

from typing import Any

from .core import SanitizerIssue, guard_function
from .taint import clean_prefix_of, contains_taint


class DynamicImport(SanitizerIssue):
    pass


def find_import_issue(name: Any) -> str | None:

    if isinstance(name, str) and contains_taint(name) and clean_prefix_of(name) == 0:
        return "tainted data selects the module to import"

    return None


def install() -> None:

    guard_function(
        builtins, "__import__", DynamicImport, find_import_issue,
        argpos=0, kwname="name"
    )
    guard_function(
        importlib, "import_module", DynamicImport, find_import_issue,
        argpos=0, kwname="name"
    )
