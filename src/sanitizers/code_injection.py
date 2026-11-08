"""
Code injection.

Находка, если данные фаззера исполняются как код Python:

    eval(tainted), exec(tainted),
    eval/exec(code), где code получен из compile(tainted, ...).

Почему не только audit events
-----------------------------
Для eval/exec/compile CPython превращает исходник в bytes ДО генерации
события `compile`, а событие `exec` получает уже объект кода. Метка
теряется в обоих случаях (то же, что у os.system), поэтому:

* eval / exec / compile подменяются обёртками в builtins: они видят
  исходный объект и проверяют его;
* результат compile(tainted) запоминается в реестре, а исполнение такого
  code-объекта ловит audit event `exec` (в том числе без обёрток —
  например, из C-кода).

compile() сам по себе находкой не считается: он ничего не выполняет
(ast.literal_eval, ast.parse — легальные случаи). Находка возникает при
исполнении.

Ограничения: `from builtins import eval` до установки обходит обёртки;
типовой "очиститель" — ast.literal_eval — безопасен и не помечается.
"""

from __future__ import annotations

import builtins
import sys
import weakref

from functools import wraps
from types import CodeType
from typing import Any

from .core import SanitizerIssue, on_audit, patch, report
from .taint import contains_taint


class CodeInjection(SanitizerIssue):
    pass


REASON = "tainted data executed as Python code"

# id(code) -> weakref. По id, а не по значению: равные по содержимому
# code-объекты (compile одного и того же текста) считаются равными.
_tainted_code: dict[int, weakref.ref] = {}


def _remember(code: CodeType) -> None:

    key = id(code)

    _tainted_code[key] = weakref.ref(
        code,
        lambda _ref, key=key: _tainted_code.pop(key, None)
    )


def _is_tainted_code(code: Any) -> bool:

    ref = _tainted_code.get(id(code))

    return ref is not None and ref() is code


def find_code_issue(source: Any) -> str | None:
    """Описание проблемы или None (строка / bytes / code-объект)."""

    if isinstance(source, CodeType):
        return REASON if _is_tainted_code(source) else None

    return REASON if contains_taint(source) else None


def _on_exec_event(args: tuple) -> None:
    # Исполнение code-объекта, полученного из tainted-исходника.

    if _is_tainted_code(args[0]):
        report(CodeInjection, "exec", REASON)


def _guard_eval_exec(name: str) -> None:

    original = getattr(builtins, name)

    @wraps(original)
    def guarded(source, globals=None, locals=None, /, **kwargs):

        reason = find_code_issue(source)

        if reason:
            report(CodeInjection, name, reason)

        # Без явных namespace eval/exec работают в окружении ВЫЗЫВАЮЩЕГО.
        # Обёртка — отдельная функция, поэтому подставляем его вручную.
        if globals is None and locals is None:

            frame = sys._getframe(1)

            globals, locals = frame.f_globals, frame.f_locals

        return original(source, globals, locals, **kwargs)

    patch(builtins, name, guarded)


def _guard_compile() -> None:

    original = builtins.compile

    @wraps(original)
    def guarded_compile(source, *args, **kwargs):

        result = original(source, *args, **kwargs)

        if isinstance(result, CodeType) and contains_taint(source):
            _remember(result)

        return result

    patch(builtins, "compile", guarded_compile)


def install() -> None:

    _tainted_code.clear()

    _guard_eval_exec("eval")
    _guard_eval_exec("exec")
    _guard_compile()

    on_audit("exec", _on_exec_event)
