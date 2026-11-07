"""
Code Injection.

Перехват через Python audit events.

Обнаруживает передачу данных под контролем фаззера
в механизмы динамического исполнения Python-кода:

    1. eval(expression)
    2. exec(source)
    3. compile(source, filename, mode)

Находка возникает, если исходный код или выражение
содержит tainted-данные.

Известные ограничения:
    - Не отслеживает автоматически taint внутри объектов CodeType,
      созданных ранее из tainted-строки.
    - Не обнаруживает динамическое исполнение через сторонние
      интерпретаторы и библиотеки, если они не генерируют
      соответствующие audit events.
    - Не различает безопасные и опасные выражения:
      любое исполнение tainted-кода считается потенциальной
      Code Injection.
"""

from __future__ import annotations

from typing import Any

from .core import SanitizerIssue, on_audit, report
from .taint import contains_taint, untaint


class CodeInjection(SanitizerIssue):
    pass


# Audit event -> индексы аргументов с исходным кодом.
#
# exec:
#   args[0] — объект кода или исходный код
#
# compile:
#   args[0] — исходный код
#   args[1] — имя файла
#   args[2] — режим компиляции
#
# Важно: compile сам по себе только компилирует код,
# но не выполняет его. Поэтому его обнаружение можно
# считать отдельной категорией потенциального риска.

_CODE_EVENTS = {
    "exec": (0,),
    "compile": (0,),
}


def find_code_issue(source: Any) -> str | None:
    """Описание проблемы или None."""

    if not contains_taint(source):
        return None

    return "tainted data passed to dynamic code execution"


def _make_handler(event: str, indexes: tuple[int, ...]):

    def handler(args: tuple) -> None:

        for index in indexes:

            if index >= len(args):
                continue

            source = args[index]

            # Для exec аргументом может быть объект CodeType.
            # Если taint engine умеет отслеживать такие объекты,
            # contains_taint() сможет обнаружить их метку.
            reason = find_code_issue(source)

            if reason:
                report(CodeInjection, event, reason)

    return handler


def install() -> None:
    """Устанавливает audit hooks для Code Injection."""

    for event, indexes in _CODE_EVENTS.items():
        on_audit(event, _make_handler(event, indexes))