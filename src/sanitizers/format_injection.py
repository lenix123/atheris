"""
Format string injection.

    user_template.format(obj)     # {0.__class__.__init__.__globals__}

Находка, если в ТЕКСТЕ шаблона `str.format` / `format_map` есть поле с
обращением к атрибуту или индексу (`{x.attr}`, `{x[0]}`), причём поле
заканчивается в потенциально tainted части. Простые поля `{}` / `{name}`
и экранированные `{{ }}` находкой не считаются.

Работает в инструментированном коде: проверка вызывается из
instrumentation._taint_method_call перед выполнением format.
"""

from __future__ import annotations

import re

from typing import Any

from .core import FORMAT_CHECKS, SanitizerIssue, report
from .taint import clean_prefix_of, contains_taint, untaint


class FormatStringInjection(SanitizerIssue):
    pass


_NAME_END = re.compile(r"[!:]")


def find_format_issue(template: Any) -> str | None:

    if not isinstance(template, str) or not contains_taint(template):
        return None

    text = untaint(template)
    prefix = clean_prefix_of(template)

    i, size = 0, len(text)

    while i < size:

        if text[i] != "{":
            i += 1
            continue

        if text[i + 1:i + 2] == "{":          # экранированная скобка
            i += 2
            continue

        end = text.find("}", i)

        if end < 0:
            break

        name = _NAME_END.split(text[i + 1:end], 1)[0]

        if ("." in name or "[" in name) and end >= prefix:
            return "tainted format template accesses attributes or items"

        i = end + 1

    return None


def _check(template: Any) -> None:

    reason = find_format_issue(template)

    if reason:
        report(FormatStringInjection, "str.format", reason)


def install() -> None:

    FORMAT_CHECKS.append(_check)
