"""
Server-Side Template Injection (SSTI).

Находка, если данные фаззера попали в ТЕКСТ шаблона. Данные в контексте
рендеринга (`template.render(name=user)`) — штатный безопасный способ.

Защищено: Jinja2 (Environment.from_string; через него идут
jinja2.Template(...) и flask.render_template_string).
Mako и Django защищаются, если установлены.
"""

from __future__ import annotations

import importlib
import importlib.util

from .core import SanitizerIssue, guard_function, tainted_check


class TemplateInjection(SanitizerIssue):
    pass


REASON = "tainted data in template source"

# (модуль, класс, метод, позиция источника (с self), имя параметра)
_TARGETS = (
    ("jinja2", "Environment", "from_string", 1, "source"),
    ("mako.template", "Template", "__init__", 1, "text"),
    ("django.template.base", "Template", "__init__", 1, "template_string"),
)


def _load(module_name: str):

    root = module_name.partition(".")[0]

    if importlib.util.find_spec(root) is None:
        return None

    try:
        return importlib.import_module(module_name)

    except Exception:                  # например, Django без настроек
        return None


def install() -> None:

    for module_name, class_name, method, argpos, kwname in _TARGETS:

        module = _load(module_name)

        owner = getattr(module, class_name, None) if module else None

        if owner is None:
            continue

        guard_function(
            owner, method, TemplateInjection, tainted_check(REASON),
            argpos=argpos, kwname=kwname,
            sink=f"{module_name}.{class_name}.{method}"
        )
