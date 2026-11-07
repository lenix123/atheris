"""
AST-инструментация: распространение taint там, где обычные str-операции
создают новую строку без участия наших taint-типов.

Что переписывается:

* f-строки;
* оператор `%`;
* методы, которые могут вставить АРГУМЕНТ в результат
  (`"{}".format(x)`, `",".join(xs)`, `"a".replace("a", x)` ...).

Если получатель уже tainted, методы обрабатывает сам TaintedStr/TaintedBytes
(см. taint_tracking), поэтому остальные методы переписывать не нужно.
"""

from __future__ import annotations

import ast
import sys

from collections.abc import Iterable
from importlib.abc import MetaPathFinder
from importlib.machinery import PathFinder, SourceFileLoader
from types import CodeType
from typing import Any

from taint_tracking import propagate_taint


ARGUMENT_INSERTING_METHODS = frozenset({
    "format", "format_map", "join", "replace", "translate",
    "ljust", "rjust", "center",
})


# ============================================================
# Runtime-хелперы (вызываются из инструментированного кода)
#
# Имена начинаются с ОДНОГО "_": имена вида "__x" компилятор
# переименовывает внутри классов (name mangling), и хелпер
# перестал бы находиться.
# ============================================================

_CONVERSIONS = {ord("s"): str, ord("r"): repr, ord("a"): ascii}


def _taint_fstring_part(value: Any, conversion: int, spec: Any) -> str:

    converted = value if conversion == -1 else _CONVERSIONS[conversion](value)

    return propagate_taint(
        format(converted, str(spec)),
        value,
        spec
    )


def _taint_join_parts(parts: list[str]) -> str:

    return propagate_taint("".join(parts), parts)


def _taint_method_call(receiver: Any, name: str, /, *args, **kwargs) -> Any:
    # receiver и name — positional-only, чтобы не конфликтовать
    # с именованными аргументами исходного вызова.

    result = getattr(receiver, name)(*args, **kwargs)

    return propagate_taint(result, receiver, args, kwargs)


def _taint_percent(template: Any, values: Any) -> Any:

    return propagate_taint(template % values, template, values)


RUNTIME_HELPERS = {
    helper.__name__: helper
    for helper in (
        _taint_fstring_part,
        _taint_join_parts,
        _taint_method_call,
        _taint_percent,
    )
}


# ============================================================
# AST-трансформер
# ============================================================

def _call(helper, *args: ast.expr, keywords=()) -> ast.Call:

    return ast.Call(
        func=ast.Name(id=helper.__name__, ctx=ast.Load()),
        args=list(args),
        keywords=list(keywords)
    )


class TaintASTTransformer(ast.NodeTransformer):

    def visit_JoinedStr(self, node: ast.JoinedStr):

        parts: list[ast.expr] = []

        for part in node.values:

            if isinstance(part, ast.FormattedValue):

                spec = (
                    self.visit(part.format_spec)
                    if part.format_spec is not None
                    else ast.Constant(value="")
                )

                parts.append(
                    _call(
                        _taint_fstring_part,
                        self.visit(part.value),
                        ast.Constant(value=part.conversion),
                        spec
                    )
                )

            else:
                parts.append(part)  # строковый литерал

        return ast.copy_location(
            _call(
                _taint_join_parts,
                ast.List(elts=parts, ctx=ast.Load())
            ),
            node
        )

    def visit_Call(self, node: ast.Call):

        node = self.generic_visit(node)

        func = node.func

        if (
            isinstance(func, ast.Attribute)
            and func.attr in ARGUMENT_INSERTING_METHODS
        ):
            return ast.copy_location(
                _call(
                    _taint_method_call,
                    func.value,
                    ast.Constant(value=func.attr),
                    *node.args,
                    keywords=node.keywords
                ),
                node
            )

        return node

    def visit_BinOp(self, node: ast.BinOp):

        node = self.generic_visit(node)

        if isinstance(node.op, ast.Mod):
            return ast.copy_location(
                _call(_taint_percent, node.left, node.right),
                node
            )

        return node


# ============================================================
# Публичный API
# ============================================================

def instrument_source(
    source: str | bytes,
    filename: str = "<taint-instrumented>"
) -> CodeType:

    tree = TaintASTTransformer().visit(
        ast.parse(source, filename=filename)
    )

    ast.fix_missing_locations(tree)

    return compile(tree, filename, "exec", dont_inherit=True)


def exec_instrumented(
    source: str,
    namespace: dict | None = None,
    *,
    filename: str = "<taint-instrumented>"
) -> dict:
    """Выполняет инструментированный код (удобно для тестов)."""

    namespace = {} if namespace is None else namespace

    namespace.update(RUNTIME_HELPERS)

    exec(instrument_source(source, filename), namespace)

    return namespace


# ============================================================
# Import hook
#
# Инструментирует выбранные модули при обычном `import`, поэтому
# работает вместе с atheris.instrument_imports() и с пакетами.
# ============================================================

class _TaintSourceLoader(SourceFileLoader):

    def get_code(self, fullname):
        # Намеренно без __pycache__: иначе инструментированный байткод
        # попал бы в кэш (и наоборот — подхватился бы чужой).
        path = self.get_filename(fullname)

        return self.source_to_code(self.get_data(path), path)

    def source_to_code(self, data, path, *, _optimize=-1):

        return instrument_source(data, str(path))

    def exec_module(self, module):

        vars(module).update(RUNTIME_HELPERS)

        super().exec_module(module)


class TaintInstrumentationFinder(MetaPathFinder):

    def __init__(self, module_names: Iterable[str]) -> None:

        self._names = tuple(module_names)

    def _matches(self, fullname: str) -> bool:

        return any(
            fullname == name or fullname.startswith(name + ".")
            for name in self._names
        )

    def find_spec(self, fullname, path=None, target=None):

        if not self._matches(fullname):
            return None

        spec = PathFinder.find_spec(fullname, path, target)

        if spec is None or not isinstance(spec.loader, SourceFileLoader):
            return None

        spec.loader = _TaintSourceLoader(
            spec.loader.name,
            spec.loader.path
        )

        return spec


def install_taint_import_hook(
    module_names: Iterable[str]
) -> TaintInstrumentationFinder:
    """
    Все последующие `import <module_names>` (и подмодули)
    будут инструментированы. Уже импортированные модули не затрагиваются.
    """

    finder = TaintInstrumentationFinder(module_names)

    sys.meta_path.insert(0, finder)

    return finder
