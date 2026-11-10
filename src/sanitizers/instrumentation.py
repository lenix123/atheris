"""
AST-инструментация: распространение taint там, где обычные str-операции
создают новую строку без участия наших taint-типов.

Переписываются:

* f-строки;
* оператор `%`;
* методы, которые могут вставить АРГУМЕНТ в результат
  (`"{}".format(x)`, `",".join(xs)`, `"a".replace("a", x)` ...).

Если получатель уже tainted, методы обрабатывает сам TaintedStr
(см. taint.py), поэтому остальные методы переписывать не нужно.
"""

from __future__ import annotations

import ast
import builtins
import inspect
import sys
import textwrap

from collections.abc import Iterable
from functools import wraps
from importlib.abc import MetaPathFinder
from importlib.machinery import PathFinder, SourceFileLoader
from types import CodeType
from typing import Any

from .core import FORMAT_CHECKS
from .taint import (
    clean_prefix_of,
    make_tainted_str,
    propagate_taint,
    taint_sources,
    untaint,
)


ARGUMENT_INSERTING_METHODS = frozenset({
    "format", "format_map", "join", "replace", "translate",
    "ljust", "rjust", "center",
})


# ============================================================
# Runtime-хелперы (вызываются из инструментированного кода)
#
# Имена начинаются с ОДНОГО "_": имена вида "__x" компилятор
# переименовывает внутри классов (name mangling).
# ============================================================

_CONVERSIONS = {ord("s"): str, ord("r"): repr, ord("a"): ascii}


def _parts_clean_prefix(parts: list) -> int:
    """Clean-префикс конкатенации parts (str или TaintedStr)."""

    total = 0

    for part in parts:

        prefix = clean_prefix_of(part)
        total += prefix

        if prefix < len(part):
            break

    return total


def _concat(text: str, parts: list) -> str:

    sources = taint_sources(parts)

    if not sources:
        return text

    return make_tainted_str(text, sources, _parts_clean_prefix(parts))


def _literal_prefix(template: Any, marker: str) -> int:
    """Длина части шаблона до первого плейсхолдера."""

    plain = untaint(template)

    first = plain.find(marker)

    limit = len(plain) if first < 0 else first

    return min(clean_prefix_of(template), limit)


def _taint_fstring_part(value: Any, conversion: int, spec: Any) -> str:

    converted = value if conversion == -1 else _CONVERSIONS[conversion](value)

    return propagate_taint(
        format(converted, str(spec)),
        value,
        spec
    )


def _taint_join_parts(parts: list[str]) -> str:

    return _concat("".join(parts), parts)


def _taint_method_call(receiver: Any, name: str, /, *args, **kwargs) -> Any:
    # receiver и name — positional-only, чтобы не конфликтовать
    # с именованными аргументами исходного вызова.

    if (
        name == "join"
        and isinstance(receiver, str)
        and len(args) == 1
        and not kwargs
    ):
        items = list(args[0])

        text = untaint(receiver).join(items)       # TypeError как у str.join

        parts: list = []

        for index, item in enumerate(items):
            if index:
                parts.append(receiver)
            parts.append(item)

        return _concat(text, parts)

    if FORMAT_CHECKS and name in ("format", "format_map"):

        for check in tuple(FORMAT_CHECKS):
            check(receiver)

    result = getattr(receiver, name)(*args, **kwargs)

    if name == "format" and isinstance(receiver, str):

        sources = taint_sources((receiver, args, kwargs))

        if not sources:
            return result

        return make_tainted_str(
            untaint(result),
            sources,
            _literal_prefix(receiver, "{")
        )

    return propagate_taint(result, receiver, args, kwargs)


def _taint_percent(template: Any, values: Any) -> Any:

    result = template % values

    if isinstance(template, str):

        sources = taint_sources((template, values))

        if not sources:
            return result

        return make_tainted_str(
            untaint(result),
            sources,
            _literal_prefix(template, "%")
        )

    return propagate_taint(result, template, values)


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


def instrument_function(function):
    """
    Декоратор: пересобирает функцию с taint-инструментацией.

    Код harness (TestOneInput в запускаемом скрипте) import hook не
    инструментирует, и f-строки / `%` / `.format()` там теряют метку.
    Достаточно повесить декоратор:

        @sanitizers.instrument_function
        def TestOneInput(data): ...

    Ограничения: нужен доступный исходник; замыкания не поддерживаются.
    """

    if function.__closure__:
        raise ValueError("instrument_function does not support closures")

    source = textwrap.dedent(inspect.getsource(function))

    tree = ast.parse(source)

    node = tree.body[0]

    node.decorator_list = [
        decorator for decorator in node.decorator_list
        if "instrument_function" not in ast.unparse(decorator)
    ]

    tree = TaintASTTransformer().visit(tree)

    ast.increment_lineno(tree, function.__code__.co_firstlineno - 1)
    ast.fix_missing_locations(tree)

    code = compile(
        tree, inspect.getsourcefile(function) or "<instrumented>", "exec",
        dont_inherit=True
    )

    vars(builtins).update(RUNTIME_HELPERS)

    namespace = function.__globals__
    name = function.__name__
    missing = object()
    previous = namespace.get(name, missing)

    exec(code, namespace)             # имя временно перезаписывается

    result = namespace[name]

    if previous is missing:
        del namespace[name]

    else:
        namespace[name] = previous

    return result


# ============================================================
# Import hook
#
# Как это устроено и почему именно так
# ------------------------------------
# Atheris (instrument_imports) опрашивает остальные finder'ы, но затем
# ПОДМЕНЯЕТ loader своим AtherisSourceFileLoader, пересоздавая его только
# из name и path. Любой наш собственный loader при этом теряется, и модуль
# компилируется без taint-инструментации.
#
# Поэтому finder только ЗАПОМИНАЕТ путь целевого модуля, а инструментацию
# выполняет единственный патч SourceFileLoader.get_code — его наследуют и
# обычный loader, и loader Atheris (его get_code вызывает super().get_code()
# и затем добавляет coverage-инструментацию к УЖЕ преобразованному коду).
# Для целевых модулей кэш __pycache__ не используется: иначе подхватился
# бы валидный .pyc без инструментации.
# ============================================================

# Свои пакеты и сам atheris не инструментируем.
_OWN_ROOTS = frozenset({__name__.split(".")[0], "atheris"})

_TARGET_PATHS: set[str] = set()
_loader_patched = False


def _patch_source_loader() -> None:

    global _loader_patched

    if _loader_patched:
        return

    original = SourceFileLoader.get_code

    @wraps(original)
    def get_code(self, fullname):

        path = self.get_filename(fullname)

        if path in _TARGET_PATHS:
            return instrument_source(self.get_data(path), str(path))

        return original(self, fullname)

    SourceFileLoader.get_code = get_code

    _loader_patched = True


class TaintInstrumentationFinder(MetaPathFinder):
    """
    modules=None — инструментировать любой не-stdlib модуль
    (кроме самих санитайзеров и atheris).
    """

    def __init__(self, modules: Iterable[str] | None = None) -> None:

        self._names = None if modules is None else tuple(modules)
        self.paths: set[str] = set()

    def _matches(self, fullname: str) -> bool:

        root = fullname.partition(".")[0]

        if self._names is None:
            return (
                root not in _OWN_ROOTS
                and root not in sys.stdlib_module_names
            )

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

        origin = spec.loader.path

        self.paths.add(origin)
        _TARGET_PATHS.add(origin)

        return spec


def install_taint_import_hook(
    modules: Iterable[str] | None = None
) -> TaintInstrumentationFinder:
    """
    Все последующие `import` (указанных модулей и подмодулей или,
    при modules=None, любых не-stdlib модулей) будут инструментированы.
    Уже импортированные модули не затрагиваются.
    """

    finder = TaintInstrumentationFinder(modules)

    # Хелперы доступны через builtins, а не через globals модуля: код
    # выполняет тот loader, который выберет Atheris.
    vars(builtins).update(RUNTIME_HELPERS)

    _patch_source_loader()

    sys.meta_path.insert(0, finder)

    return finder


def remove_taint_import_hook(finder: TaintInstrumentationFinder) -> None:

    if finder in sys.meta_path:
        sys.meta_path.remove(finder)

    _TARGET_PATHS.difference_update(finder.paths)