"""
Подключение санитайзеров к модулю atheris.

Пользователь пишет обёртку как обычно:

    import atheris
    with atheris.instrument_imports():
        import my_library

    def TestOneInput(data): my_library.parse(data)

    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

а `install_into(atheris)` (вызывается при импорте atheris в форке) делает
всё остальное:

* ставит санитайзеры (sink'и) сразу при `import atheris`;
* Setup(): помечает входные данные как tainted и добавляет словарь;
* FuzzedDataProvider: результаты Consume* (str/bytes) tainted;
* instrument_imports(): модули, импортируемые внутри блока, получают
  taint-инструментацию вместе с coverage-инструментацией Atheris.
"""

from __future__ import annotations

from functools import wraps
from types import ModuleType
from typing import Any

from . import install, installed
from .dictionary import with_dictionary
from .instrumentation import (
    install_taint_import_hook,
    remove_taint_import_hook,
)
from .taint import mark_tainted, untaint

_FLAG = "_sanitizers_installed"


def _mark_text(value: Any) -> Any:
    """str/bytes (и списки из них) -> tainted. Числа не трогаем."""

    if isinstance(value, (str, bytes)):
        return mark_tainted(value, "atheris")

    if isinstance(value, list):
        return [_mark_text(item) for item in value]

    return value


def _patch_setup(atheris: ModuleType, names: list[str]) -> None:

    original = atheris.Setup

    @wraps(original)
    def Setup(args, test_one_input, *rest, **kwargs):

        @wraps(test_one_input)
        def tainted_input(data):

            try:
                data = mark_tainted(data, "atheris")

            except TypeError:
                pass

            return test_one_input(data)

        return original(
            with_dictionary(args, names),
            tainted_input,
            *rest,
            **kwargs
        )

    atheris.Setup = Setup


def _patch_data_provider(atheris: ModuleType) -> None:

    original = getattr(atheris, "FuzzedDataProvider", None)

    if original is None:
        return

    class FuzzedDataProvider:
        """Обёртка: Consume* возвращают tainted str/bytes."""

        def __init__(self, data):
            self._inner = original(untaint(data))

        def __getattr__(self, name):

            attribute = getattr(self._inner, name)

            if not (callable(attribute) and name.startswith("Consume")):
                return attribute

            @wraps(attribute)
            def consume(*args, **kwargs):
                return _mark_text(attribute(*args, **kwargs))

            return consume

    atheris.FuzzedDataProvider = FuzzedDataProvider


class _ImportContext:
    """`with instrument_imports(...)`: coverage Atheris + taint-hook."""

    def __init__(self, inner, include):
        self._inner = inner
        self._include = include
        self._finder = None

    def __enter__(self):
        # Наш finder ставится первым; Atheris при входе вставляет свой
        # перед ним и для поиска spec делегирует остальным finder'ам.
        self._finder = install_taint_import_hook(self._include)
        return self._inner.__enter__()

    def __exit__(self, *exc_info):
        try:
            return self._inner.__exit__(*exc_info)
        finally:
            remove_taint_import_hook(self._finder)

    def __getattr__(self, name):
        return getattr(self._inner, name)


def _patch_instrument_imports(atheris: ModuleType) -> None:

    original = atheris.instrument_imports

    @wraps(original)
    def instrument_imports(include=None, *args, **kwargs):
        return _ImportContext(original(include, *args, **kwargs), include)

    atheris.instrument_imports = instrument_imports


def install_into(atheris: ModuleType) -> list[str]:
    """Идемпотентно подключает санитайзеры к модулю atheris."""

    if getattr(atheris, _FLAG, False):
        return installed()

    names = install()

    if not names:
        return []

    _patch_setup(atheris, names)
    _patch_data_provider(atheris)
    _patch_instrument_imports(atheris)

    setattr(atheris, _FLAG, True)

    return names
