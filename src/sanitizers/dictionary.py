"""
Словарь libFuzzer с "опасными" токенами.

Санитайзеры ищут не любые данные, а данные с определёнными
свойствами (`..`, `;`, `'`, адрес хоста), которые фаззер сам вряд ли
быстро соберёт из случайных байтов. Словарь подкладывается автоматически
через `-dict=`, если пользователь не задал свой.
"""

from __future__ import annotations

import os
import tempfile

from collections.abc import Sequence

TOKENS: dict[str, tuple[bytes, ...]] = {
    "command": (
        b"; id", b"| id", b"&& id", b"$(id)", b"`id`", b"\n id",
        b"'; id; '",
    ),
    "code": (
        b"__import__('os').system('id')", b"__import__", b"().__class__",
        b"exec(", b"eval(", b"open('/etc/passwd')",
    ),
    "path": (
        b"../", b"..\\", b"../../", b"....//", b"/etc/passwd", b"..",
    ),
    "sql": (
        b"' OR '1'='1", b"'; DROP TABLE t;--", b"\" OR 1=1--",
        b"' UNION SELECT 1--", b"--", b"'",
    ),
    "ssrf": (
        b"http://127.0.0.1", b"http://localhost", b"file:///etc/passwd",
        b"http://169.254.169.254/", b"gopher://", b"//",
    ),
    "native": (b"libc.so.6", b"../", b"system"),
    "env": (b"LD_PRELOAD", b"PATH", b"PYTHONPATH", b"BASH_ENV"),
    "import": (b"os", b"posix", b"subprocess", b"ctypes", b"pickle"),
    "browser": (b"file:///etc/passwd", b"javascript:", b"//"),
    "template": (
        b"{{7*7}}", b"{{config}}", b"{{''.__class__}}", b"{% for x in y %}",
        b"${7*7}", b"<%= 7*7 %>",
    ),
    "format": (b"{0.__class__}", b"{0[0]}", b"{a.__dict__}", b"{0.__init__.__globals__}"),
    "deserialization": (
        b"\x80\x04", b"cos\nsystem\n", b"\x80\x05\x95",
    ),
}


def _escape(token: bytes) -> str:

    out = []

    for byte in token:

        if 32 <= byte < 127 and byte not in (ord('"'), ord("\\")):
            out.append(chr(byte))

        else:
            out.append(f"\\x{byte:02x}")

    return "".join(out)


def render(names: Sequence[str]) -> str:
    """Содержимое словаря в формате libFuzzer."""

    lines = []

    for name in names:
        for index, token in enumerate(TOKENS.get(name, ())):
            lines.append(f'{name}_{index}="{_escape(token)}"')

    return "\n".join(lines) + "\n"


def with_dictionary(args: Sequence[str], names: Sequence[str]) -> list[str]:
    """
    Возвращает args с добавленным `-dict=<файл>`. Если пользователь уже
    передал -dict, аргументы не меняются.
    """

    args = list(args)

    if any(arg.startswith("-dict=") for arg in args) or not names:
        return args

    handle, path = tempfile.mkstemp(prefix="atheris-sanitizers-", suffix=".dict")

    with os.fdopen(handle, "w", encoding="ascii") as file:
        file.write(render(names))

    return args + [f"-dict={path}"]
