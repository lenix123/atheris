"""
SQL injection.

Находка, если данные фаззера попали в ТЕКСТ запроса. Параметры
(`execute("... WHERE id = ?", (user,))`) — штатный безопасный способ и
не проверяются.

Встроенный sqlite3: Connection и Cursor — C-типы, их методы нельзя
подменить, поэтому sqlite3.connect() по умолчанию возвращает подкласс
соединения, а тот создаёт подкласс курсора.

Другие драйверы (psycopg2, mysql-connector, ...) подключаются через
guard_sql_method(); см. docstring.
"""

from __future__ import annotations

import sqlite3

from functools import wraps
from typing import Any

from .core import SanitizerIssue, guard_function, patch, report, tainted_check
from .taint import contains_taint


class SqlInjection(SanitizerIssue):
    pass


def _check(sql: Any, sink: str) -> None:

    if contains_taint(sql):
        report(SqlInjection, sink, "tainted data in SQL statement text")


class GuardedCursor(sqlite3.Cursor):

    def execute(self, sql, *args, **kwargs):
        _check(sql, "sqlite3.Cursor.execute")
        return super().execute(sql, *args, **kwargs)

    def executemany(self, sql, *args, **kwargs):
        _check(sql, "sqlite3.Cursor.executemany")
        return super().executemany(sql, *args, **kwargs)

    def executescript(self, script, *args, **kwargs):
        _check(script, "sqlite3.Cursor.executescript")
        return super().executescript(script, *args, **kwargs)


class GuardedConnection(sqlite3.Connection):

    def cursor(self, factory=GuardedCursor):
        return super().cursor(factory)

    def execute(self, sql, *args, **kwargs):
        _check(sql, "sqlite3.Connection.execute")
        return super().execute(sql, *args, **kwargs)

    def executemany(self, sql, *args, **kwargs):
        _check(sql, "sqlite3.Connection.executemany")
        return super().executemany(sql, *args, **kwargs)

    def executescript(self, script, *args, **kwargs):
        _check(script, "sqlite3.Connection.executescript")
        return super().executescript(script, *args, **kwargs)


def guard_sql_method(
    owner: Any,
    name: str,
    *,
    argpos: int = 1,
    kwname: str | None = "query"
) -> None:
    """
    Защищает метод другого драйвера, например:

        guard_sql_method(psycopg2.extensions.cursor, "execute",
                         argpos=1, kwname="query")

    argpos считается вместе с self. Работает для классов, написанных на
    Python; для C-типов нужен подкласс (как для sqlite3 выше).
    """

    guard_function(
        owner, name, SqlInjection,
        tainted_check("tainted data in SQL statement text"),
        argpos=argpos, kwname=kwname
    )


def install() -> None:

    original_connect = sqlite3.connect

    @wraps(original_connect)
    def connect(*args, **kwargs):

        # factory — 6-й позиционный аргумент sqlite3.connect.
        if "factory" not in kwargs and len(args) < 6:
            kwargs["factory"] = GuardedConnection

        return original_connect(*args, **kwargs)

    patch(sqlite3, "connect", connect)

    dbapi2 = getattr(sqlite3, "dbapi2", None)

    if dbapi2 is not None and dbapi2.connect is original_connect:
        patch(dbapi2, "connect", connect)
