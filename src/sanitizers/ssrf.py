"""
SSRF (Server-Side Request Forgery).

Находка, если данные фаззера определяют КУДА идёт запрос:

1. API-уровень (метка ещё не потеряна при разборе URL):
   urllib.request.urlopen / Request, http.client.HTTPConnection,
   requests.Session.request (если установлен).
   URL считается подконтрольным, если tainted-часть начинается не позже
   конца authority (схема, userinfo, хост, порт). Конструкция
   "https://api.example.com/?q=" + user — НЕ находка: контролируется
   только query. Точность даёт clean_prefix (см. taint.py).

2. Сокеты (audit events socket.getaddrinfo / connect / gethostbyname):
   tainted-хост, дошедший до разрешения имени или соединения.
   Срабатывает, если URL был разобран операциями, сохраняющими taint.

Ограничение: клиенты, разбирающие URL регулярными выражениями
(urllib3, httpx), теряют метку внутри — их ловит только API-уровень.
"""

from __future__ import annotations

import importlib
import importlib.util

from typing import Any
from urllib.parse import urlsplit

import http.client
import urllib.request

from .core import SanitizerIssue, guard_function, on_audit, report
from .taint import clean_prefix_of, contains_taint, untaint


class SSRF(SanitizerIssue):
    pass


def find_url_issue(url: Any) -> str | None:

    if isinstance(url, bytes):
        return "tainted URL" if contains_taint(url) else None

    if not isinstance(url, str) or not contains_taint(url):
        return None

    text = untaint(url)

    parts = urlsplit(text)

    authority_start = len(parts.scheme) + 1 if parts.scheme else 0

    if text[authority_start:authority_start + 2] == "//":
        authority_end = authority_start + 2 + len(parts.netloc)

    else:
        authority_end = len(text)        # нет authority: важна вся строка

    if clean_prefix_of(url) < authority_end:
        return "tainted data controls the URL scheme or host"

    return None


def _host_issue(host: Any) -> str | None:

    return "tainted host" if contains_taint(host) else None


def _make_socket_handler(event: str, extract):

    def handler(args: tuple) -> None:

        reason = _host_issue(extract(args))

        if reason:
            report(SSRF, event, reason)

    return handler


def _connect_host(args: tuple) -> Any:
    # socket.connect: (sock, address); address — (host, port, ...)
    address = args[1]
    return address[0] if isinstance(address, tuple) and address else None


def install() -> None:

    on_audit(
        "socket.getaddrinfo",
        _make_socket_handler("socket.getaddrinfo", lambda a: a[0])
    )
    on_audit(
        "socket.gethostbyname",
        _make_socket_handler("socket.gethostbyname", lambda a: a[0])
    )
    on_audit(
        "socket.connect",
        _make_socket_handler("socket.connect", _connect_host)
    )

    guard_function(
        urllib.request, "urlopen", SSRF, find_url_issue,
        argpos=0, kwname="url"
    )
    guard_function(
        urllib.request.Request, "__init__", SSRF, find_url_issue,
        argpos=1, kwname="url", sink="urllib.request.Request"
    )
    guard_function(
        http.client.HTTPConnection, "__init__", SSRF, _host_issue,
        argpos=1, kwname="host", sink="http.client.HTTPConnection"
    )

    if importlib.util.find_spec("requests") is not None:

        try:
            sessions = importlib.import_module("requests.sessions")

        except ImportError:
            return

        guard_function(
            sessions.Session, "request", SSRF, find_url_issue,
            argpos=2, kwname="url", sink="requests.Session.request"
        )
