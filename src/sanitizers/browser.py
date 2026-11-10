"""
webbrowser.open*: запуск браузера / обработчика URL по данным фаззера.

Находка, если tainted управляет схемой или хостом открываемого URL
(file://, javascript:, внутренние адреса). Правило то же, что для SSRF:
`"https://site.example/?q=" + user` находкой не считается.
"""

from __future__ import annotations

import webbrowser

from .core import SanitizerIssue, guard_function
from .ssrf import find_url_issue


class BrowserLaunch(SanitizerIssue):
    pass


def install() -> None:

    for name in ("open", "open_new", "open_new_tab"):
        guard_function(
            webbrowser, name, BrowserLaunch, find_url_issue,
            argpos=0, kwname="url"
        )
