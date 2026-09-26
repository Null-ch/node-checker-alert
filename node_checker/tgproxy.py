"""Проверка прокси к Telegram Bot API."""
from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from typing import Optional
from urllib.parse import urlsplit

from .config import TelegramProxySettings
from .http import USER_AGENT


class TelegramProxyClient:
    """Прокси работает, если через него пришёл ответ Bot API на getMe.

    С верным токеном это {"ok": true}, с неверным — {"ok": false, "error_code": 401},
    но в обоих случаях прокси достучался до Telegram. Ошибки nginx (502/504 и т.п.),
    таймауты и обрывы соединения значат, что прокси не работает.
    """

    def __init__(self, settings: TelegramProxySettings, bot_token: str):
        self._settings = settings
        self._bot_token = bot_token

    @property
    def title(self) -> str:
        return f"Telegram-прокси ({urlsplit(self._settings.url).netloc})"

    def check(self) -> Optional[str]:
        """Причина недоступности или None, если прокси работает."""
        # URL с токеном не логируем и не показываем в причинах
        req = urllib.request.Request(f"{self._settings.url}/bot{self._bot_token}/getMe",
                                     headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self._settings.timeout) as resp:
                status, raw = resp.status, resp.read()
        except urllib.error.HTTPError as e:
            status, raw = e.code, e.read()
        except urllib.error.URLError as e:
            if isinstance(e.reason, socket.timeout):
                return self._timeout_reason()
            return f"нет соединения: {e.reason}"
        except socket.timeout:
            return self._timeout_reason()
        except OSError as e:
            return f"нет соединения: {e}"

        if _is_bot_api_response(raw):
            return None
        return f"HTTP {status}, ответ не от Telegram Bot API"

    def _timeout_reason(self) -> str:
        return f"нет ответа за {self._settings.timeout} сек"


def _is_bot_api_response(raw: bytes) -> bool:
    try:
        data = json.loads(raw)
    except ValueError:
        return False
    return isinstance(data, dict) and "ok" in data
