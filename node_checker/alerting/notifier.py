"""Каналы доставки уведомлений."""
from __future__ import annotations

import json
import logging
import time
import urllib.error
from typing import Callable, List, Protocol

from ..config import TelegramSettings
from ..http import JsonHttpClient

log = logging.getLogger(__name__)


class Notifier(Protocol):
    def send(self, text: str) -> bool:
        """True, если сообщение доставлено."""
        ...


class ConsoleNotifier:
    def send(self, text: str) -> bool:
        print(f"----- notification -----\n{text}\n------------------------", flush=True)
        return True


class TelegramNotifier:
    LIMIT = 4000
    ATTEMPTS = 3

    def __init__(self, settings: TelegramSettings, http: JsonHttpClient,
                 sleep: Callable[[float], None] = time.sleep):
        self._settings = settings
        self._http = http
        self._sleep = sleep

    def send(self, text: str) -> bool:
        return all(self._send_chunk(chunk) for chunk in split_message(text, self.LIMIT))

    def _send_chunk(self, text: str) -> bool:
        url = f"https://api.telegram.org/bot{self._settings.bot_token}/sendMessage"
        body = {
            "chat_id": self._settings.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        if self._settings.thread_id:
            body["message_thread_id"] = int(self._settings.thread_id)

        for attempt in range(1, self.ATTEMPTS + 1):
            try:
                self._http.post(url, body)
                return True
            except urllib.error.HTTPError as e:
                details = e.read().decode(errors="replace")
                if e.code != 429:
                    log.error("Telegram HTTP %s: %s", e.code, details)
                    return False
                retry_after = _retry_after(details)
                log.warning("Telegram 429, жду %s сек", retry_after)
                self._sleep(retry_after)
            except OSError as e:
                log.warning("Telegram недоступен (попытка %d): %s", attempt, e)
                self._sleep(3 * attempt)
        return False


def _retry_after(details: str) -> int:
    try:
        return min(int(json.loads(details)["parameters"]["retry_after"]), 60)
    except (ValueError, KeyError, TypeError):
        return 5


def split_message(text: str, limit: int) -> List[str]:
    """Режет по строкам, чтобы не разорвать HTML-теги."""
    chunks, current = [], ""
    for line in text.split("\n"):
        if current and len(current) + len(line) + 1 > limit:
            chunks.append(current)
            current = ""
        current = f"{current}\n{line}" if current else line
    if current:
        chunks.append(current)
    return chunks
