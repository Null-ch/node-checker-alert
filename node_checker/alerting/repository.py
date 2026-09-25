"""Хранилище состояния алертов (чтобы рестарт не вызывал повторных уведомлений)."""
from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, dataclass
from typing import Dict, Protocol

log = logging.getLogger(__name__)


@dataclass
class TargetState:
    title: str = ""
    reason: str = ""
    fails: int = 0          # неудачных проверок подряд
    oks: int = 0            # удачных проверок подряд после алерта
    down: bool = False      # алерт «не работает» уже отправлен
    since: float = 0.0      # время первой неудачной проверки
    last_alert: float = 0.0


States = Dict[str, TargetState]


class StateRepository(Protocol):
    def load(self) -> States: ...

    def save(self, states: States) -> None: ...


class InMemoryStateRepository:
    def __init__(self):
        self._states: States = {}

    def load(self) -> States:
        return dict(self._states)

    def save(self, states: States) -> None:
        self._states = dict(states)


class JsonFileStateRepository:
    def __init__(self, path: str):
        self._path = path

    def load(self) -> States:
        try:
            with open(self._path, encoding="utf-8") as f:
                raw = json.load(f)
            known = TargetState.__dataclass_fields__
            return {key: TargetState(**{k: v for k, v in value.items() if k in known})
                    for key, value in raw.items()}
        except FileNotFoundError:
            return {}
        except (ValueError, TypeError, AttributeError) as e:
            log.warning("Файл состояния %s повреждён, начинаю с нуля: %s", self._path, e)
            return {}

    def save(self, states: States) -> None:
        tmp = f"{self._path}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({k: asdict(v) for k, v in states.items()}, f, ensure_ascii=False, indent=1)
        os.replace(tmp, self._path)
