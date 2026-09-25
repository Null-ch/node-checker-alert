"""Доменные модели: ноды, наблюдения, события алертов."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


@dataclass(frozen=True)
class ProbeTarget:
    """Порт инбаунда ноды, доступность которого проверяется извне."""
    port: int
    sni: str = ""           # пусто — проверяется только TCP


@dataclass(frozen=True)
class Node:
    id: str
    name: str
    address: str
    country: str = ""
    is_disabled: bool = False
    is_connected: bool = True
    is_node_online: Optional[bool] = None       # в части версий Remnawave поля нет
    is_xray_running: Optional[bool] = None
    last_status_message: str = ""
    probe_targets: tuple = field(default_factory=tuple)

    @property
    def label(self) -> str:
        return f"{self.name} ({self.address})" if self.address else self.name

    @property
    def problem(self) -> Optional[str]:
        """Причина неработоспособности или None, если нода в порядке."""
        if self.is_disabled:
            return "отключена в панели"
        if not self.is_connected:
            return "не подключена" + (f": {self.last_status_message}" if self.last_status_message else "")
        if self.is_node_online is False:
            return "нода офлайн"
        if self.is_xray_running is False:
            return "Xray не запущен"
        return None

    @property
    def is_healthy(self) -> bool:
        return self.problem is None


class TargetKind(str, Enum):
    PANEL = "panel"
    NODE = "node"
    BLOCK = "block"


@dataclass(frozen=True)
class Observation:
    """Результат одной проверки одного объекта."""
    kind: TargetKind
    object_id: str
    title: str
    problem: Optional[str]              # None — всё в порядке
    threshold: Optional[int] = None     # своё число неудач до алерта (иначе общее)

    @property
    def key(self) -> str:
        return self.kind.value if self.kind is TargetKind.PANEL else f"{self.kind.value}:{self.object_id}"


class EventKind(str, Enum):
    DOWN = "down"
    REMIND = "remind"
    UP = "up"


@dataclass(frozen=True)
class Event:
    kind: EventKind
    target: TargetKind
    key: str
    title: str
    reason: str
    since: float
