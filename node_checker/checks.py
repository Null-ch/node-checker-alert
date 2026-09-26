"""Проверки: каждая получает общий контекст цикла и возвращает наблюдения.

Проверки выполняются по порядку; PanelCheck кладёт список нод в контекст,
последующие проверки работают с ним и молча пропускают цикл, если панель недоступна.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Iterable, List, Optional, Protocol

from .config import ProbeSettings
from .models import Node, Observation, TargetKind
from .panel import PanelClient, PanelUnavailable
from .probes import Prober, ProbeResults
from .tgproxy import TelegramProxyClient

log = logging.getLogger(__name__)


@dataclass
class CycleContext:
    now: float
    nodes: Optional[List[Node]] = None          # None — панель недоступна
    panel_error: str = ""
    probe_results: Optional[ProbeResults] = None  # None — в этом цикле не проверялось
    tg_proxy_error: Optional[str] = None          # None — не проверялось, "" — работает


class HealthCheck(Protocol):
    def run(self, ctx: CycleContext) -> Iterable[Observation]: ...


class PanelCheck:
    def __init__(self, client: PanelClient, include_disabled: bool):
        self._client = client
        self._include_disabled = include_disabled

    def run(self, ctx: CycleContext) -> Iterable[Observation]:
        try:
            nodes = self._client.get_nodes()
        except PanelUnavailable as e:
            log.warning("Панель: %s", e)
            ctx.panel_error = str(e)
            return [Observation(TargetKind.PANEL, "", "Панель", str(e))]
        ctx.nodes = [n for n in nodes if self._include_disabled or not n.is_disabled]
        return [Observation(TargetKind.PANEL, "", "Панель", None)]


class NodeStatusCheck:
    def run(self, ctx: CycleContext) -> Iterable[Observation]:
        if ctx.nodes is None:
            return []
        observations = [Observation(TargetKind.NODE, n.id, n.label, n.problem) for n in ctx.nodes]
        broken = [o for o in observations if o.problem]
        for o in broken:
            log.info("Нода %s: %s", o.title, o.problem)
        log.info("Проверено нод: %d, проблемных: %d", len(observations), len(broken))
        return observations


class TelegramProxyCheck:
    """Доступность прокси к Telegram Bot API; от панели не зависит."""

    def __init__(self, client: TelegramProxyClient):
        self._client = client

    def run(self, ctx: CycleContext) -> Iterable[Observation]:
        problem = self._client.check()
        ctx.tg_proxy_error = problem or ""
        if problem:
            log.warning("%s: %s", self._client.title, problem)
        return [Observation(TargetKind.TG_PROXY, "", self._client.title, problem)]


class BlockingCheck:
    """Доступность нод из РФ. Проверяются только ноды, живые по мнению панели,
    иначе упавшая нода дала бы ещё и ложный алерт о блокировке."""

    def __init__(self, prober: Prober, settings: ProbeSettings):
        self._prober = prober
        self._settings = settings
        self._last_run = 0.0

    def run(self, ctx: CycleContext) -> Iterable[Observation]:
        if ctx.nodes is None or ctx.now - self._last_run < self._settings.interval:
            return []
        self._last_run = ctx.now
        candidates = {n.id: n for n in ctx.nodes if self._should_probe(n)}
        ctx.probe_results = self._prober.probe(list(candidates.values()))

        observations = []
        for node_id, reason in ctx.probe_results.items():
            node = candidates[node_id]
            if reason:
                log.info("Доступ из РФ, %s: %s", node.label, reason)
            observations.append(Observation(TargetKind.BLOCK, node_id, node.label, reason or None,
                                            threshold=self._settings.fail_threshold))
        log.info("Доступ из РФ (%s): проверено нод %d, с проблемами %d", self._prober.source,
                 len(observations), sum(1 for o in observations if o.problem))
        return observations

    def _should_probe(self, node: Node) -> bool:
        excluded = node.name.lower() in self._settings.exclude_nodes or node.address in self._settings.exclude_nodes
        return (node.is_healthy and bool(node.probe_targets) and not excluded
                and node.country not in self._settings.skip_countries)
