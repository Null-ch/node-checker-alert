"""Оркестратор: прогоняет проверки, пропускает наблюдения через трекер, отправляет алерты."""
from __future__ import annotations

import logging
import threading
import time
from typing import Callable, Optional, Sequence

from .alerting import AlertTracker, HtmlMessageFormatter, Notifier
from .alerting.tracker import collect
from .checks import CycleContext, HealthCheck

log = logging.getLogger(__name__)


class MonitorService:
    def __init__(self, checks: Sequence[HealthCheck], tracker: AlertTracker, notifier: Notifier,
                 formatter: HtmlMessageFormatter, probe_source: Optional[str] = None,
                 clock: Callable[[], float] = time.time):
        self._checks = checks
        self._tracker = tracker
        self._notifier = notifier
        self._formatter = formatter
        self._probe_source = probe_source
        self._clock = clock

    def run_cycle(self) -> CycleContext:
        ctx = CycleContext(now=self._clock())
        observations = [obs for check in self._checks for obs in check.run(ctx)]
        if ctx.nodes is not None:
            self._tracker.retain_nodes({n.id for n in ctx.nodes})
        events = collect(self._tracker.observe(obs, ctx.now) for obs in observations)

        if events:
            if self._notifier.send(self._formatter.events(events, ctx.now)):
                self._tracker.commit(events, ctx.now)
            else:
                log.error("Не удалось отправить алерт, повторю в следующем цикле")
        self._tracker.save()
        return ctx

    def send_report(self, ctx: CycleContext) -> bool:
        return self._notifier.send(self._formatter.report(ctx, self._probe_source))

    def send_test(self) -> bool:
        return self._notifier.send(self._formatter.test())

    def run_forever(self, interval: int, stop: threading.Event, startup_report: bool) -> None:
        first = True
        while not stop.is_set():
            try:
                ctx = self.run_cycle()
                if first and startup_report:
                    self.send_report(ctx)
            except Exception:
                log.exception("Ошибка в цикле проверки")
            first = False
            stop.wait(interval)
