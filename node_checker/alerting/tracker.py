"""Машина состояний алертов — вся логика защиты от спама здесь.

  * алерт только при смене состояния (не работает / восстановлено);
  * «не работает» — после N неудач подряд, «восстановлено» — после M успехов подряд (гасит флаппинг);
  * пока проблема не ушла — редкие напоминания раз в remind_interval (0 = выкл);
  * состояние меняется только после успешной отправки (commit), иначе событие повторится.
"""
from __future__ import annotations

from typing import Iterable, List, Optional, Set

from ..config import AlertSettings
from ..models import Event, EventKind, Observation, TargetKind
from .repository import StateRepository, TargetState


class AlertTracker:
    def __init__(self, settings: AlertSettings, repository: StateRepository):
        self._settings = settings
        self._repository = repository
        self._states = repository.load()

    def observe(self, obs: Observation, now: float) -> Optional[Event]:
        state = self._states.setdefault(obs.key, TargetState())
        state.title = obs.title
        if obs.problem:
            return self._on_failure(obs, state, now)
        return self._on_success(obs, state)

    def commit(self, events: Iterable[Event], now: float) -> None:
        for event in events:
            if event.kind is EventKind.UP:
                self._states[event.key] = TargetState(title=event.title)
            else:
                state = self._states[event.key]
                state.down = True
                state.last_alert = now

    def retain_nodes(self, node_ids: Set[str]) -> None:
        """Забыть ноды, которых больше нет в панели."""
        node_kinds = (TargetKind.NODE.value, TargetKind.BLOCK.value)
        for key in list(self._states):
            kind, _, object_id = key.partition(":")
            if kind in node_kinds and object_id not in node_ids:
                del self._states[key]

    def save(self) -> None:
        self._repository.save(self._states)

    def _on_failure(self, obs: Observation, state: TargetState, now: float) -> Optional[Event]:
        state.oks = 0
        state.fails += 1
        state.reason = obs.problem
        state.since = state.since or now
        threshold = obs.threshold or self._settings.fail_threshold
        if not state.down and state.fails >= threshold:
            return self._event(EventKind.DOWN, obs, state)
        remind = self._settings.remind_interval
        if state.down and remind and now - state.last_alert >= remind:
            return self._event(EventKind.REMIND, obs, state)
        return None

    def _on_success(self, obs: Observation, state: TargetState) -> Optional[Event]:
        state.fails = 0
        if not state.down:
            state.since = 0.0
            return None
        state.oks += 1
        if state.oks >= self._settings.recover_threshold:
            return self._event(EventKind.UP, obs, state)
        return None

    @staticmethod
    def _event(kind: EventKind, obs: Observation, state: TargetState) -> Event:
        return Event(kind=kind, target=obs.kind, key=obs.key, title=obs.title,
                     reason=state.reason, since=state.since)


def collect(events: Iterable[Optional[Event]]) -> List[Event]:
    return [e for e in events if e]
