"""Проверка доступности нод из РФ через узлы check-host.net."""
from __future__ import annotations

import logging
import time
import urllib.parse
from typing import Callable, Dict, Optional, Sequence, Tuple

from ..config import ProbeSettings
from ..http import JsonHttpClient
from ..models import Node
from .base import ProbeResults, merge_port_verdicts

log = logging.getLogger(__name__)

API = "https://check-host.net"


class CheckHostClient:
    def __init__(self, http: JsonHttpClient):
        self._http = http

    def start_tcp(self, host: str, port: int, nodes: Sequence[str]) -> str:
        query = urllib.parse.urlencode([("host", f"{host}:{port}")] + [("node", n) for n in nodes])
        data = self._http.get(f"{API}/check-tcp?{query}")
        if not isinstance(data, dict) or not data.get("request_id"):
            raise ValueError(f"неожиданный ответ check-host: {data}")
        return data["request_id"]

    def result(self, request_id: str) -> dict:
        return self._http.get(f"{API}/check-result/{request_id}") or {}


def tcp_verdict(results: dict, probe_nodes: Sequence[str], control_nodes: Sequence[str]) -> Optional[str]:
    """Причина проблемы, "" если порт доступен из РФ, None если данных нет."""
    def split(nodes):
        ok, errors = [], []
        for node in nodes:
            items = results.get(node) or []
            entry = items[0] if items and isinstance(items[0], dict) else None
            if entry is not None:
                (errors if entry.get("error") else ok).append((node.split(".")[0], entry.get("error")))
        return ok, errors

    ru_ok, ru_errors = split(probe_nodes)
    if not ru_ok and not ru_errors:
        return None
    if len(ru_errors) <= len(ru_ok):
        return ""
    control_ok, control_errors = split(control_nodes)
    where = ", ".join(f"{node}: {error}" for node, error in ru_errors)
    if control_ok:
        return f"недоступен из РФ ({where}), из-за рубежа доступен — вероятна блокировка ТСПУ"
    if control_errors:
        return f"недоступен ни из РФ, ни из-за рубежа ({where})"
    return f"недоступен из РФ ({where})"


class CheckHostProber:
    source = "через check-host.net"

    def __init__(self, settings: ProbeSettings, client: CheckHostClient,
                 sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.time,
                 submit_delay: float = 0.5, first_poll_delay: float = 8, poll_delay: float = 3,
                 max_wait: float = 40):
        self._settings = settings
        self._client = client
        self._sleep = sleep
        self._clock = clock
        self._submit_delay = submit_delay
        self._first_poll_delay = first_poll_delay
        self._poll_delay = poll_delay
        self._max_wait = max_wait

    @property
    def _all_nodes(self) -> tuple:
        return self._settings.checkhost_nodes + self._settings.checkhost_control_nodes

    def probe(self, nodes: Sequence[Node]) -> ProbeResults:
        pending = self._submit(nodes)
        if not pending:
            return {}
        verdicts = []
        deadline = self._clock() + self._max_wait
        self._sleep(self._first_poll_delay)
        while pending:
            final = self._clock() + self._poll_delay >= deadline
            for key, request_id in list(pending.items()):
                results = self._fetch(request_id)
                if results is None or not (final or self._complete(results)):
                    continue
                verdicts.append((*key, tcp_verdict(results, self._settings.checkhost_nodes,
                                                   self._settings.checkhost_control_nodes)))
                del pending[key]
            if final:
                break
            if pending:
                self._sleep(self._poll_delay)
        return merge_port_verdicts(verdicts)

    def _submit(self, nodes: Sequence[Node]) -> Dict[Tuple[str, int], str]:
        requests = {}
        for node in nodes:
            for target in node.probe_targets:
                try:
                    requests[(node.id, target.port)] = self._client.start_tcp(
                        node.address, target.port, self._all_nodes)
                except (OSError, ValueError) as e:
                    log.warning("check-host: %s:%s — %s", node.address, target.port, e)
                self._sleep(self._submit_delay)
        return requests

    def _fetch(self, request_id: str) -> Optional[dict]:
        try:
            return self._client.result(request_id)
        except (OSError, ValueError) as e:
            log.warning("check-host result %s: %s", request_id, e)
            return None

    def _complete(self, results: dict) -> bool:
        return all(results.get(node) is not None for node in self._all_nodes)
