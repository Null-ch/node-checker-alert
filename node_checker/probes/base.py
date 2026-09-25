"""Общий интерфейс пробников доступности нод из РФ."""
from __future__ import annotations

from typing import Dict, Iterable, Optional, Protocol, Sequence, Tuple

from ..models import Node

# node_id -> причина проблемы; "" — доступна. Ноды без данных в результат не попадают.
ProbeResults = Dict[str, str]


class Prober(Protocol):
    source: str             # откуда проверяем — для отчёта

    def probe(self, nodes: Sequence[Node]) -> ProbeResults: ...


def merge_port_verdicts(verdicts: Iterable[Tuple[str, int, Optional[str]]]) -> ProbeResults:
    """Сводит результаты по портам в один вердикт на ноду. None — нет данных по порту."""
    results: ProbeResults = {}
    for node_id, port, reason in verdicts:
        if reason is None:
            continue
        if reason:
            previous = results.get(node_id)
            line = f"порт {port}: {reason}"
            results[node_id] = f"{previous}; {line}" if previous else line
        else:
            results.setdefault(node_id, "")
    return results
