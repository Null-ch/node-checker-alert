"""Тексты сообщений для Telegram (HTML-разметка)."""
from __future__ import annotations

from html import escape
from typing import TYPE_CHECKING, List, Optional, Sequence

from ..models import Event, EventKind, TargetKind

if TYPE_CHECKING:
    from ..checks import CycleContext


def fmt_duration(seconds: float) -> str:
    seconds = int(max(0, seconds))
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    parts = [f"{v} {u}" for v, u in ((days, "д"), (hours, "ч"), (minutes, "мин")) if v]
    return " ".join(parts[:2]) if parts else f"{seconds} сек"


class HtmlMessageFormatter:
    SECTIONS = (
        (EventKind.DOWN, "🔴 <b>Не работает</b>"),
        (EventKind.REMIND, "🟠 <b>Всё ещё не работает</b>"),
        (EventKind.UP, "🟢 <b>Восстановлено</b>"),
    )
    TARGET_ORDER = {TargetKind.PANEL: 0, TargetKind.TG_PROXY: 1, TargetKind.NODE: 2, TargetKind.BLOCK: 3}

    def __init__(self, title: str):
        self._title = escape(title)

    def events(self, events: Sequence[Event], now: float) -> str:
        lines = [f"<b>{self._title}</b>"]
        for kind, header in self.SECTIONS:
            items = sorted((e for e in events if e.kind is kind),
                           key=lambda e: (self.TARGET_ORDER[e.target], e.title.lower()))
            if items:
                lines += ["", header]
                lines += [f"• <b>{escape(self._subject(e))}</b>: {self._details(e, now)}" for e in items]
        return "\n".join(lines)

    def report(self, ctx: "CycleContext", probe_source: Optional[str]) -> str:
        lines = [f"ℹ️ <b>{self._title}</b>: мониторинг запущен", ""]
        lines += self._tg_proxy_lines(ctx)
        if ctx.panel_error:
            lines.append(f"❌ Панель: {escape(ctx.panel_error)}")
            return "\n".join(lines)

        nodes = ctx.nodes or []
        broken = [n for n in nodes if not n.is_healthy]
        lines.append("✅ Панель доступна")
        lines.append(f"{'⚠️' if broken else '✅'} Ноды: работают {len(nodes) - len(broken)} из {len(nodes)}")
        lines += [f"  • <b>{escape(n.label)}</b>: {escape(n.problem)}" for n in broken]
        lines += self._probe_lines(ctx, probe_source)
        return "\n".join(lines)

    def test(self) -> str:
        return f"✅ <b>{self._title}</b>: тестовое сообщение node-checker"

    @staticmethod
    def _tg_proxy_lines(ctx: "CycleContext") -> List[str]:
        if ctx.tg_proxy_error is None:
            return []
        if ctx.tg_proxy_error:
            return [f"❌ Telegram-прокси: {escape(ctx.tg_proxy_error)}"]
        return ["✅ Telegram-прокси доступен"]

    @staticmethod
    def _probe_lines(ctx: "CycleContext", probe_source: Optional[str]) -> List[str]:
        if probe_source is None:
            return ["⚪ Проверка доступа из РФ выключена (PROBE_MODE=off)"]
        if not ctx.probe_results:
            return [f"⚪ Доступ из РФ ({probe_source}): нет данных, см. логи"]
        labels = {n.id: n.label for n in ctx.nodes or []}
        blocked = {node_id: reason for node_id, reason in ctx.probe_results.items() if reason}
        lines = [f"{'🚫' if blocked else '✅'} Доступ из РФ ({probe_source}): "
                 f"проверено нод {len(ctx.probe_results)}, с проблемами {len(blocked)}"]
        lines += [f"  • <b>{escape(labels.get(i, i))}</b>: {escape(r)}" for i, r in blocked.items()]
        return lines

    @staticmethod
    def _subject(e: Event) -> str:
        return f"🚫 {e.title} — доступ из РФ" if e.target is TargetKind.BLOCK else e.title

    @staticmethod
    def _details(e: Event, now: float) -> str:
        if e.kind is EventKind.UP:
            return f"простой {fmt_duration(now - e.since)}"
        if e.kind is EventKind.REMIND:
            return f"{fmt_duration(now - e.since)} — {escape(e.reason)}"
        return escape(e.reason)
