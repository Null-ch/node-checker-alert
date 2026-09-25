"""Точка сборки (composition root): создаёт зависимости и запускает сервис."""
from __future__ import annotations

import argparse
import logging
import signal
import sys
import threading

from .alerting import (AlertTracker, ConsoleNotifier, HtmlMessageFormatter, InMemoryStateRepository,
                       JsonFileStateRepository, TelegramNotifier, fmt_duration)
from .checks import BlockingCheck, NodeStatusCheck, PanelCheck
from .config import ConfigError, Settings, load_dotenv
from .http import JsonHttpClient
from .panel import RemnawaveClient
from .probes import create_prober
from .service import MonitorService

log = logging.getLogger("node_checker")


def build_service(settings: Settings, dry_run: bool = False) -> MonitorService:
    http = JsonHttpClient(timeout=settings.panel.timeout)
    prober = create_prober(settings.probe, http)

    checks = [
        PanelCheck(RemnawaveClient(settings.panel, http), include_disabled=settings.alerts.alert_on_disabled),
        NodeStatusCheck(),
    ]
    if prober:
        checks.append(BlockingCheck(prober, settings.probe))

    # в dry-run не трогаем боевое состояние, иначе рабочий контейнер потеряет алерты
    repository = InMemoryStateRepository() if dry_run else JsonFileStateRepository(settings.state_file)
    notifier = ConsoleNotifier() if dry_run else TelegramNotifier(settings.telegram, http)
    return MonitorService(
        checks=checks,
        tracker=AlertTracker(settings.alerts, repository),
        notifier=notifier,
        formatter=HtmlMessageFormatter(settings.title),
        probe_source=prober.source if prober else None,
    )


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="node_checker", description="Мониторинг панели Remnawave и нод")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--once", action="store_true", help="одна проверка (алерты по обычным правилам) и выход")
    mode.add_argument("--report", action="store_true", help="одна проверка и сводка в чат")
    mode.add_argument("--test-telegram", action="store_true", help="тестовое сообщение в чат")
    parser.add_argument("--dry-run", action="store_true",
                        help="печатать сообщения в консоль, состояние не сохранять")
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", errors="replace")

    load_dotenv()
    try:
        settings = Settings.from_env()
    except ConfigError as e:
        print(f"Ошибка конфигурации: {e}", file=sys.stderr)
        return 2
    logging.basicConfig(level=settings.log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    service = build_service(settings, dry_run=args.dry_run)

    if args.test_telegram:
        return 0 if service.send_test() else 1
    if args.once or args.report:
        ctx = service.run_cycle()
        return 0 if not args.report or service.send_report(ctx) else 1

    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())

    p = settings.probe
    log.info("Старт: %s, интервал %d сек, порог %d/%d, напоминания %s, доступ из РФ: %s",
             settings.panel.api_base, settings.check_interval,
             settings.alerts.fail_threshold, settings.alerts.recover_threshold,
             f"раз в {fmt_duration(settings.alerts.remind_interval)}" if settings.alerts.remind_interval else "выкл",
             f"{p.mode}, раз в {fmt_duration(p.interval)}" if p.enabled else "выкл")
    service.run_forever(settings.check_interval, stop, startup_report=settings.startup_report)
    log.info("Остановлен")
    return 0
