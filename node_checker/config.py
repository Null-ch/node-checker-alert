"""Настройки сервиса из переменных окружения."""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping, MutableMapping


class ConfigError(Exception):
    pass


def load_dotenv(path: str = ".env", environ: MutableMapping[str, str] = os.environ) -> None:
    """Минимальный загрузчик .env: не перетирает уже заданные переменные окружения."""
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                environ.setdefault(key.strip(), value.strip().strip("'\""))
    except FileNotFoundError:
        pass


class EnvReader:
    """Типизированное чтение переменных окружения."""

    def __init__(self, env: Mapping[str, str]):
        self._env = env

    def str(self, name: str, default: str = "") -> str:
        return (self._env.get(name) or "").strip().strip("'\"") or default

    def int(self, name: str, default: int, minimum: int = 0) -> int:
        raw = self.str(name)
        try:
            value = int(raw) if raw else default
        except ValueError as e:
            raise ConfigError(f"{name} должно быть целым числом, получено {raw!r}") from e
        return max(minimum, value)

    def bool(self, name: str, default: bool) -> bool:
        raw = self.str(name).lower()
        return raw in ("1", "true", "yes", "on") if raw else default

    def list(self, name: str, default: str = "") -> tuple:
        return tuple(item.strip() for item in self.str(name, default).split(",") if item.strip())


@dataclass(frozen=True)
class PanelSettings:
    api_base: str
    token: str
    timeout: int


@dataclass(frozen=True)
class TelegramSettings:
    bot_token: str
    chat_id: str
    thread_id: str
    timeout: int


@dataclass(frozen=True)
class AlertSettings:
    fail_threshold: int
    recover_threshold: int
    remind_interval: int
    alert_on_disabled: bool


@dataclass(frozen=True)
class ProbeSettings:
    mode: str                       # off | local | checkhost
    interval: int
    timeout: int
    fail_threshold: int
    skip_countries: tuple
    exclude_nodes: tuple            # имена или адреса нод, lower-case
    freeze_check: bool
    control: str
    checkhost_nodes: tuple
    checkhost_control_nodes: tuple

    @property
    def enabled(self) -> bool:
        return self.mode != "off"


PROBE_MODES = ("off", "local", "checkhost")
REQUIRED = ("PANEL_URL", "PANEL_API_TOKEN", "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID")


@dataclass(frozen=True)
class Settings:
    title: str
    check_interval: int
    startup_report: bool
    state_file: str
    log_level: str
    panel: PanelSettings
    telegram: TelegramSettings
    alerts: AlertSettings
    probe: ProbeSettings

    @classmethod
    def from_env(cls, env: Mapping[str, str] = os.environ) -> "Settings":
        e = EnvReader(env)
        missing = [name for name in REQUIRED if not e.str(name)]
        if missing:
            raise ConfigError(f"Не заданы переменные окружения: {', '.join(missing)}")

        api_base = e.str("PANEL_URL").rstrip("/")
        if not api_base.endswith("/api"):
            api_base += "/api"

        probe_mode = e.str("PROBE_MODE", "off").lower()
        if probe_mode not in PROBE_MODES:
            raise ConfigError(f"PROBE_MODE должен быть одним из: {', '.join(PROBE_MODES)}")

        timeout = e.int("REQUEST_TIMEOUT", 15, minimum=1)
        return cls(
            title=e.str("PANEL_NAME", "Remnawave"),
            check_interval=e.int("CHECK_INTERVAL", 60, minimum=10),
            startup_report=e.bool("STARTUP_MESSAGE", True),
            state_file=e.str("STATE_FILE", "state.json"),
            log_level=e.str("LOG_LEVEL", "INFO").upper(),
            panel=PanelSettings(api_base=api_base, token=e.str("PANEL_API_TOKEN"), timeout=timeout),
            telegram=TelegramSettings(
                bot_token=e.str("TELEGRAM_BOT_TOKEN"),
                chat_id=e.str("TELEGRAM_CHAT_ID"),
                thread_id=e.str("TELEGRAM_THREAD_ID"),
                timeout=timeout,
            ),
            alerts=AlertSettings(
                fail_threshold=e.int("FAIL_THRESHOLD", 3, minimum=1),
                recover_threshold=e.int("RECOVER_THRESHOLD", 2, minimum=1),
                remind_interval=e.int("REMIND_INTERVAL", 10800),
                alert_on_disabled=e.bool("ALERT_ON_DISABLED", True),
            ),
            probe=ProbeSettings(
                mode=probe_mode,
                interval=e.int("PROBE_INTERVAL", 600, minimum=60),
                timeout=e.int("PROBE_TIMEOUT", 8, minimum=2),
                fail_threshold=e.int("PROBE_FAIL_THRESHOLD", 2, minimum=1),
                skip_countries=tuple(c.upper() for c in e.list("PROBE_SKIP_COUNTRIES", "RU")),
                exclude_nodes=tuple(n.lower() for n in e.list("PROBE_EXCLUDE_NODES")),
                freeze_check=e.bool("PROBE_FREEZE_CHECK", True),
                control=e.str("PROBE_CONTROL", "ya.ru:443"),
                checkhost_nodes=e.list(
                    "CHECKHOST_NODES",
                    "ru1.node.check-host.net,ru2.node.check-host.net,ru3.node.check-host.net"),
                checkhost_control_nodes=e.list("CHECKHOST_CONTROL_NODES", "de1.node.check-host.net"),
            ),
        )
