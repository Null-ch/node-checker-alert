#!/usr/bin/env python3
"""Мониторинг панели Remnawave и её нод с алертами в Telegram.

Защита от спама:
  * алерт уходит только при смене состояния (упало / восстановилось);
  * «упало» фиксируется только после FAIL_THRESHOLD неудачных проверок подряд,
    «восстановилось» — после RECOVER_THRESHOLD удачных (гасит флаппинг);
  * пока проблема не ушла — только редкие напоминания раз в REMIND_INTERVAL (0 = выкл);
  * все события за один цикл склеиваются в одно сообщение;
  * если лежит сама панель, статусы нод не оцениваются (не шлём «упали все ноды»);
  * состояние хранится в STATE_FILE, поэтому рестарт сервиса не вызывает повторных алертов.
"""
import argparse
import html
import json
import logging
import os
import signal
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field

log = logging.getLogger("node-checker")

PANEL_KEY = "panel"


# --------------------------------------------------------------------------- config

def load_dotenv(path: str = ".env") -> None:
    """Минимальный загрузчик .env: не перетирает уже заданные переменные окружения."""
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                os.environ.setdefault(key.strip(), value.strip().strip("'\""))
    except FileNotFoundError:
        pass


def env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    return int(raw) if raw else default


def env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    return raw in ("1", "true", "yes", "on") if raw else default


@dataclass
class Config:
    api_base: str
    panel_token: str
    bot_token: str
    chat_id: str
    thread_id: str
    panel_name: str
    check_interval: int
    fail_threshold: int
    recover_threshold: int
    remind_interval: int
    request_timeout: int
    alert_on_disabled: bool
    startup_message: bool
    state_file: str

    @classmethod
    def from_env(cls) -> "Config":
        required = ("PANEL_URL", "PANEL_API_TOKEN", "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID")
        missing = [name for name in required if not os.environ.get(name, "").strip()]
        if missing:
            sys.exit(f"Не заданы переменные окружения: {', '.join(missing)}")

        api_base = os.environ["PANEL_URL"].strip().rstrip("/")
        if not api_base.endswith("/api"):
            api_base += "/api"

        return cls(
            api_base=api_base,
            panel_token=os.environ["PANEL_API_TOKEN"].strip(),
            bot_token=os.environ["TELEGRAM_BOT_TOKEN"].strip(),
            chat_id=os.environ["TELEGRAM_CHAT_ID"].strip(),
            thread_id=os.environ.get("TELEGRAM_THREAD_ID", "").strip(),
            panel_name=os.environ.get("PANEL_NAME", "").strip() or "Remnawave",
            check_interval=max(10, env_int("CHECK_INTERVAL", 60)),
            fail_threshold=max(1, env_int("FAIL_THRESHOLD", 3)),
            recover_threshold=max(1, env_int("RECOVER_THRESHOLD", 2)),
            remind_interval=max(0, env_int("REMIND_INTERVAL", 10800)),
            request_timeout=max(1, env_int("REQUEST_TIMEOUT", 15)),
            alert_on_disabled=env_bool("ALERT_ON_DISABLED", True),
            startup_message=env_bool("STARTUP_MESSAGE", True),
            state_file=os.environ.get("STATE_FILE", "").strip() or "state.json",
        )


# --------------------------------------------------------------------------- http

def http_json(method: str, url: str, headers: dict, body=None, timeout: int = 15):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
    return json.loads(raw) if raw else None


# --------------------------------------------------------------------------- panel

class PanelError(Exception):
    pass


def fetch_nodes(cfg: Config) -> list:
    headers = {
        "Authorization": f"Bearer {cfg.panel_token}",
        "Accept": "application/json",
        "User-Agent": "node-checker/1.0",
        # Remnawave требует эти заголовки, если обращаться к бэкенду в обход reverse-proxy
        "X-Forwarded-For": "127.0.0.1",
        "X-Forwarded-Proto": "https",
    }
    try:
        data = http_json("GET", f"{cfg.api_base}/nodes", headers, timeout=cfg.request_timeout)
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            raise PanelError(f"HTTP {e.code} — API-токен неверный или просрочен") from e
        raise PanelError(f"HTTP {e.code} {e.reason}") from e
    except urllib.error.URLError as e:
        raise PanelError(f"недоступна: {e.reason}") from e
    except TimeoutError as e:
        raise PanelError(f"нет ответа за {cfg.request_timeout} сек") from e
    except json.JSONDecodeError as e:
        raise PanelError("ответ не JSON (заглушка прокси / страница ошибки?)") from e
    except OSError as e:
        raise PanelError(f"ошибка соединения: {e}") from e

    nodes = data.get("response") if isinstance(data, dict) else data
    if not isinstance(nodes, list):
        raise PanelError("неожиданный формат ответа /api/nodes")
    return nodes


def node_problem(node: dict):
    """Причина неработоспособности ноды или None, если всё в порядке."""
    if node.get("isDisabled"):
        return "отключена в панели"
    if not node.get("isConnected", True):
        message = (node.get("lastStatusMessage") or "").strip()
        return "не подключена" + (f": {message}" if message else "")
    if node.get("isNodeOnline") is False:
        return "нода офлайн"
    if node.get("isXrayRunning") is False:
        return "Xray не запущен"
    return None


def node_label(node: dict) -> str:
    name = node.get("name") or node.get("uuid") or "?"
    address = node.get("address")
    return f"{name} ({address})" if address else name


# --------------------------------------------------------------------------- state

@dataclass
class Target:
    name: str = ""
    reason: str = ""
    fails: int = 0          # неудачных проверок подряд
    oks: int = 0            # удачных проверок подряд после алерта
    down: bool = False      # алерт «упало» уже отправлен
    since: float = 0.0      # время первой неудачной проверки
    last_alert: float = 0.0


@dataclass
class Event:
    kind: str               # down | remind | up
    key: str
    name: str
    reason: str
    since: float


@dataclass
class Monitor:
    cfg: Config
    targets: dict = field(default_factory=dict)

    def load(self) -> None:
        try:
            with open(self.cfg.state_file, encoding="utf-8") as f:
                raw = json.load(f)
            self.targets = {key: Target(**value) for key, value in raw.items()}
            log.info("Загружено состояние: %d объектов", len(self.targets))
        except FileNotFoundError:
            pass
        except (ValueError, TypeError) as e:
            log.warning("Файл состояния повреждён, начинаю с нуля: %s", e)

    def save(self) -> None:
        tmp = self.cfg.state_file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({k: asdict(v) for k, v in self.targets.items()}, f, ensure_ascii=False, indent=1)
        os.replace(tmp, self.cfg.state_file)

    def observe(self, key: str, name: str, problem, now: float):
        t = self.targets.setdefault(key, Target())
        t.name = name
        if problem:
            t.oks = 0
            t.fails += 1
            t.reason = problem
            if not t.since:
                t.since = now
            if not t.down and t.fails >= self.cfg.fail_threshold:
                return Event("down", key, name, problem, t.since)
            if (t.down and self.cfg.remind_interval
                    and now - t.last_alert >= self.cfg.remind_interval):
                return Event("remind", key, name, problem, t.since)
            return None

        t.fails = 0
        if not t.down:
            t.since = 0.0
            return None
        t.oks += 1
        if t.oks >= self.cfg.recover_threshold:
            return Event("up", key, name, t.reason, t.since)
        return None

    def commit(self, events: list, now: float) -> None:
        """Вызывается только после успешной отправки — иначе события повторятся в след. цикле."""
        for e in events:
            if e.kind == "up":
                self.targets[e.key] = Target(name=e.name)
            else:
                t = self.targets[e.key]
                t.down = True
                t.last_alert = now

    def forget_missing_nodes(self, seen: set) -> None:
        for key in [k for k in self.targets if k != PANEL_KEY and k not in seen]:
            del self.targets[key]


# --------------------------------------------------------------------------- telegram

class Telegram:
    LIMIT = 4000

    def __init__(self, cfg: Config, dry_run: bool = False):
        self.cfg = cfg
        self.dry_run = dry_run

    def send(self, text: str) -> bool:
        if self.dry_run:
            print("----- TELEGRAM (dry-run) -----\n" + text + "\n------------------------------")
            return True
        return all(self._send_chunk(chunk) for chunk in self._split(text))

    def _split(self, text: str) -> list:
        chunks, current = [], ""
        for line in text.split("\n"):
            if current and len(current) + len(line) + 1 > self.LIMIT:
                chunks.append(current)
                current = ""
            current = f"{current}\n{line}" if current else line
        if current:
            chunks.append(current)
        return chunks

    def _send_chunk(self, text: str) -> bool:
        url = f"https://api.telegram.org/bot{self.cfg.bot_token}/sendMessage"
        body = {
            "chat_id": self.cfg.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        if self.cfg.thread_id:
            body["message_thread_id"] = int(self.cfg.thread_id)

        for attempt in range(1, 4):
            try:
                http_json("POST", url, {"Content-Type": "application/json"}, body,
                          timeout=self.cfg.request_timeout)
                return True
            except urllib.error.HTTPError as e:
                details = e.read().decode(errors="replace")
                if e.code == 429:
                    try:
                        retry_after = json.loads(details)["parameters"]["retry_after"]
                    except (ValueError, KeyError, TypeError):
                        retry_after = 5
                    log.warning("Telegram 429, жду %s сек", retry_after)
                    time.sleep(min(int(retry_after), 60))
                    continue
                log.error("Telegram HTTP %s: %s", e.code, details)
                return False
            except OSError as e:
                log.warning("Telegram недоступен (попытка %d): %s", attempt, e)
                time.sleep(3 * attempt)
        return False


# --------------------------------------------------------------------------- formatting

def fmt_duration(seconds: float) -> str:
    seconds = int(max(0, seconds))
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    parts = []
    if days:
        parts.append(f"{days} д")
    if hours:
        parts.append(f"{hours} ч")
    if minutes:
        parts.append(f"{minutes} мин")
    return " ".join(parts[:2]) if parts else f"{seconds} сек"


def format_events(cfg: Config, events: list, now: float) -> str:
    esc = html.escape
    sections = (
        ("down", "🔴 <b>Не работает</b>", lambda e: esc(e.reason)),
        ("remind", "🟠 <b>Всё ещё не работает</b>",
         lambda e: f"{fmt_duration(now - e.since)} — {esc(e.reason)}"),
        ("up", "🟢 <b>Восстановлено</b>", lambda e: f"простой {fmt_duration(now - e.since)}"),
    )
    lines = [f"<b>{esc(cfg.panel_name)}</b>"]
    for kind, title, describe in sections:
        items = [e for e in events if e.kind == kind]
        if not items:
            continue
        lines += ["", title]
        # панель всегда первой, дальше ноды по имени
        items.sort(key=lambda e: (e.key != PANEL_KEY, e.name.lower()))
        lines += [f"• <b>{esc(e.name)}</b>: {describe(e)}" for e in items]
    return "\n".join(lines)


# --------------------------------------------------------------------------- main loop

def run_cycle(cfg: Config, monitor: Monitor, telegram: Telegram) -> None:
    now = time.time()
    events = []

    try:
        nodes = fetch_nodes(cfg)
    except PanelError as e:
        log.warning("Панель: %s", e)
        events.append(monitor.observe(PANEL_KEY, "Панель", str(e), now))
    else:
        events.append(monitor.observe(PANEL_KEY, "Панель", None, now))
        seen = set()
        for node in nodes:
            if node.get("isDisabled") and not cfg.alert_on_disabled:
                continue
            key = f"node:{node.get('uuid') or node.get('name')}"
            seen.add(key)
            problem = node_problem(node)
            if problem:
                log.info("Нода %s: %s", node_label(node), problem)
            events.append(monitor.observe(key, node_label(node), problem, now))
        monitor.forget_missing_nodes(seen)
        log.info("Проверено нод: %d, проблемных: %d", len(seen),
                 sum(1 for k in seen if monitor.targets[k].fails))

    events = [e for e in events if e]
    if events:
        if telegram.send(format_events(cfg, events, now)):
            monitor.commit(events, now)
        else:
            log.error("Не удалось отправить алерт, повторю в следующем цикле")
    monitor.save()


def main() -> None:
    parser = argparse.ArgumentParser(description="Мониторинг панели Remnawave и нод")
    parser.add_argument("--once", action="store_true", help="выполнить одну проверку и выйти")
    parser.add_argument("--dry-run", action="store_true", help="печатать алерты в консоль вместо Telegram")
    parser.add_argument("--test-telegram", action="store_true", help="отправить тестовое сообщение и выйти")
    args = parser.parse_args()

    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", errors="replace")
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(message)s",
    )
    load_dotenv()
    cfg = Config.from_env()
    telegram = Telegram(cfg, dry_run=args.dry_run)

    if args.test_telegram:
        ok = telegram.send(f"✅ <b>{html.escape(cfg.panel_name)}</b>: тестовое сообщение node-checker")
        sys.exit(0 if ok else 1)

    monitor = Monitor(cfg)
    monitor.load()

    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())

    log.info("Старт: %s, интервал %d сек, порог %d/%d, напоминания %s",
             cfg.api_base, cfg.check_interval, cfg.fail_threshold, cfg.recover_threshold,
             f"раз в {fmt_duration(cfg.remind_interval)}" if cfg.remind_interval else "выкл")
    if cfg.startup_message and not args.once:
        telegram.send(f"ℹ️ <b>{html.escape(cfg.panel_name)}</b>: мониторинг запущен")

    while not stop.is_set():
        try:
            run_cycle(cfg, monitor, telegram)
        except Exception:
            log.exception("Ошибка в цикле проверки")
        if args.once:
            break
        stop.wait(cfg.check_interval)
    log.info("Остановлен")


if __name__ == "__main__":
    main()
