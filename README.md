# node-checker

Мониторинг панели Remnawave, её нод и доступности нод из РФ с алертами в Telegram.
Только стандартная библиотека Python 3.10+.

## Что проверяется
Раз в `CHECK_INTERVAL` секунд — `GET {PANEL_URL}/api/nodes`:
- **Панель**: таймаут, сетевые ошибки, HTTP 5xx, 401/403 (протух токен), не-JSON ответ.
- **Ноды**: `isDisabled`, `!isConnected` (с `lastStatusMessage`), `isNodeOnline=false`, `isXrayRunning=false`.
- **Доступ из РФ** (раз в `PROBE_INTERVAL`, если `PROBE_MODE` не `off`): TCP-порты активных инбаундов
  нод, которые панель считает живыми. Инбаунды на `127.0.0.1` / unix-сокетах пропускаются.
  - `checkhost` — узлы check-host.net в Москве и СПб + контрольный узел в Германии.
    Доступен из-за рубежа, но не из РФ → «вероятна блокировка ТСПУ».
  - `local` — проверка с сервера, где запущен сервис (только если он в РФ): TCP, TLS-рукопожатие
    с SNI из Reality и скачивание страницы через ноду, чтобы поймать «заморозку» после ~16 КБ.

При старте в чат уходит сводка: панель, ноды, результат проверки доступа из РФ.

## Защита от спама
- Алерт только при смене состояния: 🔴 «не работает» → 🟢 «восстановлено» (с длительностью простоя).
- 🔴 после `FAIL_THRESHOLD` неудач подряд (для блокировок — `PROBE_FAIL_THRESHOLD`), 🟢 после `RECOVER_THRESHOLD` успехов.
- Пока проблема не ушла — одно напоминание 🟠 раз в `REMIND_INTERVAL` (0 = выкл).
- Все события за цикл — одним сообщением.
- Если лежит панель, ноды не проверяются — не будет «упали все ноды».
- Состояние хранится в `STATE_FILE`: рестарт не вызывает повторных алертов.
- Если Telegram не принял сообщение, событие повторится в следующем цикле.

## Структура
```
node_checker/
  cli.py          точка сборки: создаёт зависимости, разбирает аргументы
  service.py      MonitorService — цикл: проверки → трекер → уведомление
  checks.py       HealthCheck: PanelCheck, NodeStatusCheck, BlockingCheck
  panel.py        клиент API Remnawave, JSON → доменные модели
  models.py       Node, Observation, Event
  config.py       Settings из переменных окружения
  http.py         JSON-клиент поверх urllib
  probes/         Prober: LocalProber, CheckHostProber (+ фабрика create_prober)
  alerting/       AlertTracker (антиспам), StateRepository, HtmlMessageFormatter, Notifier (Telegram / консоль)
```
Новая проверка — класс с методом `run(ctx) -> Iterable[Observation]`, добавленный в список в `cli.build_service`.
Новый канал уведомлений — класс с методом `send(text) -> bool`.

## Запуск
```bash
cp .env.example .env        # заполнить PANEL_API_TOKEN, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
docker compose up -d --build
docker compose logs -f
```
Без Docker: `python -m node_checker`

```bash
docker compose exec node-checker python -m node_checker --test-telegram      # тестовое сообщение
docker compose exec node-checker python -m node_checker --report             # сводка в чат сейчас
docker compose exec node-checker python -m node_checker --report --dry-run   # сводка в консоль
```
`--dry-run` не сохраняет состояние, поэтому не мешает работающему сервису.
