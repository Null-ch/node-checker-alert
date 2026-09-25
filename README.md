# node-checker

Мониторинг панели Remnawave и её нод с алертами в Telegram. Только стандартная библиотека Python 3.10+.

## Что проверяется
Раз в `CHECK_INTERVAL` секунд — `GET {PANEL_URL}/api/nodes`:
- **Панель**: таймаут, сетевые ошибки, HTTP 5xx, 401/403 (протух токен), не-JSON ответ.
- **Ноды**: `isDisabled` (отключена), `!isConnected` (упала, с `lastStatusMessage`), `isNodeOnline=false`, `isXrayRunning=false`.

## Защита от спама
- Алерт уходит только при смене состояния: 🔴 «не работает» → 🟢 «восстановлено» (с длительностью простоя).
- 🔴 отправляется после `FAIL_THRESHOLD` неудачных проверок подряд, 🟢 — после `RECOVER_THRESHOLD` удачных. Это гасит флаппинг.
- Пока проблема не ушла — одно напоминание 🟠 раз в `REMIND_INTERVAL` (0 = выкл).
- Все события за цикл идут одним сообщением.
- Если недоступна панель, ноды не проверяются — не будет «упали все 18 нод».
- Состояние хранится в `STATE_FILE`, поэтому рестарт не вызывает повторных алертов.
- Если Telegram не принял сообщение, событие повторяется в следующем цикле, а не теряется.

## Запуск
```bash
cp .env.example .env        # заполнить PANEL_API_TOKEN, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
docker compose up -d --build
docker compose logs -f
```
Без Docker: `python node_checker.py`

Отладка:
```bash
python node_checker.py --test-telegram     # тестовое сообщение в чат
python node_checker.py --once --dry-run    # одна проверка, алерты печатаются в консоль
```
Все переменные описаны в `.env.example`.
