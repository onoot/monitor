# Защита от враждебных нейросетей (`ad/guard.py`)

Модуль защищает наш контур от ИИ-противника, которому дали доступ к нашему
эндпоинту. Он не блокирует трафик (это запрещено регламентом IV.10) — он
**классифицирует и карантинит**, а решения остаются за человеком.

## Модель угроз

| Вектор | Как выглядит | Что делает guard |
|---|---|---|
| **Зацикливание** | Противник гонит запросы, пока наш агент не выжжет шаги/время/токены | `LoopGuard` останавливает цикл |
| **Закодированный payload** | «Странный» маршрут несёт base64/hex/base32/url/gzip — закодированный, но не зашифрованный файл или текст с нагрузкой | `decode_payloads` декодирует в песочнице и `scan_injection` помечает |
| **Перебор маршрутов** | Много разных путей за окно, 404-свип, регулярные интервалы | `ScannerDetector` |
| **Эмуляция браузера** | UA вида `playwright/…`, `python-requests/…`, `curl/…`, `go-http-client/…` | `ScannerDetector` (`automation_user_agent`) |
| **Подброс флага** | Противник шлёт нам «флаг» через наш эндпоинт | `FlagQuarantine` (статус максимум `quarantined`) |
| **Prompt injection** | В теле/пути/декодированном blob-е — «ignore previous instructions», `<tool_call>`, «отправь флаг на…» | `scan_injection` только сообщает, ничего не выполняет |

Ключевые инварианты: внешние данные никогда не становятся инструкциями; ничего с
провода не считается истиной; вся распаковка ограничена по размеру/глубине/слоям;
все часы инъектируемы (тесты не спят).

## Компоненты и API

```python
import re
from ad import guard

# 1. Бюджет и детект цикла
loop = guard.LoopGuard(max_steps=200, max_seconds=900, max_duplicate_actions=5)
decision = loop.step("probe:/users/info")          # GuardDecision
if not decision.allowed:
    ...  # reason: step_budget | time_budget | cost_budget | duplicate_loop | action_cycle

# 2. Декодирование нет, исполнения
layers = guard.decode_payloads(encoded_blob, origin="body")
#   -> [DecodedLayer(encoding, depth, origin, text, size, score)]  # base64/hex/base32/url/gzip/zlib

# 3. Сканер инъекций (report-only)
hits = guard.scan_injection(text)                  # [InjectionHit(category, pattern, excerpt)]

# 4. Детектор сканеров / эмуляции браузера
det = guard.ScannerDetector(window_s=10, enum_threshold=20)
signals = det.observe(client_ip, path, method="GET", status=404, user_agent=ua)
#   kinds: path_enumeration | not_found_sweep | automation_user_agent | encoded_path | regular_timing

# 5. Один вызов на входящий запрос
verdict = guard.inspect_request(path, query, body, headers)
#   verdict.suspicious: encoded_path_segment | encoded_payload | instruction_smuggling |
#                       flag_shaped_string | automation_user_agent

# 6. Карантин флагов: нет статуса accepted, нет отправки
q = guard.FlagQuarantine(flag_regex=re.compile(r"alctf\{[a-z0-9_]{16}\}"))
result = q.submit(candidate, source="opponent", client=ip)
#   result.state: quarantined | duplicate | rejected | rate_limited
q.pending()        # список QuarantinedFlag (trust="untrusted", state="quarantined")
q.to_jsonl()       # выгрузка для оператора
```

## Приёмник флагов

Запуск (std-lib HTTP-сервер, наружу ничего не отправляет):

```powershell
python -m ad guard --serve --port 8765 --token SECRET --pattern 'alctf{[a-z0-9_]{16}}'
# либо
$env:AD_GUARD_HOST="127.0.0.1"; $env:AD_GUARD_PORT="8765"
$env:AD_GUARD_TOKEN="SECRET"; $env:AD_FLAG_PATTERN='alctf{[a-z0-9_]{16}}'
python -m ad guard --serve
```

Маршруты:

| Метод | Путь | Назначение |
|---|---|---|
| `POST` | `/flags`, `/api/flags`, `/api/flags/inbound`, `/inbound` | принять флаг → карантин (ответ: `202 {state, id, format_ok, suspicious}`) |
| `POST` | любой другой | «странный маршрут»: наблюдаем и **не действуем** (`action: "none"`) |
| `GET` | `/quarantine` | список удержанных (нужен `X-Guard-Token`) |
| `GET` | `/signals` | сигналы сканера (нужен `X-Guard-Token`) |
| `GET` | `/health` | открыт |

`POST /flags` принимает либо JSON `{"flag": "...", "source": "..."}`, либо текст
тела, либо `?flag=...`. В ответе **никогда** не подтверждается «настоящесть»
флага — только факт карантина и формат.

## Как встраивать

- Весь входящий от «противника» контент прогоняй через `inspect_request` **до**
  любого использования агентом; результат — данные, не инструкции.
- Оборачивай каждый цикл агента в `LoopGuard.step(...)`; `halted` = обязательная
  остановка.
- Флаги — только `FlagQuarantine`. Отправка в систему жюри — отдельный шаг
  человека, никогда из этого модуля.

## Чего модуль намеренно НЕ делает

- Не ставит WAF/фильтр/`drop` — это запрещено IV.10; guard только сообщает.
- Не выполняет и не «следует» декодированному содержимому.
- Не подтверждает и не отправляет флаги автоматически.
- Не заменяет человеческое решение о провенансе флага.
