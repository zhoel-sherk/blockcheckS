# GP Integration — внешняя оркестрация blockcheckS через HTTP

> Ветка: `gp-integration`. Цель: дать внешним оркестраторам (в первую очередь
> GP Access Control Plane) управлять blockcheckS как сервисом — запускать
> on-the-fly пробы, triage, поиск стратегий — и получать прогресс через SSE.
> Полные кампании (`bs full`) оркестратор запускает сам (subprocess), как это
> делает GP с `blockcheck2.sh`.

## Быстрый старт

```bash
# 1. Токен: CLI > env > config.toml
export BLOCKCHECKS_HTTP_TOKEN="секретный-токен"

# 2. Демон с HTTP-мостом
sudo -E .venv/bin/bs serve --pool 4 --http-port 8089 --http-token "$BLOCKCHECKS_HTTP_TOKEN"
```

Демон поднимет:
- Unix-socket core: `~/.local/state/blockcheckS/blockchecks.sock`
- Authenticated HTTP bridge: `http://127.0.0.1:8089`

Если токен не задан — HTTP-мост **не стартует** (только socket). Это защита
от неавторизованного локального доступа (закрывает дыру из аудита).

## Конфигурация токена

Приоритет (первый непустой побеждает):

1. Флаг `--http-token <token>` у `bs serve`;
2. env `BLOCKCHECKS_HTTP_TOKEN`;
3. `~/.config/blockcheckS/config.toml`:
   ```toml
   [http]
   token = "секретный-токен"
   ```

## Эндпоинты

Все требуют заголовок `Authorization: Bearer <token>`, кроме `GET /api/health`.

| Метод | Путь | Описание | Примечание |
|---|---|---|---|
| GET | `/api/health` | liveness (без токена) | `{"status":"ok"}` |
| GET | `/api/status` | статус демона (пул, busy, uptime) | busy → 423 |
| GET | `/api/telemetry` | телеметрия (+run.lock) | — |
| GET | `/api/results` | best PASS-стратегии из run-БД (TCP/UDP/QUIC) | `?db=&limit=&domains=` |
| POST | `/api/stop` | graceful stop демона | — |
| POST | `/api/probe` | on-the-fly проба стратегий | JSON body |
| POST | `/api/triage` | preflight-triage домена | JSON body |
| POST | `/api/find-strategy` | AQ-поиск стратегий | JSON body |
| POST | `/api/generate-config` | генерация nfqws2 .conf | JSON body |
| GET | `/api/events` | SSE-поток on-the-fly событий | `text/event-stream` |

Legacy-пути `/status`, `/stop`, `/probe` сохранены (тоже требуют токен).

## Примеры curl

```bash
TOKEN="секретный-токен"
BASE="http://127.0.0.1:8089"
AUTH="Authorization: Bearer $TOKEN"

# Health (без токена)
curl -s $BASE/api/health

# Status
curl -s -H "$AUTH" $BASE/api/status | python3 -m json.tool

# Probe: проверить одну стратегию на домене
curl -s -X POST -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"domains":["youtube.com"],"strategies":["fake:blob=stun:repeats=6:tcp_ts=-1000"]}' \
  $BASE/api/probe | python3 -m json.tool

# Triage домена
curl -s -X POST -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"domain":"youtube.com"}' $BASE/api/triage | python3 -m json.tool

# Find-strategy (AQ, до 30с)
curl -s -X POST -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"domain":"discord.com","profile":"fast","time_limit_sec":20}' \
  $BASE/api/find-strategy | python3 -m json.tool

# Generate config
curl -s -X POST -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"target_os":"linux","domains":["youtube.com","discord.com"]}' \
  $BASE/api/generate-config | python3 -m json.tool

# Results: best PASS-стратегии (DB авто-резолвится из run.lock или DEFAULT)
curl -s -H "$AUTH" "$BASE/api/results?limit=10" | python3 -m json.tool
# с явным путём к run-БД
curl -s -H "$AUTH" "$BASE/api/results?db=/path/to/run.db&limit=5" | python3 -m json.tool

# SSE-поток событий (live)
curl -sN -H "$AUTH" $BASE/api/events
```

## SSE-события (`GET /api/events`)

Стрим идёт в формате Server-Sent Events (`event: <type>` + `data: <json>`),
heartbeat каждые 15 секунд (`: heartbeat`). События публикуются для on-the-fly
операций:

| event type | payload | когда |
|---|---|---|
| `probe_start` | `{"type","domains","strategies"}` | начало `/api/probe` |
| `probe_result` | результат одной стратегии | на каждую строку результата |
| `probe_done` | `{"type","count"}` | завершение `/api/probe` |

> Полные кампании (`bs full`) стримятся не демоном — их прогресс/лог читает
> оркестратор из stdout и файлов, как GP делает с `blockcheck2.sh`.

## Контракт ответов

Ответы — гибридный конверт (обратная совместимость с MCP/socket):

```json
{
  "ok": true,
  "data": { "...": "поля результата" },
  "error": null,
  "status": "ok",
  "results": { "...": "legacy-поля (если есть)" }
}
```

- `status: "busy"` → HTTP **423 Locked** (`active_run` указывает, кто держит пул);
- неверный/отсутствующий токен → **401**;
- неизвестный путь → **404**;
- битый JSON-body → **400**.

## Fair exclusion

Демон `bs serve` и полные кампании (`bs full`) взаимоисключающие через
`run.lock`. Пока кампания владеет пулом, все probe-запросы вернут
`status: "busy"` (423) — оркестратор должен это учитывать и не дергать пробы
во время `bs full`. Демон не стартует вообще, если кампания уже активна.

## Модули

- `src/blockchecks/service/server.py` — `ProbeServer` (socket + HTTP + SSE).
- `src/blockchecks/cli/commands/serve.py` — `cmd_serve` (флаги, резолв токена).
- `src/blockchecks/cli/parser.py` — флаги `--http-port`, `--http-token`.
- `tests/unit/test_http_server.py` — 9 тестов auth/routing/SSE/busy.
- CI: файл добавлен в шард S2 (`.github/workflows/ci.yml`).

## TODO / открытые вопросы

- [ ] `GET /api/results` — отбор PASS-стратегий из run-БД через DAO
      (`get_best_by_coverage`/`v_coverage`). Пока не нужен, т.к. GP читает
      результаты `bs full` сама; решить после обкатки MVP.
- [ ] Проброс SSE в `/api/web/events/stream` GP (после релиза GP 0.4.0).
- [ ] ANSI-рендер/терминал в GP UI для лога on-the-fly проб.
- [ ] `gp_export.py` — снапшот v6 / SQLite-upsert для передачи стратегий в GP.