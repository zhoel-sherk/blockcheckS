# API — единый контракт blockcheckS (socket / HTTP / MCP)

> Общий документ-положение. Заменяет docs/gp-integration.md.
> Специфичные детали MCP-клиентов — в docs/mcp.md.

## 1. Слои и транспорт

Взаимодействие с демоном `blockcheckS` (`bs serve`) осуществляется через три слоя:

| Слой | Транспорт / Протокол | Описание | Основные потребители |
|---|---|---|---|
| **Socket core** | Unix Domain Socket | `~/.local/state/blockcheckS/blockchecks.sock` (не `/var/run`). Права 0600. | Внутренние компоненты, `bs-mcp` |
| **HTTP bridge** | HTTP/1.1 (REST / SSE) | Слушает только `127.0.0.1`, порт по умолчанию `8089` (`--http-port`). | GP (Green Parallel), сторонние HTTP-клиенты, браузеры |
| **MCP** | Stdio (FastMCP) | Проксирует вызовы через Socket core. | LLM-агенты, MCP-хосты |

Схема взаимодействия: `LLM → bs-mcp (stdio) → Socket core (unix) → bs serve`. HTTP-мост работает параллельно с сокетом.

## 2. Аутентификация

### HTTP bridge
Запросы к HTTP-мосту требуют обязательной аутентификации (кроме `GET /api/health`). При запуске `bs serve` без указания токена HTTP-слой **не стартует** (защита от локального сканирования/аудита).
Приоритет конфигурации токена (от высшего к низшему):
1. Флаг CLI: `--http-token`
2. Переменная окружения: `BLOCKCHECKS_HTTP_TOKEN`
3. Конфигурация XDG: `~/.config/blockcheckS/config.toml` (секция `[http]`, ключ `token`)

Передача в запросе: заголовок `Authorization: Bearer <token>`.

### Socket core
Аутентификация не требуется. Защита обеспечивается правами файловой системы (unix socket 0600 в `~/.local/state/`).

## 3. Конверт ответов (обязателен)

Все API (HTTP, Socket, MCP) возвращают унифицированный "гибридный" конверт, совмещающий современный MCP-стиль с обратной совместимостью для старых клиентов:

```json
{
  "status": "ok",        // Legacy-статус (ok | error | busy | stopping)
  "ok": true,            // MCP-стиль (true | false)
  "data": { ... },       // Полезная нагрузка (опционально)
  "error": null,         // Сообщение об ошибке, если ok=false
  ...legacy_fields       // Поля для обратной совместимости (например, results, active_run)
}
```

## 4. HTTP bridge — таблица эндпоинтов

| Метод | Путь | Описание | Примечания |
|---|---|---|---|
| GET / HEAD | `/api/health` | Проверка доступности | **Не требует auth** |
| GET / HEAD | `/api/status` | Статус демона и текущих кампаний | |
| GET / HEAD | `/api/telemetry` | Системные метрики (RAM, netns) + `debug` snapshot | |
| GET / HEAD | `/api/logs` | Хвост лога по каналу (`python` / `campaign` / `nfqws2`) | Query: `?source=&tail=&offset=&raw=&ansi=` |
| GET | `/api/results` | Результаты лучшей кампании | Параметры: `?db=&limit=&domains=` |
| POST | `/api/stop` | Остановка текущих задач/кампаний | |
| POST | `/api/probe` | Выполнение зондирования | Возможен код 423 (busy) |
| POST | `/api/triage` | Предварительный анализ домена | |
| POST | `/api/find-strategy`| Поиск рабочей стратегии | |
| POST | `/api/generate-config`| Генерация конфигурации роутера | |
| POST | `/api/dbg-probe` | Прямой probe (отладка) | |
| POST | `/api/set-debug` | Включить/выключить unified debug (`{enabled}`) | Python DEBUG + `BLOCKCHECKS_NFQWS2_DEBUG` |
| GET / HEAD | `/api/events` | SSE-стриминг событий | Возвращает поток `text/event-stream` |

**Legacy-эндпоинты** (сохранены для обратной совместимости, новые клиенты использовать не должны):
- `GET /status` (аналог `/api/status`)
- `POST /stop`, `POST /probe`, `POST /`

## 5. Socket core — actions

Запрос к сокету должен быть валидным JSON с полем `action` (предпочтительно) или `cmd` (legacy).
Возможные действия: `probe`, `status`, `triage`, `find_strategy`, `generate_config`, `dbg_probe`, `dbg_inspect_lua`, `dbg_dump_pool`, `get_telemetry`, `set_debug`, `log_tail`, `results`, `stop`.

Формат запроса:
```json
{
  "action": "triage",
  "domain": "example.com"
}
```

## 6. MCP-инструменты (сводка)

Реализовано **22 инструмента**. Детали и контракты — в [docs/mcp.md](mcp.md), воркфлоу — в [docs/mcp-skill.md](mcp-skill.md).

- **Слой A (требуют демон):** `triage_domain`, `find_working_strategy`, `get_service_status`, `set_debug_mode`
- **Слой A (гибрид):** `generate_router_config` (демон или offline PASS SQL, `bridge_applied IS NULL OR = 1`)
- **Слой A (оффлайн / серия):** `get_series_status`, `get_log_tail` (диск: `python` / `campaign` / `nfqws2`)
- **Слой A2 (оффлайн / данные):** `query_strategies`, `get_campaign_domains_summary`, `get_presets`, `get_live_events` (live-журнал проб кампании)
- **Слой A2 (демон/диск):** `stop_campaign` — `bs stop` по `run.lock`, иначе stop **`bs serve`**
- **Слой B (требуют демон, отладка):** `dbg_probe_raw`, `dbg_inspect_lua_ipc`, `dbg_dump_pool_state`, `probe_strategy`
- **Слой B (без демона):** `dbg_validate_strategy_syntax`
- **Слой C (без демона, RO):** `get_nfqws2_status`, `get_zapret2_config`, `list_zapret2_blobs`, `get_ipset_status`, `get_provider_profile`
*(Псевдоним `probe_strategy` маппится на `dbg_probe_raw`)*

`get_log_tail` читает каналы `python` / `campaign` / `nfqws2` с диска (`LOG_SOURCES`); live-пробы — `get_live_events`.

## 7. SSE-события (/api/events)

Подключение по SSE предоставляет realtime-уведомления. События имеют тип (`event: <type>`) и JSON-данные (`data: {...}`).
Типы событий:
- `probe_start`: начало проверки. Payload: `{type, domains, strategies}`.
- `probe_result`: результат единичного запроса. Payload: строка-результат или объект.
- `probe_done`: завершение. Payload: `{type, count}`.

Для поддержания соединения отправляется `: heartbeat` каждые 15 секунд.

WebUI **не стримит** содержимое лог-файлов через SSE. Для хвоста `blockchecks.log` / campaign / nfqws2 используйте poll:

```
GET /api/logs?source=python&tail=200&offset=0
```

- `source` — только enum: `python` | `campaign` | `nfqws2` (нет path-параметров).
- `offset` — байтовый курсор. Если файл усечён/ротирован (`offset > size`), ответ `truncated: true` и чтение с нуля.
- ANSI снимается в JSON. `ansi=1` оставляет escape-коды. Для `nfqws2` IP/длинный hex редактируются, пока не передан `raw=1`.
- Во время `bs full` (A→F) HTTP-мост часто **не запущен** (fair exclusion). Кампания: MCP `get_log_tail` с диска или poll файла `logs/run_*_LATEST.logpath`.

## 8. Fair exclusion (Взаимоисключение)

Демон `bs serve` и полные CLI-кампании (`bs full`) используют блокировку через файл `run.lock` (fair exclusion) для предотвращения конкуренции за пул netns.
- Пока работает CLI-кампания (`bs full`), демон на запросы `probe` / `triage` / `find_strategy` будет возвращать HTTP `423 Locked` (status: `busy`).
- Демон откажется стартовать, если уже запущена кампания, захватившая блокировку.
- События CLI-кампаний **не транслируются** в SSE (`/api/events`).

## 9. Ошибки и статусы

- `200 OK`: Успешный запрос.
- `400 Bad Request`: Неверный JSON или отсутствуют параметры.
- `401 Unauthorized`: Токен не передан или не совпадает (только HTTP).
- `404 Not Found`: Неизвестный эндпоинт.
- `423 Locked`: Механизм Fair Exclusion (демон заблокирован выполняющейся кампанией).

Поле `status` в JSON:
- `ok`: всё прошло успешно.
- `error`: ошибка исполнения или валидации.
- `busy`: подсистема занята другой задачей (соответствует 423).
- `stopping`: процесс находится в состоянии завершения.

## 10. Правила для разработчиков (API charter)

Эти правила являются обязательными при добавлении новых эндпоинтов HTTP, socket-actions или MCP-инструментов. См. также `docs/architecture.md` §Public vs internal API.

1. **Единый конверт:** Все ответы обязаны использовать гибридный конверт (см. п.3).
2. **Аутентификация:** Все новые пути HTTP должны быть защищены проверкой Bearer-токена.
3. **HTTP-коды:** Должны использоваться семантичные коды (200, 400, 401, 404, 423).
4. **SSE:** При длительных операциях (probe/scan) необходимо эмиттить соответствующие SSE-события для UI-клиентов.
5. **Документация:** Любой новый метод должен быть отражен в этом файле `docs/api.md` (и в `mcp.md` для инструментов).
6. **Версионирование:** Изменение схемы ответа "ok"/"data" допускается только в мажорных релизах. Legacy-поля можно удалять только при предупреждении.
7. **Тестирование:** Слой HTTP-моста покрывается тестами (см. `tests/unit/test_http_server.py`, шард `S2` в CI). Модули `service/server.py` и `mcp/server.py` должны сохранять изоляцию.

## 10a. GP control-plane: движок blockcheckS

В варианте GP с двумя движками webui выбирает `discovery_engine`
(`blockcheck2` | `blockchecks`); переключение движка меняет панель подбора,
preflight-ридинг и кнопки экспорта, но HTTP-контракт `/api/...` остаётся тем же.
Ниже — карта «единица функционала BS → вызов из GP».

| GP-действие | BS-единица (субпроцесс CLI) | BS-единица (демон `bs serve`) |
|---|---|---|
| Быстрый подбор стратегии домена | `bs scan -d D -M gp-verified --scan-level single --max 24` | `POST /api/find-strategy` (AQ, time-boxed) |
| Discovery-run по доменам (кампания) | `bs scan [-d D1 -d D2 ...] [-M preset] [--db PATH]` | `POST /api/probe` (ad-hoc, без БД) |
| Одиночная проверка стратегии | `bs tcp -d D -s <strategy>` | `POST /api/probe` |
| Preflight / ридинг | `bs preflight --json -d D` (stdout-JSON) | `POST /api/triage` |
| Остановка | `bs stop --wait 120` (run.lock) | `POST /api/stop` |
| Экспорт nfqws2 | `bc-nfconf --db <db> --out-dir <dir>` | `POST /api/generate-config` |
| Прогресс / live | stdout `[N/M] pass=`, `run_summary_*.json`, `logs/` | `GET /api/status`, `/api/logs`, SSE `/api/events` |
| Результаты (PASS) | `state.db` (`tcp_results`), `run_summary` | `GET /api/results` |

### Контракт вызова `bs scan` из GP

`bs scan` (движок B в GP) вызывается как subprocess с флагами, совместимыми с
`DiscoveryOptions` GP:

```
bs scan -d <domain>... [--preset P] --scan-level {single|fast|full}
       --repeats N --parallel-repeats [--repeats-mode fast|stable]
       --curl-parallel N --parallel N --timeout SEC
       --max N | --max-timem MIN | --max-timeh HOURS
       [--tcp-sources custom,configs] [--skip-dns-audit] [--db PATH]
```

- **Мульти-домен:** `-d/--domain` повторяемый (с 1.4.1); тестируется весь
  набор. Альтернативы: `--preset` (presets/domains) или `--domains-file`
  (файл, bare FQDN — побеждает `-d`/`--preset`; GP передаёт его для больших
  v2fly-списков).
- **Матрица стратегий:** `-M/--strategy-preset` (gp-verified / flowseal-fast /
  gp-custom-*…) — матрица строго из пресета; иначе конфиги BS по умолчанию.
  `--protocol tls12|tls13`, `--repeats-mode fast|stable`, `--no-adaptive`,
  `--skip-ip-block`, `--debug` управляют поведением прогона.
- **БД и скоуп:** каждый run пишет в `--db` (по умолчанию XDG `state.db`) и
  отдельную строку в `runs`; завершение фиксируется `run_summary_*.json`
  (`run_id`, `domains`). GP для изоляции задач передаёт свежий `--db`.
- **Harvest:** аргументы кандидатов — `strategies.config_path`
  (`SqliteRunStore.get_strategy_config`), не `strategies.name` (слаг).
  PASS-фильтр: `tcp_results.status IN ('PASS','THROTTLED')` и
  `bridge_applied IS NULL OR bridge_applied = 1`; для кампании строго `=1`.
- **Окружение/пути:** `BLOCKCHECKS_{STATE,DATA,CONFIG,CACHE}_HOME` — **корень**
  XDG; приложение добавляет `/blockcheckS`. `BLOCKCHECKS_ZAPRET2` /
  `BLOCKCHECKS_NFQWS2` указывают на zapret2-дерево GP.
- **Привилегии / exclusion:** live-команды требуют passwordless `sudo` и
  nfqws2 в PATH/`BLOCKCHECKS_NFQWS2`. `bs serve` и CLI-кампания взаимо
  исключаются через `run.lock` (fair exclusion, HTTP 423): GP не поднимает
  демон во время своего discovery-run.

## 11. Открытые вопросы
- На данный момент нет (все заявленные TODO по HTTP bridge и `GET /api/results` были реализованы).
