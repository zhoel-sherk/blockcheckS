# Backlog — blockcheckS

Открытые задачи после **1.0.2**. Закрытые фазы и release notes: [changelog.md](../changelog.md).

Приоритеты: **P1** = matrix/speed/protocol gaps; **P2** = voice/GP integration; **P3** = ML/hierarchy.

### Closed in 1.0.2

- [x] XDG audit: paths priority docs, out_dir finalize, DATA_DIR export/shortlists, subprocess_env
- [x] DAO: flush transaction, get_best_pairs THROTTLED, indexes, remove get_passing_pairs
- [x] tmp-scripts → `dev/` + `scripts/strategy_debug_probe.py`

### Closed in 1.0.1

- [x] system deps warnings + zapret2 auto-fetch (`engine/system_deps.py`)
- [x] C1 nfqws2 temp unlink; C2 portable chown; C3 chown warn
- [x] requirements sync; `BLOCKCHECKS_LUA_DIR` / `apply_tool_paths`
- [x] README legal disclaimer

### Closed in 1.0.0 audit / campaign (see changelog)

- [x] adaptive pair matrix after AQ TCP
- [x] repeats-aware worker wall timeout
- [x] AQ googlevideo solo batches
- [x] pair resume completed-set only (idx skip removed)
- [x] THROTTLED pair metadata via `get_working_tcp_details`
- [x] family_needs fakedsplit finish
- [x] THROTTLED ∈ working set
- [x] delete pair_runner/pair_manager; composite JSON worker; netns allowlist

### Still open (follow-up)

_(none — E3 closed in Wave2)_

### Closed in 1.1.0a1 (alpha Wave1–2)

- [x] Unify `_nfqws2_daemon` ↔ `Nfqws2Manager` (E3 → `nfqws2.start_daemon`)
- [x] Docs architecture rewrite (DoH/GV-1 as current + NetNsPool scale)
- [x] `--preset` path jail + token file modes
- [x] composite_runner: public `engine.probe.invoke_curl_probe_worker`

---

## P1 — Matrix, protocols, speed

### Phase 7 — QUIC / HTTP3

- [ ] `ipfrag_udp` / `ipfrag_tcp` (`send:` dual-call) — generator gap

### Phase 10 — Matrix coverage

- [ ] **M8** `flowseal` в default `bs full --tcp-sources` или merge combos в `standard`
- [ ] **M10** `circular` в optional scan mode (rotate blob combos on fail)
- [ ] TTL > 255, `repeats=4` generator — matrix gap

### Phase 11 — Speed / throughput

- [ ] **A4** GP multi-domain + `curl_parallelism` 4–10 — один nfqws2, parallel curl *(GP-side; BS = B2)*
- [ ] **B3** persistent nfqws2 per worker — высокий риск; после B7
- [ ] **B6** blockcheckw (Rust vmap) — fast scan reference, не drop-in voice/pair
- [ ] **B7** nftables vmap POC — prerequisite parallel > 4

### YouTube

- [ ] **GV-2** Опционально: Playwright intercept как в `dpi-tester/youtube_test.py`

### External heuristics

- [ ] **[unblock-pro](https://github.com/by-sonic/unblock-pro)** — переносимые эвристики в matrix/checkers

---

## P2 — Voice & GP bridge

- [ ] **V2-1** multi-endpoint pair matrix по всем discover EP (сейчас только `eps[0]`)
- [ ] **V2-2** `--full-voice` gateway WS probe (сейчас discovery+STUN only)
- [ ] **V2-3** `scripts/voice_smoke.sh` — новый smoke-скрипт для voice end-to-end (есть аналоги: `gv_e2e_smoke.sh`, `gv1_smoke.sh`)
- [ ] **P5-1** GP JSON import в `state.db` (partial сейчас)

---

## P3 — Smart scan (Phase 12)

### ML ranker (sklearn)

- [ ] **ML1** optional-dep `scikit-learn` в `[project.optional-dependencies] ml`
- [ ] **ML2** `scripts/train_strategy_ranker.py` — export `state.db` → parquet → fit → `model.pkl`
- [ ] **ML3** feature parser: domain (TLD, cdn_class) + strategy (family/blob/repeats/fooling)
- [ ] **ML4** BS integration: `--ranker model.pkl` → top-K candidates
- [ ] **ML5** retrain policy: после mass scan / drift / provider change

### Hierarchical progressive scan

- [ ] **H1** спецификация «облака параметров»: оси (desync, blob, fooling, ttl, repeats, split…)
- [ ] **H2** `ProgressiveStrategyBuilder` — API: `add_axis()` → partial conf → test → branch
- [ ] **H3** default tree order из GP `family_rank` + Fryazino facts
- [ ] **H4** beam width B=3 — не только greedy
- [ ] **H5** интеграция в `bs scan --progressive` / `scan_level=progressive`
- [ ] **H6** лог partial results в DB (`partial_results`) для ML train
- [ ] **H7** learned axis order: contextual bandit / RF на domain_class
- [ ] **H8** provider template export из dpi-tester → A5
- [ ] **H9** benchmark vs full matrix на 10 доменах: Recall(best strategy found)
- [ ] **H10** fallback: progressive 0 PASS → expand beam / RF top-K / full family scan

---

## 1.1.0 — tech debt (audit backlog)

- [ ] **H2** `run_finalize.py` — `count_tcp_passes` открывает свежий коннект к БД
- [ ] **H3** `adaptive_queue.py` — sequential await'ы в `filter_resume`
- [ ] **H4** `preflight.py` — prolog-проверка только TLS (не контент)
- [ ] **H6** `dns_secure.py` — `DnsRunCache` не ротирует DoH-сервер
- [ ] **H8** `voice_discovery.py` — глобальный `_singbox_proc` не concurrent-safe
- [ ] **E3** два competing nfqws2 lifecycle-подхода (daemon vs foreground)
- [ ] `[paths.migrate]` — авто-миграция legacy `./state.db` → XDG при первом запуске
