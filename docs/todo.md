# TODO — blockcheckS

## Цели

Сделать **быстрый подборщик стратегий**, который **не ошибается**, а его
тесты **репрезентативны** — в отличие от `blockcheck.sh` и blockcheckw (Rust),
где легко получить ложно-зелёный PASS без адекватной валидации трафика/DPI.

Критерии «не врёт»:

- реальный браузерный TLS (curl_cffi / JA4), не голый OpenSSL curl;
- проверка контента и DPI-заглушек (Fryazino-patterns);
- изоляция netns + tracked iptables;
- TCP×UDP пары с fingerprint resume;
- unit/integration, которые ловят регрессии контрактов, а не «success=False == ok».

## План на ближайшее будущее

1. **Покрытие ~80% тестов bol-van/zapret2**  
   Перенести/отразить сценарии из upstream zapret2/blockcheck2 в matrix + checkers.

2. **Покрытие ~95% тестов flowseal-like**  
   - перевести тесты Flowseal в формат zapret2/nfqws2;  
   - расширить их (домены, UDP, composite);  
   - проверить пересечения наборов zapret2 ∩ flowseal (дубли / уникальные дыры).

3. **Изучить nfqws2-keenetic**  
   Стандартный конфиг keenetic-сборки: что уже «боевое», что можно взять в
   `configs/` и generators.

4. **[by-sonic/unblock-pro](https://github.com/by-sonic/unblock-pro)**  
   Разобрать подход (Discord/YouTube DPI bypass, macOS/Windows) — какие
   стратегии/эвристики переносимы в nfqws2.

5. **Имплементация в `matrix_generator.py`**  
   Новые источники/уровни скана из пунктов 1–4: registries, scan_level,
   dedup, приоритезация известных PASS, импорт flowseal/zapret2/keenetic/
   unblock-pro списков без TypeError и с стабильным fingerprint.

## Ближний техдолг (из аудита packaging)

- [ ] `scan`: не затирать `--auto-discover`
- [ ] multi-endpoint: pair matrix по всем `discover_multiple` EP
- [ ] untrack `state.db`, `*.egg-info`; дополнить `.gitignore`
- [ ] nfqws2: drain/DEVNULL stderr на success path
- [ ] package-data: либо копировать `configs/` в пакет, либо явно
      документировать root-only (сейчас `CONFIGS_DIR` = repo `configs/`)

## Low-priority features (near-term alpha)

- [ ] **ipfrag_udp family** — `send:ipfrag:ipfrag_pos_udp=N` + `drop` (N=8,16,24,32)
      Not used by Flowseal, niche parameter. Blocked by `send:` not being testable
      in current subprocess architecture (needs dual nfqws2 calls).
- [ ] **ipfrag_tcp family** — `send:ipfrag:ipfrag_pos_tcp=N` + `drop` (N=8,16,24,32)
- [ ] **multidisorder** — `multidisorder:pos=X` variant of multisplit. Rarely works,
      requires specific DPI config. Not used by Flowseal.
- [ ] **TTL expansion beyond 255** — edge case, most ISP paths don't exceed 255
- [ ] **repeats=4** — exists in one custom config (alt9), not generated yet
