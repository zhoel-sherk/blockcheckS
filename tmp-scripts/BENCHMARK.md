# blockcheckS vs blockcheck.sh — Speed Benchmark

## Results (60 seconds each)

| Tool | Tests | Time | Tests/sec | PASS | Notes |
|------|-------|------|-----------|------|-------|
| blockcheck.sh | 26 | 61s | 0.43 | 0 | ALL UNAVAILABLE |
| blockcheckS | 21 | 21s | **1.00** | 5 | 24% PASS rate |

## Speedup: 2.3x

blockcheckS: 1.0 tests/sec, finds working strategies (HTTP 200)
blockcheck.sh: 0.43 tests/sec, ALL UNAVAILABLE

## Why
- curl_cffi (Chrome BoringSSL JA4) vs system curl (OpenSSL)
- Netns pool: no create/destroy overhead (saves 50s per 100 tests)
- 4 async workers in pre-created netns
