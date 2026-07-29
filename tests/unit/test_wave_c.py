"""Wave C unit regressions — UA, DPI helpers, fingerprint API."""

from __future__ import annotations

import inspect

import pytest

from blockchecks.checkers.tcp_tls import DPI_FAKE_PATTERNS, check_tls
from blockchecks.engine.db_logger import matrix_fingerprint

pytestmark = pytest.mark.unit


def test_tcp_tls_no_empty_user_agent():
    src = inspect.getsource(check_tls)
    assert '"User-Agent": ""' not in src
    assert "'User-Agent': ''" not in src


def test_dpi_fake_patterns_fryazino_only():
    decoded = [p.decode() for p in DPI_FAKE_PATTERNS]
    assert set(decoded) == {"roskomnadzor", "rkn.gov.ru", "blockpage", "utmblock"}


def test_matrix_fingerprint_stable():
    a = matrix_fingerprint(["b", "a"], ["u"], "fast", 10)
    b = matrix_fingerprint(["a", "b"], ["u"], "fast", 10)
    assert a == b
    c = matrix_fingerprint(["a", "b"], ["u"], "full", 10)
    assert a != c
