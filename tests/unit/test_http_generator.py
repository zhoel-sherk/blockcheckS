"""BC2-9: HTTP :80 standard generator and nfqws2 config."""

from __future__ import annotations

import pytest

from blockchecks.engine.async_runner import _build_inline_nfqws_lines
from blockchecks.engine.generators.standard import StandardGenerator
from blockchecks.engine.matrix_generator import MatrixGenerator

pytestmark = pytest.mark.unit


@pytest.mark.asyncio
async def test_standard_http_families():
    gen = StandardGenerator(strategy_types=["http_simple", "http_fake"])
    items = await gen.generate(protocol="http", scan_level="fast", max_count=30)
    assert items
    assert all(i.protocol == "http" for i in items)
    strategies = "\n".join(i.strategy for i in items)
    assert "http_hostcase" in strategies
    assert "http_methodeol" in strategies
    assert "fake_default_http" in strategies


@pytest.mark.asyncio
async def test_matrix_generate_http():
    gen = MatrixGenerator()
    items = await gen.generate_http(
        sources=["standard_http"],
        scan_level="single",
        max_count=5,
    )
    assert len(items) >= 1
    assert items[0].protocol == "http"


def test_build_http_nfqws_config():
    lines = _build_inline_nfqws_lines("fake:blob=fake_default_http:tcp_ts=-1000", "http")
    text = "\n".join(lines)
    assert "--filter-tcp=80" in text
    assert "--filter-l7=http" in text
    assert "--payload=http_req" in text
    assert "fake_default_http" in text


def test_build_tls_nfqws_config_unchanged():
    lines = _build_inline_nfqws_lines("fake:blob=stun:repeats=6", "tls12")
    text = "\n".join(lines)
    assert "--filter-tcp=443" in text
    assert "--filter-l7=tls" in text
    assert "--payload=tls_client_hello" in text


def test_build_inline_escapes_lt():
    """S3 audit fix: '<' in a strategy must be escaped in the @conf, else
    nfqws2's conf splitter fails with 'failed to split command line options'."""
    lines = _build_inline_nfqws_lines("--out-range=s1<d1 --in-range=-s1", "tls12")
    text = "\n".join(lines)
    assert "--out-range=s1\\<d1" in text
    assert "--in-range=-s1" in text
    assert "s1<d1" not in text


def test_family_expanders_all_have_methods():
    """Every _FAMILY_EXPANDERS entry must resolve to a real _fam_* method.

    Jules/vulture flag these as "unused" (getattr dispatcher), but they are
    called dynamically in _expand_family. This guards against broken links.
    """
    import inspect
    import re
    from pathlib import Path

    import blockchecks.engine.generators.standard as standard_mod

    src = inspect.getsource(standard_mod)
    m = re.search(r"_FAMILY_EXPANDERS = \{(.*?)\n    \}", src, re.S)
    assert m, "could not find _FAMILY_EXPANDERS in standard.py"
    mapped = set(re.findall(r': "(_fam_\w+)"', m.group(1)))
    assert mapped, "no _fam_* entries in _FAMILY_EXPANDERS"

    fam_dir = Path(standard_mod.__file__).parent / "families"
    defined = set()
    for f in fam_dir.glob("*.py"):
        defined |= set(re.findall(r"def (_fam_\w+)\b", f.read_text(encoding="utf-8")))

    assert mapped <= defined, (
        f"_FAMILY_EXPANDERS references missing methods: {sorted(mapped - defined)}"
    )
