"""Unit tests for blockchecks.terminal module."""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

from blockchecks.terminal import (
    CYAN,
    GREEN,
    GREY,
    RED,
    RESET,
    YELLOW,
    C,
    eprint,
    error,
    heading,
    init_terminal,
    status_tag,
    supports_color,
    warn,
)


def test_supports_color_no_color_env():
    with patch.dict(os.environ, {"NO_COLOR": "1"}):
        assert supports_color() is False


def test_supports_color_force_color_env():
    with patch.dict(os.environ, {"NO_COLOR": "", "FORCE_COLOR": "1"}, clear=False):
        assert supports_color() is True


def test_supports_color_clicolor_force_env():
    with patch.dict(os.environ, {"NO_COLOR": "", "CLICOLOR_FORCE": "1"}, clear=False):
        assert supports_color() is True


def test_supports_color_term_dumb():
    with patch.dict(os.environ, {"NO_COLOR": "", "FORCE_COLOR": "", "TERM": "dumb"}, clear=False):
        assert supports_color() is False


def test_supports_color_stream_isatty():
    mock_stream = MagicMock()
    mock_stream.isatty.return_value = True
    with patch.dict(
        os.environ, {"NO_COLOR": "", "FORCE_COLOR": "", "TERM": "xterm-256color"}, clear=False
    ):
        assert supports_color(mock_stream) is True

    mock_stream.isatty.return_value = False
    with patch.dict(
        os.environ, {"NO_COLOR": "", "FORCE_COLOR": "", "TERM": "xterm-256color"}, clear=False
    ):
        assert supports_color(mock_stream) is False


def test_status_tag():
    assert "OK" in status_tag(True)
    assert "FAIL" in status_tag(False)
    assert "THROTTLED" in status_tag(False, throttled=True)


def test_error_and_warn(capsys):
    error("test error")
    err_out = capsys.readouterr().err
    assert "ERROR:" in err_out
    assert "test error" in err_out

    warn("test warning")
    err_out2 = capsys.readouterr().err
    assert "WARNING:" in err_out2
    assert "test warning" in err_out2


def test_heading_and_eprint(capsys):
    heading("TEST SECTION")
    out = capsys.readouterr().out
    assert "TEST SECTION" in out

    eprint("direct eprint")
    err = capsys.readouterr().err
    assert "direct eprint" in err


def test_color_constants():
    assert C.GREEN == GREEN
    assert C.RED == RED
    assert C.YELLOW == YELLOW
    assert C.CYAN == CYAN
    assert C.GREY == GREY
    assert C.RESET == RESET


def test_init_terminal():
    # Calling multiple times does not raise
    init_terminal()
    init_terminal()
