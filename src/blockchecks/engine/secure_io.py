"""Write tokens and settings with tight file permissions."""

from __future__ import annotations

import os


def write_secure_text(path: str, content: str, *, mode: int = 0o600) -> None:
    """Write text atomically-ish with restrictive permissions (token/settings)."""
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    tmp = f"{path}.tmp.{os.getpid()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        os.replace(tmp, path)
        os.chmod(path, mode)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
