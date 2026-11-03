"""Journal applicatif en fichier (rotation + rétention) avec masquage des secrets."""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

from loguru import logger

_SECRET = re.compile(r"(?i)(password|passwd|mot de passe|secret|token|api[_-]?key|authorization|webhook_url)(\"?\s*[:=]\s*\"?)([^\s\"',;]+)")
_installed = False


def log_dir() -> Path:
    return Path(os.environ.get("PROCUS_LOG_DIR") or (Path.home() / ".procus_hsr" / "logs"))


def redact(text: str) -> str:
    return _SECRET.sub(lambda m: m.group(1) + m.group(2) + "***", text)


def _patch(record):
    record["message"] = redact(record["message"])


def setup_logging(level: str = "INFO", rotation: str = "5 MB", retention: int = 10) -> Path:
    """Installe un fichier procus.log (5 Mo × 10 fichiers compressés). Idempotent. Retourne le dossier."""
    global _installed
    d = log_dir()
    d.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        os.chmod(d, 0o700)
    if not _installed:
        logger.configure(patcher=_patch)
        logger.add(str(d / "procus.log"), level=level, rotation=rotation, retention=retention, compression="zip",
                   enqueue=False, encoding="utf-8", backtrace=False, diagnose=False,
                   format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}")
        _installed = True
    return d
