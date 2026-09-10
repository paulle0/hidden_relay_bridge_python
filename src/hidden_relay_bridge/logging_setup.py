"""Logging configuration shared by the CLI entry points."""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"
_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S%z"


def setup_logging(level: str = "INFO", file: str = "", systemd: bool = False) -> None:
    """Configure the root logger.

    Under systemd the journal adds its own timestamps, so the format drops them.
    """
    numeric = getattr(logging, level.upper(), None)
    if not isinstance(numeric, int):
        raise ValueError(f"unknown log level '{level}'")

    handler: logging.Handler
    if file:
        path = Path(file).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(path, encoding="utf-8")
    else:
        handler = logging.StreamHandler(sys.stderr)

    fmt = "%(levelname)-7s %(name)s: %(message)s" if systemd and not file else _FORMAT
    handler.setFormatter(logging.Formatter(fmt, datefmt=_DATE_FORMAT))

    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(numeric)

    # websockets is chatty at DEBUG and drowns out the bridge's own messages.
    logging.getLogger("websockets").setLevel(max(numeric, logging.INFO))


def running_under_systemd() -> bool:
    return bool(os.environ.get("INVOCATION_ID") or os.environ.get("JOURNAL_STREAM"))
