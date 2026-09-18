"""Paths and settings. Everything can be overridden with environment variables."""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = Path(os.environ.get("SENTINEL_RULES", ROOT / "rules"))
DATA_DIR = Path(os.environ.get("SENTINEL_DATA", ROOT / "data"))
SAMPLES_DIR = Path(os.environ.get("SENTINEL_SAMPLES", ROOT / "samples"))
DB_PATH = Path(os.environ.get("SENTINEL_DB", ROOT / "var" / "sentinel.db"))
HOST = os.environ.get("SENTINEL_HOST", "127.0.0.1")   # localhost only by default
PORT = int(os.environ.get("SENTINEL_PORT", "5050"))
