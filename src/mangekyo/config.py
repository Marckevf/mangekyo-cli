"""Centralised environment config — NVD API key loaded once via python-dotenv."""
import os

from dotenv import load_dotenv

from .paths import ENV_PATH

load_dotenv(ENV_PATH, override=False)

NVD_API_KEY:   str   = os.environ.get("NVD_API_KEY", "").strip()
NVD_RATE_DELAY: float = 0.6 if NVD_API_KEY else 6.5
