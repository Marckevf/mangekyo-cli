import sqlite3
import os
import json
from datetime import datetime, timedelta, timezone

from .paths import NVD_CACHE_DIR, NVD_DB_PATH

DB_NAME = str(NVD_DB_PATH)
CACHE_TTL_DAYS = 7
# Empty results (score 0, no CVEs) expire much faster: a wrong fallback CPE or
# a transient empty NVD response must not poison the cache for a full week.
EMPTY_CACHE_TTL_HOURS = 1

def init_db():
    """ Initializes the NVD cache database at ~/.mangekyo/nvd_cache.db. """
    NVD_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    # Table to cache NVD results
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS nvd_cache (
            cpe_text TEXT PRIMARY KEY,
            cvss_score REAL,
            discovery_date DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    # M1 migration (idempotent): add the cve_ids column if missing.
    existing_cols = [r[1] for r in cursor.execute("PRAGMA table_info(nvd_cache)").fetchall()]
    if "cve_ids" not in existing_cols:
        cursor.execute("ALTER TABLE nvd_cache ADD COLUMN cve_ids TEXT")
    conn.commit()
    conn.close()

def get_local_score(cpe):
    """ Checks the local DB for a cached (score, cve_ids).

    Returns a (cvss_score, cve_ids) tuple, or None if the CPE is not cached,
    the entry is older than the TTL, or it is a legacy score-only row (cve_ids
    is NULL).
    """
    if not os.path.exists(DB_NAME):
        init_db()
        return None

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT cvss_score, discovery_date, cve_ids FROM nvd_cache WHERE cpe_text = ?",
        (cpe,),
    )
    result = cursor.fetchone()
    conn.close()

    if not result:
        return None

    cached_score, discovery_date, cve_ids_json = result
    cached_time = datetime.fromisoformat(str(discovery_date)).replace(tzinfo=timezone.utc)
    age = datetime.now(timezone.utc) - cached_time
    if age.days > CACHE_TTL_DAYS:
        return None
    if cve_ids_json is None:
        return None
    try:
        cve_ids = json.loads(cve_ids_json)
    except (ValueError, TypeError):
        return None
    # Empty results get a short TTL so they are re-checked against NVD soon.
    if not cve_ids and age > timedelta(hours=EMPTY_CACHE_TTL_HOURS):
        return None
    return cached_score, cve_ids

def save_local_score(cpe, score, cve_ids=None):
    """ Saves a newly fetched (score, cve_ids) to the local DB. """
    NVD_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT OR REPLACE INTO nvd_cache (cpe_text, cvss_score, cve_ids) VALUES (?, ?, ?)",
        (cpe, score, json.dumps(list(cve_ids or []))),
    )
    conn.commit()
    conn.close()
