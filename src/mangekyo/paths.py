"""Central data-directory resolution so the package works regardless of cwd."""
import os
from pathlib import Path


def _find_data_dir() -> Path:
    env = os.environ.get("MANGEKYO_HOME")
    if env:
        return Path(env).expanduser().resolve()
    for parent in Path(__file__).resolve().parents:
        if (parent / "pyproject.toml").exists():
            return parent
    return Path.cwd()


DATA_DIR            = _find_data_dir()
MODEL_PATH          = DATA_DIR / "model.pkl"
DB_PATH             = DATA_DIR / "mangekyo_brain.db"
KEV_CACHE_PATH      = DATA_DIR / "kev_cache.json"
KEV_SUPPLEMENT_PATH = DATA_DIR / "kev_supplement_cache.json"
MITRE_CACHE_PATH    = DATA_DIR / "mitre_attack_cache.json"
ENV_PATH            = DATA_DIR / ".env"

# NVD response cache — user-home location so it persists across installations.
NVD_CACHE_DIR = Path.home() / ".mangekyo"
NVD_DB_PATH   = NVD_CACHE_DIR / "nvd_cache.db"
