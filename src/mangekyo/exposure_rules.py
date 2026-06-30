"""
exposure_rules.py
=================
Single source of truth for per-port base exposure risk (0–100).

Consolidates the previously-duplicated EXPOSURE_RULES tables (M3). The scorer
and feature_extractor import from here; the collectors reach it through the
mangekyo package. Edit exposure values ONLY in this file.

Note: port 2121 is intentionally NOT listed — it falls through to
DEFAULT_EXPOSURE (5), matching the scorer's historical behavior (Option A).

Import resolution: callers use `from .exposure_rules import ...` (package-
relative import within mangekyo) or `from mangekyo.exposure_rules import ...`
(from outside the package). This resolves regardless of working directory
once the package is installed (`pip install -e .`).
"""

# port -> base exposure risk (0–100)
EXPOSURE_RULES = {
    # Management & Remote Access
    22:   15,   23:   95,   3389: 70,   5900: 75,
    # File Transfer & Sharing
    21:   65,   139:  60,   445:  85,
    # Web Services
    80:   30,   443:  10,   8080: 40,
    # Infrastructure & Database
    53:   30,   1433: 70,   3306: 70,   5432: 70,
    # Mail Services
    25:   50,   110:  55,   143:  55,   993:  20,
}

# Any port not in the table above
DEFAULT_EXPOSURE = 5
