"""
retrain_validate.py
===================
Project Mangekyo — Post-Diversity Retrain + 5-Task Validation Suite

Tasks:
  1. Full retrain via 3_train_model.py (official, updates model.pkl)
  2. Synthetic→Real cross-domain split test
  3. Real-on-real 80/20 split + 5-fold CV
  4. Feature importance comparison: before vs after diversity sweep
  5. Summary vs baselines

Run: python -u retrain_validate.py  (logs to retrain_validate.log)
"""

from __future__ import annotations

import os
import subprocess
import sys
import re
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestRegressor
from sklearn.model_selection import train_test_split, cross_val_score, KFold
from sklearn.metrics import mean_squared_error, r2_score

# Windows console / redirected stdout defaults to cp1252, which cannot encode
# the report's Unicode (→ ← ² ±). Force UTF-8 so the run doesn't crash when
# piped to a log file.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

PROJ         = Path(__file__).parent
TRAIN_CSV    = PROJ / "training_data_v2.csv"
FEATURE_CSV  = PROJ / "final_feature_matrix.csv"
MODEL_PATH   = PROJ / "model.pkl"
OLD_MODEL    = PROJ / "model_pre_diversity.pkl"
REPORT_PATH  = PROJ / "validation_report.txt"

BASELINES = {
    "original":    {"r2": 0.411,  "mse": 420.66,  "label": "Original (XML-only)"},
    "cloud_sweep": {"r2": 0.888,  "mse": 76.96,   "label": "Post-cloud sweep"},
}

SEP  = "=" * 65
SEP2 = "-" * 50

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

# Accumulates everything pr() emits so the full run can be persisted to
# REPORT_PATH at the end (previously the report was only ever printed).
_REPORT_LINES: list[str] = []


def pr(msg: str = "", end: str = "\n") -> None:
    """Print (flushed) and tee into the report buffer.

    Accepts `end` so callers can build partial lines (e.g. a label followed
    by a verdict) — the previous signature crashed on `pr(..., end="")`.
    """
    print(msg, end=end, flush=True)
    _REPORT_LINES.append(f"{msg}{end}")


def write_report() -> None:
    """Persist the accumulated run output to REPORT_PATH."""
    try:
        REPORT_PATH.write_text("".join(_REPORT_LINES), encoding="utf-8")
        print(f"\n[report] Written to {REPORT_PATH}", flush=True)
    except Exception as e:
        print(f"\n[!] Failed to write {REPORT_PATH}: {e}", flush=True)


def delta(new: float, old: float, higher_better: bool = True) -> str:
    d = new - old
    better = (d > 0) if higher_better else (d < 0)
    mark = "^" if better else "v"
    return f"{d:+.4f} {mark}"


# Columns in the feature matrix that are NOT model inputs.
NON_FEATURE_COLS = ("filename", "is_synthetic", "tier", "risk_score")


def feature_columns(fm: pd.DataFrame) -> list[str]:
    """Model-input columns: everything except identity/label/target columns."""
    return [c for c in fm.columns if c not in NON_FEATURE_COLS]


def load_feature_matrix_with_synthetic() -> tuple[pd.DataFrame, int, str]:
    """
    Load final_feature_matrix.csv. The synthetic/real split is now an explicit
    `is_synthetic` column carried through from the source (synthetic generator /
    real collectors → 2_prepare). No value-matching join — the old approach
    re-identified synthetic rows by matching intel fingerprints across two CSVs
    and silently mislabeled ~336 of 1,000 synthetic rows (audit H3).
    """
    fm = pd.read_csv(FEATURE_CSV)
    if "is_synthetic" not in fm.columns:
        raise SystemExit(
            "[!] final_feature_matrix.csv has no 'is_synthetic' column. "
            "Run reconcile_feature_matrix.py (or regenerate via "
            "2_prepare_training_data.py) so the label is carried through."
        )
    n_synth = int((fm["is_synthetic"] == 1).sum())
    n_real  = int((fm["is_synthetic"] == 0).sum())
    note = f"is_synthetic read directly from matrix | synthetic={n_synth:,} | real={n_real:,}"
    return fm, n_synth, note


def parse_best_params(text: str) -> dict:
    """Extract best params from 3_train_model.py output.

    Handles both the report style (``max_depth : None``) and the dict style
    the trainer prints (``'max_depth': None``) — the optional quote before the
    separator is what previously made this miss the stdout and fall back to the
    report (which then clobbered the already-parsed test metrics).
    """
    params: dict = {}
    for line in text.splitlines():
        m = re.search(r"max_depth['\"]?\s*[:=]\s*(\w+)", line)
        if m:
            v = m.group(1)
            params["max_depth"] = None if v in ("None", "none") else int(v)
        m = re.search(r"n_estimators['\"]?\s*[:=]\s*(\d+)", line)
        if m:
            params["n_estimators"] = int(m.group(1))
        m = re.search(r"min_samples_split['\"]?\s*[:=]\s*(\d+)", line)
        if m:
            params["min_samples_split"] = int(m.group(1))
    return params


def parse_test_metrics(text: str) -> dict:
    """Extract test R² and MSE from 3_train_model.py stdout."""
    metrics = {}
    for line in text.splitlines():
        m = re.search(r"Test MSE\s*:\s*([\d.]+)", line)
        if m:
            metrics["mse"] = float(m.group(1))
        # Tolerate any glyph between "Test R" and ":" (²/2/replacement char)
        m = re.search(r"Test R\S{0,3}\s*:\s*([\d.]+)", line)
        if m:
            metrics["r2"] = float(m.group(1))
    return metrics


def train_rf(X_tr, y_tr, params: dict) -> RandomForestRegressor:
    rf = RandomForestRegressor(**params, random_state=42, n_jobs=-1)
    rf.fit(X_tr, y_tr)
    return rf


def eval_metrics(model, X_te, y_te) -> tuple[float, float]:
    y_pred = model.predict(X_te)
    return r2_score(y_te, y_pred), mean_squared_error(y_te, y_pred)


# ─────────────────────────────────────────────────────────────────────────────
# TASK 0: Back up pre-diversity model
# ─────────────────────────────────────────────────────────────────────────────

def backup_old_model() -> dict | None:
    if not MODEL_PATH.exists():
        pr("[0] No existing model.pkl — skipping backup")
        return None
    old_model = joblib.load(MODEL_PATH)
    joblib.dump(old_model, OLD_MODEL)
    pr(f"[0] Backed up existing model -> {OLD_MODEL.name}")

    fm = pd.read_csv(FEATURE_CSV)
    feature_names = feature_columns(fm)

    imp = pd.Series(old_model.feature_importances_, index=feature_names)
    pr(f"[0] Pre-diversity top-10 feature importances (Gini):")
    for rank, (feat, val) in enumerate(imp.nlargest(10).items(), 1):
        pr(f"    {rank:>2}. {feat:<32} {val:.6f}")
    return imp.to_dict()

# ─────────────────────────────────────────────────────────────────────────────
# TASK 1: Full retrain via 3_train_model.py
# ─────────────────────────────────────────────────────────────────────────────

def task1_retrain() -> tuple[dict, dict]:
    pr(f"\n{SEP}")
    pr("TASK 1 — FULL RETRAIN (3_train_model.py)")
    pr(SEP)

    fm = pd.read_csv(FEATURE_CSV)
    pr(f"  Feature matrix: {len(fm):,} rows × {len(fm.columns)} cols")
    td = pd.read_csv(TRAIN_CSV)
    pr(f"  Training data : {len(td):,} rows | "
       f"real={int((td.is_synthetic==0).sum()):,} "
       f"synthetic={int((td.is_synthetic==1).sum()):,}")
    pr("")

    # Force the child to emit UTF-8 and decode it as such, so metric lines
    # containing "²" survive the pipe and parse correctly.
    child_env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    result = subprocess.run(
        [sys.executable, str(PROJ / "3_train_model.py")],
        capture_output=True, text=True, cwd=str(PROJ),
        encoding="utf-8", errors="replace", env=child_env,
    )
    stdout = result.stdout + result.stderr
    pr(stdout)

    best_params  = parse_best_params(stdout)
    test_metrics = parse_test_metrics(stdout)

    if not best_params or not test_metrics:
        # Fallback: read from evaluation_report.txt, but only FILL values that
        # are still missing — never overwrite what we already parsed from stdout
        # (the report's metric lines lack the "Test " prefix and would blank
        # out a good test_metrics).
        try:
            rpt = (PROJ / "evaluation_report.txt").read_text(errors="replace")
            if not best_params:
                best_params = parse_best_params(rpt)
            if not test_metrics:
                test_metrics = parse_test_metrics(rpt)
        except Exception:
            pass

    pr(f"\n[Task 1 summary]")
    pr(f"  Best params : {best_params}")
    pr(f"  Test R²     : {test_metrics.get('r2', 'N/A')}")
    pr(f"  Test MSE    : {test_metrics.get('mse', 'N/A')}")
    return best_params, test_metrics

# ─────────────────────────────────────────────────────────────────────────────
# TASK 2: Synthetic → Real cross-domain split test
# ─────────────────────────────────────────────────────────────────────────────

def task2_synth_to_real(best_params: dict) -> dict:
    pr(f"\n{SEP}")
    pr("TASK 2 — SYNTHETIC→REAL CROSS-DOMAIN SPLIT TEST")
    pr(SEP)

    fm, n_synth, merge_note = load_feature_matrix_with_synthetic()
    pr(f"  {merge_note}")

    n_real = int((fm["is_synthetic"] == 0).sum())
    pr(f"  Rows in FM  : {len(fm):,}  |  synthetic: {n_synth:,}  |  real: {n_real:,}")

    feature_cols = feature_columns(fm)

    if n_synth < 10:
        pr("\n  [!] Too few synthetic rows identified to train a model.")
        pr("      Likely cause: synthetic samples share intel fingerprints with real data.")
        pr("      Skipping task 2 — reporting what we found.")
        return {"r2": None, "mse": None, "n_synth": n_synth, "n_real": n_real}

    synth_df = fm[fm["is_synthetic"] == 1]
    real_df  = fm[fm["is_synthetic"] == 0]

    X_synth = synth_df[feature_cols]
    y_synth = synth_df["risk_score"]
    X_real  = real_df[feature_cols]
    y_real  = real_df["risk_score"]

    pr(f"\n  Training on {len(X_synth):,} synthetic rows …")
    model = train_rf(X_synth, y_synth, best_params)

    r2, mse = eval_metrics(model, X_real, y_real)
    pr(f"  Testing  on {len(X_real):,} real rows")
    pr(f"\n  R²  = {r2:.4f}")
    pr(f"  MSE = {mse:.4f}")

    baseline_r2  = BASELINES["cloud_sweep"]["r2"]
    baseline_mse = BASELINES["cloud_sweep"]["mse"]
    pr(f"\n  vs last check (R²={baseline_r2}, MSE={baseline_mse}):")
    pr(f"    R²  {delta(r2,  baseline_r2,  higher_better=True)}")
    pr(f"    MSE {delta(mse, baseline_mse, higher_better=False)}")

    return {"r2": r2, "mse": mse, "n_synth": n_synth, "n_real": n_real}

# ─────────────────────────────────────────────────────────────────────────────
# TASK 3: Real-on-real 80/20 split + 5-fold CV
# ─────────────────────────────────────────────────────────────────────────────

def task3_real_on_real(best_params: dict) -> dict:
    pr(f"\n{SEP}")
    pr("TASK 3 — REAL-ON-REAL (80/20 SPLIT + 5-FOLD CV)")
    pr(SEP)

    fm, n_synth, _ = load_feature_matrix_with_synthetic()
    real_df = fm[fm["is_synthetic"] == 0].copy()
    pr(f"  Real rows available: {len(real_df):,}")

    feature_cols = feature_columns(fm)
    X = real_df[feature_cols]
    y = real_df["risk_score"]

    # 80/20 split
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, random_state=42)
    pr(f"  Train: {len(X_tr):,}  |  Test: {len(X_te):,}")

    pr(f"  Training RF {best_params} on real-only 80% …")
    model = train_rf(X_tr, y_tr, best_params)
    r2_split, mse_split = eval_metrics(model, X_te, y_te)

    pr(f"\n  80/20 split results:")
    pr(f"    R²  = {r2_split:.4f}")
    pr(f"    MSE = {mse_split:.4f}")

    # 5-fold CV on all real data
    pr(f"\n  Running 5-fold CV on all {len(X):,} real rows …")
    rf_cv = RandomForestRegressor(**best_params, random_state=42, n_jobs=-1)
    kf    = KFold(n_splits=5, shuffle=True, random_state=42)

    r2_scores  = cross_val_score(rf_cv, X, y, cv=kf, scoring="r2",
                                  n_jobs=-1)
    mse_scores = -cross_val_score(rf_cv, X, y, cv=kf,
                                   scoring="neg_mean_squared_error",
                                   n_jobs=-1)

    pr(f"\n  5-fold CV results:")
    pr(f"    R²  per fold : {[round(s,4) for s in r2_scores]}")
    pr(f"    R²  mean±std : {r2_scores.mean():.4f} ± {r2_scores.std():.4f}")
    pr(f"    MSE per fold : {[round(s,4) for s in mse_scores]}")
    pr(f"    MSE mean±std : {mse_scores.mean():.4f} ± {mse_scores.std():.4f}")

    return {
        "r2_split":  r2_split,  "mse_split":  mse_split,
        "r2_cv_mean": r2_scores.mean(), "r2_cv_std": r2_scores.std(),
        "mse_cv_mean": mse_scores.mean(), "mse_cv_std": mse_scores.std(),
        "n_real": len(real_df),
    }

# ─────────────────────────────────────────────────────────────────────────────
# TASK 4: Feature importance comparison before vs after diversity sweep
# ─────────────────────────────────────────────────────────────────────────────

def task4_feature_importance(pre_importances: dict | None) -> None:
    pr(f"\n{SEP}")
    pr("TASK 4 — FEATURE IMPORTANCE: BEFORE vs AFTER DIVERSITY SWEEP")
    pr(SEP)

    if not MODEL_PATH.exists():
        pr("  [!] model.pkl not found — skipping task 4")
        return

    new_model    = joblib.load(MODEL_PATH)
    fm           = pd.read_csv(FEATURE_CSV)
    feature_cols = feature_columns(fm)

    new_imp = pd.Series(new_model.feature_importances_, index=feature_cols)

    if pre_importances:
        old_imp = pd.Series(pre_importances).reindex(feature_cols).fillna(0)
    else:
        pr("  [!] No pre-diversity model found — showing post-diversity only")
        old_imp = pd.Series(0.0, index=feature_cols)

    # Build comparison table (top 20 by new importance)
    top20 = new_imp.nlargest(20)
    pr(f"\n  {'Feature':<32} {'Before':>10} {'After':>10} {'Delta':>10}  {'Dir'}")
    pr(f"  {'-'*32} {'-'*10} {'-'*10} {'-'*10}  {'-'*4}")
    for feat, new_val in top20.items():
        old_val = old_imp.get(feat, 0.0)
        d       = new_val - old_val
        sign    = "^" if d > 0.001 else ("v" if d < -0.001 else "-")
        pr(f"  {feat:<32} {old_val:>10.6f} {new_val:>10.6f} {d:>+10.6f}  {sign}")

    # Specifically check diversity-relevant features
    diversity_features = [
        "os_is_windows", "has_ancient_version", "is_http", "is_https",
        "is_rdp", "is_smb", "is_ftp", "is_telnet",
        "max_nvd_score", "max_epss_score", "has_kev_cve",
    ]
    pr(f"\n  Diversity-relevant feature spotlight:")
    pr(f"  {'Feature':<32} {'Before':>10} {'After':>10} {'Delta':>10}  Rank(after)")
    pr(f"  {'-'*32} {'-'*10} {'-'*10} {'-'*10}  -----------")
    ranked = new_imp.rank(ascending=False).astype(int)
    for feat in diversity_features:
        old_val  = old_imp.get(feat, 0.0)
        new_val  = new_imp.get(feat, 0.0)
        d        = new_val - old_val
        rank     = ranked.get(feat, "?")
        pr(f"  {feat:<32} {old_val:>10.6f} {new_val:>10.6f} {d:>+10.6f}  #{rank}")

# ─────────────────────────────────────────────────────────────────────────────
# TASK 5: Summary comparison vs baselines
# ─────────────────────────────────────────────────────────────────────────────

def task5_summary(t1: dict, t2: dict, t3: dict) -> None:
    pr(f"\n{SEP}")
    pr("TASK 5 — FULL COMPARISON vs BASELINES")
    pr(SEP)

    rows = [
        ("Original (XML-only)",           0.411,  420.66),
        ("Post-cloud sweep",              0.888,   76.96),
    ]
    if t1.get("r2") is not None:
        rows.append(("Post-diversity retrain (full)",
                     t1["r2"], t1["mse"]))
    if t2.get("r2") is not None:
        rows.append((f"Synth→Real ({t2['n_synth']:,}→{t2['n_real']:,})",
                     t2["r2"], t2["mse"]))
    rows.append((f"Real-on-real 80/20 ({t3['n_real']:,} real)",
                 t3["r2_split"], t3["mse_split"]))
    rows.append((f"Real 5-fold CV mean",
                 t3["r2_cv_mean"], t3["mse_cv_mean"]))

    pr(f"\n  {'Scenario':<42} {'R²':>8} {'MSE':>10}  {'vs original R²':>16}")
    pr(f"  {'-'*42} {'-'*8} {'-'*10}  {'-'*16}")
    for label, r2, mse in rows:
        d_r2 = r2 - 0.411
        pr(f"  {label:<42} {r2:>8.4f} {mse:>10.4f}  {d_r2:>+15.4f}")

    pr(f"\n  Targets (MSE<80, R²>0.90): ", end="")
    if t1.get("r2") is not None:
        met = t1["r2"] > 0.90 and t1["mse"] < 80
        pr("MET [YES]" if met else "NOT MET [NO]")
    else:
        pr("N/A")

    # Real-vs-synthetic gap analysis
    if t2.get("r2") is not None and t1.get("r2") is not None:
        pr(f"\n  Real-vs-synthetic generalisation gap:")
        pr(f"    Full-dataset R²   : {t1['r2']:.4f}")
        pr(f"    Synth→Real R²     : {t2['r2']:.4f}")
        gap = t1["r2"] - t2["r2"]
        if gap > 0.15:
            pr(f"    Gap               : {gap:.4f}  ← some synthetic-distribution leakage")
        elif gap > 0.05:
            pr(f"    Gap               : {gap:.4f}  ← mild, acceptable gap")
        else:
            pr(f"    Gap               : {gap:.4f}  ← tight, model generalises well")

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    pr(SEP)
    pr("MANGEKYO — POST-DIVERSITY RETRAIN + VALIDATION SUITE")
    pr(SEP)
    pr(f"  Feature matrix : {FEATURE_CSV}")
    pr(f"  Training data  : {TRAIN_CSV}")
    pr(f"  Output report  : {REPORT_PATH}")
    pr("")

    pre_imp = backup_old_model()

    best_params, t1_metrics = task1_retrain()

    if not best_params:
        pr("[!] Could not parse best_params from 3_train_model.py — using defaults")
        best_params = {"max_depth": 20, "n_estimators": 300, "min_samples_split": 2}

    t2 = task2_synth_to_real(best_params)
    t3 = task3_real_on_real(best_params)
    task4_feature_importance(pre_imp)
    task5_summary(t1_metrics, t2, t3)

    pr(f"\n{SEP}")
    pr("DONE — all tasks complete.")
    pr(SEP)

    write_report()


if __name__ == "__main__":
    main()
