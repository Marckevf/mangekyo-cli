"""
Robustness checks for the risk-score Random Forest model.
  1. Repeated 5×5-fold CV on the full dataset
  2. Seed sensitivity: 80/20 split with random_state 0-9
  3. Real vs synthetic evaluation
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestRegressor
from sklearn.model_selection import train_test_split, RepeatedKFold, cross_validate
from sklearn.metrics import mean_squared_error, r2_score

BEST_PARAMS = dict(n_estimators=300, max_depth=None, random_state=42, n_jobs=-1)
SEP = "=" * 60

# ── Load data ─────────────────────────────────────────────────
# Single source of truth: read the synthetic/real label straight from the
# feature matrix. Previously this masked the 16,866-row matrix with a vector
# derived from the 18,027-row training_data_v2.csv — different length and no
# guaranteed row order, which crashed and/or silently mislabeled rows.
df_feat = pd.read_csv("final_feature_matrix.csv").drop(columns=["tier"], errors="ignore")

if "is_synthetic" not in df_feat.columns:
    raise SystemExit(
        "[!] final_feature_matrix.csv has no 'is_synthetic' column. "
        "Regenerate it via 2_prepare_training_data.py so the column is carried "
        "through, then re-run this script."
    )

is_synthetic = df_feat["is_synthetic"].astype(int).astype(bool).values
# Drop identity/label columns from the feature space (keep only model inputs).
X_full = df_feat.drop(columns=["risk_score", "is_synthetic", "filename"], errors="ignore")
y_full = df_feat["risk_score"]

# ══════════════════════════════════════════════════════════════
# 1. REPEATED K-FOLD (5 folds × 5 repeats = 25 folds)
# ══════════════════════════════════════════════════════════════
print(SEP)
print("1. REPEATED K-FOLD  (5 folds × 5 repeats)")
print(SEP)

rkf = RepeatedKFold(n_splits=5, n_repeats=5, random_state=42)
rf  = RandomForestRegressor(**BEST_PARAMS)

cv_results = cross_validate(
    rf, X_full, y_full,
    cv=rkf,
    scoring={"r2": "r2", "neg_mse": "neg_mean_squared_error"},
    n_jobs=-1,
)

r2_scores  = cv_results["test_r2"]
mse_scores = -cv_results["test_neg_mse"]

print(f"  Folds completed : {len(r2_scores)}")
print(f"  R²  — mean: {r2_scores.mean():.4f}  std: {r2_scores.std():.4f}"
      f"  min: {r2_scores.min():.4f}  max: {r2_scores.max():.4f}")
print(f"  MSE — mean: {mse_scores.mean():.4f}  std: {mse_scores.std():.4f}"
      f"  min: {mse_scores.min():.4f}  max: {mse_scores.max():.4f}")
print()
print("  Per-fold detail:")
print(f"  {'Fold':>5}  {'R²':>8}  {'MSE':>10}")
for i, (r2, mse) in enumerate(zip(r2_scores, mse_scores), 1):
    print(f"  {i:>5}  {r2:>8.4f}  {mse:>10.4f}")

# ══════════════════════════════════════════════════════════════
# 2. SEED SENSITIVITY  (80/20 split, random_state 0-9)
# ══════════════════════════════════════════════════════════════
print()
print(SEP)
print("2. SEED SENSITIVITY  (80/20 split, seeds 0-9)")
print(SEP)

seed_r2, seed_mse = [], []
print(f"  {'Seed':>5}  {'R²':>8}  {'MSE':>10}")

for seed in range(10):
    X_tr, X_te, y_tr, y_te = train_test_split(
        X_full, y_full, test_size=0.2, random_state=seed
    )
    rf_s = RandomForestRegressor(**BEST_PARAMS)
    rf_s.fit(X_tr, y_tr)
    y_pred = rf_s.predict(X_te)
    r2  = r2_score(y_te, y_pred)
    mse = mean_squared_error(y_te, y_pred)
    seed_r2.append(r2)
    seed_mse.append(mse)
    print(f"  {seed:>5}  {r2:>8.4f}  {mse:>10.4f}")

seed_r2  = np.array(seed_r2)
seed_mse = np.array(seed_mse)
print()
print(f"  R²  — mean: {seed_r2.mean():.4f}  std: {seed_r2.std():.4f}"
      f"  min: {seed_r2.min():.4f}  max: {seed_r2.max():.4f}")
print(f"  MSE — mean: {seed_mse.mean():.4f}  std: {seed_mse.std():.4f}"
      f"  min: {seed_mse.min():.4f}  max: {seed_mse.max():.4f}")

# ══════════════════════════════════════════════════════════════
# 3. REAL vs SYNTHETIC SPLIT
# ══════════════════════════════════════════════════════════════
print()
print(SEP)
print("3. REAL vs SYNTHETIC SPLIT")
print(SEP)

n_syn  = is_synthetic.sum()
n_real = (~is_synthetic).sum()
print(f"  Synthetic samples : {n_syn}")
print(f"  Real samples      : {n_real}")

X_syn,  y_syn  = X_full[is_synthetic],  y_full[is_synthetic]
X_real, y_real = X_full[~is_synthetic], y_full[~is_synthetic]

rf_syn = RandomForestRegressor(**BEST_PARAMS)
rf_syn.fit(X_syn, y_syn)

y_pred_real = rf_syn.predict(X_real)
r2_real  = r2_score(y_real, y_pred_real)
mse_real = mean_squared_error(y_real, y_pred_real)

print(f"\n  Model trained on {n_syn} synthetic samples.")
print(f"  Evaluated on {n_real} real samples.\n")
print(f"  R²  on real samples : {r2_real:.4f}")
print(f"  MSE on real samples : {mse_real:.4f}")

print()
print("  Per-sample detail (real samples):")
print(f"  {'#':>4}  {'y_true':>8}  {'y_pred':>8}  {'error':>8}")
for i, (yt, yp) in enumerate(zip(y_real.values, y_pred_real), 1):
    print(f"  {i:>4}  {yt:>8.2f}  {yp:>8.2f}  {yp - yt:>+8.2f}")

print()
print(SEP)
print("Done.")
print(SEP)
