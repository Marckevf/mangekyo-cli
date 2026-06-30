import pandas as pd
import numpy as np
import shap
import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestRegressor
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import mean_squared_error, r2_score
from itertools import product

# ── 1. Load data ──────────────────────────────────────────────────────────────
print("Loading feature matrix...")
df = pd.read_csv("final_feature_matrix.csv")

# Identity/label/metadata columns — NOT model inputs.
#   filename, is_synthetic : carried for joins + the synthetic/real split
#   tier                   : human-readable bucket
#   risk_score             : the target
# is_synthetic in particular must never be a feature (it would leak the split).
NON_FEATURE_COLS = ["filename", "is_synthetic", "tier", "risk_score"]

X = df.drop(columns=[c for c in NON_FEATURE_COLS if c in df.columns])
y = df["risk_score"]
feature_names = X.columns.tolist()

# ── 2. Train/test split ───────────────────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)
print(f"Train: {len(X_train)} samples | Test: {len(X_test)} samples")

# ── 3. No augmentation — use raw training set ────────────────────────────────
X_train_res, y_train_res = X_train, y_train

# ── 4. Hyperparameter search with 3-fold CV ───────────────────────────────────
param_grid = {
    "max_depth":         [5, 10, 15, 20, None],
    "n_estimators":      [100, 200, 300],
    "min_samples_split": [2, 5, 10],
}

combos = list(product(
    param_grid["max_depth"],
    param_grid["n_estimators"],
    param_grid["min_samples_split"],
))
total = len(combos)
print(f"\nSearching {total} hyperparameter combinations (3-fold CV)...")

best_score = -np.inf
best_params = None

for i, (max_depth, n_estimators, min_samples_split) in enumerate(combos, 1):
    rf = RandomForestRegressor(
        max_depth=max_depth,
        n_estimators=n_estimators,
        min_samples_split=min_samples_split,
        random_state=42,
        n_jobs=-1,
    )
    scores = cross_val_score(rf, X_train_res, y_train_res, cv=3, scoring="r2", n_jobs=-1)
    mean_r2 = scores.mean()
    if mean_r2 > best_score:
        best_score = mean_r2
        best_params = {
            "max_depth": max_depth,
            "n_estimators": n_estimators,
            "min_samples_split": min_samples_split,
        }
    if i % 15 == 0 or i == total:
        print(f"  [{i}/{total}] best CV R²={best_score:.4f}  params={best_params}")

print(f"\nBest hyperparameters: {best_params}")
print(f"Best CV R²: {best_score:.4f}")

# ── 5. Train final model ──────────────────────────────────────────────────────
print("\nTraining final model on full training set...")
final_model = RandomForestRegressor(**best_params, random_state=42, n_jobs=-1)
final_model.fit(X_train_res, y_train_res)

# ── 6. Evaluate on held-out test set ─────────────────────────────────────────
y_pred = final_model.predict(X_test)
mse  = mean_squared_error(y_test, y_pred)
r2   = r2_score(y_test, y_pred)
print(f"\nTest MSE : {mse:.4f}")
print(f"Test R²  : {r2:.4f}")

targets_met = "YES" if mse < 80 and r2 > 0.90 else "NO"
print(f"Targets met (MSE<80, R²>0.90): {targets_met}")

# ── 7. SHAP feature importance plot ──────────────────────────────────────────
print("\nComputing SHAP values (top 15 features)...")
explainer   = shap.TreeExplainer(final_model)
shap_values = explainer.shap_values(X_test)

mean_abs_shap = np.abs(shap_values).mean(axis=0)
shap_series   = pd.Series(mean_abs_shap, index=feature_names).sort_values(ascending=False)
top15_features = shap_series.head(15)

plt.figure(figsize=(10, 7))
top15_features[::-1].plot(kind="barh", color="steelblue")
plt.xlabel("Mean |SHAP Value|")
plt.title("Top 15 Feature Importances (SHAP)")
plt.tight_layout()
plt.savefig("shap_summary.png", dpi=150)
plt.close()
print("Saved: shap_summary.png")

# ── 8. Save model ─────────────────────────────────────────────────────────────
joblib.dump(final_model, "model.pkl")
print("Saved: model.pkl")

# ── 9. Write evaluation report ────────────────────────────────────────────────
report_lines = [
    "=" * 50,
    "MANGEKYO MODEL EVALUATION REPORT",
    "=" * 50,
    "",
    "BEST HYPERPARAMETERS",
    "-" * 30,
    f"  max_depth         : {best_params['max_depth']}",
    f"  n_estimators      : {best_params['n_estimators']}",
    f"  min_samples_split : {best_params['min_samples_split']}",
    "",
    "TEST SET PERFORMANCE",
    "-" * 30,
    f"  MSE : {mse:.4f}",
    f"  R²  : {r2:.4f}",
    f"  Targets met (MSE<80, R²>0.90): {targets_met}",
    "",
    "TOP 10 SHAP FEATURE IMPORTANCES",
    "-" * 30,
]
for rank, (feat, val) in enumerate(shap_series.head(10).items(), 1):
    report_lines.append(f"  {rank:>2}. {feat:<30} {val:.4f}")

report_lines += ["", "=" * 50]

with open("evaluation_report.txt", "w") as f:
    f.write("\n".join(report_lines) + "\n")
print("Saved: evaluation_report.txt")

# ── Final summary ─────────────────────────────────────────────────────────────
print(f"\nFINAL SUMMARY | MSE={mse:.4f} | R²={r2:.4f} | best_params={best_params} | targets_met={targets_met}")
