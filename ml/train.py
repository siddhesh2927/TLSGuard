import pandas as pd
import numpy as np
import joblib
import os
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import (
    classification_report,
    roc_auc_score,
    confusion_matrix,
    recall_score,
    f1_score
)

# ─────────────────────────────────────────────
# 1. LOAD DATASET
# ─────────────────────────────────────────────
print("=" * 60)
print("  TLSGUARD — ML Model Training")
print("=" * 60)

DATASET_PATH = os.path.join(os.path.dirname(__file__), "dataset.csv")
print(f"\n[1/6] Loading dataset from: {DATASET_PATH}")
df = pd.read_csv(DATASET_PATH)

print(f"      Rows: {len(df):,}")
print(f"      Cols: {len(df.columns)}")
print(f"      Label distribution:")
print(f"        Phishing (1): {(df['label'] == 1).sum():,}")
print(f"        Benign   (0): {(df['label'] == 0).sum():,}")

# ─────────────────────────────────────────────
# 1b. CONVERT ALL STRING VALUES TO NUMERIC
# ─────────────────────────────────────────────
print("\n[1b] Converting TRUE/FALSE strings and any text columns to numeric...")

# Step 1: Replace TRUE/FALSE across entire dataframe at once (vectorized)
df.replace({"TRUE": 1, "FALSE": 0, "True": 1, "False": 0, "true": 1, "false": 0}, inplace=True)

# Step 2: Force-convert any remaining object columns to numeric
for col in df.columns:
    if col == "label":
        continue
    if df[col].dtype == object:
        df[col] = pd.to_numeric(df[col], errors="coerce")

print(f"      Done. All columns are now numeric.")

# ─────────────────────────────────────────────
# 2. PREPARE FEATURES & LABELS
# ─────────────────────────────────────────────
print("\n[2/6] Preparing features...")

X = df.drop(columns=["label"])
y = df["label"]

# Store feature names for inference
feature_names = list(X.columns)
joblib.dump(feature_names, os.path.join(os.path.dirname(__file__), "feature_names.pkl"))
print(f"      {len(feature_names)} features ready.")

# Handle any NaN values
X = X.fillna(0)

# ─────────────────────────────────────────────
# 3. TRAIN / TEST SPLIT (80/20, stratified)
# ─────────────────────────────────────────────
print("\n[3/6] Splitting data (80% train / 20% test, stratified)...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.20,
    random_state=42,
    stratify=y  # ensures equal phishing/benign in both splits
)
print(f"      Train size: {len(X_train):,} samples")
print(f"      Test  size: {len(X_test):,} samples")

# ─────────────────────────────────────────────
# 4. SCALE FEATURES (fit only on train!)
# ─────────────────────────────────────────────
print("\n[4/6] Scaling features (StandardScaler)...")
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)   # fit on train only
X_test_scaled  = scaler.transform(X_test)         # transform test (no fit)
joblib.dump(scaler, os.path.join(os.path.dirname(__file__), "scaler.pkl"))
print("      Scaler saved.")

# ─────────────────────────────────────────────
# 5. TRAIN MLP NEURAL NETWORK
# ─────────────────────────────────────────────
print("\n[5/6] Training MLP Neural Network...")
print("      Architecture: Input(197) → 256 → 128 → 64 → Output(1)")
print("      Max epochs: 300 | Optimizer: Adam | Early stopping: ON")
print("      ─" * 30)

model = MLPClassifier(
    hidden_layer_sizes=(256, 128, 64),
    activation="relu",
    solver="adam",
    learning_rate_init=0.001,
    max_iter=300,
    early_stopping=True,
    validation_fraction=0.1,
    n_iter_no_change=15,
    tol=1e-4,
    verbose=True,
    random_state=42
)

model.fit(X_train_scaled, y_train)

print(f"\n      Training stopped at epoch: {model.n_iter_}")
print(f"      Best validation score: {model.best_validation_score_:.4f}")

joblib.dump(model, os.path.join(os.path.dirname(__file__), "model.pkl"))
print("      Model saved to ml/model.pkl")

# ─────────────────────────────────────────────
# 6. EVALUATE ON TEST SET
# ─────────────────────────────────────────────
print("\n[6/6] Evaluating on TEST SET...")
print("      ─" * 30)

y_pred = model.predict(X_test_scaled)
y_prob = model.predict_proba(X_test_scaled)[:, 1]

recall   = recall_score(y_test, y_pred)
f1       = f1_score(y_test, y_pred)
roc_auc  = roc_auc_score(y_test, y_prob)
cm       = confusion_matrix(y_test, y_pred)

print("\n  Classification Report:")
print(classification_report(y_test, y_pred, target_names=["Benign", "Phishing"]))

print(f"  ┌─────────────────────────────────────┐")
print(f"  │  🎯 KEY METRICS (Phishing Class)    │")
print(f"  ├─────────────────────────────────────┤")
print(f"  │  Recall    (most critical): {recall:.4f}  │")
print(f"  │  F1-Score  (balanced):      {f1:.4f}  │")
print(f"  │  ROC-AUC   (overall):       {roc_auc:.4f}  │")
print(f"  └─────────────────────────────────────┘")

print(f"\n  Confusion Matrix:")
print(f"                  Predicted")
print(f"                  Benign  Phishing")
print(f"  Actual Benign  [{cm[0][0]:6,}  {cm[0][1]:6,}]")
print(f"  Actual Phishing[{cm[1][0]:6,}  {cm[1][1]:6,}]")

tn, fp, fn, tp = cm.ravel()
print(f"\n  TP (Correctly caught phishing):   {tp:,}")
print(f"  FN (Missed phishing — DANGEROUS): {fn:,}")
print(f"  FP (False alarms):                {fp:,}")
print(f"  TN (Correctly allowed benign):    {tn:,}")

# ─────────────────────────────────────────────
# COMPUTE FEATURE IMPORTANCE (Permutation)
# ─────────────────────────────────────────────
print("\n  Computing top feature importances...")
from sklearn.inspection import permutation_importance

perm = permutation_importance(
    model, X_test_scaled, y_test,
    n_repeats=5,
    random_state=42,
    scoring="f1"
)

importances = pd.Series(perm.importances_mean, index=feature_names)
top_features = importances.sort_values(ascending=False).head(10)

print("\n  Top 10 Most Important Features:")
for i, (feat, imp) in enumerate(top_features.items(), 1):
    print(f"  {i:2}. {feat[:50]:<50} {imp:.4f}")

joblib.dump(top_features.to_dict(), os.path.join(os.path.dirname(__file__), "top_features.pkl"))

print("\n" + "=" * 60)
print("  ✅ Training Complete! Files saved:")
print("     ml/model.pkl")
print("     ml/scaler.pkl")
print("     ml/feature_names.pkl")
print("     ml/top_features.pkl")
print("=" * 60)
