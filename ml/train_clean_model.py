import pandas as pd
import numpy as np
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score


# 1. LOAD DATA & SYNC FEATURES

DATASET_PATH = "dataset.csv"
df = pd.read_csv(DATASET_PATH)

# Features we want for the live system
LIVE_FEATURES = [
    "TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1", "SSLv3",
    "cert_validity_ratio", "issuer_trusted", "cipher_risk", "country_risk",
    "vt_score", "abuse_score"
]

# Ensure all LIVE_FEATURES exist in df
for feat in LIVE_FEATURES:
    if feat not in df.columns:
        df[feat] = 0.0  # Add missing features with default 0

print("Dataset shape:", df.shape)


# 2. CLEANING


# Replace -1 with NaN
df.replace(-1, np.nan, inplace=True)


# Convert boolean-like strings (FIXED)
def convert_bool(val):
    if isinstance(val, str):
        val = val.strip().upper()
        if val in ["TRUE", "YES", "1"]: return 1
        if val in ["FALSE", "NO", "0"]: return 0
    return val


for col in df.select_dtypes(include='object').columns:
    df[col] = df[col].apply(convert_bool)


for col in df.columns:
    df[col] = pd.to_numeric(df[col], errors='coerce')



# 3. FILL MISSING & SCALE


df.fillna(0, inplace=True)


if "label" not in df.columns:
    raise ValueError("Dataset must contain 'label' column")


X = df[LIVE_FEATURES]
y = df["label"].astype(int)


from sklearn.preprocessing import StandardScaler
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)



# 4. SPLIT & TRAIN


X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.2, stratify=y, random_state=42
)


model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    class_weight='balanced',
    n_jobs=-1
)


model.fit(X_train, y_train)



# 5. EVALUATION & SAVE


y_pred = model.predict(X_test)
print("\nAccuracy:", accuracy_score(y_test, y_pred))


joblib.dump(model, "model.pkl")
joblib.dump(scaler, "scaler.pkl")
joblib.dump(LIVE_FEATURES, "feature_names.pkl")


print("\n✅ Model, scaler, and features saved successfully.")
