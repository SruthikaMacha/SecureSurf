"""Malicious URL Classifier — feature-based approach with Random Forest."""

import pandas as pd
import numpy as np
import re
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib

# ── 1. Load data (CSV with columns: url, label) ─────────────────────────
df = pd.read_csv("urls.csv")  # ← point to your file
print(f"Dataset: {len(df)} rows | label distribution:\n{df['label'].value_counts()}\n")

# ── 2. Feature extraction ───────────────────────────────────────────────
def extract_features(url: str) -> dict:
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
    except Exception:
        parsed = urlparse(f"http://{url}")

    host = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    return {
        "url_length":        len(url),
        "host_length":       len(host),
        "path_length":       len(path),
        "num_dots":          url.count("."),
        "num_hyphens":       url.count("-"),
        "num_slashes":       url.count("/"),
        "num_digits":        sum(c.isdigit() for c in url),
        "num_special":       len(re.findall(r"[^a-zA-Z0-9]", url)),
        "has_ip":            int(bool(re.match(r"\d+\.\d+\.\d+\.\d+", host))),
        "has_at_symbol":     int("@" in url),
        "has_https":         int(parsed.scheme == "https"),
        "num_subdomains":    max(host.count(".") - 1, 0),
        "path_depth":        path.count("/"),
        "has_query":         int(len(query) > 0),
        "query_length":      len(query),
        "digit_ratio":       sum(c.isdigit() for c in url) / max(len(url), 1),
        "letter_ratio":      sum(c.isalpha() for c in url) / max(len(url), 1),
        "avg_token_len":     np.mean([len(t) for t in re.split(r"[./\-_?&=]", url) if t]) if url else 0,
        "suspicious_words":  int(bool(re.search(r"login|verify|secure|account|update|bank|paypal|signin|confirm", url, re.I))),
        "entropy":           _entropy(url),
    }

def _entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * np.log2(p) for p in probs)

# ── 3. Build feature matrix ─────────────────────────────────────────────
features_df = pd.DataFrame([extract_features(u) for u in df["url"]])
X = features_df.values
y = df["label"].values

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# ── 4. Train ─────────────────────────────────────────────────────────────
model = RandomForestClassifier(n_estimators=200, max_depth=15, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

# ── 5. Evaluate ──────────────────────────────────────────────────────────
y_pred = model.predict(X_test)
print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}\n")
print(classification_report(y_test, y_pred, target_names=["benign", "malicious"]))

# Feature importance
importances = sorted(zip(features_df.columns, model.feature_importances_), key=lambda x: -x[1])
print("Top features:")
for name, imp in importances[:10]:
    print(f"  {name:20s} {imp:.4f}")

# ── 6. Save model ────────────────────────────────────────────────────────
joblib.dump(model, "url_classifier.pkl")
print("\nModel saved → url_classifier.pkl")

# ── 7. Quick inference helper ────────────────────────────────────────────
def predict_url(url: str) -> str:
    feats = np.array(list(extract_features(url).values())).reshape(1, -1)
    pred = model.predict(feats)[0]
    prob = model.predict_proba(feats)[0]
    return f"{'MALICIOUS' if pred == 1 else 'BENIGN'} (confidence: {max(prob):.2%})"

# Test
if __name__ == "__main__":
    test_urls = [
        "https://google.com",
        "http://192.168.1.1/login/verify-account.php?id=1234",
    ]
    for u in test_urls:
        print(f"  {u} → {predict_url(u)}")
