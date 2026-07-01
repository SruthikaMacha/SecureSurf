"""SecureSurf — advanced malicious-URL classifier.

Combines three complementary views of a URL:

  1. character n-grams (``char_wb`` TF-IDF)  — catches obfuscation, random
     hostnames, look-alike domains, encoded payloads.
  2. word/token n-grams (TF-IDF)             — catches phishing keywords and
     suspicious path/query tokens.
  3. hand-crafted lexical features           — structural signals (IP hosts,
     punycode, entropy, suspicious TLDs, brand impersonation, file types…).

These are fused with a ``FeatureUnion`` and fed to a calibrated linear model.
The ENTIRE pipeline (feature extraction + classifier) is pickled, so the live
browser only needs ``pipeline.predict_proba([url])`` — no feature code to keep
in sync. Run this file to (re)train and overwrite ``url_classifier.pkl``:

    cd model && python malicious_url_classifier.py
"""
import os
import random
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline, make_pipeline
from sklearn.preprocessing import MaxAbsScaler

# Make sibling `features.py` importable both when run directly and via package.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from features import LexicalFeatures  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.join(HERE, "urls.csv")
MODEL_PATH = os.path.join(HERE, "url_classifier.pkl")
THRESHOLD = 0.50  # decision threshold for the report; the browser uses its own

# The benign rows (Tranco) are bare domain roots with no path, while the
# malicious rows (URLhaus) almost all have paths/queries. Left unbalanced, the
# model learns the shortcut "has a path => malicious" and flags normal browsing.
# We fix that by adding realistic benign URLs *with* paths/queries (including
# login/search/download-style paths) so the model must learn real signals.
BENIGN_PATHS = [
    "/", "/about", "/about/contact", "/login", "/signin", "/account/settings",
    "/search?q=hello+world", "/search?q=weather+today", "/products/12345",
    "/blog/2024/01/post-title", "/help/faq", "/category/news/article-1234",
    "/user/profile?id=42", "/cart", "/checkout", "/api/v1/items?page=2",
    "/images/logo.png", "/static/app.css", "/download/report.pdf",
    "/signin?next=/dashboard", "/docs/getting-started", "/pricing",
]

#breaks urls and sends benign urls to extra list 
def augment_benign(df: pd.DataFrame, n_variants: int = 2, seed: int = 42) -> pd.DataFrame:
    """Add benign URLs carrying realistic paths/queries to balance the data."""
    rng = random.Random(seed)
    benign = df[df["label"] == 0]
    extra = []
    for url in benign["url"].astype(str):
        base = url.rstrip("/")
        for path in rng.sample(BENIGN_PATHS, k=min(n_variants, len(BENIGN_PATHS))):
            extra.append({"url": base + path, "label": 0, "source": "augmented"})
    return pd.concat([df, pd.DataFrame(extra)], ignore_index=True)

# converts chars and words to numbers so model can read, defines type of model
def build_pipeline() -> Pipeline:
    """Assemble the full feature-extraction + classification pipeline."""
    char_vec = TfidfVectorizer(
        analyzer="char_wb", ngram_range=(3, 5),
        min_df=5, max_features=60000, lowercase=True, sublinear_tf=True,
    )
    word_vec = TfidfVectorizer(
        analyzer="word", token_pattern=r"[A-Za-z0-9]+", ngram_range=(1, 2),
        min_df=5, max_features=25000, lowercase=True, sublinear_tf=True,
    )
    # Lexical features are dense + on very different scales → MaxAbsScaler keeps
    # them sparse-friendly and comparable to the TF-IDF blocks.
    lexical = make_pipeline(LexicalFeatures(), MaxAbsScaler())

    features = FeatureUnion(
        [("char", char_vec), ("word", word_vec), ("lex", lexical)],
        n_jobs=None,
    )
    clf = LogisticRegression(
        C=4.0, class_weight="balanced", max_iter=3000,
        solver="saga", n_jobs=-1,
    )
    return Pipeline([("features", features), ("clf", clf)])

#
def main() -> None:
    if not os.path.exists(CSV_PATH):
        raise SystemExit(f"Dataset not found: {CSV_PATH}")

    df = pd.read_csv(CSV_PATH)
    df = df.dropna(subset=["url", "label"])
    df["label"] = df["label"].astype(int)

    before = len(df)
    df = augment_benign(df, n_variants=2)
    print(f"Benign-path augmentation: {before} -> {len(df)} rows")

    X = df["url"].astype(str).tolist()
    y = df["label"].to_numpy()
    print(
        f"Dataset: {len(df)} rows | "
        f"benign={int((y == 0).sum())} malicious={int((y == 1).sum())}"
    )

    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    pipe = build_pipeline()
    print("Training advanced pipeline (char + word n-grams + lexical)…")
    pipe.fit(X_tr, y_tr)

    prob = pipe.predict_proba(X_te)[:, 1]
    pred = (prob >= THRESHOLD).astype(int)
    print(f"\nAccuracy: {accuracy_score(y_te, pred):.4f}")
    print(f"ROC-AUC : {roc_auc_score(y_te, prob):.4f}\n")
    print(classification_report(y_te, pred, target_names=["benign", "malicious"]))

    joblib.dump(pipe, MODEL_PATH)
    print(f"Model saved -> {MODEL_PATH}")


def predict_url(url: str, pipe=None) -> str:
    """Convenience single-URL inference helper."""
    pipe = pipe or joblib.load(MODEL_PATH)
    p = float(pipe.predict_proba([url])[0][1])
    verdict = "MALICIOUS" if p >= THRESHOLD else "BENIGN"
    return f"{verdict} (p={p:.2%})"


# testing with some basic urls
if __name__ == "__main__":
    main()
    print("\nSpot checks (benign pages with paths should now stay BENIGN):")
    samples = [
        ("https://google.com", "benign root"),
        ("https://www.google.com/search?q=weather+today", "benign + query"),
        ("https://github.com/torvalds/linux/blob/master/README", "benign deep path"),
        ("https://www.amazon.com/account/login?ref=nav", "benign login page"),
        ("http://192.168.1.1/login/verify-account.php?id=1234", "malicious IP login"),
        ("http://kpq.at/dlr.arm", "malicious payload"),
        ("https://paypal.com.secure-login.account-update.ru/signin", "brand phishing"),
        ("http://bit.ly/3xPhish", "shortener"),
    ]
    loaded = joblib.load(MODEL_PATH)
    for url, note in samples:
        print(f"  [{note:18s}] {url} -> {predict_url(url, loaded)}")
