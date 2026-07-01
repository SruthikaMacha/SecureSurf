"""Live malicious-URL classifier used by the running browser.

Loads the trained pipeline once at startup and answers ``is_malicious()`` fast,
with a per-host cache so each site is scored only once. It *fails open*: if the
model can't be loaded (e.g. not trained yet, or a version mismatch), the browser
keeps running on the static blocklists alone instead of crashing.
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_MODEL_DIR = os.path.join(os.path.dirname(_HERE), "model")

# The saved pipeline contains `features.LexicalFeatures`; make that module
# importable so joblib can unpickle it.
if _MODEL_DIR not in sys.path:
    sys.path.insert(0, _MODEL_DIR)


class URLClassifier:
    def __init__(self, threshold: float = 0.85):
        self.threshold = threshold
        self.enabled = False
        self.model = None
        self._cache: dict[str, bool] = {}
        self._load()

    def _load(self) -> None:
        try:
            import joblib
            path = os.path.join(_MODEL_DIR, "url_classifier.pkl")
            self.model = joblib.load(path)
            # Smoke test: the new pipeline takes raw URL strings. An old bare
            # estimator (numeric input) will raise here → we fail open.
            self.model.predict_proba(["http://example.com/"])
            self.enabled = True
            print("URLClassifier: model loaded — AI protection ON "
                  f"(threshold={self.threshold:.2f})")
        except Exception as exc:  # noqa: BLE001 - any failure must fail open
            self.enabled = False
            print(f"URLClassifier: AI protection OFF ({type(exc).__name__}: {exc})")

    def score(self, url: str) -> float:
        """Return P(malicious) in [0, 1], or 0.0 if scoring is unavailable."""
        if not self.enabled:
            return 0.0
        try:
            return float(self.model.predict_proba([url])[0][1])
        except Exception:  # noqa: BLE001
            return 0.0

    def is_malicious(self, url: str, host: str) -> bool:
        if not self.enabled:
            return False
        key = host or url
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        verdict = self.score(url) >= self.threshold
        self._cache[key] = verdict
        return verdict
