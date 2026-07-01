"""Shared URL feature extraction for SecureSurf.

This module is imported by BOTH the training script and the live browser so
the model sees *identical* features at train and inference time. The
``LexicalFeatures`` transformer is baked into the saved pipeline, so this
module MUST stay importable under the name ``features`` for unpickling to work
(see ``src/classifier.py`` which puts this folder on ``sys.path``).
"""
from __future__ import annotations

import math
import re
from urllib.parse import urlparse, unquote

import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin

# ── Threat-intel word/host lists used as boolean signals ────────────────────
SUSPICIOUS_TLDS = {
    "zip", "mov", "ru", "cn", "tk", "ml", "ga", "cf", "gq", "xyz", "top",
    "work", "click", "link", "country", "kim", "science", "party", "gdn",
    "review", "stream", "download", "loan", "racing", "date", "faith",
    "cricket", "win", "bid", "trade", "webcam", "men", "rest", "fit", "su",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "cutt.ly", "rebrand.ly", "rb.gy", "shorturl.at",
    "t.ly", "tiny.cc", "soo.gd", "s2r.co", "clck.ru",
}

BRANDS = [
    "paypal", "apple", "microsoft", "amazon", "google", "facebook", "instagram",
    "netflix", "whatsapp", "outlook", "office365", "linkedin", "dropbox",
    "icloud", "wellsfargo", "chase", "bankofamerica", "coinbase", "binance",
    "metamask", "steam", "ebay", "roblox", "discord",
]

SENSITIVE_WORDS = [
    "login", "signin", "verify", "secure", "account", "update", "confirm",
    "password", "bank", "wallet", "invoice", "billing", "payment", "support",
    "unlock", "recover", "webscr", "ebayisapi", "authenticate", "session",
    "token", "suspend", "limited", "validate", "credential",
]

SUSPICIOUS_EXT = (
    ".exe", ".scr", ".bin", ".sh", ".apk", ".bat", ".cmd", ".com", ".dll",
    ".jar", ".js", ".jse", ".vbs", ".ps1", ".msi", ".dmg", ".pkg", ".zip",
    ".rar", ".7z", ".gz", ".mips", ".arm", ".elf", ".hta", ".lnk", ".scr",
)

IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
HEX_RE = re.compile(r"0x[0-9a-fA-F]{2,}")


def _shannon_entropy(s: str) -> float:
    """Shannon entropy in bits/char — high values flag random-looking strings."""
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def extract_features(raw_url: str) -> dict:
    """Return a dict of hand-crafted lexical/structural features for one URL."""
    url = (raw_url or "").strip()
    decoded = unquote(url)
    parsed = urlparse(url if "://" in url else f"http://{url}")
    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    frag = parsed.fragment or ""
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    reg_domain = ".".join(host.split(".")[-2:]) if host.count(".") >= 1 else host
    tokens = [t for t in re.split(r"[\W_]+", url) if t]
    alpha = sum(c.isalpha() for c in url)
    digits = sum(c.isdigit() for c in url)
    specials = len(re.findall(r"[^a-zA-Z0-9]", url))
    n = max(len(url), 1)
    body = f"{path}?{query}#{frag}".lower()

    return {
        # ── raw sizes ──
        "url_length":        len(url),
        "host_length":       len(host),
        "path_length":       len(path),
        "query_length":      len(query),
        "frag_length":       len(frag),
        # ── character counts ──
        "num_dots":          url.count("."),
        "num_hyphens":       url.count("-"),
        "num_underscore":    url.count("_"),
        "num_slashes":       url.count("/"),
        "num_qmark":         url.count("?"),
        "num_equal":         url.count("="),
        "num_amp":           url.count("&"),
        "num_at":            url.count("@"),
        "num_percent":       url.count("%"),
        "num_digits":        digits,
        "num_special":       specials,
        "num_params":        query.count("=") if query else 0,
        "num_subdomains":    max(host.count(".") - 1, 0),
        "path_depth":        path.count("/"),
        # ── ratios / shape ──
        "digit_ratio":       digits / n,
        "letter_ratio":      alpha / n,
        "special_ratio":     specials / n,
        "longest_token":     max((len(t) for t in tokens), default=0),
        "avg_token_len":     float(np.mean([len(t) for t in tokens])) if tokens else 0.0,
        "url_entropy":       _shannon_entropy(url),
        "host_entropy":      _shannon_entropy(host),
        # ── boolean threat signals ──
        "has_ip":            int(bool(IP_RE.match(host))),
        "has_hex":           int(bool(HEX_RE.search(url))),
        "has_port":          int(parsed.port is not None),
        "has_at":            int("@" in url),
        "has_https":         int(parsed.scheme == "https"),
        "is_http":           int(parsed.scheme == "http"),
        "has_punycode":      int("xn--" in host),         # IDN homograph attacks
        "is_shortener":      int(reg_domain in SHORTENERS),
        "suspicious_tld":    int(tld in SUSPICIOUS_TLDS),
        "double_slash_path": int("//" in path),
        "has_encoded":       int("%" in url),
        "encoded_expands":   int(len(decoded) != len(url)),
        "sensitive_words":   int(any(w in decoded.lower() for w in SENSITIVE_WORDS)),
        "brand_in_path":     int(any(b in body and b not in reg_domain for b in BRANDS)),
        "brand_in_subdomain": int(any(b in host and not reg_domain.startswith(b) for b in BRANDS)),
        "suspicious_ext":    int(decoded.lower().split("?")[0].endswith(SUSPICIOUS_EXT)),
        "many_subdomains":   int(host.count(".") >= 3),
    }


# Deterministic column order — both train and inference rely on this.
FEATURE_ORDER = list(extract_features("http://example.com").keys())


class LexicalFeatures(BaseEstimator, TransformerMixin):
    """Turn an iterable of raw URL strings into a dense lexical feature matrix.

    Lives inside the fitted pipeline, so it must remain importable as
    ``features.LexicalFeatures`` for the pickle to load.
    """

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        rows = [extract_features(u) for u in X]
        return np.array(
            [[r[k] for k in FEATURE_ORDER] for r in rows], dtype=float
        )

    def get_feature_names_out(self, input_features=None):
        return np.asarray(FEATURE_ORDER, dtype=object)
