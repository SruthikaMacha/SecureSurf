# SecureSurf

A security-focused desktop browser built with **PyQt6** + Chromium (QtWebEngine).
It wraps normal browsing with three layers of protection and a machine-learning
classifier that flags malicious URLs in real time.

## Protection layers

1. **Static firewall** — every network request is checked against host
   blocklists (`data/ads_hosts.txt`, `data/unsafe_urls.txt`) and dropped on an
   exact match. Essentially free, runs on every request.
2. **AI URL classifier** — top-level page navigations are scored by a trained
   model (`model/url_classifier.pkl`). Pages above the risk threshold are
   blocked. Only main-frame URLs are scored (not sub-resources), and verdicts
   are cached per host, so it stays real-time.
3. **Download guard** — cancels risky file types (`.exe`, `.dmg`, `.zip`, …).

Blocked pages show a styled `assets/block.html` notice.

## Project layout

```
src/
  main.py         app entry point
  ui.py           modern dark UI (toolbar, address bar, shield, progress)
  browser.py      wires the engine to the 3 protection layers
  interceptor.py  static blocklist + AI firewall (main-frame only)
  classifier.py   loads the model, caches verdicts, fails open
  downloader.py   loads the blocklist files
model/
  features.py                 shared feature extraction (train == inference)
  malicious_url_classifier.py training script -> url_classifier.pkl
  urls.csv                    labelled dataset (URLhaus + Tranco)
data/   host blocklists
assets/ block.html
```

## Setup

```bash
pip install -r requirements.txt
```

## Train (or retrain) the model

The model and its feature extraction must come from the same code, so the whole
pipeline (feature extraction + classifier) is trained and pickled together:

```bash
cd model
python malicious_url_classifier.py     # writes url_classifier.pkl + prints metrics
```

## Run the browser

```bash
cd src
python main.py
```

If the model file is missing or incompatible, the browser **fails open** —
it still runs using the static blocklists, with AI protection disabled (a
message is printed at startup).

## The model

A single scikit-learn `Pipeline` fuses three views of each URL:

- **character n-grams** (`char_wb` TF-IDF) — obfuscation, random hostnames,
  look-alike domains, encoded payloads;
- **word/token n-grams** (TF-IDF) — phishing keywords and suspicious tokens;
- **40+ lexical/structural features** — IP-literal hosts, ports, punycode/IDN
  homographs, entropy, suspicious TLDs, URL shorteners, brand impersonation,
  dangerous file extensions, and more (see `model/features.py`).

Because the feature extractor lives inside the pickled pipeline, inference is
just `pipeline.predict_proba([url])` — there is no feature code to keep in sync
between training and the browser.
