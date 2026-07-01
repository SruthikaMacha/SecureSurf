from urllib.parse import quote_plus

from PyQt6.QtWidgets import (
    QMainWindow, QToolBar, QLineEdit, QPushButton, QLabel,
    QProgressBar, QWidget, QVBoxLayout, QSizePolicy,
)
from PyQt6.QtCore import QUrl, Qt, QTimer
from browser import SecureBrowser

HOME_URL = "https://www.google.com"

# ── Modern dark theme (Qt Style Sheet) ──────────────────────────────────────
STYLE = """
QMainWindow, QWidget#root { background: #0f1117; }

QToolBar#navBar {
    background: #171a23;
    border: none;
    padding: 8px 12px;
    spacing: 8px;
}

QPushButton#navBtn {
    background: #232735;
    color: #cdd3e0;
    border: none;
    border-radius: 19px;
    font-size: 18px;
    font-weight: 600;
}
QPushButton#navBtn:hover  { background: #2e3446; color: #ffffff; }
QPushButton#navBtn:pressed { background: #1d2230; }
QPushButton#navBtn:disabled { color: #4b5163; }

QLabel#shield {
    font-size: 17px;
    padding: 0 6px 0 10px;
    border-radius: 14px;
}

QLineEdit#urlBar {
    background: #232735;
    color: #eef1f7;
    border: 1px solid #2c3142;
    border-radius: 19px;
    padding: 9px 18px;
    font-size: 14px;
    min-height: 20px;
    selection-background-color: #4c6ef5;
}
QLineEdit#urlBar:focus {
    border: 1px solid #4c6ef5;
    background: #262b3b;
}

QProgressBar#progress {
    background: transparent;
    border: none;
    max-height: 3px;
    min-height: 3px;
}
QProgressBar#progress::chunk { background: #4c6ef5; }

QStatusBar {
    background: #171a23;
    color: #8b93a7;
    border-top: 1px solid #232735;
    padding: 2px 10px;
    font-size: 12px;
}
"""

SHIELD_SAFE = "🛡"
SHIELD_BLOCK = "⛔"


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SecureSurf")
        self.resize(1200, 820)
        self.setStyleSheet(STYLE)

        # Browser engine
        self.browser = SecureBrowser()

        # Central area: thin progress line stacked above the web view
        root = QWidget()
        root.setObjectName("root")
        layout = QVBoxLayout(root)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.progress = QProgressBar()
        self.progress.setObjectName("progress")
        self.progress.setTextVisible(False)
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        layout.addWidget(self.progress)
        layout.addWidget(self.browser)
        self.setCentralWidget(root)

        self._build_toolbar()
        self.statusBar().showMessage("Protected by SecureSurf")
        self._connect_signals()

        self.browser.setUrl(QUrl(HOME_URL))

    # ── Toolbar construction ────────────────────────────────────────────────
    def _nav_button(self, glyph, tip, slot):
        btn = QPushButton(glyph)
        btn.setObjectName("navBtn")
        btn.setToolTip(tip)
        btn.setFixedSize(38, 38)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.clicked.connect(slot)
        return btn

    def _build_toolbar(self):
        bar = QToolBar("Navigation")
        bar.setObjectName("navBar")
        bar.setMovable(False)
        bar.setFloatable(False)
        self.addToolBar(bar)

        self.back_btn = self._nav_button("‹", "Back", self.browser.back)
        self.fwd_btn = self._nav_button("›", "Forward", self.browser.forward)
        self.reload_btn = self._nav_button("⟳", "Reload", self.browser.reload)
        self.home_btn = self._nav_button("⌂", "Home", self.go_home)
        for b in (self.back_btn, self.fwd_btn, self.reload_btn, self.home_btn):
            bar.addWidget(b)

        # Security shield indicator
        self.shield = QLabel(SHIELD_SAFE)
        self.shield.setObjectName("shield")
        self.shield.setToolTip("SecureSurf protection active")
        bar.addWidget(self.shield)

        # Address / search bar
        self.url_bar = QLineEdit()
        self.url_bar.setObjectName("urlBar")
        self.url_bar.setPlaceholderText("Search Google or type a URL")
        self.url_bar.setClearButtonEnabled(True)
        self.url_bar.setSizePolicy(QSizePolicy.Policy.Expanding,
                                   QSizePolicy.Policy.Fixed)
        self.url_bar.returnPressed.connect(self.navigate_to_url)
        bar.addWidget(self.url_bar)

    # ── Signal wiring ───────────────────────────────────────────────────────
    def _connect_signals(self):
        self.browser.urlChanged.connect(self.update_url_bar)
        self.browser.titleChanged.connect(self._update_title)
        self.browser.loadStarted.connect(self._on_load_started)
        self.browser.loadProgress.connect(self.progress.setValue)
        self.browser.loadFinished.connect(self._on_load_finished)
        # Security events from the firewall/AI interceptor
        self.browser.interceptor.blocked.connect(self._on_blocked)

    # ── Navigation ──────────────────────────────────────────────────────────
    def navigate_to_url(self):
        text = self.url_bar.text().strip()
        if not text:
            return
        # Looks like a URL? (has a dot, no spaces) → browse. Otherwise search.
        if " " not in text and "." in text:
            if not text.startswith(("http://", "https://")):
                text = "https://" + text
            self.browser.setUrl(QUrl(text))
        else:
            self.browser.setUrl(
                QUrl(f"https://www.google.com/search?q={quote_plus(text)}")
            )

    def go_home(self):
        self.browser.setUrl(QUrl(HOME_URL))

    # ── UI updates ──────────────────────────────────────────────────────────
    def update_url_bar(self, q: QUrl):
        # When the block screen (a local file) loads, keep the URL the user
        # actually tried to visit in the bar instead of the file:// path.
        if q.scheme() == "file":
            return
        self.url_bar.setText(q.toString())
        self.url_bar.setCursorPosition(0)
        # Reflect transport security in the shield tooltip
        if q.scheme() == "https":
            self.shield.setToolTip("Secure connection — protection active")
        else:
            self.shield.setToolTip("Not a secure (HTTPS) connection")

    def _update_title(self, title: str):
        self.setWindowTitle(f"{title} — SecureSurf" if title else "SecureSurf")

    def _on_load_started(self):
        self.progress.setValue(0)
        self.progress.show()
        self._set_shield_safe()

    def _on_load_finished(self, ok: bool):
        self.progress.setValue(100)
        # Briefly let the full bar show, then hide it
        QTimer.singleShot(300, lambda: self.progress.setValue(0))
        self.back_btn.setEnabled(self.browser.history().canGoBack())
        self.fwd_btn.setEnabled(self.browser.history().canGoForward())
        if ok:
            self.statusBar().showMessage("Protected by SecureSurf", 4000)

    def _on_blocked(self, host: str, reason: str):
        label = "AI model" if reason == "ai" else "blocklist"
        self.statusBar().showMessage(f"⛔ Blocked {host}  ({label})", 8000)
        self._set_shield_blocked()

    def _set_shield_blocked(self):
        self.shield.setText(SHIELD_BLOCK)
        self.shield.setStyleSheet("background:#3a1d22;")
        QTimer.singleShot(4000, self._set_shield_safe)

    def _set_shield_safe(self):
        self.shield.setText(SHIELD_SAFE)
        self.shield.setStyleSheet("")
