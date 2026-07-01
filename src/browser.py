import os
from PyQt6.QtCore import QUrl
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore import QWebEngineProfile
from interceptor import SecurityInterceptor
from downloader import load_threat_lists
from classifier import URLClassifier


class SecureBrowser(QWebEngineView):
    def __init__(self):
        super().__init__()
        self.profile = QWebEngineProfile.defaultProfile()

        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self._block_page = os.path.join(base_dir, "assets", "block.html")
        self._showing_block = False  # guards against re-entrancy / loops

        # 1. Load your blocked domains into memory
        ad_domains, unsafe_urls = load_threat_lists()

        # 1b. Load the trained AI model (fails open if not trained yet)
        self.classifier = URLClassifier(threshold=0.90)

        # 2. Attach the Firewall Interceptor (static lists + AI model)
        self.interceptor = SecurityInterceptor(ad_domains, unsafe_urls, self.classifier)
        self.profile.setUrlRequestInterceptor(self.interceptor)

        # 3. Attach the Download Guard
        self.profile.downloadRequested.connect(self.handle_download)

        # 4. Show the block screen only when a TOP-LEVEL page is blocked.
        self.interceptor.blocked.connect(self.handle_blocked)
        # Clear the block lock once we're back on a real page.
        self.urlChanged.connect(self._on_url_changed)

    def handle_download(self, download_item):
        filename = download_item.suggestedFileName()
        blocked_extensions = ('.dmg', '.pkg', '.zip', '.exe', '.app')

        if filename.lower().endswith(blocked_extensions):
            print(f"DOWNLOAD GUARD: Blocked unsafe file type -> {filename}")
            download_item.cancel()
        else:
            download_item.accept()

    def handle_blocked(self, host, reason, is_main):
        # Sub-resource blocks (ads/trackers) are silent — only take over the
        # window for top-level page navigations, and never recurse on ourselves
        # (the block page is a local file and is never intercepted).
        if not is_main or self._showing_block:
            return
        self._showing_block = True
        url = QUrl.fromLocalFile(self._block_page)
        url.setFragment(f"host={host}&reason={reason}")
        self.setUrl(url)

    def _on_url_changed(self, q):
        # Navigating to a real (http/https) page again releases the block lock.
        if q.scheme() in ("http", "https"):
            self._showing_block = False
