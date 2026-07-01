# looks for unsafe urls

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWebEngineCore import (
    QWebEngineUrlRequestInterceptor,
    QWebEngineUrlRequestInfo,
)

# Only real web traffic is ever inspected. Local pages (our block screen),
# about:blank, data: URLs, etc. are always allowed so we never block our own UI
# and never get stuck in a block -> redirect -> block loop.
ALLOWED_SCHEMES = ("http", "https")


class SecurityInterceptor(QWebEngineUrlRequestInterceptor):
    # (host, reason, is_main_frame). reason is "blocklist" or "ai".
    blocked = pyqtSignal(str, str, bool)

    def __init__(self, ad_domains, unsafe_urls, classifier=None):
        super().__init__()
        self.ad_domains = ad_domains
        self.unsafe_urls = unsafe_urls
        self.classifier = classifier

    def interceptRequest(self, info: QWebEngineUrlRequestInfo):
        url_obj = info.requestUrl()
        if url_obj.scheme() not in ALLOWED_SCHEMES:
            return  # leave the local block page / about: / data: URLs alone

        host = url_obj.host()
        is_main = self._is_main_frame(info)

        # 1. Static blocklists — exact host match (runs on every request).
        if host in self.ad_domains or host in self.unsafe_urls:
            info.block(True)
            self.blocked.emit(host, "blocklist", is_main)
            return

        # 2. AI model — score ONLY top-level page navigations. The classifier
        #    caches its verdict per host, so each site is sent to the model at
        #    most once (no repeated scoring, no message spam).
        if self.classifier is not None and is_main:
            if self.classifier.is_malicious(url_obj.toString(), host):
                print(f"AI FIREWALL: Blocked suspicious page -> {host}")
                info.block(True)
                self.blocked.emit(host, "ai", is_main)

    @staticmethod
    def _is_main_frame(info: QWebEngineUrlRequestInfo) -> bool:
        try:
            return (info.resourceType()
                    == QWebEngineUrlRequestInfo.ResourceType.ResourceTypeMainFrame)
        except Exception:  # noqa: BLE001 - never let detection break a request
            return False
