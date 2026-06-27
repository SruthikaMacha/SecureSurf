import os
from PyQt6.QtCore import QUrl
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore import QWebEngineProfile
from interceptor import SecurityInterceptor
from downloader import load_threat_lists

class SecureBrowser(QWebEngineView):
    def __init__(self):
        super().__init__()
        self.profile = QWebEngineProfile.defaultProfile()
        
        # 1. Load your blocked domains into memory
        ad_domains, unsafe_urls = load_threat_lists()
        
        # 2. Attach the Firewall Interceptor
        self.interceptor = SecurityInterceptor(ad_domains, unsafe_urls)
        self.profile.setUrlRequestInterceptor(self.interceptor)
        
        # 3. Attach the Download Guard
        self.profile.downloadRequested.connect(self.handle_download)

        # ✨ NEW: Listen for when a page finishes loading (or fails!)
        self.loadFinished.connect(self.handle_load_finished)

    def handle_download(self, download_item):
        filename = download_item.suggestedFileName()
        blocked_extensions = ('.dmg', '.pkg', '.zip', '.exe', '.app')
        
        if filename.lower().endswith(blocked_extensions):
            print(f"DOWNLOAD GUARD: Blocked unsafe file type -> {filename}")
            download_item.cancel()
        else:
            download_item.accept()

    # ✨ NEW: If a page gets blocked, show our custom HTML asset instead
    def handle_load_finished(self, success):
        if not success:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            block_page_path = os.path.join(base_dir, 'assets', 'block.html')
            # Safely point the browser window to your local file
            self.setUrl(QUrl.fromLocalFile(block_page_path))