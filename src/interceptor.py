# looks for unsafe urls

from PyQt6.QtWebEngineCore import QWebEngineUrlRequestInterceptor, QWebEngineUrlRequestInfo

class SecurityInterceptor(QWebEngineUrlRequestInterceptor):
    def __init__(self, ad_domains, unsafe_urls):
        super().__init__()
        self.ad_domains = ad_domains
        self.unsafe_urls = unsafe_urls

    def interceptRequest(self, info: QWebEngineUrlRequestInfo):
        host = info.requestUrl().host()

        # Check if the domain requested is in our block lists
        if host in self.ad_domains or host in self.unsafe_urls:
            print(f"FIREWALL TRIGGERED: Blocked connection to {host}")
            info.block(True) # Drops the connection instantly