from PyQt6.QtWidgets import QMainWindow, QToolBar, QLineEdit
from PyQt6.QtCore import QUrl
from PyQt6.QtGui import QAction
from browser import SecureBrowser

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SecureBrowse macOS")
        self.resize(1100, 800)

        # Embed the Chromium Browser Engine
        self.browser = SecureBrowser()
        self.setCentralWidget(self.browser)

        # Create Top Navigation Bar
        self.nav_bar = QToolBar("Navigation")
        self.addToolBar(self.nav_bar)

        # Back Button
        back_btn = QAction("Back", self)
        back_btn.triggered.connect(self.browser.back)
        self.nav_bar.addAction(back_btn)

        # Forward Button
        forward_btn = QAction("Forward", self)
        forward_btn.triggered.connect(self.browser.forward)
        self.nav_bar.addAction(forward_btn)

        # Reload Button
        reload_btn = QAction("Reload", self)
        reload_btn.triggered.connect(self.browser.reload)
        self.nav_bar.addAction(reload_btn)

        # Address Bar
        self.url_bar = QLineEdit()
        self.url_bar.returnPressed.connect(self.navigate_to_url)
        self.nav_bar.addWidget(self.url_bar)

        # Update address bar when the website changes
        self.browser.urlChanged.connect(self.update_url_bar)

        # Load Google on startup
        self.browser.setUrl(QUrl("https://www.google.com"))

    def navigate_to_url(self):
        url = self.url_bar.text()
        if not url.startswith("http"):
            url = "https://" + url
        self.browser.setUrl(QUrl(url))

    def update_url_bar(self, q):
        self.url_bar.setText(q.toString())