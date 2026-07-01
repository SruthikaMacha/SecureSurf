import sys
from PyQt6.QtWidgets import QApplication
from ui import MainWindow

def main():
    # Create the application
    app = QApplication(sys.argv)
    
    # Create and show the main window
    window = MainWindow()
    window.show()
    
    # Run the application loop safely
    sys.exit(app.exec())

if __name__ == "__main__":
    main()