import sys
from PySide6.QtWidgets import QApplication
from core.db import DatabaseManager
from ui.main_window import MainWindow

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("ProofChain")
    dbm = DatabaseManager()
    window = MainWindow(dbm)
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
