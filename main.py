"""AegisGuard - Network Security Suite
Entry point. Run as Administrator for full functionality.
"""
import sys
import os

# Allow imports from project root
sys.path.insert(0, os.path.dirname(__file__))

from PyQt6.QtWidgets import QApplication, QMessageBox
from PyQt6.QtGui import QPalette, QColor, QFont
from PyQt6.QtCore import Qt

from db.database import initialize
from ui.main_window import MainWindow


def load_stylesheet(app):
    style_path = os.path.join(os.path.dirname(__file__), "resources", "style.qss")
    if os.path.isfile(style_path):
        with open(style_path, "r", encoding="utf-8") as f:
            app.setStyleSheet(f.read())


def check_admin():
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("AegisGuard")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("AegisGuard Security")

    font = QFont("Segoe UI", 10)
    app.setFont(font)

    # Force dark palette base
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor("#1e2329"))
    palette.setColor(QPalette.ColorRole.WindowText, QColor("#e0e6ed"))
    palette.setColor(QPalette.ColorRole.Base, QColor("#161b22"))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor("#1e2329"))
    palette.setColor(QPalette.ColorRole.Text, QColor("#e0e6ed"))
    palette.setColor(QPalette.ColorRole.Button, QColor("#21262d"))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor("#e0e6ed"))
    palette.setColor(QPalette.ColorRole.Highlight, QColor("#c0392b"))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff"))
    app.setPalette(palette)

    load_stylesheet(app)

    # Initialize database
    try:
        initialize()
    except Exception as e:
        QMessageBox.critical(None, "Database Error", f"Failed to initialize database:\n{e}")
        return 1

    if not check_admin():
        QMessageBox.warning(
            None, "Administrator Required",
            "AegisGuard is running without Administrator privileges.\n\n"
            "Some features will be limited:\n"
            "  - Windows Firewall rule sync\n"
            "  - Hosts file web filtering\n"
            "  - WireGuard tunnel management\n"
            "  - Site-to-Site IPSec configuration\n\n"
            "Right-click and 'Run as Administrator' for full functionality.",
            QMessageBox.StandardButton.Ok
        )

    window = MainWindow()
    window.show()

    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
