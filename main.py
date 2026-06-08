import sys
import os
from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QFont, QGuiApplication
from PyQt6.QtCore import Qt, QCoreApplication

from ui import MainWindow


def main():
    QGuiApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    if sys.platform == "win32":
        import ctypes
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(2)
        except Exception:
            try:
                ctypes.windll.user32.SetProcessDPIAware()
            except Exception:
                pass

    app = QApplication(sys.argv)
    app.setApplicationName("文件加密解密工具")
    app.setApplicationVersion("1.0.0")

    screen = app.primaryScreen()
    base_font_size = 10
    if screen:
        dpi = screen.logicalDotsPerInch()
        device_ratio = screen.devicePixelRatio()
        scale_factor = max(dpi / 96.0, device_ratio)
        if scale_factor > 1.0:
            base_font_size = int(10 * scale_factor)

    font = QFont("Microsoft YaHei")
    font.setPointSize(base_font_size)
    app.setFont(font)

    app.setStyleSheet(
        f"""
        QWidget {{
            font-size: {base_font_size}px;
        }}
        """
    )

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
