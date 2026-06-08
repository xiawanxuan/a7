import sys
from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QFont

from ui import MainWindow


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("文件加密解密工具")
    app.setApplicationVersion("1.0.0")

    font = QFont("Microsoft YaHei", 10)
    app.setFont(font)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
