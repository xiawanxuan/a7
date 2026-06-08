import os
from pathlib import Path
from typing import List

from PyQt6.QtWidgets import (
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QProgressBar,
    QFileDialog,
    QMessageBox,
    QTabWidget,
    QFormLayout,
    QGroupBox,
    QCheckBox,
    QComboBox,
    QTextEdit,
    QSplitter,
    QFrame,
)
from PyQt6.QtCore import Qt, QThread
from PyQt6.QtGui import QIcon, QFont

from file_manager import BatchProcessor, FolderBatchProcessor, ProcessStatus
from crypto import MetadataManager, AppDataManager


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("文件加密解密工具 - AES-256")
        self.setMinimumSize(900, 650)

        self.file_paths: List[str] = []
        self.folder_paths: List[str] = []
        self.batch_processor = None
        self.metadata_manager = MetadataManager()
        self.app_data = AppDataManager()

        self._init_ui()
        self._apply_styles()
        self._load_app_config()

    def _setup_dpi_scaling(self):
        screen = self.screen()
        if screen:
            self._dpi_scale = screen.devicePixelRatio()
        else:
            self._dpi_scale = 1.0
        if self._dpi_scale < 1.0:
            self._dpi_scale = 1.0

    def _scale(self, value: int) -> int:
        return int(value * self._dpi_scale)

    def _scale_font(self, point_size: int) -> int:
        base = int(point_size * self._dpi_scale)
        return max(base, point_size)

    def _init_ui(self):
        self._setup_dpi_scaling()

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(self._scale(15))
        main_layout.setContentsMargins(self._scale(20), self._scale(20), self._scale(20), self._scale(20))

        title_label = QLabel("文件加密解密工具")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_font = QFont()
        title_font.setPointSize(self._scale_font(20))
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setStyleSheet(f"color: #2c3e50; margin-bottom: {self._scale(10)}px;")
        main_layout.addWidget(title_label)

        subtitle_label = QLabel("基于 AES-256 算法的安全文件加密")
        subtitle_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle_label.setStyleSheet(f"color: #7f8c8d; margin-bottom: {self._scale(10)}px;")
        main_layout.addWidget(subtitle_label)

        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget, 1)

        self._init_encrypt_tab()
        self._init_decrypt_tab()
        self._init_metadata_tab()

        self._init_progress_section()
        main_layout.addWidget(self.progress_group)

    def _init_encrypt_tab(self):
        encrypt_tab = QWidget()
        layout = QVBoxLayout(encrypt_tab)
        layout.setSpacing(self._scale(15))

        password_group = QGroupBox("加密设置")
        password_layout = QFormLayout(password_group)

        self.encrypt_password = QLineEdit()
        self.encrypt_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.encrypt_password.setPlaceholderText("请输入加密密码...")
        self.encrypt_password.setMinimumHeight(self._scale(35))

        self.encrypt_confirm = QLineEdit()
        self.encrypt_confirm.setEchoMode(QLineEdit.EchoMode.Password)
        self.encrypt_confirm.setPlaceholderText("请再次输入密码...")
        self.encrypt_confirm.setMinimumHeight(self._scale(35))

        self.show_password_check = QCheckBox("显示密码")
        self.show_password_check.stateChanged.connect(self._toggle_password_visibility)

        password_layout.addRow("加密密码:", self.encrypt_password)
        password_layout.addRow("确认密码:", self.encrypt_confirm)
        password_layout.addRow("", self.show_password_check)

        layout.addWidget(password_group)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        file_section = QWidget()
        file_layout = QVBoxLayout(file_section)
        file_layout.setContentsMargins(0, 0, 0, 0)

        file_label = QLabel("待加密文件列表")
        file_label.setStyleSheet("font-weight: bold; color: #34495e;")
        file_layout.addWidget(file_label)

        self.encrypt_file_list = QListWidget()
        self.encrypt_file_list.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)
        file_layout.addWidget(self.encrypt_file_list, 1)

        btn_layout = QHBoxLayout()
        add_file_btn = QPushButton("添加文件")
        add_file_btn.clicked.connect(self._add_encrypt_files)
        add_folder_btn = QPushButton("添加文件夹")
        add_folder_btn.clicked.connect(self._add_encrypt_folder)
        remove_btn = QPushButton("移除选中")
        remove_btn.clicked.connect(lambda: self._remove_selected(self.encrypt_file_list))
        clear_btn = QPushButton("清空列表")
        clear_btn.clicked.connect(lambda: self._clear_list(self.encrypt_file_list))

        for btn in [add_file_btn, add_folder_btn, remove_btn, clear_btn]:
            btn_layout.addWidget(btn)

        file_layout.addLayout(btn_layout)

        splitter.addWidget(file_section)

        output_section = QWidget()
        output_layout = QVBoxLayout(output_section)
        output_layout.setContentsMargins(0, 0, 0, 0)

        output_label = QLabel("输出设置")
        output_label.setStyleSheet("font-weight: bold; color: #34495e;")
        output_layout.addWidget(output_label)

        self.output_same_check = QCheckBox("输出到源文件同目录")
        self.output_same_check.setChecked(True)
        self.output_same_check.stateChanged.connect(self._toggle_output_dir)
        output_layout.addWidget(self.output_same_check)

        output_dir_layout = QHBoxLayout()
        self.output_dir_edit = QLineEdit()
        self.output_dir_edit.setPlaceholderText("选择输出目录...")
        self.output_dir_edit.setEnabled(False)
        output_dir_btn = QPushButton("浏览...")
        output_dir_btn.clicked.connect(self._select_output_dir)
        output_dir_btn.setEnabled(False)
        output_dir_layout.addWidget(self.output_dir_edit, 1)
        output_dir_layout.addWidget(output_dir_btn)
        output_layout.addLayout(output_dir_layout)

        self.output_dir_btn = output_dir_btn

        output_layout.addStretch()

        splitter.addWidget(output_section)
        splitter.setSizes([self._scale(500), self._scale(300)])

        layout.addWidget(splitter, 1)

        encrypt_btn = QPushButton("开始加密")
        encrypt_btn.setMinimumHeight(self._scale(45))
        btn_font_size = self._scale_font(16)
        encrypt_btn.setStyleSheet(
            f"""
            QPushButton {{
                background-color: #3498db;
                color: white;
                font-size: {btn_font_size}px;
                font-weight: bold;
                border-radius: {self._scale(8)}px;
            }}
            QPushButton:hover {{
                background-color: #2980b9;
            }}
            QPushButton:pressed {{
                background-color: #217dbb;
            }}
        """
        )
        encrypt_btn.clicked.connect(self._start_encryption)
        layout.addWidget(encrypt_btn)

        self.tab_widget.addTab(encrypt_tab, "加密")

    def _init_decrypt_tab(self):
        decrypt_tab = QWidget()
        layout = QVBoxLayout(decrypt_tab)
        layout.setSpacing(self._scale(15))

        password_group = QGroupBox("解密设置")
        password_layout = QFormLayout(password_group)

        self.decrypt_password = QLineEdit()
        self.decrypt_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.decrypt_password.setPlaceholderText("请输入解密密码...")
        self.decrypt_password.setMinimumHeight(self._scale(35))

        self.show_decrypt_check = QCheckBox("显示密码")
        self.show_decrypt_check.stateChanged.connect(self._toggle_decrypt_password)

        password_layout.addRow("解密密码:", self.decrypt_password)
        password_layout.addRow("", self.show_decrypt_check)

        layout.addWidget(password_group)

        file_section = QWidget()
        file_layout = QVBoxLayout(file_section)

        file_label = QLabel("待解密文件列表")
        file_label.setStyleSheet("font-weight: bold; color: #34495e;")
        file_layout.addWidget(file_label)

        self.decrypt_file_list = QListWidget()
        self.decrypt_file_list.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)
        file_layout.addWidget(self.decrypt_file_list, 1)

        btn_layout = QHBoxLayout()
        add_file_btn = QPushButton("添加文件")
        add_file_btn.clicked.connect(self._add_decrypt_files)
        add_folder_btn = QPushButton("添加文件夹")
        add_folder_btn.clicked.connect(self._add_decrypt_folder)
        remove_btn = QPushButton("移除选中")
        remove_btn.clicked.connect(lambda: self._remove_selected(self.decrypt_file_list))
        clear_btn = QPushButton("清空列表")
        clear_btn.clicked.connect(lambda: self._clear_list(self.decrypt_file_list))

        for btn in [add_file_btn, add_folder_btn, remove_btn, clear_btn]:
            btn_layout.addWidget(btn)

        file_layout.addLayout(btn_layout)

        layout.addWidget(file_section, 1)

        decrypt_btn = QPushButton("开始解密")
        decrypt_btn.setMinimumHeight(self._scale(45))
        decrypt_btn_font_size = self._scale_font(16)
        decrypt_btn.setStyleSheet(
            f"""
            QPushButton {{
                background-color: #27ae60;
                color: white;
                font-size: {decrypt_btn_font_size}px;
                font-weight: bold;
                border-radius: {self._scale(8)}px;
            }}
            QPushButton:hover {{
                background-color: #229954;
            }}
            QPushButton:pressed {{
                background-color: #1e8449;
            }}
        """
        )
        decrypt_btn.clicked.connect(self._start_decryption)
        layout.addWidget(decrypt_btn)

        self.tab_widget.addTab(decrypt_tab, "解密")

    def _init_metadata_tab(self):
        metadata_tab = QWidget()
        layout = QVBoxLayout(metadata_tab)

        select_layout = QHBoxLayout()
        self.metadata_path_edit = QLineEdit()
        self.metadata_path_edit.setPlaceholderText("选择加密文件查看元数据...")
        select_btn = QPushButton("选择文件")
        select_btn.clicked.connect(self._select_metadata_file)
        refresh_btn = QPushButton("刷新列表")
        refresh_btn.clicked.connect(self._refresh_metadata_list)
        select_layout.addWidget(self.metadata_path_edit, 1)
        select_layout.addWidget(select_btn)
        select_layout.addWidget(refresh_btn)
        layout.addLayout(select_layout)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        list_widget = QWidget()
        list_layout = QVBoxLayout(list_widget)
        list_layout.setContentsMargins(0, 0, 0, 0)

        list_label = QLabel("已加密文件列表")
        list_label.setStyleSheet("font-weight: bold; color: #34495e;")
        list_layout.addWidget(list_label)

        self.metadata_list = QListWidget()
        self.metadata_list.itemClicked.connect(self._show_metadata)
        list_layout.addWidget(self.metadata_list, 1)

        splitter.addWidget(list_widget)

        detail_widget = QWidget()
        detail_layout = QVBoxLayout(detail_widget)
        detail_layout.setContentsMargins(0, 0, 0, 0)

        detail_label = QLabel("元数据详情")
        detail_label.setStyleSheet("font-weight: bold; color: #34495e;")
        detail_layout.addWidget(detail_label)

        self.metadata_detail = QTextEdit()
        self.metadata_detail.setReadOnly(True)
        detail_layout.addWidget(self.metadata_detail, 1)

        splitter.addWidget(detail_widget)
        splitter.setSizes([self._scale(300), self._scale(500)])

        layout.addWidget(splitter, 1)

        self.tab_widget.addTab(metadata_tab, "元数据管理")

        self._refresh_metadata_list()

    def _init_progress_section(self):
        self.progress_group = QGroupBox("处理进度")
        progress_layout = QVBoxLayout(self.progress_group)

        self.current_file_label = QLabel("等待开始...")
        self.current_file_label.setStyleSheet("color: #555;")
        progress_layout.addWidget(self.current_file_label)

        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimumHeight(self._scale(25))
        self.progress_bar.setStyleSheet(
            f"""
            QProgressBar {{
                border: {self._scale(2)}px solid #bdc3c7;
                border-radius: {self._scale(5)}px;
                text-align: center;
            }}
            QProgressBar::chunk {{
                background-color: #3498db;
                border-radius: {self._scale(3)}px;
            }}
        """
        )
        progress_layout.addWidget(self.progress_bar)

        status_layout = QHBoxLayout()
        self.status_label = QLabel("就绪")
        self.status_label.setStyleSheet("color: #7f8c8d;")
        status_layout.addWidget(self.status_label)

        self.cancel_btn = QPushButton("取消")
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self._cancel_processing)
        status_layout.addWidget(self.cancel_btn)

        progress_layout.addLayout(status_layout)

    def _apply_styles(self):
        s = self._scale
        self.setStyleSheet(
            f"""
            QMainWindow {{
                background-color: #ecf0f1;
            }}
            QGroupBox {{
                font-weight: bold;
                border: {s(2)}px solid #bdc3c7;
                border-radius: {s(8)}px;
                margin-top: {s(10)}px;
                padding-top: {s(10)}px;
                background-color: white;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: {s(10)}px;
                padding: 0 {s(5)}px;
                color: #2c3e50;
            }}
            QPushButton {{
                background-color: #95a5a6;
                color: white;
                border: none;
                padding: {s(8)}px {s(16)}px;
                border-radius: {s(5)}px;
                min-height: {s(25)}px;
            }}
            QPushButton:hover {{
                background-color: #7f8c8d;
            }}
            QPushButton:pressed {{
                background-color: #6c7a7b;
            }}
            QPushButton:disabled {{
                background-color: #bdc3c7;
            }}
            QLineEdit {{
                border: {s(2)}px solid #bdc3c7;
                border-radius: {s(5)}px;
                padding: {s(5)}px {s(10)}px;
                background-color: white;
            }}
            QLineEdit:focus {{
                border-color: #3498db;
            }}
            QListWidget {{
                border: {s(2)}px solid #bdc3c7;
                border-radius: {s(5)}px;
                background-color: white;
            }}
            QTabWidget::pane {{
                border: {s(2)}px solid #bdc3c7;
                border-radius: {s(8)}px;
                top: -1px;
                background-color: white;
            }}
            QTabBar::tab {{
                background-color: #d5dbdb;
                border: {s(2)}px solid #bdc3c7;
                border-bottom: none;
                border-top-left-radius: {s(8)}px;
                border-top-right-radius: {s(8)}px;
                padding: {s(8)}px {s(20)}px;
                margin-right: {s(2)}px;
            }}
            QTabBar::tab:selected {{
                background-color: white;
                color: #2c3e50;
            }}
            QTextEdit {{
                border: {s(2)}px solid #bdc3c7;
                border-radius: {s(5)}px;
                background-color: white;
            }}
        """
        )

    def _toggle_password_visibility(self, state):
        mode = QLineEdit.EchoMode.Normal if state else QLineEdit.EchoMode.Password
        self.encrypt_password.setEchoMode(mode)
        self.encrypt_confirm.setEchoMode(mode)

    def _toggle_decrypt_password(self, state):
        mode = QLineEdit.EchoMode.Normal if state else QLineEdit.EchoMode.Password
        self.decrypt_password.setEchoMode(mode)

    def _toggle_output_dir(self, state):
        enabled = not state
        self.output_dir_edit.setEnabled(enabled)
        self.output_dir_btn.setEnabled(enabled)

    def _add_encrypt_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, "选择要加密的文件")
        if files:
            self._add_files_to_list(files, self.encrypt_file_list)

    def _add_encrypt_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "选择要加密的文件夹")
        if folder:
            self._collect_and_add_folder(folder, self.encrypt_file_list)

    def _add_decrypt_files(self):
        files, _ = QFileDialog.getOpenFileNames(
            self, "选择要解密的文件", "", "加密文件 (*.enc);;所有文件 (*.*)"
        )
        if files:
            self._add_files_to_list(files, self.decrypt_file_list)

    def _add_decrypt_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "选择要解密的文件夹")
        if folder:
            self._collect_and_add_folder(folder, self.decrypt_file_list, only_encrypted=True)

    def _add_files_to_list(self, files, list_widget):
        for file_path in files:
            if not self._is_file_in_list(file_path, list_widget):
                item = QListWidgetItem(file_path)
                list_widget.addItem(item)

    def _is_file_in_list(self, file_path, list_widget):
        for i in range(list_widget.count()):
            if list_widget.item(i).text() == file_path:
                return True
        return False

    def _collect_and_add_folder(self, folder_path, list_widget, only_encrypted=False):
        import os

        for root, dirs, files in os.walk(folder_path):
            for file in files:
                if only_encrypted and not file.endswith(".enc"):
                    continue
                file_path = os.path.join(root, file)
                if not self._is_file_in_list(file_path, list_widget):
                    item = QListWidgetItem(file_path)
                    list_widget.addItem(item)

    def _remove_selected(self, list_widget):
        for item in list_widget.selectedItems():
            list_widget.takeItem(list_widget.row(item))

    def _clear_list(self, list_widget):
        list_widget.clear()

    def _select_output_dir(self):
        folder = QFileDialog.getExistingDirectory(self, "选择输出目录")
        if folder:
            self.output_dir_edit.setText(folder)

    def _select_metadata_file(self):
        file, _ = QFileDialog.getOpenFileName(
            self, "选择加密文件", "", "加密文件 (*.enc);;所有文件 (*.*)"
        )
        if file:
            self.metadata_path_edit.setText(file)
            metadata = self.metadata_manager.load_metadata(file)
            if metadata:
                self._display_metadata(metadata)
            else:
                QMessageBox.warning(self, "提示", "未找到该文件的元数据信息")

    def _refresh_metadata_list(self):
        self.metadata_list.clear()
        metadata_list = self.metadata_manager.list_all_metadata()
        for metadata in metadata_list:
            original_name = metadata.get("original_name", "未知")
            enc_path = metadata.get("encrypted_path", "")
            item = QListWidgetItem(f"{original_name}")
            item.setData(Qt.ItemDataRole.UserRole, enc_path)
            self.metadata_list.addItem(item)

    def _show_metadata(self, item):
        enc_path = item.data(Qt.ItemDataRole.UserRole)
        if enc_path:
            metadata = self.metadata_manager.load_metadata(enc_path)
            if metadata:
                self._display_metadata(metadata)

    def _display_metadata(self, metadata):
        mm = self.metadata_manager
        text = f"""文件信息
{'='*50}
原始文件名: {metadata.get('original_name', 'N/A')}
原始文件大小: {mm.format_size(metadata.get('original_size', 0))}
加密文件路径: {metadata.get('encrypted_path', 'N/A')}
加密后文件大小: {mm.format_size(metadata.get('encrypted_size', 0))}
原始路径: {metadata.get('original_path', 'N/A')}

加密信息
{'='*50}
加密算法: {metadata.get('algorithm', 'N/A')}
加密时间: {metadata.get('encryption_time', 'N/A')}
密码哈希: {metadata.get('password_hash', 'N/A')[:32]}...
"""
        self.metadata_detail.setText(text)

    def _get_list_files(self, list_widget):
        files = []
        for i in range(list_widget.count()):
            files.append(list_widget.item(i).text())
        return files

    def _start_encryption(self):
        password = self.encrypt_password.text()
        confirm = self.encrypt_confirm.text()

        if not password:
            QMessageBox.warning(self, "提示", "请输入加密密码")
            return

        if password != confirm:
            QMessageBox.warning(self, "提示", "两次输入的密码不一致")
            return

        files = self._get_list_files(self.encrypt_file_list)
        if not files:
            QMessageBox.warning(self, "提示", "请添加要加密的文件")
            return

        output_dir = None
        if not self.output_same_check.isChecked():
            output_dir = self.output_dir_edit.text()
            if not output_dir:
                QMessageBox.warning(self, "提示", "请选择输出目录")
                return

        self._start_batch_process(files, password, "encrypt", output_dir)

    def _start_decryption(self):
        password = self.decrypt_password.text()

        if not password:
            QMessageBox.warning(self, "提示", "请输入解密密码")
            return

        files = self._get_list_files(self.decrypt_file_list)
        if not files:
            QMessageBox.warning(self, "提示", "请添加要解密的文件")
            return

        self._start_batch_process(files, password, "decrypt", None)

    def _start_batch_process(self, files, password, mode, output_dir):
        self.batch_processor = BatchProcessor(files, password, mode, output_dir)
        self.batch_processor.progress_updated.connect(self._on_progress)
        self.batch_processor.file_started.connect(self._on_file_started)
        self.batch_processor.file_completed.connect(self._on_file_completed)
        self.batch_processor.batch_completed.connect(self._on_batch_completed)

        self.cancel_btn.setEnabled(True)
        self.progress_bar.setMaximum(len(files))
        self.progress_bar.setValue(0)
        self.status_label.setText("处理中...")

        self.batch_processor.start()

    def _on_progress(self, current, total, filename):
        self.progress_bar.setValue(current)
        self.current_file_label.setText(f"当前文件: {os.path.basename(filename)}")

    def _on_file_started(self, filename, index, total):
        self.status_label.setText(f"处理中 ({index}/{total})...")

    def _on_file_completed(self, filename, status, error):
        if status == ProcessStatus.FAILED:
            print(f"失败: {filename} - {error}")

    def _on_batch_completed(self, results):
        self.cancel_btn.setEnabled(False)
        success_count = sum(1 for r in results if r.status == ProcessStatus.SUCCESS)
        fail_count = sum(1 for r in results if r.status == ProcessStatus.FAILED)
        total = len(results)

        self.status_label.setText(f"完成: 成功 {success_count}/{total}, 失败 {fail_count}")
        self.current_file_label.setText("处理完成")

        if fail_count > 0:
            error_msgs = "\n".join(
                [f"- {os.path.basename(r.source_path)}: {r.error}" for r in results if r.status == ProcessStatus.FAILED]
            )
            QMessageBox.warning(
                self,
                "处理完成",
                f"处理完成！\n成功: {success_count} 个\n失败: {fail_count} 个\n\n失败文件:\n{error_msgs}",
            )
        else:
            QMessageBox.information(self, "处理完成", f"处理完成！成功 {success_count} 个文件")

        self._refresh_metadata_list()

    def _cancel_processing(self):
        if self.batch_processor:
            self.batch_processor.cancel()
            self.status_label.setText("正在取消...")
            self.cancel_btn.setEnabled(False)

    def _load_app_config(self):
        config = self.app_data
        output_same = config.get_config("output_same_dir", True)
        self.output_same_check.setChecked(output_same)
        self.output_dir_edit.setEnabled(not output_same)
        self.output_dir_btn.setEnabled(not output_same)

        output_dir = config.get_config("output_dir", "")
        if output_dir:
            self.output_dir_edit.setText(output_dir)

        show_pwd = config.get_config("show_password", False)
        if show_pwd:
            self.show_password_check.setChecked(True)
            self.show_decrypt_check.setChecked(True)
            self.encrypt_password.setEchoMode(QLineEdit.EchoMode.Normal)
            self.encrypt_confirm.setEchoMode(QLineEdit.EchoMode.Normal)
            self.decrypt_password.setEchoMode(QLineEdit.EchoMode.Normal)

        geometry = config.get_config("window_geometry")
        if geometry:
            from PyQt6.QtCore import QByteArray
            self.restoreGeometry(QByteArray.fromHex(geometry.encode()))

    def _save_app_config(self):
        self.app_data.set_config("output_same_dir", self.output_same_check.isChecked())
        self.app_data.set_config("output_dir", self.output_dir_edit.text())
        self.app_data.set_config("show_password", self.show_password_check.isChecked())
        self.app_data.set_config(
            "window_geometry", bytes(self.saveGeometry().toHex()).decode()
        )

    def closeEvent(self, event):
        if self.batch_processor and self.batch_processor.isRunning():
            reply = QMessageBox.question(
                self,
                "确认退出",
                "正在处理文件，确定要退出吗？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply == QMessageBox.StandardButton.Yes:
                self.batch_processor.cancel()
                self.batch_processor.wait()
                self._save_app_config()
                event.accept()
            else:
                event.ignore()
        else:
            self._save_app_config()
            event.accept()
