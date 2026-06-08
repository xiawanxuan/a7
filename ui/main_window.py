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
from file_manager import VersionManager, CloudSyncManager, ShareManager, SyncStatus
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
        self.version_manager = VersionManager()
        self.cloud_sync = CloudSyncManager()
        self.share_manager = ShareManager()

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

        self._init_version_tab()
        self._init_cloud_tab()
        self._init_share_tab()

        self._refresh_metadata_list()

    def _init_version_tab(self):
        version_tab = QWidget()
        layout = QVBoxLayout(version_tab)
        layout.setSpacing(self._scale(10))

        select_layout = QHBoxLayout()
        self.version_file_edit = QLineEdit()
        self.version_file_edit.setPlaceholderText("选择加密文件查看历史版本...")
        self.version_file_edit.setMinimumHeight(self._scale(30))
        select_btn = QPushButton("选择文件")
        select_btn.clicked.connect(self._select_version_file)
        refresh_btn = QPushButton("刷新")
        refresh_btn.clicked.connect(self._refresh_version_list)
        select_layout.addWidget(self.version_file_edit, 1)
        select_layout.addWidget(select_btn)
        select_layout.addWidget(refresh_btn)
        layout.addLayout(select_layout)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        list_widget = QWidget()
        list_layout = QVBoxLayout(list_widget)
        list_layout.setContentsMargins(0, 0, 0, 0)

        list_label = QLabel("版本列表")
        list_label.setStyleSheet("font-weight: bold; color: #34495e;")
        list_layout.addWidget(list_label)

        self.version_list = QListWidget()
        self.version_list.itemClicked.connect(self._show_version_detail)
        list_layout.addWidget(self.version_list, 1)

        btn_layout = QHBoxLayout()
        restore_btn = QPushButton("恢复此版本")
        restore_btn.clicked.connect(self._restore_version)
        delete_btn = QPushButton("删除此版本")
        delete_btn.clicked.connect(self._delete_version)
        btn_layout.addWidget(restore_btn)
        btn_layout.addWidget(delete_btn)
        list_layout.addLayout(btn_layout)

        splitter.addWidget(list_widget)

        detail_widget = QWidget()
        detail_layout = QVBoxLayout(detail_widget)
        detail_layout.setContentsMargins(0, 0, 0, 0)

        detail_label = QLabel("版本详情")
        detail_label.setStyleSheet("font-weight: bold; color: #34495e;")
        detail_layout.addWidget(detail_label)

        self.version_detail = QTextEdit()
        self.version_detail.setReadOnly(True)
        detail_layout.addWidget(self.version_detail, 1)

        splitter.addWidget(detail_widget)
        splitter.setSizes([self._scale(350), self._scale(450)])

        layout.addWidget(splitter, 1)

        self.tab_widget.addTab(version_tab, "版本管理")

    def _select_version_file(self):
        file, _ = QFileDialog.getOpenFileName(
            self, "选择加密文件", "", "加密文件 (*.enc);;所有文件 (*.*)"
        )
        if file:
            self.version_file_edit.setText(file)
            self._refresh_version_list()

    def _refresh_version_list(self):
        self.version_list.clear()
        file_path = self.version_file_edit.text().strip()
        if not file_path or not os.path.exists(file_path):
            metadata_list = self.version_manager.list_all_versioned_files()
            for info in metadata_list:
                item = QListWidgetItem(f"{info['original_name']} ({info['version_count']}个版本)")
                item.setData(Qt.ItemDataRole.UserRole, info["original_path"])
                self.version_list.addItem(item)
            return

        versions = self.version_manager.get_versions(file_path)
        for v in versions:
            item = QListWidgetItem(f"{v['timestamp']} - {v.get('description', '无描述')}")
            item.setData(Qt.ItemDataRole.UserRole, v["version_id"])
            item.setData(Qt.ItemDataRole.UserRole + 1, file_path)
            self.version_list.addItem(item)

    def _show_version_detail(self, item):
        version_id = item.data(Qt.ItemDataRole.UserRole)
        file_path = item.data(Qt.ItemDataRole.UserRole + 1)

        if file_path is None:
            file_path = version_id
            versions = self.version_manager.get_versions(file_path)
            if versions:
                latest = versions[0]
                self._display_version_detail(latest)
        else:
            versions = self.version_manager.get_versions(file_path)
            for v in versions:
                if v["version_id"] == version_id:
                    self._display_version_detail(v)
                    break

    def _display_version_detail(self, version_info):
        mm = self.metadata_manager
        text = f"""版本信息
{'=' * 50}
版本ID: {version_info.get('version_id', 'N/A')}
创建时间: {version_info.get('timestamp', 'N/A')}
原始文件名: {version_info.get('original_name', 'N/A')}
原始文件大小: {mm.format_size(version_info.get('original_size', 0))}
加密后大小: {mm.format_size(version_info.get('encrypted_size', 0))}
描述: {version_info.get('description', '无')}
版本文件: {version_info.get('version_file', 'N/A')}
"""
        self.version_detail.setText(text)

    def _restore_version(self):
        current_item = self.version_list.currentItem()
        if not current_item:
            QMessageBox.warning(self, "提示", "请先选择要恢复的版本")
            return

        version_id = current_item.data(Qt.ItemDataRole.UserRole)
        file_path = current_item.data(Qt.ItemDataRole.UserRole + 1)

        if file_path is None:
            QMessageBox.warning(self, "提示", "请先选择具体文件")
            return

        password, ok = self._input_password("请输入解密密码以恢复版本")
        if not ok or not password:
            return

        output_path, _ = QFileDialog.getSaveFileName(
            self, "选择恢复文件保存位置",
            f"{Path(file_path).stem}_v{version_id}{Path(file_path).suffix}",
            "所有文件 (*.*)"
        )
        if not output_path:
            return

        try:
            from file_manager import FileHandler
            handler = FileHandler(password)
            result = handler.restore_and_decrypt_version(file_path, version_id, output_path)
            if result:
                QMessageBox.information(self, "成功", f"版本恢复成功！\n文件已保存到: {output_path}")
            else:
                QMessageBox.warning(self, "失败", "版本恢复失败，请检查密码是否正确")
        except Exception as e:
            QMessageBox.warning(self, "错误", f"恢复失败: {str(e)}")

    def _delete_version(self):
        current_item = self.version_list.currentItem()
        if not current_item:
            QMessageBox.warning(self, "提示", "请先选择要删除的版本")
            return

        version_id = current_item.data(Qt.ItemDataRole.UserRole)
        file_path = current_item.data(Qt.ItemDataRole.UserRole + 1)

        if file_path is None:
            QMessageBox.warning(self, "提示", "请先选择具体文件")
            return

        reply = QMessageBox.question(
            self, "确认删除",
            "确定要删除这个版本吗？此操作不可撤销。",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            if self.version_manager.delete_version(file_path, version_id):
                self._refresh_version_list()
                self.version_detail.clear()
                QMessageBox.information(self, "成功", "版本已删除")
            else:
                QMessageBox.warning(self, "失败", "删除版本失败")

    def _input_password(self, title: str):
        from PyQt6.QtWidgets import QDialog, QDialogButtonBox

        dialog = QDialog(self)
        dialog.setWindowTitle(title)
        dialog.setMinimumWidth(self._scale(300))

        layout = QVBoxLayout(dialog)
        password_edit = QLineEdit()
        password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        password_edit.setPlaceholderText("请输入密码...")
        password_edit.setMinimumHeight(self._scale(30))
        layout.addWidget(password_edit)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)

        result = dialog.exec()
        if result == QDialog.DialogCode.Accepted:
            return password_edit.text(), True
        return "", False

    def _init_cloud_tab(self):
        cloud_tab = QWidget()
        layout = QVBoxLayout(cloud_tab)
        layout.setSpacing(self._scale(10))

        header_layout = QHBoxLayout()
        status_label = QLabel(f"云存储提供方: {self.cloud_sync.get_provider_name()}")
        status_label.setStyleSheet("color: #34495e; font-weight: bold;")
        header_layout.addWidget(status_label)
        header_layout.addStretch()
        refresh_btn = QPushButton("刷新状态")
        refresh_btn.clicked.connect(self._refresh_cloud_list)
        header_layout.addWidget(refresh_btn)
        layout.addLayout(header_layout)

        file_list_group = QGroupBox("同步文件列表")
        file_layout = QVBoxLayout(file_list_group)

        self.cloud_file_list = QListWidget()
        file_layout.addWidget(self.cloud_file_list, 1)

        btn_layout = QHBoxLayout()
        add_btn = QPushButton("添加同步文件")
        add_btn.clicked.connect(self._add_cloud_sync_file)
        upload_btn = QPushButton("上传选中")
        upload_btn.clicked.connect(self._upload_selected)
        download_btn = QPushButton("下载选中")
        download_btn.clicked.connect(self._download_selected)
        remove_btn = QPushButton("移除同步")
        remove_btn.clicked.connect(self._remove_cloud_sync)
        for btn in [add_btn, upload_btn, download_btn, remove_btn]:
            btn_layout.addWidget(btn)
        file_layout.addLayout(btn_layout)

        layout.addWidget(file_list_group, 1)

        self.cloud_progress = QProgressBar()
        self.cloud_progress.setMinimumHeight(self._scale(20))
        layout.addWidget(self.cloud_progress)

        self.cloud_status_label = QLabel("就绪")
        self.cloud_status_label.setStyleSheet("color: #7f8c8d;")
        layout.addWidget(self.cloud_status_label)

        self.tab_widget.addTab(cloud_tab, "云同步")

        self._refresh_cloud_list()

    def _refresh_cloud_list(self):
        self.cloud_file_list.clear()
        sync_files = self.cloud_sync.list_sync_files()
        for info in sync_files:
            status_text = self._get_sync_status_text(info["sync_status"])
            item_text = f"{info['file_name']}  -  {status_text}"
            item = QListWidgetItem(item_text)
            item.setData(Qt.ItemDataRole.UserRole, info["local_path"])
            if info["sync_status"] == "synced":
                item.setForeground(Qt.GlobalColor.darkGreen)
            elif info["sync_status"] in ["local_newer", "only_local"]:
                item.setForeground(Qt.GlobalColor.darkBlue)
            elif info["sync_status"] in ["cloud_newer", "only_cloud"]:
                item.setForeground(Qt.GlobalColor.darkYellow)
            elif info["sync_status"] == "conflict":
                item.setForeground(Qt.GlobalColor.red)
            self.cloud_file_list.addItem(item)

    def _get_sync_status_text(self, status: str) -> str:
        status_map = {
            "synced": "已同步",
            "local_newer": "本地较新",
            "cloud_newer": "云端较新",
            "conflict": "冲突",
            "only_local": "仅本地",
            "only_cloud": "仅云端",
            "unknown": "未知",
        }
        return status_map.get(status, status)

    def _add_cloud_sync_file(self):
        files, _ = QFileDialog.getOpenFileNames(
            self, "选择要同步的加密文件", "", "加密文件 (*.enc);;所有文件 (*.*)"
        )
        if files:
            for f in files:
                self.cloud_sync.add_sync_file(f)
            self._refresh_cloud_list()
            QMessageBox.information(self, "成功", f"已添加 {len(files)} 个文件到同步列表")

    def _upload_selected(self):
        items = self.cloud_file_list.selectedItems()
        if not items:
            QMessageBox.warning(self, "提示", "请先选择要上传的文件")
            return

        self.cloud_progress.setMaximum(len(items))
        self.cloud_progress.setValue(0)

        success_count = 0
        for i, item in enumerate(items):
            local_path = item.data(Qt.ItemDataRole.UserRole)
            self.cloud_status_label.setText(f"正在上传: {os.path.basename(local_path)}")
            if self.cloud_sync.upload(local_path):
                success_count += 1
            self.cloud_progress.setValue(i + 1)

        self.cloud_status_label.setText(f"上传完成: 成功 {success_count}/{len(items)}")
        self._refresh_cloud_list()

    def _download_selected(self):
        items = self.cloud_file_list.selectedItems()
        if not items:
            QMessageBox.warning(self, "提示", "请先选择要下载的文件")
            return

        self.cloud_progress.setMaximum(len(items))
        self.cloud_progress.setValue(0)

        success_count = 0
        for i, item in enumerate(items):
            local_path = item.data(Qt.ItemDataRole.UserRole)
            self.cloud_status_label.setText(f"正在下载: {os.path.basename(local_path)}")
            if self.cloud_sync.download(local_path):
                success_count += 1
            self.cloud_progress.setValue(i + 1)

        self.cloud_status_label.setText(f"下载完成: 成功 {success_count}/{len(items)}")
        self._refresh_cloud_list()

    def _remove_cloud_sync(self):
        items = self.cloud_file_list.selectedItems()
        if not items:
            QMessageBox.warning(self, "提示", "请先选择要移除的文件")
            return

        reply = QMessageBox.question(
            self, "确认移除",
            f"确定要从同步列表中移除 {len(items)} 个文件吗？",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            for item in items:
                local_path = item.data(Qt.ItemDataRole.UserRole)
                self.cloud_sync.remove_sync_file(local_path)
            self._refresh_cloud_list()

    def _init_share_tab(self):
        share_tab = QWidget()
        layout = QVBoxLayout(share_tab)
        layout.setSpacing(self._scale(10))

        create_group = QGroupBox("创建分享")
        create_layout = QFormLayout(create_group)

        self.share_file_edit = QLineEdit()
        self.share_file_edit.setPlaceholderText("选择要分享的加密文件...")
        self.share_file_edit.setMinimumHeight(self._scale(30))
        select_share_btn = QPushButton("选择文件")
        select_share_btn.clicked.connect(self._select_share_file)
        file_layout = QHBoxLayout()
        file_layout.addWidget(self.share_file_edit, 1)
        file_layout.addWidget(select_share_btn)

        self.share_expiry_combo = QComboBox()
        self.share_expiry_combo.addItems(["1小时", "24小时", "7天", "30天", "永久"])

        self.share_desc_edit = QLineEdit()
        self.share_desc_edit.setPlaceholderText("分享描述（可选）...")

        create_share_btn = QPushButton("创建分享链接")
        create_share_btn.setMinimumHeight(self._scale(35))
        create_share_btn.setStyleSheet(
            f"""
            QPushButton {{
                background-color: #9b59b6;
                color: white;
                font-weight: bold;
                border-radius: {self._scale(5)}px;
            }}
            QPushButton:hover {{
                background-color: #8e44ad;
            }}
            """
        )
        create_share_btn.clicked.connect(self._create_share)

        create_layout.addRow("文件:", file_layout)
        create_layout.addRow("有效期:", self.share_expiry_combo)
        create_layout.addRow("描述:", self.share_desc_edit)
        create_layout.addRow("", create_share_btn)

        layout.addWidget(create_group)

        shares_group = QGroupBox("我的分享")
        shares_layout = QVBoxLayout(shares_group)

        self.share_list = QListWidget()
        self.share_list.itemClicked.connect(self._show_share_detail)
        shares_layout.addWidget(self.share_list, 1)

        btn_layout = QHBoxLayout()
        copy_link_btn = QPushButton("复制链接")
        copy_link_btn.clicked.connect(self._copy_share_link)
        export_btn = QPushButton("导出分享文件")
        export_btn.clicked.connect(self._export_share_file)
        revoke_btn = QPushButton("撤销分享")
        revoke_btn.clicked.connect(self._revoke_share)
        refresh_btn = QPushButton("刷新")
        refresh_btn.clicked.connect(self._refresh_share_list)
        for btn in [copy_link_btn, export_btn, revoke_btn, refresh_btn]:
            btn_layout.addWidget(btn)
        shares_layout.addLayout(btn_layout)

        layout.addWidget(shares_group, 1)

        detail_group = QGroupBox("分享详情")
        detail_layout = QVBoxLayout(detail_group)
        self.share_detail = QTextEdit()
        self.share_detail.setReadOnly(True)
        self.share_detail.setMaximumHeight(self._scale(120))
        detail_layout.addWidget(self.share_detail)
        layout.addWidget(detail_group)

        self.tab_widget.addTab(share_tab, "安全分享")

        self._refresh_share_list()

    def _select_share_file(self):
        file, _ = QFileDialog.getOpenFileName(
            self, "选择要分享的加密文件", "", "加密文件 (*.enc);;所有文件 (*.*)"
        )
        if file:
            self.share_file_edit.setText(file)

    def _get_expiry_hours(self, text: str) -> int:
        mapping = {
            "1小时": 1,
            "24小时": 24,
            "7天": 7 * 24,
            "30天": 30 * 24,
            "永久": 87600,
        }
        return mapping.get(text, 24)

    def _create_share(self):
        file_path = self.share_file_edit.text().strip()
        if not file_path or not os.path.exists(file_path):
            QMessageBox.warning(self, "提示", "请选择要分享的加密文件")
            return

        expiry_text = self.share_expiry_combo.currentText()
        expiry_hours = self._get_expiry_hours(expiry_text)
        description = self.share_desc_edit.text().strip()

        try:
            result = self.share_manager.create_share(
                encrypted_file_path=file_path,
                expiry_hours=expiry_hours,
                description=description,
            )

            detail_text = f"""分享创建成功！
{'=' * 40}
分享ID: {result['share_id']}
分享密码: {result['share_password']}
文件名: {result['original_name']}
文件大小: {self.metadata_manager.format_size(result['original_size'])}
有效期: {expiry_text}
过期时间: {result['expires_at']}
分享链接: {self.share_manager.get_share_link(result['share_id'])}

⚠️  请妥善保管分享密码，接收方需要密码才能解密文件
"""
            self.share_detail.setText(detail_text)

            self._refresh_share_list()
            QMessageBox.information(self, "成功", "分享创建成功！")
        except Exception as e:
            QMessageBox.warning(self, "错误", f"创建分享失败: {str(e)}")

    def _refresh_share_list(self):
        self.share_list.clear()
        shares = self.share_manager.list_shares(include_expired=True)
        for share in shares:
            is_active = share.get("is_active", True) and not self._is_share_expired(share)
            status_text = "有效" if is_active else "已过期/撤销"
            text = f"{share['original_name']}  -  {status_text}"
            item = QListWidgetItem(text)
            item.setData(Qt.ItemDataRole.UserRole, share["share_id"])
            if not is_active:
                item.setForeground(Qt.GlobalColor.gray)
            self.share_list.addItem(item)

    def _is_share_expired(self, share: dict) -> bool:
        from datetime import datetime
        try:
            expires_at = datetime.fromisoformat(share["expires_at"])
            return datetime.now() > expires_at
        except Exception:
            return False

    def _show_share_detail(self, item):
        share_id = item.data(Qt.ItemDataRole.UserRole)
        share = self.share_manager.get_share_info(share_id)
        if share:
            is_active = share.get("is_active", True)
            status_text = "有效" if is_active else "已撤销"
            text = f"""分享ID: {share['share_id']}
文件名: {share['original_name']}
文件大小: {self.metadata_manager.format_size(share['original_size'])}
创建时间: {share['created_at']}
过期时间: {share['expires_at']}
下载次数: {share.get('download_count', 0)}
状态: {status_text}
描述: {share.get('description', '无')}
"""
            self.share_detail.setText(text)

    def _copy_share_link(self):
        current_item = self.share_list.currentItem()
        if not current_item:
            QMessageBox.warning(self, "提示", "请先选择一个分享")
            return

        share_id = current_item.data(Qt.ItemDataRole.UserRole)
        share = self.share_manager.get_share_info(share_id)
        if not share:
            return

        from PyQt6.QtGui import QClipboard
        link = self.share_manager.get_share_link(share_id)
        QApplication.clipboard().setText(link)
        QMessageBox.information(self, "成功", "分享链接已复制到剪贴板")

    def _export_share_file(self):
        current_item = self.share_list.currentItem()
        if not current_item:
            QMessageBox.warning(self, "提示", "请先选择一个分享")
            return

        share_id = current_item.data(Qt.ItemDataRole.UserRole)
        share = self.share_manager.get_share_info(share_id)
        if not share:
            return

        output_path, _ = QFileDialog.getSaveFileName(
            self, "导出分享文件", f"{share['original_name']}.share",
            "分享文件 (*.share);;所有文件 (*.*)"
        )
        if output_path:
            if self.share_manager.export_share_file(share_id, output_path):
                QMessageBox.information(self, "成功", f"分享文件已导出到: {output_path}")
            else:
                QMessageBox.warning(self, "失败", "导出分享文件失败")

    def _revoke_share(self):
        current_item = self.share_list.currentItem()
        if not current_item:
            QMessageBox.warning(self, "提示", "请先选择一个分享")
            return

        reply = QMessageBox.question(
            self, "确认撤销",
            "确定要撤销这个分享吗？撤销后将无法再使用。",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            share_id = current_item.data(Qt.ItemDataRole.UserRole)
            if self.share_manager.revoke_share(share_id):
                self._refresh_share_list()
                self.share_detail.clear()
                QMessageBox.information(self, "成功", "分享已撤销")
            else:
                QMessageBox.warning(self, "失败", "撤销分享失败")

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
