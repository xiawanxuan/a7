import os
import threading
from pathlib import Path
from typing import List, Callable, Optional, Dict, Any
from enum import Enum
from PyQt6.QtCore import QThread, pyqtSignal

from .file_handler import FileHandler


class ProcessStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


class ProcessResult:
    def __init__(self, source_path: str, target_path: str = "", status: ProcessStatus = ProcessStatus.PENDING, error: str = ""):
        self.source_path = source_path
        self.target_path = target_path
        self.status = status
        self.error = error


class BatchProcessor(QThread):
    progress_updated = pyqtSignal(int, int, str)
    file_started = pyqtSignal(str, int, int)
    file_completed = pyqtSignal(str, ProcessStatus, str)
    batch_completed = pyqtSignal(list)

    def __init__(
        self,
        file_paths: List[str],
        password: str,
        mode: str = "encrypt",
        output_dir: Optional[str] = None,
        parent=None,
    ):
        super().__init__(parent)
        self.file_paths = file_paths
        self.password = password
        self.mode = mode
        self.output_dir = output_dir
        self._is_cancelled = False
        self._lock = threading.Lock()
        self.results: List[ProcessResult] = []

    def cancel(self) -> None:
        with self._lock:
            self._is_cancelled = True

    def is_cancelled(self) -> bool:
        with self._lock:
            return self._is_cancelled

    def run(self) -> None:
        self.results = []
        file_handler = FileHandler(self.password)
        total_files = len(self.file_paths)

        for idx, file_path in enumerate(self.file_paths):
            if self.is_cancelled():
                break

            self.file_started.emit(file_path, idx + 1, total_files)
            self.progress_updated.emit(idx, total_files, file_path)

            result = ProcessResult(source_path=file_path)

            try:
                if self.mode == "encrypt":
                    if self.output_dir:
                        output_path = self._get_output_path(file_path, self.output_dir, "encrypt")
                    else:
                        output_path = None
                    target = file_handler.encrypt_file(file_path, output_path)
                    result.target_path = target
                    result.status = ProcessStatus.SUCCESS
                elif self.mode == "decrypt":
                    if self.output_dir:
                        output_path = self._get_output_path(file_path, self.output_dir, "decrypt")
                    else:
                        output_path = None
                    target = file_handler.decrypt_file(file_path, output_path)
                    result.target_path = target
                    result.status = ProcessStatus.SUCCESS
                else:
                    result.status = ProcessStatus.FAILED
                    result.error = f"Unknown mode: {self.mode}"
            except Exception as e:
                result.status = ProcessStatus.FAILED
                result.error = str(e)

            self.results.append(result)
            self.file_completed.emit(file_path, result.status, result.error)

        self.progress_updated.emit(total_files, total_files, "完成")
        self.batch_completed.emit(self.results)

    def _get_output_path(self, source_path: str, output_dir: str, mode: str) -> str:
        source_name = Path(source_path).name
        if mode == "encrypt":
            if not source_name.endswith(FileHandler.ENCRYPTED_EXT):
                output_name = source_name + FileHandler.ENCRYPTED_EXT
            else:
                output_name = source_name
        else:
            if source_name.endswith(FileHandler.ENCRYPTED_EXT):
                output_name = source_name[: -len(FileHandler.ENCRYPTED_EXT)]
            else:
                output_name = source_name + ".decrypted"
        return str(Path(output_dir) / output_name)


class FolderBatchProcessor(QThread):
    progress_updated = pyqtSignal(int, int, str)
    folder_started = pyqtSignal(str)
    folder_completed = pyqtSignal(str, ProcessStatus, str, int)
    batch_completed = pyqtSignal(list)

    def __init__(
        self,
        folder_paths: List[str],
        password: str,
        mode: str = "encrypt",
        output_dir: Optional[str] = None,
        parent=None,
    ):
        super().__init__(parent)
        self.folder_paths = folder_paths
        self.password = password
        self.mode = mode
        self.output_dir = output_dir
        self._is_cancelled = False
        self._lock = threading.Lock()
        self.results = []

    def cancel(self) -> None:
        with self._lock:
            self._is_cancelled = True

    def is_cancelled(self) -> bool:
        with self._lock:
            return self._is_cancelled

    def run(self) -> None:
        self.results = []
        file_handler = FileHandler(self.password)
        total_folders = len(self.folder_paths)

        for idx, folder_path in enumerate(self.folder_paths):
            if self.is_cancelled():
                break

            self.folder_started.emit(folder_path)
            self.progress_updated.emit(idx, total_folders, folder_path)

            result = ProcessResult(source_path=folder_path)

            try:
                if self.mode == "encrypt":
                    if self.output_dir:
                        out_dir = str(Path(self.output_dir) / f"{Path(folder_path).name}_encrypted")
                    else:
                        out_dir = None
                    files = file_handler.encrypt_folder(folder_path, out_dir)
                    result.target_path = os.path.dirname(files[0]) if files else ""
                    result.status = ProcessStatus.SUCCESS
                    file_count = len(files)
                elif self.mode == "decrypt":
                    if self.output_dir:
                        out_dir = str(Path(self.output_dir) / f"{Path(folder_path).name}_decrypted")
                    else:
                        out_dir = None
                    files = file_handler.decrypt_folder(folder_path, out_dir)
                    result.target_path = os.path.dirname(files[0]) if files else ""
                    result.status = ProcessStatus.SUCCESS
                    file_count = len(files)
                else:
                    result.status = ProcessStatus.FAILED
                    result.error = f"Unknown mode: {self.mode}"
                    file_count = 0
            except Exception as e:
                result.status = ProcessStatus.FAILED
                result.error = str(e)
                file_count = 0

            self.results.append(result)
            self.folder_completed.emit(folder_path, result.status, result.error, file_count)

        self.progress_updated.emit(total_folders, total_folders, "完成")
        self.batch_completed.emit(self.results)
