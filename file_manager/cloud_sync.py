import os
import json
import shutil
import hashlib
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Dict, Any, Callable
from abc import ABC, abstractmethod
from enum import Enum


class SyncStatus(Enum):
    SYNCED = "synced"
    LOCAL_NEWER = "local_newer"
    CLOUD_NEWER = "cloud_newer"
    CONFLICT = "conflict"
    ONLY_LOCAL = "only_local"
    ONLY_CLOUD = "only_cloud"
    UNKNOWN = "unknown"


class SyncDirection(Enum):
    UPLOAD = "upload"
    DOWNLOAD = "download"
    BOTH = "both"


class CloudProviderBase(ABC):
    @abstractmethod
    def upload_file(self, local_path: str, remote_path: str) -> bool:
        pass

    @abstractmethod
    def download_file(self, remote_path: str, local_path: str) -> bool:
        pass

    @abstractmethod
    def delete_file(self, remote_path: str) -> bool:
        pass

    @abstractmethod
    def list_files(self, remote_dir: str = "") -> List[Dict[str, Any]]:
        pass

    @abstractmethod
    def get_file_info(self, remote_path: str) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    def exists(self, remote_path: str) -> bool:
        pass

    @abstractmethod
    def get_provider_name(self) -> str:
        pass


class LocalCloudProvider(CloudProviderBase):
    def __init__(self, root_dir: str = None):
        if root_dir is None:
            root_dir = str(Path.home() / ".file_crypto" / "cloud_sync")
        self.root_dir = Path(root_dir)
        self.root_dir.mkdir(parents=True, exist_ok=True)

    def _to_remote_path(self, remote_path: str) -> Path:
        remote_path = remote_path.lstrip("/").lstrip("\\")
        return self.root_dir / remote_path

    def _to_relative_path(self, absolute_path: Path) -> str:
        return str(absolute_path.relative_to(self.root_dir))

    def upload_file(self, local_path: str, remote_path: str) -> bool:
        try:
            local = Path(local_path)
            if not local.exists():
                return False
            remote = self._to_remote_path(remote_path)
            remote.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(local), str(remote))
            return True
        except Exception:
            return False

    def download_file(self, remote_path: str, local_path: str) -> bool:
        try:
            remote = self._to_remote_path(remote_path)
            if not remote.exists():
                return False
            local = Path(local_path)
            local.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(remote), str(local))
            return True
        except Exception:
            return False

    def delete_file(self, remote_path: str) -> bool:
        try:
            remote = self._to_remote_path(remote_path)
            if remote.exists():
                remote.unlink()
                return True
            return False
        except Exception:
            return False

    def list_files(self, remote_dir: str = "") -> List[Dict[str, Any]]:
        result = []
        remote = self._to_remote_path(remote_dir)
        if not remote.exists():
            return result
        for root, dirs, files in os.walk(str(remote)):
            for file in files:
                filepath = Path(root) / file
                rel_path = self._to_relative_path(filepath)
                stat = filepath.stat()
                result.append({
                    "path": rel_path,
                    "name": file,
                    "size": stat.st_size,
                    "modified_time": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                })
        return result

    def get_file_info(self, remote_path: str) -> Optional[Dict[str, Any]]:
        try:
            remote = self._to_remote_path(remote_path)
            if not remote.exists():
                return None
            stat = remote.stat()
            return {
                "path": remote_path,
                "name": remote.name,
                "size": stat.st_size,
                "modified_time": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            }
        except Exception:
            return None

    def exists(self, remote_path: str) -> bool:
        return self._to_remote_path(remote_path).exists()

    def get_provider_name(self) -> str:
        return "local_cloud"


class CloudSyncManager:
    STATE_FILE = "sync_state.json"

    def __init__(self, provider: CloudProviderBase = None, state_dir: str = None):
        if provider is None:
            self.provider = LocalCloudProvider()
        else:
            self.provider = provider

        if state_dir is None:
            state_dir = str(Path.home() / ".file_crypto")
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.state_path = self.state_dir / self.STATE_FILE
        self._state = self._load_state()

    def _load_state(self) -> Dict[str, Any]:
        if self.state_path.exists():
            try:
                with open(self.state_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return {"files": {}, "last_sync": None}
        return {"files": {}, "last_sync": None}

    def _save_state(self) -> None:
        import tempfile
        self.state_dir.mkdir(parents=True, exist_ok=True)
        temp_fd, temp_path = tempfile.mkstemp(
            dir=str(self.state_dir),
            suffix=".tmp"
        )
        try:
            with os.fdopen(temp_fd, "w", encoding="utf-8") as f:
                json.dump(self._state, f, indent=2, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
            if os.name == "nt":
                try:
                    os.replace(temp_path, str(self.state_path))
                except OSError:
                    if os.path.exists(str(self.state_path)):
                        os.unlink(str(self.state_path))
                    os.rename(temp_path, str(self.state_path))
            else:
                os.replace(temp_path, str(self.state_path))
        except Exception:
            if os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass
            raise

    def _get_file_hash(self, filepath: str) -> str:
        hasher = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    def _get_remote_file_id(self, local_path: str) -> str:
        path = Path(local_path).resolve()
        return hashlib.sha256(str(path).encode("utf-8")).hexdigest()

    def _get_remote_path(self, local_path: str) -> str:
        file_id = self._get_remote_file_id(local_path)
        filename = Path(local_path).name
        return f"{file_id}_{filename}"

    def add_sync_file(self, local_path: str) -> bool:
        local = Path(local_path)
        if not local.exists():
            return False

        file_id = self._get_remote_file_id(local_path)
        remote_path = self._get_remote_path(local_path)
        file_hash = self._get_file_hash(local_path)
        stat = local.stat()

        self._state["files"][file_id] = {
            "local_path": str(local.resolve()),
            "remote_path": remote_path,
            "file_name": local.name,
            "local_hash": file_hash,
            "cloud_hash": None,
            "local_modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "cloud_modified": None,
            "sync_status": SyncStatus.ONLY_LOCAL.value,
            "last_sync": None,
        }
        self._save_state()
        return True

    def remove_sync_file(self, local_path: str) -> bool:
        file_id = self._get_remote_file_id(local_path)
        if file_id in self._state["files"]:
            del self._state["files"][file_id]
            self._save_state()
            return True
        return False

    def get_sync_status(self, local_path: str) -> Optional[SyncStatus]:
        file_id = self._get_remote_file_id(local_path)
        if file_id not in self._state["files"]:
            return None
        return SyncStatus(self._state["files"][file_id]["sync_status"])

    def check_status(self, local_path: str) -> Optional[SyncStatus]:
        file_id = self._get_remote_file_id(local_path)
        if file_id not in self._state["files"]:
            return None

        file_state = self._state["files"][file_id]
        local = Path(file_state["local_path"])
        remote_path = file_state["remote_path"]

        local_exists = local.exists()
        cloud_exists = self.provider.exists(remote_path)

        if local_exists and not cloud_exists:
            status = SyncStatus.ONLY_LOCAL
        elif not local_exists and cloud_exists:
            status = SyncStatus.ONLY_CLOUD
        elif local_exists and cloud_exists:
            local_stat = local.stat()
            cloud_info = self.provider.get_file_info(remote_path)

            local_hash = self._get_file_hash(str(local))
            cloud_hash = self._get_cloud_file_hash(remote_path)

            if local_hash == cloud_hash:
                status = SyncStatus.SYNCED
            else:
                local_time = local_stat.st_mtime
                cloud_time = datetime.fromisoformat(cloud_info["modified_time"]).timestamp()

                if local_time > cloud_time + 60:
                    status = SyncStatus.LOCAL_NEWER
                elif cloud_time > local_time + 60:
                    status = SyncStatus.CLOUD_NEWER
                else:
                    status = SyncStatus.CONFLICT
        else:
            status = SyncStatus.UNKNOWN

        file_state["sync_status"] = status.value
        self._save_state()
        return status

    def _get_cloud_file_hash(self, remote_path: str) -> Optional[str]:
        import tempfile
        tmp_file = tempfile.NamedTemporaryFile(delete=False)
        tmp_path = tmp_file.name
        tmp_file.close()

        try:
            if self.provider.download_file(remote_path, tmp_path):
                file_hash = self._get_file_hash(tmp_path)
                os.unlink(tmp_path)
                return file_hash
            return None
        except Exception:
            if os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
            return None

    def upload(self, local_path: str, progress_callback: Callable[[int, int], None] = None) -> bool:
        file_id = self._get_remote_file_id(local_path)
        if file_id not in self._state["files"]:
            self.add_sync_file(local_path)

        file_state = self._state["files"][file_id]
        remote_path = file_state["remote_path"]

        if progress_callback:
            total = os.path.getsize(local_path)
            progress_callback(0, total)

        success = self.provider.upload_file(local_path, remote_path)

        if success:
            local_stat = Path(local_path).stat()
            file_hash = self._get_file_hash(local_path)
            file_state["local_hash"] = file_hash
            file_state["cloud_hash"] = file_hash
            file_state["local_modified"] = datetime.fromtimestamp(local_stat.st_mtime).isoformat()
            file_state["cloud_modified"] = datetime.fromtimestamp(local_stat.st_mtime).isoformat()
            file_state["sync_status"] = SyncStatus.SYNCED.value
            file_state["last_sync"] = datetime.now().isoformat()
            self._save_state()

            if progress_callback:
                progress_callback(local_stat.st_size, local_stat.st_size)

        return success

    def download(self, local_path: str, output_path: Optional[str] = None,
                 progress_callback: Callable[[int, int], None] = None) -> bool:
        file_id = self._get_remote_file_id(local_path)
        if file_id not in self._state["files"]:
            return False

        file_state = self._state["files"][file_id]
        remote_path = file_state["remote_path"]

        if output_path is None:
            output_path = file_state["local_path"]

        cloud_info = self.provider.get_file_info(remote_path)
        if cloud_info and progress_callback:
            progress_callback(0, cloud_info["size"])

        success = self.provider.download_file(remote_path, output_path)

        if success:
            local_stat = Path(output_path).stat()
            file_hash = self._get_file_hash(output_path)
            file_state["local_hash"] = file_hash
            file_state["cloud_hash"] = file_hash
            file_state["local_modified"] = datetime.fromtimestamp(local_stat.st_mtime).isoformat()
            file_state["sync_status"] = SyncStatus.SYNCED.value
            file_state["last_sync"] = datetime.now().isoformat()
            self._save_state()

            if progress_callback:
                progress_callback(local_stat.st_size, local_stat.st_size)

        return success

    def sync_file(self, local_path: str, direction: SyncDirection = SyncDirection.BOTH,
                  progress_callback: Callable[[int, int], None] = None) -> bool:
        status = self.check_status(local_path)
        if status is None:
            return False

        if status == SyncStatus.SYNCED:
            return True

        if status == SyncStatus.ONLY_LOCAL:
            if direction in [SyncDirection.UPLOAD, SyncDirection.BOTH]:
                return self.upload(local_path, progress_callback)
            return False

        if status == SyncStatus.ONLY_CLOUD:
            if direction in [SyncDirection.DOWNLOAD, SyncDirection.BOTH]:
                return self.download(local_path, None, progress_callback)
            return False

        if status == SyncStatus.LOCAL_NEWER:
            if direction in [SyncDirection.UPLOAD, SyncDirection.BOTH]:
                return self.upload(local_path, progress_callback)
            return False

        if status == SyncStatus.CLOUD_NEWER:
            if direction in [SyncDirection.DOWNLOAD, SyncDirection.BOTH]:
                return self.download(local_path, None, progress_callback)
            return False

        if status == SyncStatus.CONFLICT:
            if direction == SyncDirection.UPLOAD:
                return self.upload(local_path, progress_callback)
            elif direction == SyncDirection.DOWNLOAD:
                return self.download(local_path, None, progress_callback)
            else:
                return False

        return False

    def list_sync_files(self) -> List[Dict[str, Any]]:
        result = []
        for file_id, info in self._state["files"].items():
            result.append({
                "file_id": file_id,
                "local_path": info["local_path"],
                "file_name": info["file_name"],
                "sync_status": info["sync_status"],
                "last_sync": info.get("last_sync"),
            })
        return result

    def get_provider_name(self) -> str:
        return self.provider.get_provider_name()
