import os
import json
import shutil
import hashlib
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Dict, Any


class VersionManager:
    VERSIONS_DIR_NAME = ".versions"
    VERSION_INDEX_FILE = "versions_index.json"

    def __init__(self, storage_dir: str = None):
        if storage_dir is None:
            storage_dir = str(Path.home() / ".file_crypto" / "versions")
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.index_path = self.storage_dir / self.VERSION_INDEX_FILE
        self._index = self._load_index()

    def _load_index(self) -> Dict[str, Any]:
        if self.index_path.exists():
            try:
                with open(self.index_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return {"files": {}}
        return {"files": {}}

    def _save_index(self) -> None:
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        import tempfile
        temp_fd, temp_path = tempfile.mkstemp(
            dir=str(self.storage_dir),
            suffix=".tmp"
        )
        try:
            with os.fdopen(temp_fd, "w", encoding="utf-8") as f:
                json.dump(self._index, f, indent=2, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
            if os.name == "nt":
                try:
                    os.replace(temp_path, str(self.index_path))
                except OSError:
                    if os.path.exists(str(self.index_path)):
                        os.unlink(str(self.index_path))
                    os.rename(temp_path, str(self.index_path))
            else:
                os.replace(temp_path, str(self.index_path))
        except Exception:
            if os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass
            raise

    def _get_file_id(self, file_path: str) -> str:
        path = Path(file_path).resolve()
        return hashlib.sha256(str(path).encode("utf-8")).hexdigest()

    def _get_version_dir(self, file_id: str) -> Path:
        return self.storage_dir / file_id

    def save_version(
        self,
        original_path: str,
        encrypted_path: str,
        description: str = "",
    ) -> str:
        file_id = self._get_file_id(original_path)
        version_dir = self._get_version_dir(file_id)
        version_dir.mkdir(parents=True, exist_ok=True)

        version_id = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        timestamp = datetime.now().isoformat()

        version_file = version_dir / f"{version_id}.enc"
        shutil.copy2(encrypted_path, str(version_file))

        original_size = os.path.getsize(original_path)
        encrypted_size = os.path.getsize(version_file)

        version_info = {
            "version_id": version_id,
            "timestamp": timestamp,
            "original_path": str(Path(original_path).resolve()),
            "original_name": Path(original_path).name,
            "original_size": original_size,
            "encrypted_size": encrypted_size,
            "description": description,
            "version_file": str(version_file),
        }

        if file_id not in self._index["files"]:
            self._index["files"][file_id] = {
                "original_path": str(Path(original_path).resolve()),
                "original_name": Path(original_path).name,
                "versions": [],
            }

        self._index["files"][file_id]["versions"].insert(0, version_info)

        max_versions = 10
        if len(self._index["files"][file_id]["versions"]) > max_versions:
            old_versions = self._index["files"][file_id]["versions"][max_versions:]
            for old_ver in old_versions:
                old_file = Path(old_ver["version_file"])
                if old_file.exists():
                    old_file.unlink()
            self._index["files"][file_id]["versions"] = self._index["files"][file_id]["versions"][:max_versions]

        self._save_index()
        return version_id

    def get_versions(self, file_path: str) -> List[Dict[str, Any]]:
        file_id = self._get_file_id(file_path)
        if file_id not in self._index["files"]:
            return []
        return list(self._index["files"][file_id]["versions"])

    def get_version_count(self, file_path: str) -> int:
        return len(self.get_versions(file_path))

    def restore_version(
        self,
        file_path: str,
        version_id: str,
        output_path: Optional[str] = None,
    ) -> Optional[str]:
        file_id = self._get_file_id(file_path)
        if file_id not in self._index["files"]:
            return None

        version_info = None
        for v in self._index["files"][file_id]["versions"]:
            if v["version_id"] == version_id:
                version_info = v
                break

        if version_info is None:
            return None

        version_file = Path(version_info["version_file"])
        if not version_file.exists():
            return None

        if output_path is None:
            output_path = str(Path(file_path).with_name(
                f"{Path(file_path).stem}_v{version_id}{Path(file_path).suffix}.enc"
            ))

        shutil.copy2(str(version_file), output_path)
        return output_path

    def delete_version(self, file_path: str, version_id: str) -> bool:
        file_id = self._get_file_id(file_path)
        if file_id not in self._index["files"]:
            return False

        versions = self._index["files"][file_id]["versions"]
        for i, v in enumerate(versions):
            if v["version_id"] == version_id:
                version_file = Path(v["version_file"])
                if version_file.exists():
                    version_file.unlink()
                del versions[i]
                self._save_index()
                return True

        return False

    def delete_all_versions(self, file_path: str) -> bool:
        file_id = self._get_file_id(file_path)
        if file_id not in self._index["files"]:
            return False

        version_dir = self._get_version_dir(file_id)
        if version_dir.exists():
            shutil.rmtree(str(version_dir))

        del self._index["files"][file_id]
        self._save_index()
        return True

    def list_all_versioned_files(self) -> List[Dict[str, Any]]:
        result = []
        for file_id, info in self._index["files"].items():
            result.append({
                "file_id": file_id,
                "original_path": info["original_path"],
                "original_name": info["original_name"],
                "version_count": len(info["versions"]),
                "latest_version": info["versions"][0] if info["versions"] else None,
            })
        return result
