import os
from pathlib import Path
from typing import List, Tuple, Optional
from crypto import AESCrypto, MetadataManager


class FileHandler:
    ENCRYPTED_EXT = ".enc"

    def __init__(self, password: str):
        self.crypto = AESCrypto(password)
        self.metadata_manager = MetadataManager()

    def encrypt_file(self, input_path: str, output_path: Optional[str] = None) -> str:
        input_path = str(Path(input_path).resolve())

        if output_path is None:
            output_path = input_path + self.ENCRYPTED_EXT
        else:
            output_path = str(Path(output_path).resolve())

        original_size = os.path.getsize(input_path)
        self.crypto.encrypt_file(input_path, output_path)

        password_hash = self._get_password_hash()
        self.metadata_manager.save_metadata(
            encrypted_path=output_path,
            original_path=input_path,
            original_size=original_size,
            password_hash=password_hash,
        )

        return output_path

    def decrypt_file(self, input_path: str, output_path: Optional[str] = None) -> str:
        input_path = str(Path(input_path).resolve())

        if output_path is None:
            if input_path.endswith(self.ENCRYPTED_EXT):
                output_path = input_path[: -len(self.ENCRYPTED_EXT)]
            else:
                output_path = input_path + ".decrypted"
        else:
            output_path = str(Path(output_path).resolve())

        self.crypto.decrypt_file(input_path, output_path)
        return output_path

    def encrypt_folder(self, folder_path: str, output_folder: Optional[str] = None) -> List[str]:
        folder_path = str(Path(folder_path).resolve())
        folder_name = Path(folder_path).name

        if output_folder is None:
            output_folder = str(Path(folder_path).parent / f"{folder_name}_encrypted")
        else:
            output_folder = str(Path(output_folder).resolve())

        Path(output_folder).mkdir(parents=True, exist_ok=True)

        encrypted_files = []
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                src_file = os.path.join(root, file)
                rel_path = os.path.relpath(src_file, folder_path)
                dst_file = os.path.join(output_folder, rel_path + self.ENCRYPTED_EXT)

                os.makedirs(os.path.dirname(dst_file), exist_ok=True)
                self.encrypt_file(src_file, dst_file)
                encrypted_files.append(dst_file)

        return encrypted_files

    def decrypt_folder(self, folder_path: str, output_folder: Optional[str] = None) -> List[str]:
        folder_path = str(Path(folder_path).resolve())
        folder_name = Path(folder_path).name

        if output_folder is None:
            if folder_name.endswith("_encrypted"):
                base_name = folder_name[: -len("_encrypted")]
            else:
                base_name = folder_name
            output_folder = str(Path(folder_path).parent / f"{base_name}_decrypted")
        else:
            output_folder = str(Path(output_folder).resolve())

        Path(output_folder).mkdir(parents=True, exist_ok=True)

        decrypted_files = []
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                if file.endswith(self.ENCRYPTED_EXT):
                    src_file = os.path.join(root, file)
                    rel_path = os.path.relpath(src_file, folder_path)
                    dst_file = os.path.join(output_folder, rel_path[: -len(self.ENCRYPTED_EXT)])

                    os.makedirs(os.path.dirname(dst_file), exist_ok=True)
                    self.decrypt_file(src_file, dst_file)
                    decrypted_files.append(dst_file)

        return decrypted_files

    def _get_password_hash(self) -> str:
        import hashlib

        return hashlib.sha256(self.crypto.password).hexdigest()

    @staticmethod
    def is_encrypted_file(file_path: str) -> bool:
        return file_path.endswith(FileHandler.ENCRYPTED_EXT)

    @staticmethod
    def collect_files(paths: List[str]) -> List[Tuple[str, bool]]:
        files = []
        for path in paths:
            path_obj = Path(path)
            if path_obj.is_file():
                files.append((str(path_obj.resolve()), False))
            elif path_obj.is_dir():
                for root, dirs, filenames in os.walk(path_obj):
                    for filename in filenames:
                        file_path = os.path.join(root, filename)
                        files.append((file_path, True))
        return files

    @staticmethod
    def get_total_size(file_paths: List[str]) -> int:
        total = 0
        for path in file_paths:
            if os.path.isfile(path):
                total += os.path.getsize(path)
        return total
