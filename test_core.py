import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from crypto import AESCrypto, PasswordManager, MetadataManager, AppDataManager


def test_aes_crypto():
    print("=== 测试 AES 加密解密 ===")
    crypto = AESCrypto("test_password_123")

    test_data = b"Hello, World! This is a test message for AES encryption."
    encrypted = crypto.encrypt_data(test_data)
    decrypted = crypto.decrypt_data(encrypted)

    assert decrypted == test_data, "AES 加解密不匹配"
    print(f"原始数据: {test_data[:30]}...")
    print(f"加密后长度: {len(encrypted)} 字节")
    print(f"解密后数据: {decrypted[:30]}...")
    print("AES 加密解密测试通过!\n")


def test_password_manager():
    print("=== 测试密码管理器 ===")
    with tempfile.TemporaryDirectory() as tmpdir:
        storage_path = os.path.join(tmpdir, "passwords.json")
        pm = PasswordManager(storage_path)

        file_id = "test_file_id_123"
        password = "my_secret_password"

        pm.set_password(file_id, password)
        assert pm.has_password(file_id), "密码应该存在"
        assert pm.verify_password(file_id, password), "密码验证应该通过"
        assert not pm.verify_password(file_id, "wrong_password"), "错误密码应该验证失败"

        print(f"密码存储路径: {storage_path}")
        print(f"密码哈希存储成功")
        print(f"密码验证功能正常")
        print("密码管理器测试通过!\n")


def test_metadata_manager():
    print("=== 测试元数据管理器 ===")
    with tempfile.TemporaryDirectory() as tmpdir:
        mm = MetadataManager(tmpdir)

        test_enc_file = os.path.join(tmpdir, "test.txt.enc")
        with open(test_enc_file, "wb") as f:
            f.write(b"encrypted content")

        mm.save_metadata(
            encrypted_path=test_enc_file,
            original_path="/path/to/original.txt",
            original_size=1024,
            password_hash="abc123def456",
        )

        metadata = mm.load_metadata(test_enc_file)
        assert metadata is not None, "元数据应该存在"
        assert metadata["original_name"] == "original.txt"
        assert metadata["original_size"] == 1024
        assert metadata["algorithm"] == "AES-256-CBC"

        all_meta = mm.list_all_metadata()
        assert len(all_meta) == 1, "应该有1条元数据记录"

        print(f"元数据保存成功")
        print(f"元数据加载成功")
        print(f"原始文件名: {metadata['original_name']}")
        print(f"加密算法: {metadata['algorithm']}")
        print("元数据管理器测试通过!\n")


def test_app_data_manager():
    print("=== 测试应用数据管理器 ===")
    with tempfile.TemporaryDirectory() as tmpdir:
        app_data = AppDataManager()
        app_data.app_dir = Path(tmpdir)
        app_data.config_path = Path(tmpdir) / "config.json"
        app_data.history_path = Path(tmpdir) / "history.json"
        app_data._config = app_data._default_config()
        app_data._history = []

        app_data.set_config("output_dir", "/test/output")
        app_data.set_config("show_password", True)

        assert app_data.get_config("output_dir") == "/test/output"
        assert app_data.get_config("show_password") == True
        assert app_data.get_config("nonexistent_key", "default") == "default"

        app_data.add_history_item({"encrypted_path": "/test/file1.enc", "original_name": "file1.txt"})
        app_data.add_history_item({"encrypted_path": "/test/file2.enc", "original_name": "file2.txt"})

        history = app_data.get_history()
        assert len(history) == 2, "应该有2条历史记录"

        app_data.remove_history_item("/test/file1.enc")
        history = app_data.get_history()
        assert len(history) == 1, "应该剩下1条历史记录"

        print(f"配置保存和读取正常")
        print(f"历史记录添加正常")
        print(f"历史记录删除正常")
        print("应用数据管理器测试通过!\n")


def test_file_handler_integration():
    print("=== 测试文件处理集成 ===")
    from file_manager import FileHandler

    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = os.path.join(tmpdir, "test_file.txt")
        with open(test_file, "w", encoding="utf-8") as f:
            f.write("这是一个测试文件的内容。Hello World!")

        original_size = os.path.getsize(test_file)
        print(f"原始文件大小: {original_size} 字节")

        handler = FileHandler("test_password")

        handler.metadata_manager = MetadataManager(os.path.join(tmpdir, "metadata"))
        handler.password_manager = PasswordManager(os.path.join(tmpdir, "passwords.json"))

        encrypted_file = handler.encrypt_file(test_file)
        print(f"加密文件路径: {encrypted_file}")
        print(f"加密文件大小: {os.path.getsize(encrypted_file)} 字节")

        assert os.path.exists(encrypted_file), "加密文件应该存在"

        decrypted_file = os.path.join(tmpdir, "decrypted.txt")
        handler.decrypt_file(encrypted_file, decrypted_file)

        with open(decrypted_file, "r", encoding="utf-8") as f:
            content = f.read()
        assert content == "这是一个测试文件的内容。Hello World!", "解密后内容不匹配"
        print(f"解密成功，内容正确")

        metadata = handler.metadata_manager.load_metadata(encrypted_file)
        assert metadata is not None, "元数据应该存在"
        print(f"元数据保存成功")

        file_id = PasswordManager.generate_file_id(encrypted_file)
        assert handler.password_manager.has_password(file_id), "密码记录应该存在"
        print(f"密码记录保存成功")

        print("文件处理集成测试通过!\n")


if __name__ == "__main__":
    print("开始功能测试...\n")

    test_aes_crypto()
    test_password_manager()
    test_metadata_manager()
    test_app_data_manager()
    test_file_handler_integration()

    print("=" * 50)
    print("所有测试全部通过! ✓")
    print("=" * 50)
