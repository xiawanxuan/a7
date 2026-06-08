import os
import sys
import tempfile
import importlib.util
from pathlib import Path

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

ROOT_DIR = Path(__file__).parent

def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module

crypto_pkg = load_module("crypto", str(ROOT_DIR / "crypto" / "__init__.py"))

aes_module = load_module("crypto.aes_crypto", str(ROOT_DIR / "crypto" / "aes_crypto.py"))
password_module = load_module("crypto.password_manager", str(ROOT_DIR / "crypto" / "password_manager.py"))
metadata_module = load_module("crypto.metadata_manager", str(ROOT_DIR / "crypto" / "metadata_manager.py"))
app_data_module = load_module("crypto.app_data_manager", str(ROOT_DIR / "crypto" / "app_data_manager.py"))

AESCrypto = aes_module.AESCrypto
PasswordManager = password_module.PasswordManager
MetadataManager = metadata_module.MetadataManager
AppDataManager = app_data_module.AppDataManager

version_module = load_module("version_manager", str(ROOT_DIR / "file_manager" / "version_manager.py"))
VersionManager = version_module.VersionManager

cloud_module = load_module("cloud_sync", str(ROOT_DIR / "file_manager" / "cloud_sync.py"))
CloudSyncManager = cloud_module.CloudSyncManager
LocalCloudProvider = cloud_module.LocalCloudProvider
SyncStatus = cloud_module.SyncStatus

share_module = load_module("secure_share", str(ROOT_DIR / "file_manager" / "secure_share.py"))
ShareManager = share_module.ShareManager


def test_version_integration():
    print("=" * 60)
    print("测试: 版本管理与加密功能集成")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = os.path.join(tmpdir, "test_doc.txt")
        with open(test_file, "w", encoding="utf-8") as f:
            f.write("版本1: 初始内容 Hello World")

        version_dir = os.path.join(tmpdir, "versions")
        metadata_dir = os.path.join(tmpdir, "metadata")
        password_path = os.path.join(tmpdir, "passwords.json")

        password = "test_password_123"

        vm = VersionManager(version_dir)
        crypto = AESCrypto(password)
        mm = MetadataManager(metadata_dir)
        pm = PasswordManager(password_path)

        enc_file = os.path.join(tmpdir, "test_doc.txt.enc")
        crypto.encrypt_file(test_file, enc_file)

        original_size = os.path.getsize(test_file)
        password_hash = __import__("hashlib").sha256(password.encode()).hexdigest()
        mm.save_metadata(enc_file, test_file, original_size, password_hash)

        vm.save_version(test_file, enc_file, description="初始版本")

        versions = vm.get_versions(test_file)
        assert len(versions) == 1
        print(f"✓ 第一次加密后版本数: {len(versions)}")

        with open(test_file, "w", encoding="utf-8") as f:
            f.write("版本2: 更新内容 新的功能")

        crypto.encrypt_file(test_file, enc_file)
        vm.save_version(test_file, enc_file, description="第二次更新")

        versions = vm.get_versions(test_file)
        assert len(versions) == 2
        print(f"✓ 第二次加密后版本数: {len(versions)}")

        all_versioned = vm.list_all_versioned_files()
        assert len(all_versioned) == 1
        print(f"✓ 版本化文件总数: {len(all_versioned)}")

        old_version = versions[1]
        restored_enc = vm.restore_version(test_file, old_version["version_id"])
        assert restored_enc is not None
        print(f"✓ 版本恢复成功: {old_version['version_id']}")

        decrypted = os.path.join(tmpdir, "restored_v1.txt")
        crypto.decrypt_file(restored_enc, decrypted)

        with open(decrypted, "r", encoding="utf-8") as f:
            content = f.read()
        assert "版本1" in content
        print(f"✓ 恢复的版本内容正确")

        print("\n✅ 版本管理集成测试通过!\n")


def test_cloud_sync_integration():
    print("=" * 60)
    print("测试: 云同步与加密功能集成")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        local_file = os.path.join(tmpdir, "sync_test.txt.enc")
        with open(local_file, "wb") as f:
            f.write(b"encrypted content for sync test")

        cloud_dir = os.path.join(tmpdir, "cloud_storage")
        state_dir = os.path.join(tmpdir, "sync_state")

        provider = LocalCloudProvider(cloud_dir)
        sync_manager = CloudSyncManager(provider, state_dir)

        sync_manager.add_sync_file(local_file)
        sync_files = sync_manager.list_sync_files()
        assert len(sync_files) == 1
        print(f"✓ 添加同步文件成功")

        status = sync_manager.check_status(local_file)
        assert status == SyncStatus.ONLY_LOCAL
        print(f"✓ 初始同步状态: {status.value}")

        success = sync_manager.upload(local_file)
        assert success
        print(f"✓ 文件上传成功")

        status = sync_manager.check_status(local_file)
        assert status == SyncStatus.SYNCED
        print(f"✓ 上传后同步状态: {status.value}")

        with open(local_file, "wb") as f:
            f.write(b"modified encrypted content version 2")
        import time
        time.sleep(0.1)

        status = sync_manager.check_status(local_file)
        assert status in [SyncStatus.LOCAL_NEWER, SyncStatus.CONFLICT]
        print(f"✓ 修改本地后状态: {status.value}")

        success = sync_manager.download(local_file)
        assert success
        print(f"✓ 文件下载成功")

        sync_manager.remove_sync_file(local_file)
        sync_files = sync_manager.list_sync_files()
        assert len(sync_files) == 0
        print(f"✓ 移除同步文件成功")

        print("\n✅ 云同步集成测试通过!\n")


def test_share_integration():
    print("=" * 60)
    print("测试: 安全分享与加密功能集成")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        original_file = os.path.join(tmpdir, "original.txt")
        with open(original_file, "w", encoding="utf-8") as f:
            f.write("这是需要分享的机密文件内容 Super Secret!")

        password = "my_secure_password"
        crypto = AESCrypto(password)

        encrypted_file = os.path.join(tmpdir, "original.txt.enc")
        crypto.encrypt_file(original_file, encrypted_file)

        share_dir = os.path.join(tmpdir, "shares")
        share_manager = ShareManager(share_dir)

        share_result = share_manager.create_share(
            encrypted_file_path=encrypted_file,
            expiry_hours=24,
            description="测试分享",
        )
        assert share_result is not None
        assert "share_id" in share_result
        assert "share_password" in share_result
        print(f"✓ 创建分享成功: {share_result['share_id']}")

        share_info = share_manager.get_share_info(share_result["share_id"])
        assert share_info is not None
        assert share_info["is_active"] == True
        print(f"✓ 分享状态: 有效")

        is_valid = share_manager.is_share_valid(share_result["share_id"])
        assert is_valid
        print(f"✓ 分享验证通过")

        is_verified = share_manager.verify_share_password(
            share_result["share_id"], share_result["share_password"]
        )
        assert is_verified
        print(f"✓ 分享密码验证通过")

        is_verified_wrong = share_manager.verify_share_password(
            share_result["share_id"], "wrong_password"
        )
        assert not is_verified_wrong
        print(f"✓ 错误密码验证失败 (预期行为)")

        decrypted_share = os.path.join(tmpdir, "shared_encrypted.enc")
        result = share_manager.decrypt_share(
            share_result["share_id"],
            share_result["share_password"],
            decrypted_share,
        )
        assert result is not None
        print(f"✓ 分享文件解密成功 (得到原始加密文件)")

        decrypted_output = os.path.join(tmpdir, "shared_decrypted.txt")
        crypto.decrypt_file(decrypted_share, decrypted_output)

        with open(decrypted_output, "r", encoding="utf-8") as f:
            content = f.read()
        assert "机密文件内容" in content
        print(f"✓ 二次解密后内容正确")

        shares = share_manager.list_shares()
        assert len(shares) == 1
        print(f"✓ 分享列表数: {len(shares)}")

        success = share_manager.revoke_share(share_result["share_id"])
        assert success
        print(f"✓ 分享撤销成功")

        is_valid_after = share_manager.is_share_valid(share_result["share_id"])
        assert not is_valid_after
        print(f"✓ 撤销后分享状态: 无效")

        print("\n✅ 安全分享集成测试通过!\n")


def test_full_integration():
    print("=" * 60)
    print("测试: 全部功能完整集成测试")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = os.path.join(tmpdir, "important_doc.txt")
        with open(test_file, "w", encoding="utf-8") as f:
            f.write("重要文档 v1: 这是一份非常重要的文档")

        password = "StrongPassword@2024"
        crypto = AESCrypto(password)

        version_dir = os.path.join(tmpdir, "versions")
        metadata_dir = os.path.join(tmpdir, "metadata")
        password_path = os.path.join(tmpdir, "passwords.json")
        share_dir = os.path.join(tmpdir, "shares")
        cloud_dir = os.path.join(tmpdir, "cloud")
        state_dir = os.path.join(tmpdir, "sync_state")

        vm = VersionManager(version_dir)
        mm = MetadataManager(metadata_dir)
        pm = PasswordManager(password_path)
        sm = ShareManager(share_dir)
        cloud_provider = LocalCloudProvider(cloud_dir)
        sync_manager = CloudSyncManager(cloud_provider, state_dir)

        enc_file = os.path.join(tmpdir, "important_doc.txt.enc")
        crypto.encrypt_file(test_file, enc_file)
        vm.save_version(test_file, enc_file, "v1 初始版本")
        print(f"✓ 第1次加密 + 保存版本")

        with open(test_file, "w", encoding="utf-8") as f:
            f.write("重要文档 v2: 添加了新的章节和修改")

        crypto.encrypt_file(test_file, enc_file)
        vm.save_version(test_file, enc_file, "v2 内容更新")
        print(f"✓ 第2次加密 + 保存版本")

        versions = vm.get_versions(test_file)
        assert len(versions) == 2
        print(f"✓ 历史版本数: {len(versions)}")

        original_size = os.path.getsize(test_file)
        password_hash = __import__("hashlib").sha256(password.encode()).hexdigest()
        mm.save_metadata(enc_file, test_file, original_size, password_hash)
        metadata = mm.load_metadata(enc_file)
        assert metadata is not None
        assert metadata["algorithm"] == "AES-256-CBC"
        print(f"✓ 元数据正常")

        file_id = pm.generate_file_id(enc_file)
        pm.set_password(file_id, password)
        assert pm.verify_password(file_id, password)
        print(f"✓ 密码验证正常")

        sync_manager.add_sync_file(enc_file)
        sync_manager.upload(enc_file)
        status = sync_manager.check_status(enc_file)
        assert status == SyncStatus.SYNCED
        print(f"✓ 云同步正常 (状态: {status.value})")

        share_result = sm.create_share(enc_file, expiry_hours=24, description="分享给同事")
        assert share_result["share_id"]
        print(f"✓ 创建分享成功: {share_result['share_id']}")

        first_version = versions[-1]
        restored_enc = vm.restore_version(test_file, first_version["version_id"])
        assert restored_enc is not None
        restored = os.path.join(tmpdir, "restored_v1.txt")
        crypto.decrypt_file(restored_enc, restored)
        with open(restored, "r", encoding="utf-8") as f:
            content = f.read()
        assert "v1" in content
        print(f"✓ 版本恢复成功 (v1)")

        share_decrypted_enc = os.path.join(tmpdir, "share_decrypted.enc")
        share_result2 = sm.decrypt_share(
            share_result["share_id"],
            share_result["share_password"],
            share_decrypted_enc,
        )
        assert share_result2 is not None

        decrypted = os.path.join(tmpdir, "share_decrypted.txt")
        crypto.decrypt_file(share_decrypted_enc, decrypted)
        print(f"✓ 分享解密成功")

        print("\n" + "=" * 60)
        print("✅ 全部功能完整集成测试通过!")
        print("=" * 60)
        print("\n所有新增功能与原有加密模块完全兼容 ✓")


if __name__ == "__main__":
    print("\n开始新增功能集成测试...\n")

    test_version_integration()
    test_cloud_sync_integration()
    test_share_integration()
    test_full_integration()

    print("\n" + "=" * 60)
    print("🎉  所有测试全部通过!")
    print("=" * 60)
