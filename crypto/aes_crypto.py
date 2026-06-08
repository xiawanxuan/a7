import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


class AESCrypto:
    KEY_SIZE = 32
    IV_SIZE = 16
    SALT_SIZE = 32
    ITERATIONS = 100000
    CHUNK_SIZE = 64 * 1024

    def __init__(self, password: str):
        self.password = password.encode("utf-8")

    def _derive_key(self, salt: bytes) -> bytes:
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_SIZE,
            salt=salt,
            iterations=self.ITERATIONS,
            backend=default_backend(),
        )
        return kdf.derive(self.password)

    def encrypt_file(self, input_path: str, output_path: str) -> None:
        salt = os.urandom(self.SALT_SIZE)
        iv = os.urandom(self.IV_SIZE)
        key = self._derive_key(salt)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()

        with open(input_path, "rb") as infile, open(output_path, "wb") as outfile:
            outfile.write(salt)
            outfile.write(iv)

            while True:
                chunk = infile.read(self.CHUNK_SIZE)
                if len(chunk) == 0:
                    break
                padded_chunk = padder.update(chunk)
                outfile.write(encryptor.update(padded_chunk))

            final_padded = padder.finalize()
            outfile.write(encryptor.update(final_padded))
            outfile.write(encryptor.finalize())

    def decrypt_file(self, input_path: str, output_path: str) -> None:
        with open(input_path, "rb") as infile:
            salt = infile.read(self.SALT_SIZE)
            iv = infile.read(self.IV_SIZE)
            key = self._derive_key(salt)

            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

            with open(output_path, "wb") as outfile:
                while True:
                    chunk = infile.read(self.CHUNK_SIZE)
                    if len(chunk) == 0:
                        break
                    decrypted = decryptor.update(chunk)
                    outfile.write(unpadder.update(decrypted))

                final_decrypted = decryptor.finalize()
                outfile.write(unpadder.update(final_decrypted))
                outfile.write(unpadder.finalize())

    def encrypt_data(self, data: bytes) -> bytes:
        salt = os.urandom(self.SALT_SIZE)
        iv = os.urandom(self.IV_SIZE)
        key = self._derive_key(salt)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()

        padded_data = padder.update(data) + padder.finalize()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()

        return salt + iv + encrypted

    def decrypt_data(self, encrypted_data: bytes) -> bytes:
        salt = encrypted_data[: self.SALT_SIZE]
        iv = encrypted_data[self.SALT_SIZE : self.SALT_SIZE + self.IV_SIZE]
        ciphertext = encrypted_data[self.SALT_SIZE + self.IV_SIZE :]

        key = self._derive_key(salt)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        return unpadder.update(decrypted) + unpadder.finalize()
