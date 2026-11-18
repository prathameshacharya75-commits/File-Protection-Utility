
import os
import argparse
import getpass
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


# Encryption configuration
MAGIC = b"FPV1"
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
ITERATIONS = 600_000


def derive_key(password, salt):
    """Derive a 256-bit key using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_file(input_file, output_file, password):
    input_path = Path(input_file)
    output_path = Path(output_file)

    if not input_path.is_file():
        raise FileNotFoundError("Input file does not exist.")

    if input_path.resolve() == output_path.resolve():
        raise ValueError("Input and output files must be different.")

    if output_path.exists():
        raise FileExistsError("Output file already exists.")

    data = input_path.read_bytes()

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    # AES-GCM authenticates ciphertext and detects modifications.
    ciphertext = aesgcm.encrypt(nonce, data, MAGIC)

    encrypted_data = MAGIC + salt + nonce + ciphertext
    output_path.write_bytes(encrypted_data)

    print(f"Encryption successful: {output_path}")


def decrypt_file(input_file, output_file, password):
    input_path = Path(input_file)
    output_path = Path(output_file)

    if not input_path.is_file():
        raise FileNotFoundError("Encrypted file does not exist.")

    if input_path.resolve() == output_path.resolve():
        raise ValueError("Input and output files must be different.")

    if output_path.exists():
        raise FileExistsError("Output file already exists.")

    encrypted_data = input_path.read_bytes()

    minimum_size = len(MAGIC) + SALT_SIZE + NONCE_SIZE + 16

    if len(encrypted_data) < minimum_size:
        raise ValueError("Invalid or corrupted encrypted file.")

    if encrypted_data[:len(MAGIC)] != MAGIC:
        raise ValueError("Invalid file format.")

    position = len(MAGIC)

    salt = encrypted_data[position:position + SALT_SIZE]
    position += SALT_SIZE

    nonce = encrypted_data[position:position + NONCE_SIZE]
    position += NONCE_SIZE

    ciphertext = encrypted_data[position:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    # Authentication failure raises an exception.
    plaintext = aesgcm.decrypt(nonce, ciphertext, MAGIC)

    output_path.write_bytes(plaintext)

    print(f"Decryption successful: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="AES-256 File Protection Utility"
    )

    parser.add_argument(
        "operation",
        choices=["encrypt", "decrypt"],
        help="Choose encryption or decryption"
    )

    parser.add_argument("input", help="Input file path")
    parser.add_argument("output", help="Output file path")

    args = parser.parse_args()

    password = getpass.getpass("Enter password: ")

    if not password:
        parser.error("Password cannot be empty.")

    try:
        if args.operation == "encrypt":
            encrypt_file(args.input, args.output, password)

        elif args.operation == "decrypt":
            decrypt_file(args.input, args.output, password)

    except Exception as error:
        print(f"Operation failed: {error}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
