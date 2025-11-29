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

# --- Derive key using same fixed salt ---
SALT = b"fixed_salt_for_all_files!"  # must match encryption
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=SALT,
    iterations=100_000,
)
key = kdf.derive(password.encode())
aesgcm = AESGCM(key)

# --- Decrypt a single file ---
def decrypt_file(file_path: Path):
    try:
        if not file_path.suffix.endswith(".enc"):
            return
        data = file_path.read_bytes()
        nonce = data[:12]
        ciphertext = data[12:]
        decrypted = aesgcm.decrypt(nonce, ciphertext, None)
        # Restore original file name
        orig_suffix = "".join(file_path.suffixes[:-1])
        orig_path = file_path.with_suffix(orig_suffix)
        orig_path.write_bytes(decrypted)
        file_path.unlink()  # remove encrypted file
        print(f"[+] Decrypted: {orig_path}")
    except Exception as e:
        print(f"[-] Failed: {file_path} | {e}")

# --- Gather all encrypted files ---
def gather_files(drive: Path):
    skip_dirs = {"Windows", "Program Files", "Program Files (x86)", "$Recycle.Bin", "System Volume Information"}
    files = []
    for root, dirs, filenames in os.walk(drive):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for f in filenames:
            if f.endswith(".enc"):
                files.append(Path(root) / f)
    return files

# --- Main ---
def main():
    drive = Path("D:/")  # change if needed
    if not drive.exists():
        print("Drive not found.")
        return

    all_files = gather_files(drive)
    print(f"Found {len(all_files)} encrypted files to decrypt.")

    # --- Parallel decryption ---
    with ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as executor:
        executor.map(decrypt_file, all_files)

    print("\nDecryption complete. Only original files restored.")

    # Remove .env for security
    env_path = Path(".env")
    if env_path.exists():
        env_path.unlink()
        print(".env file deleted for security.")

if __name__ == "__main__":
    main()
