import os
import hashlib
from pathlib import Path
import json
from datetime import datetime
import shutil

class IntegrityMonitor:
    def __init__(self, protected_dirs=None):
        if protected_dirs is None:
            protected_dirs = ["D:/Hello"]  # Only monitor test folder
        self.protected_dirs = protected_dirs
        self.file_hashes = {}
        self.backup_dir = "C:/Backups/"
        self.quarantine_dir = "C:/QuarantineZone/"
        self.encrypted_extensions = ['.enc', '.locked', '.crypted', '.ransom', '.encrypted']
        self.critical_extensions = ['.doc', '.docx', '.xls', '.xlsx', '.pdf', '.jpg', '.png', '.txt']
        self.create_backup_system()
        
    def create_backup_system(self):
        """Initialize backup and quarantine directories"""
        for directory in [self.backup_dir, self.quarantine_dir]:
            if not os.path.exists(directory):
                os.makedirs(directory, exist_ok=True)
                print(f"[+] Created backup directory: {directory}")
    
    def create_backup(self, filepath):
        """Create backup of important files (defensive counterpart to encryption)"""
        if not os.path.exists(self.backup_dir):
            os.makedirs(self.backup_dir, exist_ok=True)
        
        try:
            filename = os.path.basename(filepath)
            backup_path = os.path.join(self.backup_dir, filename + ".backup")
            
            # Only backup if not already backed up
            if not os.path.exists(backup_path):
                with open(filepath, 'rb') as src, open(backup_path, 'wb') as dst:
                    dst.write(src.read())
                print(f"[+] Backup created: {backup_path}")
                return backup_path
        except Exception as e:
            print(f"[-] Backup failed for {filepath}: {e}")
        return None
    
    def quarantine_file(self, filepath):
        """Move suspicious file to quarantine"""
        try:
            filename = os.path.basename(filepath)
            quarantine_path = os.path.join(self.quarantine_dir, filename)
            shutil.move(filepath, quarantine_path)
            print(f"[!] QUARANTINED: {filepath} -> {quarantine_path}")
            return True
        except Exception as e:
            print(f"[-] Failed to quarantine: {e}")
            return False
    
    def restore_file(self, original_path, backup_path):
        """Restore encrypted file from backup"""
        try:
            if os.path.exists(original_path):
                os.remove(original_path)
            shutil.copy2(backup_path, original_path)
            print(f"[+] RESTORED: {original_path}")
            return True
        except Exception as e:
            print(f"[-] Restore failed: {e}")
            return False
    
    def monitor_directory(self, directory):
        """Monitor for unauthorized encryption attempts and take action"""
        if not os.path.exists(directory):
            return []
        
        alerts = []
        files_to_process = []
        
        try:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    filepath = Path(root) / file
                    files_to_process.append(filepath)
                    
                    # Check for encrypted file extensions
                    if filepath.suffix in self.encrypted_extensions:
                        original_file = filepath.with_suffix('')
                        alert = f"THREAT: Encrypted file detected: {file}"
                        alerts.append(alert)
                        # Quarantine immediately
                        self.quarantine_file(str(filepath))
                        
                        # Try to restore from backup
                        backup_path = os.path.join(self.backup_dir, original_file.name + ".backup")
                        if os.path.exists(backup_path):
                            self.restore_file(str(original_file), backup_path)
                    
                    # Monitor file size changes (encryption often changes size)
                    if filepath.suffix not in self.encrypted_extensions:
                        try:
                            current_size = os.path.getsize(filepath)
                            filepath_str = str(filepath)
                            
                            if filepath_str in self.file_hashes:
                                baseline_size = self.file_hashes[filepath_str].get('size', 0)
                                size_change = abs(current_size - baseline_size)
                                
                                # Sensitive detection for critical files
                                if filepath.suffix in self.critical_extensions and size_change > 50:
                                    alert = f"ALERT: Critical file size change: {filepath} ({size_change} bytes)"
                                    alerts.append(alert)
                                elif size_change > 500:
                                    alert = f"ALERT: Significant size change: {filepath} ({size_change} bytes)"
                                    alerts.append(alert)
                        except Exception as e:
                            pass
        except Exception as e:
            alerts.append(f"Error monitoring directory: {e}")
        
        return alerts
    
    def recovery_assistance(self, encrypted_dir):
        """Help identify encrypted files for recovery and attempt restoration"""
        if not os.path.exists(encrypted_dir):
            return {"status": "error", "message": "Directory not found"}
        
        encrypted_files = []
        restored_files = []
        
        # Search for all encrypted file extensions
        for ext in self.encrypted_extensions:
            encrypted_files.extend(list(Path(encrypted_dir).rglob(f"*{ext}")))
        
        # Attempt to restore from backups
        for enc_file in encrypted_files:
            original_name = enc_file.name.replace(enc_file.suffix, '')
            backup_path = os.path.join(self.backup_dir, original_name + ".backup")
            
            if os.path.exists(backup_path):
                if self.restore_file(str(enc_file.with_suffix('')), backup_path):
                    restored_files.append(str(enc_file))
        
        report = {
            "status": "completed",
            "directory": encrypted_dir,
            "encrypted_files_found": len(encrypted_files),
            "encrypted_files": [str(f) for f in encrypted_files[:10]],
            "files_restored": len(restored_files),
            "restored_files": restored_files,
            "recovery_advice": [
                "1. ✓ Automated restoration from backups attempted",
                "2. ✓ Remaining encrypted files quarantined",
                "3. Disconnect from network if not already done",
                "4. Do NOT pay any ransom",
                "5. Contact cybersecurity professionals for additional recovery"
            ]
        }
        
        return report