"""
Guardian Antivirus - Core Protection Engine
Optimized, async protection engine with efficient scanning algorithms
"""

import os
import sys
import time
import shutil
import hashlib
import threading
import queue
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Callable, Set
from dataclasses import dataclass, field
from enum import Enum
import psutil

# Watchdog for efficient file monitoring
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent


class ThreatType(Enum):
    RANSOMWARE = "ransomware"
    WORM = "worm"
    SPYWARE = "spyware"
    SUSPICIOUS_PROCESS = "suspicious_process"
    MALICIOUS_FILE = "malicious_file"
    AUTORUN = "autorun"


class ThreatSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ThreatInfo:
    """Information about a detected threat"""
    threat_type: ThreatType
    severity: ThreatSeverity
    description: str
    file_path: Optional[str] = None
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    action_taken: str = "detected"
    timestamp: datetime = field(default_factory=datetime.now)


class FileEventHandler(FileSystemEventHandler):
    """Efficient file system event handler with debouncing"""
    
    def __init__(self, engine: 'ProtectionEngine'):
        super().__init__()
        self.engine = engine
        self.last_events: Dict[str, float] = {}
        self.debounce_time = 1.0  # seconds
    
    def _should_process(self, path: str) -> bool:
        """Debounce events for the same file"""
        now = time.time()
        if path in self.last_events:
            if now - self.last_events[path] < self.debounce_time:
                return False
        self.last_events[path] = now
        return True
    
    def on_created(self, event: FileSystemEvent):
        if event.is_directory:
            return
        if self._should_process(event.src_path):
            self.engine.queue_file_check(event.src_path, "created")
    
    def on_modified(self, event: FileSystemEvent):
        if event.is_directory:
            return
        if self._should_process(event.src_path):
            self.engine.queue_file_check(event.src_path, "modified")
    
    def on_moved(self, event: FileSystemEvent):
        if event.is_directory:
            return
        if self._should_process(event.dest_path):
            self.engine.queue_file_check(event.dest_path, "renamed")


class ProtectionEngine:
    """
    Core protection engine with optimized scanning and async operations.
    Designed to run efficiently in background without blocking UI.
    """
    
    # Malicious file signatures
    RANSOMWARE_EXTENSIONS = {'.enc', '.locked', '.crypted', '.encrypted', '.ransom', '.wcry', '.crypto'}
    RANSOM_NOTE_KEYWORDS = {'ransom', 'decrypt', 'recover', 'bitcoin', 'pay', 'readme', 'your_files'}
    
    # Suspicious process patterns
    MALICIOUS_SIGNATURES = {
        'longchhunhour', 'encrypt.py', 'worm.py', 'spyware.py', 
        'ransomware', 'cryptography.hazmat', 'aesgcm', 'keylogger'
    }
    
    # Suspicious commands in process arguments
    MALICIOUS_COMMANDS = {
        'encrypt', 'aesgcm', 'ransom', '.enc', 'autorun.inf',
        'spread_via', 'execute_ransomware', 'pynput', 'keylog'
    }
    
    # Worm-related names
    WORM_EXECUTABLES = {
        'windows_update_service.exe', 'adobe_flash_update.exe',
        'system_service.exe', 'update_service.exe', 'system_update.exe'
    }
    
    # Safe processes (whitelist)
    WHITELISTED_PROCESSES = {
        'system', 'svchost.exe', 'csrss.exe', 'dwm.exe', 'explorer.exe',
        'taskhostw.exe', 'runtimebroker.exe', 'applicationframehost.exe',
        'code.exe', 'python.exe', 'pythonw.exe', 'powershell.exe',
        'cmd.exe', 'conhost.exe', 'msedge.exe', 'chrome.exe', 'firefox.exe',
        'windowsterminal.exe', 'searchhost.exe', 'shellexperiencehost.exe',
        'guardian_av.exe', 'main.py'  # Our own process
    }
    
    def __init__(self, config_manager):
        self.config = config_manager
        self.running = False
        self.protection_enabled = False
        
        # Event queue for file operations
        self.file_queue: queue.Queue = queue.Queue()
        
        # Watchdog observers for each directory
        self.observers: Dict[str, Observer] = {}
        
        # File hashes for integrity monitoring
        self.file_hashes: Dict[str, str] = {}
        
        # Blocked process PIDs
        self.blocked_pids: Set[int] = set()
        
        # Callbacks for UI updates
        self.on_threat_detected: Optional[Callable[[ThreatInfo], None]] = None
        self.on_status_change: Optional[Callable[[str], None]] = None
        self.on_stats_update: Optional[Callable[[Dict], None]] = None
        
        # Threads
        self._process_monitor_thread: Optional[threading.Thread] = None
        self._file_processor_thread: Optional[threading.Thread] = None
        self._usb_monitor_thread: Optional[threading.Thread] = None
        self._spyware_monitor_thread: Optional[threading.Thread] = None
        
        # Statistics
        self.stats = {
            "threats_detected": 0,
            "threats_blocked": 0,
            "files_scanned": 0,
            "processes_scanned": 0,
        }
        
        # Ensure directories exist
        Path(self.config.backup_directory).mkdir(parents=True, exist_ok=True)
        Path(self.config.quarantine_directory).mkdir(parents=True, exist_ok=True)
    
    def start(self):
        """Start the protection engine"""
        if self.running:
            return
        
        self.running = True
        self.protection_enabled = True
        
        self._notify_status("Starting protection engine...")
        
        # Create initial backups
        self._create_backups()
        
        # Start file system watchers
        self._start_file_watchers()
        
        # Start monitoring threads
        self._file_processor_thread = threading.Thread(
            target=self._file_processor_loop, 
            name="FileProcessor", 
            daemon=True
        )
        self._file_processor_thread.start()
        
        self._process_monitor_thread = threading.Thread(
            target=self._process_monitor_loop, 
            name="ProcessMonitor", 
            daemon=True
        )
        self._process_monitor_thread.start()
        
        self._usb_monitor_thread = threading.Thread(
            target=self._usb_monitor_loop, 
            name="USBMonitor", 
            daemon=True
        )
        self._usb_monitor_thread.start()
        
        self._spyware_monitor_thread = threading.Thread(
            target=self._spyware_monitor_loop,
            name="SpywareMonitor",
            daemon=True
        )
        self._spyware_monitor_thread.start()
        
        self._notify_status("Protection active")
    
    def stop(self):
        """Stop the protection engine"""
        self.running = False
        self.protection_enabled = False
        
        # Stop all observers
        for path, observer in self.observers.items():
            try:
                observer.stop()
                observer.join(timeout=2)
            except:
                pass
        self.observers.clear()
        
        self._notify_status("Protection stopped")
    
    def _start_file_watchers(self):
        """Start watchdog observers for protected directories"""
        for directory in self.config.protected_directories:
            self._add_watcher(directory)
    
    def _add_watcher(self, directory: str):
        """Add a watchdog observer for a directory"""
        if directory in self.observers:
            return
        
        if not Path(directory).exists():
            return
        
        try:
            observer = Observer()
            handler = FileEventHandler(self)
            observer.schedule(handler, directory, recursive=True)
            observer.start()
            self.observers[directory] = observer
        except Exception as e:
            print(f"Error starting watcher for {directory}: {e}")
    
    def _remove_watcher(self, directory: str):
        """Remove watchdog observer for a directory"""
        if directory in self.observers:
            try:
                self.observers[directory].stop()
                self.observers[directory].join(timeout=2)
            except:
                pass
            del self.observers[directory]
    
    def add_protected_directory(self, directory: str) -> bool:
        """Add a directory to protection"""
        if self.config.add_protected_directory(directory):
            if self.running:
                self._add_watcher(directory)
            return True
        return False
    
    def remove_protected_directory(self, directory: str) -> bool:
        """Remove a directory from protection"""
        if self.config.remove_protected_directory(directory):
            self._remove_watcher(directory)
            return True
        return False
    
    def queue_file_check(self, filepath: str, action: str):
        """Queue a file for threat checking"""
        self.file_queue.put((filepath, action))
    
    def _file_processor_loop(self):
        """Process queued file checks"""
        while self.running:
            try:
                filepath, action = self.file_queue.get(timeout=1)
                self._check_file(filepath, action)
                self.stats["files_scanned"] += 1
            except queue.Empty:
                continue
            except Exception as e:
                pass
    
    def _check_file(self, filepath: str, action: str):
        """Check a file for threats"""
        if not os.path.exists(filepath):
            return
        
        filename = os.path.basename(filepath).lower()
        
        # Check for ransomware indicators
        _, ext = os.path.splitext(filename)
        if ext in self.RANSOMWARE_EXTENSIONS:
            threat = ThreatInfo(
                threat_type=ThreatType.RANSOMWARE,
                severity=ThreatSeverity.CRITICAL,
                description=f"Encrypted file detected: {filename}",
                file_path=filepath,
                action_taken="detected"
            )
            self._handle_ransomware_file(filepath, threat)
            return
        
        # Check for ransom notes
        if filename.endswith('.txt'):
            if any(kw in filename for kw in self.RANSOM_NOTE_KEYWORDS):
                threat = ThreatInfo(
                    threat_type=ThreatType.RANSOMWARE,
                    severity=ThreatSeverity.HIGH,
                    description=f"Ransom note detected: {filename}",
                    file_path=filepath,
                    action_taken="quarantined"
                )
                self._quarantine_file(filepath, threat)
                return
    
    def _handle_ransomware_file(self, filepath: str, threat: ThreatInfo):
        """Handle a detected ransomware encrypted file"""
        # Quarantine the encrypted file
        self._quarantine_file(filepath, threat)
        
        # Kill any suspicious processes
        self._scan_and_kill_malicious()
        
        # Try to restore from backup
        self._restore_file(filepath)
        
        threat.action_taken = "quarantined_and_restored"
        self._notify_threat(threat)
    
    def _quarantine_file(self, filepath: str, threat: ThreatInfo):
        """Move a file to quarantine"""
        try:
            filename = os.path.basename(filepath)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            quarantine_path = os.path.join(
                self.config.quarantine_directory, 
                f"{timestamp}_{filename}"
            )
            
            shutil.move(filepath, quarantine_path)
            
            self.config.log_quarantine(filepath, quarantine_path, threat.description)
            self.config.increment_stat("files_quarantined")
            self.stats["threats_blocked"] += 1
            
            threat.action_taken = "quarantined"
            self._notify_threat(threat)
            
            return quarantine_path
        except Exception as e:
            print(f"Quarantine failed: {e}")
            return None
    
    def _restore_file(self, encrypted_path: str):
        """Restore a file from backup"""
        # Remove encryption extension to get original filename
        original_path = encrypted_path
        for ext in self.RANSOMWARE_EXTENSIONS:
            if original_path.endswith(ext):
                original_path = original_path[:-len(ext)]
                break
        
        # Find backup
        for protected_dir in self.config.protected_directories:
            try:
                rel_path = os.path.relpath(original_path, protected_dir)
                if not rel_path.startswith('..'):
                    backup_path = os.path.join(self.config.backup_directory, rel_path)
                    if os.path.exists(backup_path):
                        shutil.copy2(backup_path, original_path)
                        self.config.increment_stat("files_restored")
                        return True
            except:
                pass
        
        return False
    
    def _create_backups(self):
        """Create backups of protected files"""
        for directory in self.config.protected_directories:
            if not os.path.exists(directory):
                continue
            
            for root, dirs, files in os.walk(directory):
                for file in files:
                    filepath = os.path.join(root, file)
                    try:
                        # Calculate relative path for backup
                        rel_path = os.path.relpath(filepath, directory)
                        backup_path = os.path.join(self.config.backup_directory, rel_path)
                        
                        # Create backup directory
                        os.makedirs(os.path.dirname(backup_path), exist_ok=True)
                        
                        # Copy file
                        shutil.copy2(filepath, backup_path)
                        
                        # Store hash
                        with open(filepath, 'rb') as f:
                            self.file_hashes[filepath] = hashlib.sha256(f.read()).hexdigest()
                    except:
                        pass
    
    def _process_monitor_loop(self):
        """Monitor processes for malicious activity"""
        scan_interval = self.config.config["protection"]["process_scan_interval"]
        
        while self.running:
            try:
                self._scan_and_kill_malicious()
                self.stats["processes_scanned"] += 1
            except Exception as e:
                pass
            
            time.sleep(scan_interval)
    
    def _scan_and_kill_malicious(self) -> List[ThreatInfo]:
        """Scan and kill malicious processes"""
        threats = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    info = proc.info
                    name = info.get('name', '').lower()
                    pid = info.get('pid')
                    
                    # Skip if already blocked
                    if pid in self.blocked_pids:
                        continue
                    
                    # Skip whitelisted
                    if name in self.WHITELISTED_PROCESSES:
                        continue
                    
                    # Only check Python processes for malware signatures
                    if 'python' not in name:
                        continue
                    
                    cmdline = info.get('cmdline', [])
                    cmdline_str = ' '.join(cmdline).lower() if cmdline else ''
                    
                    # Skip our own process
                    if 'guardian_av' in cmdline_str or 'main.py' in cmdline_str:
                        if 'guardian_av' in os.path.dirname(os.path.abspath(__file__)):
                            continue
                    
                    is_malicious = False
                    reason = ""
                    
                    # Check for malicious signatures
                    for sig in self.MALICIOUS_SIGNATURES:
                        if sig in cmdline_str:
                            is_malicious = True
                            reason = f"Malicious signature: {sig}"
                            break
                    
                    # Check for malicious commands
                    if not is_malicious:
                        for cmd in self.MALICIOUS_COMMANDS:
                            if cmd in cmdline_str:
                                is_malicious = True
                                reason = f"Malicious command: {cmd}"
                                break
                    
                    # Check for access to protected folders
                    if not is_malicious:
                        for protected_dir in self.config.protected_directories:
                            dir_lower = protected_dir.lower().replace('\\', '/')
                            if dir_lower in cmdline_str.replace('\\', '/'):
                                # Skip if it's our antivirus
                                if 'main_defender' not in cmdline_str and 'guardian' not in cmdline_str:
                                    is_malicious = True
                                    reason = f"Unauthorized access to {protected_dir}"
                                    break
                    
                    if is_malicious:
                        try:
                            process = psutil.Process(pid)
                            process.kill()
                            self.blocked_pids.add(pid)
                            
                            threat = ThreatInfo(
                                threat_type=ThreatType.SUSPICIOUS_PROCESS,
                                severity=ThreatSeverity.CRITICAL,
                                description=reason,
                                process_name=name,
                                process_id=pid,
                                action_taken="terminated"
                            )
                            threats.append(threat)
                            self._notify_threat(threat)
                            self.stats["threats_blocked"] += 1
                        except:
                            pass
                
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception as e:
            pass
        
        return threats
    
    def _usb_monitor_loop(self):
        """Monitor USB drives for worms"""
        usb_drives = ['D:', 'E:', 'F:', 'G:', 'H:']
        
        while self.running:
            try:
                for drive in usb_drives:
                    if not os.path.exists(drive):
                        continue
                    
                    # Check for suspicious executables
                    for exe_name in self.WORM_EXECUTABLES:
                        suspect_path = os.path.join(drive, exe_name)
                        if os.path.exists(suspect_path):
                            threat = ThreatInfo(
                                threat_type=ThreatType.WORM,
                                severity=ThreatSeverity.HIGH,
                                description=f"Worm detected on {drive}: {exe_name}",
                                file_path=suspect_path,
                                action_taken="quarantined"
                            )
                            self._quarantine_file(suspect_path, threat)
                    
                    # Check for autorun.inf
                    autorun_path = os.path.join(drive, "autorun.inf")
                    if os.path.exists(autorun_path):
                        try:
                            with open(autorun_path, 'r') as f:
                                content = f.read().lower()
                            
                            # Check for malicious autorun
                            if any(exe in content for exe in self.WORM_EXECUTABLES):
                                threat = ThreatInfo(
                                    threat_type=ThreatType.AUTORUN,
                                    severity=ThreatSeverity.HIGH,
                                    description=f"Malicious autorun.inf on {drive}",
                                    file_path=autorun_path,
                                    action_taken="neutralized"
                                )
                                self._neutralize_autorun(autorun_path)
                                self._notify_threat(threat)
                        except:
                            pass
            except Exception as e:
                pass
            
            time.sleep(20)  # Check every 20 seconds
    
    def _neutralize_autorun(self, autorun_path: str):
        """Neutralize a malicious autorun.inf"""
        try:
            # Replace with safe content
            safe_content = "[AutoRun]\nopen=\naction=\n"
            with open(autorun_path, 'w') as f:
                f.write(safe_content)
            # Make read-only
            os.chmod(autorun_path, 0o444)
        except:
            # If can't modify, try to delete
            try:
                os.remove(autorun_path)
            except:
                pass
    
    def _spyware_monitor_loop(self):
        """Monitor for spyware activity"""
        spyware_indicators = [
            'pynput', 'keyboard', 'keylogger', 'keystroke',
            'screenshot', 'imagegrab', 'screencapture',
            'webcam', 'camera', 'videocapture',
            'microphone', 'sounddevice', 'audiorecord'
        ]
        
        while self.running:
            try:
                for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                    try:
                        info = proc.info
                        name = info.get('name', '').lower()
                        pid = info.get('pid')
                        
                        if pid in self.blocked_pids:
                            continue
                        
                        if name in self.WHITELISTED_PROCESSES:
                            continue
                        
                        cmdline = info.get('cmdline', [])
                        cmdline_str = ' '.join(cmdline).lower() if cmdline else ''
                        
                        for indicator in spyware_indicators:
                            if indicator in cmdline_str:
                                # Additional check for listener/capture patterns
                                if any(kw in cmdline_str for kw in ['listener', 'on_press', 'capture', 'record', 'grab']):
                                    try:
                                        process = psutil.Process(pid)
                                        process.kill()
                                        self.blocked_pids.add(pid)
                                        
                                        threat = ThreatInfo(
                                            threat_type=ThreatType.SPYWARE,
                                            severity=ThreatSeverity.CRITICAL,
                                            description=f"Spyware detected: {indicator}",
                                            process_name=name,
                                            process_id=pid,
                                            action_taken="terminated"
                                        )
                                        self._notify_threat(threat)
                                        self.stats["threats_blocked"] += 1
                                    except:
                                        pass
                                break
                    
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue
            except Exception as e:
                pass
            
            time.sleep(30)  # Check every 30 seconds
    
    def run_manual_scan(self, callback: Optional[Callable[[str, int], None]] = None):
        """Run a manual scan of all protected directories"""
        threats_found = []
        total_files = 0
        scanned = 0
        
        # Count files first
        for directory in self.config.protected_directories:
            if os.path.exists(directory):
                for root, dirs, files in os.walk(directory):
                    total_files += len(files)
        
        for directory in self.config.protected_directories:
            if not os.path.exists(directory):
                continue
            
            for root, dirs, files in os.walk(directory):
                for file in files:
                    filepath = os.path.join(root, file)
                    filename = file.lower()
                    scanned += 1
                    
                    # Report progress
                    if callback:
                        progress = int((scanned / max(total_files, 1)) * 100)
                        callback(filepath, progress)
                    
                    # Check for ransomware
                    _, ext = os.path.splitext(filename)
                    if ext in self.RANSOMWARE_EXTENSIONS:
                        threat = ThreatInfo(
                            threat_type=ThreatType.RANSOMWARE,
                            severity=ThreatSeverity.CRITICAL,
                            description=f"Encrypted file: {filename}",
                            file_path=filepath,
                            action_taken="quarantined"
                        )
                        self._quarantine_file(filepath, threat)
                        threats_found.append(threat)
                    
                    # Check for ransom notes
                    elif filename.endswith('.txt'):
                        if any(kw in filename for kw in self.RANSOM_NOTE_KEYWORDS):
                            threat = ThreatInfo(
                                threat_type=ThreatType.RANSOMWARE,
                                severity=ThreatSeverity.HIGH,
                                description=f"Ransom note: {filename}",
                                file_path=filepath,
                                action_taken="quarantined"
                            )
                            self._quarantine_file(filepath, threat)
                            threats_found.append(threat)
                    
                    # Small delay to prevent high CPU usage
                    time.sleep(0.01)
        
        self.config.update_last_scan()
        return threats_found
    
    def restore_from_backup(self):
        """Restore all files from backup"""
        restored = []
        
        if not os.path.exists(self.config.backup_directory):
            return restored
        
        for root, dirs, files in os.walk(self.config.backup_directory):
            for file in files:
                backup_path = os.path.join(root, file)
                try:
                    rel_path = os.path.relpath(backup_path, self.config.backup_directory)
                    
                    # Try to restore to each protected directory
                    for protected_dir in self.config.protected_directories:
                        original_path = os.path.join(protected_dir, rel_path)
                        
                        # Create directory if needed
                        os.makedirs(os.path.dirname(original_path), exist_ok=True)
                        
                        # Restore file
                        shutil.copy2(backup_path, original_path)
                        restored.append(original_path)
                        break
                except:
                    pass
        
        return restored
    
    def get_quarantine_items(self) -> List[Dict]:
        """Get list of quarantined items"""
        return self.config.load_quarantine_log()
    
    def restore_from_quarantine(self, quarantine_path: str, original_path: str) -> bool:
        """Restore a file from quarantine (use with caution)"""
        try:
            if os.path.exists(quarantine_path):
                os.makedirs(os.path.dirname(original_path), exist_ok=True)
                shutil.move(quarantine_path, original_path)
                return True
        except:
            pass
        return False
    
    def delete_quarantine_item(self, quarantine_path: str) -> bool:
        """Permanently delete a quarantined file"""
        try:
            if os.path.exists(quarantine_path):
                os.remove(quarantine_path)
                return True
        except:
            pass
        return False
    
    def _notify_threat(self, threat: ThreatInfo):
        """Notify about a detected threat"""
        self.stats["threats_detected"] += 1
        self.config.increment_stat("threats_detected")
        
        # Save to alerts
        self.config.save_alert({
            "type": threat.threat_type.value,
            "severity": threat.severity.value,
            "description": threat.description,
            "file_path": threat.file_path,
            "process_name": threat.process_name,
            "process_id": threat.process_id,
            "action_taken": threat.action_taken
        })
        
        # Call UI callback
        if self.on_threat_detected:
            self.on_threat_detected(threat)
    
    def _notify_status(self, status: str):
        """Notify about status change"""
        if self.on_status_change:
            self.on_status_change(status)
    
    def get_stats(self) -> Dict:
        """Get current statistics"""
        return {
            **self.stats,
            "protected_directories": len(self.config.protected_directories),
            "protection_active": self.protection_enabled
        }
