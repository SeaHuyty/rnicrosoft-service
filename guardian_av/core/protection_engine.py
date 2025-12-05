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
    REGISTRY_PERSISTENCE = "registry_persistence"
    SCREEN_LOCKER = "screen_locker"
    KEYLOGGER = "keylogger"
    DATA_EXFILTRATION = "data_exfiltration"
    CHROME_STEALER = "chrome_stealer"


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
    
    # Suspicious process patterns - detect specific malware files
    MALICIOUS_SIGNATURES = {
        'longchhunhour.py',  # Ransomware + worm
        'execute_ransomware',
        'spread_via_usb', 
        'spread_via_network',
        'spyware.py',  # Spyware main file
        'encrypt.py',  # Encryption component
        'worm.py',  # Worm component
    }
    
    # Suspicious commands - detect malicious operations
    MALICIOUS_COMMANDS = {
        'execute_ransomware',
        'spread_via',
        'encrypt_file_with_ransom',
        'create_ransom_note',
        'send_telegram_message',  # Data exfiltration
        'send_telegram_file',  # Data exfiltration
        'get_chrome_passwords',  # Chrome stealing
        'get_master_key',  # Chrome decryption
        'decrypt_password',  # Password theft
        'quick_keylogger',  # Keylogger function
        'imagegrab.grab',  # Screenshot capture
        'cv2.videocapture',  # Webcam capture
    }
    
    # Spyware indicators - specific to detected spyware
    SPYWARE_INDICATORS = {
        'pynput.keyboard',  # Keylogger library
        'listener(on_press',  # Keylogger pattern
        'imagegrab',  # Screenshot
        'cv2.videocapture',  # Webcam
        'win32crypt',  # Password decryption
        'browserhistory',  # Browser history theft
        'telegram.ext',  # Telegram bot exfiltration
        'api.telegram.org',  # Telegram API
        'chrome_passwords',  # Chrome password theft
        'login data',  # Chrome login database
    }
    
    # Registry keys used for persistence (by YouTube Premium ransomware)
    MALICIOUS_REGISTRY_VALUES = {
        'windowssystemupdate',  # The fake YouTube Premium ransomware
        'windowsupdate.vbs',
        'systemupdate.bat',
        'systemupdate.vbs',
    }
    
    # Suspicious script patterns in AppData
    SUSPICIOUS_SCRIPTS = {
        'windowsupdate.vbs',
        'windowsupdate.bat', 
        'systemupdate.vbs',
        'systemupdate.bat',
    }
    
    # Worm-related names
    WORM_EXECUTABLES = {
        'windows_update_service.exe', 'adobe_flash_update.exe',
        'system_service.exe', 'update_service.exe', 'system_update.exe'
    }
    
    # Safe processes (whitelist) - expanded to reduce false positives
    WHITELISTED_PROCESSES = {
        'system', 'svchost.exe', 'csrss.exe', 'dwm.exe', 'explorer.exe',
        'taskhostw.exe', 'runtimebroker.exe', 'applicationframehost.exe',
        'code.exe', 'python.exe', 'pythonw.exe', 'powershell.exe',
        'cmd.exe', 'conhost.exe', 'msedge.exe', 'chrome.exe', 'firefox.exe',
        'windowsterminal.exe', 'searchhost.exe', 'shellexperiencehost.exe',
        'guardian_av.exe', 'main.py', 'pip.exe', 'git.exe', 'node.exe',
        'npm.exe', 'vscode.exe', 'windowsapps', 'microsoft', 'defender',
        'antimalware', 'securityhealth', 'smartscreen', 'msbuild.exe',
        'devenv.exe', 'notepad.exe', 'notepad++.exe', 'sublime_text.exe'
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
        self._registry_monitor_thread: Optional[threading.Thread] = None
        self._script_monitor_thread: Optional[threading.Thread] = None
        
        # Statistics
        self.stats = {
            "threats_detected": 0,
            "threats_blocked": 0,
            "files_scanned": 0,
            "processes_scanned": 0,
            "registry_threats_blocked": 0,
            "spyware_blocked": 0,
        }
        
        # Load saved stats from config
        saved_stats = self.config.get_stats()
        if saved_stats:
            self.stats.update(saved_stats)
        
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
        
        # Start registry monitor thread (detects persistence mechanisms)
        self._registry_monitor_thread = threading.Thread(
            target=self._registry_monitor_loop,
            name="RegistryMonitor",
            daemon=True
        )
        self._registry_monitor_thread.start()
        
        # Start script monitor thread (detects malicious VBS/BAT in AppData)
        self._script_monitor_thread = threading.Thread(
            target=self._script_monitor_loop,
            name="ScriptMonitor",
            daemon=True
        )
        self._script_monitor_thread.start()
        
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
        
        # Check for ransom notes - must be exact match for READ_ME.txt
        # or contain multiple ransom keywords to avoid false positives
        if filename == 'read_me.txt' or filename == 'readme_ransom.txt':
            try:
                with open(filepath, 'r', errors='ignore') as f:
                    content = f.read().lower()
                # Only flag if content looks like a ransom note
                ransom_indicators = ['bitcoin', 'decrypt', 'pay', 'ransom', 'encrypted', 'wallet']
                matches = sum(1 for kw in ransom_indicators if kw in content)
                if matches >= 2:  # Need at least 2 indicators
                    threat = ThreatInfo(
                        threat_type=ThreatType.RANSOMWARE,
                        severity=ThreatSeverity.HIGH,
                        description=f"Ransom note detected: {filename}",
                        file_path=filepath,
                        action_taken="quarantined"
                    )
                    self._quarantine_file(filepath, threat)
                    return
            except:
                pass
    
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
                    
                    # NOTE: Removed "access to protected folders" check
                    # It was causing too many false positives. 
                    # We rely on file monitoring instead.
                    
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
        """Monitor for spyware activity - enhanced detection for keyloggers, screen capture, data theft"""
        # Spyware scripts to detect
        spyware_scripts = [
            'spyware.py',  # Main spyware file
            'keylogger.py',
            'screengrab.py',
        ]
        
        # Spyware file indicators (log files created by spyware)
        spyware_log_patterns = [
            'key_logs', 'keylogger', 'keystroke',
            'screenshot', 'webcam', 'camera_capture',
            'chrome_passwords', 'decrypted_passwords',
            'browser_history', 'wifi_password',
        ]
        
        while self.running:
            try:
                # 1. Check for spyware processes
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
                        
                        detected = False
                        threat_type = ThreatType.SPYWARE
                        description = ""
                        
                        # Check for spyware scripts
                        for script in spyware_scripts:
                            if script in cmdline_str:
                                detected = True
                                description = f"Spyware script: {script}"
                                break
                        
                        # Check for spyware indicators in command line
                        if not detected:
                            for indicator in self.SPYWARE_INDICATORS:
                                if indicator in cmdline_str:
                                    detected = True
                                    # Categorize threat type
                                    if 'pynput' in indicator or 'keyboard' in indicator:
                                        threat_type = ThreatType.KEYLOGGER
                                        description = f"Keylogger detected: {indicator}"
                                    elif 'telegram' in indicator:
                                        threat_type = ThreatType.DATA_EXFILTRATION
                                        description = f"Data exfiltration: {indicator}"
                                    elif 'chrome' in indicator or 'password' in indicator:
                                        threat_type = ThreatType.CHROME_STEALER
                                        description = f"Password stealer: {indicator}"
                                    else:
                                        description = f"Spyware activity: {indicator}"
                                    break
                        
                        if detected:
                            try:
                                process = psutil.Process(pid)
                                process.kill()
                                self.blocked_pids.add(pid)
                                
                                threat = ThreatInfo(
                                    threat_type=threat_type,
                                    severity=ThreatSeverity.CRITICAL,
                                    description=description,
                                    process_name=name,
                                    process_id=pid,
                                    action_taken="terminated"
                                )
                                self._notify_threat(threat)
                                self.stats["spyware_blocked"] += 1
                                self.stats["threats_blocked"] += 1
                            except:
                                pass
                    
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue
                        
                # 2. Check for spyware log files in temp
                temp_path = os.getenv('TEMP', '')
                if os.path.exists(temp_path):
                    try:
                        for item in os.listdir(temp_path):
                            item_lower = item.lower()
                            for pattern in spyware_log_patterns:
                                if pattern in item_lower:
                                    item_path = os.path.join(temp_path, item)
                                    if os.path.isfile(item_path):
                                        try:
                                            os.remove(item_path)
                                        except:
                                            pass
                                    break
                    except:
                        pass
                        
            except Exception as e:
                pass
            
            time.sleep(15)  # Check every 15 seconds
    
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
                    self.stats["files_scanned"] += 1
                    
                    # Report progress
                    if callback:
                        progress = int((scanned / max(total_files, 1)) * 100)
                        callback(filepath, progress)
                    
                    # Check for ransomware encrypted files
                    _, ext = os.path.splitext(filename)
                    if ext in self.RANSOMWARE_EXTENSIONS:
                        threat = ThreatInfo(
                            threat_type=ThreatType.RANSOMWARE,
                            severity=ThreatSeverity.CRITICAL,
                            description=f"Encrypted file: {filename}",
                            file_path=filepath,
                            action_taken="detected"
                        )
                        threats_found.append(threat)
                        self._notify_threat(threat)
                    
                    # Check for ransom notes
                    elif filename.endswith('.txt'):
                        if any(kw in filename for kw in self.RANSOM_NOTE_KEYWORDS):
                            threat = ThreatInfo(
                                threat_type=ThreatType.RANSOMWARE,
                                severity=ThreatSeverity.HIGH,
                                description=f"Ransom note: {filename}",
                                file_path=filepath,
                                action_taken="detected"
                            )
                            threats_found.append(threat)
                            self._notify_threat(threat)
                    
                    # Check Python files for malware patterns
                    elif filename.endswith('.py'):
                        try:
                            with open(filepath, 'r', errors='ignore') as f:
                                content = f.read().lower()
                            
                            # Check for spyware indicators
                            for indicator in self.SPYWARE_INDICATORS:
                                if indicator.lower() in content:
                                    threat_type = ThreatType.SPYWARE
                                    if 'keyboard' in indicator or 'keylog' in indicator:
                                        threat_type = ThreatType.KEYLOGGER
                                    elif 'telegram' in indicator or 'bot_token' in indicator:
                                        threat_type = ThreatType.DATA_EXFILTRATION
                                    elif 'chrome' in indicator or 'login' in indicator:
                                        threat_type = ThreatType.CHROME_STEALER
                                    
                                    threat = ThreatInfo(
                                        threat_type=threat_type,
                                        severity=ThreatSeverity.HIGH,
                                        description=f"Malware pattern '{indicator}' in {filename}",
                                        file_path=filepath,
                                        action_taken="detected"
                                    )
                                    threats_found.append(threat)
                                    self.stats["threats_detected"] += 1
                                    self._notify_threat(threat)
                                    break  # One alert per file
                            
                            # Check for ransomware patterns
                            for reg_value in self.MALICIOUS_REGISTRY_VALUES:
                                if reg_value.lower() in content:
                                    threat = ThreatInfo(
                                        threat_type=ThreatType.RANSOMWARE,
                                        severity=ThreatSeverity.CRITICAL,
                                        description=f"Ransomware pattern '{reg_value}' in {filename}",
                                        file_path=filepath,
                                        action_taken="detected"
                                    )
                                    threats_found.append(threat)
                                    self.stats["threats_detected"] += 1
                                    self._notify_threat(threat)
                                    break
                        except:
                            pass
                    
                    # Small delay to prevent high CPU usage
                    time.sleep(0.01)
        
        self.config.update_last_scan()
        return threats_found
    
    def restore_from_backup(self, target_directory: str = None):
        """Restore all files from backup to their original locations"""
        restored = []
        
        if not os.path.exists(self.config.backup_directory):
            return restored
        
        for root, dirs, files in os.walk(self.config.backup_directory):
            for file in files:
                backup_path = os.path.join(root, file)
                try:
                    rel_path = os.path.relpath(backup_path, self.config.backup_directory)
                    
                    if target_directory:
                        # Restore to specific directory
                        original_path = os.path.join(target_directory, file)
                    else:
                        # Try to restore to each protected directory
                        for protected_dir in self.config.protected_directories:
                            original_path = os.path.join(protected_dir, rel_path)
                            break
                    
                    # Create directory if needed
                    os.makedirs(os.path.dirname(original_path), exist_ok=True)
                    
                    # Restore file
                    shutil.copy2(backup_path, original_path)
                    restored.append(original_path)
                except:
                    pass
        
        return restored
    
    def get_backup_files(self) -> List[Dict]:
        """Get list of backed up files"""
        backups = []
        
        if not os.path.exists(self.config.backup_directory):
            return backups
        
        for root, dirs, files in os.walk(self.config.backup_directory):
            for file in files:
                backup_path = os.path.join(root, file)
                try:
                    stat = os.stat(backup_path)
                    backups.append({
                        'filename': file,
                        'path': backup_path,
                        'size': stat.st_size,
                        'modified': stat.st_mtime
                    })
                except:
                    pass
        
        return backups
    
    def restore_single_backup(self, backup_path: str, target_path: str) -> bool:
        """Restore a single file from backup"""
        try:
            if os.path.exists(backup_path):
                os.makedirs(os.path.dirname(target_path), exist_ok=True)
                shutil.copy2(backup_path, target_path)
                return True
        except:
            pass
        return False
    
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
    
    # ==================== REGISTRY MONITORING ====================
    
    def _registry_monitor_loop(self):
        """Monitor Windows registry for malicious persistence entries"""
        import winreg
        
        registry_locations = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ]
        
        while self.running:
            try:
                for hkey, subkey in registry_locations:
                    try:
                        with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ) as key:
                            i = 0
                            while True:
                                try:
                                    name, value, _ = winreg.EnumValue(key, i)
                                    name_lower = name.lower()
                                    value_lower = value.lower() if isinstance(value, str) else ""
                                    
                                    # Check for known malicious registry entries
                                    for mal_value in self.MALICIOUS_REGISTRY_VALUES:
                                        if mal_value in name_lower or mal_value in value_lower:
                                            threat = ThreatInfo(
                                                threat_type=ThreatType.REGISTRY_PERSISTENCE,
                                                severity=ThreatSeverity.CRITICAL,
                                                description=f"Malicious startup entry: {name}",
                                                file_path=value if isinstance(value, str) else None,
                                                action_taken="detected"
                                            )
                                            self._notify_threat(threat)
                                            self.stats["registry_threats_blocked"] += 1
                                            # Attempt to remove
                                            self._remove_registry_entry(hkey, subkey, name)
                                            break
                                    
                                    i += 1
                                except OSError:
                                    break
                    except WindowsError:
                        pass
            except Exception as e:
                pass
            
            time.sleep(10)  # Check every 10 seconds
    
    def _remove_registry_entry(self, hkey, subkey: str, value_name: str) -> bool:
        """Remove a malicious registry entry"""
        import winreg
        try:
            with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, value_name)
                return True
        except:
            return False
    
    # ==================== SCRIPT MONITORING ====================
    
    def _script_monitor_loop(self):
        """Monitor for malicious VBS/BAT scripts in AppData"""
        appdata_locations = [
            os.path.join(os.getenv('APPDATA', ''), 'Microsoft'),
            os.path.join(os.getenv('APPDATA', ''), 'Microsoft', 'Windows'),
            os.getenv('TEMP', ''),
        ]
        
        while self.running:
            try:
                for location in appdata_locations:
                    if not os.path.exists(location):
                        continue
                    
                    try:
                        for item in os.listdir(location):
                            item_lower = item.lower()
                            item_path = os.path.join(location, item)
                            
                            # Check for suspicious script files
                            for script in self.SUSPICIOUS_SCRIPTS:
                                if script in item_lower:
                                    threat = ThreatInfo(
                                        threat_type=ThreatType.MALICIOUS_FILE,
                                        severity=ThreatSeverity.HIGH,
                                        description=f"Malicious script detected: {item}",
                                        file_path=item_path,
                                        action_taken="quarantined"
                                    )
                                    self._quarantine_file(item_path, threat)
                                    break
                    except PermissionError:
                        pass
            except Exception as e:
                pass
            
            time.sleep(15)  # Check every 15 seconds
    
    # ==================== ENHANCED SPYWARE DETECTION ====================
    
    def detect_spyware_processes(self) -> List[ThreatInfo]:
        """Detect and terminate spyware processes (keyloggers, screen capture, etc.)"""
        threats = []
        
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
                    
                    # Check for spyware indicators
                    detected_indicator = None
                    threat_type = ThreatType.SPYWARE
                    
                    for indicator in self.SPYWARE_INDICATORS:
                        if indicator in cmdline_str:
                            detected_indicator = indicator
                            
                            # Categorize the threat
                            if 'pynput' in indicator or 'keylog' in indicator or 'listener' in indicator:
                                threat_type = ThreatType.KEYLOGGER
                            elif 'telegram' in indicator or 'api.telegram' in indicator:
                                threat_type = ThreatType.DATA_EXFILTRATION
                            elif 'chrome' in indicator or 'password' in indicator or 'win32crypt' in indicator:
                                threat_type = ThreatType.CHROME_STEALER
                            elif 'imagegrab' in indicator or 'videocapture' in indicator:
                                threat_type = ThreatType.SPYWARE
                            
                            break
                    
                    # Also check for specific spyware files
                    if not detected_indicator:
                        if 'spyware.py' in cmdline_str:
                            detected_indicator = 'spyware.py'
                    
                    if detected_indicator:
                        try:
                            process = psutil.Process(pid)
                            process.kill()
                            self.blocked_pids.add(pid)
                            
                            threat = ThreatInfo(
                                threat_type=threat_type,
                                severity=ThreatSeverity.CRITICAL,
                                description=f"Spyware detected: {detected_indicator}",
                                process_name=name,
                                process_id=pid,
                                action_taken="terminated"
                            )
                            threats.append(threat)
                            self._notify_threat(threat)
                            self.stats["spyware_blocked"] += 1
                        except:
                            pass
                
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception as e:
            pass
        
        return threats
    
    # ==================== EMERGENCY REMOVAL TOOLS ====================
    
    def emergency_remove_all_threats(self) -> Dict:
        """Emergency removal of all known malware persistence mechanisms"""
        results = {
            "registry_removed": [],
            "scripts_removed": [],
            "processes_killed": [],
            "files_quarantined": [],
            "errors": []
        }
        
        # 1. Remove registry entries
        import winreg
        registry_locations = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ]
        
        for hkey, subkey in registry_locations:
            try:
                with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_ALL_ACCESS) as key:
                    # Get all values first
                    values_to_remove = []
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            name_lower = name.lower()
                            value_lower = value.lower() if isinstance(value, str) else ""
                            
                            for mal_value in self.MALICIOUS_REGISTRY_VALUES:
                                if mal_value in name_lower or mal_value in value_lower:
                                    values_to_remove.append(name)
                                    break
                            i += 1
                        except OSError:
                            break
                    
                    # Remove malicious values
                    for name in values_to_remove:
                        try:
                            winreg.DeleteValue(key, name)
                            results["registry_removed"].append(f"{subkey}\\{name}")
                        except Exception as e:
                            results["errors"].append(f"Failed to remove registry {name}: {e}")
            except Exception as e:
                pass
        
        # 2. Kill malicious processes (pythonw.exe running malware)
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    info = proc.info
                    name = info.get('name', '').lower()
                    pid = info.get('pid')
                    cmdline = info.get('cmdline', [])
                    cmdline_str = ' '.join(cmdline).lower() if cmdline else ''
                    
                    # Kill pythonw.exe processes that might be the ransomware service
                    if 'pythonw' in name:
                        # Check if it's running any known malicious scripts
                        suspicious_scripts = ['premium', 'youtube', 'systemupdate', 'windowsupdate', 'spyware', 'ransomware']
                        for script in suspicious_scripts:
                            if script in cmdline_str:
                                try:
                                    process = psutil.Process(pid)
                                    process.kill()
                                    results["processes_killed"].append(f"{name} (PID: {pid})")
                                except:
                                    pass
                                break
                except:
                    continue
        except Exception as e:
            results["errors"].append(f"Process scan error: {e}")
        
        # 3. Remove malicious scripts from AppData
        script_locations = [
            os.path.join(os.getenv('APPDATA', ''), 'Microsoft'),
            os.path.join(os.getenv('APPDATA', ''), 'Microsoft', 'Windows'),
        ]
        
        for location in script_locations:
            if not os.path.exists(location):
                continue
            
            try:
                for item in os.listdir(location):
                    item_lower = item.lower()
                    item_path = os.path.join(location, item)
                    
                    for script in self.SUSPICIOUS_SCRIPTS:
                        if script in item_lower:
                            try:
                                os.remove(item_path)
                                results["scripts_removed"].append(item_path)
                            except Exception as e:
                                results["errors"].append(f"Failed to remove {item_path}: {e}")
                            break
            except:
                pass
        
        # 4. Also check temp folder for log files from spyware
        temp_path = os.getenv('TEMP', '')
        spyware_logs = ['key_logs', 'keylogger', 'screenshot', 'webcam', 'chrome_passwords', 'system_info']
        
        if os.path.exists(temp_path):
            try:
                for root, dirs, files in os.walk(temp_path):
                    for file in files:
                        file_lower = file.lower()
                        for log in spyware_logs:
                            if log in file_lower:
                                file_path = os.path.join(root, file)
                                try:
                                    os.remove(file_path)
                                    results["files_quarantined"].append(file_path)
                                except:
                                    pass
                                break
                    # Don't go too deep
                    if root.count(os.sep) - temp_path.count(os.sep) > 2:
                        break
            except:
                pass
        
        return results
    
    def check_for_screen_locker(self) -> bool:
        """Check if a ransomware screen locker is active"""
        try:
            import ctypes
            from ctypes import wintypes
            
            user32 = ctypes.windll.user32
            
            # Get foreground window
            hwnd = user32.GetForegroundWindow()
            
            # Get window title
            length = user32.GetWindowTextLengthW(hwnd)
            buff = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, buff, length + 1)
            title = buff.value.lower()
            
            # Check for ransomware indicators in window title
            ransomware_indicators = [
                'enterprise security',
                'ransomware',
                'files encrypted',
                'bitcoin',
                'decrypt',
                'security breach',
                'ransom',
                'pay',
            ]
            
            for indicator in ransomware_indicators:
                if indicator in title:
                    return True
            
            # Check if window is fullscreen and topmost
            rect = wintypes.RECT()
            user32.GetWindowRect(hwnd, ctypes.byref(rect))
            
            screen_width = user32.GetSystemMetrics(0)
            screen_height = user32.GetSystemMetrics(1)
            
            is_fullscreen = (
                rect.right - rect.left >= screen_width - 10 and 
                rect.bottom - rect.top >= screen_height - 10
            )
            
            # If fullscreen and has suspicious title keywords
            if is_fullscreen and any(kw in title for kw in ['security', 'alert', 'warning', 'locked']):
                return True
                
        except Exception as e:
            pass
        
        return False
    
    def kill_screen_locker(self) -> bool:
        """Attempt to kill ransomware screen locker windows"""
        try:
            import subprocess
            
            # Kill common ransomware process names
            processes_to_kill = ['pythonw.exe', 'wscript.exe']
            
            for proc_name in processes_to_kill:
                try:
                    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                        info = proc.info
                        name = info.get('name', '').lower()
                        cmdline = info.get('cmdline', [])
                        cmdline_str = ' '.join(cmdline).lower() if cmdline else ''
                        
                        if proc_name in name:
                            # Check if it's running known ransomware
                            if any(kw in cmdline_str for kw in ['premium', 'ransom', 'encrypt', 'locker', 'youtube']):
                                try:
                                    process = psutil.Process(info.get('pid'))
                                    process.kill()
                                except:
                                    pass
                except:
                    continue
            
            return True
        except:
            return False
    
    def get_threat_summary(self) -> Dict:
        """Get a summary of current threat status"""
        return {
            "threats_detected": self.stats["threats_detected"],
            "threats_blocked": self.stats["threats_blocked"],
            "registry_threats": self.stats["registry_threats_blocked"],
            "spyware_blocked": self.stats["spyware_blocked"],
            "files_scanned": self.stats["files_scanned"],
            "processes_scanned": self.stats["processes_scanned"],
            "screen_locker_detected": self.check_for_screen_locker(),
        }
