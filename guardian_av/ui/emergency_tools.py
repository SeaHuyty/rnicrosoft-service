"""
Someth Antivirus - Emergency Tools Widget
Tools for removing ransomware, spyware, and restoring system
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QTextEdit, QMessageBox, QGroupBox, QGridLayout,
    QProgressBar, QScrollArea, QSizePolicy
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont
from datetime import datetime
import os

from ..ui.styles import COLORS


class RemovalWorker(QThread):
    """Background worker for emergency removal operations"""
    progress = pyqtSignal(str)
    finished = pyqtSignal(dict)
    
    def __init__(self, engine):
        super().__init__()
        self.engine = engine
    
    def run(self):
        self.progress.emit("Starting emergency removal...")
        results = self.engine.emergency_remove_all_threats()
        self.finished.emit(results)


class EmergencyToolsWidget(QWidget):
    """Emergency tools for malware removal"""
    
    def __init__(self, config_manager, protection_engine, parent=None):
        super().__init__(parent)
        self.config = config_manager
        self.engine = protection_engine
        self.worker = None
        self.setup_ui()
    
    def setup_ui(self):
        # Main layout with scroll area
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Create scroll area
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll_area.setStyleSheet("""
            QScrollArea {
                border: none;
                background-color: transparent;
            }
            QScrollBar:vertical {
                background-color: #1a1a2e;
                width: 12px;
                border-radius: 6px;
            }
            QScrollBar::handle:vertical {
                background-color: #00d4aa;
                border-radius: 6px;
                min-height: 30px;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
        """)
        
        # Content widget inside scroll area
        content_widget = QWidget()
        layout = QVBoxLayout(content_widget)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(12)
        
        # Header
        header_layout = QHBoxLayout()
        
        title = QLabel("🚨 Emergency Tools")
        title.setObjectName("titleLabel")
        header_layout.addWidget(title)
        
        header_layout.addStretch()
        
        layout.addLayout(header_layout)
        
        # Warning banner
        warning_frame = QFrame()
        warning_frame.setStyleSheet(f"""
            QFrame {{
                background-color: #442200;
                border: 2px solid #ff6600;
                border-radius: 8px;
                padding: 10px;
            }}
        """)
        warning_layout = QHBoxLayout(warning_frame)
        warning_layout.setContentsMargins(15, 10, 15, 10)
        
        warning_icon = QLabel("⚠️")
        warning_icon.setStyleSheet("font-size: 24px;")
        warning_layout.addWidget(warning_icon)
        
        warning_text = QLabel(
            "<b>Emergency Removal Tools</b><br>"
            "Use these tools if your system is infected with ransomware or spyware. "
            "These tools will remove malicious registry entries, kill dangerous processes, "
            "and delete malware persistence files."
        )
        warning_text.setStyleSheet(f"color: #ffcc00; font-size: 11px;")
        warning_text.setWordWrap(True)
        warning_layout.addWidget(warning_text, 1)
        
        warning_frame.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Maximum)
        layout.addWidget(warning_frame)
        
        # Tools Grid
        tools_frame = QFrame()
        tools_frame.setObjectName("card")
        tools_layout = QGridLayout(tools_frame)
        tools_layout.setContentsMargins(15, 15, 15, 15)
        tools_layout.setSpacing(15)
        
        # Tool 1: Emergency Removal
        removal_group = self._create_tool_group(
            "🔥 Emergency Removal",
            "Remove ALL known malware persistence:\n"
            "• Registry startup entries\n"
            "• Malicious VBS/BAT scripts\n"
            "• Background malware processes\n"
            "• Spyware log files",
            "Run Emergency Removal",
            "#cc0000",
            self._run_emergency_removal
        )
        tools_layout.addWidget(removal_group, 0, 0)
        
        # Tool 2: Kill Screen Locker
        locker_group = self._create_tool_group(
            "🔓 Kill Screen Locker",
            "Terminate ransomware screen lock:\n"
            "• Kills fullscreen ransom windows\n"
            "• Terminates pythonw.exe malware\n"
            "• Removes VBS service scripts\n"
            "• Restores desktop access",
            "Kill Screen Locker",
            "#ff6600",
            self._kill_screen_locker
        )
        tools_layout.addWidget(locker_group, 0, 1)
        
        # Tool 3: Clean Registry
        registry_group = self._create_tool_group(
            "🗝️ Clean Registry",
            "Remove malicious registry entries:\n"
            "• HKCU\\...\\Run entries\n"
            "• HKCU\\...\\RunOnce entries\n"
            "• WindowsSystemUpdate\n"
            "• Fake update services",
            "Clean Registry",
            "#0066cc",
            self._clean_registry
        )
        tools_layout.addWidget(registry_group, 1, 0)
        
        # Tool 4: Kill Spyware
        spyware_group = self._create_tool_group(
            "🕵️ Kill Spyware",
            "Terminate spyware processes:\n"
            "• Keyloggers (pynput)\n"
            "• Screen capture tools\n"
            "• Webcam/mic access\n"
            "• Data exfiltration bots",
            "Kill Spyware",
            "#660066",
            self._kill_spyware
        )
        tools_layout.addWidget(spyware_group, 1, 1)
        
        layout.addWidget(tools_frame)
        
        # Status/Log area
        log_frame = QFrame()
        log_frame.setObjectName("card")
        log_layout = QVBoxLayout(log_frame)
        log_layout.setContentsMargins(15, 15, 15, 15)
        
        log_header = QHBoxLayout()
        log_title = QLabel("📋 Operation Log")
        log_title.setStyleSheet(f"color: {COLORS['text']}; font-weight: bold; font-size: 12px;")
        log_header.addWidget(log_title)
        
        log_header.addStretch()
        
        clear_btn = QPushButton("Clear Log")
        clear_btn.setFixedWidth(80)
        clear_btn.clicked.connect(self._clear_log)
        log_header.addWidget(clear_btn)
        
        log_layout.addLayout(log_header)
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMinimumHeight(80)
        self.log_text.setMaximumHeight(150)
        self.log_text.setStyleSheet(f"""
            QTextEdit {{
                background-color: #0a0a0a;
                color: #00ff00;
                font-family: Consolas, 'Courier New', monospace;
                font-size: 11px;
                border: 2px solid {COLORS['primary']};
                border-radius: 6px;
                padding: 10px;
            }}
        """)
        self.log_text.setPlainText(f"[{datetime.now().strftime('%H:%M:%S')}] Emergency Tools ready.\n[{datetime.now().strftime('%H:%M:%S')}] Click any tool button to perform emergency operations.\n")
        log_layout.addWidget(self.log_text)
        
        layout.addWidget(log_frame)
        
        # Quick Status
        status_frame = QFrame()
        status_frame.setObjectName("card")
        status_layout = QHBoxLayout(status_frame)
        status_layout.setContentsMargins(15, 10, 15, 10)
        
        self.status_label = QLabel("Status: Ready")
        self.status_label.setStyleSheet(f"color: {COLORS['success']}; font-weight: bold;")
        status_layout.addWidget(self.status_label)
        
        status_layout.addStretch()
        
        # Check for threats button
        check_btn = QPushButton("🔍 Check System Status")
        check_btn.clicked.connect(self._check_system_status)
        status_layout.addWidget(check_btn)
        
        layout.addWidget(status_frame)
        
        layout.addStretch()
        
        # Set scroll area content
        scroll_area.setWidget(content_widget)
        main_layout.addWidget(scroll_area)
    
    def _create_tool_group(self, title, description, button_text, button_color, callback):
        """Create a tool group box"""
        group = QGroupBox(title)
        group.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        group.setStyleSheet(f"""
            QGroupBox {{
                color: {COLORS['text']};
                font-weight: bold;
                font-size: 13px;
                border: 2px solid {button_color};
                border-radius: 8px;
                margin-top: 12px;
                padding: 10px;
                background-color: rgba(0, 0, 0, 0.2);
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 12px;
                padding: 2px 8px;
                background-color: {COLORS['card']};
                border-radius: 4px;
            }}
        """)
        
        layout = QVBoxLayout(group)
        layout.setContentsMargins(10, 18, 10, 10)
        layout.setSpacing(8)
        
        desc_label = QLabel(description)
        desc_label.setStyleSheet(f"color: {COLORS['text']}; font-size: 10px; font-weight: normal;")
        desc_label.setWordWrap(True)
        layout.addWidget(desc_label)
        
        layout.addStretch()
        
        btn = QPushButton(button_text)
        btn.setMinimumHeight(35)
        btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {button_color};
                color: white;
                font-weight: bold;
                font-size: 11px;
                padding: 8px 15px;
                border-radius: 6px;
                border: none;
            }}
            QPushButton:hover {{
                background-color: {self._lighten_color(button_color)};
            }}
            QPushButton:pressed {{
                background-color: {self._darken_color(button_color)};
            }}
        """)
        btn.clicked.connect(callback)
        layout.addWidget(btn)
        
        return group
    
    def _lighten_color(self, color):
        """Lighten a hex color"""
        # Simple implementation
        if color.startswith('#'):
            r = min(255, int(color[1:3], 16) + 30)
            g = min(255, int(color[3:5], 16) + 30)
            b = min(255, int(color[5:7], 16) + 30)
            return f"#{r:02x}{g:02x}{b:02x}"
        return color
    
    def _darken_color(self, color):
        """Darken a hex color"""
        if color.startswith('#'):
            r = max(0, int(color[1:3], 16) - 30)
            g = max(0, int(color[3:5], 16) - 30)
            b = max(0, int(color[5:7], 16) - 30)
            return f"#{r:02x}{g:02x}{b:02x}"
        return color
    
    def _log(self, message):
        """Add message to log"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.log_text.append(f"[{timestamp}] {message}")
        # Scroll to bottom
        scrollbar = self.log_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
    
    def _clear_log(self):
        """Clear the log"""
        self.log_text.clear()
        self._log("Log cleared.")
    
    def _update_status(self, status, color=None):
        """Update status label"""
        if color:
            self.status_label.setStyleSheet(f"color: {color}; font-weight: bold;")
        self.status_label.setText(f"Status: {status}")
    
    def _run_emergency_removal(self):
        """Run emergency removal of all threats"""
        reply = QMessageBox.warning(
            self,
            "Emergency Removal",
            "This will attempt to remove ALL known malware:\n\n"
            "• Kill malicious processes\n"
            "• Remove registry persistence\n"
            "• Delete malware scripts\n"
            "• Clean spyware log files\n\n"
            "Continue with emergency removal?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply != QMessageBox.Yes:
            return
        
        self._update_status("Running emergency removal...", "#ff6600")
        self._log("🔥 Starting emergency removal...")
        
        # Run in background
        self.worker = RemovalWorker(self.engine)
        self.worker.progress.connect(self._log)
        self.worker.finished.connect(self._on_removal_complete)
        self.worker.start()
    
    def _on_removal_complete(self, results):
        """Handle removal completion"""
        self._log("=" * 40)
        self._log("EMERGENCY REMOVAL COMPLETE")
        self._log("=" * 40)
        
        if results["registry_removed"]:
            self._log(f"✅ Registry entries removed: {len(results['registry_removed'])}")
            for entry in results["registry_removed"]:
                self._log(f"   - {entry}")
        
        if results["scripts_removed"]:
            self._log(f"✅ Scripts removed: {len(results['scripts_removed'])}")
            for script in results["scripts_removed"]:
                self._log(f"   - {script}")
        
        if results["processes_killed"]:
            self._log(f"✅ Processes killed: {len(results['processes_killed'])}")
            for proc in results["processes_killed"]:
                self._log(f"   - {proc}")
        
        if results["files_quarantined"]:
            self._log(f"✅ Files cleaned: {len(results['files_quarantined'])}")
        
        if results["errors"]:
            self._log(f"⚠️ Errors: {len(results['errors'])}")
            for error in results["errors"]:
                self._log(f"   - {error}")
        
        total_removed = (
            len(results["registry_removed"]) + 
            len(results["scripts_removed"]) + 
            len(results["processes_killed"]) +
            len(results["files_quarantined"])
        )
        
        if total_removed > 0:
            self._update_status(f"Removed {total_removed} threats", COLORS['success'])
            QMessageBox.information(
                self,
                "Removal Complete",
                f"Emergency removal completed!\n\n"
                f"Registry entries removed: {len(results['registry_removed'])}\n"
                f"Scripts removed: {len(results['scripts_removed'])}\n"
                f"Processes killed: {len(results['processes_killed'])}\n"
                f"Files cleaned: {len(results['files_quarantined'])}"
            )
        else:
            self._update_status("No threats found", COLORS['text_secondary'])
            QMessageBox.information(
                self,
                "Removal Complete",
                "No known threats were found on your system."
            )
    
    def _kill_screen_locker(self):
        """Kill ransomware screen locker"""
        self._log("🔓 Attempting to kill screen locker...")
        self._update_status("Killing screen locker...", "#ff6600")
        
        # Check if screen locker is detected
        if self.engine.check_for_screen_locker():
            self._log("⚠️ Screen locker detected!")
        
        # Attempt to kill it
        success = self.engine.kill_screen_locker()
        
        if success:
            self._log("✅ Screen locker processes terminated")
            self._update_status("Screen locker killed", COLORS['success'])
            
            # Also clean registry
            self._log("Cleaning registry persistence...")
            import winreg
            try:
                with winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r"Software\Microsoft\Windows\CurrentVersion\Run",
                    0, winreg.KEY_ALL_ACCESS
                ) as key:
                    try:
                        winreg.DeleteValue(key, "WindowsSystemUpdate")
                        self._log("✅ Registry entry removed")
                    except FileNotFoundError:
                        self._log("ℹ️ No registry entry found")
            except Exception as e:
                self._log(f"⚠️ Registry cleanup: {e}")
            
            QMessageBox.information(
                self,
                "Screen Locker Killed",
                "The screen locker has been terminated.\n\n"
                "If the screen is still locked, try pressing Alt+Tab or Ctrl+Alt+Delete."
            )
        else:
            self._log("ℹ️ No screen locker process found")
            self._update_status("Ready", COLORS['text_secondary'])
    
    def _clean_registry(self):
        """Clean malicious registry entries"""
        self._log("🗝️ Scanning registry for malicious entries...")
        self._update_status("Cleaning registry...", "#0066cc")
        
        import winreg
        removed = []
        
        registry_locations = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ]
        
        malicious_names = [
            'windowssystemupdate', 'windowsupdate', 'systemupdate',
            'adobeflashupdate', 'chromeupdate'
        ]
        
        for hkey, subkey in registry_locations:
            try:
                with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_ALL_ACCESS) as key:
                    i = 0
                    values_to_remove = []
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            name_lower = name.lower().replace(' ', '').replace('_', '')
                            
                            for mal_name in malicious_names:
                                if mal_name in name_lower:
                                    values_to_remove.append(name)
                                    break
                            i += 1
                        except OSError:
                            break
                    
                    for name in values_to_remove:
                        try:
                            winreg.DeleteValue(key, name)
                            removed.append(f"{subkey}\\{name}")
                            self._log(f"✅ Removed: {name}")
                        except:
                            pass
            except Exception as e:
                self._log(f"⚠️ Error accessing {subkey}: {e}")
        
        if removed:
            self._update_status(f"Removed {len(removed)} entries", COLORS['success'])
            QMessageBox.information(
                self,
                "Registry Cleaned",
                f"Removed {len(removed)} malicious registry entries."
            )
        else:
            self._log("ℹ️ No malicious registry entries found")
            self._update_status("Registry clean", COLORS['text_secondary'])
    
    def _kill_spyware(self):
        """Kill spyware processes"""
        self._log("🕵️ Scanning for spyware processes...")
        self._update_status("Killing spyware...", "#660066")
        
        threats = self.engine.detect_spyware_processes()
        
        if threats:
            self._log(f"✅ Terminated {len(threats)} spyware processes:")
            for threat in threats:
                self._log(f"   - {threat.process_name} (PID: {threat.process_id})")
            
            self._update_status(f"Killed {len(threats)} spyware", COLORS['success'])
            QMessageBox.information(
                self,
                "Spyware Killed",
                f"Terminated {len(threats)} spyware processes."
            )
        else:
            self._log("ℹ️ No spyware processes found")
            self._update_status("No spyware found", COLORS['text_secondary'])
        
        # Also clean temp folder
        self._log("Cleaning temp folder for spyware logs...")
        temp_path = os.getenv('TEMP', '')
        spyware_patterns = ['key_log', 'keylogger', 'screenshot', 'webcam', 'chrome_password']
        cleaned = 0
        
        if os.path.exists(temp_path):
            try:
                for item in os.listdir(temp_path):
                    item_lower = item.lower()
                    for pattern in spyware_patterns:
                        if pattern in item_lower:
                            try:
                                item_path = os.path.join(temp_path, item)
                                if os.path.isfile(item_path):
                                    os.remove(item_path)
                                    cleaned += 1
                                    self._log(f"   Deleted: {item}")
                            except:
                                pass
                            break
            except:
                pass
        
        if cleaned > 0:
            self._log(f"✅ Cleaned {cleaned} spyware log files")
    
    def _check_system_status(self):
        """Check current system threat status"""
        self._log("🔍 Checking system status...")
        self._update_status("Checking...", "#0066cc")
        
        summary = self.engine.get_threat_summary()
        
        self._log("=" * 40)
        self._log("SYSTEM STATUS REPORT")
        self._log("=" * 40)
        self._log(f"Threats Detected: {summary['threats_detected']}")
        self._log(f"Threats Blocked: {summary['threats_blocked']}")
        self._log(f"Registry Threats: {summary['registry_threats']}")
        self._log(f"Spyware Blocked: {summary['spyware_blocked']}")
        self._log(f"Screen Locker: {'DETECTED!' if summary['screen_locker_detected'] else 'Not detected'}")
        self._log("=" * 40)
        
        if summary['screen_locker_detected']:
            self._update_status("⚠️ SCREEN LOCKER DETECTED!", "#ff0000")
            QMessageBox.warning(
                self,
                "Screen Locker Detected!",
                "A ransomware screen locker has been detected!\n\n"
                "Click 'Kill Screen Locker' to terminate it."
            )
        elif summary['threats_blocked'] > 0:
            self._update_status(f"Protected - {summary['threats_blocked']} threats blocked", COLORS['success'])
        else:
            self._update_status("System appears clean", COLORS['success'])
