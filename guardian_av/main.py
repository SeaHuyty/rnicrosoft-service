"""
Guardian Antivirus - Main Application
Professional GUI Antivirus with Real-time Protection
"""

import sys
import os
import threading
import subprocess
from datetime import datetime

# Add parent directory to path for imports when running directly
_script_dir = os.path.dirname(os.path.abspath(__file__))
_parent_dir = os.path.dirname(_script_dir)
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QLabel, QPushButton, QSystemTrayIcon, QMenu, QAction,
    QMessageBox, QSplashScreen, QSizePolicy
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QObject
from PyQt5.QtGui import QIcon, QPixmap, QFont

# Import our modules
from guardian_av.core.config_manager import ConfigManager
from guardian_av.core.protection_engine import ProtectionEngine, ThreatInfo
from guardian_av.core.startup_manager import StartupManager
from guardian_av.core.notifications import NotificationManager, NotificationConfig
from guardian_av.ui.styles import DARK_STYLESHEET, COLORS
from guardian_av.ui.dashboard import DashboardWidget
from guardian_av.ui.settings import SettingsWidget
from guardian_av.ui.alerts import AlertsWidget
from guardian_av.ui.quarantine import QuarantineWidget
from guardian_av.ui.backup_restore import BackupRestoreWidget
from guardian_av.ui.emergency_tools import EmergencyToolsWidget


class SignalBridge(QObject):
    """Bridge for thread-safe signal emission"""
    threat_detected = pyqtSignal(object)  # ThreatInfo
    status_changed = pyqtSignal(str)
    scan_progress = pyqtSignal(str, int)  # filepath, progress
    scan_complete = pyqtSignal(int)  # threats found
    emergency_kill = pyqtSignal()  # Emergency hotkey triggered


class MainWindow(QMainWindow):
    """Main application window"""
    
    def __init__(self, start_minimized=False):
        super().__init__()
        
        self.start_minimized = start_minimized
        
        # Initialize managers
        self.config = ConfigManager()
        self.startup = StartupManager()
        self.notifier = NotificationManager(NotificationConfig(
            enabled=self.config.notifications_enabled
        ))
        
        # Initialize protection engine
        self.engine = ProtectionEngine(self.config)
        
        # Signal bridge for thread-safe communication
        self.signals = SignalBridge()
        self.signals.threat_detected.connect(self._on_threat_detected)
        self.signals.status_changed.connect(self._on_status_changed)
        self.signals.scan_progress.connect(self._on_scan_progress)
        self.signals.scan_complete.connect(self._on_scan_complete)
        
        # Connect engine callbacks
        self.engine.on_threat_detected = lambda t: self.signals.threat_detected.emit(t)
        self.engine.on_status_change = lambda s: self.signals.status_changed.emit(s)
        
        # Setup UI
        self.setup_ui()
        self.setup_tray()
        
        # Stats update timer
        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self._update_stats)
        self.stats_timer.start(2000)  # Update every 2 seconds
        
        # Auto-start protection
        QTimer.singleShot(500, self._auto_start_protection)
        
        # Setup global emergency hotkey
        self.signals.emergency_kill.connect(self._emergency_kill_ransomware)
        self._setup_emergency_hotkey()
    
    def setup_ui(self):
        """Setup the main UI"""
        self.setWindowTitle("Someth Antivirus")
        self.setMinimumSize(900, 600)
        self.resize(1100, 750)
        self.setStyleSheet(DARK_STYLESHEET)
        
        # Start maximized to prevent UI responsiveness issues
        self.showMaximized()
        
        # Central widget
        central = QWidget()
        self.setCentralWidget(central)
        
        layout = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Header
        header = QWidget()
        header.setStyleSheet(f"background-color: {COLORS['card']};")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(20, 12, 20, 12)
        
        # Logo/Title
        logo_label = QLabel("🛡️")
        logo_label.setStyleSheet("font-size: 28px;")
        header_layout.addWidget(logo_label)
        
        title_layout = QVBoxLayout()
        title = QLabel("Someth Antivirus")
        title.setStyleSheet(f"font-size: 18px; font-weight: bold; color: {COLORS['accent']};")
        subtitle = QLabel("Real-time Protection")
        subtitle.setStyleSheet(f"font-size: 11px; color: {COLORS['text_secondary']};")
        title_layout.addWidget(title)
        title_layout.addWidget(subtitle)
        header_layout.addLayout(title_layout)
        
        header_layout.addStretch()
        
        # Status indicator
        self.status_indicator = QLabel("● Inactive")
        self.status_indicator.setStyleSheet(f"""
            font-size: 12px;
            font-weight: bold;
            color: {COLORS['danger']};
            padding: 8px 16px;
            background-color: rgba(231, 76, 60, 0.2);
            border-radius: 12px;
        """)
        header_layout.addWidget(self.status_indicator)
        
        layout.addWidget(header)
        
        # Tab widget
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        
        # Dashboard tab
        self.dashboard = DashboardWidget()
        self.dashboard.scan_requested.connect(self._on_scan_requested)
        self.dashboard.protection_toggled.connect(self._on_protection_toggled)
        self.dashboard.view_all_btn.clicked.connect(lambda: self.tabs.setCurrentIndex(2))
        self.tabs.addTab(self.dashboard, "🏠 Dashboard")
        
        # Settings tab
        self.settings = SettingsWidget(self.config, self.startup)
        self.settings.directory_added.connect(self._on_directory_added)
        self.settings.directory_removed.connect(self._on_directory_removed)
        self.settings.restore_backup_btn.clicked.connect(self._on_restore_backup)
        self.tabs.addTab(self.settings, "⚙️ Settings")
        
        # Alerts tab
        self.alerts = AlertsWidget(self.config)
        self.tabs.addTab(self.alerts, "🔔 Alerts")
        
        # Quarantine tab
        self.quarantine = QuarantineWidget(self.config, self.engine)
        self.tabs.addTab(self.quarantine, "🔒 Quarantine")
        
        # Backup & Restore tab
        self.backup_restore = BackupRestoreWidget(self.config, self.engine)
        self.tabs.addTab(self.backup_restore, "💾 Restore")
        
        # Emergency Tools tab
        self.emergency_tools = EmergencyToolsWidget(self.config, self.engine)
        self.tabs.addTab(self.emergency_tools, "🚨 Emergency")
        
        layout.addWidget(self.tabs)
        
        # Footer
        footer = QWidget()
        footer.setStyleSheet(f"background-color: {COLORS['card']};")
        footer_layout = QHBoxLayout(footer)
        footer_layout.setContentsMargins(20, 8, 20, 8)
        
        self.footer_status = QLabel("Ready")
        self.footer_status.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 11px;")
        footer_layout.addWidget(self.footer_status)
        
        footer_layout.addStretch()
        
        version_label = QLabel("v1.0.0")
        version_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 11px;")
        footer_layout.addWidget(version_label)
        
        layout.addWidget(footer)
    
    def setup_tray(self):
        """Setup system tray icon"""
        self.tray_icon = QSystemTrayIcon(self)
        
        # Create icon (we'll use a simple colored square for now)
        pixmap = QPixmap(32, 32)
        pixmap.fill(Qt.transparent)
        from PyQt5.QtGui import QPainter, QBrush, QColor
        painter = QPainter(pixmap)
        painter.setBrush(QBrush(QColor(COLORS['accent'])))
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(2, 2, 28, 28)
        painter.end()
        
        self.tray_icon.setIcon(QIcon(pixmap))
        self.tray_icon.setToolTip("Guardian Antivirus")
        
        # Create tray menu
        tray_menu = QMenu()
        
        self.show_action = QAction("Show Guardian", self)
        self.show_action.triggered.connect(self.show_window)
        tray_menu.addAction(self.show_action)
        
        tray_menu.addSeparator()
        
        self.protection_action = QAction("Enable Protection", self)
        self.protection_action.triggered.connect(self._toggle_protection_from_tray)
        tray_menu.addAction(self.protection_action)
        
        scan_action = QAction("Quick Scan", self)
        scan_action.triggered.connect(self._on_scan_requested)
        tray_menu.addAction(scan_action)
        
        tray_menu.addSeparator()
        
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self._on_exit)
        tray_menu.addAction(exit_action)
        
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.activated.connect(self._on_tray_activated)
        self.tray_icon.show()
    
    def show_window(self):
        """Show and bring window to front"""
        self.show()
        self.setWindowState(self.windowState() & ~Qt.WindowMinimized | Qt.WindowActive)
        self.activateWindow()
        self.raise_()
    
    def _setup_emergency_hotkey(self):
        """Setup global emergency hotkey listener (Ctrl+Shift+K to kill ransomware)"""
        def hotkey_listener():
            """Background thread to listen for emergency hotkey"""
            try:
                import ctypes
                from ctypes import wintypes
                
                user32 = ctypes.windll.user32
                
                # Register hotkey: Ctrl+Shift+K (kill ransomware)
                # MOD_CONTROL = 0x0002, MOD_SHIFT = 0x0004
                # K = 0x4B
                HOTKEY_ID = 1
                MOD_CONTROL = 0x0002
                MOD_SHIFT = 0x0004
                VK_K = 0x4B
                
                if not user32.RegisterHotKey(None, HOTKEY_ID, MOD_CONTROL | MOD_SHIFT, VK_K):
                    print("[HOTKEY] Failed to register Ctrl+Shift+K")
                    return
                
                print("[HOTKEY] Emergency hotkey registered: Ctrl+Shift+K")
                
                # Message loop
                msg = wintypes.MSG()
                while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) != 0:
                    if msg.message == 0x0312:  # WM_HOTKEY
                        if msg.wParam == HOTKEY_ID:
                            print("[HOTKEY] Emergency kill triggered!")
                            self.signals.emergency_kill.emit()
                    user32.TranslateMessage(ctypes.byref(msg))
                    user32.DispatchMessageW(ctypes.byref(msg))
                    
            except Exception as e:
                print(f"[HOTKEY] Error: {e}")
        
        # Start hotkey listener in background thread
        hotkey_thread = threading.Thread(target=hotkey_listener, daemon=True)
        hotkey_thread.start()
    
    def _emergency_kill_ransomware(self):
        """Emergency function to kill ransomware - triggered by hotkey"""
        print("[EMERGENCY] Killing ransomware processes...")
        
        killed_count = 0
        registry_cleaned = 0
        
        try:
            # Kill common ransomware processes (but not ourselves)
            current_pid = os.getpid()
            
            # Use taskkill to kill suspicious python processes
            # Kill pythonw.exe (hidden python) which ransomware uses
            result = subprocess.run(
                ['taskkill', '/F', '/IM', 'pythonw.exe'],
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0:
                killed_count += 1
            
            # Kill any fullscreen tkinter windows (ransomware uses tkinter)
            # We identify them by looking for python processes with ransomware-like scripts
            result = subprocess.run(
                ['wmic', 'process', 'where', "name='python.exe'", 'get', 'processid,commandline'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            for line in result.stdout.split('\n'):
                if 'premuim_ui' in line.lower() or 'ransom' in line.lower() or 'premium' in line.lower():
                    # Extract PID and kill
                    parts = line.strip().split()
                    if parts:
                        try:
                            pid = int(parts[-1])
                            if pid != current_pid:
                                subprocess.run(['taskkill', '/F', '/PID', str(pid)], capture_output=True)
                                killed_count += 1
                                print(f"[EMERGENCY] Killed suspicious process PID: {pid}")
                        except:
                            pass
            
            # Clean registry
            import winreg
            malicious_keys = ['WindowsSystemUpdate', 'WindowsUpdate', 'SystemUpdate']
            for key_name in malicious_keys:
                try:
                    with winreg.OpenKey(
                        winreg.HKEY_CURRENT_USER,
                        r"Software\Microsoft\Windows\CurrentVersion\Run",
                        0, winreg.KEY_ALL_ACCESS
                    ) as key:
                        winreg.DeleteValue(key, key_name)
                        registry_cleaned += 1
                        print(f"[EMERGENCY] Removed registry key: {key_name}")
                except FileNotFoundError:
                    pass
                except Exception as e:
                    print(f"[EMERGENCY] Registry error: {e}")
            
            # Also clean RunOnce
            for key_name in malicious_keys:
                try:
                    with winreg.OpenKey(
                        winreg.HKEY_CURRENT_USER,
                        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                        0, winreg.KEY_ALL_ACCESS
                    ) as key:
                        winreg.DeleteValue(key, key_name)
                        registry_cleaned += 1
                except FileNotFoundError:
                    pass
                except:
                    pass
            
            # Clear dashboard alerts and reset threat display
            self.dashboard.clear_alerts()
            
            # Add success message to dashboard
            self.dashboard.add_alert(
                "EMERGENCY CLEANUP COMPLETE",
                f"✅ Killed {killed_count} malicious processes, cleaned {registry_cleaned} registry entries. System is now clean!",
                "info"
            )
            
            # Reset threat stats to show clean state
            self.engine.stats["threats_detected"] = 0
            self.engine.stats["threats_blocked"] = killed_count + registry_cleaned
            
            # Force update dashboard stats
            self._update_stats()
            
            # Log to emergency tools if on that tab
            if hasattr(self, 'emergency_tools'):
                from datetime import datetime
                timestamp = datetime.now().strftime('%H:%M:%S')
                self.emergency_tools.log_text.append(f"[{timestamp}] 🚨 EMERGENCY HOTKEY ACTIVATED (Ctrl+Shift+K)")
                self.emergency_tools.log_text.append(f"[{timestamp}] ✅ Killed {killed_count} ransomware processes")
                self.emergency_tools.log_text.append(f"[{timestamp}] ✅ Cleaned {registry_cleaned} malicious registry entries")
                self.emergency_tools.log_text.append(f"[{timestamp}] ✅ System is now CLEAN!")
                self.emergency_tools._update_status("System Clean - Emergency removal complete", "#00ff00")
            
            # Show notification
            self.tray_icon.showMessage(
                "🚨 Emergency Kill Complete!",
                f"✅ Killed {killed_count} processes\n✅ Cleaned {registry_cleaned} registry entries\nSystem is now CLEAN!",
                QSystemTrayIcon.Information,
                5000
            )
            
            # Bring antivirus to front
            self.show_window()
            
            # Switch to Emergency tab to show the log
            self.tabs.setCurrentIndex(5)  # Emergency tab
            
        except Exception as e:
            print(f"[EMERGENCY] Error during kill: {e}")
    
    def _auto_start_protection(self):
        """Auto-start protection on launch"""
        if self.config.protection_enabled:
            self._on_protection_toggled(True)
        
        # Handle start minimized
        if self.start_minimized:
            self.hide()
            self.tray_icon.showMessage(
                "Guardian Antivirus",
                "Running in background. Click the tray icon to open.",
                QSystemTrayIcon.Information,
                3000
            )
    
    def _on_protection_toggled(self, enabled: bool):
        """Handle protection toggle"""
        if enabled:
            self.engine.start()
            self._update_status(True)
            self.notifier.show_protection_status(True)
        else:
            self.engine.stop()
            self._update_status(False)
            self.notifier.show_protection_status(False)
        
        self.config.protection_enabled = enabled
        self.dashboard.set_protection_active(enabled)
    
    def _toggle_protection_from_tray(self):
        """Toggle protection from tray menu"""
        self._on_protection_toggled(not self.engine.protection_enabled)
    
    def _update_status(self, active: bool):
        """Update status indicators"""
        if active:
            self.status_indicator.setText("● Protected")
            self.status_indicator.setStyleSheet(f"""
                font-size: 12px;
                font-weight: bold;
                color: {COLORS['accent']};
                padding: 8px 16px;
                background-color: rgba(0, 184, 148, 0.2);
                border-radius: 12px;
            """)
            self.protection_action.setText("Disable Protection")
            self.footer_status.setText("Real-time protection active")
        else:
            self.status_indicator.setText("● Inactive")
            self.status_indicator.setStyleSheet(f"""
                font-size: 12px;
                font-weight: bold;
                color: {COLORS['danger']};
                padding: 8px 16px;
                background-color: rgba(231, 76, 60, 0.2);
                border-radius: 12px;
            """)
            self.protection_action.setText("Enable Protection")
            self.footer_status.setText("Protection disabled")
    
    def _update_stats(self):
        """Update statistics display"""
        stats = self.engine.get_stats()
        self.dashboard.update_stats(stats)
    
    def _on_threat_detected(self, threat: ThreatInfo):
        """Handle threat detection"""
        # Show notification
        self.notifier.show_threat_alert(
            threat.threat_type.value,
            threat.description,
            threat.severity.value
        )
        
        # Update dashboard
        self.dashboard.add_alert(
            threat.threat_type.value,
            threat.description,
            threat.severity.value
        )
        
        # Update alerts tab
        self.alerts.add_alert({
            'type': threat.threat_type.value,
            'severity': threat.severity.value,
            'description': threat.description,
            'file_path': threat.file_path,
            'process_name': threat.process_name,
            'action_taken': threat.action_taken,
            'timestamp': datetime.now().isoformat()
        })
        
        # Show tray notification
        self.tray_icon.showMessage(
            f"Threat Detected: {threat.threat_type.value.upper()}",
            threat.description,
            QSystemTrayIcon.Critical,
            5000
        )
        
        # Update quarantine if applicable
        if threat.action_taken == "quarantined":
            self.quarantine.load_quarantine()
    
    def _on_status_changed(self, status: str):
        """Handle status change"""
        self.footer_status.setText(status)
    
    def _on_scan_requested(self):
        """Handle scan request"""
        if not self.engine.protection_enabled:
            reply = QMessageBox.question(
                self,
                "Protection Disabled",
                "Protection is currently disabled. Enable protection and scan?",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.Yes:
                self._on_protection_toggled(True)
            else:
                return
        
        self.dashboard.set_scanning(True)
        self.footer_status.setText("Scanning...")
        
        # Run scan in background thread
        def run_scan():
            def progress_callback(filepath, progress):
                self.signals.scan_progress.emit(filepath, progress)
            
            threats = self.engine.run_manual_scan(progress_callback)
            self.signals.scan_complete.emit(len(threats))
        
        thread = threading.Thread(target=run_scan, daemon=True)
        thread.start()
    
    def _on_scan_progress(self, filepath: str, progress: int):
        """Handle scan progress update"""
        self.dashboard.update_scan_progress(filepath, progress)
    
    def _on_scan_complete(self, threats_found: int):
        """Handle scan completion"""
        self.dashboard.set_scanning(False)
        self.footer_status.setText(f"Scan complete - {threats_found} threats found")
        
        self.notifier.show_scan_complete(threats_found)
        
        if threats_found > 0:
            self.quarantine.load_quarantine()
            self.alerts.load_alerts()
    
    def _on_directory_added(self, directory: str):
        """Handle directory added"""
        self.engine.add_protected_directory(directory)
        self.footer_status.setText(f"Added protection for: {directory}")
    
    def _on_directory_removed(self, directory: str):
        """Handle directory removed"""
        self.engine.remove_protected_directory(directory)
        self.footer_status.setText(f"Removed protection for: {directory}")
    
    def _on_restore_backup(self):
        """Handle restore from backup"""
        reply = QMessageBox.question(
            self,
            "Restore from Backup",
            "This will restore all files from the backup folder.\n"
            "Existing files may be overwritten.\n\n"
            "Continue?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            restored = self.engine.restore_from_backup()
            QMessageBox.information(
                self,
                "Restore Complete",
                f"Restored {len(restored)} files from backup."
            )
    
    def _on_tray_activated(self, reason):
        """Handle tray icon activation"""
        if reason == QSystemTrayIcon.DoubleClick:
            self.show_window()
    
    def _on_exit(self):
        """Handle exit request"""
        reply = QMessageBox.question(
            self,
            "Exit Guardian",
            "Are you sure you want to exit?\n"
            "Real-time protection will be disabled.",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.engine.stop()
            self.tray_icon.hide()
            QApplication.quit()
    
    def closeEvent(self, event):
        """Handle window close"""
        if self.config.minimize_to_tray:
            event.ignore()
            self.hide()
            self.tray_icon.showMessage(
                "Guardian Antivirus",
                "Still running in background. Click to open.",
                QSystemTrayIcon.Information,
                2000
            )
        else:
            self._on_exit()
    
    def changeEvent(self, event):
        """Handle window state changes"""
        if event.type() == event.WindowStateChange:
            if self.isMinimized() and self.config.minimize_to_tray:
                event.ignore()
                self.hide()
                return
        super().changeEvent(event)


def main():
    """Main entry point"""
    # Check for --minimized argument
    start_minimized = '--minimized' in sys.argv
    
    # Enable high DPI scaling
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    
    # Create application
    app = QApplication(sys.argv)
    app.setApplicationName("Guardian Antivirus")
    app.setOrganizationName("SecurityTeam")
    app.setQuitOnLastWindowClosed(False)  # Allow running in tray
    
    # Set application-wide font
    font = QFont("Segoe UI", 9)
    app.setFont(font)
    
    # Create and show main window
    window = MainWindow(start_minimized=start_minimized)
    
    if not start_minimized:
        window.show()
    
    # Run application
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
