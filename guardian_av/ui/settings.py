"""
Someth Antivirus - Settings Widget
Settings panel for configuration options
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QCheckBox, QGroupBox, QListWidget, QListWidgetItem,
    QFileDialog, QMessageBox, QScrollArea
)
from PyQt5.QtCore import Qt, pyqtSignal

from ..ui.styles import COLORS


class SettingsWidget(QWidget):
    """Settings panel widget"""
    
    settings_changed = pyqtSignal()
    directory_added = pyqtSignal(str)
    directory_removed = pyqtSignal(str)
    startup_changed = pyqtSignal(bool)
    
    def __init__(self, config_manager, startup_manager, parent=None):
        super().__init__(parent)
        self.config = config_manager
        self.startup = startup_manager
        self.setup_ui()
        self.load_settings()
    
    def setup_ui(self):
        # Main scroll area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        
        scroll_content = QWidget()
        layout = QVBoxLayout(scroll_content)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(15)
        
        # Title
        title = QLabel("Settings")
        title.setObjectName("titleLabel")
        layout.addWidget(title)
        
        # Protected Directories Section
        dirs_group = QGroupBox("Protected Directories")
        dirs_layout = QVBoxLayout(dirs_group)
        dirs_layout.setSpacing(8)
        
        dirs_desc = QLabel("Guardian will monitor these directories for threats")
        dirs_desc.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 11px;")
        dirs_layout.addWidget(dirs_desc)
        
        self.dirs_list = QListWidget()
        self.dirs_list.setMinimumHeight(120)
        self.dirs_list.setSelectionMode(QListWidget.SingleSelection)
        dirs_layout.addWidget(self.dirs_list)
        
        dirs_btn_layout = QHBoxLayout()
        
        self.add_dir_btn = QPushButton("➕ Add Directory")
        self.add_dir_btn.clicked.connect(self._on_add_directory)
        
        self.remove_dir_btn = QPushButton("➖ Remove Selected")
        self.remove_dir_btn.setObjectName("dangerButton")
        self.remove_dir_btn.clicked.connect(self._on_remove_directory)
        
        dirs_btn_layout.addWidget(self.add_dir_btn)
        dirs_btn_layout.addWidget(self.remove_dir_btn)
        dirs_btn_layout.addStretch()
        
        dirs_layout.addLayout(dirs_btn_layout)
        layout.addWidget(dirs_group)
        
        # Startup & System Section
        startup_group = QGroupBox("Startup & System")
        startup_layout = QVBoxLayout(startup_group)
        startup_layout.setSpacing(8)
        
        self.auto_start_cb = QCheckBox("Start Guardian with Windows")
        self.auto_start_cb.stateChanged.connect(self._on_auto_start_changed)
        startup_layout.addWidget(self.auto_start_cb)
        
        self.start_minimized_cb = QCheckBox("Start minimized to system tray")
        self.start_minimized_cb.stateChanged.connect(self._on_setting_changed)
        startup_layout.addWidget(self.start_minimized_cb)
        
        self.minimize_to_tray_cb = QCheckBox("Minimize to system tray instead of taskbar")
        self.minimize_to_tray_cb.stateChanged.connect(self._on_setting_changed)
        startup_layout.addWidget(self.minimize_to_tray_cb)
        
        layout.addWidget(startup_group)
        
        # Notifications Section
        notif_group = QGroupBox("Notifications")
        notif_layout = QVBoxLayout(notif_group)
        notif_layout.setSpacing(8)
        
        self.notif_enabled_cb = QCheckBox("Enable Windows notifications")
        self.notif_enabled_cb.stateChanged.connect(self._on_setting_changed)
        notif_layout.addWidget(self.notif_enabled_cb)
        
        self.notif_sound_cb = QCheckBox("Play sound on threat detection")
        self.notif_sound_cb.stateChanged.connect(self._on_setting_changed)
        notif_layout.addWidget(self.notif_sound_cb)
        
        layout.addWidget(notif_group)
        
        # Protection Settings Section
        protection_group = QGroupBox("Protection Modules")
        protection_layout = QVBoxLayout(protection_group)
        protection_layout.setSpacing(8)
        
        self.ransomware_cb = QCheckBox("Ransomware Detection")
        self.ransomware_cb.setChecked(True)
        self.ransomware_cb.stateChanged.connect(self._on_setting_changed)
        protection_layout.addWidget(self.ransomware_cb)
        
        self.worm_cb = QCheckBox("Worm & USB Monitoring")
        self.worm_cb.setChecked(True)
        self.worm_cb.stateChanged.connect(self._on_setting_changed)
        protection_layout.addWidget(self.worm_cb)
        
        self.spyware_cb = QCheckBox("Spyware Detection")
        self.spyware_cb.setChecked(True)
        self.spyware_cb.stateChanged.connect(self._on_setting_changed)
        protection_layout.addWidget(self.spyware_cb)
        
        self.autorun_cb = QCheckBox("Autorun Blocking")
        self.autorun_cb.setChecked(True)
        self.autorun_cb.stateChanged.connect(self._on_setting_changed)
        protection_layout.addWidget(self.autorun_cb)
        
        layout.addWidget(protection_group)
        
        # Backup & Quarantine Section
        backup_group = QGroupBox("Backup & Quarantine")
        backup_layout = QVBoxLayout(backup_group)
        backup_layout.setSpacing(8)
        
        backup_info = QLabel(f"Backup Location: {self.config.backup_directory}")
        backup_info.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 11px;")
        backup_layout.addWidget(backup_info)
        
        quarantine_info = QLabel(f"Quarantine Location: {self.config.quarantine_directory}")
        quarantine_info.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 11px;")
        backup_layout.addWidget(quarantine_info)
        
        backup_btn_layout = QHBoxLayout()
        
        self.restore_backup_btn = QPushButton("Restore All from Backup")
        self.restore_backup_btn.setObjectName("warningButton")
        backup_btn_layout.addWidget(self.restore_backup_btn)
        
        self.clear_quarantine_btn = QPushButton("Clear Quarantine")
        self.clear_quarantine_btn.setObjectName("dangerButton")
        backup_btn_layout.addWidget(self.clear_quarantine_btn)
        
        backup_btn_layout.addStretch()
        backup_layout.addLayout(backup_btn_layout)
        
        layout.addWidget(backup_group)
        
        # About Section
        about_group = QGroupBox("About")
        about_layout = QVBoxLayout(about_group)
        
        about_text = QLabel("""
Someth Antivirus v1.0.0

A professional real-time protection solution featuring:
• Real-time file system monitoring
• Ransomware detection and recovery
• Worm and USB threat protection
• Spyware and keylogger detection
• Automatic backup and restore
• Windows startup integration

© 2024 Security Team
        """)
        about_text.setStyleSheet(f"color: {COLORS['text_secondary']};")
        about_layout.addWidget(about_text)
        
        layout.addWidget(about_group)
        
        layout.addStretch()
        
        scroll.setWidget(scroll_content)
        
        # Add scroll area to main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.addWidget(scroll)
    
    def load_settings(self):
        """Load settings from config"""
        # Load directories
        self.dirs_list.clear()
        for directory in self.config.protected_directories:
            item = QListWidgetItem(f"📁 {directory}")
            item.setData(Qt.UserRole, directory)
            self.dirs_list.addItem(item)
        
        # Load startup settings
        self.auto_start_cb.setChecked(self.startup.is_enabled())
        self.start_minimized_cb.setChecked(self.config.start_minimized)
        self.minimize_to_tray_cb.setChecked(self.config.minimize_to_tray)
        
        # Load notification settings
        self.notif_enabled_cb.setChecked(self.config.notifications_enabled)
        self.notif_sound_cb.setChecked(self.config.config["notifications"]["sound"])
        
        # Load protection settings
        scanning = self.config.get_scanning_config()
        self.ransomware_cb.setChecked(scanning.get("ransomware_detection", True))
        self.worm_cb.setChecked(scanning.get("worm_detection", True))
        self.spyware_cb.setChecked(scanning.get("spyware_detection", True))
        self.autorun_cb.setChecked(scanning.get("autorun_blocking", True))
    
    def _on_add_directory(self):
        """Handle add directory button"""
        directory = QFileDialog.getExistingDirectory(
            self,
            "Select Directory to Protect",
            "",
            QFileDialog.ShowDirsOnly
        )
        
        if directory:
            # Check if already in list
            for i in range(self.dirs_list.count()):
                if self.dirs_list.item(i).data(Qt.UserRole) == directory:
                    QMessageBox.information(
                        self,
                        "Directory Exists",
                        "This directory is already in the protection list."
                    )
                    return
            
            # Add to list
            item = QListWidgetItem(f"📁 {directory}")
            item.setData(Qt.UserRole, directory)
            self.dirs_list.addItem(item)
            
            self.directory_added.emit(directory)
    
    def _on_remove_directory(self):
        """Handle remove directory button"""
        current_item = self.dirs_list.currentItem()
        if current_item:
            directory = current_item.data(Qt.UserRole)
            reply = QMessageBox.question(
                self,
                "Remove Directory",
                f"Remove '{directory}' from protection?",
                QMessageBox.Yes | QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                self.dirs_list.takeItem(self.dirs_list.row(current_item))
                self.directory_removed.emit(directory)
    
    def _on_auto_start_changed(self, state):
        """Handle auto-start checkbox change"""
        enabled = state == Qt.Checked
        self.startup.toggle(enabled, self.start_minimized_cb.isChecked())
        self.config.auto_start = enabled
        self.startup_changed.emit(enabled)
    
    def _on_setting_changed(self, state):
        """Handle generic setting change"""
        # Update config
        self.config.start_minimized = self.start_minimized_cb.isChecked()
        self.config.minimize_to_tray = self.minimize_to_tray_cb.isChecked()
        self.config.notifications_enabled = self.notif_enabled_cb.isChecked()
        self.config.config["notifications"]["sound"] = self.notif_sound_cb.isChecked()
        
        # Update scanning config
        self.config.config["scanning"]["ransomware_detection"] = self.ransomware_cb.isChecked()
        self.config.config["scanning"]["worm_detection"] = self.worm_cb.isChecked()
        self.config.config["scanning"]["spyware_detection"] = self.spyware_cb.isChecked()
        self.config.config["scanning"]["autorun_blocking"] = self.autorun_cb.isChecked()
        
        self.config.save()
        self.settings_changed.emit()
