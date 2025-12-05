"""
Guardian Antivirus - Dashboard Widget
Main dashboard showing protection status and statistics
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QGridLayout, QProgressBar, QSpacerItem, QSizePolicy
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QFont

from ..ui.styles import COLORS


class StatCard(QFrame):
    """A card widget displaying a statistic"""
    
    def __init__(self, title: str, value: str = "0", icon: str = "", parent=None):
        super().__init__(parent)
        self.setObjectName("card")
        self.setMinimumSize(140, 90)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 12, 15, 12)
        
        # Value label
        self.value_label = QLabel(value)
        self.value_label.setObjectName("statValue")
        self.value_label.setAlignment(Qt.AlignCenter)
        
        # Title label
        self.title_label = QLabel(title)
        self.title_label.setObjectName("statLabel")
        self.title_label.setAlignment(Qt.AlignCenter)
        
        layout.addWidget(self.value_label)
        layout.addWidget(self.title_label)
    
    def set_value(self, value: str):
        self.value_label.setText(value)
    
    def set_color(self, color: str):
        self.value_label.setStyleSheet(f"color: {color}; font-size: 28px; font-weight: bold;")


class ProtectionStatusWidget(QFrame):
    """Widget showing protection status with toggle"""
    
    protection_toggled = pyqtSignal(bool)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("card")
        self._is_active = False
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)
        
        # Shield icon/status
        self.status_icon = QLabel("🛡️")
        self.status_icon.setStyleSheet("font-size: 48px;")
        self.status_icon.setAlignment(Qt.AlignCenter)
        
        # Status text
        self.status_text = QLabel("Protection Inactive")
        self.status_text.setStyleSheet(f"""
            font-size: 16px;
            font-weight: bold;
            color: {COLORS['danger']};
        """)
        self.status_text.setAlignment(Qt.AlignCenter)
        
        # Description
        self.description = QLabel("Click to enable real-time protection")
        self.description.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 11px;")
        self.description.setAlignment(Qt.AlignCenter)
        self.description.setWordWrap(True)
        
        # Toggle button
        self.toggle_btn = QPushButton("Enable Protection")
        self.toggle_btn.setObjectName("primaryButton")
        self.toggle_btn.setMinimumHeight(36)
        self.toggle_btn.clicked.connect(self._on_toggle)
        
        layout.addWidget(self.status_icon)
        layout.addWidget(self.status_text)
        layout.addWidget(self.description)
        layout.addSpacing(10)
        layout.addWidget(self.toggle_btn)
    
    def _on_toggle(self):
        self.protection_toggled.emit(not self._is_active)
    
    def set_active(self, active: bool):
        self._is_active = active
        if active:
            self.status_icon.setText("🛡️")
            self.status_icon.setStyleSheet(f"font-size: 48px;")
            self.status_text.setText("Protection Active")
            self.status_text.setStyleSheet(f"""
                font-size: 16px;
                font-weight: bold;
                color: {COLORS['accent']};
            """)
            self.description.setText("Your system is protected in real-time")
            self.toggle_btn.setText("Disable Protection")
            self.toggle_btn.setObjectName("dangerButton")
            self.toggle_btn.setStyle(self.toggle_btn.style())
        else:
            self.status_icon.setText("🛡️")
            self.status_icon.setStyleSheet(f"font-size: 48px; opacity: 0.5;")
            self.status_text.setText("Protection Inactive")
            self.status_text.setStyleSheet(f"""
                font-size: 16px;
                font-weight: bold;
                color: {COLORS['danger']};
            """)
            self.description.setText("Click to enable real-time protection")
            self.toggle_btn.setText("Enable Protection")
            self.toggle_btn.setObjectName("primaryButton")
            self.toggle_btn.setStyle(self.toggle_btn.style())


class DashboardWidget(QWidget):
    """Main dashboard widget"""
    
    scan_requested = pyqtSignal()
    protection_toggled = pyqtSignal(bool)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(15)
        
        # Title
        title = QLabel("Dashboard")
        title.setObjectName("titleLabel")
        layout.addWidget(title)
        
        # Main content area
        content_layout = QHBoxLayout()
        content_layout.setSpacing(15)
        
        # Left side - Protection status
        self.protection_status = ProtectionStatusWidget()
        self.protection_status.protection_toggled.connect(self.protection_toggled.emit)
        self.protection_status.setFixedWidth(250)
        content_layout.addWidget(self.protection_status)
        
        # Right side - Stats and actions
        right_layout = QVBoxLayout()
        right_layout.setSpacing(12)
        
        # Stats grid
        stats_layout = QGridLayout()
        stats_layout.setSpacing(10)
        
        self.threats_card = StatCard("Threats Detected", "0")
        self.threats_card.set_color(COLORS['danger'])
        
        self.files_card = StatCard("Files Scanned", "0")
        self.files_card.set_color(COLORS['accent'])
        
        self.dirs_card = StatCard("Protected Folders", "0")
        self.dirs_card.set_color(COLORS['info'])
        
        self.scans_card = StatCard("Processes Scanned", "0")
        self.scans_card.set_color(COLORS['warning'])
        
        stats_layout.addWidget(self.threats_card, 0, 0)
        stats_layout.addWidget(self.files_card, 0, 1)
        stats_layout.addWidget(self.dirs_card, 1, 0)
        stats_layout.addWidget(self.scans_card, 1, 1)
        
        right_layout.addLayout(stats_layout)
        
        # Scan button
        scan_frame = QFrame()
        scan_frame.setObjectName("card")
        scan_layout = QVBoxLayout(scan_frame)
        scan_layout.setContentsMargins(12, 12, 12, 12)
        scan_layout.setSpacing(8)
        
        scan_label = QLabel("Manual Scan")
        scan_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        
        scan_desc = QLabel("Scan all protected directories for threats")
        scan_desc.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 11px;")
        
        self.scan_btn = QPushButton("🔍  Scan Now")
        self.scan_btn.setObjectName("primaryButton")
        self.scan_btn.setMinimumHeight(36)
        self.scan_btn.clicked.connect(self.scan_requested.emit)
        
        self.scan_progress = QProgressBar()
        self.scan_progress.setVisible(False)
        self.scan_progress.setTextVisible(True)
        
        self.scan_status = QLabel("")
        self.scan_status.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 10px;")
        self.scan_status.setVisible(False)
        
        scan_layout.addWidget(scan_label)
        scan_layout.addWidget(scan_desc)
        scan_layout.addWidget(self.scan_btn)
        scan_layout.addWidget(self.scan_progress)
        scan_layout.addWidget(self.scan_status)
        
        right_layout.addWidget(scan_frame)
        right_layout.addStretch()
        
        content_layout.addLayout(right_layout)
        layout.addLayout(content_layout)
        
        # Recent alerts section
        alerts_frame = QFrame()
        alerts_frame.setObjectName("card")
        alerts_layout = QVBoxLayout(alerts_frame)
        alerts_layout.setContentsMargins(12, 12, 12, 12)
        alerts_layout.setSpacing(8)
        
        alerts_header = QHBoxLayout()
        alerts_title = QLabel("Recent Alerts")
        alerts_title.setStyleSheet("font-size: 14px; font-weight: bold;")
        alerts_header.addWidget(alerts_title)
        alerts_header.addStretch()
        
        self.view_all_btn = QPushButton("View All")
        self.view_all_btn.setMaximumWidth(80)
        alerts_header.addWidget(self.view_all_btn)
        
        alerts_layout.addLayout(alerts_header)
        
        self.alerts_container = QVBoxLayout()
        self.no_alerts_label = QLabel("No recent alerts")
        self.no_alerts_label.setStyleSheet(f"color: {COLORS['text_secondary']}; padding: 20px; font-size: 12px;")
        self.no_alerts_label.setAlignment(Qt.AlignCenter)
        self.alerts_container.addWidget(self.no_alerts_label)
        
        alerts_layout.addLayout(self.alerts_container)
        layout.addWidget(alerts_frame)
    
    def update_stats(self, stats: dict):
        """Update statistics display"""
        self.threats_card.set_value(str(stats.get('threats_detected', 0)))
        self.files_card.set_value(str(stats.get('files_scanned', 0)))
        self.dirs_card.set_value(str(stats.get('protected_directories', 0)))
        self.scans_card.set_value(str(stats.get('processes_scanned', 0)))
    
    def set_protection_active(self, active: bool):
        """Set protection status display"""
        self.protection_status.set_active(active)
    
    def set_scanning(self, scanning: bool):
        """Set scanning state"""
        self.scan_btn.setEnabled(not scanning)
        self.scan_progress.setVisible(scanning)
        self.scan_status.setVisible(scanning)
        if scanning:
            self.scan_btn.setText("Scanning...")
        else:
            self.scan_btn.setText("🔍  Scan Now")
    
    def update_scan_progress(self, filepath: str, progress: int):
        """Update scan progress"""
        self.scan_progress.setValue(progress)
        # Show truncated filename
        filename = filepath.split('\\')[-1] if '\\' in filepath else filepath.split('/')[-1]
        if len(filename) > 40:
            filename = filename[:37] + "..."
        self.scan_status.setText(f"Scanning: {filename}")
    
    def add_alert(self, alert_type: str, description: str, severity: str = "high"):
        """Add an alert to the recent alerts"""
        # Remove "no alerts" label if present
        if self.no_alerts_label.isVisible():
            self.no_alerts_label.setVisible(False)
        
        # Create alert frame
        alert_frame = QFrame()
        if severity == "critical":
            alert_frame.setObjectName("alertCard")
            icon = "🚨"
        elif severity == "high":
            alert_frame.setObjectName("alertCard")
            icon = "⚠️"
        else:
            alert_frame.setObjectName("alertCardInfo")
            icon = "ℹ️"
        
        alert_layout = QHBoxLayout(alert_frame)
        alert_layout.setContentsMargins(10, 8, 10, 8)
        
        icon_label = QLabel(icon)
        icon_label.setStyleSheet("font-size: 18px;")
        
        text_layout = QVBoxLayout()
        type_label = QLabel(alert_type.upper())
        type_label.setStyleSheet("font-weight: bold; font-size: 11px;")
        desc_label = QLabel(description)
        desc_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 10px;")
        desc_label.setWordWrap(True)
        text_layout.addWidget(type_label)
        text_layout.addWidget(desc_label)
        
        alert_layout.addWidget(icon_label)
        alert_layout.addLayout(text_layout, 1)
        
        # Add to top of alerts
        self.alerts_container.insertWidget(0, alert_frame)
        
        # Keep only last 5 alerts visible
        while self.alerts_container.count() > 6:  # +1 for no_alerts_label
            item = self.alerts_container.takeAt(self.alerts_container.count() - 1)
            if item.widget() and item.widget() != self.no_alerts_label:
                item.widget().deleteLater()
    
    def clear_alerts(self):
        """Clear all alerts"""
        while self.alerts_container.count() > 1:
            item = self.alerts_container.takeAt(1)
            if item.widget():
                item.widget().deleteLater()
        self.no_alerts_label.setVisible(True)
