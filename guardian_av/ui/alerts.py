"""
Guardian Antivirus - Alerts Widget
Display and manage threat alerts history
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QScrollArea, QListWidget, QListWidgetItem,
    QMessageBox, QMenu
)
from PyQt5.QtCore import Qt, pyqtSignal
from datetime import datetime

from ..ui.styles import COLORS


class AlertItemWidget(QFrame):
    """Custom widget for displaying an alert item"""
    
    def __init__(self, alert_data: dict, parent=None):
        super().__init__(parent)
        self.alert_data = alert_data
        self.setup_ui()
    
    def setup_ui(self):
        severity = self.alert_data.get('severity', 'medium')
        
        if severity == 'critical':
            self.setObjectName("alertCard")
            icon = "🚨"
            color = COLORS['danger']
        elif severity == 'high':
            self.setObjectName("alertCard")
            icon = "⚠️"
            color = COLORS['warning']
        else:
            self.setObjectName("alertCardInfo")
            icon = "ℹ️"
            color = COLORS['info']
        
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        
        # Icon
        icon_label = QLabel(icon)
        icon_label.setStyleSheet("font-size: 18px;")
        icon_label.setFixedWidth(30)
        layout.addWidget(icon_label)
        
        # Content
        content_layout = QVBoxLayout()
        content_layout.setSpacing(3)
        
        # Header row
        header_layout = QHBoxLayout()
        
        type_label = QLabel(self.alert_data.get('type', 'Unknown').upper())
        type_label.setStyleSheet(f"font-weight: bold; color: {color}; font-size: 11px;")
        header_layout.addWidget(type_label)
        
        header_layout.addStretch()
        
        # Timestamp
        timestamp = self.alert_data.get('timestamp', '')
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp)
                time_str = dt.strftime("%Y-%m-%d %H:%M:%S")
            except:
                time_str = timestamp
        else:
            time_str = "Unknown time"
        
        time_label = QLabel(time_str)
        time_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 10px;")
        header_layout.addWidget(time_label)
        
        content_layout.addLayout(header_layout)
        
        # Description
        desc_label = QLabel(self.alert_data.get('description', 'No description'))
        desc_label.setStyleSheet(f"color: {COLORS['text']}; font-size: 11px;")
        desc_label.setWordWrap(True)
        content_layout.addWidget(desc_label)
        
        # Details row
        details = []
        if self.alert_data.get('file_path'):
            details.append(f"File: {self.alert_data['file_path']}")
        if self.alert_data.get('process_name'):
            details.append(f"Process: {self.alert_data['process_name']}")
        if self.alert_data.get('action_taken'):
            details.append(f"Action: {self.alert_data['action_taken']}")
        
        if details:
            details_label = QLabel(" | ".join(details))
            details_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 10px;")
            details_label.setWordWrap(True)
            content_layout.addWidget(details_label)
        
        layout.addLayout(content_layout, 1)


class AlertsWidget(QWidget):
    """Alerts history widget"""
    
    clear_alerts = pyqtSignal()
    
    def __init__(self, config_manager, parent=None):
        super().__init__(parent)
        self.config = config_manager
        self.setup_ui()
        self.load_alerts()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(12)
        
        # Header
        header_layout = QHBoxLayout()
        
        title = QLabel("Threat History")
        title.setObjectName("titleLabel")
        header_layout.addWidget(title)
        
        header_layout.addStretch()
        
        # Stats
        self.total_label = QLabel("Total: 0")
        self.total_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px;")
        header_layout.addWidget(self.total_label)
        
        # Clear button
        self.clear_btn = QPushButton("Clear All")
        self.clear_btn.setObjectName("dangerButton")
        self.clear_btn.setMaximumWidth(80)
        self.clear_btn.clicked.connect(self._on_clear)
        header_layout.addWidget(self.clear_btn)
        
        layout.addLayout(header_layout)
        
        # Filter buttons
        filter_layout = QHBoxLayout()
        filter_layout.setSpacing(8)
        
        self.filter_all_btn = QPushButton("All")
        self.filter_all_btn.setCheckable(True)
        self.filter_all_btn.setChecked(True)
        self.filter_all_btn.clicked.connect(lambda: self._filter_alerts(None))
        filter_layout.addWidget(self.filter_all_btn)
        
        self.filter_critical_btn = QPushButton("🚨 Critical")
        self.filter_critical_btn.setCheckable(True)
        self.filter_critical_btn.clicked.connect(lambda: self._filter_alerts('critical'))
        filter_layout.addWidget(self.filter_critical_btn)
        
        self.filter_high_btn = QPushButton("⚠️ High")
        self.filter_high_btn.setCheckable(True)
        self.filter_high_btn.clicked.connect(lambda: self._filter_alerts('high'))
        filter_layout.addWidget(self.filter_high_btn)
        
        filter_layout.addStretch()
        
        self.refresh_btn = QPushButton("🔄 Refresh")
        self.refresh_btn.clicked.connect(self.load_alerts)
        filter_layout.addWidget(self.refresh_btn)
        
        layout.addLayout(filter_layout)
        
        # Alerts list
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setFrameShape(QFrame.NoFrame)
        
        self.alerts_container = QWidget()
        self.alerts_layout = QVBoxLayout(self.alerts_container)
        self.alerts_layout.setContentsMargins(0, 0, 0, 0)
        self.alerts_layout.setSpacing(6)
        
        self.no_alerts_label = QLabel("No alerts to display")
        self.no_alerts_label.setStyleSheet(f"""
            color: {COLORS['text_secondary']};
            font-size: 13px;
            padding: 30px;
        """)
        self.no_alerts_label.setAlignment(Qt.AlignCenter)
        self.alerts_layout.addWidget(self.no_alerts_label)
        self.alerts_layout.addStretch()
        
        self.scroll_area.setWidget(self.alerts_container)
        layout.addWidget(self.scroll_area)
        
        self.current_filter = None
    
    def load_alerts(self):
        """Load alerts from config"""
        self._clear_display()
        
        alerts = self.config.load_alerts()
        
        # Filter if needed
        if self.current_filter:
            alerts = [a for a in alerts if a.get('severity') == self.current_filter]
        
        # Sort by timestamp (newest first)
        alerts.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        self.total_label.setText(f"Total: {len(alerts)}")
        
        if not alerts:
            self.no_alerts_label.setVisible(True)
            return
        
        self.no_alerts_label.setVisible(False)
        
        for alert in alerts[:100]:  # Show last 100
            alert_widget = AlertItemWidget(alert)
            self.alerts_layout.insertWidget(self.alerts_layout.count() - 1, alert_widget)
    
    def _clear_display(self):
        """Clear the alerts display"""
        while self.alerts_layout.count() > 2:  # Keep no_alerts_label and stretch
            item = self.alerts_layout.takeAt(0)
            if item.widget() and item.widget() != self.no_alerts_label:
                item.widget().deleteLater()
    
    def _filter_alerts(self, severity: str):
        """Filter alerts by severity"""
        self.current_filter = severity
        
        # Update button states
        self.filter_all_btn.setChecked(severity is None)
        self.filter_critical_btn.setChecked(severity == 'critical')
        self.filter_high_btn.setChecked(severity == 'high')
        
        self.load_alerts()
    
    def _on_clear(self):
        """Handle clear all button"""
        reply = QMessageBox.question(
            self,
            "Clear Alert History",
            "Are you sure you want to clear all alert history?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.config.clear_alerts()
            self.load_alerts()
            self.clear_alerts.emit()
    
    def add_alert(self, alert_data: dict):
        """Add a new alert to the display"""
        self.no_alerts_label.setVisible(False)
        
        alert_widget = AlertItemWidget(alert_data)
        self.alerts_layout.insertWidget(0, alert_widget)
        
        # Update total
        total = int(self.total_label.text().replace("Total: ", "")) + 1
        self.total_label.setText(f"Total: {total}")
