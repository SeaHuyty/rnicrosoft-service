"""
Guardian Antivirus - Quarantine Widget
Manage quarantined files
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QTableWidget, QTableWidgetItem, QHeaderView,
    QMessageBox, QAbstractItemView
)
from PyQt5.QtCore import Qt, pyqtSignal
from datetime import datetime
import os

from ..ui.styles import COLORS


class QuarantineWidget(QWidget):
    """Quarantine management widget"""
    
    restore_requested = pyqtSignal(str, str)  # quarantine_path, original_path
    delete_requested = pyqtSignal(str)  # quarantine_path
    
    def __init__(self, config_manager, protection_engine, parent=None):
        super().__init__(parent)
        self.config = config_manager
        self.engine = protection_engine
        self.setup_ui()
        self.load_quarantine()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(12)
        
        # Header
        header_layout = QHBoxLayout()
        
        title = QLabel("Quarantine")
        title.setObjectName("titleLabel")
        header_layout.addWidget(title)
        
        header_layout.addStretch()
        
        self.count_label = QLabel("0 items")
        self.count_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px;")
        header_layout.addWidget(self.count_label)
        
        layout.addLayout(header_layout)
        
        # Info card
        info_frame = QFrame()
        info_frame.setObjectName("card")
        info_layout = QHBoxLayout(info_frame)
        info_layout.setContentsMargins(12, 10, 12, 10)
        
        info_icon = QLabel("🔒")
        info_icon.setStyleSheet("font-size: 20px;")
        info_layout.addWidget(info_icon)
        
        info_text = QLabel(
            "Quarantined files are isolated and cannot harm your system. "
            "You can restore files if they were flagged incorrectly, or delete them permanently."
        )
        info_text.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 11px;")
        info_text.setWordWrap(True)
        info_layout.addWidget(info_text, 1)
        
        layout.addWidget(info_frame)
        
        # Actions bar
        actions_layout = QHBoxLayout()
        
        self.restore_btn = QPushButton("📂 Restore Selected")
        self.restore_btn.setObjectName("warningButton")
        self.restore_btn.clicked.connect(self._on_restore)
        self.restore_btn.setEnabled(False)
        actions_layout.addWidget(self.restore_btn)
        
        self.delete_btn = QPushButton("🗑️ Delete Selected")
        self.delete_btn.setObjectName("dangerButton")
        self.delete_btn.clicked.connect(self._on_delete)
        self.delete_btn.setEnabled(False)
        actions_layout.addWidget(self.delete_btn)
        
        actions_layout.addStretch()
        
        self.refresh_btn = QPushButton("🔄 Refresh")
        self.refresh_btn.clicked.connect(self.load_quarantine)
        actions_layout.addWidget(self.refresh_btn)
        
        self.clear_all_btn = QPushButton("Clear All")
        self.clear_all_btn.setObjectName("dangerButton")
        self.clear_all_btn.clicked.connect(self._on_clear_all)
        actions_layout.addWidget(self.clear_all_btn)
        
        layout.addLayout(actions_layout)
        
        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["File Name", "Original Location", "Reason", "Date"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setStyleSheet(f"""
            QTableWidget {{
                background-color: {COLORS['card']};
                border: 1px solid {COLORS['primary']};
                border-radius: 6px;
                gridline-color: {COLORS['primary']};
                font-size: 11px;
            }}
            QTableWidget::item {{
                padding: 6px;
            }}
            QTableWidget::item:selected {{
                background-color: {COLORS['primary']};
            }}
            QHeaderView::section {{
                background-color: {COLORS['background']};
                color: {COLORS['text']};
                padding: 8px;
                border: none;
                border-bottom: 1px solid {COLORS['primary']};
                font-weight: bold;
                font-size: 11px;
            }}
        """)
        self.table.itemSelectionChanged.connect(self._on_selection_changed)
        
        layout.addWidget(self.table)
        
        # Empty state
        self.empty_label = QLabel("No quarantined files")
        self.empty_label.setStyleSheet(f"""
            color: {COLORS['text_secondary']};
            font-size: 13px;
            padding: 30px;
        """)
        self.empty_label.setAlignment(Qt.AlignCenter)
        self.empty_label.setVisible(False)
        layout.addWidget(self.empty_label)
    
    def load_quarantine(self):
        """Load quarantine items"""
        self.table.setRowCount(0)
        
        items = self.config.load_quarantine_log()
        
        # Also scan quarantine directory for any files
        quarantine_dir = self.config.quarantine_directory
        if os.path.exists(quarantine_dir):
            for filename in os.listdir(quarantine_dir):
                filepath = os.path.join(quarantine_dir, filename)
                if os.path.isfile(filepath):
                    # Check if already in log
                    found = False
                    for item in items:
                        if item.get('quarantine_path') == filepath:
                            found = True
                            break
                    
                    if not found:
                        items.append({
                            'quarantine_path': filepath,
                            'original_path': 'Unknown',
                            'reason': 'Found in quarantine folder',
                            'timestamp': datetime.fromtimestamp(os.path.getmtime(filepath)).isoformat()
                        })
        
        self.count_label.setText(f"{len(items)} items")
        
        if not items:
            self.table.setVisible(False)
            self.empty_label.setVisible(True)
            return
        
        self.table.setVisible(True)
        self.empty_label.setVisible(False)
        
        for item in items:
            row = self.table.rowCount()
            self.table.insertRow(row)
            
            # File name
            quarantine_path = item.get('quarantine_path', '')
            filename = os.path.basename(quarantine_path)
            name_item = QTableWidgetItem(filename)
            name_item.setData(Qt.UserRole, item)
            self.table.setItem(row, 0, name_item)
            
            # Original location
            original = item.get('original_path', 'Unknown')
            self.table.setItem(row, 1, QTableWidgetItem(original))
            
            # Reason
            reason = item.get('reason', 'Unknown threat')
            self.table.setItem(row, 2, QTableWidgetItem(reason))
            
            # Date
            timestamp = item.get('timestamp', '')
            if timestamp:
                try:
                    dt = datetime.fromisoformat(timestamp)
                    date_str = dt.strftime("%Y-%m-%d %H:%M")
                except:
                    date_str = timestamp
            else:
                date_str = "Unknown"
            self.table.setItem(row, 3, QTableWidgetItem(date_str))
    
    def _on_selection_changed(self):
        """Handle selection change"""
        has_selection = len(self.table.selectedItems()) > 0
        self.restore_btn.setEnabled(has_selection)
        self.delete_btn.setEnabled(has_selection)
    
    def _on_restore(self):
        """Handle restore button"""
        selected_rows = set(item.row() for item in self.table.selectedItems())
        
        if not selected_rows:
            return
        
        reply = QMessageBox.warning(
            self,
            "Restore Files",
            "Warning: Restoring quarantined files may pose a security risk. "
            "Only restore files you are certain are safe.\n\n"
            "Are you sure you want to restore the selected files?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            for row in selected_rows:
                item_data = self.table.item(row, 0).data(Qt.UserRole)
                quarantine_path = item_data.get('quarantine_path')
                original_path = item_data.get('original_path')
                
                if quarantine_path and original_path != 'Unknown':
                    self.restore_requested.emit(quarantine_path, original_path)
                    self.engine.restore_from_quarantine(quarantine_path, original_path)
            
            self.load_quarantine()
    
    def _on_delete(self):
        """Handle delete button"""
        selected_rows = set(item.row() for item in self.table.selectedItems())
        
        if not selected_rows:
            return
        
        reply = QMessageBox.question(
            self,
            "Delete Files",
            f"Permanently delete {len(selected_rows)} file(s)?\n"
            "This action cannot be undone.",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            for row in selected_rows:
                item_data = self.table.item(row, 0).data(Qt.UserRole)
                quarantine_path = item_data.get('quarantine_path')
                
                if quarantine_path:
                    self.delete_requested.emit(quarantine_path)
                    self.engine.delete_quarantine_item(quarantine_path)
            
            self.load_quarantine()
    
    def _on_clear_all(self):
        """Handle clear all button"""
        if self.table.rowCount() == 0:
            return
        
        reply = QMessageBox.question(
            self,
            "Clear Quarantine",
            "Permanently delete ALL quarantined files?\n"
            "This action cannot be undone.",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            quarantine_dir = self.config.quarantine_directory
            if os.path.exists(quarantine_dir):
                for filename in os.listdir(quarantine_dir):
                    filepath = os.path.join(quarantine_dir, filename)
                    try:
                        if os.path.isfile(filepath):
                            os.remove(filepath)
                    except:
                        pass
            
            self.load_quarantine()
