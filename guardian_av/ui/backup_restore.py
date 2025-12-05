"""
Guardian Antivirus - Backup & Restore Widget
Restore files from ransomware backup
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QTableWidget, QTableWidgetItem, QHeaderView,
    QMessageBox, QAbstractItemView, QFileDialog, QLineEdit
)
from PyQt5.QtCore import Qt, pyqtSignal
from datetime import datetime
import os

from ..ui.styles import COLORS


class BackupRestoreWidget(QWidget):
    """Backup restore management widget"""
    
    def __init__(self, config_manager, protection_engine, parent=None):
        super().__init__(parent)
        self.config = config_manager
        self.engine = protection_engine
        self.setup_ui()
        self.load_backups()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(12)
        
        # Header
        header_layout = QHBoxLayout()
        
        title = QLabel("🔄 Backup & Restore")
        title.setObjectName("titleLabel")
        header_layout.addWidget(title)
        
        header_layout.addStretch()
        
        self.count_label = QLabel("0 files backed up")
        self.count_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px;")
        header_layout.addWidget(self.count_label)
        
        layout.addLayout(header_layout)
        
        # Info card
        info_frame = QFrame()
        info_frame.setObjectName("card")
        info_layout = QHBoxLayout(info_frame)
        info_layout.setContentsMargins(12, 10, 12, 10)
        
        info_icon = QLabel("💾")
        info_icon.setStyleSheet("font-size: 20px;")
        info_layout.addWidget(info_icon)
        
        info_text = QLabel(
            "Guardian AV automatically backs up files before ransomware can encrypt them. "
            "Use this panel to restore your original files after a ransomware attack."
        )
        info_text.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 11px;")
        info_text.setWordWrap(True)
        info_layout.addWidget(info_text, 1)
        
        layout.addWidget(info_frame)
        
        # Restore target selector
        target_frame = QFrame()
        target_frame.setObjectName("card")
        target_layout = QHBoxLayout(target_frame)
        target_layout.setContentsMargins(12, 10, 12, 10)
        
        target_label = QLabel("Restore to:")
        target_label.setStyleSheet(f"color: {COLORS['text']}; font-size: 11px;")
        target_layout.addWidget(target_label)
        
        self.target_input = QLineEdit()
        self.target_input.setText("D:/Hello")
        self.target_input.setStyleSheet(f"""
            QLineEdit {{
                background-color: {COLORS['background']};
                border: 1px solid {COLORS['primary']};
                border-radius: 4px;
                padding: 6px 10px;
                color: {COLORS['text']};
                font-size: 11px;
            }}
        """)
        target_layout.addWidget(self.target_input, 1)
        
        browse_btn = QPushButton("📁 Browse")
        browse_btn.clicked.connect(self._browse_target)
        target_layout.addWidget(browse_btn)
        
        layout.addWidget(target_frame)
        
        # Actions bar
        actions_layout = QHBoxLayout()
        
        self.restore_selected_btn = QPushButton("📥 Restore Selected")
        self.restore_selected_btn.setObjectName("primaryButton")
        self.restore_selected_btn.clicked.connect(self._on_restore_selected)
        self.restore_selected_btn.setEnabled(False)
        actions_layout.addWidget(self.restore_selected_btn)
        
        self.restore_all_btn = QPushButton("📥 Restore All Files")
        self.restore_all_btn.setObjectName("successButton")
        self.restore_all_btn.clicked.connect(self._on_restore_all)
        actions_layout.addWidget(self.restore_all_btn)
        
        actions_layout.addStretch()
        
        self.refresh_btn = QPushButton("🔄 Refresh")
        self.refresh_btn.clicked.connect(self.load_backups)
        actions_layout.addWidget(self.refresh_btn)
        
        self.delete_btn = QPushButton("🗑️ Delete Selected")
        self.delete_btn.setObjectName("dangerButton")
        self.delete_btn.clicked.connect(self._on_delete)
        self.delete_btn.setEnabled(False)
        actions_layout.addWidget(self.delete_btn)
        
        layout.addLayout(actions_layout)
        
        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["File Name", "Size", "Backup Path", "Modified"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.setAlternatingRowColors(True)
        self.table.setStyleSheet(f"""
            QTableWidget {{
                background-color: {COLORS['card']};
                alternate-background-color: {COLORS['background']};
                border: 1px solid {COLORS['primary']};
                border-radius: 6px;
                gridline-color: {COLORS['primary']};
                font-size: 11px;
                color: {COLORS['text']};
            }}
            QTableWidget::item {{
                padding: 6px;
                background-color: {COLORS['card']};
                color: {COLORS['text']};
            }}
            QTableWidget::item:alternate {{
                background-color: {COLORS['background']};
            }}
            QTableWidget::item:selected {{
                background-color: {COLORS['primary']};
                color: {COLORS['text']};
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
            QTableCornerButton::section {{
                background-color: {COLORS['background']};
                border: none;
            }}
        """)
        self.table.itemSelectionChanged.connect(self._on_selection_changed)
        
        layout.addWidget(self.table)
        
        # Empty state
        self.empty_label = QLabel("No backup files found")
        self.empty_label.setStyleSheet(f"""
            color: {COLORS['text_secondary']};
            font-size: 13px;
            padding: 30px;
        """)
        self.empty_label.setAlignment(Qt.AlignCenter)
        self.empty_label.setVisible(False)
        layout.addWidget(self.empty_label)
    
    def load_backups(self):
        """Load backup files"""
        self.table.setRowCount(0)
        
        backups = self.engine.get_backup_files()
        
        # Filter to show only relevant files (skip large tool folders)
        filtered_backups = []
        for backup in backups:
            # Skip files from tool directories
            path_lower = backup['path'].lower()
            if 'die_win64' in path_lower or '.sg' in backup['filename']:
                continue
            filtered_backups.append(backup)
        
        total_count = len(filtered_backups)
        
        # Limit display to prevent UI freeze (show most recent 100)
        MAX_DISPLAY = 100
        if len(filtered_backups) > MAX_DISPLAY:
            # Sort by modified time (most recent first) and take top 100
            filtered_backups.sort(key=lambda x: x.get('modified', 0), reverse=True)
            filtered_backups = filtered_backups[:MAX_DISPLAY]
            self.count_label.setText(f"Showing {MAX_DISPLAY} of {total_count} files backed up")
        else:
            self.count_label.setText(f"{total_count} files backed up")
        
        if not filtered_backups:
            self.table.setVisible(False)
            self.empty_label.setVisible(True)
            self.restore_all_btn.setEnabled(False)
            return
        
        self.table.setVisible(True)
        self.empty_label.setVisible(False)
        self.restore_all_btn.setEnabled(True)
        
        for backup in filtered_backups:
            row = self.table.rowCount()
            self.table.insertRow(row)
            
            # File name
            name_item = QTableWidgetItem(backup['filename'])
            name_item.setData(Qt.UserRole, backup)
            self.table.setItem(row, 0, name_item)
            
            # Size
            size = backup['size']
            if size < 1024:
                size_str = f"{size} B"
            elif size < 1024 * 1024:
                size_str = f"{size / 1024:.1f} KB"
            else:
                size_str = f"{size / (1024 * 1024):.1f} MB"
            self.table.setItem(row, 1, QTableWidgetItem(size_str))
            
            # Path
            self.table.setItem(row, 2, QTableWidgetItem(backup['path']))
            
            # Modified
            try:
                dt = datetime.fromtimestamp(backup['modified'])
                date_str = dt.strftime("%Y-%m-%d %H:%M")
            except:
                date_str = "Unknown"
            self.table.setItem(row, 3, QTableWidgetItem(date_str))
    
    def _browse_target(self):
        """Browse for target directory"""
        directory = QFileDialog.getExistingDirectory(
            self, "Select Restore Location", self.target_input.text()
        )
        if directory:
            self.target_input.setText(directory)
    
    def _on_selection_changed(self):
        """Handle selection change"""
        has_selection = len(self.table.selectedItems()) > 0
        self.restore_selected_btn.setEnabled(has_selection)
        self.delete_btn.setEnabled(has_selection)
    
    def _on_restore_selected(self):
        """Restore selected files"""
        selected_rows = set(item.row() for item in self.table.selectedItems())
        
        if not selected_rows:
            return
        
        target_dir = self.target_input.text()
        if not target_dir:
            QMessageBox.warning(self, "Error", "Please specify a restore location.")
            return
        
        reply = QMessageBox.question(
            self,
            "Restore Files",
            f"Restore {len(selected_rows)} file(s) to:\n{target_dir}\n\n"
            "Existing files with the same name will be overwritten.",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            restored = 0
            for row in selected_rows:
                item_data = self.table.item(row, 0).data(Qt.UserRole)
                backup_path = item_data.get('path')
                filename = item_data.get('filename')
                
                if backup_path:
                    target_path = os.path.join(target_dir, filename)
                    if self.engine.restore_single_backup(backup_path, target_path):
                        restored += 1
            
            QMessageBox.information(
                self,
                "Restore Complete",
                f"Successfully restored {restored} file(s) to:\n{target_dir}"
            )
    
    def _on_restore_all(self):
        """Restore all backup files"""
        target_dir = self.target_input.text()
        if not target_dir:
            QMessageBox.warning(self, "Error", "Please specify a restore location.")
            return
        
        reply = QMessageBox.question(
            self,
            "Restore All Files",
            f"Restore ALL backed up files to:\n{target_dir}\n\n"
            "This will restore all your original files before they were encrypted.\n"
            "Existing files with the same name will be overwritten.",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            restored = 0
            backups = self.engine.get_backup_files()
            
            for backup in backups:
                # Skip tool files
                path_lower = backup['path'].lower()
                if 'die_win64' in path_lower or '.sg' in backup['filename']:
                    continue
                
                target_path = os.path.join(target_dir, backup['filename'])
                if self.engine.restore_single_backup(backup['path'], target_path):
                    restored += 1
            
            QMessageBox.information(
                self,
                "Restore Complete",
                f"Successfully restored {restored} file(s) to:\n{target_dir}"
            )
    
    def _on_delete(self):
        """Delete selected backup files"""
        selected_rows = set(item.row() for item in self.table.selectedItems())
        
        if not selected_rows:
            return
        
        reply = QMessageBox.question(
            self,
            "Delete Backups",
            f"Permanently delete {len(selected_rows)} backup file(s)?\n"
            "You will not be able to restore these files later.",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            for row in selected_rows:
                item_data = self.table.item(row, 0).data(Qt.UserRole)
                backup_path = item_data.get('path')
                
                if backup_path:
                    try:
                        os.remove(backup_path)
                    except:
                        pass
            
            self.load_backups()
