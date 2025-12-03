"""
Guardian Antivirus - Modern PyQt5 Stylesheet
Dark theme with professional appearance
"""

DARK_STYLESHEET = """
/* Main Window */
QMainWindow {
    background-color: #1a1a2e;
}

QWidget {
    background-color: #1a1a2e;
    color: #eaeaea;
    font-family: 'Segoe UI', Arial, sans-serif;
    font-size: 12px;
}

/* Buttons */
QPushButton {
    background-color: #0f3460;
    color: #eaeaea;
    border: none;
    border-radius: 6px;
    padding: 8px 16px;
    font-weight: bold;
    font-size: 12px;
    min-width: 80px;
    min-height: 32px;
}

QPushButton:hover {
    background-color: #16537e;
}

QPushButton:pressed {
    background-color: #0a2540;
}

QPushButton:disabled {
    background-color: #2a2a4a;
    color: #666;
}

QPushButton#primaryButton {
    background-color: #00b894;
    color: white;
}

QPushButton#primaryButton:hover {
    background-color: #00d9a7;
}

QPushButton#dangerButton {
    background-color: #e74c3c;
    color: white;
}

QPushButton#dangerButton:hover {
    background-color: #ff5e4d;
}

QPushButton#warningButton {
    background-color: #f39c12;
    color: white;
}

QPushButton#warningButton:hover {
    background-color: #ffb732;
}

/* Labels */
QLabel {
    color: #eaeaea;
    background: transparent;
}

QLabel#titleLabel {
    font-size: 20px;
    font-weight: bold;
    color: #00b894;
}

QLabel#subtitleLabel {
    font-size: 12px;
    color: #a0a0a0;
}

QLabel#statusLabel {
    font-size: 13px;
    font-weight: bold;
    padding: 10px;
    border-radius: 6px;
}

QLabel#statusLabelActive {
    background-color: rgba(0, 184, 148, 0.2);
    color: #00b894;
    border: 1px solid #00b894;
}

QLabel#statusLabelInactive {
    background-color: rgba(231, 76, 60, 0.2);
    color: #e74c3c;
    border: 1px solid #e74c3c;
}

QLabel#statValue {
    font-size: 28px;
    font-weight: bold;
    color: #00b894;
}

QLabel#statLabel {
    font-size: 11px;
    color: #a0a0a0;
}

/* Cards/Frames */
QFrame#card {
    background-color: #16213e;
    border-radius: 10px;
    padding: 15px;
}

QFrame#alertCard {
    background-color: #16213e;
    border-radius: 8px;
    border-left: 4px solid #e74c3c;
    padding: 10px;
    margin: 5px 0;
}

QFrame#alertCardWarning {
    background-color: #16213e;
    border-radius: 8px;
    border-left: 4px solid #f39c12;
    padding: 10px;
    margin: 5px 0;
}

QFrame#alertCardInfo {
    background-color: #16213e;
    border-radius: 8px;
    border-left: 4px solid #3498db;
    padding: 10px;
    margin: 5px 0;
}

/* Scroll Areas */
QScrollArea {
    border: none;
    background: transparent;
}

QScrollArea > QWidget > QWidget {
    background: transparent;
}

QScrollBar:vertical {
    background-color: #1a1a2e;
    width: 10px;
    border-radius: 5px;
}

QScrollBar::handle:vertical {
    background-color: #0f3460;
    border-radius: 5px;
    min-height: 30px;
}

QScrollBar::handle:vertical:hover {
    background-color: #16537e;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

/* List Widget */
QListWidget {
    background-color: #16213e;
    border: 1px solid #0f3460;
    border-radius: 6px;
    padding: 5px;
    outline: none;
    font-size: 12px;
}

QListWidget::item {
    background-color: #1a1a2e;
    border-radius: 4px;
    padding: 8px;
    margin: 2px;
}

QListWidget::item:selected {
    background-color: #0f3460;
    border: 1px solid #00b894;
}

QListWidget::item:hover {
    background-color: #1f2f50;
}

/* Tab Widget */
QTabWidget::pane {
    background-color: #16213e;
    border: none;
    border-radius: 10px;
}

QTabBar::tab {
    background-color: #1a1a2e;
    color: #a0a0a0;
    padding: 10px 20px;
    margin-right: 3px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    font-weight: bold;
    font-size: 12px;
}

QTabBar::tab:selected {
    background-color: #16213e;
    color: #00b894;
}

QTabBar::tab:hover:!selected {
    background-color: #1f2f50;
    color: #eaeaea;
}

/* Line Edit */
QLineEdit {
    background-color: #16213e;
    border: 1px solid #0f3460;
    border-radius: 4px;
    padding: 6px;
    color: #eaeaea;
    font-size: 12px;
}

QLineEdit:focus {
    border: 1px solid #00b894;
}

/* Check Box */
QCheckBox {
    spacing: 8px;
    color: #eaeaea;
    font-size: 12px;
}

QCheckBox::indicator {
    width: 18px;
    height: 18px;
    border-radius: 3px;
    border: 1px solid #0f3460;
    background-color: #1a1a2e;
}

QCheckBox::indicator:checked {
    background-color: #00b894;
    border-color: #00b894;
}

QCheckBox::indicator:hover {
    border-color: #16537e;
}

/* Progress Bar */
QProgressBar {
    background-color: #16213e;
    border-radius: 10px;
    text-align: center;
    color: #eaeaea;
    height: 20px;
}

QProgressBar::chunk {
    background-color: #00b894;
    border-radius: 10px;
}

/* Combo Box */
QComboBox {
    background-color: #16213e;
    border: 1px solid #0f3460;
    border-radius: 6px;
    padding: 8px;
    color: #eaeaea;
}

QComboBox:hover {
    border-color: #16537e;
}

QComboBox::drop-down {
    border: none;
    padding-right: 10px;
}

QComboBox QAbstractItemView {
    background-color: #16213e;
    border: 1px solid #0f3460;
    selection-background-color: #0f3460;
}

/* Group Box */
QGroupBox {
    background-color: #16213e;
    border: 1px solid #0f3460;
    border-radius: 8px;
    margin-top: 15px;
    padding-top: 15px;
    font-weight: bold;
}

QGroupBox::title {
    subcontrol-origin: margin;
    left: 15px;
    padding: 0 5px;
    color: #00b894;
}

/* Tool Tip */
QToolTip {
    background-color: #16213e;
    color: #eaeaea;
    border: 1px solid #0f3460;
    border-radius: 4px;
    padding: 5px;
}

/* Menu */
QMenu {
    background-color: #16213e;
    border: 1px solid #0f3460;
    border-radius: 4px;
    padding: 5px;
    font-size: 12px;
}

QMenu::item {
    padding: 6px 20px;
    border-radius: 3px;
}

QMenu::item:selected {
    background-color: #0f3460;
}

QMenu::separator {
    height: 1px;
    background-color: #0f3460;
    margin: 5px 10px;
}

/* Message Box */
QMessageBox {
    background-color: #1a1a2e;
}

QMessageBox QLabel {
    color: #eaeaea;
}
"""

# Color constants for use in code
COLORS = {
    'background': '#1a1a2e',
    'card': '#16213e',
    'primary': '#0f3460',
    'accent': '#00b894',
    'danger': '#e74c3c',
    'warning': '#f39c12',
    'info': '#3498db',
    'text': '#eaeaea',
    'text_secondary': '#a0a0a0',
}
