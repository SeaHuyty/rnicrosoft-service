# Someth Antivirus

A professional, modern GUI antivirus application with real-time protection for Windows.

![Someth Antivirus](https://img.shields.io/badge/Version-1.0.0-green)
![Python](https://img.shields.io/badge/Python-3.8+-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)

## Features

### 🛡️ Real-Time Protection
- **Ransomware Detection**: Monitors for encrypted files (.enc, .locked, .crypted) and ransom notes
- **Worm Detection**: Monitors USB drives and blocks autorun.inf threats
- **Spyware Detection**: Detects keyloggers, screenshot capture, and webcam access
- **Process Monitoring**: Automatically kills malicious processes

### 💻 Professional GUI
- Modern dark theme interface
- Clean dashboard with protection status
- Real-time threat counter and statistics
- System tray integration for silent background operation
- Windows toast notifications for alerts

### ⚙️ Flexible Configuration
- Add/remove protected directories
- Enable/disable protection modules
- Configure notifications
- Windows startup integration

### 🔒 Security Features
- Automatic file backup before protection starts
- Quarantine zone for isolated threats
- One-click restore from backup
- Detailed threat history and logs

## Installation

### Prerequisites
- Windows 10/11
- Python 3.8 or higher

### Quick Setup

1. **Install dependencies**:
   ```
   Double-click: install.bat
   ```
   Or run manually:
   ```bash
   pip install -r requirements.txt
   ```

2. **Run Guardian Antivirus**:
   ```
   Double-click: Guardian.bat
   ```
   Or run manually:
   ```bash
   python main.py
   ```

3. **Start minimized to system tray**:
   ```bash
   python main.py --minimized
   ```

## Usage

### Dashboard
- View protection status (ON/OFF)
- See threat statistics
- Run manual scans
- View recent alerts

### Settings
- **Protected Directories**: Add folders you want to protect
- **Startup**: Enable auto-start with Windows
- **Notifications**: Configure Windows toast notifications
- **Protection Modules**: Enable/disable specific detectors

### Alerts
- View complete threat history
- Filter by severity (Critical, High, Info)
- Clear alert history

### Quarantine
- View quarantined files
- Restore files (if false positive)
- Permanently delete threats

## How It Works

### File Monitoring
Guardian uses the `watchdog` library to monitor protected directories in real-time. When a file is created, modified, or renamed, it's instantly checked for:
- Encrypted file extensions (.enc, .locked, .crypted)
- Ransom note patterns (README, DECRYPT, etc.)
- Suspicious file names

### Process Monitoring
Background threads scan running processes for:
- Known malicious signatures
- Suspicious command-line arguments
- Unauthorized access to protected folders

When a threat is detected:
1. The malicious process is terminated
2. Infected files are quarantined
3. Original files are restored from backup
4. User is notified via Windows toast

### Performance Optimization
- Uses efficient file system events (no constant scanning)
- Rate-limited process scanning (every 3 seconds)
- Debounced file events to prevent duplicate alerts
- Runs completely separate from VS Code

## File Structure

```
guardian_av/
├── main.py              # Main application entry point
├── requirements.txt     # Python dependencies
├── Guardian.bat         # Windows launcher
├── install.bat          # Dependency installer
├── core/
│   ├── config_manager.py    # Configuration handling
│   ├── protection_engine.py # Core detection engine
│   ├── startup_manager.py   # Windows startup integration
│   └── notifications.py     # Toast notifications
└── ui/
    ├── styles.py        # Dark theme stylesheet
    ├── dashboard.py     # Main dashboard widget
    ├── settings.py      # Settings panel
    ├── alerts.py        # Alert history
    └── quarantine.py    # Quarantine manager
```

## Configuration

Settings are stored in:
```
%LOCALAPPDATA%\GuardianAV\config.json
```

### Default Directories
- Backup: `C:\RansomwareBackup`
- Quarantine: `C:\QuarantineZone`

### Default Protected Folders
- Documents
- Desktop
- Downloads
- Pictures
- D:\Hello (if exists)

## Development

### Adding New Detection Modules

1. Add detection logic to `protection_engine.py`
2. Add configuration options to `config_manager.py`
3. Add UI controls to `settings.py`

### Customizing Theme

Edit `ui/styles.py` to customize colors and styling.

## Troubleshooting

### "Python not found"
Make sure Python is installed and added to PATH during installation.

### "PyQt5 not found"
Run `install.bat` or `pip install -r requirements.txt`

### High CPU Usage
- Enable "Low Resource Mode" in settings
- Reduce number of protected directories

### False Positives
- Restore files from Quarantine tab
- Add exceptions in Settings (future feature)

## License

This project is for educational purposes. Use responsibly.

## Credits

- PyQt5 for the GUI framework
- psutil for process monitoring
- watchdog for file system events
- win10toast for Windows notifications
