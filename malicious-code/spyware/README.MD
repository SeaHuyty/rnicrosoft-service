# Windows Spyware - Educational Project

## Overview

This is an **educational cybersecurity project** demonstrating how malicious software can gather sensitive user information and exfiltrate data from a Windows system. It serves as a learning tool for understanding cybersecurity threats, defensive measures, and system vulnerabilities.

**⚠️ WARNING:** This code is for educational purposes only. Deploying this on systems without explicit authorization is illegal and unethical.

---

## Project Purpose

The goal of this project is to understand:
- How malware collects user data (keystrokes, screenshots, audio, video)
- How systems can be compromised through legitimate Windows APIs
- Data encryption and secure transmission techniques
- The importance of system security and user privacy protection
- Detection and prevention of malicious software

---

## What This Code Does

### 1. **Keystroke Logging**
- Monitors and records all keyboard input
- Saves captured keystrokes to `key_logs.txt`
- Runs in a separate background process

### 2. **Screenshot Capture**
- Takes 10 screenshots at 5-second intervals
- Captures user activity and sensitive information displayed on screen
- Stores images in `Screenshots\` folder

### 3. **Microphone Recording**
- Records 5 audio clips of 10 seconds each
- Captures ambient sound and conversations
- Saves as WAV files in the logs directory

### 4. **Webcam Snapshots**
- Captures 10 images from the system's webcam
- Records at 5-second intervals
- Stores images in `WebcamPics\` folder

### 5. **System Information Gathering**
Collects comprehensive system data including:
- **Network Information:** WiFi profiles, IP addresses, network configurations, ARP tables, MAC addresses, routing tables
- **System Information:** Hostname, running processes, installed services
- **Clipboard Data:** Recently copied/pasted information
- **Browser History:** Browsing activity and database paths from installed browsers

### 6. **Data Encryption**
- Encrypts all collected files using Fernet (symmetric encryption)
- Uses a pre-shared encryption key
- Provides confidentiality during data transmission

### 7. **Telegram Exfiltration**
- Sends collected data through Telegram bot API
- Encrypts sensitive data before transmission
- Provides real-time updates via chat messages
- Supports file attachments and formatted messages

### 8. **Evidence Cleanup**
- Deletes all local log files after exfiltration
- Removes the logs directory to prevent forensic recovery
- Covers its tracks

### 9. **Persistent Execution**
- Runs in an infinite loop
- Continuously gathers data
- Restarts data collection after each cycle

---

## Technical Architecture

### Multi-Process Design
The program uses Python's `multiprocessing` module to run data collection tasks in parallel:
- Process 1: Keystroke logger (runs for 5 minutes)
- Process 2: Screenshot capturer (runs for 5 minutes)
- Process 3: Microphone recorder (runs for 5 minutes)
- Process 4: Webcam snapshotter (runs for 5 minutes)

### File Structure
```
spyware/
├── spyware.py              # Main malware script
├── requirements.txt        # Python dependencies
└── README.MD              # This documentation
```

### Data Collection Workflow
1. Create logs directory: `C:\Users\<Username>\AppData\Local\Temp\Logs\`
2. Start system information collection (network, system info, clipboard, browser history)
3. Launch 4 parallel processes for intensive data capture
4. Wait for all processes to complete (5-minute timeout)
5. Encrypt collected files using Fernet encryption
6. Send data through Telegram bot API
7. Cleanup local evidence
8. Maintain persistent Telegram bot connection
9. Restart the loop

---

## Installation & Setup

### Prerequisites
- Windows OS (10 or later recommended)
- Python 3.8+
- Administrator privileges

### Installation Steps

1. **Clone/Download the project**
```bash
cd spyware/
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Configure Email Credentials** (in `spyware.py`)
```python
BOT_TOKEN = 'your-telegram-bot-token'  # Change this
CHAT_ID = 'your-chat-id'               # Telegram chat ID
```

4. **Generate Encryption Key** (optional - to create a new key)
```python
from cryptography.fernet import Fernet
print(Fernet.generate_key())
```

5. **Run the program**
```bash
python spyware.py
```

---

## Key Functions Explained

### `logg_keys(file_path)`
- Uses `pynput.keyboard.Listener` to monitor keystrokes
- Logs each key press with timestamp
- Runs indefinitely in background process

### `screenshot(file_path)`
- Uses `PIL.ImageGrab` to capture screen
- Saves 10 screenshots at 5-second intervals
- Resolution: Full desktop resolution

### `microphone(file_path)`
- Uses `sounddevice` to access system audio input
- Records at 44.1 kHz, 2 channels (stereo)
- Saves as uncompressed WAV files

### `webcam(file_path)`
- Uses `cv2.VideoCapture` to access webcam
- Captures video frames as JPEG images
- Validates camera accessibility before recording

### Telegram Integration
- Uses `python-telegram-bot` for asynchronous communication
- Implements directory navigation bot with /list, /cd, /zip commands
- Encrypts sensitive data before transmission
- Supports real-time file exfiltration via chat

---

## Security & Defense Mechanisms

### What Makes This Dangerous
✓ Runs silently in background (no UI)
✓ Multi-threading captures diverse data simultaneously
✓ Encryption prevents interception
✓ Deletes evidence automatically
✓ Uses legitimate Windows APIs
✓ Runs in infinite loop for persistence

### How to Protect Yourself
✗ Keep antivirus/malware software updated
✗ Monitor running processes regularly
✗ Disable webcam when not in use
✗ Use VPN for network traffic encryption
✗ Implement application whitelisting
✗ Enable Windows Defender real-time protection
✗ Use endpoint detection and response (EDR) tools
✗ Practice secure coding and code review
✗ Monitor outgoing email traffic
✗ Use firewall rules to block suspicious connections

---

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| Pillow | 10.0.0+ | Screen capture and image processing |
| pynput | 1.7.6+ | Keyboard monitoring |
| opencv-python | 4.8.0+ | Webcam video capture |
| sounddevice | 0.4.6+ | Microphone recording |
| scipy | 1.11.0+ | Audio file writing |
| cryptography | 41.0.0+ | Data encryption (Fernet) |
| requests | 2.31.0+ | HTTP requests for public IP |
| browserhistory | 0.1.2+ | Browser history extraction |
| pywin32 | 305+ | Windows API access (clipboard) |
| python-telegram-bot | 20.0+ | Telegram bot integration |
| numpy | 1.24.0+ | Numeric operations for audio |

---

## Important Notes

### For Windows Users
- This code is **Windows-specific** and uses Windows APIs
- Requires **Administrator privileges** to access certain system functions
- Webcam and microphone require **hardware permissions** (Windows 10+)
- Some antivirus software will flag/block this code

### Ethical Considerations
- This project demonstrates **real cybersecurity threats**
- Never use this code against systems you don't own or have permission to test
- Understanding threats is crucial for **defending systems**
- This is a **learning tool only**, not for malicious purposes

---

## Troubleshooting

### Issue: "No logs folder created"
**Solution:** The code now auto-creates logs in `AppData\Local\Temp\Logs\` - a writable directory on all Windows systems.

### Issue: "Webcam not working"
**Solution:** Check if another application is using the camera, or grant permissions in Windows Settings.

### Issue: "Telegram bot not responding"
**Solution:**
- Verify BOT_TOKEN and CHAT_ID are correct
- Ensure internet connectivity
- Check Telegram API status
- Confirm bot has message sending permissions

### Issue: "Audio recording fails"
**Solution:** Verify microphone is working in Windows Sound settings and not muted.

---

## Learning Outcomes

By studying this code, you will understand:
1. ✓ How malware uses legitimate APIs for malicious purposes
2. ✓ Multi-process and multi-threading concepts
3. ✓ Data exfiltration techniques
4. ✓ Encryption and secure communication
5. ✓ Operating system security vulnerabilities
6. ✓ Defensive programming strategies
7. ✓ Forensic and detection evasion techniques

---

## Disclaimer

This project is provided strictly for **educational and authorized testing purposes**. The authors are not responsible for any misuse, illegal activity, or harm caused by this code. Unauthorized access to computer systems is a crime under the Computer Fraud and Abuse Act (CFAA) and similar laws worldwide.

**Use responsibly. Stay ethical.**

---

## Author Notes

This is part of the **Introduction to Cybersecurity** course at CADT GEN10 YEAR3. The project demonstrates offensive security concepts while emphasizing the importance of defensive measures and ethical behavior in cybersecurity.

Last Updated: December 3, 2025