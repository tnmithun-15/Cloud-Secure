import smtplib
import logging
import time
import tkinter as tk
import customtkinter as ctk
from email.mime.text import MIMEText
import webbrowser
import psutil
import sqlite3
import socket
from tkinter import messagebox
from collections import deque
import os
import random
import boto3
from botocore.exceptions import NoCredentialsError
from datetime import datetime

# AWS Configuration
AWS_REGION = "us-east-1"  # Example: "us-east-1"
LOG_GROUP_NAME = "enter your cloud watch group name"
LOG_STREAM_NAME = #f"Mycyber-{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}"

# Initialize CloudWatch client
cloudwatch_client = boto3.client("logs", region_name=AWS_REGION)

# Create log group if it doesn't exist
try:
    cloudwatch_client.create_log_group(logGroupName=LOG_GROUP_NAME)
    print(f"Log group '{LOG_GROUP_NAME}' created.")
except cloudwatch_client.exceptions.ResourceAlreadyExistsException:
    print(f"Log group '{LOG_GROUP_NAME}' already exists.")

# Create log stream
try:
    cloudwatch_client.create_log_stream(logGroupName=LOG_GROUP_NAME, logStreamName=LOG_STREAM_NAME)
    print(f"Log stream '{LOG_STREAM_NAME}' created.")
except cloudwatch_client.exceptions.ResourceAlreadyExistsException:
    print(f"Log stream '{LOG_STREAM_NAME}' already exists.")

# Custom handler for CloudWatch logs
class CloudWatchLogHandler(logging.Handler):
    def __init__(self, log_group, log_stream):
        super().__init__()
        self.log_group = log_group
        self.log_stream = log_stream
        self.sequence_token = None

    def emit(self, record):
        log_entry = self.format(record)
        timestamp = int(time.time() * 1000)  # CloudWatch expects timestamp in milliseconds

        log_event = {
            "logGroupName": self.log_group,
            "logStreamName": self.log_stream,
            "logEvents": [{"timestamp": timestamp, "message": log_entry}],
        }

        if self.sequence_token:
            log_event["sequenceToken"] = self.sequence_token

        try:
            response = cloudwatch_client.put_log_events(**log_event)
            self.sequence_token = response["nextSequenceToken"]
        except Exception as e:
            print(f"Failed to send log to CloudWatch: {e}")

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
cloudwatch_handler = CloudWatchLogHandler(LOG_GROUP_NAME, LOG_STREAM_NAME)
cloudwatch_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
cloudwatch_handler.setFormatter(formatter)
logger.addHandler(cloudwatch_handler)

# Email configuration
sender_email = "sender mail id"
receiver_email = "reciver mail id"
email_password = "app passowrd of Google account"

# Constants
FAILED_ATTEMPT_THRESHOLD = 5
TIME_WINDOW = 60
MONITOR_INTERVAL = 5
OTP_EXPIRATION_TIME = 300
failed_attempts = deque()

# Database path
db_path = os.path.join(os.getenv("USERPROFILE"), "databases", "blocked_ips.db")
logger.debug(f"Database path: {db_path}")

# Database functions
def create_db():
    if not os.path.exists(os.path.dirname(db_path)):
        os.makedirs(os.path.dirname(db_path))
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS blocked_ips (
                        ip_address TEXT PRIMARY KEY,
                        blocked_time INTEGER,
                        otp TEXT,
                        otp_sent_time INTEGER,
                        failed_attempts INTEGER DEFAULT 0
    )''')
    conn.commit()
    conn.close()

def add_blocked_ip(ip_address, otp):
    try:
        logger.debug(f"Adding blocked IP {ip_address} with OTP {otp}")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO blocked_ips (ip_address, blocked_time, otp, otp_sent_time, failed_attempts) VALUES (?, ?, ?, ?, ?)",
            (ip_address, int(time.time()), otp, int(time.time()), len(failed_attempts)))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to add blocked IP {ip_address} to database: {e}")

def is_ip_blocked(ip_address):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT blocked_time, otp, otp_sent_time FROM blocked_ips WHERE ip_address = ?", (ip_address,))
    result = cursor.fetchone()
    conn.close()

    if result:
        blocked_time = result[0]
        otp = result[1]
        otp_sent_time = result[2]

        if otp_sent_time and time.time() - blocked_time < 3600:
            if time.time() - otp_sent_time < OTP_EXPIRATION_TIME:
                logger.debug(f"IP {ip_address} is blocked, OTP valid.")
                return True, otp, otp_sent_time
            else:
                logger.warning(f"OTP expired for IP: {ip_address}.")
                remove_blocked_ip(ip_address)
                return False, None, None
        else:
            remove_blocked_ip(ip_address)
    return False, None, None

def remove_blocked_ip(ip_address):
    logger.debug(f"Removing blocked IP {ip_address}")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM blocked_ips WHERE ip_address = ?", (ip_address,))
    conn.commit()
    conn.close()

# Email and OTP functions
def send_alert_email(subject, body):
    try:
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = sender_email
        msg['To'] = receiver_email
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp_server:
            smtp_server.login(sender_email, email_password)
            smtp_server.sendmail(sender_email, receiver_email, msg.as_string())
        logger.info("Alert email sent!")
    except smtplib.SMTPAuthenticationError as e:
        logger.error(f"Authentication failed: {e}")
    except Exception as e:
        logger.error(f"Failed to send alert email: {e}")

def generate_otp():
    otp = str(random.randint(100000, 999999))
    logger.debug(f"Generated OTP: {otp}")
    return otp

# Block IP function
def block_ip(ip_address):
    otp = generate_otp()
    add_blocked_ip(ip_address, otp)
    send_alert_email("IP Blocked", f"IP address {ip_address} has been blocked due to multiple failed login attempts. The OTP is: {otp}. Do not share it publicly.")

# Tkinter GUI setup
app = ctk.CTk()
app.title("Intrusion Detection System")

label_username = ctk.CTkLabel(app, text="Username")
label_username.pack(pady=10)
entry_username = ctk.CTkEntry(app)
entry_username.pack(pady=10)

label_password = ctk.CTkLabel(app, text="Password")
label_password.pack(pady=10)
entry_password = ctk.CTkEntry(app, show="*")
entry_password.pack(pady=10)

label_otp = ctk.CTkLabel(app, text="OTP")
label_otp.pack(pady=10)
entry_otp = ctk.CTkEntry(app)
entry_otp.pack(pady=10)

label_result = ctk.CTkLabel(app, text="")
label_result.pack(pady=20)

def on_login_button_click(username, password):
    ip_address = socket.gethostbyname(socket.gethostname())
    is_blocked, otp, otp_sent_time = is_ip_blocked(ip_address)
    if is_blocked:
        logger.debug(f"IP {ip_address} is blocked, OTP {otp} is required.")
        label_result.configure(text="Blocked IP", text_color="red")
        user_otp = entry_otp.get()
        if user_otp == otp:
            label_result.configure(text="Login Successful", text_color="green")
        else:
            label_result.configure(text="Invalid OTP", text_color="red")
            logger.warning(f"Failed OTP attempt for IP: {ip_address}")
            return

    correct_username = "admin"
    correct_password = "admin123"

    if username == correct_username and password == correct_password:
        label_result.configure(text="Login Successful", text_color="green")
    else:
        label_result.configure(text="Login Failed", text_color="red")
        failed_attempts.append(time.time())
        if len(failed_attempts) >= FAILED_ATTEMPT_THRESHOLD:
            block_ip(ip_address)

login_button = ctk.CTkButton(app, text="Login", command=lambda: on_login_button_click(entry_username.get(), entry_password.get()))
login_button.pack(pady=20)

create_db()
app.mainloop()
