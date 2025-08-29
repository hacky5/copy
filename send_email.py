# send_email.py

import smtplib
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from dotenv import load_dotenv

# Load environment variables (for local testing)
load_dotenv()

EMAIL_SENDER = os.getenv("EMAIL_SENDER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

def send_email_message(recipient_email, subject, html_body):
    """
    Sends an email with HTML content.
    :param recipient_email: The email address of the recipient.
    :param subject: The subject line of the email.
    :param html_body: The HTML content of the email.
    :return: True if sent successfully, False otherwise.
    """
    if not all([EMAIL_SENDER, EMAIL_PASSWORD]):
        print("Error: Email credentials are not fully configured.")
        return False

    # Create a multipart message and set headers
    message = MIMEMultipart()
    message['From'] = EMAIL_SENDER
    message['To'] = recipient_email
    message['Subject'] = subject

    # Attach the HTML part
    message.attach(MIMEText(html_body, 'html'))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()  # Secure the connection
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, recipient_email, message.as_string())
        print(f"HTML Email sent successfully to {recipient_email}")
        return True
    except Exception as e:
        print(f"Error sending email to {recipient_email}: {e}")
        return False
