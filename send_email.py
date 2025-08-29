# send_email.py

import os
import resend
from dotenv import load_dotenv

# Load environment variables (for local testing)
load_dotenv()

RESEND_API_KEY = os.getenv("RESEND_API_KEY")
RESEND_FROM_EMAIL = os.getenv("RESEND_FROM_EMAIL")

resend.api_key = RESEND_API_KEY

def send_email_message(recipient_email, subject, html_body):
    """
    Sends an email with HTML content using Resend.
    :param recipient_email: The email address of the recipient.
    :param subject: The subject line of the email.
    :param html_body: The HTML content of the email.
    :return: True if sent successfully, False otherwise.
    """
    if not all([RESEND_API_KEY, RESEND_FROM_EMAIL]):
        print("Error: Resend credentials are not fully configured.")
        return False

    params = {
        "from": RESEND_FROM_EMAIL,
        "to": recipient_email,
        "subject": subject,
        "html": html_body,
    }

    try:
        email = resend.Emails.send(params)
        print(f"Email sent successfully to {recipient_email}. Message ID: {email['id']}")
        return True
    except Exception as e:
        print(f"Error sending email to {recipient_email}: {e}")
        return False
