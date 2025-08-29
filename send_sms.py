import requests
import os

# Credentials are loaded from Vercel's environment variables
SMS_USERNAME = os.getenv("BULKSMS_USERNAME")
SMS_PASSWORD = os.getenv("BULKSMS_PASSWORD")
SMS_API_URL = "https://api.bulksms.com/v1/messages"

def send_sms_message(recipient_number, message_body):
    """Sends an SMS using the BulkSMS.com API."""
    if not all([SMS_USERNAME, SMS_PASSWORD]):
        print("SMS credentials are not fully configured.")
        return False
        
    # The API expects the number without the leading '+'
    if recipient_number.startswith('+'):
        recipient_number = recipient_number[1:]

    payload = {'to': recipient_number, 'body': message_body}
    headers = {'Content-Type': 'application/json'}

    try:
        response = requests.post(
            SMS_API_URL,
            json=payload,
            headers=headers,
            auth=(SMS_USERNAME, SMS_PASSWORD)
        )
        response.raise_for_status() 
        print(f"SMS submitted successfully to {recipient_number}.")
        return True
    except Exception as e:
        print(f"Error sending SMS to {recipient_number}: {e}")
        return False