import os
import requests

BULKSMS_API_URL = "https://api.bulksms.com/v1/messages"

def send_sms_message(to_number, message_body):
    """
    Sends an SMS using the BulkSMS service.
    Expects to_number in E.164 format (e.g., +27123456789).
    """
    username = os.environ.get("BULKSMS_USERNAME")
    password = os.environ.get("BULKSMS_PASSWORD")

    if not username or not password:
        print("ERROR: BulkSMS username or password is not configured in environment variables.")
        return False
        
    # The BulkSMS API expects a specific format.
    # It removes the leading '+' if it exists.
    formatted_number = to_number.lstrip('+')

    payload = {
        "to": formatted_number,
        "body": message_body
    }

    try:
        response = requests.post(
            BULKSMS_API_URL,
            json=[payload], # API expects a list of message objects
            auth=(username, password),
            headers={"Content-Type": "application/json"}
        )
        response.raise_for_status()  # This will raise an exception for HTTP errors
        
        response_data = response.json()
        if response_data and response_data[0].get("status", {}).get("type") == "ACCEPTED":
             print(f"SMS submitted successfully to {to_number}")
             return True
        else:
             error_detail = response_data[0].get("status", {}).get("detail", "Unknown error")
             print(f"Failed to send SMS to {to_number}: {error_detail}")
             return False

    except requests.exceptions.RequestException as e:
        print(f"Error sending SMS to {to_number}: {e}")
        return False
