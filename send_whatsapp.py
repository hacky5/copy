import os
import requests
import json

AISENSY_API_URL = "https://api.aisensy.com/v1/template/send"

def send_whatsapp_template_message(recipient_number, template_name, template_params):
    """
    Sends a WhatsApp template message using the AiSensy API.
    
    :param recipient_number: The user's WhatsApp number (e.g., 919876543210).
    :param template_name: The pre-approved template name from AiSensy dashboard.
    :param template_params: A list of strings to fill the template variables.
    """
    api_key = os.environ.get("AISENSY_API_KEY")

    if not api_key:
        print("ERROR: AISENSY_API_KEY is not configured in environment variables.")
        return False
    
    if not template_name:
        print(f"ERROR: No AiSensy template name was provided for the request to {recipient_number}.")
        return False

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }

    payload = {
        "recipient": recipient_number,
        "template_name": template_name,
        "template_params": template_params
    }

    try:
        response = requests.post(AISENSY_API_URL, headers=headers, data=json.dumps(payload))
        response.raise_for_status()  # Raises an exception for bad responses (4xx or 5xx)
        
        response_data = response.json()
        # AiSensy success response can vary, check for a positive status
        if response.status_code in [200, 202] and response_data.get('success', True):
            print(f"WhatsApp template '{template_name}' sent successfully to {recipient_number}")
            return True
        else:
            print(f"Failed to send WhatsApp to {recipient_number}. Response: {response_data}")
            return False

    except requests.exceptions.RequestException as e:
        print(f"Error sending WhatsApp to {recipient_number}: {e}")
        return False
    except Exception as e:
        print(f"An unexpected error occurred while sending WhatsApp: {e}")
        return False
