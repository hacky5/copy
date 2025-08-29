# send_whatsapp.py

import os
import requests
from dotenv import load_dotenv

# Load environment variables (for local testing)
load_dotenv()

AISENSY_API_KEY = os.getenv("AISENSY_API_KEY")
AISENSY_API_URL = "https://backend.aisensy.com/campaign/t1/api/v2"

def send_whatsapp_template_message(recipient_number, user_name, campaign_name, template_params):
    """
    Sends a WhatsApp message using AiSensy campaigns.
    :param recipient_number: The mobile number of the user with country code.
    :param user_name: The name of the user.
    :param campaign_name: The name of the AiSensy campaign to trigger.
    :param template_params: A list of parameter values for the template.
    :return: True if sent successfully, False otherwise.
    """
    if not all([AISENSY_API_KEY, campaign_name]):
        print("Error: AiSensy API Key or Campaign Name is not configured.")
        return False

    headers = {
        'Content-Type': 'application/json'
    }

    payload = {
        "apiKey": AISENSY_API_KEY,
        "campaignName": campaign_name,
        "destination": recipient_number,
        "userName": user_name,
        "templateParams": template_params
    }

    try:
        response = requests.post(AISENSY_API_URL, headers=headers, json=payload)
        response.raise_for_status()  # Raise an exception for bad status codes

        response_json = response.json()
        if response_json.get("success"):
            print(f"WhatsApp message sent successfully to {recipient_number} via campaign '{campaign_name}'.")
            return True
        else:
            print(f"Error sending WhatsApp to {recipient_number}: {response_json.get('message')}")
            return False

    except requests.exceptions.RequestException as e:
        print(f"Error sending WhatsApp to {recipient_number}: {e}")
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return False
