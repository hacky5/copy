import os
import requests
import json

# This new endpoint is for sending "API Campaigns"
AISENSY_API_URL = "https://backend.aisensy.com/campaign/t1/api/v2"

def send_whatsapp_template_message(recipient_number, user_name, campaign_name, template_params):
    """
    Sends a WhatsApp template message using the AiSensy Campaign API.
    
    :param recipient_number: The user's WhatsApp number (e.g., +919876543210).
    :param user_name: The name of the user.
    :param campaign_name: The pre-approved campaign name from AiSensy dashboard.
    :param template_params: A list of strings to fill the template variables.
    """
    api_key = os.environ.get("AISENSY_API_KEY")

    if not api_key:
        print("ERROR: AISENSY_API_KEY is not configured in environment variables.")
        return False
    
    if not campaign_name:
        print(f"ERROR: No AiSensy campaign name was provided for the request to {recipient_number}.")
        return False

    headers = {
        "Content-Type": "application/json"
    }

    payload = {
        "apiKey": api_key,
        "campaignName": campaign_name,
        "destination": recipient_number,
        "userName": user_name,
        "source": "Bin Reminder App", # Optional source tag
        "templateParams": template_params
    }

    try:
        response = requests.post(AISENSY_API_URL, headers=headers, data=json.dumps(payload))
        response.raise_for_status()
        
        response_data = response.json()

        # The new API response structure might be different, check for a success key.
        # This is a guess, you may need to adjust based on actual AiSensy responses.
        if response_data.get('status') == 'success' or response.status_code in [200, 202]:
            print(f"WhatsApp campaign '{campaign_name}' sent successfully to {recipient_number}")
            return True
        else:
            # Try to get a meaningful error message from the response
            error_message = response_data.get('message', 'Unknown error')
            print(f"Failed to send WhatsApp to {recipient_number}. Response: {error_message}")
            return False

    except requests.exceptions.RequestException as e:
        print(f"Error sending WhatsApp to {recipient_number}: {e}")
        return False
    except Exception as e:
        print(f"An unexpected error occurred while sending WhatsApp: {e}")
        return False
