import os
from twilio.rest import Client

# Credentials are loaded from Vercel's environment variables
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_WHATSAPP_NUMBER = os.getenv("TWILIO_WHATSAPP_NUMBER")

client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

def send_whatsapp_message(recipient_number, message_body):
    """Sends a WhatsApp message using Twilio."""
    if not all([TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_WHATSAPP_NUMBER]):
        print("WhatsApp credentials are not fully configured.")
        return False
    try:
        message = client.messages.create(
            from_=TWILIO_WHATSAPP_NUMBER,
            body=message_body,
            to=f"whatsapp:{recipient_number}"
        )
        print(f"WhatsApp message sent to {recipient_number}: {message.sid}")
        return True
    except Exception as e:
        print(f"Error sending WhatsApp to {recipient_number}: {e}")
        return False