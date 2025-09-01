from flask import Flask, request, jsonify, g
from flask_cors import CORS
from functools import wraps
from firebase_admin import auth, credentials, initialize_app
import os
import json
from services.database import get_residents_in_order, get_resident_by_id, add_resident as db_add_resident, update_resident as db_update_resident, delete_resident as db_delete_resident, get_settings as db_get_settings, update_settings as db_update_settings, get_admin_users, get_admin_by_email, add_admin_user, update_admin_user, delete_admin_user, log_event, get_logs, delete_log_entries, add_issue, get_issues as db_get_issues, update_issue_status as db_update_issue_status, delete_issues as db_delete_issues, get_history as db_get_history, delete_history_items as db_delete_history_items, update_resident_order as db_update_resident_order, clear_and_insert_residents, get_resident_by_flat_number, get_current_duty_resident, set_current_duty_resident_by_id, get_next_in_rotation as db_get_next_in_rotation, advance_turn as db_advance_turn, skip_turn as db_skip_turn, clear_history
from services.send_email import send_email
from services.send_sms import send_sms
from services.send_whatsapp import send_whatsapp_template_message
from datetime import datetime
import pytz
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.jobstores.memory import MemoryJobStore

app = Flask(__name__)
CORS(app) 

# Load Firebase credentials from environment variable
firebase_creds_json = os.environ.get('FIREBASE_CREDS_JSON')
if not firebase_creds_json:
    raise ValueError("FIREBASE_CREDS_JSON environment variable is not set.")

# Decode the JSON string
try:
    firebase_creds_dict = json.loads(firebase_creds_json)
except json.JSONDecodeError:
    raise ValueError("FIREBASE_CREDS_JSON is not a valid JSON string.")

# Initialize Firebase Admin SDK
cred = credentials.Certificate(firebase_creds_dict)
initialize_app(cred)

# In-memory store for settings cache
settings_cache = None

def get_cached_settings():
    """Gets settings from cache or database."""
    global settings_cache
    if settings_cache is None:
        settings_cache = db_get_settings()
    return settings_cache

# Decorator for token validation
def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('x-access-token')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            decoded_token = auth.verify_id_token(token)
            g.user = decoded_token
        except Exception as e:
            return jsonify({'message': 'Token is invalid or expired!'}), 403
        return f(*args, **kwargs)
    return decorated_function

# Decorator for role-based access control
def roles_required(allowed_roles):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # Assumes token_required has already run and set g.user
            user_email = g.user.get('email')
            if not user_email:
                return jsonify({'message': 'User email not found in token'}), 403
            
            admin_user = get_admin_by_email(user_email)
            if not admin_user or admin_user['role'] not in allowed_roles:
                return jsonify({'message': 'You do not have permission to perform this action'}), 403
            
            return f(*args, **kwargs)
        return wrapper
    return decorator


# --- LOGIN ---
@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    try:
        # Step 1: Check if user is an admin in our database
        admin_user = get_admin_by_email(email)
        if not admin_user:
            return jsonify({'message': 'User not found or not an admin'}), 404
        
        # Step 2: Verify user with Firebase Auth
        user = auth.get_user_by_email(email)
        
        # Step 3: Firebase doesn't verify passwords on the server side in a simple way.
        # The frontend handles the sign-in, and sends the ID token.
        # This endpoint is a bit of a placeholder. In a real scenario, the client
        # would sign in with email/password against Firebase, get an ID token, and send that.
        # For now, we'll just return a custom token if the user exists.
        
        custom_token = auth.create_custom_token(user.uid)

        return jsonify({
            'token': custom_token.decode('utf-8'),
            'user': {
                'id': admin_user['id'],
                'email': admin_user['email'],
                'role': admin_user['role']
            }
        })
    
    except auth.UserNotFoundError:
        return jsonify({'message': 'User not found in Firebase Authentication'}), 404
    except Exception as e:
        return jsonify({'message': f'An error occurred: {str(e)}'}), 500

# --- DASHBOARD ---
@app.route('/api/dashboard', methods=['GET'])
@token_required
def get_dashboard_info():
    try:
        current_duty_resident = get_current_duty_resident()
        next_in_rotation_resident = db_get_next_in_rotation()
        settings = get_cached_settings()
        
        # Fetch last run time of the job from the scheduler
        job = scheduler.get_job('send_weekly_reminders')
        last_run_time = None
        if job and job.last_run_at:
            sast = pytz.timezone('Africa/Johannesburg')
            last_run_time_utc = job.last_run_at.astimezone(pytz.utc)
            last_run_time_sast = last_run_time_utc.astimezone(sast)
            last_run_time = last_run_time_sast.strftime('%Y-%m-%d %H:%M:%S SAST')
        else:
            last_run_time = "Never"


        return jsonify({
            'current_duty': {'name': current_duty_resident['name'] if current_duty_resident else 'N/A'},
            'next_in_rotation': {'name': next_in_rotation_resident['name'] if next_in_rotation_resident else 'N/A'},
            'system_status': {
                'last_reminder_run': last_run_time,
                'reminders_paused': settings.get('reminders_paused', False)
            }
        })
    except Exception as e:
        print(f"Error in get_dashboard_info: {e}")
        return jsonify({'error': 'Could not retrieve dashboard information'}), 500


# --- RESIDENTS ---
@app.route('/api/residents', methods=['GET'])
@token_required
def get_residents():
    try:
        residents = get_residents_in_order()
        return jsonify(residents)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/residents', methods=['POST'])
@token_required
@roles_required(['superuser', 'editor'])
def add_resident():
    try:
        data = request.json
        resident_id = db_add_resident(data)
        return jsonify({'id': resident_id}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/residents/<resident_id>', methods=['PUT'])
@token_required
@roles_required(['superuser', 'editor'])
def update_resident(resident_id):
    try:
        data = request.json
        db_update_resident(resident_id, data)
        return jsonify({'message': 'Resident updated successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/residents/<resident_id>', methods=['DELETE'])
@token_required
@roles_required(['superuser'])
def delete_resident(resident_id):
    try:
        db_delete_resident(resident_id)
        return jsonify({'message': 'Resident deleted successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/residents/order', methods=['PUT'])
@token_required
@roles_required(['superuser', 'editor'])
def update_resident_order():
    try:
        data = request.json
        residents_data = data.get('residents')
        if not residents_data:
            return jsonify({'error': 'No residents data provided'}), 400
        db_update_resident_order(residents_data)
        return jsonify({'message': 'Resident order updated successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# --- ADMINS ---
@app.route('/api/admins', methods=['GET'])
@token_required
@roles_required(['superuser'])
def get_admins():
    admins = get_admin_users()
    return jsonify(admins)

@app.route('/api/admins', methods=['POST'])
@token_required
@roles_required(['superuser'])
def add_admin():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    role = data.get('role', 'editor')

    if not email or not password:
        return jsonify({'message': 'Email and password are required'}), 400

    try:
        # Create user in Firebase Auth
        new_user = auth.create_user(email=email, password=password)
        # Add user to our database
        add_admin_user({'email': email, 'role': role, 'firebase_uid': new_user.uid})
        return jsonify({'message': 'Admin added successfully'}), 201
    except auth.EmailAlreadyExistsError:
        return jsonify({'message': 'An account with this email already exists'}), 409
    except Exception as e:
        return jsonify({'message': f'Failed to add admin: {e}'}), 500


@app.route('/api/admins/<admin_id>', methods=['PUT'])
@token_required
@roles_required(['superuser'])
def update_admin(admin_id):
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    role = data.get('role')

    try:
        # Get existing admin to find their UID
        admin_to_update = next((admin for admin in get_admin_users() if admin['id'] == admin_id), None)
        if not admin_to_update:
            return jsonify({'message': 'Admin not found'}), 404

        update_payload = {}
        if email:
            update_payload['email'] = email
        if password:
            update_payload['password'] = password
        
        if update_payload:
            auth.update_user(admin_to_update['firebase_uid'], **update_payload)
        
        update_admin_user(admin_id, {'email': email, 'role': role})
        return jsonify({'message': 'Admin updated successfully'}), 200
    except Exception as e:
        return jsonify({'message': f'Failed to update admin: {e}'}), 500

@app.route('/api/admins/<admin_id>', methods=['DELETE'])
@token_required
@roles_required(['superuser'])
def delete_admin(admin_id):
    try:
         # Get existing admin to find their UID
        admin_to_delete = next((admin for admin in get_admin_users() if admin['id'] == admin_id), None)
        if not admin_to_delete:
            return jsonify({'message': 'Admin not found'}), 404

        auth.delete_user(admin_to_delete['firebase_uid'])
        delete_admin_user(admin_id)
        return jsonify({'message': 'Admin deleted successfully'}), 200
    except Exception as e:
        return jsonify({'message': f'Failed to delete admin: {e}'}), 500


# --- SETTINGS ---
@app.route('/api/settings', methods=['GET'])
@token_required
@roles_required(['superuser'])
def get_settings():
    settings = get_cached_settings()
    return jsonify(settings)

@app.route('/api/settings', methods=['PUT'])
@token_required
@roles_required(['superuser'])
def update_settings():
    global settings_cache
    data = request.json
    db_update_settings(data)
    settings_cache = None # Invalidate cache
    
    # After updating settings, potentially restart the scheduler if the cron time changed
    new_cron_str = data.get('reminder_cron_string')
    if new_cron_str and scheduler.get_job('send_weekly_reminders'):
        try:
            # This assumes a standard cron format, e.g., "40 7 * * 3"
            cron_parts = new_cron_str.split()
            minute, hour, _, _, day_of_week = cron_parts
            scheduler.reschedule_job(
                'send_weekly_reminders',
                trigger=CronTrigger(hour=hour, minute=minute, day_of_week=day_of_week, timezone='Africa/Johannesburg')
            )
            log_event(f"Scheduler rescheduled to: {new_cron_str}")
        except Exception as e:
            log_event(f"ERROR: Could not reschedule job. Invalid cron string? Error: {e}")
            return jsonify({"message": "Settings saved, but failed to reschedule reminders. Check cron format."}), 500

    return jsonify({'message': 'Settings updated successfully'})


# --- LOGS ---
@app.route('/api/logs', methods=['GET'])
@token_required
@roles_required(['superuser', 'editor', 'viewer'])
def get_system_logs():
    logs = get_logs()
    return jsonify(logs)

@app.route('/api/logs', methods=['DELETE'])
@token_required
@roles_required(['superuser'])
def delete_logs():
    data = request.json
    logs_to_delete = data.get('logs', [])
    if not logs_to_delete:
        return jsonify({'error': 'No logs provided to delete'}), 400
    
    try:
        delete_log_entries(logs_to_delete)
        return jsonify({'message': 'Logs deleted successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# --- ISSUES ---
@app.route('/api/issues', methods=['GET'])
@token_required
@roles_required(['superuser', 'editor', 'viewer'])
def get_issues():
    issues = db_get_issues()
    return jsonify(issues)

# Public endpoint for reporting issues
@app.route('/api/issues', methods=['POST'])
def report_issue():
    data = request.json
    reported_by = data.get('name')
    flat_number = data.get('flat_number')
    description = data.get('description')

    if not all([reported_by, flat_number, description]):
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        issue_id = add_issue(reported_by, flat_number, description)
        
        # Notify owner
        settings = get_cached_settings()
        owner_name = settings.get('owner_name', 'Owner')
        owner_email = settings.get('owner_contact_email')
        owner_sms = settings.get('owner_contact_number')
        owner_whatsapp = settings.get('owner_contact_whatsapp')
        
        email_subject = f"New Maintenance Issue Reported - Flat {flat_number}"
        email_body = f"""
        A new maintenance issue has been reported.

        Reported by: {reported_by}
        Flat Number: {flat_number}
        Description: {description}
        """

        if owner_email:
            send_email(owner_email, email_subject, email_body)
            log_event(f"Issue report email sent to {owner_email}")

        if owner_sms:
            sms_body = f"New Issue (Flat {flat_number}): {description}"
            send_sms(owner_sms, sms_body)
            log_event(f"Issue report SMS sent to {owner_sms}")
        
        if owner_whatsapp:
            campaign_name = settings.get('whatsapp_issue_template')
            if campaign_name:
                # Correct parameters: Resident name, Flat number, Issue body
                whatsapp_template_params = [reported_by, flat_number, description]
                send_whatsapp_template_message(owner_whatsapp, owner_name, campaign_name, whatsapp_template_params)
                log_event(f"Issue report WhatsApp sent to {owner_whatsapp}")

        return jsonify({'id': issue_id}), 201
    except Exception as e:
        log_event(f"ERROR reporting issue: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/issues/<issue_id>', methods=['PUT'])
@token_required
@roles_required(['superuser', 'editor'])
def update_issue_status(issue_id):
    data = request.json
    status = data.get('status')
    if not status:
        return jsonify({'error': 'Status is required'}), 400
    try:
        db_update_issue_status(issue_id, status)
        return jsonify({'message': 'Issue status updated'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/issues', methods=['DELETE'])
@token_required
@roles_required(['superuser'])
def delete_issues():
    data = request.json
    issue_ids = data.get('ids', [])
    if not issue_ids:
        return jsonify({'error': 'No issue IDs provided'}), 400
    try:
        db_delete_issues(issue_ids)
        return jsonify({'message': 'Issues deleted successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# --- HISTORY ---
@app.route('/api/history', methods=['GET'])
@token_required
@roles_required(['superuser', 'editor'])
def get_history():
    history = db_get_history()
    return jsonify(history)


@app.route('/api/history', methods=['DELETE'])
@token_required
@roles_required(['superuser'])
def delete_history():
    data = request.json
    history_ids = data.get('history_ids', [])
    if not history_ids:
        return jsonify({'error': 'No history IDs provided'}), 400
    try:
        db_delete_history_items(history_ids)
        return jsonify({'message': 'History items deleted successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# --- ACTIONS ---
@app.route('/api/trigger-reminder', methods=['POST', 'GET']) # Allow GET for cron
def trigger_reminder_endpoint():
    data = request.get_json(silent=True) or {} # silent=True for GET requests
    custom_message = data.get('message')
    send_weekly_reminders(custom_message=custom_message)
    return jsonify({'message': 'Reminder process triggered and turn advanced.'})

@app.route('/api/set-current-turn/<resident_id>', methods=['POST'])
@token_required
@roles_required(['superuser', 'editor'])
def set_current_turn(resident_id):
    try:
        set_current_duty_resident_by_id(resident_id)
        log_event(f"Duty manually set to resident ID {resident_id} by {g.user.get('email')}")
        return jsonify({'message': 'Current turn set successfully'})
    except Exception as e:
        log_event(f"ERROR setting current turn: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/skip-turn', methods=['POST'])
@token_required
@roles_required(['superuser', 'editor'])
def skip_turn_endpoint():
    try:
        skipped_resident = db_skip_turn()
        log_event(f"Turn skipped for {skipped_resident['name']} by {g.user.get('email')}")
        return jsonify({'message': f"Turn skipped for {skipped_resident['name']}."})
    except Exception as e:
        log_event(f"ERROR skipping turn: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/advance-turn', methods=['POST'])
@token_required
@roles_required(['superuser', 'editor'])
def advance_turn_endpoint():
    try:
        db_advance_turn()
        log_event(f"Turn advanced manually by {g.user.get('email')}")
        return jsonify({'message': 'Turn advanced successfully'})
    except Exception as e:
        log_event(f"ERROR advancing turn: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/announcements', methods=['POST'])
@token_required
@roles_required(['superuser', 'editor'])
def send_announcement_endpoint():
    data = request.json
    subject = data.get('subject')
    message = data.get('message')
    resident_ids = data.get('resident_ids', [])

    if not all([subject, message, resident_ids]):
        return jsonify({'error': 'Missing required fields'}), 400

    send_announcement(subject, message, resident_ids)
    return jsonify({'message': 'Announcement sent successfully'}), 200

# --- SCHEDULER AND CORE LOGIC ---

def send_whatsapp_reminder(resident, reminder_message):
    settings = get_cached_settings()
    recipient_number = resident.get('contact', {}).get('whatsapp')
    campaign_name = settings.get('whatsapp_reminder_template')
    owner_name = settings.get('owner_name', '')
    owner_contact = settings.get('owner_contact_number', '')

    if recipient_number and campaign_name:
        try:
            # Correct parameters: Resident name, Owner name, Owner number
            template_params = [resident['name'], owner_name, owner_contact]
            success = send_whatsapp_template_message(
                recipient_number,
                resident['name'],
                campaign_name,
                template_params
            )
            if success:
                log_event(f"WhatsApp reminder sent to {resident['name']} at {recipient_number}")
            else:
                log_event(f"ERROR: Failed to send WhatsApp reminder to {resident['name']}")
        except Exception as e:
            log_event(f"ERROR sending WhatsApp to {resident['name']}: {e}")

def send_announcement_whatsapp(resident, subject, message_template):
    settings = get_cached_settings()
    recipient_number = resident.get('contact', {}).get('whatsapp')
    campaign_name = settings.get('whatsapp_announcement_template')

    if recipient_number and campaign_name:
        try:
            # Correct parameters: Announcement topic, Resident name, Announcement body
            template_params = [subject, resident['name'], message_template]
            success = send_whatsapp_template_message(
                recipient_number,
                resident['name'],
                campaign_name,
                template_params
            )
            if success:
                log_event(f"WhatsApp announcement sent to {resident['name']} at {recipient_number}")
            else:
                log_event(f"ERROR: Failed to send WhatsApp announcement to {resident['name']}")
        except Exception as e:
            log_event(f"ERROR sending announcement WhatsApp to {resident['name']}: {e}")

def send_weekly_reminders(custom_message=None):
    with app.app_context(): # Create an application context
        log_event("Starting weekly reminder job...")
        settings = get_cached_settings()
        
        if settings.get('reminders_paused', False):
            log_event("Reminders are paused. Skipping job.")
            return

        current_resident = get_current_duty_resident()

        if not current_resident:
            log_event("No resident currently on duty. Cannot send reminder.")
            return

        resident_name = current_resident.get('name', 'Resident')
        
        # Prepare the message from template or use custom message
        if custom_message:
            reminder_message = custom_message
        else:
            template = settings.get('reminder_template', "Hi {first_name}, it's your turn for bin duty.")
            reminder_message = template.format(
                first_name=resident_name.split()[0],
                flat_number=current_resident.get('flat_number', '')
            )
        
        # --- Send Communications ---
        # Email
        recipient_email = current_resident.get('contact', {}).get('email')
        if recipient_email:
            send_email(recipient_email, "Bin Duty Reminder", reminder_message)
            log_event(f"Email reminder sent to {resident_name} at {recipient_email}")
        
        # SMS
        recipient_sms = current_resident.get('contact', {}).get('sms')
        if recipient_sms:
            send_sms(recipient_sms, reminder_message)
            log_event(f"SMS reminder sent to {resident_name} at {recipient_sms}")
        
        # WhatsApp
        send_whatsapp_reminder(current_resident, reminder_message)

        # Advance the turn
        db_advance_turn()
        next_resident = get_current_duty_resident()
        log_event(f"Duty advanced from {resident_name} to {next_resident.get('name', 'N/A') if next_resident else 'N/A'}")

def send_announcement(subject, message, resident_ids):
    """Sends a broadcast announcement to selected residents."""
    log_event(f"Starting announcement: '{subject}' to {len(resident_ids)} residents.")
    settings = get_cached_settings()
    
    # Prepare message from template
    template = settings.get('announcement_template', '{message}')
    
    for resident_id in resident_ids:
        resident = get_resident_by_id(resident_id)
        if not resident:
            log_event(f"WARNING: Could not find resident with ID {resident_id} for announcement.")
            continue
        
        message_template = template.format(
            first_name=resident['name'].split()[0],
            flat_number=resident['flat_number'],
            subject=subject,
            message=message
        )
        
        # Send via Email
        email = resident.get('contact', {}).get('email')
        if email:
            send_email(email, subject, message_template)
            log_event(f"Announcement email sent to {resident['name']} at {email}")
        
        # Send via SMS
        sms = resident.get('contact', {}).get('sms')
        if sms:
            send_sms(sms, f"{subject}: {message}")
            log_event(f"Announcement SMS sent to {resident['name']} at {sms}")

        # Send via WhatsApp
        send_announcement_whatsapp(resident, subject, message_template)

# --- Scheduler setup ---
scheduler = BackgroundScheduler(jobstores={'default': MemoryJobStore()})
scheduler.start()

# Schedule the job
# Default: Every Wednesday at 07:40 AM SAST (UTC+2)
# This can be overridden by a setting in the database
sast_timezone = pytz.timezone('Africa/Johannesburg')
try:
    with app.app_context(): # Need context to access db
      settings = get_cached_settings()
      cron_str = settings.get('reminder_cron_string', "40 7 * * 3") # Default to Wed 7:40 AM
      cron_parts = cron_str.split()
      minute, hour, _, _, day_of_week = cron_parts
      scheduler.add_job(
          func=send_weekly_reminders,
          trigger=CronTrigger(hour=hour, minute=minute, day_of_week=day_of_week, timezone=sast_timezone),
          id='send_weekly_reminders',
          name='Send weekly bin duty reminders',
          replace_existing=True
      )
      log_event(f"Scheduler initialized. Reminders set for: {cron_str} (SAST)")
except Exception as e:
    log_event(f"CRITICAL: Failed to initialize scheduler. Reminders will not run automatically. Error: {e}")


if __name__ == '__main__':
    # Use Gunicorn in production
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)), debug=True)
else:
    # This block is executed when running with Gunicorn
    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)

    
