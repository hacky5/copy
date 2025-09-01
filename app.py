# app.py

import os
import json
from flask import Flask, jsonify, request
...
# HISTORY
@app.route('/api/history', methods=['GET', 'DELETE'])
@token_required
def handle_history(current_user):
    if request.method == 'GET':
        history_json = redis.get('communication_history')
        history = json.loads(history_json) if history_json else []
        return jsonify(history)

    if request.method == 'DELETE':
        @role_required(['superuser'])
        def delete(current_user):
            data = request.get_json()
            ids_to_delete = data.get('history_ids', [])
            if not ids_to_delete:
                return jsonify({'message': 'No history IDs provided'}), 400

            history_json = redis.get('communication_history')
            history = json.loads(history_json) if history_json else []
            
            original_len = len(history)
            history = [item for item in history if item.get('id') not in ids_to_delete]

            if len(history) == original_len:
                return jsonify({'message': 'No matching history items found to delete'}), 404
            
            redis.set('communication_history', json.dumps(history))
            add_log_entry(current_user['email'], f"Deleted {original_len - len(history)} history item(s)")
            return jsonify({'message': 'History items deleted successfully'})
        return delete(current_user)

# ADMINS
@app.route('/api/admins', methods=['GET', 'POST'])
...