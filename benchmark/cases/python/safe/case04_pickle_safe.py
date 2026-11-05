import json

def restore_session_state_safe(raw_cookie_json):
    session = json.loads(raw_cookie_json)
    return session
