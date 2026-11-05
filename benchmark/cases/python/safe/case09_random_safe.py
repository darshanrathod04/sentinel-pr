import secrets

def generate_session_token_safe():
    token = secrets.token_hex(32)
    return token
