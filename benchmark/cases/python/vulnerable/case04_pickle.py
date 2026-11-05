import pickle

def restore_session_state(raw_cookie_bytes):
    session = pickle.loads(raw_cookie_bytes)
    return session
