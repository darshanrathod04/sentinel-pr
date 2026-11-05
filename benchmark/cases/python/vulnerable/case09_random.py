import random

def generate_session_token():
    token = random.randint(10000000, 99999999)
    return str(token)
