from flask import Flask, make_response

app = Flask(__name__)

@app.route("/login", methods=["POST"])
def handle_login_safe(user_token):
    resp = make_response("Login successful")
    # Safe: session cookie with mandatory security flags
    resp.set_cookie("session_token", user_token, httponly=True, secure=True, samesite="Lax")
    return resp
