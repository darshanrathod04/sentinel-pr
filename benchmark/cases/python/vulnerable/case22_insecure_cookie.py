from flask import Flask, make_response

app = Flask(__name__)

@app.route("/login", methods=["POST"])
def handle_login(user_token):
    resp = make_response("Login successful")
    # Insecure: session_token cookie missing HttpOnly and Secure flags
    resp.set_cookie("session_token", user_token)
    return resp
