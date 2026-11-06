from flask import Flask

app = Flask(__name__)
app.config['DEBUG'] = False

@app.route("/")
def index():
    return "Hello Safe"
