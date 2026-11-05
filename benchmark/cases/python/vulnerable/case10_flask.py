from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/greeting")
def greeting():
    username = request.args.get("name", "Guest")
    template = f"Hello {username}!"
    return render_template_string(template)
