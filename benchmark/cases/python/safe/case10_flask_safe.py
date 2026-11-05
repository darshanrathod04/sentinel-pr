from flask import Flask, render_template

app = Flask(__name__)

@app.route("/greeting")
def greeting_safe():
    return render_template("greeting.html", user="Guest")
