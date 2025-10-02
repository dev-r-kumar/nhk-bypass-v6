from flask import Flask, redirect
from threading import Thread
from flask_cors import CORS

app = Flask("")
CORS(app)

@app.route("/")
def home():
    return redirect("https://discord.gg/Jgj6Msrem4")


def run():
    app.run(host="0.0.0.0", port=8002)


def keep_alive():
    Thread(target=run).start()

