from flask import Flask, render_template
import json
import os

app = Flask(__name__)

ALERT_FILE = "../alerts.json"

@app.route("/")
def index():
    alerts = []
    if os.path.exists(ALERT_FILE):
        with open(ALERT_FILE, "r") as f:
            for line in f:
                try:
                    alerts.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    continue
    alerts.reverse()  # Show newest first
    return render_template("index.html", alerts=alerts)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
