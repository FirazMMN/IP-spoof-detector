from flask import Flask, render_template, jsonify
import sqlite3

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/logs")
def get_logs():
    conn = sqlite3.connect("spoof_logs.db")
    cursor = conn.cursor()
    cursor.execute("SELECT detected_at, suspected_ip, suspected_mac, reason FROM spoof_logs ORDER BY detected_at DESC")
    logs = cursor.fetchall()
    conn.close()
    return jsonify(logs)

if __name__ == "__main__":
    app.run(debug=True)

