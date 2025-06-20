import sqlite3
from datetime import datetime

def log_spoof_attempt(ip, mac, reason):
    conn = sqlite3.connect("spoof_logs.db")
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO spoof_logs (detected_at, suspected_ip, suspected_mac, reason)
        VALUES (?, ?, ?, ?)
    """, (datetime.now().isoformat(), ip, mac, reason))
    conn.commit()
    conn.close()

# Sample test data
log_spoof_attempt("192.168.1.101", "11:22:33:44:55:66", "MAC not in trusted list")
