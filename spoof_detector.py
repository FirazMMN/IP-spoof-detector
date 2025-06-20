from scapy.all import sniff, ARP
import sqlite3
from datetime import datetime

def load_trusted_devices():
    conn = sqlite3.connect("trusted_devices.db")
    cursor = conn.cursor()
    cursor.execute("SELECT ip, mac FROM trusted_list")
    trusted = cursor.fetchall()
    conn.close()
    return {ip: mac.lower() for ip, mac in trusted}

def log_spoof_attempt(ip, mac, reason):
    conn = sqlite3.connect("spoof_logs.db")
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO spoof_logs (detected_at, suspected_ip, suspected_mac, reason)
        VALUES (?, ?, ?, ?)
    """, (datetime.now().isoformat(), ip, mac, reason))
    conn.commit()
    conn.close()

def detect_spoof(pkt):
    if pkt.haslayer(ARP) and pkt[ARP].op == 2:
        ip = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc.lower()

        print(f"[✓] ARP Reply from IP: {ip} | MAC: {mac}")

        if ip in trusted_devices:
            if mac != trusted_devices[ip]:
                reason = f"MAC mismatch for IP {ip} (expected {trusted_devices[ip]}, got {mac})"
                print(f"[!] SPOOFING DETECTED: {reason}")
                log_spoof_attempt(ip, mac, reason)
        else:
            print(f"[!] Unrecognized IP {ip} — not in trusted list")

trusted_devices = load_trusted_devices()
print("[*] Starting real-time ARP spoof detection...")
sniff(filter="arp", store=0, prn=detect_spoof)
