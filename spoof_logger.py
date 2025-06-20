from scapy.all import sniff, Ether, IP
import sqlite3

# Connect to SQLite database
conn = sqlite3.connect("trusted_devices.db", check_same_thread=False)
cursor = conn.cursor()

# Function to check trusted MAC-IP
def is_trusted(mac, ip):
    cursor.execute("SELECT * FROM trusted_list WHERE mac=? AND ip=?", (mac, ip))
    return cursor.fetchone() is not None

# Function to log spoofing attempts
def log_spoof(mac, ip):
    cursor.execute("INSERT INTO spoof_log (mac, ip) VALUES (?, ?)", (mac, ip))
    conn.commit()

# Callback for each sniffed packet
def process_packet(packet):
    if Ether in packet and IP in packet:
        src_mac = packet[Ether].src
        src_ip = packet[IP].src
        if is_trusted(src_mac, src_ip):
            print(f"[OK] Trusted: {src_mac} -> {src_ip}")
        else:
            print(f"[ALERT] Spoofing Detected! {src_mac} -> {src_ip}")
            log_spoof(src_mac, src_ip)

# Start sniffing
sniff(iface="wlan0", prn=process_packet, store=False)
