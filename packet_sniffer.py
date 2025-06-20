from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP

def process_packet(packet):
    if Ether in packet:
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
        protocol = "Unknown"

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            if TCP in packet:
                protocol = "TCP"
            elif UDP in packet:
                protocol = "UDP"
            elif ICMP in packet:
                protocol = "ICMP"

            print(f"[+] Protocol: {protocol} | MAC: {src_mac} -> {dst_mac} | IP: {src_ip} -> {dst_ip}")
        else:
            print(f"Ethernet Frame: MAC {src_mac} -> {dst_mac} | No IP Layer")

# Replace 'wlan0' with your actual interface name (use 'ip a' to check)
sniff(iface="wlan0", prn=process_packet, store=False)
