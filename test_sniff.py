from scapy.all import sniff, ARP

def show_arp(pkt):
    if pkt.haslayer(ARP):
        print(f"ARP Packet: {pkt.summary()}")

print("[*] Sniffing ARP packets...")
sniff(filter="arp", store=0, prn=show_arp)
