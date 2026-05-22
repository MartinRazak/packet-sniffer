from scapy.all import sniff, IP
import time

last = 0

def process(pkt):
    global last
    if time.time() - last > 0.1:  # 10 packets/sec max
        if pkt.haslayer(IP):
            print(pkt[IP].src, "→", pkt[IP].dst)
        last = time.time()

sniff(prn=process)