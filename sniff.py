from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
from datetime import datetime
import signal
import sys


stats = {
    "packets": 0,
    "bytes": 0,
    "protocols": defaultdict(int)
}

running = True


def shutdown(sig, frame):
    global running
    running = False
    print("\n\n=== Capture stopped ===")
    print(f"Packets captured: {stats['packets']}")
    print(f"Data captured: {stats['bytes']} bytes")

    print("\nProtocols:")
    for proto, count in stats["protocols"].items():
        print(f"  {proto}: {count}")

    sys.exit(0)


signal.signal(signal.SIGINT, shutdown)


def get_protocol(pkt):
    if pkt.haslayer(TCP):
        return "TCP"
    elif pkt.haslayer(UDP):
        return "UDP"
    elif pkt.haslayer(ICMP):
        return "ICMP"
    return "OTHER"


def process(pkt):

    if not pkt.haslayer(IP):
        return

    ip = pkt[IP]

    proto = get_protocol(pkt)

    size = len(pkt)

    stats["packets"] += 1
    stats["bytes"] += size
    stats["protocols"][proto] += 1


    timestamp = datetime.now().strftime("%H:%M:%S")


    src = ip.src
    dst = ip.dst


    ports = ""

    if pkt.haslayer(TCP) or pkt.haslayer(UDP):
        ports = f":{pkt.sport} → :{pkt.dport}"


    print(
        f"[{timestamp}] "
        f"{proto:<5} "
        f"{src}{ports} → {dst} "
        f"({size} bytes)"
    )



print("Starting packet monitor...")
print("Press CTRL+C to stop\n")


sniff(
    prn=process,
    store=False,
    filter="ip"
)