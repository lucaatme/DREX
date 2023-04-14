# from telnetlib import IP
from scapy.all import *

target = str(sys.argv[1])
packet = scapy.IP(dst=target) / scapy.TCP(flags="")
res = sr1(packet, timeout=5, verbose=0)

if res is None:
    print("OS is Linux")
else:
    if scapy.IP in res:
        if res.getlayer(scapy.IP).ttl <= 64:
            print("OS is Linux")
        else:
            print(res.getlayer(scapy.IP).ttl)
            print("OS is Windows")
