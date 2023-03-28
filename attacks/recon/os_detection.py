from telnetlib import IP
from scapy.all import *

target = str(sys.argv[1])
packet = IP(dst = target) / TCP(flags = "")
res = sr1(packet, timeout = 5, verbose = 0)

if res is None:
	print("OS is Linux")
else:
	if IP in res:
		if res.getlayer(IP).ttl <= 64:
			print("OS is Linux")
		else:
			print(res.getlayer(IP).ttl)
			print("OS is Windows")