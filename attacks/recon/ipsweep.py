import sys
from scapy.all import *
from ipaddress import IPv4Network
from struct import pack

# Defines network to analyze
network = str(sys.argv[1])

print("Analyzing hosts in network " + network)

# make list of addresses out of network, set live host counter
def sweep(i):
    index = int(i)
    counter = index-63
    addresses = IPv4Network(network)
    # Send ICMP ping request, wait for answer
    for j in range (counter, index):
        #sr1() is a function that generates and sends packets and assigns to a variable a certain state 
        #depending from the fact that the packet/s sent did/did not receive an answer.
        resp = sr1(IP(dst=str(addresses[j]))/ICMP(), timeout=0.01, verbose = 0)
        if resp is None:
            pass
        else:
            print(f"{addresses[j]} is responding.")        

t1 = threading.Thread(target=sweep, args = ("64",))
t2 = threading.Thread(target=sweep, args = ("128",))
t3 = threading.Thread(target=sweep, args = ("192",))
t4 = threading.Thread(target=sweep, args = ("256",))

t1.start()
t2.start()
t3.start()
t4.start()