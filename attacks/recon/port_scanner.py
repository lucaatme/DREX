import sys
from scapy.all import *

target = str(sys.argv[1])

src_port = RandShort()
ports_list = [20, 21, 22, 23, 25, 50, 51, 53, 67, 68, 69, 80,
              110, 119, 123, 139, 143, 161, 162, 289, 443, 989, 990, 3389]

for port in ports_list:

    tcp_connect_scan_resp = sr1(scapy.IP(
        dst=target)/scapy.TCP(sport=src_port, dport=port, flags="S"), timeout=2, verbose=0)

    if (type(tcp_connect_scan_resp) is None):
        pass
    elif (tcp_connect_scan_resp.haslayer(scapy.TCP)):
        if (tcp_connect_scan_resp.getlayer(scapy.TCP).flags == 0x12):
            send_rst = sr(scapy.IP(dst=target)/scapy.TCP(sport=src_port,
                          dport=port, flags="AR"), timeout=2, verbose=0)
            print("Port " + str(port) + " is open")
    elif (tcp_connect_scan_resp.getlayer(scapy.TCP).flags == 0x14):
        pass
