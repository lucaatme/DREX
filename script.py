from scapy.all import *
import os
import sys
import argparse


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

def choose_recon():
    #clear the screen
    os.system("clear")
    print("\n")
    print("-----------------------------------------------------------------------------------------------------")
    string = '''/  __\\/  __//   _\\/  _ \\/ \\  /|/ \\  /|/  _ \\/ \\/ ___\\/ ___\\/  _ \\/ \\  /|/   _\\/  __/
|  \\/||  \\  |  /  | / \\|| |\\ ||| |\\ ||| / \\|| ||    \\|    \\| / \\|| |\\ |||  /  |  \\  
|    /|  /_ |  \\_ | \\_/|| | \\||| | \\||| |-||| |\\___ |\\___ || |-||| | \\|||  \\_ |  /_ 
\\_/\\_\\\\____\\\\____/\\____/\\_/  \\|\\_/  \\|\\_/ \\|\\_/\\____/\\____/\\_/ \\|\\_/  \\|\\____/\\____\\'''

    print(string)
    print("-----------------------------------------------------------------------------------------------------")
    print("Choose a reconnaissance attack.")
    print("1. OS Detection")
    print("2. Port Scanning")
    print("3. Ip Spoof Testing")
    print("4. Active Hosts in Network")
    print("5. Exit")
    print("-----------------------------------")
    choice = input("Enter your choice: ")
    if choice == "1":
        os_detection()
    elif choice == "2":
        port_scanning()
    elif choice == "3":
        ip_spoof()
    elif choice == "4":
        ip_sweep()
    elif choice == "5":
        print("Back to main menu.")
        os.system("clear")
        main()
    else:
        print("Invalid choice. Try again.")
        choose_recon()
 

def main():
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