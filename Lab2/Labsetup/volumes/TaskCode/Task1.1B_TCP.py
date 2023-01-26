#!/usr/bin/env python3
from scapy.all import *
print("Ready to sniff packets...")
def print_pkt(pkt):
	pkt.show()
pkt = sniff(iface="br-c83e1ac99060", filter="tcp and src host 10.9.0.5 and dst port 23", prn=print_pkt) #This will sniff only the tcp packets from the mentioned IP and with destination port number of 23
