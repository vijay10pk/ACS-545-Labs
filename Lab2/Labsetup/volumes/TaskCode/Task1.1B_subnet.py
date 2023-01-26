#!/usr/bin/env python3
from scapy.all import *
print("Ready to sniff packets...")
def print_pkt(pkt):
	pkt.show()
pkt = sniff(iface="br-c83e1ac99060", filter="src net 172.17.0.0/24", prn=print_pkt) #This will sniff packets only the from above mention subnet
