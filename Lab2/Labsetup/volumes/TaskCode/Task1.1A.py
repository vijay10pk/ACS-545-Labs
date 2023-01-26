#!/usr/bin/env python3
from scapy.all import *
print("Ready to sniff packets...")
def print_pkt(pkt):
	pkt.show()
pkt = sniff(iface="br-c83e1ac99060", prn=print_pkt)
