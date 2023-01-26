#!/usr/bin/env python3
from scapy.all import *
print("Sending spoofed packets...")
a = IP()
a.src = '10.9.0.9' #arbitary attacker IP address
a.dst = '10.9.0.5' #HostA IP address
b = ICMP()
p = a/b # the division operator signifies that ICMP as payload of IP
p.show()
send(p, verbose=0)
