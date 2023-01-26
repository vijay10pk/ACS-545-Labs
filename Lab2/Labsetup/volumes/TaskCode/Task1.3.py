#!/usr/bin/env python3
from scapy.all import *
a = IP()
a.dst=sys.argv[1] #input hostname or ip address
a.ttl = 1 #distance
while True:
	b = ICMP()
	p = a/b
	rp = sr1(p, timeout=2, verbose=0) #wait for response from dst
	if rp  is None:
		print("No Response")
		break
	elif rp [ICMP].type==0: #if it gets the response it will print the number of hops and IP addresses of router it hops through.
		print(f'{a.ttl} hops away:', rp [IP].src)
		print("Done", rp [IP].src)
		break
	else:
		print(f'{a.ttl} hops away: ', rp [IP].src)
	a.ttl+=1  #ttl value is increased and packet is resent 
