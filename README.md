# Introduction

These labs encompass a variety of prevalent network attack techniques and vulnerabilities. Additionally, they explore diverse defense mechanisms such as intrusion detection, firewalls, tracing attack sources, anonymous communication, and MITM attacks.

# Mitnick Attack Lab

Kevin Mitnick, one of the most renowned hackers in history, gained fame in 1994 for exploiting vulnerabilities in the TCP protocol and the trusted relationship between two of Shimomura's computers. This successful attack led to a dramatic confrontation between them and eventually resulted in Mitnick's arrest. The incident was later adapted into books and Hollywood movies. Known as the Mitnick attack, it involves a unique type of TCP session hijacking.

The purpose of this lab is to recreate the iconic Mitnick attack, allowing students to experience it firsthand. We will replicate the original settings on Shimomura's computers and launch the Mitnick attack to forge a TCP session between the two machines. If the attack is successful, we will be able to execute commands on Shimomura's computer.




![Logo](https://media.npr.org/assets/img/2011/06/11/95607ghostinsert-92b5ccb5216fee162daf7a58c2023e50bfde8218-s1100-c50.jpg)

# Content
In these labs, various essential concepts in network security are explored, focusing on both common attack techniques and vulnerabilities, as well as defense mechanisms. Here's a summary of each lab:

1. Sniffing and Spoofing:
This lab delves into packet sniffing and spoofing, fundamental threats in network communication. Participants learn to use tools like Wireshark and gain insights into their workings. Both C and Python (Scapy) programs are developed to perform sniffing and spoofing.

2. ARP Cache Poisoning Attack:
The Address Resolution Protocol (ARP) vulnerability is exploited in this lab. Attackers manipulate ARP to deceive victims into accepting forged IP-to-MAC mappings, redirecting their packets to a computer with a spoofed MAC address.

3. IP Attacks:
This lab focuses on Layer 3 vulnerabilities, exploring fragmentation and executing attacks like DOS, Ping-of-death, Teardrop, and ICMP redirect. Participants learn to exploit these vulnerabilities.

4. TCP Attacks:
The lab demonstrates vulnerabilities in TCP/IP protocols, emphasizing the importance of designing security from the start. Participants gain insights into network security challenges and the necessity of robust security measures.

5. Mitnick Attack:
This lab replicates the TCP Session Hijacking attack executed by Kevin Mitnick. By exploiting trust relationships between servers, a backdoor is planted on a sensitive machine, granting unrestricted access.

# Reference
1. https://www.npr.org/2011/06/11/137125799/hackers-and-clouds-how-secure-is-the-web 
2. https://seedsecuritylabs.org/Labs_16.04/Networking/Mitnick_Attack/



