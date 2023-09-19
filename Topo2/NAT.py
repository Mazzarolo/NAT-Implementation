#!/usr/bin/env python

from scapy.all import *
from scapy.layers.inet import TCP, UDP, ICMP, IP
from scapy.layers.l2 import Ether
from Tabela import Tabela

table = Tabela()

def whichProtocol(pkt):
    if pkt.haslayer(TCP):
        return "TCP"
    elif pkt.haslayer(ICMP):
        return "ICMP"
    elif pkt.haslayer(UDP):
        return "UDP"
    else:
        return "Outros"

def printInfo(pkt):
    print(f"IP src: {pkt[IP].src}")
    print(f"IP dst: {pkt[IP].dst}")
    protocol = whichProtocol(pkt)
    print(protocol)
    if protocol == "ICMP":
        print(f"IP id: {pkt[ICMP].id}")
    elif protocol == "TCP":
        print(f"IP sport: {pkt[TCP].sport}")
        print(f"IP dport: {pkt[TCP].dport}")
    elif protocol == "UDP":
        print(f"IP sport: {pkt[UDP].sport}")
        print(f"IP dport: {pkt[UDP].dport}")
    else:
        print("Bosta cu merda mijo")


def NAT(pkt):
    """
    pkt.show()
    if pkt.sniffed_on == 'r-eth1' and pkt[IP].dst == '10.1.1.1':
        print("Host 1")
        pkt[Ether].dst = None
        sendp(pkt, iface='r-eth2')
    elif pkt.sniffed_on == 'r-eth2' and pkt[IP].dst == '8.8.8.8':
        print("Host 2")
        pkt[Ether].dst = None
        sendp(pkt, iface='r-eth1')
    else:
        return
    """
    table.adicionar(pkt)
    table.Print()



sniff(iface=["r-eth0","r-eth1"], filter='ip',  prn=NAT)