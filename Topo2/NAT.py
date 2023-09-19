#!/usr/bin/env python

from scapy.all import *
from scapy.layers.inet import TCP, UDP, ICMP, IP
from scapy.layers.l2 import Ether
from Tabela import Tabela

table = Tabela()

def whichProtocol(pkt):
    if pkt.haslayer(TCP):
        return TCP
    elif pkt.haslayer(ICMP):
        return ICMP
    elif pkt.haslayer(UDP):
        return UDP
    else:
        return None

def printInfo(pkt):
    print(f"IP src: {pkt[IP].src}")
    print(f"IP dst: {pkt[IP].dst}")
    protocol = whichProtocol(pkt)
    print(protocol)
    if protocol == "ICMP":
        print(f"IP id: {pkt[ICMP].id}")
    elif protocol != None:
        print(f"IP sport: {pkt[protocol].sport}")
        print(f"IP dport: {pkt[protocol].dport}")
    else:
        print("Bosta cu merda mijo")


def NAT(pkt):
    if pkt.sniffed_on == 'r-eth1': #server -> host (pacote tah voltando)
        pkt[IP].src = get_if_addr(conf.iface)
        protocol = whichProtocol(pkt)
        for reg in table.registros:
            if (protocol != None and protocol != ICMP) and reg.portPriv == pkt[protocol].sport:
                pkt[protocol].sport = pkt[protocol].dport #inverte as porta
                pkt[protocol].dport = reg.portPriv
                pkt[IP].dst = reg.endPriv #coloca o endereco do host
        sendp(pkt, iface='r-eth0')
    else:
        table.adicionar(pkt)
        pkt[IP].src = get_if_addr(conf.iface)
        sendp(pkt, iface='r-eth1')
    table.Print()
        
    
    



sniff(iface=["r-eth0","r-eth1"], filter='ip',  prn=NAT)