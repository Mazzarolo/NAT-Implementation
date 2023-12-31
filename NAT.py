#!/usr/bin/env python

from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from Tabela import *
from datetime import datetime

import os

os.system('ifconfig r-eth0 mtu 10000 up && ifconfig r-eth1 mtu 10000 up')

table = Tabela()

conf.verb = 0

def printInfo(pkt):
    print(f"IP src: {pkt[IP].src}")
    print(f"IP dst: {pkt[IP].dst}")
    protocol = table.whichProtocol(pkt)
    print(protocol)
    if protocol != None:
        print(f"IP sport: {pkt[protocol].sport}")
        print(f"IP dport: {pkt[protocol].dport}")
    else:
        print("cachorro")

counter = 0

def NAT(pkt):
    routerIp = '8.8.254.254'
    protocol = table.whichProtocol(pkt)
    pkt[Ether].src = None
    pkt[Ether].dst = None

    if pkt.sniffed_on == 'r-eth1': #server -> host (pacote tah voltando)
        for reg in table.registros:
            if protocol != None and reg.portPriv == pkt[protocol].sport:
                pkt[IP].chksum = None
                pkt[IP].len = None
                pkt[protocol].chksum = None
                pkt[protocol].sport = pkt[protocol].dport
                pkt[protocol].dport = reg.portPriv
                pkt[IP].dst = reg.endPriv
                pkt[IP].src = reg.endExt
                
                table.registros.remove(reg)
        
        sendp(pkt, verbose=0, iface='r-eth0')
    elif pkt[IP].src != routerIp and pkt[IP].src[0] != '8':
        table.adicionar(pkt, pkt[protocol].sport, pkt[protocol].dport)
        pkt[IP].src = routerIp
        sendp(pkt, iface='r-eth1')
    global counter
    counter += 1
    if counter > 100:
        print(f"[{datetime.now()}]")
        counter = 0
        table.Print()
    #print('source = ', pkt[IP].src)
    #print('destiny = ', pkt[IP].dst)

sniff(iface=["r-eth0","r-eth1"], filter='ip',  prn=NAT)
