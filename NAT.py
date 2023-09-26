#!/usr/bin/env python

from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from Tabela import *

import os

os.system('ifconfig r-eth0 mtu 10000 up && ifconfig r-eth1 mtu 10000 up')

table = Tabela()


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


def NAT(pkt):
    routerIp = get_if_addr(conf.iface)
    protocol = table.whichProtocol(pkt)
    pkt[Ether].src = None
    pkt[Ether].dst = None
    pkt[IP].chksum = None
    pkt[protocol].chksum = None
    if pkt.sniffed_on == 'r-eth1': #server -> host (pacote tah voltando)
        for reg in table.registros:
            if protocol != None and reg.portPriv == pkt[protocol].sport:
                pkt[protocol].sport = pkt[protocol].dport
                pkt[protocol].dport = reg.portPriv
                pkt[IP].dst = reg.endPriv
                pkt[IP].src = reg.endExt
                table.registros.remove(reg)

        sendp(pkt, iface='r-eth0')
    else:
        if pkt[IP].src != routerIp and pkt[IP].src[0] != '8':
            table.adicionar(pkt, pkt[protocol].sport, pkt[protocol].dport)
        pkt[IP].src = routerIp

        sendp(pkt, iface='r-eth1')
    table.Print()
    #print('source = ', pkt[IP].src)
    #print('destiny = ', pkt[IP].dst)
    



sniff(iface=["r-eth0","r-eth1"], filter='ip',  prn=NAT)
