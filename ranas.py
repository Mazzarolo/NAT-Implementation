#!/usr/bin/env python

from scapy.all import *


def ranas(pkt):
    pkt[IP].src = '192.168.0.0'
    pkt.show()




sniff(iface=["r-eth0","r-eth1"], filter='ip',  prn=ranas)