#!/usr/bin/env python

from scapy.all import *

def example(pkt):
        pkt.show()
        sendp(pkt)

sniff(prn=example)