from scapy.all import *
from scapy.layers.inet import TCP, UDP, ICMP, IP
from scapy.layers.l2 import Ether

class Registro:
    def __init__(self, endPriv, portPriv, endExt, portExt, protoTipo):  # para fazer:
        self.endPriv = endPriv;                                         "fazer timeout"
        self.portPriv = portPriv
        self.endExt = endExt;
        self.portExt = portExt
        self.protoTipo = protoTipo;

    def Print(self):
        print(self.endPriv, self.portPriv, self.endExt, self.portExt, self.protoTipo)


class Tabela:
    def __init__(self):
        self.registros = []
    
    def whichProtocol(self, pkt):
        if pkt.haslayer(TCP):
            return TCP
        elif pkt.haslayer(ICMP):
            return ICMP
        elif pkt.haslayer(UDP):
            return UDP
        else:
            return None
    
    def jaExiste(self, portPriv):
        for reg in self.registros:
            if reg.portPriv == portPriv:
                return True
        return False

    def getInfo(self, pkt):
        endPriv = pkt[IP].src
        endExt = pkt[IP].dst
        protocol = self.whichProtocol(pkt)
        if protocol == ICMP:
            portPriv = pkt[ICMP].id
            portExt = pkt[ICMP].id
        elif protocol != None:
            portPriv = pkt[protocol].sport
            portExt = pkt[protocol].dport
        else:
            print("Bosta cu merda mijo")
            return None
        if not self.jaExiste(portPriv):
            novoRegistro = Registro(endPriv, portPriv, endExt, portExt, protocol)
            return novoRegistro
        else:
            return None 

    def adicionar(self, pkt):
        novoRegistro = self.getInfo(pkt)
        if novoRegistro != None:
            self.registros.append(novoRegistro)

    def Print(self):
        i = 0
        for reg in self.registros:
            print(i, end=' : ')
            reg.Print();
            i += 1;

        print()