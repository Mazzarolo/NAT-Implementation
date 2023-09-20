from scapy.all import *
from scapy.layers.inet import TCP, UDP, IP

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
        elif pkt.haslayer(UDP):
            return UDP
        else:
            return None
    
    def jaExiste(self, portPriv):
        for reg in self.registros:
            if reg.portPriv == portPriv:
                return True
        return False

    def getInfo(self, pkt, priv, ext):
        endPriv = pkt[IP].src
        endExt = pkt[IP].dst
        protocol = self.whichProtocol(pkt)
        if protocol != None:
            portPriv = priv
            portExt = ext
        else:
            print("Bosta cu merda mijo")
            return None
        if not self.jaExiste(portPriv):
            novoRegistro = Registro(endPriv, portPriv, endExt, portExt, protocol)
            return novoRegistro
        else:
            return None 

    def adicionar(self, pkt, priv, ext):
        novoRegistro = self.getInfo(pkt, priv, ext)
        if novoRegistro != None:
            self.registros.append(novoRegistro)

    def Print(self):
        i = 0
        for reg in self.registros:
            print(i, end=' : ')
            reg.Print();
            i += 1;

        print()