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
        print(f"{self.endPriv:<15} {self.portPriv:8} {self.endExt:<15} {self.portExt:7} {self.protoTipo.__qualname__}")


class Tabela:
    def __init__(self):
        self.registros = []
    
    def whichProtocol(self, pkt):
        return TCP if pkt.haslayer(TCP) else(UDP if pkt.haslayer(UDP) else None)
    
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
            print("cachorro: ", end='')
            pkt.show2()
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
        if len(self.registros) > 0:
            print(f"  i {'endPriv':<15} portPriv {'endExt':<15} portExt protoTipo")
        i = 1
        for reg in self.registros:
            print(f"{i:3} ", end='')
            reg.Print();
            i += 1;

        print()
