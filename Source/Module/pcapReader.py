# Import Section - Dependant Module inclusion
from scapy.all import *
import sys
import os

class pcapReader():

    def __init__(self, filename):
        # pcap file handle
        self.packets = rdpcap(filename)

    def fetch_specific_protocol(self, layer, protocol):
        # Packet Iteration
        if protocol == "HTTP":
            port = 80
        elif protocol == "HTTPS":
            port = 443
        else:
            port = None
        for session in self.packets.sessions():
            for packet in self.packets.sessions()[session]:
                    if layer.upper() == "TCP":
                        if (packet.haslayer(TCP)):
                            if packet[TCP].dport == port or packet[TCP].sport == port:
                                    if packet.haslayer(Raw):
                                        payload = packet.getlayer(Raw).load
                                        print "\n".join(packet.sprintf("{Raw:%Raw.load%}\n").split(r"\r\n"))
                                        #for item in payloads:
                                        #    print item.decode('hex')
                            else:
                                    return None

# Module Driver
def main():
    pcapfile = pcapReader('test.pcap')
    print pcapfile.fetch_specific_protocol("TCP","HTTPS")

main()






