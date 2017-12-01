# Import Section - Dependant Module inclusion
from scapy.all import *
import sys
import os

class pcapReader():

    def __init__(self, filename):
        # pcap file handle
        self.packets = rdpcap(filename)
        self.packetDB = {}
        self.payloadExchange = {}
        self.server_addresses = {}


    def fetch_specific_protocol(self, layer, protocol):
        # Protocol Packet Store
        self.packetDB[protocol] = []
        self.payloadExchange[protocol] = []
        self.server_addresses[protocol] = []
        # Protocol with Well Known Ports
        if protocol == "HTTP":
            port = 80
        elif protocol == "HTTPS":
            port = 443
        else:
            port = None
        # Packet Iteration
        sessions = self.packets.sessions()
        for session in sessions:
            for each_session in sessions[session]:
                for packet in each_session:
                    #print packet.show()
                    if (packet.haslayer(layer)):
                        if packet[layer].dport == port or packet[layer].sport == port:
                            self.packetDB[protocol].append(packet)
                            if packet.haslayer(Raw):
                                self.payloadExchange[protocol].append("\n".join(packet.sprintf("{Raw:%Raw.load%}\n").split(r"\r\n")))
                        if packet[layer].dport == port:
                            self.server_addresses[protocol].append(packet.getlayer(IP).dst)

# Module Driver
def main():
    pcapfile = pcapReader('test.pcap')
    pcapfile.fetch_specific_protocol("TCP","HTTP")
    print pcapfile.server_addresses


main()
