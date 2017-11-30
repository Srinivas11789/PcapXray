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


    def fetch_specific_protocol(self, layer, protocol):
        # Protocol Packet Store
        self.packetDB[protocol] = []
        self.payloadExchange[protocol] = []
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
                    if (packet.haslayer(TCP)):
                        if packet[TCP].dport == port or packet[TCP].sport == port:
                            self.packetDB[protocol].append(packet)
                            if packet.haslayer(Raw):
                                payload = packet.getlayer(Raw).load
                                self.payloadExchange[protocol].append("\n".join(packet.sprintf("{Raw:%Raw.load%}\n").split(r"\r\n")))
                    else:
                        return None

# Module Driver
def main():
    pcapfile = pcapReader('test.pcap')
    print pcapfile.fetch_specific_protocol("TCP","HTTP")

main()
