# Import Section - Dependant Module inclusion
from scapy.all import *
import sys
import os

class pcapReader():

    def __init__(self, filename):
        # pcap file handle
        self.packets = rdpcap(filename)

    def fetch_specific_protocol(self, protocol):
        # Packet Iteration
        for packet in self.packets:
            if packet.haslayer(protocol):
                if isinstance(packet.answer, protocol):
                    return packet.answer
                else:
                    return None



# Module Driver

def main():
    pcapfile = pcapReader('test.pcap')
    print pcapfile.fetch_specific_protocol("HTTP")


def __init__():
    main()





