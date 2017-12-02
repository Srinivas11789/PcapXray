# Import Section - Dependant Module inclusion
from scapy.all import *
import sys
import os
from netaddr import *

class pcapReader():

    def __init__(self, filename):
        # pcap file handle
        self.packets = rdpcap(filename)
        self.packetDB = {}
        self.private_ip_segregation()


    def private_ip_segregation(self):
        sessions = self.packets.sessions()
        for session in sessions:
            for each_session in sessions[session]:
                for packet in each_session:
                        if IPAddress(packet.getlayer(IP).src).is_private():
                            if packet.getlayer(IP).src not in self.packetDB:
                                self.packetDB[packet.getlayer(IP).src] = {}
                                if packet.haslayer(TCP):
                                    if "TCP" not in self.packetDB[packet.getlayer(IP).src]:
                                        self.packetDB[packet.getlayer(IP).src]["TCP"] = {}
                                if packet.haslayer(UDP):
                                    if "UDP" not in self.packetDB[packet.getlayer(IP).src]:
                                        self.packetDB[packet.getlayer(IP).src]["UDP"] = {}
                        if IPAddress(packet.getlayer(IP).dst).is_private():
                            if packet.getlayer(IP).dst not in self.packetDB:
                                self.packetDB[packet.getlayer(IP).dst] = {}
                                if packet.haslayer(TCP):
                                    if "TCP" not in self.packetDB[packet.getlayer(IP).dst]:
                                        self.packetDB[packet.getlayer(IP).dst]["TCP"] = {}
                                if packet.haslayer(UDP):
                                    if "UDP" not in self.packetDB[packet.getlayer(IP).dst]:
                                        self.packetDB[packet.getlayer(IP).dst]["UDP"] = {}
                                        """
                                        self.packetDB[packet.getlayer(IP).src]["UDP"]["packets"] = {}
                                        self.packetDB[packet.getlayer(IP).src]["UDP"]["server_addresses"] = {}
                                        self.packetDB[packet.getlayer(IP).src]["UDP"]["payloadExchange"] = {}
                                        """

    def fetch_specific_protocol(self, ip, layer, protocol):
        # Protocol Packet Store
        #self.packetDB[protocol] = []
        #self.payloadExchange[protocol] = []
        #self.server_addresses[protocol] = []
        # Protocol with Well Known Ports
        if protocol not in self.packetDB[ip][layer]:
            self.packetDB[layer][protocol] = {}
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
                    if (packet.haslayer(layer)):
                        if packet[layer].dport == port or packet[layer].sport == port:
                            if "packets" not in self.packetDB[layer][protocol]:
                                self.packetDB[layer][protocol]["packets"] = []
                            self.packetDB[layer][protocol]["packets"].append(packet)
                            # Only for HTTP and HTTPS
                            if packet.haslayer(Raw):
                                if "payloads" not in self.packetDB[layer][protocol]:
                                    self.packetDB[layer][protocol]["payloads"] = []
                                self.packetDB[layer][protocol]["payloads"].append("\n".join(packet.sprintf("{Raw:%Raw.load%}\n").split(r"\r\n")))
                        #Destination Server Address
                        if packet[layer].dport == port:
                            if "server_addresses" not in self.packetDB[layer][protocol]:
                                self.packetDB[layer][protocol]["server_addresses"] = []
                                self.packetDB[layer][protocol]["server_addresses"].append(packet.getlayer(IP).dst)
                            self.packetDB[layer][protocol]["server_addresses"] = list(set(self.server_addresses[protocol]))
                    else:
                        return None

# Module Driver
def main():
    pcapfile = pcapReader('test.pcap')
    for ip in pcapfile.packetDB:
        pcapfile.fetch_specific_protocol(ip, "TCP","HTTPS")
    print pcapfile.packetDB


main()
