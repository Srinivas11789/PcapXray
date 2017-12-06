# Import Section - Dependant Module inclusion
from scapy.all import *
from netaddr import *

class pcapReader():

    def __init__(self, filename):
        self.file = filename
        self.packets = rdpcap(filename)
        self.packetDB = {}
        self.private_ip_segregation()

# Private IP Segregation or LAN IP Identification Method
# A LAN Map tool to plot from the perspective of LAN Hosts
# Build a JSON Database of Private IPS
    def private_ip_segregation(self):
                for packet in self.packets:
                    if packet.haslayer(IP):
                        if IPAddress(packet.getlayer(IP).src).is_private():
                            if packet.getlayer(IP).src not in self.packetDB:
                                self.packetDB[packet.getlayer(IP).src] = {}
                            if packet.haslayer(TCP) and "TCP" not in self.packetDB[packet.getlayer(IP).src]:
                                self.packetDB[packet.getlayer(IP).src]["TCP"] = {}
                            if packet.haslayer(UDP) and "UDP" not in self.packetDB[packet.getlayer(IP).src]:
                                self.packetDB[packet.getlayer(IP).src]["UDP"] = {}
                            if packet.haslayer(Ether) and "Ethernet" not in self.packetDB[packet.getlayer(IP).src]:
                                self.packetDB[packet.getlayer(IP).src]["Ethernet"] = packet.getlayer(Ether).src
                            if packet.haslayer
                        if IPAddress(packet.getlayer(IP).dst).is_private():
                            if packet.getlayer(IP).dst not in self.packetDB:
                                self.packetDB[packet.getlayer(IP).dst] = {}
                            if packet.haslayer(TCP) and "TCP" not in self.packetDB[packet.getlayer(IP).dst]:
                                self.packetDB[packet.getlayer(IP).dst]["TCP"] = {}
                            if packet.haslayer(UDP) and "UDP" not in self.packetDB[packet.getlayer(IP).dst]:
                                self.packetDB[packet.getlayer(IP).dst]["UDP"] = {}
                            if packet.haslayer(Ether) and "Ethernet" not in self.packetDB[packet.getlayer(IP).dst]:
                                self.packetDB[packet.getlayer(IP).dst]["Ethernet"] = packet.getlayer(Ether).dst


# Sniff Packets with Filter
    def packet_filter(self, ipaddress="", protocol="", port=""):
        if ipaddress is not "":
            filter = "host "+ipaddress
        if protocol is not "":
            filter = filter+" and "+protocol
        if port is not "":
            filter = filter+" and "+"port "+port
        return sniff(offline=self.file, filter=filter)

# Populate the JSON database for specific protocols
    def populate(self, protocol):
        if protocol == "HTTP":
            port = 80
        for ip in self.packetDB:
            if protocol not in self.packetDB[ip]:
                self.packetDB[ip][protocol] = {}
            self.packetDB[ip][protocol] = self.packet_filter(ip, port=80)

# Module Driver
def main():
    pcapfile = pcapReader('lanExample.pcap')
    print pcapfile.packetDB
    pcapfile.populate("HTTP")
    print pcapfile.packetDB

main()
