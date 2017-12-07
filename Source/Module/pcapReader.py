# Import Section - Dependant Module inclusion
from scapy.all import *
from netaddr import *

class pcapReader():

    def __init__(self, filename):
        self.file = filename
        self.packets = rdpcap(filename)
        self.packetDB = {}
        self.read_pcap_and_fill_db()

# Private IP Segregation or LAN IP Identification Method
# A LAN Map tool to plot from the perspective of LAN Hosts
# Build a JSON Database of Private IPS
    def read_pcap_and_fill_db(self):
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
                            if packet.haslayer(TCP) and packet.getlayer(TCP).dport == 80:
                                if "HTTP" not in self.packetDB[packet.getlayer(IP).src]["TCP"]:
                                    self.packetDB[packet.getlayer(IP).src]["TCP"]["HTTP"] = {}
                                if "Server" not in self.packetDB[packet.getlayer(IP).src]["TCP"]["HTTP"]:
                                    self.packetDB[packet.getlayer(IP).src]["TCP"]["HTTP"]["Server"] = []
                                if "Payload" not in self.packetDB[packet.getlayer(IP).src]["TCP"]["HTTP"]:
                                    self.packetDB[packet.getlayer(IP).src]["TCP"]["HTTP"]["Payload"] = []
                                self.packetDB[packet.getlayer(IP).src]["TCP"]["HTTP"]["Server"].append(packet.getlayer(IP).dst)
                                self.packetDB[packet.getlayer(IP).src]["TCP"]["HTTP"]["Payload"].append(packet)
                            if packet.haslayer(TCP) and packet.getlayer(TCP).dport == 443:
                                if "HTTPS" not in self.packetDB[packet.getlayer(IP).src]["TCP"]:
                                    self.packetDB[packet.getlayer(IP).src]["TCP"]["HTTPS"] = []
                                if packet.getlayer(IP).dst not in self.packetDB[packet.getlayer(IP).src]["TCP"]["HTTPS"]:
                                    self.packetDB[packet.getlayer(IP).src]["TCP"]["HTTPS"].append(packet.getlayer(IP).dst)
                            if packet.haslayer(TCP):
                                if "PortsConnected" not in self.packetDB[packet.getlayer(IP).src]["TCP"]:
                                    self.packetDB[packet.getlayer(IP).src]["TCP"]["PortsConnected"] = []
                                port = packet.getlayer(TCP).dport
                                ip = packet.getlayer(IP).dst
                                if (ip,port) not in self.packetDB[packet.getlayer(IP).src]["TCP"]["PortsConnected"]:
                                    self.packetDB[packet.getlayer(IP).src]["TCP"]["PortsConnected"].append((ip,port))
                            if packet.haslayer(UDP):
                                if "PortsConnected" not in self.packetDB[packet.getlayer(IP).src]["UDP"]:
                                    self.packetDB[packet.getlayer(IP).src]["UDP"]["PortsConnected"] = []
                                port = packet.getlayer(UDP).dport
                                ip = packet.getlayer(IP).dst
                                if (ip,port) not in self.packetDB[packet.getlayer(IP).src]["UDP"]["PortsConnected"]:
                                    self.packetDB[packet.getlayer(IP).src]["UDP"]["PortsConnected"].append((ip,port))

                            #HTTPS
                            #Tor
                            #Malicious
                            # HTTP Payload Decrypt
                        if IPAddress(packet.getlayer(IP).dst).is_private():
                            if packet.getlayer(IP).dst not in self.packetDB:
                                self.packetDB[packet.getlayer(IP).dst] = {}
                            if packet.haslayer(TCP) and "TCP" not in self.packetDB[packet.getlayer(IP).dst]:
                                self.packetDB[packet.getlayer(IP).dst]["TCP"] = {}
                            if packet.haslayer(UDP) and "UDP" not in self.packetDB[packet.getlayer(IP).dst]:
                                self.packetDB[packet.getlayer(IP).dst]["UDP"] = {}
                            if packet.haslayer(Ether) and "Ethernet" not in self.packetDB[packet.getlayer(IP).dst]:
                                self.packetDB[packet.getlayer(IP).dst]["Ethernet"] = packet.getlayer(Ether).dst
                            if packet.haslayer(TCP) and packet.getlayer(TCP).sport == 80:
                                if "HTTP" not in self.packetDB[packet.getlayer(IP).dst]["TCP"]:
                                    self.packetDB[packet.getlayer(IP).dst]["TCP"]["HTTP"] = []
                                if "Server" not in self.packetDB[packet.getlayer(IP).dst]["TCP"]["HTTP"]:
                                    self.packetDB[packet.getlayer(IP).dst]["TCP"]["HTTP"]["Server"] = []
                                if "Payload" not in self.packetDB[packet.getlayer(IP).dst]["TCP"]["HTTP"]:
                                    self.packetDB[packet.getlayer(IP).dst]["TCP"]["HTTP"]["Payload"] = []
                                self.packetDB[packet.getlayer(IP).dst]["TCP"]["HTTP"]["Server"].append(packet.getlayer(IP).src)
                                self.packetDB[packet.getlayer(IP).dst]["TCP"]["HTTP"]["Payload"].append(packet)
                            if packet.haslayer(TCP) and packet.getlayer(TCP).sport == 443:
                                if "HTTPS" not in self.packetDB[packet.getlayer(IP).dst]["TCP"]:
                                    self.packetDB[packet.getlayer(IP).dst]["TCP"]["HTTPS"] = []
                                if packet.getlayer(IP).src not in self.packetDB[packet.getlayer(IP).dst]["TCP"]["HTTPS"]:
                                    self.packetDB[packet.getlayer(IP).dst]["TCP"]["HTTPS"].append(packet.getlayer(IP).src)
                            if packet.haslayer(TCP):
                                if "PortsConnected" not in self.packetDB[packet.getlayer(IP).dst]["TCP"]:
                                    self.packetDB[packet.getlayer(IP).dst]["TCP"]["PortsConnected"] = []
                                port = packet.getlayer(TCP).sport
                                ip = packet.getlayer(IP).src
                                if (ip,port) not in self.packetDB[packet.getlayer(IP).dst]["TCP"]["PortsConnected"]:
                                    self.packetDB[packet.getlayer(IP).dst]["TCP"]["PortsConnected"].append((ip,port))
                            if packet.haslayer(UDP):
                                if "PortsConnected" not in self.packetDB[packet.getlayer(IP).dst]["UDP"]:
                                        self.packetDB[packet.getlayer(IP).dst]["UDP"]["PortsConnected"] = []
                                port = packet.getlayer(UDP).sport
                                ip = packet.getlayer(IP).src
                                if (ip, port) not in self.packetDB[packet.getlayer(IP).dst]["UDP"]["PortsConnected"]:
                                    self.packetDB[packet.getlayer(IP).dst]["UDP"]["PortsConnected"].append((ip, port))


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
#main()
