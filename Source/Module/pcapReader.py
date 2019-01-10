# Import Section - Dependant Module inclusion
from scapy.all import *
from netaddr import *

class pcapReader():

    def __init__(self, filename, out=None):
        self.file = filename
        self.packets = rdpcap(filename)
        self.packetDB = {}
        # Gateway calculate for the LAN
        self.highest_ethernet_destination = {}
        self.packetDB["gateway_mac"] = ""
        self.packetDB["gateway_ip"] = ""
        self.read_pcap_and_fill_db()
        if out:
            out.put(self.packetDB)
        self.find_gateway()

# Private IP Segregation or LAN IP Identification Method
# A LAN Map tool to plot from the perspective of LAN Hosts
# Build a JSON Database of Private IPS
    def read_pcap_and_fill_db(self):
                for packet in self.packets:
                    if packet.haslayer(IP) and (packet.haslayer(TCP) or packet.haslayer(UDP)):
                        if IPAddress(packet.getlayer(IP).src).is_private():
                            if packet.getlayer(IP).src not in self.packetDB:
                                self.packetDB[packet.getlayer(IP).src] = {}
                            if packet.haslayer(TCP) and "TCP" not in self.packetDB[packet.getlayer(IP).src]:
                                self.packetDB[packet.getlayer(IP).src]["TCP"] = {}
                            if packet.haslayer(UDP) and "UDP" not in self.packetDB[packet.getlayer(IP).src]:
                                self.packetDB[packet.getlayer(IP).src]["UDP"] = {}
                            if packet.haslayer(Ether) and "Ethernet" not in self.packetDB[packet.getlayer(IP).src]:
                                self.packetDB[packet.getlayer(IP).src]["Ethernet"] = packet.getlayer(Ether).src
                            # Gateway calculation
                            if packet.haslayer(Ether):
                                if packet.getlayer(Ether).dst not in self.highest_ethernet_destination:
                                    self.highest_ethernet_destination[packet.getlayer(Ether).dst] = 0
                                self.highest_ethernet_destination[packet.getlayer(Ether).dst] += 1
                            if packet.haslayer(TCP) and packet.getlayer(TCP).dport == 80:
                                if "HTTP" not in self.packetDB[packet.getlayer(IP).src]["TCP"]:
                                    self.packetDB[packet.getlayer(IP).src]["TCP"]["HTTP"] = {}
                                if "Server" not in self.packetDB[packet.getlayer(IP).src]["TCP"]["HTTP"]:
                                    self.packetDB[packet.getlayer(IP).src]["TCP"]["HTTP"]["Server"] = []
                                if "Payload" not in self.packetDB[packet.getlayer(IP).src]["TCP"]["HTTP"]:
                                    self.packetDB[packet.getlayer(IP).src]["TCP"]["HTTP"]["Payload"] = []
                                self.packetDB[packet.getlayer(IP).src]["TCP"]["HTTP"]["Server"].append(packet.getlayer(IP).dst)
                                self.packetDB[packet.getlayer(IP).src]["TCP"]["HTTP"]["Server"] = list(set(self.packetDB[packet.getlayer(IP).src]["TCP"]["HTTP"]["Server"]))
                                self.packetDB[packet.getlayer(IP).src]["TCP"]["HTTP"]["Payload"].append(packet)
                            if packet.haslayer(TCP) and packet.getlayer(TCP).dport == 443:
                                if "HTTPS" not in self.packetDB[packet.getlayer(IP).src]["TCP"]:
                                    self.packetDB[packet.getlayer(IP).src]["TCP"]["HTTPS"] = []
                                if packet.getlayer(IP).dst not in self.packetDB[packet.getlayer(IP).src]["TCP"]["HTTPS"]:
                                    self.packetDB[packet.getlayer(IP).src]["TCP"]["HTTPS"].append(packet.getlayer(IP).dst)
                                    self.packetDB[packet.getlayer(IP).src]["TCP"]["HTTPS"] = list(set(self.packetDB[packet.getlayer(IP).src]["TCP"]["HTTPS"]))
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
                                    self.packetDB[packet.getlayer(IP).dst]["TCP"]["HTTP"] = {}
                                if "Server" not in self.packetDB[packet.getlayer(IP).dst]["TCP"]["HTTP"]:
                                    self.packetDB[packet.getlayer(IP).dst]["TCP"]["HTTP"]["Server"] = []
                                if "Payload" not in self.packetDB[packet.getlayer(IP).dst]["TCP"]["HTTP"]:
                                    self.packetDB[packet.getlayer(IP).dst]["TCP"]["HTTP"]["Payload"] = []
                                self.packetDB[packet.getlayer(IP).dst]["TCP"]["HTTP"]["Server"].append(packet.getlayer(IP).src)
                                self.packetDB[packet.getlayer(IP).dst]["TCP"]["HTTP"]["Server"] = list(set(self.packetDB[packet.getlayer(IP).dst]["TCP"]["HTTP"]["Server"]))
                                self.packetDB[packet.getlayer(IP).dst]["TCP"]["HTTP"]["Payload"].append(packet)
                            if packet.haslayer(TCP) and packet.getlayer(TCP).sport == 443:
                                if "HTTPS" not in self.packetDB[packet.getlayer(IP).dst]["TCP"]:
                                    self.packetDB[packet.getlayer(IP).dst]["TCP"]["HTTPS"] = []
                                if packet.getlayer(IP).src not in self.packetDB[packet.getlayer(IP).dst]["TCP"]["HTTPS"]:
                                    self.packetDB[packet.getlayer(IP).dst]["TCP"]["HTTPS"].append(packet.getlayer(IP).src)
                                    self.packetDB[packet.getlayer(IP).dst]["TCP"]["HTTPS"] = list(set(self.packetDB[packet.getlayer(IP).dst]["TCP"]["HTTPS"]))
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
                    
                    # Ip Control Packets within LAN --> ICMP/IGMP
                    if packet.haslayer(IP) and not (packet.haslayer(TCP) or packet.haslayer(UDP)):
                            if "ip_control_lan" not in self.packetDB:
                                self.packetDB["ip_control_lan"] = {}
                            if IPAddress(packet.getlayer(IP).src).is_private() and packet.getlayer(IP).src not in self.packetDB["ip_control_lan"]:
                                self.packetDB["ip_control_lan"][packet.getlayer(IP).src] = packet.getlayer(Ether).src
                            if IPAddress(packet.getlayer(IP).dst).is_private() and packet.getlayer(IP).dst not in self.packetDB["ip_control_lan"]:
                                self.packetDB["ip_control_lan"][packet.getlayer(IP).dst] = packet.getlayer(Ether).dst

                        


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
    """
    Ideas of finding the gateway in a network:
    * For now the below mac, assumes maximum destination macs hit to be default_gateway
    * -- This might fail if there is only internal communication (high traffic)
    * The most Mac address desinted in a network 
    * Any DHCP traces revealing gateway
    * Destination to be private ip ==> internal LAN communication?
    * IGMP or ICMP? not reliable
    * Or Find the
    """
    def find_gateway(self):
        maxi = max(self.highest_ethernet_destination.values())
        for mac, count in self.highest_ethernet_destination.items():
            if count == maxi:
                self.packetDB["gateway_mac"] = mac
        # Ensure there is not direct ip connects to gatway to confirm results
        if "ip_control_lan" in self.packetDB:
            for ip in self.packetDB["ip_control_lan"]:
                if self.packetDB["ip_control_lan"][ip] == self.packetDB["gateway_mac"]:
                    self.packetDB["gateway_ip"] = ip


# Module Driver
def main():
    pcapfile = pcapReader('examples/maliciousTraffic.pcap')
    #print pcapfile.packetDB
    print pcapfile.packetDB["gateway_mac"]
    print pcapfile.packetDB["gateway_ip"]

#main()
