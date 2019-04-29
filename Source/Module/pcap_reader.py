"""
Module pcap_reader
"""
import logging
import sys
import memory
from netaddr import IPAddress
import threading
import base64

class PcapEngine():
    """
    PcapEngine: To support different pcap parser backend engine to operate reading pcap
    Current Support:
        * Scapy
        * Pyshark
    """

    def __init__(self, pcap_file_name, pcap_parser_engine="scapy"):
        """
        Init function imports libraries based on the parser engine selected
        Return:
        * packetDB ==> Full Duplex Packet Streams
          - Used while finally plotting streams as graph
          - dump packets during report generation
        * lan_hosts ==> Private IP (LAN) list
          - device details
        * destination_hosts ==> Destination Hosts
          - communication details
          - tor identification
          - malicious identification
        """
        #memory.packet_db = {}
        #memory.lan_hosts = {}
        #memory.destination_hosts = {}
        self.engine = pcap_parser_engine
        if pcap_parser_engine == "scapy":
            try:
                from scapy.all import rdpcap
            except:
                logging.error("Cannot import selected pcap engine: Scapy!")
                sys.exit()
            # Scapy sessions and other types use more O(N) iterations so just
            # - use rdpcap + our own iteration (create full duplex streams)
            self.packets = rdpcap(pcap_file_name)
        elif pcap_parser_engine == "pyshark":
            try:
                import pyshark
            except:
                logging.error("Cannot import selected pcap engine: PyShark!")
                sys.exit()
            self.packets = pyshark.FileCapture(pcap_file_name, include_raw=True, use_json=True)
        # Analyse capture to populate data
        self.analyse_packet_data()
        # Add other pcap engine modules to generate packetDB

    #@retry(tries=5, errors=memory.CouldNotLock)
    def analyse_packet_data(self):
            #with memory.get_lock():
            """
            PcapXray runs only one O(N) packets once to memoize
            # - Parse the packets to create a usable DB
            # - All the protocol parsing should be included here
            """
            for packet in self.packets: # O(N) packet iteration
                source_private_ip = None
                if "IP" in packet:# and packet["IP"].version == "4":
                    # Handle IP packets that originated from LAN (Internal Network)
                    #print(packet["IP"].version == "4")
                    IP = "IP"
                    private_source = IPAddress(packet[IP].src).is_private()
                    private_destination = IPAddress(packet[IP].dst).is_private()
                elif "IPv6" in packet or "IPV6" in packet:
                    if self.engine == "scapy":
                        IP = "IPv6"
                    else:
                        IP = "IPV6"
                    private_source = IPAddress(packet[IP].src).is_private()
                    private_destination = IPAddress(packet[IP].dst).is_private()

                if "TCP" in packet or "UDP" in packet:
                    # Sort out indifferences in pcap engine
                    if self.engine == "pyshark":
                        eth_layer = "ETH"
                        tcp_src = str(
                            packet["TCP"].srcport if "TCP" in packet else packet["UDP"].srcport)
                        tcp_dst = str(
                            packet["TCP"].dstport if "TCP" in packet else packet["UDP"].dstport)
                    else:
                        eth_layer = "Ethernet"
                        tcp_src = str(
                            packet["TCP"].sport if "TCP" in packet else packet["UDP"].sport)
                        tcp_dst = str(
                            packet["TCP"].dport if "TCP" in packet else packet["UDP"].dport)

                    if private_source and private_destination: # Communication within LAN
                        key1 = packet[IP].src + "/" + packet[IP].dst + "/" + tcp_dst
                        key2 = packet[IP].dst + "/" + packet[IP].src + "/" + tcp_src
                        if key2 in memory.packet_db:
                            source_private_ip = key2
                        else:
                            source_private_ip = key1
                        # IntraNetwork Hosts list
                        memory.lan_hosts[packet[IP].src] = {"mac": packet[eth_layer].src}
                        memory.lan_hosts[packet[IP].dst] = {"mac": packet[eth_layer].dst}
                    elif private_source: # Internetwork packet
                        key = packet[IP].src + "/" + packet[IP].dst + "/" + tcp_dst
                        source_private_ip = key
                        # IntraNetwork vs InterNetwork Hosts list
                        memory.lan_hosts[packet[IP].src] = {"mac": packet[eth_layer].src}
                        memory.destination_hosts[packet[IP].dst] = {}
                    elif private_destination: # Internetwork packet
                        #print(packet.show())
                        key = packet[IP].dst + "/" + packet[IP].src + "/" + tcp_src
                        source_private_ip = key
                        # IntraNetwork vs InterNetwork Hosts list
                        memory.lan_hosts[packet[IP].dst] = {"mac": packet[eth_layer].dst}
                        memory.destination_hosts[packet[IP].src] = {}

                elif "ICMP" in packet:
                    key = packet[IP].src + "/" + packet[IP].dst + "/" + "ICMP"
                    source_private_ip = key
                # Fill packetDB with generated key
                #print(packet.show())
                if source_private_ip:
                    if source_private_ip not in memory.packet_db:
                        memory.packet_db[source_private_ip] = {}
                        # Ethernet Layer ( Mac address )
                        if "Ethernet" not in memory.packet_db[source_private_ip]:
                            memory.packet_db[source_private_ip]["Ethernet"] = {}
                        # HTTP Packets
                        if "Payload" not in memory.packet_db:
                            # Payload recording
                            memory.packet_db[source_private_ip]["Payload"] = []
                    if self.engine == "pyshark":
                        memory.packet_db[source_private_ip]["Ethernet"]["src"] = packet["ETH"].src
                        memory.packet_db[source_private_ip]["Ethernet"]["dst"] = packet["ETH"].dst
                        # Refer https://github.com/KimiNewt/pyshark/issues/264
                        #memory.packet_db[source_private_ip]["Payload"].append(packet.get_raw_packet())
                    else:
                        memory.packet_db[source_private_ip]["Ethernet"]["src"] = packet["Ethernet"].src
                        memory.packet_db[source_private_ip]["Ethernet"]["dst"] = packet["Ethernet"].dst
                        
                        if "TCP" in packet:
                            memory.packet_db[source_private_ip]["Payload"].append(str(packet["TCP"].payload))
                        elif "UDP" in packet:
                            memory.packet_db[source_private_ip]["Payload"].append(str(packet["UDP"].payload))
                        elif "ICMP" in packet:
                            memory.packet_db[source_private_ip]["Payload"].append(str(packet["ICMP"].payload))

    # TODO: Add function memory to store all the memory data in files (DB)
    # def memory_handle():
    """
    - Store the db as json on a file in cache folder (to not repeat read)
    """

# Local Driver
def main():
    """
    Module Driver
    """
    pcapfile = PcapEngine('examples/test.pcap', "scapy")
    print(memory.packet_db.keys())
    ports = []
    
    for key in memory.packet_db.keys():
    #    if "192.168.11.4" in key:
            print(key)
            print(memory.packet_db[key])
            ip, port = key.split("/")[0], int(key.split("/")[-1])
            if ip == "10.187.195.95":
                ports.append(port)
    

    print(sorted(list(set(ports))))
    print(memory.lan_hosts)
    print(memory.destination_hosts)
    #print(memory.packet_db["TCP 192.168.0.26:64707 > 172.217.12.174:443"].summary())
    #print(memory.packet_db["TCP 172.217.12.174:443 > 192.168.0.26:64707"].summary())
    #memory.packet_db.conversations(type="jpg", target="> test.jpg")

#main()

# Sort payload by time...
# SSL Packets
# - Get handshake details?
#HTTPS
#Tor
#Malicious
# HTTP Payload Decrypt
