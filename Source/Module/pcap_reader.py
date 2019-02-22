"""
Module pcap_reader
"""
import logging
import sys
from netaddr import IPAddress

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
        self.packet_db = {}
        self.lan_hosts = {}
        self.destination_hosts = {}
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

    def analyse_packet_data(self):
        """
        PcapXray runs only one O(N) packets once to memoize
        # - Parse the packets to create a usable DB
        # - All the protocol parsing should be included here
        """
        for packet in self.packets: # O(N) packet iteration
            if "IP" in packet:
                # Handle IP packets that originated from LAN (Internal Network)
                source_private_ip = None
                private_source = IPAddress(packet["IP"].src).is_private()
                private_destination = IPAddress(packet["IP"].dst).is_private()
                if "TCP" in packet or "UDP" in packet:
                     # Sort out indifferences in pcap engine
                    if self.engine == "pyshark":
                        tcp_src = str(
                            packet["TCP"].srcport if "TCP" in packet else packet["UDP"].srcport)
                        tcp_dst = str(
                            packet["TCP"].dstport if "TCP" in packet else packet["UDP"].dstport)
                    else:
                        tcp_src = str(
                            packet["TCP"].sport if "TCP" in packet else packet["UDP"].sport)
                        tcp_dst = str(
                            packet["TCP"].dport if "TCP" in packet else packet["UDP"].dport)

                    if private_source and private_destination: # Communication within LAN
                        key1 = packet["IP"].src + "/" + packet["IP"].dst + "/" + tcp_dst
                        key2 = packet["IP"].dst + "/" + packet["IP"].src + "/" + tcp_src
                        if key2 in self.packet_db:
                            source_private_ip = key2
                        else:
                            source_private_ip = key1
                        # IntraNetwork Hosts list
                        self.lan_hosts[packet["IP"].src] = ""
                        self.lan_hosts[packet["IP"].dst] = ""
                    elif private_source: # Internetwork packet
                        key = packet["IP"].src + "/" + packet["IP"].dst + "/" + tcp_dst
                        source_private_ip = key
                        # IntraNetwork vs InterNetwork Hosts list
                        self.lan_hosts[packet["IP"].src] = ""
                        self.destination_hosts[packet["IP"].dst] = {}
                    elif private_destination: # Internetwork packet
                        key = packet["IP"].dst + "/" + packet["IP"].src + "/" + tcp_src
                        source_private_ip = key
                        # IntraNetwork vs InterNetwork Hosts list
                        self.lan_hosts[packet["IP"].dst] = ""
                        self.destination_hosts[packet["IP"].src] = {}

                elif "ICMP" in packet:
                    key = packet["IP"].src + "/" + packet["IP"].dst + "/" + "ICMP"
                    source_private_ip = key
            # Fill packetDB with generated key
            if source_private_ip:
                if source_private_ip not in self.packet_db:
                    self.packet_db[source_private_ip] = {}
                    # Ethernet Layer ( Mac address )
                    if "Ethernet" not in self.packet_db[source_private_ip]:
                        self.packet_db[source_private_ip]["Ethernet"] = {}
                    # HTTP Packets
                    if "Payloads" not in self.packet_db:
                        # Payload recording
                        self.packet_db[source_private_ip]["Payload"] = []
                if self.engine == "pyshark":
                    self.packet_db[source_private_ip]["Ethernet"]["src"] = packet["ETH"].src
                    self.packet_db[source_private_ip]["Ethernet"]["dst"] = packet["ETH"].dst
                    # Refer https://github.com/KimiNewt/pyshark/issues/264
                    self.packet_db[source_private_ip]["Payload"].append(packet.get_raw_packet())
                else:
                    self.packet_db[source_private_ip]["Ethernet"]["src"] = packet["Ethernet"].src
                    self.packet_db[source_private_ip]["Ethernet"]["dst"] = packet["Ethernet"].dst
                    if "Raw" in packet:
                        self.packet_db[source_private_ip]["Payload"].append(packet["Raw"].load)

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
    print(pcapfile.packet_db)
    print(pcapfile.lan_hosts)
    print(pcapfile.destination_hosts)
    #print(self.packet_db["TCP 192.168.0.26:64707 > 172.217.12.174:443"].summary())
    #print(self.packet_db["TCP 172.217.12.174:443 > 192.168.0.26:64707"].summary())
    #self.packet_db.conversations(type="jpg", target="> test.jpg")

#main()

# Sort payload by time...
# SSL Packets
# - Get handshake details?
#HTTPS
#Tor
#Malicious
# HTTP Payload Decrypt
