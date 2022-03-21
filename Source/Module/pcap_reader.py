"""
Module pcap_reader
"""
import logging
import sys
import os
import memory
from netaddr import IPAddress
import threading
import base64
import malicious_traffic_identifier
import communication_details_fetch

# Feature toggle
tls_view_feature = False

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

        # Initialize Data Structures
        memory.lan_hosts = {}
        memory.destination_hosts = {}
        memory.possible_mal_traffic = []
        memory.possible_tor_traffic = []
        
        # If the database already exists, pcap_reader will not do anything. 
        if memory.init_sqlite_dbs(os.getcwd(), pcap_file_name):
            return

        # Set Pcap Engine
        self.engine = pcap_parser_engine

        # Import library for pcap parser engine selected
        if pcap_parser_engine == "scapy":
            try:
                from scapy.all import rdpcap
            except:
                logging.error("Cannot import selected pcap engine: Scapy!")
                sys.exit()
            
            try:
                from scapy.all import load_layer
                global tls_view_feature
                tls_view_feature = True
                logging.info("tls view feature enabled")
            except:
                logging.info("tls view feature not enabled")
            
            if tls_view_feature:
                load_layer("tls")

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
            #self.packets.load_packets()
            #self.packets.apply_on_packets(self.analyse_packet_data, timeout=100)

        print("read packet stored")

        # Analyse capture to populate data
        self.analyse_packets_data()

        # <TODO>: Add other pcap engine modules to generate packetDB


    ## Operating based on payloads above IP (L3) to create the key for session (session_key)
    # <TODO> add more support as we improve
    # Currently:
    # * TCP/UDP
    # * ICMP
    def analyse_packet_data(self, packet) :
        # ***********
        # Gets a unique key from the packet's data representing the session
        # The key contains the port (destination or source), destination IP and source IP.

        session_key = None

        if "TCP" in packet or "UDP" in packet:
            session_key, is_source_private, is_destination_private, IP = self.get_tcp_session_key(packet)

        elif "ICMP" in packet:
            session_key, is_source_private, is_destination_private, IP = self.get_icmp_session_key(packet)

        if not session_key:
            return
        

        # ***********
        # Creates this packet in memory.packet_db according to its session
        
        self.add_key_packet_db(packet, session_key)

        # ***********
        # Stores the packet's hosts in the lists of hosts

        if self.engine == "pyshark":
            eth_layer = "ETH"
        elif self.engine == "scapy":
            eth_layer = "Ether" 
        
        self.store_host_list(packet, eth_layer, IP, is_source_private, is_destination_private)
        
        # ***********
        # Stores the MAC address in the memory

        if is_source_private :
            if eth_layer in packet:
                memory.packet_db.packet["Ethernet"]["src"] = packet[eth_layer].src
                memory.packet_db.packet["Ethernet"]["dst"] = packet[eth_layer].dst
            payload_direction = "forward"
        else:
            if eth_layer in packet:
                memory.packet_db.packet["Ethernet"]["src"] = packet[eth_layer].dst
                memory.packet_db.packet["Ethernet"]["dst"] = packet[eth_layer].src
            payload_direction = "reverse"
        
        # ***********
        # Stores the Payload
        
        payload_string = "" # Variable to hold payload and detect covert

        # Gets Pyshark payload
        if self.engine == "pyshark":
            # <TODO>: Payload recording for pyshark
            # Refer https://github.com/KimiNewt/pyshark/issues/264
            try:
                payload_dump = str(packet.get_raw_packet())
                payload_string = packet.get_raw_packet()
            except:
                payload_dump = ""
        
        # Gets Scapy payload
        elif self.engine == "scapy":
            global tls_view_feature
            if "TCP" in packet:
                payload_dump = self.get_scapy_payload_dump(packet)
                payload_string = packet["TCP"].payload
            elif "UDP" in packet:
                payload_dump = str(bytes(packet["UDP"].payload))
                payload_string = packet["UDP"].payload
            elif "ICMP" in packet:
                payload_dump = str(bytes(packet["ICMP"].payload))
                payload_string = packet["ICMP"].payload

        # Adds payload to memory.packet_db
        memory.packet_db.packet["Payload"][payload_direction].append(payload_dump)

        # ***********
        # Stores covert file signatures
        if payload_string and memory.packet_db.packet["covert"] == True:
            file_signs = malicious_traffic_identifier.maliciousTrafficIdentifier.covert_payload_prediction(payload_string)
            # print(file_signs)
            if file_signs:
                memory.packet_db.packet["file_signatures"].extend(file_signs)
                memory.packet_db.packet["file_signatures"] = list(set(memory.packet_db.packet["file_signatures"]))

        # ***********
        # Dumps data to the SQLite DB

        memory.packet_db.save_packet()

    def store_host_list(self, packet, eth_layer, IP, is_source_private, is_destination_private):
        if is_source_private and is_destination_private: # Communication within LAN

            # IntraNetwork Hosts list 
            # * When both are private they are LAN host
            # TODO: this assumes a unique mac address per LAN, investigate if we need to account duplicate MAC
            # * This requirement occurred when working with CTF with fake MAC like 00:00:00:00:00:00
            if eth_layer in packet:
                lan_key_src = packet[eth_layer].src
                lan_key_dst = packet[eth_layer].dst
                if lan_key_src not in memory.lan_hosts:
                    memory.lan_hosts[lan_key_src] = {"ip": packet[IP].src}
                if lan_key_dst not in memory.lan_hosts:
                    memory.lan_hosts[lan_key_dst] = {"ip": packet[IP].dst}

        elif is_source_private: # Internetwork packet

            # IntraNetwork vs InterNetwork Hosts list
            if eth_layer in packet:
                lan_key_src = packet[eth_layer].src
                if lan_key_src not in memory.lan_hosts:
                    memory.lan_hosts[lan_key_src] = {"ip": packet[IP].src}
                if packet[IP].dst not in memory.destination_hosts:
                    memory.destination_hosts[packet[IP].dst] = {"mac": packet[eth_layer].dst}

        elif is_destination_private: # Internetwork packet

            # InterNetwork vs IntraNetwork Hosts list
            if eth_layer in packet:
                lan_key_dst = packet[eth_layer].dst
                if lan_key_dst not in memory.lan_hosts:
                    memory.lan_hosts[lan_key_dst] = {"ip": packet[IP].dst}
                if packet[IP].src not in memory.destination_hosts:
                    memory.destination_hosts[packet[IP].src] = {"mac": packet[eth_layer].src}
        
        else: # public ip communication if no match

            # InterNetwork Hosts list 
            # * When both are public they are never LAN hosts
            if eth_layer in packet:
                if packet[IP].src not in memory.destination_hosts:
                    memory.destination_hosts[packet[IP].src] = {"mac": packet[eth_layer].src}
                if packet[IP].dst not in memory.destination_hosts:
                    memory.destination_hosts[packet[IP].dst] = {"mac": packet[eth_layer].dst}

    def add_key_packet_db(self, packet, session_key):
        memory.packet_db.create_packet(session_key)
        
        
        

    def get_scapy_payload_dump(self, packet):
        global tls_view_feature
        if tls_view_feature:
            if "TLS" in packet:
                payload_dump = str(packet["TLS"].msg)
            elif "SSLv2" in packet:
                payload_dump = str(packet["SSLv2"].msg)
            elif "SSLv3" in packet:
                payload_dump = str(packet["SSLv3"].msg)
            else:
                payload_dump = str(bytes(packet["TCP"].payload))
        else:
            # TODO: clean this payload dump
            payload_dump = str(bytes(packet["TCP"].payload))
        
        return payload_dump
    
    def is_private(self, packet) : 
        IP = None
        is_source_private = None
        is_destination_private = None
        # IPV6 Condition
        if "IPv6" in packet or "IPV6" in packet:
            # Set Engine respective properties
            if self.engine == "scapy":
                IP = "IPv6"
            else:
                IP = "IPV6"

            # TODO: Fix weird ipv6 errors in pyshark engine
            # * ExHandler as temperory fix
            try:
                is_source_private = IPAddress(packet[IP].src).is_private()
            except:
                pass
            try:
                is_destination_private = IPAddress(packet[IP].dst).is_private()
            except:
                pass
    
        elif "IP" in packet: # IPV4 Condition
            # and packet["IP"].version == "4":
            # Handle IP packets that originated from LAN (Internal Network)
            #print(packet["IP"].version == "4")
            IP = "IP"
            is_source_private = IPAddress(packet[IP].src).is_private()
            is_destination_private = IPAddress(packet[IP].dst).is_private()

        
        return (IP, is_source_private, is_destination_private)

    def get_icmp_session_key(self, packet): 
        (IP, is_source_private, is_destination_private) = self.is_private(packet)

        # Key creation similar to both private interface condition
        key1 = packet[IP].src + "/" + packet[IP].dst + "/" + "ICMP"
        key2 = packet[IP].dst + "/" + packet[IP].src + "/" + "ICMP"

        # First come first serve
        if key2 in memory.packet_db.session_keys():
            session_key = key2
        else:
            session_key = key1
        
        return (session_key, is_source_private, is_destination_private, IP)

    def get_tcp_session_key (self, packet):
        (IP, is_source_private, is_destination_private) = self.is_private(packet)

        # Set Engine respective properties
        if self.engine == "pyshark":
            src_port = str(
                packet["TCP"].srcport if "TCP" in packet else packet["UDP"].srcport)
            dst_port = str(
                packet["TCP"].dstport if "TCP" in packet else packet["UDP"].dstport)
        else:
            src_port = str(
                packet["TCP"].sport if "TCP" in packet else packet["UDP"].sport)
            dst_port = str(
                packet["TCP"].dport if "TCP" in packet else packet["UDP"].dport)

        # Session Key Creation
        if is_source_private and not is_destination_private: 
            # Internetwork packet
            # Key := Always lan hosts as source in session
            key = packet[IP].src + "/" + packet[IP].dst + "/" + dst_port
            session_key = key
        elif is_destination_private and not is_source_private : 
            # Internetwork packet
            # Key := Always lan hosts as source in session
            key = packet[IP].dst + "/" + packet[IP].src + "/" + src_port
            session_key = key
        else : 
            # Intranetwork or Public ip communication
            key1 = packet[IP].src + "/" + packet[IP].dst + "/" + dst_port
            key2 = packet[IP].dst + "/" + packet[IP].src + "/" + src_port

            # First come first serve
            if key2 in memory.packet_db.session_keys():
                session_key = key2
            else:
                session_key = key1
        
        return  (session_key, is_source_private, is_destination_private, IP)


    #@retry(tries=5, errors=memory.CouldNotLock)
    def analyse_packets_data(self):
            #with memory.get_lock():
            """
            PcapXray runs only one O(N) packets once to memoize
            # - Parse the packets to create a usable DB
            # - All the protocol parsing should be included here
            """
            print("packet reading starts")
            for packet in self.packets: # O(N) packet iteration
                self.analyse_packet_data(packet)
            memory.packet_db.commit()
            print("packet reading complete, now, analysis")
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
    pcapfile = PcapEngine(sys.path[0]+'/examples/biz.pcap', "scapy")
    print(memory.packet_db.keys())
    ports = []
    
    """
    for key in memory.packet_db.session_keys():
    #    if "192.168.11.4" in key:
            print(key)
            print(memory.packet_db[key])
            ip, port = key.split("/")[0], int(key.split("/")[-1])
            if ip == "10.187.195.95":
                ports.append(port)
    print(sorted(list(set(ports))))
    print(memory.lan_hosts)
    print(memory.destination_hosts)
    """
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
