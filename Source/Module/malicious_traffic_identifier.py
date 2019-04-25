# Custom Module Imports
import memory

# Custom Module Import
import pcap_reader

# Library Import

# Module to Identify Possible Malicious Traffic

class maliciousTrafficIdentifier:

    def __init__(self):
        for session in memory.packet_db:
            src, dst, port = session.split("/")
            if self.malicious_traffic_detection(src, dst, port) == 1:
                memory.possible_mal_traffic.append(session)

    def malicious_traffic_detection(self, src, dst, port):
        very_well_known_ports = [443]
        well_known_ports = [20, 21, 22, 23, 25, 53, 69, 80, 161, 179, 389]
        if (dst in memory.destination_hosts and memory.destination_hosts[dst] == "NotResolvable") or port not in well_known_ports:
            return 1

    # TODO: Covert communication module --> Add here

def main():
    cap = pcap_reader.PcapEngine('examples/torExample.pcap', "scapy")
    maliciousTrafficIdentifier()
    print(memory.possible_mal_traffic)

#main()


