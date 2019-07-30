# Custom Module Imports
import memory

# Custom Module Import
import pcap_reader
import communication_details_fetch

# Library Import

# Module to Identify Possible Malicious Traffic

class maliciousTrafficIdentifier:

    def __init__(self):
        for session in memory.packet_db:
            src, dst, port = session.split("/")
            if port.isdigit() and self.malicious_traffic_detection(src, dst, int(port)) == 1:
                memory.possible_mal_traffic.append(session)

    def malicious_traffic_detection(self, src, dst, port):
        very_well_known_ports = [443] # used to differentiate possible mal vs serious mal
        well_known_ports = [20, 21, 22, 23, 25, 53, 69, 80, 161, 179, 389, 443]
        # Currently whitelist all the ports
        if not communication_details_fetch.trafficDetailsFetch.is_multicast(src) and not communication_details_fetch.trafficDetailsFetch.is_multicast(dst):
            if (dst in memory.destination_hosts and memory.destination_hosts[dst]["domain_name"] == "NotResolvable") or port > 1024:
                return 1
        return 0

    # TODO: Covert communication module --> Add here
    # * Only add scapy first
    @staticmethod
    def covert_traffic_detection(packet):
        # covert ICMP - icmp tunneling
        tunnelled_protocols = ["DNS", "HTTP"]

        if "IP" in packet:
            if communication_details_fetch.trafficDetailsFetch.is_multicast(packet["IP"].src) or communication_details_fetch.trafficDetailsFetch.is_multicast(packet["IP"].dst):
                return 0

        if "ICMP" in packet:
            if "TCP in ICMP" in packet or "UDP in ICMP" in packet or "DNS" in packet:
                #print(packet.show())
                return 1
            elif "padding" in packet:
                return 1
            elif filter(lambda x: x in str(packet["ICMP"].payload), tunnelled_protocols):
                return 1
        elif "DNS" in packet:
            #print(packet["DNS"].qd.qname)
            try:
                if communication_details_fetch.trafficDetailsFetch.dns(packet["DNS"].qd.qname.strip()) == "NotResolvable":
                    return 1
                elif len(filter(str.isdigit, str(packet["DNS"].qd.qname).strip())) > 8:
                    return 1
            except:
                pass
        return 0

def main():
    cap = pcap_reader.PcapEngine('examples/torExample.pcap', "scapy")
    maliciousTrafficIdentifier()
    print(memory.possible_mal_traffic)

#main()


