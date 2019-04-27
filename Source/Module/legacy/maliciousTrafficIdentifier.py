# Custom Module Import
import pcapReader

# Library Import

# Module to Identify Possible Malicious Traffic

class maliciousTrafficIdentifier:

    def __init__(self, packetDB, dns_details):
        self.possible_malicious_traffic = {}
        sessions = []
        for ip in packetDB:
            if ip not in self.possible_malicious_traffic:
                self.possible_malicious_traffic[ip] = []
            if "TCP" in packetDB[ip] and "PortsConnected" in packetDB[ip]["TCP"]:
                 sessions = packetDB[ip]["TCP"]["PortsConnected"]
            if "UDP" in packetDB[ip] and "PortsConnected" in packetDB[ip]["UDP"]["PortsConnected"]:
                 sessions = sessions + packetDB[ip]["UDP"]["PortsConnected"]
            self.malicious_traffic_detection(ip, sessions, dns_details)

    def malicious_traffic_detection(self, ip, sessions, dns):
        very_well_known_ports = [443]
        well_known_ports = [20, 21, 22, 23, 25, 53, 69, 80, 161, 179, 389]
        for connection in sessions:
            if (connection[0] in dns and dns[connection[0]] == "NotResolvable") or connection[1] not in well_known_ports:
                self.possible_malicious_traffic[ip].append(connection)


def main():
    malicious_capture = pcapReader.pcapReader("torexample.pcapng")
    print malicious_capture.packetDB
    dns_details = {}
    mal_identify = maliciousTrafficIdentifier(malicious_capture.packetDB, dns_details)
    print mal_identify.possible_malicious_traffic

#main()


