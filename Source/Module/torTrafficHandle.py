# Custom Module Imports
import pcapReader

# Library Import
from stem.descriptor import remote

# Tor Traffic Module Class

class torTrafficHandle():

    def __init__(self, packetDB):
        self.possible_tor_traffic = {}
        self.tor_nodes = []
        self.get_consensus_data()
        for ip in packetDB:
            if ip not in self.possible_tor_traffic:
                self.possible_tor_traffic[ip] = []
            sessions = packetDB[ip]["TCP"]["PortsConnected"] + packetDB[ip]["UDP"]["PortsConnected"]
            self.tor_traffic_detection(ip, sessions)

    def get_consensus_data(self):
        try:
            for desc in remote.get_consensus().run():
                self.tor_nodes.append((desc.address, desc.or_port))
        except Exception as exc:
            print("Unable to retrieve the consensus: %s" % exc)

    def tor_traffic_detection(self, ip, sessions):
        for connection in sessions:
            if connection in self.tor_nodes:
                self.possible_tor_traffic[ip].append(connection)

def main():
     tor_capture = pcapReader.pcapReader("torexample.pcapng")
     print tor_capture.packetDB
     tor_identify = torTrafficHandle(tor_capture.packetDB)
     print tor_identify.possible_tor_traffic

#main()






