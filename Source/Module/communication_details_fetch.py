import memory 

# Library Import
import ipwhois
from dns import reversename, resolver
import socket
# Module Import
import pcap_reader
import netaddr

# Class Communication or Traffic Details Fetch

class trafficDetailsFetch():

    def __init__(self, option):
        for host in memory.destination_hosts:
            if not memory.destination_hosts[host]:
                if option == "whois":
                    memory.destination_hosts[host] = self.whois_info_fetch(host)
                else:
                    memory.destination_hosts[host] = self.dns(host)

    def whois_info_fetch(self, ip):
        try:
           whois_info = ipwhois.IPWhois(ip).lookup_rdap()
        except:
           whois_info = "NoWhoIsInfo"
        return whois_info

    def dns(self, ip):
        try:
            dns_info = socket.gethostbyaddr(ip)[0]
        except:
            dns_info = "NotResolvable"
        return dns_info

def main():
    capture = pcap_reader.PcapEngine('examples/test.pcap', "scapy")
    details = trafficDetailsFetch("sock")
    print(memory.destination_hosts)
    print("\n")

#main()
