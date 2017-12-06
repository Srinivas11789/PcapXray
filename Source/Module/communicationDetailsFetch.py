# Library Import
import ipwhois
import dns
import socket

# Module Import
import pcapReader

# Class Communication or Traffic Details Fetch

class trafficDetailsFetch():

    def __init__(self, ipDB):
        self.ips = []
        for entry in ipDB["PortsConnected"]:
            self.ips.append(entry[0])
        self.ip_details = {}
        self.dns()
        self.ip_whois_details()

    # whois_info_fetch
    #        - Input    : Domain Name and IP address
    #        - Function : Obtains the Whois Information for the given domain or IP
    #                      * Domain
    #                      * Leverages restApi with "whois.com/whois" api call
    #                      * IP
    #                      * Leverages the ipWhois python library to fetch info
    #        - Output   : Returns the whois data obtained from whois.com and ipwhois
    #
    def whois_info_fetch(self):
       for ip in self.ips:
         if "whois" not in self.ip_details[ip]:
            self.ip_details[ip]["whois"] = ""
         try:
           whois_info = ipwhois.IPWhois(ip).lookup_rdap()
           self.ip_details[ip] = whois_info
         except:
             self.ip_details[ip] = ""
         self.ip_details[ip]["whois"] = whois_info

    def dns(self):
        for ip in self.ips:
            if "dns" not in self.ip_details[ip]:
                self.ip_details[ip]["dns"] = ""
            try:
                dns_info = socket.gethostbyaddr(ip)[0]
            except:
                dns_info = ""
            self.ip_details[ip]["dns"] = dns_info

def main():
    capture = pcapReader("test.pcap")
    for ip in capture.packetDB:
        details = trafficDetailsFetch(capture.packetDB[ip])
        print details.ip_details
        print "\n"

main()
