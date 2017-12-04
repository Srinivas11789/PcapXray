# Library Import
import ipwhois
import dns
import socket

# Module Import
import pcapReader


# Class Communication or Traffic Details Fetch

class trafficDetailsFetch():

    def __init__(self, ips, protocol):
        self.ips = ips
        self.dns_details = {}
        self.ip_whois_details = {}
        self.dns()

    def ip_type(self): # Public or Private Ips
        for ip in self.ips:
            if ip in range(172,192):
                print "IP is Private"
            else:
                print "Ip is Public"

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
         try:
           whois_info = ipwhois.IPWhois(ip).lookup_rdap()
           self.ip_details[ip] = whois_info
         except:
             self.ip_details[ip] = ""



    def dns(self):
        for ip in self.ips:
            try:
                dns_info = socket.gethostbyaddr(ip)[0]
            except:
                dns_info = ""
            self.dns_details[ip] = dns_info

def main():
    capture = pcapReader.pcapReader("test.pcap")
    capture.fetch_specific_protocol("TCP","HTTPS")
    details = trafficDetailsFetch(capture.server_addresses, "HTTPS")
    print details.dns_details

#main()
