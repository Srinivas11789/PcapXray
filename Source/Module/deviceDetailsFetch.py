# Library Import
import urllib2
import json

# Module Import
import pcapReader

class fetchDeviceDetails:

    def __init__(self, ipObject):
        self.mac = ipObject["Ethernet"]
        self.url = "http://macvendors.co/api/" + self.mac

    def oui_identification(self):
        apiRequest = urllib2.Request(self.url, headers={'User-Agent':'PcapXray'})
        apiResponse = urllib2.urlopen(apiRequest)
        return json.loads(apiResponse)

def main():
    filename = "test.pcap"
    pcapfile = pcapReader('test.pcap')
    for ip in pcapfile.packetDB:
        macObj = fetchDeviceDetails(pcapfile.packetDB[ip])
        macObj.oui_identification()
main()

# MAC Oui Identification Module
# LAN IP and Getway Identification