# Library Import
import urllib2
import json
import codecs
# Module Import
import pcapReader
import reportGen
import threading

class fetchDeviceDetails:

    def __init__(self, ipObject, reportDir):
        self.mac = ipObject["Ethernet"]
        self.url = "http://macvendors.co/api/" + self.mac

    def oui_identification(self):
        apiRequest = urllib2.Request(self.url, headers={'User-Agent':'PcapXray'})
        try:
            apiResponse = urllib2.urlopen(apiRequest)
            details = json.loads(apiResponse.read())
            reportThread = threading.Thread(target=reportGen.reportGen(reportDir).deviceDetailsReport,args=(details,))
            reportThread.start()
            detail = details["result"]["company"]
        except:
            detail = "No Match!"
        return detail

def main():
    filename = "test.pcap"
    pcapfile = pcapReader.pcapReader('test.pcap')
    for ip in pcapfile.packetDB:
        macObj = fetchDeviceDetails(pcapfile.packetDB[ip])
        print macObj.oui_identification()
#main()

# MAC Oui Identification Module
# LAN IP and Getway Identification
