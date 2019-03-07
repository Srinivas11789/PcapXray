"""
Module device_details
"""
# Library Import
import urllib.request
import json
import logging
# Module Import
import pcap_reader
import memory
import threading
from netaddr import *

class fetchDeviceDetails:

    def __init__(self, option="ieee"):
        """
        Init
        """
        self.target_oui_database = option

    def fetch_info(self):
        if self.target_oui_database == "api":
            for ip in memory.lan_hosts:
                memory.lan_hosts[ip]["device_vendor"] = self.oui_identification_via_api(memory.lan_hosts[ip]["mac"])  
        else:
            for ip in memory.lan_hosts:
                memory.lan_hosts[ip]["device_vendor"], memory.lan_hosts[ip]["vendor_address"] = self.oui_identification_via_ieee(memory.lan_hosts[ip]["mac"])    

    def oui_identification_via_api(self, mac):
        url = "http://macvendors.co/api/" + mac
        api_request = urllib.request.Request(url, headers={'User-Agent':'PcapXray'})
        try:
            apiResponse = urllib.request.urlopen(api_request)
            details = json.loads(apiResponse.read())
            #reportThread = threading.Thread(target=reportGen.reportGen().deviceDetailsReport,args=(details,))
            #reportThread.start()
            return details["result"]["company"], details["result"]["address"]
        except Exception as e:
            logging.info("device_details module: oui identification failure via api" + str(e))
            return "Unknown", "Unknown"

    def oui_identification_via_ieee(self, mac):
        try:
            mac_obj = EUI(mac)
            mac_oui = mac_obj.oui
            return mac_oui.registration().org, mac_oui.registration().address
        except Exception as e:
            logging.info("device_details module: oui identification failure via ieee " + str(e))
            return "Unknown", "Unknown"

def main():
    filename = "test.pcap"
    pcap_reader.PcapEngine('examples/test.pcap', "scapy")
    fetchDeviceDetails("api").fetch_info()
    print(memory.lan_hosts)

main()

# MAC Oui Identification Module
# LAN IP and Getway Identification
