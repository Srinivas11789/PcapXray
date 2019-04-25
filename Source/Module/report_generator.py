# Report Generation
import os, json
from scapy.all import *
import memory

class reportGen:

    def __init__(self, path):
        if not os.path.exists(path+"/Report"):
            os.makedirs(path+"/Report")
        self.directory = path+"/Report"

    def communicationDetailsReport(self):
        try:
            text_handle = open(self.directory + "/communicationDetailsReport.txt", "w")
        except Exception as e:
            print "Could not create the report text file !!!!! Please debug error %s" % (str(e.message))
        text_handle.write("CommunicationDetails: %s\n" % json.dumps(memory.destination_hosts, indent=2,sort_keys=True))
        text_handle.write("Tor Nodes: %s\n" % json.dumps(memory.tor_nodes, indent=2,sort_keys=True))
        text_handle.write("Tor Traffic: %s\n" % json.dumps(memory.possible_tor_traffic, indent=2,sort_keys=True))
        text_handle.write("Malicious Traffic: %s\n" % json.dumps(memory.possible_mal_traffic, indent=2,sort_keys=True))

    def deviceDetailsReport(self):
        try:
            text_handle = open(self.directory + "/deviceDetailsReport.txt", "w")
        except Exception as e:
            print "Could not create the report text file !!!!! Please debug error %s" % (str(e.message))
        text_handle.write("deviceDetails: %s\n" % json.dumps(memory.lan_hosts, indent=2,sort_keys=True))

    def packetDetails(self):
        try:
            text_handle = open(self.directory + "/packetDetailsReport.txt", "w")
        except Exception as e:
            print "Could not create the report text file !!!!! Please debug error %s" % (str(e.message))
        text_handle.write("%s\n" % json.dumps(memory.packet_db, indent=2,sort_keys=True))