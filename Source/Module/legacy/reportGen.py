# Report Generation
import os, json
from scapy.all import *

class reportGen:

    def __init__(self):
        if not os.path.exists("Report"):
            os.makedirs("Report")
        self.directory = "Report"

    def communicationDetailsReport(self, commDB):
        try:
            text_handle = open(self.directory + "/communicationDetailsReport.txt", "w")
        except Exception as e:
            print "Could not create the report text file !!!!! Please debug error %s" % (str(e.message))
        text_handle.write("CommunicationDetails: %s" % json.dumps(commDB, indent=2,sort_keys=True))

    def deviceDetailsReport(self, deviceDetails):
        try:
            text_handle = open(self.directory + "/deviceDetailsReport.txt", "w")
        except Exception as e:
            print "Could not create the report text file !!!!! Please debug error %s" % (str(e.message))
        text_handle.write("deviceDetails: %s" % json.dumps(deviceDetails, indent=2,sort_keys=True))

    def packetDetails(self, packetDB):
        try:
            text_handle = open(self.directory + "/packetDetailsReport.txt", "w")
        except Exception as e:
            print "Could not create the report text file !!!!! Please debug error %s" % (str(e.message))
        for ip in packetDB:
            if "TCP" in packetDB[ip]:
                if "HTTP" in packetDB[ip]["TCP"]:
                    text_handle.write("IP: %s ---> \n" % ip)
                    if "Payload" in packetDB[ip]["TCP"]["HTTP"]:
                        for entry in packetDB[ip]["TCP"]["HTTP"]["Payload"]:
                            text_handle.write("%s\n" % entry[TCP].payload)






