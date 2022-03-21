# Report Generation
import os, json
from scapy.all import *
import memory

# Module to write in files the reports.
# This class generates the report when the user clicks on analyze button. 
# All reports are stored in the Report folder inside of the Module folder.
class reportGen:

    def __init__(self, path, filename):
        self.directory = os.path.join(path, "Report")
        if not os.path.exists(self.directory):
            os.makedirs(self.directory)
        self.filename = filename

    def communicationDetailsReport(self):
        try:
            print("Reporting communication details...")
            comm_file = os.path.join(self.directory, self.filename + "_communication_details.txt")
            text_handle = open(comm_file, "w")
            text_handle.write("CommunicationDetails: %s\n" % json.dumps(memory.destination_hosts, indent=2,sort_keys=True))
            text_handle.write("Tor Traffic: %s\n" % json.dumps(memory.possible_tor_traffic, indent=2,sort_keys=True))
            text_handle.write("Malicious Traffic: %s\n" % json.dumps(memory.possible_mal_traffic, indent=2,sort_keys=True))
            text_handle.write("Destination DNS: %s\n" % json.dumps(memory.destination_hosts, indent=2,sort_keys=True))
            text_handle.write("Lan Hosts: %s\n" % json.dumps(memory.lan_hosts, indent=2,sort_keys=True))
            text_handle.write("Tor Nodes: %s\n" % json.dumps(memory.tor_nodes, indent=2,sort_keys=True))
            text_handle.close()
            print("Done.")
        except Exception as e:
            print("Could not create the report text file !!!!! Please debug error %s" % (str(e)))

    def deviceDetailsReport(self):
        try:
            print("Reporting device details...")
            device_file = os.path.join(self.directory, self.filename + "_device_details.txt")
            text_handle = open(device_file, "w")
            text_handle.write("deviceDetails: %s\n" % json.dumps(memory.lan_hosts, indent=2,sort_keys=True))
            text_handle.close()
            print("Done.")
        except Exception as e:
            print("Could not create the report text file !!!!! Please debug error %s" % (str(e)))

    def packetDetails(self):
        try:
            print("Reporting raw packet details...")
            packet_file = os.path.join(self.directory, self.filename + "_packet_details.txt")
            text_handle = open(packet_file, "w")
            text_handle.write("%s\n" % json.dumps(memory.packet_db.get_all(), indent=2, sort_keys=True))            
            text_handle.close()
            print("Done.")
        except Exception as e:
            print("Could not create the report text file, trying backup mode !!!!! %s" % (str(e)))
            self.backupReport()

    def backupReport(self):
        try:
            print("Reporting backup details...")
            """
            packet_file = os.path.join(self.directory, self.filename + "_packet_details.txt")
            text_handle = open(packet_file, "w")
            # <TODO>: Do we need to format payload?
            for session in memory.packet_db.session_keys():
                text_handle.write("\nSession: %s\n" % session)
                text_handle.write("\nEthernet: %s\n" % memory.packet_db[session]["Ethernet"])
                text_handle.write("\nPayload:\n")
                fpayloads = "\n".join(memory.packet_db[session]["Payload"]["forward"])
                text_handle.write("\nForward:\n")
                if fpayloads:
                    text_handle.write("%s\n" % fpayloads)
                rpayloads = "\n".join(memory.packet_db[session]["Payload"]["reverse"])
                text_handle.write("\nReverse:\n")
                if rpayloads:
                    text_handle.write("%s\n" % rpayloads)                
                text_handle.write("="*80+"\n")
            text_handle.close()
            """
        except Exception as e:
            print("Could not create the report text file by backup method !!!!! Please debug error %s" % (str(e)))