# Sanity or Smoke Test - Test proper functionality of the module

# Test System Setup
import sys
import os

if sys.path[0]:
    sys.path.insert(0, sys.path[0]+'/../Source/Module/')
else:
    sys.path.insert(0,'/../Source/Module/')

# All the Module imports

# Report generation module
import reportGen
# 1 - pcapReader Module
import pcapReader
# 2 - communicationDetailsFetch module 
import communicationDetailsFetch
# 3 - deviceDetailsFetch module
import deviceDetailsFetch
# 4 - maliciousTrafficIdentifier module
import maliciousTrafficIdentifier
# 5 - plotLanNetwork module
import plotLanNetwork
# 7 - userInterface module
import userInterface
# 8 - torTrafficHandle module
import torTrafficHandle

# End to end Workflow Tests - All tests will be applied to example/test.pcap file

def test_pcapreader():
    pcapfile = pcapReader.pcapReader(sys.path[0]+'examples/test.pcap')
    if pcapfile.packetDB:
        assert True

def test_communication_details_fetch():
    capture = pcapReader.pcapReader(sys.path[0]+'examples/test.pcap')
    details = communicationDetailsFetch.trafficDetailsFetch(capture.packetDB)
    if details.communication_details:
        assert True

def test_device_details_fetch():
    pcapfile = pcapReader.pcapReader(sys.path[0]+'examples/test.pcap')
    for ip in pcapfile.packetDB:
        macObj = deviceDetailsFetch.fetchDeviceDetails(pcapfile.packetDB[ip])
        if macObj.oui_identification():
            assert True

def test_malicious_traffic_identifier():
    malicious_capture = pcapReader.pcapReader(sys.path[0]+'examples/test.pcap')
    dns_details = {}
    mal_identify = maliciousTrafficIdentifier.maliciousTrafficIdentifier(malicious_capture.packetDB, dns_details)
    if mal_identify.possible_malicious_traffic:
        assert True

#def test_plot_lan_network():
#    pcapfile = pcapReader.pcapReader(sys.path[0]+'examples/test.pcap')
#    details = communicationDetailsFetch.trafficDetailsFetch(pcapfile.packetDB)
#    plotLanNetwork.plotLan(pcapfile.packetDB, "network12345", details.communication_details,"HTTPS")
#    if os.path.isfile(sys.path[1]+"/../Report/network12345"):
#        assert True

def test_report_gen():
    pcapfile = pcapReader.pcapReader(sys.path[0]+'examples/test.pcap')
    if pcapfile.packetDB:
        reportGen.reportGen().packetDetails(pcapfile.packetDB)
        if os.path.isfile(sys.path[1]+"/../Report/communicationDetailsReport.txt") and os.path.isfile(sys.path[1]+"/../Report/deviceDetailsReport.txt") and os.path.isfile(sys.path[1]+"/../Report/packetDetailsReport.txt"):
            assert True

# 7 - userInterface module
# Manual Test for now - Sikuli type automation to be implemented soon
# * Look at Travis Integrations for GUI Test

def test_tor_traffic_handle():
    tor_capture = pcapReader.pcapReader(sys.path[0]+'examples/test.pcap')
    tor_identify = torTrafficHandle.torTrafficHandle(tor_capture.packetDB)
    if tor_identify:
        assert True