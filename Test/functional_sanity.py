# Sanity or Smoke Test - Test proper functionality of the module

# Test System Setup
import sys

if sys.path[0]:
    sys.path.insert(0, sys.path[0]+'/../Source/Module/')
else:
    sys.path.insert(0,'/../Source/Module/')


# Report generation module
import reportGen

# End to end Workflow Tests - All tests will be applied to example/test.pcap file


# 1 - pcapReader Module

import pcapReader

def test_pcapreader():
    pcapfile = pcapReader.pcapReader(sys.path[0]+'examples/test.pcap')
    if pcapfile.packetDB:
        reportGen.packetDetails(pcapfile.packetDB)
        assert True


# 2 - communicationDetailsFetch module 

import trafficDetailsFetch

def test_communication_details_fetch():
    capture = pcapReader.pcapReader("lanExample.pcap")
    details = trafficDetailsFetch(capture.packetDB)
    if details.communication_details:
        reportGen.communicationDetails(details)
        assert True

# 3 - deviceDetailsFetch module

import deviceDetailsFetch

def test_device_details_fetch():
    pcapfile = pcapReader.pcapReader('test.pcap')
    for ip in pcapfile.packetDB:
        macObj = fetchDeviceDetails(pcapfile.packetDB[ip])
        reportGen.deviceDetails(macObj)
        if macObj.oui_identification():
            assert True

# 4 - maliciousTrafficIdentifier module

import maliciousTrafficIdentifier

def test_malicious_traffic_identifier():
    malicious_capture = pcapReader.pcapReader("torexample.pcapng")
    dns_details = {}
    mal_identify = maliciousTrafficIdentifier(malicious_capture.packetDB, dns_details)
    if mal_identify.possible_malicious_traffic:
        assert True

# 5 - plotLanNetwork module

import plotLanNetwork
import os

def test_plot_lan_network():
    pcapfile = pcapReader.pcapReader('lanExample.pcap')
    details = communicationDetailsFetch.trafficDetailsFetch(pcapfile.packetDB)
    plotLan(pcapfile.packetDB, "network12345", details.communication_details,"HTTPS")
    if os.path.isfile("Report/network12345"):
        assert True

# 6 - reportGen module

import reportGen

def test_report_gen():
    if os.path.isfile("Report/communicationDetailsReport.txt") and os.path.isfile("Report/deviceDetailsReport.txt") and os.path.isfile("Report/packetDetailsReport.txt"):
        assert True

# 7 - userInterface module
import userInterface

# Manual Test for now - Sikuli type automation to be implemented soon
# * Look at Travis Integrations for GUI Test

# 8 - torTrafficHandle module
import torTrafficHandle

def test_tor_traffic_handle():
    tor_capture = pcapReader.pcapReader("torexample.pcapng")
    tor_identify = torTrafficHandle(tor_capture.packetDB)
    if tor_identify:
        assert True