# Sanity or Smoke Test - Test proper functionality of the module

# Test System Setup
import sys
import os
import pytest

if sys.path[0]:
    sys.path.insert(0, sys.path[0]+'/../Source/Module/')
else:
    sys.path.insert(0,'/../Source/Module/')

# All the Module imports

# Report generation module
import report_generator
# 1 - pcapReader Module
import pcap_reader
# 2 - communicationDetailsFetch module 
import communication_details_fetch
# 3 - deviceDetailsFetch module
import device_details_fetch
# 4 - maliciousTrafficIdentifier module
import malicious_traffic_identifier
# 5 - plotLanNetwork module
#import plotLanNetwork
# 7 - userInterface module
#import userInterface
# 8 - torTrafficHandle module
import tor_traffic_handle
import memory

# End to end Workflow Tests - All tests will be applied to example/test.pcap file
pcap_files = os.listdir(sys.path[0]+"examples/")

@pytest.mark.parametrize("packet_capture_file", pcap_files)
def test_pcapreader(packet_capture_file):
    pcap_reader.PcapEngine(sys.path[0]+'examples/'+packet_capture_file, "scapy")
    if memory.packet_db:
        memory.packet_db = {}
        assert True

def test_pcapreader_pyshark_engine():
    # Testing pyshark engine for >= python3.0
    from sys import version_info
    if version_info[0] >= 3:
        pcapfile = pcap_reader.PcapEngine(sys.path[0]+'examples/test.pcap', "pyshark")
        if memory.packet_db:
                assert True
    else:
        # Python2.7 tests
        # Ref: https://medium.com/python-pandemonium/testing-sys-exit-with-pytest-10c6e5f7726f
        with pytest.raises(SystemExit):
             pcap_reader.PcapEngine(sys.path[0]+'examples/test.pcap', "pyshark")

def test_communication_details_fetch():
    pcap_reader.PcapEngine(sys.path[0]+'examples/test.pcap', "scapy")
    communication_details_fetch.trafficDetailsFetch("sock")
    if memory.destination_hosts:
        assert True

def test_device_details_fetch():
    pcap_reader.PcapEngine(sys.path[0]+'examples/test.pcap', "scapy")
    device_details_fetch.fetchDeviceDetails("ieee").fetch_info()
    if memory.lan_hosts:
        assert True

def test_malicious_traffic_identifier():
    pcap_reader.PcapEngine(sys.path[0]+'examples/test.pcap', "scapy")
    communication_details_fetch.trafficDetailsFetch("sock")
    malicious_traffic_identifier.maliciousTrafficIdentifier()
    if memory.possible_mal_traffic:
        assert True

#def test_plot_lan_network():
#    pcapfile = pcapReader.pcapReader(sys.path[0]+'examples/test.pcap')
#    details = communicationDetailsFetch.trafficDetailsFetch(pcapfile.packetDB)
#    plotLanNetwork.plotLan(pcapfile.packetDB, "network12345", details.communication_details,"HTTPS")
#    if os.path.isfile(sys.path[1]+"/../Report/network12345"):
#        assert True

def test_report_gen():
    directory = sys.path[0] 
    filename = "test"
    pcap_reader.PcapEngine(directory + 'examples/' + filename + ".pcap", "scapy")
    if memory.packet_db:
        report_generator.reportGen(sys.path[0], filename).packetDetails()
        report_generator.reportGen(sys.path[0], filename).communicationDetailsReport()
        report_generator.reportGen(sys.path[0], filename).deviceDetailsReport()
        if os.path.isfile(sys.path[0]+"/Report/testcommunicationDetailsReport.txt") and os.path.isfile(sys.path[0]+"/Report/testdeviceDetailsReport.txt") and os.path.isfile(sys.path[0]+"/Report/testpacketDetailsReport.txt"):
            assert True

# 7 - userInterface module
# Manual Test for now - Sikuli type automation to be implemented soon
# * Look at Travis Integrations for GUI Test

def test_tor_traffic_handle():
    pcap_reader.PcapEngine(sys.path[0]+'examples/test.pcap', "scapy")
    tor_traffic_handle.torTrafficHandle().tor_traffic_detection()
    if memory.possible_tor_traffic:
            assert True