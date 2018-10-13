# Test file for deviceDetailsFetch module
"""
The Module as of now has the following provisions:
* Obtained the ethernet address of all the host present in the network < obtained from packetsDb > 
* Identify the OUI 
* Format the response and Update the packetDb with corresponding information
"""

# Reference to the modules folder
import sys
print sys.path[0]
if sys.path[0]:
    sys.path.insert(0, sys.path[0]+'/../Source/Module/')
else:
    sys.path.insert(0,'/../Source/Module/')

import pcapReader
import deviceDetailsFetch 

# Testcases

def test_workflow_with_example_pcap():
    filename = "test.pcap"
    pcapfile = pcapReader.pcapReader(sys.path[0]+'examples/'+filename)
    for ip in pcapfile.packetDB:
        macObj = deviceDetailsFetch.fetchDeviceDetails(pcapfile.packetDB[ip])
        if macObj.oui_identification():
 		assert True
	

