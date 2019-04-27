# Separate Module Tests - Assure proper pcap reading of the example/test.pcap file
# Pending work....
import sys
if sys.path[0]:
    sys.path.insert(0, sys.path[0]+'/../Source/Module/')
else:
    sys.path.insert(0,'/../Source/Module/')

import pcap_reader
import memory

def test_pcapreader():
    pcapfile = pcap_reader.PcapEngine(sys.path[0]+'examples/test.pcap', "scapy")
    if memory.packet_db:
        assert True

test_pcapreader()
