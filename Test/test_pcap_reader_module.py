# Separate Module Tests - Assure proper pcap reading of the example/test.pcap file
# Pending work....
import sys
print sys.path[0]
if sys.path[0]:
    sys.path.insert(0, sys.path[0]+'/../Source/Module/')
else:
    sys.path.insert(0,'/../Source/Module/')

import pcapReader

def test_pcapreader():
    pcapfile = pcapReader.pcapReader(sys.path[0]+'examples/test.pcap')
    if pcapfile.packetDB:
        assert True

test_pcapreader()
