import sqlite3
import json
import os
from sqlite_packets import SqlitePackets
from sqlite_destination_hosts import SqliteDestinationHosts

# Key for access is MAC Address/IP Address
# * Initially had mac address (assuming unique) as the only key
#   - CTF problems sometime cause a scenario of same mac with different IP address so segregated this
# * Otherwise each key holds
#   - Mac Vendor
#   - Ip address
global lan_hosts
lan_hosts = {}
global destination_hosts
destination_hosts = {}
global tor_nodes
tor_nodes = []
global possible_tor_traffic
possible_tor_traffic = []
global malicious_traffic
possible_mal_traffic = []
global signatures
signatures = {}

#
# Initialize the Sqlite DB classes
#
global packet_db
global destination_hosts_db

packet_db = SqlitePackets()
destination_hosts_db = SqliteDestinationHosts()

#
# 
#
def init_sqlite_dbs(path, pcap_filename):
    # path for sqlite databases
    directory = os.path.join(path, "Database")
        
    if not os.path.exists(directory):
        os.makedirs(directory)
            
    # Check if the file existed before connection
    filename = os.path.join(directory, os.path.basename(pcap_filename) + "_database.sqlite")
    file_existed =  os.path.exists(filename)
        
    # Create connection and potentially create file
    con = sqlite3.connect(filename, check_same_thread=False)
    cur = con.cursor()
        
    # Create Sqlite Tables
    packet_db.create_table(directory, filename, con, cur)
    #destination_hosts_db
                
    return file_existed
        

