#class memorySetting():


global packet_db
packet_db = {}

# Schema
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
