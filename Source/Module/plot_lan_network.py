#File Import
import pcap_reader
import communication_details_fetch
import tor_raffic_handle
import malicious_traffic_identifier
import device_details_fetch
import memory

import networkx as nx
#import matplotlib.pyplot as plt

from graphviz import Digraph
import threading
import os

class plotLan:

    def __init__(self, filename, path, option="Tor"):
        if not os.path.exists(path+"/Report"):
            os.makedirs(path+"/Report")
        self.filename = path+"/Report/"+filename+option

        self.styles = {
            'graph': {
                'label': 'PcapGraph',
                'fontsize': '16',
                'fontcolor': 'black',
                'bgcolor': 'grey',
                'rankdir': 'BT',
                'dpi':'300'
            },
            'nodes': {
                'fontname': 'Helvetica',
                'shape': 'circle',
                'fontcolor': 'black',
                'color': ' black',
                'style': 'filled',
                'fillcolor': 'yellow',
            }
        }

        self.sessions = self.packetDB.keys()
        device_details_fetch.fetchDeviceDetails("ieee").fetch_info()
        if option == "Malicious" or option == "All":
            self.mal_identify = malicious_traffic_identifier.maliciousTrafficIdentifier()
        if option == "Tor" or option == "All":
            self.tor_identify = tor_traffic_handle.torTrafficHandle().tor_traffic_detection()
        self.draw_graph(option)
    
    def apply_styles(self, graph, styles):
        graph.graph_attr.update(
            ('graph' in styles and styles['graph']) or {}
        )
        graph.node_attr.update(
            ('nodes' in styles and styles['nodes']) or {}
        )
        return graph

    def apply_custom_style(self, graph, color):
        style = {'edges': {
                'style': 'dashed',
                'color': color,
                'arrowhead': 'open',
                'fontname': 'Courier',
                'fontsize': '12',
                'fontcolor': color,
        }}
        graph.edge_attr.update(
            ('edges' in style and style['edges']) or {}
        )
        return graph

    def draw_graph(self,option="All"):
        f = Digraph('network_diagram - '+option, filename=self.filename, engine="dot", format="png")
        f.attr(rankdir='LR', size='8,5')

        f.attr('node', shape='doublecircle')
        f.node('defaultGateway')

        f.attr('node', shape='circle')

        print "Starting Graph Plotting"

        if option == "All":
            # add nodes
            for session in self.sessions:
                src, dst, port = session.split("/")
                try:
                    curr_node = src+"\n"+memory.lan_hosts[src]['mac']+"\n"+memory.lan_hosts[src]['device_vendor']
                except:
                    curr_node = src
                f.node(curr_node)

                if session in memory.possible_tor_traffic:
                    f.edge(curr_node, 'defaultGateway', label='TOR: ' + str(dst) ,color="white")
                elif session in memory.possible_mal_traffic:
                    f.edge(curr_node, 'defaultGateway', label='Malicious: ' + str(dst) ,color="red")
                else:
                    if port == "443":
                        f.edge(curr_node, 'defaultGateway', label='HTTPS: ' +dst+": "+memory.destination_hosts[dst], color = "blue")
                    if port == "80":
                        f.edge(curr_node, 'defaultGateway', label='HTTP: ' + dst+": "+memory.destination_hosts[dst], color = "green")

        if option == "HTTP":
            for session in self.sessions:
                src, dst, port = session.split("/")
                try:
                    curr_node = src+"\n"+memory.lan_hosts[src]['mac']+"\n"+memory.lan_hosts[src]['device_vendor']
                except:
                    curr_node = src

                f.node(curr_node)

                if port == "80":
                    f.edge(curr_node, 'defaultGateway', label='HTTP: ' + dst+": "+memory.destination_hosts[dst], color = "green")

        if option == "HTTPS":
           for session in self.sessions:
                src, dst, port = session.split("/")
                try:
                    curr_node = src+"\n"+memory.lan_hosts[src]['mac']+"\n"+memory.lan_hosts[src]['device_vendor']
                except:
                    curr_node = src

                f.node(curr_node)

                if port == "443":
                    f.edge(curr_node, 'defaultGateway', label='HTTPS: ' + dst+": "+memory.destination_hosts[dst], color = "blue")



        if option == "Tor":
            for session in self.sessions:
                src, dst, port = session.split("/")
                try:
                    curr_node = src+"\n"+memory.lan_hosts[src]['mac']+"\n"+memory.lan_hosts[src]['device_vendor']
                except:
                    curr_node = src

                f.node(curr_node)

                if session in memory.possible_tor_traffic:
                    f.edge(curr_node, 'defaultGateway', label='TOR: ' + str(dst) ,color="white")

        if option == "Malicious":
            for session in self.sessions:
                src, dst, port = session.split("/")
                try:
                    curr_node = src+"\n"+memory.lan_hosts[src]['mac']+"\n"+memory.lan_hosts[src]['device_vendor']
                except:
                    curr_node = src
                f.node(curr_node)

                if session in memory.possible_mal_traffic:
                    f.edge(curr_node, 'defaultGateway', label='Malicious: ' + str(dst) ,color="red")
        
        self.apply_styles(f,self.styles)
        f.render()


def main():
    # draw example
    pcapfile = pcapReader.pcapReader('lanExample.pcap')
    print "Reading Done...."
    details = communicationDetailsFetch.trafficDetailsFetch(pcapfile.packetDB)
    network = plotLan(pcapfile.packetDB, "network12345", details.communication_details,"HTTPS")

#main()
