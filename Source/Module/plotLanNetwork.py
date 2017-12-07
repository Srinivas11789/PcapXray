#File Import
import pcapReader
import communicationDetailsFetch

import networkx as nx
import matplotlib.pyplot as plt

from graphviz import Digraph


class plotLan:

    def __init__(self, packetDB, filename, option="All"):
        self.packetDB = packetDB
        self.filename = filename
        #self.draw_graph(self.filename, option)

        self.styles = {
            'graph': {
                'label': 'A Fancy Graph',
                'fontsize': '16',
                'fontcolor': 'white',
                'bgcolor': '#333333',
                'rankdir': 'BT',
            },
            'nodes': {
                'fontname': 'Helvetica',
                'shape': 'hexagon',
                'fontcolor': 'white',
                'color': 'white',
                'style': 'filled',
                'fillcolor': '#006699',
            },
            'edges': {
                'style': 'dashed',
                'color': 'white',
                'arrowhead': 'open',
                'fontname': 'Courier',
                'fontsize': '12',
                'fontcolor': 'white',
            }
        }
        self.draw_graph(self.filename, option)

    def apply_styles(self, graph, styles):
        graph.graph_attr.update(
            ('graph' in styles and styles['graph']) or {}
        )
        graph.node_attr.update(
            ('nodes' in styles and styles['nodes']) or {}
        )
        graph.edge_attr.update(
            ('edges' in styles and styles['edges']) or {}
        )
        return graph

    def draw_graph(self, filename, option="All"):
        f = Digraph('network_diagram - '+option, filename=filename)
        f.attr(rankdir='LR', size='8,5')

        f.attr('node', shape='doublecircle')
        f.node('defaultGateway')

        f.attr('node', shape='circle')

        # extract nodes from graph
        nodes = self.packetDB.keys()

        if option == "All":
            # add nodes
            for node in nodes:
                f.node(node)
                if "TCP" in self.packetDB[node]:
                    if "HTTPS" in self.packetDB[node]["TCP"]:
                        name_servers = communicationDetailsFetch.trafficDetailsFetch(self.packetDB[node]).ip_details
                        for dest in self.packetDB[node]["TCP"]["HTTPS"]:
                            f.edge(node, 'defaultGateway', label='HTTPS: ' + dest + ": " + name_servers[dest]["dns"])

        self.apply_styles(f,self.styles)

        f.view()




def main():
    # draw example
    pcapfile = pcapReader.pcapReader('test.pcap')
    network = plotLan(pcapfile.packetDB, "network.gv", "All")

main()

"""
    for node in nodes:
            if node in self.packetDB:
              if "TCP" in self.packetDB[node]:
                if "HTTPS" in self.packetDB[node]["TCP"]:
                    if "server_addresses" in self.packetDB[node]["TCP"]["HTTPS"]:
                        name_servers = communicationDetailsFetch.trafficDetailsFetch(self.packetDB[node]["TCP"]["HTTPS"]["server_addresses"], "HTTPS").dns_details
                        for dest in self.packetDB[node]["TCP"]["HTTPS"]["server_addresses"]:
                            f.edge(node, 'defaultGateway', label='HTTPS: '+dest+": "+name_servers[dest])
                if "HTTP" in self.packetDB[node]["TCP"]:
                    if "server_addresses" in self.packetDB[node]["TCP"]["HTTP"]:
                        name_servers = communicationDetailsFetch.trafficDetailsFetch(self.packetDB[node]["TCP"]["HTTP"]["server_addresses"], "HTTP").dns_details
                        for dest in self.packetDB[node]["TCP"]["HTTP"]["server_addresses"]:
                            f.edge(node, 'defaultGateway', label='HTTP: '+dest+": "+name_servers[dest])
"""
