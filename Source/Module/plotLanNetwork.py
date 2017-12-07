#File Import
import pcapReader
import communicationDetailsFetch
import torTrafficHandle

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
                'fontcolor': 'grey',
                'bgcolor': '#333333',
                'rankdir': 'BT',
            },
            'nodes': {
                'fontname': 'Helvetica',
                'shape': 'circle',
                'fontcolor': 'white',
                'color': 'yellow',
                'style': 'filled',
                'fillcolor': '#006699',
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

    def draw_graph(self, filename, option="All"):
        f = Digraph('network_diagram - '+option, filename=filename)
        f.attr(rankdir='LR', size='8,5')

        f.attr('node', shape='doublecircle')
        f.node('defaultGateway')

        f.attr('node', shape='circle')

        # extract nodes from graph
        nodes = self.packetDB.keys()
        name_servers =
        mal_identify = maliciousTrafficIdentifier(self.packetDB, dns_details)
        tor_identify = torTrafficHandle.torTrafficHandle(self.packetDB).possible_tor_traffic

        if option == "All":
            # add nodes
            for node in nodes:
                f.node(node)
                if "TCP" in self.packetDB[node]:
                    if "HTTPS" in self.packetDB[node]["TCP"]:
                        for dest in self.packetDB[node]["TCP"]["HTTPS"]:
                            f.edge(node, 'defaultGateway', label='HTTPS: ' +dest+": "+name_servers[dest]["dns"], color = "blue")
                    if "HTTP" in self.packetDB[node]["TCP"]:
                        for dest in self.packetDB[node]["TCP"]["HTTP"]["Server"]:
                            f.edge(node, 'defaultGateway', label='HTTP: ' + dest+": "+name_servers[dest]["dns"], color = "green")
                    for tor in tor_identify[node]:
                       f.edge(node, 'defaultGateway', label='TOR: ' + str(tor) ,color="white")


        if option == "HTTP":
            for node in nodes:
                f.node(node)
                if "HTTP" in self.packetDB[node]["TCP"]:
                    name_servers = communicationDetailsFetch.trafficDetailsFetch(self.packetDB[node]).ip_details
                    for dest in self.packetDB[node]["TCP"]["HTTP"]["Server"]:
                        f.edge(node, 'defaultGateway', label='HTTP: ' + dest + ": " + name_servers[dest]["dns"],color="green")

        if option == "HTTPS":
            for node in nodes:
                f.node(node)
                if "TCP" in self.packetDB[node]:
                    if "HTTPS" in self.packetDB[node]["TCP"]:
                        name_servers = communicationDetailsFetch.trafficDetailsFetch(self.packetDB[node]).ip_details
                        for dest in self.packetDB[node]["TCP"]["HTTPS"]:
                            f.edge(node, 'defaultGateway', label='HTTPS: ' +dest+": "+name_servers[dest]["dns"], color = "blue")

        if option == "Tor":
            for node in nodes:
                f.node(node)
                for tor in tor_identify[node]:
                    f.edge(node, 'defaultGateway', label='TOR: ' + str(tor), color="white")

        if option == "Malicious":
            for node in nodes:
                f.node(node)
                for tor in tor_identify[node]:
                    f.edge(node, 'defaultGateway', label='TOR: ' + str(tor), color="red")


        self.apply_styles(f,self.styles)

        f.view()

def main():
    # draw example
    pcapfile = pcapReader.pcapReader('torexample.pcapng')
    print "Reading Done...."
    network = plotLan(pcapfile.packetDB, "network.gv", "All")

main()
