#File Import
import pcapReader

import networkx as nx
import matplotlib.pyplot as plt

from graphviz import Digraph

class plotLan:

    def __init__(self, packetDB):
        self.packetDB = packetDB
        self.draw_graph2()

    def draw_graph(self):

        # extract nodes from graph
        nodes = self.packetDB.keys()

        # create networkx graph
        G=nx.Graph()

        # add nodes
        for node in nodes:
            G.add_node(node)

        G.add_node("defaultGateway")

        # add edges
        # HTTPS and HTTP traffic
        for node in nodes:
            if node in self.packetDB:
                if "HTTPS" in self.packetDB[node]["TCP"]:
                    for dest in self.packetDB[node]["TCP"]["HTTPS"]["server_addresses"]:
                        G.add_edge(node, "defaultGateway")

        # draw graph
        pos = nx.shell_layout(G)
        nx.draw(G, pos, with_labels=True)

        # show graph
        plt.show()

    def draw_graph2(self):
        f = Digraph('network_diagram', filename='network.gv')
        f.attr(rankdir='LR', size='8,5')

        f.attr('node', shape='doublecircle')
        f.node('defaultGateway')

        f.attr('node', shape='circle')

        # extract nodes from graph
        nodes = self.packetDB.keys()

        # add nodes
        for node in nodes:
            f.node(node)

        for node in nodes:
            if node in self.packetDB:
              if "TCP" in self.packetDB[node]:
                if "HTTPS" in self.packetDB[node]["TCP"]:
                    if "server_addresses" in self.packetDB[node]["TCP"]["HTTPS"]:
                        for dest in self.packetDB[node]["TCP"]["HTTPS"]["server_addresses"]:
                            f.edge(node, 'defaultGateway', label='HTTPS: '+dest)
                if "HTTP" in self.packetDB[node]["TCP"]:
                    if "server_addresses" in self.packetDB[node]["TCP"]["HTTP"]:
                        for dest in self.packetDB[node]["TCP"]["HTTP"]["server_addresses"]:
                            f.edge(node, 'defaultGateway', label='HTTP: '+dest)

        f.view()



def main():
    # draw example
    pcapfile = pcapReader.pcapReader('lanExample.pcap')
    #print pcapfile.packetDB
    for ip in pcapfile.packetDB:
        pcapfile.fetch_specific_protocol(ip,"TCP","HTTPS")
        pcapfile.fetch_specific_protocol(ip, "TCP","HTTP")

    network = plotLan(pcapfile.packetDB)

main()
