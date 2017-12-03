#File Import
import pcapReader

import networkx as nx
import matplotlib.pyplot as plt


class plotLan:

    def __init__(self, packetDB):
        self.packetDB = packetDB
        self.draw_graph()

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
        nx.draw(G, pos)

        # show graph
        plt.show()


def main():
    # draw example
    pcapfile = pcapReader.pcapReader('test.pcap')
    for ip in pcapfile.packetDB:
        pcapfile.fetch_specific_protocol(ip, "TCP","HTTPS")
    network = plotLan(pcapfile.packetDB)