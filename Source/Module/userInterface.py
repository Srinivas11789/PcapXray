from Tkinter import *
import ttk
import pcapReader
import time
import threading

class pcapXrayGui:
    def __init__(self, base):
        self.base = base
        base.title("PcapXray")
        base.resizable(width=FALSE, height=FALSE)
        Label(base, text="PcapXray Tool - A LAN Network Analyzer")

        style = ttk.Style()
        style.configure("BW.TLabel", foreground="black")
        style.configure("BW.TEntry", foreground="black")

        self.InitFrame = ttk.Frame(base,  width=50, padding="10 10 10 10",relief= GROOVE)
        self.InitFrame.grid(column=10, row=10, sticky=(N, W, E, S))
        self.InitFrame.columnconfigure(10, weight=1)
        self.InitFrame.rowconfigure(10, weight=1)
        self.pcap_file = StringVar()
        self.label = ttk.Label(self.InitFrame, text="Enter pcap file path: ",style="BW.TLabel").grid(column=0, row=0, sticky="W")
        self.file_entry = ttk.Entry(self.InitFrame, width=30, textvariable=self.pcap_file, style="BW.TEntry").grid(column=1, row=0, sticky="W, E")
        self.counter = "0"
        self.progressbar = ttk.Progressbar(self.InitFrame, orient="horizontal", length=200, variable=self.counter,value=0, maximum=200,  mode="indeterminate")
        self.button = ttk.Button(self.InitFrame, text="Analyze!", command=self.pcap_analyse).grid(column=2, row=0, padx=10, pady=10,sticky="E")
        self.progressbar.grid(column=3, row=0, padx=10, pady=10, sticky="E")
        self.SecondFrame = ttk.Frame(base,  width=50, padding="10 10 10 10",relief= GROOVE)
        self.SecondFrame.grid(column=10, row=20, sticky=(N, W, E, S))
        self.SecondFrame.columnconfigure(10, weight=1)
        self.SecondFrame.rowconfigure(10, weight=1)
        self.label = ttk.Label(self.SecondFrame, text="Options: ", style="BW.TLabel").grid(column=0, row=10, sticky="W")
        option = StringVar()
        options = {'All','HTTP','HTTPS','Tor','Malicious'}
        option.set('HTTPS')
        ttk.OptionMenu(self.SecondFrame,option,*options).grid(column=1, row=10,sticky="W, E")

        self.ThirdFrame = ttk.Frame(base,  width=50, padding="10 10 10 10",relief= GROOVE)
        description = """It is a tool aimed to simplyfy the network analysis and speed the process of analysing the network traffic.\nThis prototype aims to accomplish 4 important modules,
                        \n 1. Web Traffic\n 2. Tor Traffic \n 3. Malicious Traffic \n 4. Device/Traffic Details\n\nPlease contact me @ spg349@nyu.edu for any bugs or problems !
                      """
        self.label = ttk.Label(self.ThirdFrame, text="Description: \nPcapXray tools is an aid for Network Forensics or Any Network Analysis!\n"+description, style="BW.TLabel").grid(column=10, row=10,sticky="W")
        self.ThirdFrame.grid(column=10, row=30, sticky=(N, W, E, S))
        self.ThirdFrame.columnconfigure(10, weight=1)
        self.ThirdFrame.rowconfigure(10, weight=1)


    def pcap_analyse(self):
        def progress_bar():
            self.progressbar.start()
        t = threading.Thread(None, progress_bar, ())
        t.start()
        capture_read = pcapReader.pcapReader(self.pcap_file.get())
        print capture_read.packetDB
        self.progressbar.stop()

def main():
    base = Tk()
    pcapgui =pcapXrayGui(base)
    base.mainloop()

main()
"""
def main():
    base = Tk()
    base.title("PcapXray - A Network Traffic Analysis Tool")

    mainframe = ttk.Frame(base, padding="10 10 12 12")
    mainframe.grid(column=10, row=10, sticky=(N, W, E, S))
    mainframe.columnconfigure(0, weight=1)
    mainframe.rowconfigure(0, weight=1)

    pcap_file = StringVar()

    file_entry = ttk.Entry(mainframe, width=10, textvariable=pcap_file)
    file_entry.grid(column=2, row=1, sticky=(W, E))

    ttk.Button(mainframe, text="Analyze!", command=pcap_analyse).grid(column=3, row=1, sticky=W)

    ttk.Label(mainframe, text="Enter pcap file path: ").grid(column=1, row=1, sticky=W)

    for child in mainframe.winfo_children(): child.grid_configure(padx=5, pady=5)

    file_entry.focus()
    base.bind('<Return>', pcap_analyse("network.gv"))

    base.mainloop()

main()
"""
