import sys
try:
    # for Python2
    from Tkinter import *
    import ttk
    import tkFileDialog as fd
    import Tkconstants
    import tkMessageBox as mb
    import Queue as q
except ImportError:
    # for Python3
    from tkinter import *
    from tkinter import ttk
    from tkinter import filedialog as fd
    from tkinter import messagebox as mb
    import queue as q

import pcap_reader
import plot_lan_network
import communication_details_fetch
import device_details_fetch
import report_generator
import time
import threading
from PIL import Image,ImageTk
import os, sys

class pcapXrayGui:
    def __init__(self, base):
        # Base Frame Configuration
        self.base = base
        base.title("PcapXray")
        Label(base, text="PcapXray Tool - A LAN Network Analyzer")

        # Style Configuration
        style = ttk.Style()
        style.configure("BW.TLabel", foreground="black")
        style.configure("BW.TEntry", foreground="black")

        # 1st Frame - Initial Frame
        InitFrame = ttk.Frame(base,  width=50, padding="10 10 10 10",relief= GROOVE)
        InitFrame.grid(column=10, row=10, sticky=(N, W, E, S))
        InitFrame.columnconfigure(10, weight=1)
        InitFrame.rowconfigure(10, weight=1)

        # Pcap File Entry
        self.pcap_file = StringVar()
        self.filename = ""
        ttk.Label(InitFrame, text="Enter pcap file path: ",style="BW.TLabel").grid(column=0, row=0, sticky="W")
        self.filename_field = ttk.Entry(InitFrame, width=32, textvariable=self.pcap_file, style="BW.TEntry").grid(column=1, row=0, sticky="W, E")
        self.progressbar = ttk.Progressbar(InitFrame, orient="horizontal", length=200,value=0, maximum=200,  mode="indeterminate")
        # Browse button
        #self.filename = StringVar()
        ttk.Button(InitFrame, text="Browse", command=lambda: self.browse_directory("pcap")).grid(column=2, row=0, padx=10, pady=10,sticky="E")
        ttk.Button(InitFrame, text="Analyze!", command=self.pcap_analyse).grid(column=3, row=0, padx=10, pady=10,sticky="E")
        self.progressbar.grid(column=4, row=0, padx=10, pady=10, sticky="E")

        # First Frame with Report Directory
        # Output and Results Frame
        FirstFrame = ttk.Frame(base,  width=50, padding="10 0 0 0", relief= GROOVE)
        FirstFrame.grid(column=10, row=20, sticky=(N, W, E, S))
        FirstFrame.columnconfigure(10, weight=1)
        FirstFrame.rowconfigure(10, weight=1)
        self.destination_report = StringVar(value=sys.path[0])
        ttk.Label(FirstFrame, text="Output directory path: ",style="BW.TLabel").grid(column=0, row=0, sticky="W")
        self.report_field = ttk.Entry(FirstFrame, width=30, textvariable=self.destination_report, style="BW.TEntry").grid(column=1, row=0, sticky="W, E")
        # Browse button
        ttk.Button(FirstFrame, text="Browse", command=lambda: self.browse_directory("report")).grid(column=2, row=0, padx=10, pady=10,sticky="E")        

        # Second Frame with Options
        SecondFrame = ttk.Frame(base,  width=50, padding="10 10 10 10",relief= GROOVE)
        SecondFrame.grid(column=10, row=30, sticky=(N, W, E, S))
        SecondFrame.columnconfigure(10, weight=1)
        SecondFrame.rowconfigure(10, weight=1)
        ttk.Label(SecondFrame, text="Options: ", style="BW.TLabel").grid(row=10,column=0,sticky="W")
        self.option = StringVar()
        self.options = {'All', 'HTTP', 'HTTPS', 'Tor', 'Malicious', 'ICMP', 'DNS'}
        #self.option.set('Tor')
        ttk.OptionMenu(SecondFrame,self.option,"Select",*self.options).grid(row=10,column=1,sticky="W")
        self.zoom = [900,900]
        self.img = ""
        ttk.Button(SecondFrame, text="zoomIn", command=self.zoom_in).grid(row=10,column=10,padx=5,sticky="E")
        ttk.Button(SecondFrame, text="zoomOut", command=self.zoom_out).grid(row=10,column=11,sticky="E")

        # Third Frame with Results and Descriptioms
        self.ThirdFrame = ttk.Frame(base,  width=100, height=100, padding="10 10 10 10",relief= GROOVE)
        description = """It is a tool aimed to simplyfy the network analysis and speed the process of analysing the network traffic.\nThis prototype aims to accomplish 4 important modules,
                        \n 1. Web Traffic\n 2. Tor Traffic \n 3. Malicious Traffic \n 4. Device/Traffic Details \n 5. Covert Communication \n \nPlease contact me @ spg349@nyu.edu for any bugs or problems !
                      """
        self.label = ttk.Label(self.ThirdFrame, text="Description: \nPcapXray tools is an aid for Network Forensics or Any Network Analysis!\n"+description, style="BW.TLabel")
        self.label.grid(column=10, row=10,sticky="W")
        self.xscrollbar = Scrollbar(self.ThirdFrame, orient=HORIZONTAL)
        self.xscrollbar.grid(row=100, column=0, sticky=E + W)
        self.yscrollbar = Scrollbar(self.ThirdFrame, orient=VERTICAL)
        self.yscrollbar.grid(row=0, column=100, sticky=N + S)
        self.ThirdFrame.grid(column=10, row=40, sticky=(N, W, E, S))
        self.ThirdFrame.columnconfigure(0, weight=1)
        self.ThirdFrame.rowconfigure(0, weight=1)
        #self.details_fetch = 0
        #self.destination_report = ""

    def browse_directory(self, option):
        if option == "pcap":
            # Reference: http://effbot.org/tkinterbook/tkinter-dialog-windows.htm
            self.pcap_file.set(fd.askopenfilename(initialdir = sys.path[0],title = "Select Packet Capture File!",filetypes = (("All","*.pcap *.pcapng"),("pcap files","*.pcap"),("pcapng files","*.pcapng"))))
            self.filename = self.pcap_file.get().replace(".pcap","")
            if "/" in self.filename:
                self.filename = self.filename.split("/")[-1]
            #,("all files","*.*")
            #self.filename_field.delete(0, END)
            #self.filename_field.insert(0, self.pcap_file)
            print(self.filename)
            print(self.pcap_file)
        else:
            self.destination_report.set(fd.askdirectory())
            if self.destination_report.get():
                if not os.access(self.destination_report.get(), os.W_OK):
                    mb.showerror("Error","Permission denied to create report! Run with higher privilege.")
            else:
                mb.showerror("Error", "Enter a output directory!")

    def pcap_analyse(self):
        if not os.access(self.destination_report.get(), os.W_OK):
            mb.showerror("Error","Permission denied to create report! Run with higher privilege.")
            return

        if os.path.exists(self.pcap_file.get()):
            self.progressbar.start()
            #result = q.Queue()
            packet_read = threading.Thread(target=pcap_reader.PcapEngine,args=(self.pcap_file.get(),"scapy"))
            packet_read.start()
            while packet_read.is_alive():
                self.progressbar.update()
            packet_read.join()
            self.progressbar.stop()
            #packet_read.join()
            #self.capture_read = result.get()
            reportThreadpcap = threading.Thread(target=report_generator.reportGen(self.destination_report.get(), self.filename).packetDetails,args=())
            reportThreadpcap.start()
            #self.option.set("Tor")
            self.option.trace("w",self.map_select)
            #self.option.set("Tor")
            self.details_fetch = 0
        else:
            mb.showerror("Error","File Not Found !")

    def generate_graph(self):
        if self.details_fetch == 0:
            #result = q.Queue()
            t = threading.Thread(target=communication_details_fetch.trafficDetailsFetch,args=("sock",))
            t1 = threading.Thread(target=device_details_fetch.fetchDeviceDetails("ieee").fetch_info, args=())
            t.start()
            t1.start()
            self.progressbar.start()
            while t.is_alive():
                  self.progressbar.update()
            t.join()
            t1.join()
            self.progressbar.stop()
            #self.name_servers = result.get()
            reportThread = threading.Thread(target=report_generator.reportGen(self.destination_report.get(), self.filename).communicationDetailsReport,args=())
            reportThread.start()
            reportThread = threading.Thread(target=report_generator.reportGen(self.destination_report.get(), self.filename).deviceDetailsReport,args=())
            reportThread.start()
        
        self.image_file = os.path.join(self.destination_report.get(), "Report", self.filename+"_"+self.option.get()+".png")
        if not os.path.exists(self.image_file):
            t1 = threading.Thread(target=plot_lan_network.plotLan, args=(self.filename, self.destination_report.get(), self.option.get(),))
            t1.start()
            self.progressbar.start()
            while t1.is_alive():
                 self.progressbar.update()
            t1.join()
            self.progressbar.stop()
            self.label.grid_forget()
            self.load_image()
        else:
            self.label.grid_forget()
            self.load_image()

    def load_image(self):
        self.canvas = Canvas(self.ThirdFrame, width=700,height=600, bd=0, bg="navy", xscrollcommand=self.xscrollbar.set, yscrollcommand=self.yscrollbar.set)
        self.canvas.grid(row=0, column=0, sticky=N + S + E + W)
        self.img = ImageTk.PhotoImage(Image.open(self.image_file).resize(tuple(self.zoom),Image.ANTIALIAS))#.convert('RGB'))
        self.canvas.create_image(0,0, image=self.img)
        self.canvas.config(scrollregion=self.canvas.bbox(ALL))
        self.xscrollbar.config(command=self.canvas.xview)
        self.yscrollbar.config(command=self.canvas.yview)

    def map_select(self, *args):
        print(self.option.get())
        self.generate_graph()

    def zoom_in(self):
        print("zoomin")
        self.zoom[0] += 100
        self.zoom[1] += 100
        if self.img:
             self.load_image()

    def zoom_out(self):
        print("zoomout")
        if self.zoom[0] > 700 and self.zoom[1] > 700:
            self.zoom[0] -= 100
            self.zoom[1] -= 100
        else:
            print("zoomout --> maximum")
        if self.img:
             self.load_image()


def main():
    base = Tk()
    pcapXrayGui(base)
    base.mainloop()

