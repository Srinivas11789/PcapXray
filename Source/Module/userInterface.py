from Tkinter import *
import Tkinter, Tkconstants, tkFileDialog
import ttk
import tkMessageBox
import pcapReader
import plotLanNetwork
import communicationDetailsFetch
import reportGen
import time
import threading
import Queue
from PIL import Image,ImageTk
import os

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
        ttk.Label(InitFrame, text="Enter pcap file path: ",style="BW.TLabel").grid(column=0, row=0, sticky="W")
        self.filename_field = ttk.Entry(InitFrame, width=30, textvariable=self.pcap_file, style="BW.TEntry").grid(column=1, row=0, sticky="W, E")
        self.progressbar = ttk.Progressbar(InitFrame, orient="horizontal", length=200,value=0, maximum=200,  mode="indeterminate")
        # Browse button
        #self.filename = StringVar()
        ttk.Button(InitFrame, text="Browse", command=self.browse_directory).grid(column=2, row=0, padx=10, pady=10,sticky="E")
        ttk.Button(InitFrame, text="Analyze!", command=self.pcap_analyse).grid(column=3, row=0, padx=10, pady=10,sticky="E")
        self.progressbar.grid(column=4, row=0, padx=10, pady=10, sticky="E")

        # Second Frame with Options
        SecondFrame = ttk.Frame(base,  width=50, padding="10 10 10 10",relief= GROOVE)
        SecondFrame.grid(column=10, row=20, sticky=(N, W, E, S))
        SecondFrame.columnconfigure(10, weight=1)
        SecondFrame.rowconfigure(10, weight=1)
        ttk.Label(SecondFrame, text="Options: ", style="BW.TLabel").grid(row=10,column=0,sticky="W")
        self.option = StringVar()
        self.options = {'All','HTTP','HTTPS','Tor','Malicious'}
        #self.option.set('Tor')
        ttk.OptionMenu(SecondFrame,self.option,"Select",*self.options).grid(row=10,column=1,sticky="W")
        self.zoom = [900,900]
        self.img = ""
        ttk.Button(SecondFrame, text="zoomIn", command=self.zoom_in).grid(row=10,column=10,padx=5,sticky="E")
        ttk.Button(SecondFrame, text="zoomOut", command=self.zoom_out).grid(row=10,column=11,sticky="E")

        # Third Frame with Results and Descriptioms
        self.ThirdFrame = ttk.Frame(base,  width=100, height=100, padding="10 10 10 10",relief= GROOVE)
        description = """It is a tool aimed to simplyfy the network analysis and speed the process of analysing the network traffic.\nThis prototype aims to accomplish 4 important modules,
                        \n 1. Web Traffic\n 2. Tor Traffic \n 3. Malicious Traffic \n 4. Device/Traffic Details\n\nPlease contact me @ spg349@nyu.edu for any bugs or problems !
                      """
        self.label = ttk.Label(self.ThirdFrame, text="Description: \nPcapXray tools is an aid for Network Forensics or Any Network Analysis!\n"+description, style="BW.TLabel")
        self.label.grid(column=10, row=10,sticky="W")
        self.xscrollbar = Scrollbar(self.ThirdFrame, orient=HORIZONTAL)
        self.xscrollbar.grid(row=100, column=0, sticky=E + W)
        self.yscrollbar = Scrollbar(self.ThirdFrame, orient=VERTICAL)
        self.yscrollbar.grid(row=0, column=100, sticky=N + S)
        self.ThirdFrame.grid(column=10, row=30, sticky=(N, W, E, S))
        self.ThirdFrame.columnconfigure(0, weight=1)
        self.ThirdFrame.rowconfigure(0, weight=1)
        self.name_servers = ""

    def browse_directory(self):
        # Reference: http://effbot.org/tkinterbook/tkinter-dialog-windows.htm
        self.pcap_file.set(tkFileDialog.askopenfilename(initialdir = "/",title = "Select Packet Capture File!",filetypes = (("pcap files","*.pcap"),("pcapng files","*.pcapng"))))
        # All option: ,("all files","*.*")
        #self.filename_field.delete(0, END)
        #self.filename_field.insert(0, self.pcap_file)
        print self.pcap_file

    def pcap_analyse(self):
        if os.path.exists(self.pcap_file.get()):
            self.progressbar.start()
            result = Queue.Queue()
            packet_read = threading.Thread(target=pcapReader.pcapReader,args=(self.pcap_file.get(),result))
            packet_read.start()
            while packet_read.is_alive():
                self.progressbar.update()
            packet_read.join()
            self.progressbar.stop()
            #packet_read.join()
            self.capture_read = result.get()
            reportThreadpcap = threading.Thread(target=reportGen.reportGen().packetDetails,args=(self.capture_read,))
            reportThreadpcap.start()
            #self.option.set("Tor")
            self.option.trace("w",self.map_select)
            #self.option.set("Tor")
            self.name_servers = ""
        else:
            tkMessageBox.showerror("Error","File Not Found !")

    def generate_graph(self):
        if self.name_servers == "":
            result = Queue.Queue()
            t = threading.Thread(target=communicationDetailsFetch.trafficDetailsFetch,args=(self.capture_read,result))
            t.start()
            self.progressbar.start()
            while t.is_alive():
                  self.progressbar.update()
            t.join()
            self.progressbar.stop()
            self.name_servers = result.get()
            reportThread = threading.Thread(target=reportGen.reportGen().communicationDetailsReport,args=(self.name_servers,))
            reportThread.start()
        
        if "/" in self.pcap_file.get():
            filename = self.pcap_file.get().split("/")[-1].replace(".pcap","")
        else:
            filename = self.pcap_file.get().replace(".pcap","")

        if not os.path.exists("Report/"+filename+self.option.get()+".png"):
            t1 = threading.Thread(target=plotLanNetwork.plotLan, args=(self.capture_read, filename,self.name_servers,self.option.get(),))
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
        self.img = ImageTk.PhotoImage(Image.open("Report/"+self.pcap_file.get().replace(".pcap","")+self.option.get()+".png").resize(tuple(self.zoom),Image.ANTIALIAS).convert('RGB'))
        self.canvas.create_image(0,0, image=self.img)
        self.canvas.config(scrollregion=self.canvas.bbox(ALL))
        self.xscrollbar.config(command=self.canvas.xview)
        self.yscrollbar.config(command=self.canvas.yview)

    def map_select(self, *args):
        print self.option.get()
        self.generate_graph()

    def zoom_in(self):
        print "zoomin"
        self.zoom[0] += 100
        self.zoom[1] += 100
        if self.img:
             self.load_image()

    def zoom_out(self):
        print "zoomout"
        self.zoom[0] -= 100
        self.zoom[1] -= 100
        if self.img:
             self.load_image()


def main():
    base = Tk()
    pcapXrayGui(base)
    base.mainloop()

#main()

