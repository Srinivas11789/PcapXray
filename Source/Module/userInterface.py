from Tkinter import *
import ttk
import pcapReader
import plotLanNetwork
import time
import threading
from PIL import Image,ImageTk

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
        ttk.Entry(InitFrame, width=30, textvariable=self.pcap_file, style="BW.TEntry").grid(column=1, row=0, sticky="W, E")
        self.progressbar = ttk.Progressbar(InitFrame, orient="horizontal", length=200,value=0, maximum=200,  mode="indeterminate")
        ttk.Button(InitFrame, text="Analyze!", command=self.pcap_analyse).grid(column=2, row=0, padx=10, pady=10,sticky="E")
        self.progressbar.grid(column=3, row=0, padx=10, pady=10, sticky="E")

        # Second Frame with Options
        SecondFrame = ttk.Frame(base,  width=50, padding="10 10 10 10",relief= GROOVE)
        SecondFrame.grid(column=10, row=20, sticky=(N, W, E, S))
        SecondFrame.columnconfigure(10, weight=1)
        SecondFrame.rowconfigure(10, weight=1)
        ttk.Label(SecondFrame, text="Options: ", style="BW.TLabel").grid(column=0, row=10, sticky="W")
        self.option = StringVar()
        options = {'All','HTTP','HTTPS','Tor','Malicious'}
        self.option.set('Tor')
        ttk.OptionMenu(SecondFrame,self.option,*options).grid(column=1, row=10,sticky="W, E")

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

    def pcap_analyse(self):
        self.progressbar.start()
        self.base.update()
        print self.option.get()
        self.capture_read = pcapReader.pcapReader(self.pcap_file.get())
        self.progressbar.stop()
        t1 = threading.Thread(target=plotLanNetwork.plotLan, args=(self.capture_read.packetDB, self.pcap_file.get().replace(".pcap",""),self.option.get(),))
        t1.start()
        while t1.is_alive():
            self.progressbar.start()
            self.base.update()
        self.progressbar.stop()
        self.label.grid_forget()
        canvas = Canvas(self.ThirdFrame, width=700,height=600, bd=0, bg="navy", xscrollcommand=self.xscrollbar.set, yscrollcommand=self.yscrollbar.set)
        canvas.grid(row=0, column=0, sticky=N + S + E + W)
        self.img = ImageTk.PhotoImage(Image.open(self.pcap_file.get().replace(".pcap","")+self.option.get()+".png").resize((900,900),Image.ANTIALIAS).convert('RGB'))
        canvas.create_image(0,0, image=self.img)
        canvas.config(scrollregion=canvas.bbox(ALL))
        self.xscrollbar.config(command=canvas.xview)
        self.yscrollbar.config(command=canvas.yview)
        self.option.trace("w",self.map_select)

    def map_select(self, *args):
        print self.option.get()
        self.pcap_analyse()
    
#    def show_graph(self):

 #       self.img = ImageTk.PhotoImage(Image.open(self.pcap_file.get().replace(".pcap","")+self.option.get()+".png").resize((900,900),Image.ANTIALIAS).convert('RGB'))
   #     canvas.create_image(0,0, image=self.img)
  #      self.base.update()

def main():
    base = Tk()
    pcapgui =pcapXrayGui(base)
    base.mainloop()

main()
