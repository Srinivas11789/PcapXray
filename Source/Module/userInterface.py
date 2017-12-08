from Tkinter import *
import ttk
import pcapReader
import plotLanNetwork
import time
import threading
from PIL import Image,ImageTk

class pcapXrayGui:
    def __init__(self, base):
        self.base = base
        base.title("PcapXray")
        #base.resizable(width=FALSE, height=FALSE)
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
        self.option = StringVar()
        options = {'All','HTTP','HTTPS','Tor','Malicious'}
        self.option.set('Tor')
        ttk.OptionMenu(self.SecondFrame,self.option,*options).grid(column=1, row=10,sticky="W, E")

        #self.ThirdCanvas = Canvas(base)
        self.ThirdFrame = ttk.Frame(base,  width=100, height=100, padding="10 10 10 10",relief= GROOVE)
        description = """It is a tool aimed to simplyfy the network analysis and speed the process of analysing the network traffic.\nThis prototype aims to accomplish 4 important modules,
                        \n 1. Web Traffic\n 2. Tor Traffic \n 3. Malicious Traffic \n 4. Device/Traffic Details\n\nPlease contact me @ spg349@nyu.edu for any bugs or problems !
                      """
        #self.scrollHort = ttk.Scrollbar(self.ThirdFrame, orient='horizontal',command=self.ThirdCanvas.xview)
        #self.ThirdCanvas.configure(xscrollcommand=self.scrollHort.set)
        self.label = ttk.Label(self.ThirdFrame, text="Description: \nPcapXray tools is an aid for Network Forensics or Any Network Analysis!\n"+description, style="BW.TLabel")
        self.label.grid(column=10, row=10,sticky="W")
        #self.label.pack(fill=BOTH, expand=YES)
        self.ThirdFrame.grid(column=10, row=30, sticky=(N, W, E, S))
        #self.ThirdFrame.pack(fill=BOTH,expand=YES)
        self.ThirdFrame.columnconfigure(100, weight=1)
        self.ThirdFrame.rowconfigure(100, weight=1)
        #self.ThirdCanvas.grid(column=10, row=30, sticky=(N, W, E, S))
        #self.scrollHort.grid(column=10, row=30, sticky='ew')



    def pcap_analyse(self):
        #def progress_bar():
        self.progressbar.start()
        #t = threading.Thread(None, progress_bar, ())
        #t.start()
        self.base.update()
        capture_read = pcapReader.pcapReader(self.pcap_file.get())
        print "ReadingDone"
        #diag1 = threading.Thread(target=plotLanNetwork.plotLan, args=(capture_read.packetDB, "network111", self.option.get(),))
        #diag1.start()
        #while diag1.is_alive():
        #    self.base.update()
        self.label.grid_forget()
        #image_window = ttk.Frame(self.ThirdCanvas)
        #self.ThirdCanvas.create_window(0,0,window=image_window,anchor='nw')
        image = ImageTk.PhotoImage(Image.open("network123.png").resize((700,700)))
        self.label = ttk.Label(self.ThirdFrame,image=image,relief=RAISED)
        self.label.image = image
        #self.label.grid(sticky="W")
        self.label.pack(fill=X,expand=1)
        #self.label.pack()
        #w = Canvas(self.ThirdFrame, width=50,height=50)
        #w.create_image(0,0,image=image)
        #self.label.pack(fill=BOTH, expand=1)
        #self.base.update()
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
