from tkinter import *
from tkinter import ttk


def calculate(*args):
    try:
        value = float(feet.get())
        meters.set((0.3048 * value * 10000.0 + 0.5) / 10000.0)
    except ValueError:
        pass

base = Tk()
base.title("PcaXray - A Network Traffic Analysis Tool")

mainframe = ttk.Frame(base, padding="10 10 12 12")
mainframe.grid(column=0, row=0, sticky=(N, W, E, S))
mainframe.columnconfigure(0, weight=1)
mainframe.rowconfigure(0, weight=1)

pcap_file = StringVar()

file_entry = ttk.Entry(mainframe, width=10, textvariable=pcap_file)
file_entry.grid(column=2, row=1, sticky=(W, E))

ttk.Button(mainframe, text="Analyze!", command=pcap_analyse).grid(column=3, row=3, sticky=W)

ttk.Label(mainframe, text="Enter pcap file path: ").grid(column=1, row=1, sticky=W)

for child in mainframe.winfo_children(): child.grid_configure(padx=5, pady=5)

file_entry.focus()
base.bind('<Return>', calculate)

base.mainloop()