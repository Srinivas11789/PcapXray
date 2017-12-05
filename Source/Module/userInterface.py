from Tkinter import *
import  ttk
from PIL import Image, ImageTk
from cairocffi import cairo
import rsvg

def pcap_analyse(filename):
    try:
        tk_image = svgPhotoImage(filename)
        mainframe.configure(image=tk_image)
    except ValueError:
        pass

def svgPhotoImage(file_name):
            "Returns a ImageTk.PhotoImage object represeting the svg file"
            # Based on pygame.org/wiki/CairoPygame and http://bit.ly/1hnpYZY
            svg = rsvg.Handle(file=file_name)
            width, height = svg.get_dimension_data()[:2]
            surface = cairo.ImageSurface(cairo.FORMAT_ARGB32, int(width), int(height))
            context = cairo.Context(surface)
            # context.set_antialias(cairo.ANTIALIAS_SUBPIXEL)
            svg.render_cairo(context)
            tk_image = ImageTk.PhotoImage('RGBA')
            image = Image.frombuffer('RGBA', (width, height), surface.get_data(), 'raw', 'BGRA', 0, 1)
            tk_image.paste(image)
            return (tk_image)


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
base.bind('<Return>', pcap_analyse("network.gv"))

base.mainloop()


