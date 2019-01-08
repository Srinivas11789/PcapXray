# Main File - Driver for the Application PcapXray

# Import Libraries
import os   #-- default lib - packed with python
import sys  #-- default lib
import datetime  #-- default lib
from Tkinter import *
import ttk

# Import Custom Modules - Self created by the author
if sys.path[0]:
    sys.path.insert(0,sys.path[0]+'/Module/')
else:
    sys.path.insert(0, 'Module/')
import userInterface

# Import 3rd party Libraries -- Needed to be installed using pip
import warnings
warnings.filterwarnings("ignore", category=UserWarning)

def main():
    base = Tk()
    icon = PhotoImage(file='assets/logo.gif')
    base.tk.call('wm','iconphoto',base._w,icon)
    userInterface.pcapXrayGui(base)
    base.mainloop()

main()
