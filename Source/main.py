# Main File - Driver for the Application PcapXray

# Import Libraries
import os   #-- default lib - packed with python
import sys  #-- default lib
import datetime  #-- default lib
from Tkinter import *
import ttk

# Import Custom Modules - Self created by the author
sys.path.insert(0, 'Module/')
import userInterface

# Import 3rd party Libraries -- Needed to be installed using pip
import warnings
warnings.filterwarnings("ignore", category=UserWarning)

def main():
    base = Tk()
    userInterface.pcapXrayGui(base)
    base.mainloop()

main()