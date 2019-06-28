# Reference https://github.com/cztomczak/cefpython/blob/master/examples/tkinter_.py
import sys
if sys.platform == 'darwin':
    import matplotlib
    matplotlib.use('TkAgg')

"""
from cefpython3 import cefpython as cef
import ctypes
import os
import platform
import logging as _logging
"""
import memory

#import vispy

"""
class InteractiveMap:

    def __init__(self):
        # Platforms
        # Fix for PyCharm hints warnings
        WindowUtils = cef.WindowUtils()

        # Platforms
        WINDOWS = (platform.system() == "Windows")
        LINUX = (platform.system() == "Linux")
        MAC = (platform.system() == "Darwin")

        # Globals
        logger = _logging.getLogger("tkinter_.py")

        # Constants
        # Tk 8.5 doesn't support png images
        IMAGE_EXT = ".png" if tk.TkVersion > 8.5 else ".gif"
        logger.setLevel(_logging.INFO)
        stream_handler = _logging.StreamHandler()
        formatter = _logging.Formatter("[%(filename)s] %(message)s")
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)
        logger.info("CEF Python {ver}".format(ver=cef.__version__))
        logger.info("Python {ver} {arch}".format(
        ver=platform.python_version(), arch=platform.architecture()[0]))
        logger.info("Tk {ver}".format(ver=tk.Tcl().eval('info patchlevel')))
        assert cef.__version__ >= "55.3", "CEF Python v55.3+ required to run this"
        sys.excepthook = cef.ExceptHook  # To shutdown all CEF processes on error

        cef.Initialize()

    def create_map(self, network_x_map):

    def convert_map(self):
        # Loops again with strems in memory.packet_db
        return ""
    
    def teardown(self):
        cef.Shutdown()


def main():
"""

# Example of embedding CEF Python browser using Tkinter toolkit.
# This example has two widgets: a navigation bar and a browser.
#
# NOTE: This example often crashes on Mac (Python 2.7, Tk 8.5/8.6)
#       during initial app loading with such message:
#       "Segmentation fault: 11". Reported as Issue #309.
#
# Tested configurations:
# - Tk 8.5 on Windows/Mac
# - Tk 8.6 on Linux
# - CEF Python v55.3+
#
# Known issue on Linux: When typing url, mouse must be over url
# entry widget otherwise keyboard focus is lost (Issue #255
# and Issue #284).

from cefpython3 import cefpython as cef
import ctypes
try:
    import tkinter as tk
    from tkinter import *
    from tkinter import ttk
except ImportError:
    import Tkinter as tk
    from Tkinter import *
    from Tkinter import ttk
import sys
import os
import platform
import logging as _logging

# Fix for PyCharm hints warnings
#WindowUtils = cef.WindowUtils()

# Platforms
WINDOWS = (platform.system() == "Windows")
LINUX = (platform.system() == "Linux")
MAC = (platform.system() == "Darwin")

# Globals
logger = _logging.getLogger("tkinter_.py")

# Constants
# Tk 8.5 doesn't support png images
IMAGE_EXT = ".png" if tk.TkVersion > 8.5 else ".gif"

interactive_map = ""
browser_frame = ""
FourthFrame = ""
def gimmick_initialize(window, map):
        global browser_frame, FourthFrame
        if not browser_frame and not FourthFrame:
            global interactive_map
            interactive_map = map
            logger.setLevel(_logging.INFO)
            stream_handler = _logging.StreamHandler()
            formatter = _logging.Formatter("[%(filename)s] %(message)s")
            stream_handler.setFormatter(formatter)
            logger.addHandler(stream_handler)
            logger.info("CEF Python {ver}".format(ver=cef.__version__))
            logger.info("Python {ver} {arch}".format(
                    ver=platform.python_version(), arch=platform.architecture()[0]))
            logger.info("Tk {ver}".format(ver=tk.Tcl().eval('info patchlevel')))
            assert cef.__version__ >= "55.3", "CEF Python v55.3+ required to run this"
            sys.excepthook = cef.ExceptHook  # To shutdown all CEF processes on error

            #cef.Initialize()
            #FourthFrame = ttk.Frame(window,  width=700, height=600, padding="10 10 10 10",relief= GROOVE)
            FourthFrame = ttk.Frame(window,  width=500, height=500, padding="10 10 10 10",relief= GROOVE)
            #tk.Grid.rowconfigure(1, weight=1)
            #tk.Grid.columnconfigure(0, weight=1)
            FourthFrame.grid(column=50, row=10, sticky=(N, W, E, S), columnspan=200, rowspan=200, padx=5, pady=5)

            # Pack MainFrame
            #FourthFrame.pack(fill=tk.BOTH, expand=tk.YES)
            #browser_frame.mainloop()
            browser_frame = BrowserFrame(FourthFrame)
            #browser_frame.pack(fill=tk.BOTH, expand=tk.YES)
            browser_frame.grid(row=0, column=0,sticky=(N, W, E, S),columnspan=100, rowspan=100, padx=5, pady=5)

            FourthFrame.columnconfigure(50, weight=1)
            FourthFrame.rowconfigure(10, weight=1)
            browser_frame.columnconfigure(0, weight=1)
            browser_frame.rowconfigure(0, weight=1)

            window.update()
        else:
            #(tk.N + tk.S + tk.E + tk.W)
            #cef.Shutdown()
            #browser_frame.grid_forget()
            FourthFrame.grid_forget()
            FourthFrame, browser_frame = "", ""
            window.update()

def show_frame(self, cont):
    frame = self.frames[cont]
    frame.tkraise()

class BrowserFrame(tk.Frame):

    def __init__(self, master):
        self.closing = False
        self.browser = None
        #tk.Frame.__init__(self, master, width=600, height=400)
        ttk.Frame.__init__(self, master, width=500, height=400, padding="10 10 10 10", relief=GROOVE)
        self.bind("<FocusIn>", self.on_focus_in)
        self.bind("<FocusOut>", self.on_focus_out)
        self.bind("<Configure>", self.on_configure)
        self.focus_set()

    def embed_browser(self):
        window_info = cef.WindowInfo()
        rect = [0, 0, self.winfo_width(), self.winfo_height()]
        window_info.SetAsChild(self.get_window_handle(), rect)
        self.browser = cef.CreateBrowserSync(window_info, url=interactive_map)
        assert self.browser
        self.browser.SetClientHandler(LoadHandler(self))
        self.browser.SetClientHandler(FocusHandler(self))
        self.message_loop_work()

    def get_window_handle(self):
        if self.winfo_id() > 0:
            return self.winfo_id()
        elif MAC:
            # On Mac window id is an invalid negative value (Issue #308).
            # This is kind of a dirty hack to get window handle using
            # PyObjC package. If you change structure of windows then you
            # need to do modifications here as well.
            # noinspection PyUnresolvedReferences
            from AppKit import NSApp
            # noinspection PyUnresolvedReferences
            import objc
            # Sometimes there is more than one window, when application
            # didn't close cleanly last time Python displays an NSAlert
            # window asking whether to Reopen that window.
            # noinspection PyUnresolvedReferences
            return objc.pyobjc_id(NSApp.windows()[-1].contentView())
        else:
            raise Exception("Couldn't obtain window handle")

    def message_loop_work(self):
        cef.MessageLoopWork()
        self.after(10, self.message_loop_work)

    def on_configure(self, _):
        if not self.browser:
            self.embed_browser()

    def on_root_configure(self):
        # Root <Configure> event will be called when top window is moved
        if self.browser:
            self.browser.NotifyMoveOrResizeStarted()

    def on_mainframe_configure(self, width, height):
        if self.browser:
            if WINDOWS:
                ctypes.windll.user32.SetWindowPos(
                    self.browser.GetWindowHandle(), 0,
                    0, 0, width, height, 0x0002)
            elif LINUX:
                self.browser.SetBounds(0, 0, width, height)
            self.browser.NotifyMoveOrResizeStarted()

    def on_focus_in(self, _):
        logger.debug("BrowserFrame.on_focus_in")
        if self.browser:
            self.browser.SetFocus(True)

    def on_focus_out(self, _):
        logger.debug("BrowserFrame.on_focus_out")
        if self.browser:
            self.browser.SetFocus(False)

    def on_root_close(self):
        if self.browser:
            self.browser.CloseBrowser(True)
            self.clear_browser_references()
        self.destroy()

    def clear_browser_references(self):
        # Clear browser references that you keep anywhere in your
        # code. All references must be cleared for CEF to shutdown cleanly.
        self.browser = None


class LoadHandler(object):

    def __init__(self, browser_frame):
        self.browser_frame = browser_frame

class FocusHandler(object):

    def __init__(self, browser_frame):
        self.browser_frame = browser_frame

    def OnTakeFocus(self, next_component, **_):
        logger.debug("FocusHandler.OnTakeFocus, next={next}"
                     .format(next=next_component))

    def OnSetFocus(self, source, **_):
        logger.debug("FocusHandler.OnSetFocus, source={source}"
                     .format(source=source))
        return False

    def OnGotFocus(self, **_):
        """Fix CEF focus issues (#255). Call browser frame's focus_set
           to get rid of type cursor in url entry widget."""
        logger.debug("FocusHandler.OnGotFocus")
        self.browser_frame.focus_set()



