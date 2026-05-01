import sys
import os
import time
import logging
import threading
import webbrowser

from tkinter import *

log = logging.getLogger(__name__)
from tkinter import ttk
from tkinter import filedialog as fd
from tkinter import messagebox as mb
import queue as q

import tkinter as tk

import pcap_reader
import plot_lan_network
import communication_details_fetch
import device_details_fetch
import report_generator
import tor_traffic_handle
import sqlite_store
import memory
from PIL import Image, ImageTk

_SPIN_FRAMES  = ("⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷")
_SPIN_TRAIL   = 8            # how many frames to show as a rolling wave
_SPIN_COLOR   = "#2196f3"   # blue — active
_DONE_COLOR   = "#81c784"   # green — success
_ERR_COLOR    = "#e57373"   # red   — error
_SPIN_FONT    = ("Courier", 15, "bold")
_SPIN_WIDTH   = 38           # fixed character width — prevents layout reflow


class pcapXrayGui:
    def __init__(self, base):

        # TODO: is this req? Start getting tor consensus in the background
        #threading.Thread(target=tor_traffic_handle.TorTrafficHandle().get_consensus_data(), args=()).start()

        # Base Frame Configuration
        self.base = base
        base.title("PcapXray")
        Label(base, text="PcapXray Tool - A LAN Network Analyzer")

        # Load dock icon; re-applied after matplotlib overwrites it
        try:
            _icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "logo.gif")
            self._icon_photo = tk.PhotoImage(file=_icon_path)
            base.iconphoto(True, self._icon_photo)
        except Exception:
            self._icon_photo = None

        # Style Configuration
        style = ttk.Style()
        style.configure("BW.TLabel", foreground="black")
        style.configure("BW.TEntry", foreground="black")

        # 1st Frame - Initial Frame
        InitFrame = ttk.Frame(base,  width=50, padding="10 0 0 0",relief= GROOVE)
        InitFrame.grid(column=10, row=10, sticky=(N, W, E, S))
        InitFrame.columnconfigure(5, weight=1)
        InitFrame.rowconfigure(0, weight=1)

        # Pcap File Entry
        self.pcap_file = StringVar()
        self.filename = ""
        ttk.Label(InitFrame, text="Enter pcap file path: ",style="BW.TLabel").grid(column=0, row=0, sticky="W")
        self.filename_field = ttk.Entry(InitFrame, width=32, textvariable=self.pcap_file, style="BW.TEntry").grid(column=1, row=0, sticky="W, E")
        ttk.Button(InitFrame, text="Browse", command=lambda: self.browse_directory("pcap")).grid(column=2, row=0, padx=10, pady=10, sticky="E")
        # Engine selector sits before Analyze so the choice is visible before running
        self.engine = StringVar(value="auto")
        ttk.OptionMenu(InitFrame, self.engine, "auto", "auto", "dpkt", "scapy", "pyshark").grid(
            column=3, row=0, padx=5, sticky="W"
        )
        self.analyze_button = ttk.Button(InitFrame, text="Analyze!", command=self.pcap_analyse)
        self.analyze_button.grid(column=4, row=0, padx=10, pady=10, sticky="E")
        self._spin_label = tk.Label(InitFrame, text="", fg=_SPIN_COLOR,
                                    font=_SPIN_FONT, width=_SPIN_WIDTH, anchor="w")
        self._spin_label.grid(column=5, row=0, padx=10, pady=10, sticky="EW")
        self._spin_job: str | None = None
        self._spin_idx = 0
        self._spin_msg = ""

        # First Frame with Report Directory
        FirstFrame = ttk.Frame(base, width=50, padding="10 0 0 0", relief=GROOVE)
        FirstFrame.grid(column=10, row=20, sticky=(N, W, E, S))
        FirstFrame.columnconfigure(3, weight=1)  # spacer pushes zoom buttons to the right
        self.destination_report = StringVar(value=sys.path[0])
        ttk.Label(FirstFrame, text="Output directory path: ", style="BW.TLabel").grid(column=0, row=0, sticky="W")
        self.report_field = ttk.Entry(FirstFrame, width=30, textvariable=self.destination_report, style="BW.TEntry").grid(column=1, row=0, sticky="WE")
        ttk.Button(FirstFrame, text="Browse", command=lambda: self.browse_directory("report")).grid(column=2, row=0, padx=10, pady=10, sticky="E")
        self.zoom = [900, 500]
        ttk.Button(FirstFrame, text="zoomIn",  command=self.zoom_in).grid(row=0, column=4, padx=5, sticky="E")
        ttk.Button(FirstFrame, text="zoomOut", command=self.zoom_out).grid(row=0, column=5, padx=2, sticky="E")
        ttk.Button(FirstFrame, text="Fit",     command=self.zoom_fit).grid(row=0, column=6, padx=5, sticky="E")

        # Live Capture Frame
        LiveFrame = ttk.Frame(base, width=50, padding="10 2 0 2", relief=GROOVE)
        LiveFrame.grid(column=10, row=25, sticky=(N, W, E, S))
        ttk.Label(LiveFrame, text="Interface:", style="BW.TLabel").grid(row=0, column=0, sticky="W")
        self.live_iface = StringVar(value="")
        self.live_iface_menu = ttk.Combobox(LiveFrame, width=12, textvariable=self.live_iface, state="readonly")
        self.live_iface_menu.grid(row=0, column=1, padx=5, sticky="W")
        # Populate after window renders so it doesn't block startup
        base.after(500, self._populate_ifaces)
        self.live_button = ttk.Button(LiveFrame, text="▶ Start Live", command=self._toggle_live)
        self.live_button.grid(row=0, column=2, padx=10, sticky="W")
        self._live_status = tk.Label(LiveFrame, text="", fg="#aaaaaa", font=("Courier", 11))
        self._live_status.grid(row=0, column=3, padx=10, sticky="W")
        self._live_engine = None
        self._live_job: str | None = None

        # Second Frame with Options
        SecondFrame = ttk.Frame(base,  width=50, padding="10 10 10 10",relief= GROOVE)
        SecondFrame.grid(column=10, row=30, sticky=(N, W, E, S))
        SecondFrame.columnconfigure(6, weight=1)  # spacer pushes graph buttons to the right
        ttk.Label(SecondFrame, text="Traffic: ", style="BW.TLabel").grid(row=10, column=0, sticky="W")
        self.option = StringVar()
        self.options = {'All', 'HTTP', 'HTTPS', 'Tor', 'Malicious', 'ICMP', 'DNS'}
        ttk.OptionMenu(SecondFrame, self.option, "Select", *self.options).grid(row=10, column=1, padx=10, sticky="W")
        self.ibutton = ttk.Button(SecondFrame, text="Graph Panel", command=self.gimmick)
        self.ibutton.grid(row=10, column=7, padx=10, sticky="E")
        self.trigger = ttk.Button(SecondFrame, text="Visualize!", command=self.map_select)
        self.trigger.grid(row=10, column=8, sticky="E")
        self.browser_button = ttk.Button(SecondFrame, text="Interactive Graph", command=self.open_in_browser)
        self.browser_button.grid(row=10, column=9, padx=10, sticky="E")
        self.trigger['state'] = 'disabled'
        self.ibutton['state'] = 'disabled'
        self.browser_button['state'] = 'disabled'

        self.img = ""
        self._store = sqlite_store.SqliteStore()
        
        ## Filters
        self.from_ip = StringVar()
        self.from_hosts = ["All"]
        self.to_ip = StringVar()
        self.to_hosts = ["All"]
        ttk.Label(SecondFrame, text="From: ", style="BW.TLabel").grid(row=10, column=2, sticky="W")
        self.from_menu = ttk.Combobox(SecondFrame, width=15, textvariable=self.from_ip, values=self.from_hosts)
        self.from_menu.grid(row=10, column=3, padx=10, sticky="E")
        ttk.Label(SecondFrame, text="To: ", style="BW.TLabel").grid(row=10, column=4, sticky="W")
        self.to_menu = ttk.Combobox(SecondFrame, width=15, textvariable=self.to_ip, values=self.to_hosts)
        self.to_menu.grid(row=10, column=5, padx=10, sticky="E")

        # Default filter values
        self.from_menu.set("All")
        self.to_menu.set("All")
        self.option.set("All")

        # Third Frame with Results and Descriptions
        self.ThirdFrame = ttk.Frame(base, padding="24 10 10 10", relief=GROOVE)
        description = (
            "Description:\n"
            "PcapXray tools is an aid for Network Forensics or Any Network Analysis!\n"
            "It is a tool aimed to simplify the network analysis and speed the process of analysing the network traffic.\n"
            "This prototype aims to accomplish 5 important modules,\n\n"
            " 1. Web Traffic\n"
            " 2. Tor Traffic\n"
            " 3. Malicious Traffic\n"
            " 4. Device/Traffic Details\n"
            " 5. Covert Communication\n\n"
            "Please contact me @ spg349@nyu.edu for any bugs or problems !"
        )
        self.label = ttk.Label(self.ThirdFrame, text=description, style="BW.TLabel",
                               anchor="w", justify="left", wraplength=580)
        self.label.grid(column=0, row=0, sticky="NW", padx=4, pady=4)
        self.xscrollbar = Scrollbar(self.ThirdFrame, orient=HORIZONTAL)
        self.xscrollbar.grid(row=1, column=0, sticky=E + W)
        self.yscrollbar = Scrollbar(self.ThirdFrame, orient=VERTICAL)
        self.yscrollbar.grid(row=0, column=1, sticky=N + S)
        self.ThirdFrame.grid(column=10, row=40, sticky=(N, W, E, S))
        self.ThirdFrame.columnconfigure(0, weight=1)
        self.ThirdFrame.rowconfigure(0, weight=1)

        # Fourth Frame — Wireshark-style packet browser (hidden until analysis)
        self.FourthFrame = ttk.Frame(base, padding="8 4 8 4", relief=GROOVE)
        # Not gridded yet — shown by _populate_packet_table() after analysis

        _search_bar = ttk.Frame(self.FourthFrame)
        _search_bar.grid(row=0, column=0, columnspan=2, sticky="EW", pady=(0, 4))
        ttk.Label(_search_bar, text="Search:", style="BW.TLabel").pack(side=LEFT, padx=(0, 4))
        self._search_var = tk.StringVar()
        self._search_entry = ttk.Entry(_search_bar, textvariable=self._search_var, width=28)
        self._search_entry.pack(side=LEFT, padx=2)
        self._search_entry.bind("<Return>", lambda e: self._search_packets())
        ttk.Button(_search_bar, text="Search", command=self._search_packets).pack(side=LEFT, padx=4)
        self._search_count_label = tk.Label(_search_bar, text="", fg="#aaaaaa", font=("Courier", 10))
        self._search_count_label.pack(side=LEFT, padx=8)
        ttk.Button(_search_bar, text="◀", command=lambda: self._nav_packet(-1), width=2).pack(side=LEFT, padx=2)
        ttk.Button(_search_bar, text="▶", command=lambda: self._nav_packet(1), width=2).pack(side=LEFT, padx=2)
        ttk.Button(_search_bar, text="Clear", command=self._clear_search).pack(side=LEFT, padx=8)
        self._detail_btn = ttk.Button(_search_bar, text="inspect →",
                                      command=self._open_selected_detail, state="disabled")
        self._detail_btn.pack(side=RIGHT, padx=(8, 4))

        _cols = ("src", "dst", "port", "flags", "files", "payload")
        self._pkt_tree = ttk.Treeview(self.FourthFrame, columns=_cols, show="headings", height=6)
        for _hdr, _col, _w, _anchor, _stretch in [
            ("Src IP",          "src",     130, "w",      False),
            ("Dst IP",          "dst",     130, "w",      False),
            ("Port",            "port",     65, "center", False),
            ("Flags",           "flags",   110, "center", False),
            ("Files",           "files",   110, "center", False),
            ("Payload Preview", "payload",   0, "w",      True),
        ]:
            self._pkt_tree.heading(_col, text=_hdr)
            self._pkt_tree.column(_col, width=_w, anchor=_anchor, stretch=_stretch)

        _tv_vsb = ttk.Scrollbar(self.FourthFrame, orient=VERTICAL, command=self._pkt_tree.yview)
        self._pkt_tree.configure(yscrollcommand=_tv_vsb.set)
        self._pkt_tree.grid(row=1, column=0, sticky="NSEW")
        _tv_vsb.grid(row=1, column=1, sticky="NS")
        self.FourthFrame.columnconfigure(0, weight=1)
        self.FourthFrame.rowconfigure(1, weight=1)

        self._pkt_tree.tag_configure("malicious", background="#4a1010", foreground="#ff8a80")
        self._pkt_tree.tag_configure("tor",       background="#2d1a3e", foreground="#ce93d8")
        self._pkt_tree.tag_configure("covert",    background="#0d3040", foreground="#80deea")
        self._pkt_tree.tag_configure("match",     background="#1a3a1a", foreground="#a5d6a7")
        self._pkt_tree.bind("<<TreeviewSelect>>", self._on_packet_select)
        self._pkt_tree.bind("<Double-1>", self._open_session_detail)

        self._pkt_rows: list[str] = []
        self._search_matches: list[str] = []
        self._search_idx: int = -1

        base.resizable(False, False)
        base.rowconfigure(40, weight=1)
        base.columnconfigure(10, weight=1)

    def browse_directory(self, option):
        if option == "pcap":
            self.pcap_file.set(fd.askopenfilename(initialdir=sys.path[0], title="Select Packet Capture File!", filetypes=(("All", "*.pcap *.pcapng"), ("pcap files", "*.pcap"), ("pcapng files", "*.pcapng"))))
            self.filename = self.pcap_file.get().replace(".pcap", "").replace(".pcapng", "")
            if "/" in self.filename:
                self.filename = self.filename.split("/")[-1]
        else:
            self.destination_report.set(fd.askdirectory())
            if self.destination_report.get():
                if not os.access(self.destination_report.get(), os.W_OK):
                    mb.showerror("Error", "Permission denied to create report! Run with higher privilege.")
            else:
                mb.showerror("Error", "Enter a output directory!")
        # Restore focus to main window after any native dialog (macOS loses focus otherwise)
        self._force_focus()
    
    """
    def update_ips(self, direction):
        if direction == "to":
            self.to_hosts += list(memory.destination_hosts.keys())
            self.to_menu['values'] = self.to_hosts
        else:
            for mac in memory.lan_hosts:
                self.to_hosts += memory.lan_hosts[mac].ip
                self.from_hosts += memory.lan_hosts[mac].ip
            self.from_menu['values'] = self.from_hosts
    """

    # ------------------------------------------------------------------
    # Live capture helpers
    # ------------------------------------------------------------------

    def _populate_ifaces(self) -> None:
        """Fill the interface dropdown from scapy (called once at startup)."""
        try:
            from scapy.interfaces import get_if_list
            ifaces = get_if_list()
        except Exception:
            ifaces = []
        if ifaces:
            self.live_iface_menu["values"] = ifaces
            self.live_iface.set(ifaces[0])

    def _toggle_live(self) -> None:
        if self._live_engine and self._live_engine.is_running():
            self._stop_live()
        else:
            self._start_live()

    def _start_live(self) -> None:
        iface = self.live_iface.get().strip()
        if not iface:
            mb.showerror("Live Capture", "Select a network interface first.")
            return

        # Cancel any orphaned refresh job from a previous run
        if self._live_job is not None:
            self.base.after_cancel(self._live_job)
            self._live_job = None

        import pcap_reader
        try:
            self._live_engine = pcap_reader.LivePcapEngine(iface)
            self._live_engine.start()
        except PermissionError:
            mb.showerror("Permission denied",
                         "Live capture requires elevated privileges.\n"
                         "Run PcapXray with sudo (macOS/Linux) or as Administrator (Windows).")
            self._live_engine = None
            return
        except Exception as exc:
            mb.showerror("Live Capture Error", str(exc))
            self._live_engine = None
            return

        # Use interface name as filename so Visualize! produces a sensible path
        self.filename = f"live_{iface}"

        self.live_button.config(text="⏹ Stop")
        self._live_status.config(text="📡 Live — graph updates every 4s", fg="#2196f3")
        self._disable_file_controls()
        # Always open a fresh live panel (never toggles on repeat runs)
        import interactive_gui
        interactive_gui.open_live_panel(self.base)
        if self._icon_photo is not None:
            self.base.after(300, lambda: self.base.iconphoto(True, self._icon_photo))
        self._live_job = self.base.after(4000, self._live_refresh)

    def _stop_live(self) -> None:
        if self._live_job is not None:
            self.base.after_cancel(self._live_job)
            self._live_job = None
        engine = self._live_engine
        # Clear before _poll_thread so any _live_refresh firing during base.update()
        # sees None and returns without rescheduling.
        self._live_engine = None
        if engine:
            iface = engine._iface
            self._spin_start("Running covert check")
            t, _ = self._run_in_thread(engine.stop)
            try:
                self._poll_thread(t)
            finally:
                self._spin_stop(f"✓ {len(memory.packet_db)} sessions captured")
            import time
            self._store.save_session(f"live_{iface}_{int(time.time())}")

        self.live_button.config(text="▶ Start Live")
        self._live_status.config(text="📡 Captured — click Visualize! for snapshot", fg="#81c784")
        import interactive_gui
        interactive_gui.refresh_live()
        interactive_gui.set_panel_title("Network Graph (stopped)  |  Click Visualize! to generate static snapshot")
        self._enable_file_controls()
        self._populate_filter_menus()
        self.trigger['state'] = 'normal'
        self.base.after(100, self._force_focus)

    def _live_refresh(self) -> None:
        if self._live_engine is None or not self._live_engine.is_running():
            return
        pkts = self._live_engine.packet_count
        sessions = len(memory.packet_db)
        self._live_status.config(text=f"📡 {pkts} pkts  {sessions} sessions")
        import interactive_gui
        interactive_gui.refresh_live()
        self._live_job = self.base.after(4000, self._live_refresh)

    def _disable_file_controls(self) -> None:
        self.analyze_button['state'] = 'disabled'
        self.trigger['state'] = 'disabled'
        self.ibutton['state'] = 'disabled'
        self.browser_button['state'] = 'disabled'
        self.to_menu['state'] = 'disabled'
        self.from_menu['state'] = 'disabled'

    def _enable_file_controls(self) -> None:
        self.analyze_button['state'] = 'normal'
        self.to_menu['state'] = 'normal'
        self.from_menu['state'] = 'normal'

    # ------------------------------------------------------------------
    # Spinner helpers
    # ------------------------------------------------------------------

    def _force_focus(self) -> None:
        """Bring the window to the front with real mouse focus on macOS.

        focus_force() alone only sets Tk's internal focus; macOS still requires
        a click to activate the window for mouse events.  Briefly setting
        -topmost forces the OS to grant full activation, then we remove it.
        """
        self.base.attributes('-topmost', True)
        self.base.lift()
        self.base.focus_force()
        self.base.after(200, lambda: self.base.attributes('-topmost', False))

    def _spin_start(self, text: str = "Working") -> None:
        if self._spin_job is not None:
            self.base.after_cancel(self._spin_job)
            self._spin_job = None
        self._spin_msg = text
        self._spin_idx = 0
        if self._spin_label.winfo_exists():
            self._spin_label.config(fg=_SPIN_COLOR)
            self._spin_tick()

    def _spin_tick(self) -> None:
        if not self._spin_label.winfo_exists():
            self._spin_job = None
            return
        n = len(_SPIN_FRAMES)
        trail = "".join(
            _SPIN_FRAMES[(self._spin_idx - _SPIN_TRAIL + i) % n]
            for i in range(_SPIN_TRAIL)
        )
        self._spin_label.config(text=f"{trail}  {self._spin_msg}")
        self._spin_idx += 1
        self._spin_job = self.base.after(80, self._spin_tick)

    def _spin_stop(self, done_text: str = "", ok: bool = True) -> None:
        if self._spin_job is not None:
            self.base.after_cancel(self._spin_job)
            self._spin_job = None
        if self._spin_label.winfo_exists():
            self._spin_label.config(fg=_DONE_COLOR if ok else _ERR_COLOR,
                                    text=done_text)

    def _run_in_thread(self, fn, *args) -> tuple[threading.Thread, list]:
        """Run fn(*args) in a daemon thread; store any exception in exc_box[0]."""
        exc_box: list = []
        def wrapper():
            try:
                fn(*args)
            except Exception as e:
                exc_box.append(e)
        t = threading.Thread(target=wrapper, daemon=True)
        t.start()
        return t, exc_box

    def _poll_thread(self, thread: threading.Thread) -> None:
        """Block the caller while driving the Tk event loop until thread finishes."""
        while thread.is_alive():
            try:
                self.base.update()
            except Exception as exc:
                log.debug("_poll_thread: update error (ignored): %s", exc)
            thread.join(timeout=0.05)

    def pcap_analyse(self):
        if not os.access(self.destination_report.get(), os.W_OK):
            mb.showerror("Error", "Permission denied to create report! Run with higher privilege.")
            return

        log.info("pcap_analyse: file=%s", self.pcap_file.get())
        if not os.path.exists(self.pcap_file.get()):
            mb.showerror("Error", "File Not Found!")
            return

        self.trigger['state'] = 'disabled'
        self.ibutton['state'] = 'disabled'
        self.browser_button['state'] = 'disabled'
        self.to_menu['state'] = 'disabled'
        self.from_menu['state'] = 'disabled'
        self.analyze_button['state'] = 'disabled'

        # Derive filename if user typed the path directly instead of using Browse
        if not self.filename:
            self.filename = os.path.basename(self.pcap_file.get()).replace(".pcap", "").replace(".pcapng", "")

        # Offer to reload from SQLite cache if this PCAP was analyzed before
        if self.filename and self._store.has_session(self.filename):
            if mb.askyesno("Reload Session",
                           f"Cached analysis found for '{self.filename}'.\n"
                           "Reload without re-parsing the PCAP?"):
                log.info("pcap_analyse: reloading session '%s' from cache", self.filename)
                self._spin_start("Loading cache")
                self._store.load_session(self.filename)
                self._spin_stop(f"✓ {len(memory.packet_db)} sessions (cached)")
                self._populate_filter_menus()
                self._re_enable_controls()
                return

        self._spin_start("Reading packets")
        packet_read, exc_box = self._run_in_thread(pcap_reader.PcapEngine, self.pcap_file.get(), self.engine.get())
        self._poll_thread(packet_read)

        if exc_box:
            self._spin_stop("✗ Analysis failed", ok=False)
            log.error("PCAP analysis failed: %s", exc_box[0])
            mb.showerror("Analysis Error", f"PCAP analysis failed:\n{exc_box[0]}")
            self._re_enable_controls()
            return

        self._spin_stop(f"✓ {len(memory.packet_db)} sessions")

        log.info("pcap_analyse: read complete, generating packet report")
        threading.Thread(target=report_generator.ReportGenerator(self.destination_report.get(), self.filename).packetDetails, args=(), daemon=True).start()

        if self.filename:
            self._store.save_session(self.filename)
        self._populate_filter_menus()
        self._re_enable_controls()

    def _populate_filter_menus(self) -> None:
        self.details_fetch = 0
        self.to_hosts = ["All"]
        self.from_hosts = ["All"]
        self.from_menu.set("All")
        self.to_menu.set("All")
        self.option.set("All")
        self.to_hosts += list(memory.destination_hosts.keys())
        for mac in list(memory.lan_hosts.keys()):
            self.base.update()
            self.from_hosts.append(memory.lan_hosts[mac].ip)
        self.to_hosts = list(set(self.to_hosts + self.from_hosts))
        self.to_menu['values'] = self.to_hosts
        self.from_menu['values'] = self.from_hosts
        self._populate_packet_table()

    def _re_enable_controls(self) -> None:
        # Graph Panel and Interactive Graph stay disabled until Visualize! succeeds
        self.trigger['state'] = 'normal'
        self.to_menu['state'] = 'normal'
        self.from_menu['state'] = 'normal'
        self.analyze_button['state'] = 'normal'
        self.base.after(100, self._force_focus)

    def generate_graph(self):
        log.info("generate_graph: option=%s to=%s from=%s", self.option.get(), self.to_ip.get(), self.from_ip.get())
        if self.details_fetch == 0:
            t, _ = self._run_in_thread(communication_details_fetch.TrafficDetailsFetch, "sock")
            t1, _ = self._run_in_thread(device_details_fetch.FetchDeviceDetails("ieee").fetch_info)
            self._spin_start("Resolving hosts")
            self._poll_thread(t)
            self._poll_thread(t1)
            self._spin_stop("✓ Hosts resolved")

            self.details_fetch = 1
            rpt = report_generator.ReportGenerator(self.destination_report.get(), self.filename)
            threading.Thread(target=rpt.communicationDetailsReport, daemon=True).start()
            threading.Thread(target=rpt.deviceDetailsReport, daemon=True).start()

        options = (self.option.get() + "_" + self.to_ip.get().replace(".", "-")
                   + "_" + self.from_ip.get().replace(".", "-"))
        self.image_file = os.path.join(self.destination_report.get(), "Report", self.filename + "_" + options + ".png")
        if not os.path.exists(self.image_file):
            t1, exc_box = self._run_in_thread(
                plot_lan_network.PlotLan,
                self.filename, self.destination_report.get(),
                self.option.get(), self.to_ip.get(), self.from_ip.get()
            )
            self._spin_start("Rendering graph")
            self._poll_thread(t1)
            if exc_box:
                self._spin_stop("✗ Render failed", ok=False)
                log.error("Graph generation failed: %s", exc_box[0])
                mb.showerror("Graph Error", f"Graph generation failed:\n{exc_box[0]}")
                return
            self._spin_stop("✓ Graph ready")
            self.label.grid_forget()
            self.load_image()
        else:
            self.label.grid_forget()
            self.load_image()
        self._populate_packet_table()
        # Both graph buttons become available once a graph exists
        self.ibutton['state'] = 'normal'
        self.browser_button['state'] = 'normal'

    def gimmick(self):
        import interactive_gui
        interactive_gui.gimmick_initialize(self.base, "file://" + self.image_file.replace(".png", ".html"))
        if self._icon_photo is not None:
            self.base.after(300, lambda: self.base.iconphoto(True, self._icon_photo))

    def open_in_browser(self):
        html_path = self.image_file.replace(".png", ".html")
        if os.path.exists(html_path):
            webbrowser.open("file://" + html_path)
        else:
            mb.showerror("Error", "Interactive HTML not found. Click Visualize! first.")

    def load_image(self):
        if not hasattr(self, '_zoom_factor'):
            self._zoom_factor = 1.0
            self.base.resizable(True, True)
            self.base.geometry("1100x780")

        # Destroy previous canvas so its <Configure> binding stops firing
        if hasattr(self, 'canvas') and self.canvas and self.canvas.winfo_exists():
            self.canvas.destroy()

        self._src_img = None          # cached PIL source; cleared when image_file changes
        self._src_img_path = None
        self._resize_job = None       # pending debounce after-id

        self.canvas = Canvas(self.ThirdFrame, bd=0, bg="grey",
                             xscrollcommand=self.xscrollbar.set,
                             yscrollcommand=self.yscrollbar.set)
        self.canvas.grid(column=0, row=0, sticky=(N, W, E, S))
        self.xscrollbar.config(command=self.canvas.xview)
        self.yscrollbar.config(command=self.canvas.yview)
        self.canvas.bind("<Configure>", self._on_canvas_resize)

    def _on_canvas_resize(self, event):
        """Debounce rapid <Configure> events — only redraw after 120ms of quiet."""
        if hasattr(self, '_resize_job') and self._resize_job:
            self.base.after_cancel(self._resize_job)
        self._resize_job = self.base.after(120, lambda: self._redraw_image(event.width, event.height))

    def _zoom_fill_factor(self, src_w: int, src_h: int) -> float:
        """Return the _zoom_factor that fills the canvas viewport (cover behaviour)."""
        w = self.canvas.winfo_width() or 1
        h = self.canvas.winfo_height() or 1
        fit   = min(w / src_w, h / src_h)
        cover = max(w / src_w, h / src_h)
        return cover / fit   # always ≥ 1.0

    def zoom_fit(self):
        """Reset zoom to the fill-viewport level (the default on first load)."""
        if not (hasattr(self, '_src_img') and self._src_img):
            return
        if hasattr(self, '_resize_job') and self._resize_job:
            self.base.after_cancel(self._resize_job)
            self._resize_job = None
        src_w, src_h = self._src_img.size
        self._zoom_factor = self._zoom_fill_factor(src_w, src_h)
        self._redraw_image()

    def _redraw_image(self, w=None, h=None):
        if not hasattr(self, 'image_file') or not self.image_file:
            return
        if w is None or h is None:
            w = self.canvas.winfo_width()
            h = self.canvas.winfo_height()
        if w <= 1 or h <= 1:
            return
        new_image = self._src_img is None or self._src_img_path != self.image_file
        if new_image:
            self._src_img = Image.open(self.image_file)
            self._src_img_path = self.image_file
        src_w, src_h = self._src_img.size
        if new_image:
            # Auto-zoom: fill the viewport so the graph occupies the full canvas.
            # For a tall dot layout (nodes stacked), fills the canvas width with
            # vertical scrollbars. For a wide layout, fills the canvas height.
            self._zoom_factor = self._zoom_fill_factor(src_w, src_h)
        scale = min(w / src_w, h / src_h) * self._zoom_factor
        fit_w = max(1, int(src_w * scale))
        fit_h = max(1, int(src_h * scale))
        self.img = ImageTk.PhotoImage(self._src_img.resize((fit_w, fit_h), Image.LANCZOS))
        self.canvas.delete("all")
        x = max(0, (w - fit_w) // 2)
        y = max(0, (h - fit_h) // 2)
        self.canvas.create_image(x, y, image=self.img, anchor=NW)
        self.canvas.config(scrollregion=(0, 0, max(w, fit_w), max(h, fit_h)))

    # ------------------------------------------------------------------
    # Packet browser helpers
    # ------------------------------------------------------------------

    def _populate_packet_table(self) -> None:
        self._pkt_tree.delete(*self._pkt_tree.get_children())
        self._pkt_rows = []
        self._search_matches = []
        self._search_idx = -1
        self._search_count_label.config(text="")

        for key, session in memory.packet_db.items():
            parts = key.split("/")
            if len(parts) != 3:
                continue
            src, dst, port = parts
            is_mal = key in memory.possible_mal_traffic
            is_tor = key in memory.possible_tor_traffic
            is_cov = session.covert
            flag_parts = []
            if is_mal: flag_parts.append("Malicious")
            if is_tor: flag_parts.append("Tor")
            if is_cov: flag_parts.append("Covert")
            flags = ", ".join(flag_parts) if flag_parts else "—"
            files = ", ".join(session.file_signatures) if session.file_signatures else "—"
            fwd = session.Payload.get("forward", [])
            preview = str(fwd[0])[:80] if fwd else "—"
            tag = "malicious" if is_mal else "tor" if is_tor else "covert" if is_cov else ""
            self._pkt_tree.insert("", END, iid=key,
                                  values=(src, dst, port, flags, files, preview),
                                  tags=(tag,) if tag else ())
            self._pkt_rows.append(key)

        if not self.FourthFrame.winfo_ismapped():
            self.FourthFrame.grid(column=10, row=50, sticky=(N, W, E, S))
            self.base.rowconfigure(50, weight=0)

    def _search_packets(self) -> None:
        import re as _re
        query = self._search_var.get().strip()
        if not query:
            self._clear_search()
            return

        use_regex = query.startswith("re:")
        pattern = query[3:] if use_regex else query.lower()

        for key in self._search_matches:
            self._restore_row_tag(key)
        self._search_matches = []

        for key in self._pkt_rows:
            if not self._pkt_tree.exists(key):
                continue
            session = memory.packet_db.get(key)
            if not session:
                continue
            fwd = session.Payload.get("forward", [])
            rev = session.Payload.get("reverse", [])
            haystack = (key + " " + " ".join(fwd + rev)).lower()
            try:
                matched = bool(_re.search(pattern, haystack)) if use_regex else pattern in haystack
            except _re.error:
                matched = pattern in haystack
            if matched:
                self._search_matches.append(key)

        for key in self._search_matches:
            if self._pkt_tree.exists(key):
                self._pkt_tree.item(key, tags=("match",))

        count = len(self._search_matches)
        self._search_count_label.config(text=f"{count} match{'es' if count != 1 else ''}")
        if self._search_matches:
            self._search_idx = 0
            self._scroll_to_match(0)
        else:
            self._search_idx = -1

    def _nav_packet(self, direction: int) -> None:
        if not self._search_matches:
            return
        self._search_idx = (self._search_idx + direction) % len(self._search_matches)
        self._scroll_to_match(self._search_idx)

    def _scroll_to_match(self, idx: int) -> None:
        key = self._search_matches[idx]
        if self._pkt_tree.exists(key):
            self._pkt_tree.selection_set(key)
            self._pkt_tree.see(key)
        count = len(self._search_matches)
        self._search_count_label.config(
            text=f"{idx + 1}/{count} match{'es' if count != 1 else ''}")

    def _clear_search(self) -> None:
        self._search_var.set("")
        for key in self._search_matches:
            self._restore_row_tag(key)
        self._search_matches = []
        self._search_idx = -1
        self._search_count_label.config(text="")

    def _restore_row_tag(self, key: str) -> None:
        if not self._pkt_tree.exists(key):
            return
        session = memory.packet_db.get(key)
        if not session:
            return
        is_mal = key in memory.possible_mal_traffic
        is_tor = key in memory.possible_tor_traffic
        tag = "malicious" if is_mal else "tor" if is_tor else "covert" if session.covert else ""
        self._pkt_tree.item(key, tags=(tag,) if tag else ())

    def _on_packet_select(self, event) -> None:
        sel = self._pkt_tree.selection()
        if not sel:
            self._detail_btn.configure(state="disabled")
            return
        self._detail_btn.configure(state="normal")
        parts = sel[0].split("/")
        if len(parts) != 3:
            return
        src, dst, _ = parts
        if src in self.from_menu["values"]:
            self.from_menu.set(src)
        if dst in self.to_menu["values"]:
            self.to_menu.set(dst)

    def _open_selected_detail(self) -> None:
        sel = self._pkt_tree.selection()
        if sel:
            self._open_session_detail(None)

    def _open_session_detail(self, event) -> None:
        sel = self._pkt_tree.selection()
        if not sel:
            return
        key = sel[0]
        session = memory.packet_db.get(key)
        if not session:
            return

        parts = key.split("/")
        src, dst, port = parts if len(parts) == 3 else ("?", "?", "?")

        win = Toplevel(self.base)
        win.title(f"Session: {key}")
        win.geometry("700x520")
        win.resizable(True, True)
        win.columnconfigure(0, weight=1)
        win.rowconfigure(1, weight=1)

        # ── Header ──────────────────────────────────────────────────────
        hdr = ttk.Frame(win, padding="12 10 12 6")
        hdr.grid(row=0, column=0, sticky="EW")
        hdr.columnconfigure(1, weight=1)

        def _row(r, label, value):
            ttk.Label(hdr, text=label, style="BW.TLabel",
                      font=("Courier", 10, "bold")).grid(row=r, column=0, sticky="W", padx=(0, 8))
            ttk.Label(hdr, text=value, style="BW.TLabel",
                      font=("Courier", 10)).grid(row=r, column=1, sticky="W")

        is_mal = key in memory.possible_mal_traffic
        is_tor = key in memory.possible_tor_traffic
        flag_parts = (["Malicious"] if is_mal else []) + (["Tor"] if is_tor else []) + (["Covert"] if session.covert else [])
        dst_host = memory.destination_hosts.get(dst)
        domain = dst_host.domain_name if dst_host and dst_host.domain_name else "—"

        _row(0, "Session:", key)
        _row(1, "Flags:",   ", ".join(flag_parts) if flag_parts else "None")
        _row(2, "Files:",   ", ".join(session.file_signatures) if session.file_signatures else "None")
        _row(3, "Ethernet:", f"{session.Ethernet.get('src', '—')} → {session.Ethernet.get('dst', '—')}")
        _row(4, "Domain:",  domain)

        # ── Payload tabs ────────────────────────────────────────────────
        nb = ttk.Notebook(win)
        nb.grid(row=1, column=0, sticky="NSEW", padx=10, pady=4)

        for label, lines in [("Forward", session.Payload.get("forward", [])),
                              ("Reverse", session.Payload.get("reverse", []))]:
            tab = ttk.Frame(nb)
            nb.add(tab, text=f"{label} ({len(lines)} entries)")
            tab.rowconfigure(0, weight=1)
            tab.columnconfigure(0, weight=1)
            txt = tk.Text(tab, wrap="word", font=("Courier", 10),
                          bg="#1e1e2e", fg="#e0e0e0", relief="flat")
            vsb = ttk.Scrollbar(tab, orient=VERTICAL, command=txt.yview)
            txt.configure(yscrollcommand=vsb.set)
            txt.grid(row=0, column=0, sticky="NSEW")
            vsb.grid(row=0, column=1, sticky="NS")
            txt.insert("1.0", "\n".join(lines) if lines else "(no payload)")
            txt.configure(state="disabled")

        ttk.Button(win, text="Close", command=win.destroy).grid(row=2, column=0, pady=8)
        win.after(100, lambda: (win.lift(), win.focus_force()))

    def map_select(self, *args):
        log.debug("map_select: option=%s to=%s from=%s", self.option.get(), self.to_ip.get(), self.from_ip.get())
        self.trigger['state'] = 'disabled'
        self.analyze_button['state'] = 'disabled'
        self.ibutton['state'] = 'disabled'
        self.browser_button['state'] = 'disabled'
        self.generate_graph()
        # ibutton and browser_button enabled inside generate_graph on success only
        self.trigger['state'] = 'normal'
        self.analyze_button['state'] = 'normal'
        self.base.after(100, self._force_focus)

    def zoom_in(self):
        if self.img:
            if hasattr(self, '_resize_job') and self._resize_job:
                self.base.after_cancel(self._resize_job)
                self._resize_job = None
            self._zoom_factor = min(self._zoom_factor * 1.25, 8.0)
            self._redraw_image()

    def zoom_out(self):
        if self.img:
            if hasattr(self, '_resize_job') and self._resize_job:
                self.base.after_cancel(self._resize_job)
                self._resize_job = None
            self._zoom_factor = max(self._zoom_factor / 1.25, 0.1)
            self._redraw_image()

class OtherFrame(Toplevel):

    def __init__(self, x, y):
        """Constructor"""
        Toplevel.__init__(self)
        self.geometry("+%d+%d" % (x + 100, y + 200))
        self.title("otherFrame")

def main():
    base = Tk()
    pcapXrayGui(base)
    def _reopen():
        # On macOS/Tk Cocoa, wm_state('normal') + deiconify() is a no-op for iconic
        # windows because deiconify() sees state already 'normal'. The only reliable
        # path is withdraw() → deiconify() which forces NSWindow orderOut + makeKeyAndOrderFront.
        if base.wm_state() == 'iconic':
            base.withdraw()
        base.deiconify()
        base.attributes('-topmost', True)
        base.lift()
        base.focus_force()
        base.after(200, lambda: base.attributes('-topmost', False))

    def _on_map(event):
        # macOS native deminiaturize bypasses ReopenApplication — catch it here.
        if event.widget is base:
            base.lift()
            base.focus_force()

    # macOS: grab focus after the window fully renders
    base.after(200, _reopen)
    # macOS: restore window when dock icon is clicked while app is running
    base.createcommand('::tk::mac::ReopenApplication', _reopen)
    import platform
    if platform.system() == 'Darwin':
        base.bind('<Map>', _on_map)
    base.mainloop()

