"""
Interactive network graph — right-side panel spanning the full window height.

Layout:
  col 10, rows 10-40  — existing controls + static graph (unchanged)
  col 11, rows 10-40  — this panel (rowspan covers all left-column rows)

The window extends rightward; the left column is untouched.
"""
import logging
import tkinter as tk
from tkinter import ttk

import memory

__all__ = ["gimmick_initialize", "open_live_panel", "refresh_live", "set_panel_title"]

log = logging.getLogger(__name__)

_FILTER_OPTIONS = ["All", "Malicious", "Tor", "Covert", "HTTP", "HTTPS", "DNS", "ICMP"]

_container: tk.Frame | None = None
_figure = None
_ax = None
_canvas_widget = None
_info_var: tk.StringVar | None = None
_filter_var: tk.StringVar | None = None
_node_filter_var: tk.StringVar | None = None
_live_mode: bool = False
_base: tk.Tk | None = None


def _build_graph_data(live: bool = False, filter_option: str = "All", node_filter: str = ""):
    """Build networkx graph + layout from current memory state.

    Returns (G, pos, node_colors, edge_colors) or (None, ...) if nothing to show.
    live=True uses spring_layout (~100ms); live=False tries graphviz first.
    For each (src, dst) pair only the highest-severity edge is kept so malicious/
    Tor edges are never overdrawn by lower-priority normal edges.
    node_filter: if non-empty, keep only edges where src or dst label/IP contains it.
    """
    try:
        import networkx as nx
    except ImportError:
        return None, None, None, None

    # Collect highest-priority edge per (src_label, dst_label) pair.
    # priority: malicious=4 > tor=3 > covert=2 > normal=1
    edge_best: dict[tuple, tuple] = {}

    for session_key, session in list(memory.packet_db.items()):
        parts = session_key.split("/")
        if len(parts) != 3:
            continue
        src_ip, dst_ip, port = parts

        # Apply traffic filter
        if filter_option == "Malicious" and session_key not in memory.possible_mal_traffic:
            continue
        if filter_option == "Tor" and session_key not in memory.possible_tor_traffic:
            continue
        if filter_option == "Covert" and not session.covert:
            continue
        if filter_option == "HTTP" and port != "80":
            continue
        if filter_option == "HTTPS" and port != "443":
            continue
        if filter_option == "DNS" and port != "53":
            continue
        if filter_option == "ICMP" and port != "ICMP":
            continue

        eth_src = session.Ethernet.get("src", "")
        eth_dst = session.Ethernet.get("dst", "")

        if eth_src and eth_src in memory.lan_hosts:
            src_label, src_kind = _mac_label(eth_src), "lan"
        else:
            src_label, src_kind = src_ip, "ext"

        if dst_ip in memory.destination_hosts:
            dst_mac = memory.destination_hosts[dst_ip].mac
            if dst_mac in memory.lan_hosts:
                dst_label, dst_kind = _mac_label(dst_mac), "lan"
            else:
                gw_id = dst_mac.replace(":", "")[-6:] if dst_mac else dst_ip[-4:]
                dst_label, dst_kind = f"GW:{gw_id}", "gw"
        else:
            if eth_dst and eth_dst in memory.lan_hosts:
                dst_label, dst_kind = _mac_label(eth_dst), "lan"
            else:
                gw_id = eth_dst.replace(":", "")[-6:] if eth_dst else dst_ip[-4:]
                dst_label, dst_kind = f"GW:{gw_id}", "gw"

        if src_label == dst_label:
            continue

        is_tor = session_key in memory.possible_tor_traffic
        is_mal = session_key in memory.possible_mal_traffic
        color, proto = _edge_attrs(port, session.covert, is_tor, is_mal)
        priority = 4 if is_mal else 3 if is_tor else 2 if session.covert else 1

        pair = (src_label, dst_label)
        if pair not in edge_best or priority > edge_best[pair][0]:
            edge_best[pair] = (priority, color, proto, src_ip, dst_ip, src_kind, dst_kind)

    # Apply node filter: keep only edges where src or dst label/IP matches
    if node_filter:
        nf = node_filter.lower()
        edge_best = {
            (s, d): v for (s, d), v in edge_best.items()
            if nf in s.lower() or nf in d.lower()
            or nf in v[3].lower() or nf in v[4].lower()  # src_ip, dst_ip
        }

    G = nx.MultiDiGraph()
    for (src_label, dst_label), (_, color, proto, src_ip, dst_ip, src_kind, dst_kind) in edge_best.items():
        G.add_node(src_label, kind=src_kind, ip=src_ip)
        G.add_node(dst_label, kind=dst_kind, ip=dst_ip)
        G.add_edge(src_label, dst_label, color=color, proto=proto)

    if not G.nodes:
        return None, None, None, None

    # Always use spring_layout in the interactive panel — no subprocess overhead,
    # consistent behaviour on filter changes, and graphviz is reserved for the
    # static PNG rendered by plot_lan_network.
    iterations = 50 if live else 80
    pos = nx.spring_layout(G, k=2.5, iterations=iterations, seed=42)

    pos = _normalize_pos(pos)

    # Threat IPs for external nodes only (destination side); LAN/GW nodes keep role color
    mal_dst_ips = {s.split("/")[1] for s in memory.possible_mal_traffic}
    tor_dst_ips = {s.split("/")[1] for s in memory.possible_tor_traffic}

    node_colors = []
    for node in G.nodes:
        ip   = G.nodes[node].get("ip", "")
        kind = G.nodes[node].get("kind", "")
        if kind == "lan":
            node_colors.append("#1e88e5")    # always blue for LAN hosts
        elif kind == "gw":
            node_colors.append("#78909c")    # always gray for gateways
        elif ip in tor_dst_ips:
            node_colors.append("#9c27b0")    # purple — Tor exit/relay
        elif ip in mal_dst_ips:
            node_colors.append("#f44336")    # red — known malicious external
        else:
            node_colors.append("#ff7043")    # orange — generic external

    edge_colors = [d.get("color", "#607d8b") for _, _, d in G.edges(data=True)]
    return G, pos, node_colors, edge_colors


def _draw_on_axes(ax, G, pos, node_colors, edge_colors) -> None:
    import networkx as nx
    ax.cla()
    ax.set_facecolor("#1e1e2e")
    nx.draw_networkx_nodes(G, pos, node_color=node_colors,
                           node_size=700, alpha=0.92, ax=ax)
    nx.draw_networkx_labels(G, pos, font_size=7, font_color="white", ax=ax)
    nx.draw_networkx_edges(G, pos, edge_color=edge_colors,
                           arrows=True, arrowsize=14,
                           connectionstyle="arc3,rad=0.15",
                           ax=ax, alpha=0.85)
    _add_legend(ax)
    ax.axis("off")
    _xs = [p[0] for p in pos.values()]
    _ys = [p[1] for p in pos.values()]
    _xp = max((max(_xs) - min(_xs)) * 0.4, 0.7)
    _yp = max((max(_ys) - min(_ys)) * 0.4, 0.7)
    ax.set_xlim(min(_xs) - _xp, max(_xs) + _xp)
    ax.set_ylim(min(_ys) - _yp, max(_ys) + _yp)


def refresh_live() -> None:
    """Redraw the existing panel in-place from current memory state.

    Uses spring_layout (~100ms, no subprocess). Called every ~4s during live capture.
    No-op if the panel is not open.
    """
    if _ax is None or _canvas_widget is None:
        return
    filt = _filter_var.get() if _filter_var is not None else "All"
    nf   = _node_filter_var.get() if _node_filter_var is not None else ""
    G, pos, node_colors, edge_colors = _build_graph_data(live=True, filter_option=filt, node_filter=nf)
    if G is None:
        return
    _draw_on_axes(_ax, G, pos, node_colors, edge_colors)
    _figure.subplots_adjust(left=0.02, right=0.98, top=0.98, bottom=0.02)
    _canvas_widget.draw()
    log.debug("refresh_live: %d nodes", len(G.nodes))


def _apply_panel_filter(*_) -> None:
    """Redraw the panel with the current traffic + node filter options."""
    if _ax is None or _canvas_widget is None or _filter_var is None:
        return
    filt = _filter_var.get()
    nf   = _node_filter_var.get() if _node_filter_var is not None else ""
    G, pos, node_colors, edge_colors = _build_graph_data(live=_live_mode, filter_option=filt, node_filter=nf)
    if G is None:
        _ax.cla()
        _ax.set_facecolor("#1e1e2e")
        label = filt if not nf else f"{filt} / node '{nf}'"
        _ax.text(0.5, 0.5, f"No {label} traffic", ha="center", va="center",
                 color="white", fontsize=14, transform=_ax.transAxes)
        _ax.axis("off")
    else:
        _draw_on_axes(_ax, G, pos, node_colors, edge_colors)
    _figure.subplots_adjust(left=0.02, right=0.98, top=0.98, bottom=0.02)
    _canvas_widget.draw()
    log.debug("_apply_panel_filter(%s, node=%r): %d nodes", filt, nf, len(G.nodes) if G else 0)


def open_live_panel(base: tk.Tk) -> None:
    """Open the live graph panel, closing any existing panel first (never toggles)."""
    if _container is not None and _container.winfo_exists():
        _close()
    gimmick_initialize(base, "", live=True)


def set_panel_title(title: str) -> None:
    """Update the info bar text (used to show Live vs. stopped state)."""
    if _info_var is not None:
        _info_var.set(title)


def gimmick_initialize(base: tk.Tk, _html_path: str, live: bool = False) -> None:
    """Open (or close) the interactive graph panel."""
    global _container, _figure, _ax, _canvas_widget, _info_var, _filter_var, _node_filter_var, _live_mode, _base

    if _container is not None and _container.winfo_exists():
        _close()
        return

    try:
        import networkx as nx
        import matplotlib
        matplotlib.use("TkAgg")
        import matplotlib.pyplot as plt
        from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
    except ImportError as exc:
        log.warning("Interactive graph unavailable — missing dependency: %s", exc)
        import webbrowser
        webbrowser.open(_html_path)
        return

    _base = base
    _live_mode = live

    G, pos, node_colors, edge_colors = _build_graph_data(live=live)
    if G is None and not live:
        log.info("Interactive graph: no sessions in memory, nothing to show")
        return

    # ── Figure ────────────────────────────────────────────────────────────────
    fig, ax = plt.subplots(figsize=(9, 7))
    fig.patch.set_facecolor("#1e1e2e")
    ax.set_facecolor("#1e1e2e")

    if G is not None:
        _draw_on_axes(ax, G, pos, node_colors, edge_colors)
    else:
        ax.text(0.5, 0.5, "Waiting for traffic…", ha="center", va="center",
                color="white", fontsize=14, transform=ax.transAxes)
        ax.axis("off")
    fig.subplots_adjust(left=0.02, right=0.98, top=0.98, bottom=0.02)

    # ── Embed ─────────────────────────────────────────────────────────────────
    base.resizable(True, True)
    base.columnconfigure(11, weight=1)
    base.geometry(f"{base.winfo_width() + 700}x{max(base.winfo_height(), 600)}")

    _container = tk.Frame(base, bg="#1e1e2e")
    _container.grid(row=10, column=11, rowspan=41, sticky="nsew",
                    padx=(8, 8), pady=(8, 8))
    _container.rowconfigure(1, weight=1)
    _container.columnconfigure(0, weight=1)

    toolbar_row = tk.Frame(_container, bg="#2e2e3e")
    toolbar_row.grid(row=0, column=0, sticky="ew")

    cw = FigureCanvasTkAgg(fig, master=_container)
    nav = NavigationToolbar2Tk(cw, toolbar_row, pack_toolbar=False)
    nav.update()
    nav.pack(side=tk.LEFT)

    ttk.Button(toolbar_row, text="Close", command=_close).pack(
        side=tk.RIGHT, padx=4, pady=2)

    filter_var = tk.StringVar(value="All")
    filter_cb = ttk.Combobox(toolbar_row, textvariable=filter_var,
                             values=_FILTER_OPTIONS, state="readonly", width=10)
    filter_cb.pack(side=tk.RIGHT, padx=(2, 6), pady=2)
    ttk.Label(toolbar_row, text="Filter:").pack(side=tk.RIGHT, padx=(8, 0), pady=2)
    filter_var.trace_add("write", _apply_panel_filter)
    _filter_var = filter_var

    node_filter_var = tk.StringVar()
    node_entry = ttk.Entry(toolbar_row, textvariable=node_filter_var, width=14)
    node_entry.pack(side=tk.RIGHT, padx=(2, 2), pady=2)
    ttk.Label(toolbar_row, text="Node:").pack(side=tk.RIGHT, padx=(8, 0), pady=2)
    node_entry.bind("<Return>", _apply_panel_filter)
    node_entry.bind("<FocusOut>", _apply_panel_filter)
    _node_filter_var = node_filter_var

    cw.get_tk_widget().grid(row=1, column=0, sticky="nsew")

    default_info = ("📡 Live — updates every 4s  |  Blue=LAN  Gray=Gateway  Red=Malicious  Purple=Tor"
                    if live else
                    "Click a node for details  |  Blue=LAN  Gray=Gateway  Red=Malicious  Purple=Tor")
    info_var = tk.StringVar(value=default_info)
    ttk.Label(_container, textvariable=info_var, anchor="w",
              padding=(6, 3)).grid(row=2, column=0, sticky="ew")

    cw.draw()

    # Store globals for refresh_live() and set_panel_title()
    _figure = fig
    _ax = ax
    _canvas_widget = cw
    _info_var = info_var

    # Click-to-inspect (only meaningful when G exists)
    if G is not None:
        def _on_click(event):
            if event.inaxes != ax or event.xdata is None:
                return
            closest, min_dist = None, float("inf")
            for node, (x, y) in pos.items():
                d = (event.xdata - x) ** 2 + (event.ydata - y) ** 2
                if d < min_dist:
                    min_dist, closest = d, node
            if closest is None or min_dist > 0.25:
                return
            ip = G.nodes[closest].get("ip", "?")
            sessions = [s for s in memory.packet_db if ip in s.split("/")[:2]]
            dst_host = memory.destination_hosts.get(ip)
            domain = dst_host.domain_name if dst_host and dst_host.domain_name else "—"
            protos = sorted({G[u][v][k].get("proto", "")
                             for u, v, k in G.edges(keys=True)
                             if u == closest or v == closest})
            info_var.set(
                f"Node: {closest}  |  IP: {ip}  |  Domain: {domain}  |  "
                f"Sessions: {len(sessions)}  |  Protocols: {', '.join(protos)}"
            )
        fig.canvas.mpl_connect("button_press_event", _on_click)

    base.after(250, lambda: (base.lift(), base.focus_force()))


def _close() -> None:
    global _container, _figure, _ax, _canvas_widget, _info_var, _filter_var, _node_filter_var, _live_mode, _base
    import matplotlib.pyplot as plt
    if _figure is not None:
        plt.close(_figure)
        _figure = None
    _ax = None
    _canvas_widget = None
    _info_var = None
    _filter_var = None
    _node_filter_var = None
    _live_mode = False
    if _container is not None and _container.winfo_exists():
        b = _container.winfo_toplevel()
        _container.destroy()
        _container = None
        try:
            b.columnconfigure(11, weight=0, minsize=0)
            b.geometry("")  # let Tkinter snap window back to natural content size
            b.resizable(False, False)
        except Exception as exc:
            log.warning("_close: could not restore window geometry: %s", exc)
    _base = None


def _normalize_pos(pos: dict) -> dict:
    if len(pos) <= 1:
        return {n: (0.0, 0.0) for n in pos}
    xs = [p[0] for p in pos.values()]
    ys = [p[1] for p in pos.values()]
    cx = (max(xs) + min(xs)) / 2
    cy = (max(ys) + min(ys)) / 2
    rng = max(max(xs) - min(xs), max(ys) - min(ys)) or 1.0
    return {n: ((x - cx) / rng * 1.5, (y - cy) / rng * 1.5)
            for n, (x, y) in pos.items()}


def _mac_label(mac: str) -> str:
    return memory.lan_hosts[mac].ip


def _edge_attrs(port: str, covert: bool, is_tor: bool, is_mal: bool) -> tuple[str, str]:
    if is_mal:
        return "#f44336", "Malicious"
    if is_tor:
        return "#9c27b0", "Tor"
    if covert:
        return "#00bcd4", f"Covert/{'DNS' if port == '53' else port}"
    if port == "443":
        return "#1e88e5", "HTTPS"
    if port == "80":
        return "#43a047", "HTTP"
    if port == "53":
        return "#fdd835", "DNS"
    if port == "ICMP":
        return "#ff7043", "ICMP"
    try:
        if int(port) in (20, 21, 23, 25, 110, 143, 139, 69, 161, 162, 1521):
            return "#ce93d8", f"Clear/{port}"
    except ValueError:
        pass
    return "#607d8b", f"Port {port}"


def _add_legend(ax) -> None:
    import matplotlib.patches as mpatches
    from matplotlib.lines import Line2D
    items = [
        mpatches.Patch(color="#1e88e5", label="LAN host"),
        mpatches.Patch(color="#78909c", label="Gateway"),
        mpatches.Patch(color="#f44336", label="Malicious"),
        mpatches.Patch(color="#9c27b0", label="Tor"),
        Line2D([0], [0], color="#1e88e5", linewidth=2, label="HTTPS"),
        Line2D([0], [0], color="#43a047", linewidth=2, label="HTTP"),
        Line2D([0], [0], color="#fdd835", linewidth=2, label="DNS"),
        Line2D([0], [0], color="#00bcd4", linewidth=2, label="Covert"),
    ]
    ax.legend(handles=items, loc="upper left",
              facecolor="#2e2e3e", edgecolor="#555", labelcolor="white",
              fontsize=6, ncol=2)
