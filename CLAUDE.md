# PcapXray — Claude Guidelines

## What this project is

PcapXray is a network forensics and visualization tool. It reads PCAP files or captures live traffic, classifies sessions by protocol, detects covert/malicious/Tor traffic, resolves hostnames and OUI vendor info, then renders a graph of the LAN network. It has a Tkinter GUI and a CLI entrypoint (`Source/main.py`).

Target runtime: **Python 3.10+**. Python 2 support was dropped; never reintroduce Py2 shims.

---

## Architecture

### Data flow — file mode
```
pcap_reader.PcapEngine          — streams PCAP via pluggable engine → memory state
    ↓
communication_details_fetch     — DNS/whois reverse-lookup on destination IPs
device_details_fetch            — OUI vendor lookup on LAN MACs
tor_traffic_handle              — Tor consensus download + session match
malicious_traffic_identifier    — flags sessions by port/domain heuristic
    ↓
sqlite_store.SqliteStore        — persist / reload session (optional cache)
    ↓
plot_lan_network.PlotLan        — renders graphviz PNG (+ pyvis HTML)
report_generator.ReportGenerator— writes TXT reports
    ↓
user_interface.pcapXrayGui      — Tkinter GUI driving all of the above
```

### Data flow — live mode
```
pcap_reader.LivePcapEngine      — AsyncSniffer → _process_packet() → memory state
    ↓  (every 4 s)
interactive_gui.refresh_live()  — redraws matplotlib panel in-place (spring_layout)
    ↓  (on Stop)
_run_deferred_covert()          — batch DNS covert check post-capture
sqlite_store.SqliteStore        — save session for future reload
    ↓  (user clicks Visualize!)
plot_lan_network.PlotLan        — point-in-time static PNG + pyvis HTML
```

### Shared packet processing
`pcap_reader._process_packet(pkt, dns_candidates)` and `pcap_reader._run_deferred_covert(dns_candidates)` are **module-level functions** used by both `PcapEngine` and `LivePcapEngine`. Never inline packet processing into either class.

### Pluggable engine subpackage — `Source/Module/engines/`
```
engines/
├── __init__.py       — select_engine(name, pcap_path) → PacketEngine
├── base.py           — NormalizedPacket dataclass + PacketEngine Protocol
├── scapy_engine.py   — streaming PcapReader, TLS-aware
├── dpkt_engine.py    — fast offline, low memory (PCAPng fallback)
└── pyshark_engine.py — tshark-backed, live-capture ready
```

`select_engine("auto", path)` tries `DpktEngine` first, falls back to `ScapyEngine`. All engines yield `NormalizedPacket` — the main loop is engine-agnostic.

### Global state (memory.py)
All inter-module state lives in `memory.py` as typed Pydantic models inside plain dict containers:

| Container | Key | Value type |
|---|---|---|
| `memory.packet_db` | `"src/dst/port"` | `PacketSession` |
| `memory.lan_hosts` | MAC string | `LanHost` |
| `memory.destination_hosts` | IP string | `DestinationHost` |
| `memory.tor_nodes` | — | `list[tuple[str, int]]` |
| `memory.possible_tor_traffic` | — | `list[str]` |
| `memory.possible_mal_traffic` | — | `list[str]` |

**Never use dict-style key access on model values.** Use attribute access: `session.covert`, `host.domain_name`, `h.node`. The models guarantee field presence so `.get()` fallbacks are not needed.

Memory is the live source of truth for both file and live modes. SQLite is the persistence layer (saved after analysis or after live stop). The matplotlib panel and static graph both read from memory.

---

## Coding conventions

### Module structure
Every source module must have:
- `__all__` listing its public API (at the top, after docstring/imports)
- `log = logging.getLogger(__name__)` — never use `print()` or bare `logging.*` calls
- Type hints on all function signatures

### Class naming
PEP 8 CamelCase: `TrafficDetailsFetch`, `FetchDeviceDetails`, `MaliciousTrafficIdentifier`, `TorTrafficHandle`, `ReportGenerator`, `PlotLan`, `PcapEngine`, `LivePcapEngine`, `ScapyEngine`, `DpktEngine`, `PySharkEngine`. Internal helpers are `_snake_case`.

### Logging
- Use `PCAPXRAY_DEBUG=1` env var to enable DEBUG level (wired in `Source/main.py`)
- Log file: `~/PcapXray.log` (overwritten each run)
- Pattern: `log.info("...")`, `log.warning("...")`, `log.error("...")`

### Error handling
- Never use bare `except:` — always `except Exception:` or a specific type
- External I/O (DNS, Tor, OUI APIs) must have timeouts and degrade gracefully
- DNS batch: `concurrent.futures.wait(timeout=10.0)` hard cap
- Tor consensus: daemon thread + `join(timeout=15.0)`
- Graphviz render: `f.render(timeout=30)` with `except TypeError` fallback for older lib versions
- Live capture `PermissionError`: show `mb.showerror` and restore UI — never crash

### Pydantic models
- Models live in `memory.py`; import them where needed: `from memory import PacketSession, LanHost, DestinationHost`
- When serializing to JSON (reports), use `_ModelEncoder` from `report_generator.py` or call `.model_dump()` explicitly
- Model fields have safe defaults — no need to guard with `if "key" not in dict`

### Live capture threading
- `LivePcapEngine._on_packet()` runs in scapy's sniffer thread; all `memory.*` mutations inside it are protected by `self._lock`
- `_stop_live()` sets `self._live_engine = None` **before** calling `_poll_thread()` so any `_live_refresh()` callback that fires during `base.update()` sees None and exits without rescheduling
- Use `interactive_gui.open_live_panel(base)` to open the live panel — never call `gimmick_initialize()` directly from `_start_live()` (it toggles; `open_live_panel` always opens)

---

## Testing

### Running tests
```bash
# Fast suite — no network calls (~55s)
pytest -m "not network" Test/

# Full suite including real DNS + Tor (~95s locally, may be slow in CI)
pytest Test/

# Isolated engine envs (default + dpkt)
tox
tox -e all-engines
```

### Test layout
| File | What it tests |
|---|---|
| `Test/test_unit.py` | Per-module unit tests with mocked network/OUI/Tor |
| `Test/test_sanity.py` | End-to-end smoke tests against real PCAP files |
| `Test/test_pcap_reader_module.py` | Standalone pcap_reader smoke test |
| `Test/test_engines.py` | Engine architecture: NormalizedPacket, ScapyEngine, DpktEngine, select_engine fallback, `_process_packet`, `LivePcapEngine` |
| `Test/test_sqlite_store.py` | SQLite session persistence and reload |

### Markers
- `@pytest.mark.network` — marks tests that make real network calls (DNS resolution, Tor consensus). These are skipped in CI with `-m "not network"`.

### conftest.py
Located at project root. Adds `Source/Module` to `sys.path` and exports `EXAMPLES_DIR` pointing to `Source/Module/examples/`. All tests import from there — never hardcode paths.

### Writing new tests
- Seed `memory.*` with model instances, not raw dicts: `memory.destination_hosts["1.2.3.4"] = DestinationHost(domain_name="example.com")`
- Reset memory state in a `@pytest.fixture(autouse=True)` — see `test_unit.py` for the pattern
- Mock at the module level: `patch("communication_details_fetch.socket.gethostbyaddr", ...)`
- **96+ tests must stay green before any commit**

---

## Things to avoid

- **No Python 2 shims** — no `try/except ImportError` for `tkinter`/`Tkinter`, `queue`/`Queue`, etc.
- **No `cefpython3`** — removed. The interactive graph panel uses `matplotlib` + `networkx` embedded via `FigureCanvasTkAgg`.
- **No `print()` in source modules** — use `log.*`
- **No bare `except:`** — always catch `Exception` or a specific type
- **No dict-style access on Pydantic model values** — use attribute access
- **No `netaddr.IPAddress.is_private()`** — removed in netaddr 0.9.x; use `ipaddress.ip_address(ip).is_private` (stdlib, property not method)
- **No blocking calls on the Tkinter main thread** — use `_run_in_thread()` / `_poll_thread()` from `user_interface.py`
- **No pushing many small commits to remote** — batch related changes locally and push once per logical unit of work
- **No graphviz layout during live capture** — use `nx.spring_layout` (no subprocess); graphviz is for static graph only
- **No direct `gimmick_initialize()` call for live mode** — use `open_live_panel(base)` which always opens without toggling

---

## Phased roadmap (current state)

| Phase | Status | Notes |
|---|---|---|
| 0 — Critical bug fixes | Done | Pillow ANTIALIAS, is_private(), urllib, bare excepts |
| 1 — Python 2 drop + deps | Done | Py3-only imports, requirements.txt pinned |
| 2 — Test infrastructure | Done | conftest.py, 96 tests, network marker, coverage in CI, tox |
| 3 — Code quality | Done | Pydantic models, PEP 8 names, `__all__`, logging, dead code |
| 4 — Replace cefpython3 | Done | matplotlib+networkx panel embedded in Tkinter via FigureCanvasTkAgg; `interactive_gui.py` |
| 5 — Features (partial) | Done | Streaming PCAP, pluggable engines (dpkt/scapy/pyshark), deferred covert detection, SQLite session cache |
| 6 — Live capture | Done | `LivePcapEngine`, AsyncSniffer, 4s graph refresh, live→static handoff |
| 7 — Features (remaining) | Pending | More protocols (QUIC, HTTP/2, mDNS), web UI, eBPF engine |

---

## Code Review Standards

When reviewing or implementing any change, evaluate it as a staff-level engineer and architect. Every non-trivial PR should be assessed across these axes before merge:

### Correctness and robustness
- **Closure / stale capture bugs** — closures in event handlers (Tkinter `bind`, matplotlib `mpl_connect`) must not capture mutable locals that change after registration. Promote to module-level or instance-level state instead.
- **Race conditions** — debounced `after()` callbacks can fire after the widget is destroyed. Always guard with `winfo_exists()` before touching Tk widgets inside a delayed callback.
- **Thread safety** — any `memory.*` mutation outside `_on_packet` (which holds `self._lock`) is a bug. Never read-modify-write shared containers from the Tk main thread without a lock.
- **Edge cases** — test mentally: empty PCAP (zero sessions), single node, live capture → Stop → Visualize!, re-running Visualize! with a cached PNG, closing the panel mid-refresh.

### Performance and resource safety
- **Main-thread blocking** — `spring_layout`, graphviz render, DNS lookups, file I/O must not run on the Tk main thread. Use `_run_in_thread` + `_poll_thread`. Event bindings that trigger expensive ops (e.g., `<FocusOut>` → layout) are a latent freeze.
- **Resource leaks** — every `StringVar.trace_add()` needs a matching `trace_remove()` on teardown. Every `plt.subplots()` needs `plt.close()`. Every `Toplevel` needs a `destroy()` path. Tk canvas image references must be kept alive on `self`.
- **Memory** — PIL images opened in resize callbacks must be cached, not re-opened per event. Debounce rapid `<Configure>` events (120ms minimum).

### Safety and PII
- **Payload display** — raw packet payload shown in the UI is expected (forensics tool), but never log payload content at INFO/WARNING level; use DEBUG only.
- **No data exfiltration** — the only outbound calls allowed are: DNS reverse-lookup (`gethostbyaddr`), whois/RDAP (`ipwhois`), OUI vendor lookup (`device_details_fetch`), Tor consensus (`stem`). Any new network call must be documented and opt-in.
- **Output path isolation** — all file writes (PNG, HTML, TXT, SQLite) go to the user-specified output directory only. Never write to `/tmp`, `~`, or relative paths.
- **No credentials in logs** — never log HTTP Authorization headers, cookie values, or TLS pre-master secrets even at DEBUG.
- **SQL safety** — all SQLite queries use parameterised statements (`?` placeholders). No f-string or `%`-formatted SQL.

### Architecture consistency
- **Module boundaries** — `interactive_gui` reads `memory.*` but never writes it. `user_interface` drives analysis but delegates rendering to `plot_lan_network` and `interactive_gui`. Cross-module writes outside these contracts are bugs.
- **Global state in `interactive_gui`** — all panel state lives in module-level `_*` variables. Any new state variable needs a reset in `_close()` and a guard in every function that reads it (`if _ax is None: return`).
- **Pydantic models** — use attribute access, never dict-style. Use `.model_dump()` for serialisation.

---

## CI (GitHub Actions)

Workflow: `.github/workflows/test.yml`
- Matrix: Python 3.10, 3.11, 3.12
- System deps: `graphviz python3-tk tshark` via apt
- Test command: `pytest -m "not network" --cov=Source/Module --cov-report=xml Test/`
- Also runs: `tox -e all-engines` (dpkt isolated env)
- Coverage uploaded to Codecov (requires `CODECOV_TOKEN` secret in repo settings)
- Lint: `flake8` — fatal errors only (E9, F63, F7, F82); style issues are advisory
