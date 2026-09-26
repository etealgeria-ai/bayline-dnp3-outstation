"""Desktop window for the Bayline outstation. Uses the Python standard library."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from bayline.outstation import write_point
from bayline.station import KEY_AUTH_FAIL, KEY_OK, find_point

BG = "#121816"
SURFACE = "#1c2621"
INK = "#e7efe9"
MUTED = "#8ea197"
LINE = "#2c3a34"
AMBER = "#e2a53a"
ALARM = "#e15b4a"


def run_gui(host) -> None:
    root = tk.Tk()
    root.title("Bayline DNP3 outstation")
    root.geometry("980x660")
    root.minsize(760, 520)
    root.configure(bg=BG)
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    style.configure("Treeview", background=SURFACE, fieldbackground=SURFACE, foreground=INK, borderwidth=0, rowheight=26)
    style.configure("Treeview.Heading", background="#24302a", foreground=MUTED, relief="flat")
    style.map("Treeview", background=[("selected", "#2f4038")], foreground=[("selected", INK)])

    header = tk.Frame(root, bg=BG)
    header.pack(fill="x", padx=16, pady=(14, 6))
    tk.Label(header, text="BAYLINE", bg=BG, fg=AMBER, font=("Segoe UI", 9)).pack(anchor="w")
    tk.Label(header, text="DNP3 outstation", bg=BG, fg=INK, font=("Segoe UI", 18)).pack(anchor="w")
    status = tk.StringVar()
    tk.Label(header, textvariable=status, bg=BG, fg=MUTED, font=("Segoe UI", 10)).pack(anchor="w", pady=(2, 0))

    actions = tk.Frame(root, bg=BG)
    actions.pack(fill="x", padx=16, pady=8)
    power = tk.Button(actions, text="Stop outstation", command=lambda: _toggle(host, power), bg=ALARM, fg="#1a100e", activebackground=ALARM, relief="flat", padx=14, pady=8, font=("Segoe UI", 10, "bold"))
    power.pack(side="left")
    tk.Button(actions, text="Trip 52-F1", command=lambda: _breaker(host, 1, 0), bg=SURFACE, fg=INK, activebackground="#24302a", relief="flat", padx=12, pady=8).pack(side="left", padx=(8, 0))
    tk.Button(actions, text="Close 52-F1", command=lambda: _breaker(host, 1, 1), bg=SURFACE, fg=INK, activebackground="#24302a", relief="flat", padx=12, pady=8).pack(side="left", padx=(8, 0))

    body = tk.Frame(root, bg=BG)
    body.pack(fill="both", expand=True, padx=16, pady=(0, 16))
    points = ttk.Treeview(body, columns=("kind", "idx", "name", "value"), show="headings", height=16)
    for key, title, width in (("kind", "Type", 50), ("idx", "Index", 60), ("name", "Point", 280), ("value", "Value", 120)):
        points.heading(key, text=title)
        points.column(key, width=width, anchor="w")
    points.pack(side="left", fill="both", expand=True)
    log = tk.Listbox(body, bg=SURFACE, fg=INK, selectbackground="#2f4038", highlightthickness=1, highlightbackground=LINE, relief="flat", font=("Consolas", 9), width=46)
    log.pack(side="left", fill="both", expand=True, padx=(10, 0))

    host.start()

    def refresh() -> None:
        snap = host.snapshot()
        sav = "SAv5 OK" if snap["sav_status"] == KEY_OK else "SAv5 auth fail" if snap["sav_status"] == KEY_AUTH_FAIL else "SAv5 not initialized"
        link = "link reset" if snap["link"] else "link not reset"
        tcp = f"TCP {snap['port']} · {snap['clients']} master" if snap["running"] else "TCP stopped"
        if snap["clients"] != 1 and snap["running"]:
            tcp = f"TCP {snap['port']} · {snap['clients']} masters"
        status.set(f"{snap['name']} · outstation {snap['outstation']} · master {snap['master']} · {tcp} · {link} · {sav}")
        if snap["error"]:
            status.set(snap["error"])
        power.configure(text="Stop outstation" if snap["running"] else "Start outstation", bg=ALARM if snap["running"] else AMBER)
        selected = points.selection()
        points.delete(*points.get_children())
        for kind, index, name, value, units in snap["points"]:
            shown = "CLOSED" if value >= 0.5 else "OPEN" if kind in ("bi", "bo") else f"{value:.2f} {units}".strip()
            points.insert("", "end", iid=f"{kind}-{index}", values=(kind.upper(), index, name, shown))
        if selected:
            points.selection_set([item for item in selected if points.exists(item)])
        log.delete(0, "end")
        for direction, summary, ok in snap["log"]:
            mark = {"in": "RX", "out": "TX"}.get(direction, "--")
            log.insert("end", f"{mark}  {summary}")
            if not ok:
                log.itemconfig("end", fg=ALARM)
        if not snap["log"]:
            log.insert("end", "No frames yet. Start the outstation, then connect a master.")
        root.after(500, refresh)

    refresh()
    root.protocol("WM_DELETE_WINDOW", lambda: (_shutdown(host), root.destroy()))
    root.mainloop()


def _toggle(host, button) -> None:
    if host.running:
        host.stop()
        button.configure(text="Start outstation", bg=AMBER)
    else:
        host.start()
        button.configure(text="Stop outstation", bg=ALARM)


def _breaker(host, index: int, closed: int) -> None:
    import time

    with host.lock:
        point = find_point(host.station, "bo", index)
        if point:
            write_point(host.station, point, closed, point.flags, int(time.time() * 1000), "control")


def _shutdown(host) -> None:
    host.stop()
