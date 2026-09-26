"""Desktop window matching the Bayline console: points, comms, master, wire, SAv5."""

from __future__ import annotations

import time
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
    root.title("DNP3 Outstation Simulator")
    root.geometry("1080x720")
    root.minsize(860, 560)
    root.configure(bg=BG)
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    style.configure("TNotebook", background=BG, borderwidth=0)
    style.configure("TNotebook.Tab", background=SURFACE, foreground=INK, padding=(14, 8))
    style.map("TNotebook.Tab", background=[("selected", AMBER)], foreground=[("selected", "#1a140c")])
    style.configure("Treeview", background=SURFACE, fieldbackground=SURFACE, foreground=INK, borderwidth=0, rowheight=26)
    style.configure("Treeview.Heading", background="#24302a", foreground=MUTED, relief="flat")
    style.map("Treeview", background=[("selected", "#2f4038")], foreground=[("selected", INK)])

    header = tk.Frame(root, bg=BG)
    header.pack(fill="x", padx=16, pady=(12, 4))
    tk.Label(header, text="BAYLINE", bg=BG, fg=AMBER, font=("Segoe UI", 9)).pack(anchor="w")
    tk.Label(header, text="DNP3 Outstation Simulator", bg=BG, fg=INK, font=("Segoe UI", 18)).pack(anchor="w")
    subtitle = tk.StringVar()
    tk.Label(header, textvariable=subtitle, bg=BG, fg=MUTED, font=("Segoe UI", 10)).pack(anchor="w")
    lamps = tk.Frame(header, bg=BG)
    lamps.pack(anchor="w", pady=(6, 0))
    lamp_vars = {name: tk.StringVar(value=name) for name in ("TCP", "SAv5", "Restart", "Time", "Local", "C1", "C2", "C3")}
    lamp_widgets = {}
    for name, var in lamp_vars.items():
        label = tk.Label(lamps, textvariable=var, bg=BG, fg=MUTED, font=("Segoe UI", 9))
        label.pack(side="left", padx=(0, 14))
        lamp_widgets[name] = label

    actions = tk.Frame(root, bg=BG)
    actions.pack(fill="x", padx=16, pady=8)
    power = tk.Button(actions, command=lambda: _toggle(host), bg=ALARM, fg="#1a100e", relief="flat", padx=14, pady=8, font=("Segoe UI", 10, "bold"))
    power.pack(side="left")

    book = ttk.Notebook(root)
    book.pack(fill="both", expand=True, padx=16, pady=(0, 16))
    points_tab = _tab(book, "Points")
    trend_tab = _tab(book, "Trend")
    comms_tab = _tab(book, "Comms")
    wire_tab = _tab(book, "Wire")
    security_tab = _tab(book, "Security")

    points = ttk.Treeview(points_tab, columns=("kind", "addr", "idx", "name", "value"), show="headings")
    for key, title, width in (("kind", "Type", 60), ("addr", "DNP3 address", 120), ("idx", "Index", 70), ("name", "Point", 280), ("value", "Value", 160)):
        points.heading(key, text=title)
        points.column(key, width=width, anchor="w")
    points.pack(fill="both", expand=True, padx=8, pady=8)
    point_actions = tk.Frame(points_tab, bg=BG)
    point_actions.pack(fill="x", padx=8, pady=(0, 8))
    for index, title in ((0, "52-T1"), (1, "52-F1"), (2, "52-F2")):
        tk.Button(point_actions, text=f"Trip {title}", command=lambda i=index: _breaker(host, i, 0), bg=SURFACE, fg=INK, relief="flat", padx=10, pady=6).pack(side="left", padx=(0, 6))
        tk.Button(point_actions, text=f"Close {title}", command=lambda i=index: _breaker(host, i, 1), bg=SURFACE, fg=INK, relief="flat", padx=10, pady=6).pack(side="left", padx=(0, 12))
    manual = tk.Frame(points_tab, bg=BG)
    manual.pack(fill="x", padx=8, pady=(0, 8))
    tk.Label(manual, text="Manual value", bg=BG, fg=MUTED, font=("Segoe UI", 10)).pack(side="left")
    manual_entry = tk.Entry(manual, width=16, bg=SURFACE, fg=INK, insertbackground=INK, relief="flat", font=("Consolas", 11))
    manual_entry.pack(side="left", padx=8)
    manual_error = tk.StringVar()
    tk.Button(manual, text="Write", command=lambda: _write(host, points, manual_entry, manual_error), bg=AMBER, fg="#1a140c", relief="flat", padx=12, pady=6).pack(side="left")
    tk.Button(manual, text="Release to random", command=lambda: _release(host, points), bg=SURFACE, fg=INK, relief="flat", padx=12, pady=6).pack(side="left", padx=(8, 0))
    tk.Label(manual, textvariable=manual_error, bg=BG, fg=ALARM, font=("Segoe UI", 10)).pack(side="left", padx=8)

    trend = tk.Canvas(trend_tab, bg=BG, highlightthickness=0)
    trend.pack(fill="both", expand=True)
    samples: list[dict] = []

    comms = _text(comms_tab)
    security = _text(security_tab)
    wire = tk.Listbox(wire_tab, bg=SURFACE, fg=INK, selectbackground="#2f4038", highlightthickness=0, relief="flat", font=("Consolas", 10))
    wire.pack(fill="both", expand=True, padx=8, pady=(8, 4))
    hex_line = tk.StringVar(value="Select a frame to see the hex.")
    tk.Label(wire_tab, textvariable=hex_line, bg=BG, fg=AMBER, anchor="w", font=("Consolas", 9), wraplength=980, justify="left").pack(fill="x", padx=8, pady=(0, 8))
    shown: list[tuple] = []

    def on_wire(_event=None) -> None:
        pick = wire.curselection()
        if not pick or pick[0] >= len(shown):
            return
        hex_line.set(shown[pick[0]][4] or shown[pick[0]][3])

    wire.bind("<<ListboxSelect>>", on_wire)

    security_actions = tk.Frame(security_tab, bg=BG)
    security_actions.pack(side="bottom", fill="x", padx=8, pady=(0, 8))
    sav2 = tk.Button(security_actions, text="SAv2", command=lambda: host.set_auth_version(2), bg=SURFACE, fg=INK, relief="flat", padx=10, pady=6)
    sav5 = tk.Button(security_actions, text="SAv5", command=lambda: host.set_auth_version(5), bg=SURFACE, fg=INK, relief="flat", padx=10, pady=6)
    sav_off = tk.Button(security_actions, text="Disable SAv", command=host.disable_auth, bg=SURFACE, fg=INK, relief="flat", padx=10, pady=6)
    sav2.pack(side="left", padx=(0, 6))
    sav5.pack(side="left", padx=(0, 6))
    sav_off.pack(side="left", padx=(0, 6))
    tk.Button(security_actions, text="Remote / local", command=lambda: host.set_flag("local", not host.snapshot()["local"]), bg=SURFACE, fg=INK, relief="flat", padx=10, pady=6).pack(side="left", padx=(0, 6))
    tk.Button(security_actions, text="Yard run / hold", command=lambda: host.set_flag("sim", not host.snapshot()["sim_on"]), bg=SURFACE, fg=INK, relief="flat", padx=10, pady=6).pack(side="left")

    log_key: list[tuple] = [()]

    def refresh() -> None:
        snap = host.snapshot()
        sav = snap["sav"]
        subtitle.set(f"{snap['name']} · address {snap['outstation']} · master {snap['master']} · port {snap['port']}")
        power.configure(text="Stop outstation" if snap["running"] else "Start outstation", bg=ALARM if snap["running"] else AMBER, fg="#1a100e")
        _lamp(lamp_widgets["TCP"], lamp_vars["TCP"], f"TCP {snap['clients']}" if snap["clients"] else f"TCP {snap['port']}", snap["running"] and not snap["error"], bool(snap["error"]))
        choice = "off" if not sav["enabled"] else "2" if sav["version"] == 2 else "5"
        for key, button in (("2", sav2), ("5", sav5), ("off", sav_off)):
            button.configure(bg=AMBER if key == choice else SURFACE, fg="#1a140c" if key == choice else INK)
        _lamp(lamp_widgets["SAv5"], lamp_vars["SAv5"], "SAv off" if not sav["enabled"] else sav["label"] if sav["status"] == KEY_OK else f"{sav['label']} fail" if sav["status"] == KEY_AUTH_FAIL else f"{sav['label']} init", sav["enabled"] and sav["status"] == KEY_OK, sav["enabled"] and sav["status"] == KEY_AUTH_FAIL)
        _lamp(lamp_widgets["Restart"], lamp_vars["Restart"], "Restart", snap["restart"], snap["restart"])
        _lamp(lamp_widgets["Time"], lamp_vars["Time"], "Time", snap["need_time"], snap["need_time"])
        _lamp(lamp_widgets["Local"], lamp_vars["Local"], "Local", snap["local"], snap["local"])
        for clazz, name in ((1, "C1"), (2, "C2"), (3, "C3")):
            count = snap["classes"][clazz]
            _lamp(lamp_widgets[name], lamp_vars[name], f"{name} {count}", count > 0, False)
        verdict, detail = _verdict(snap)
        unsol = " ".join(key.upper() for key, on in snap["unsol"].items() if on) or "Off"
        confirm = "None" if snap["confirm"] is None else f"Seq {snap['confirm']['seq']} · {snap['confirm']['left']} s"
        armed = "None" if snap["select"] is None else f"g{snap['select']['group']} · {snap['select']['index']} · {snap['select']['left']} s"
        quiet = "None" if snap["quiet"] is None else "Just now" if snap["quiet"] < 1500 else f"{round(snap['quiet'] / 1000)} s ago"
        _fill(comms, [
            verdict,
            detail,
            "",
            f"TCP listener     {'Up · port ' + str(snap['port']) if snap['running'] else 'Down'}",
            f"TCP clients      {snap['error'] or snap['clients']}",
            "Station owner    This PC",
            f"Outstation       {snap['outstation']}",
            f"Master           {snap['master']}",
            f"Link             {'Reset' if snap['link'] else 'Not reset'}",
            f"Last frame       {quiet}",
            f"Received         {snap['rx']}",
            f"Sent             {snap['tx']}",
            f"Rejected         {snap['bad']}",
            f"Confirm pending  {confirm}",
            f"Select armed     {armed}",
            f"Unsolicited      {unsol}",
            "",
            "Secure session",
            f"Authentication   {'On' if sav['enabled'] else 'Off'}",
            f"Version          {sav['label']}",
            f"MAC              {sav['mac_name']}",
            f"Key wrap         {sav['wrap_name']}",
            f"Key status       {_key_name(sav['status'])}",
            f"User             {sav['user']}",
            f"KSQ              {sav['ksq']}",
            f"CSQ              {sav['csq']}",
            f"Accepted         {sav['ok']}",
            f"Failed           {sav['fail']}",
            f"Aggressive       {'On' if sav['aggressive'] else 'Off'}",
            "",
            sav["result"],
        ])
        _fill(security, [
            f"Session     {'OFF' if not sav['enabled'] else sav['label'] + ' ' + _key_name(sav['status'])}",
            f"MAC         {sav['mac_name']}",
            f"Key wrap    {sav['wrap_name']}",
            f"User        {sav['user']}",
            f"KSQ         {sav['ksq']}",
            f"Next CSQ    {sav['csq']}",
            f"Accepted    {sav['ok']}",
            f"Rejected    {sav['fail']}",
            f"Aggressive  {'On' if sav['aggressive'] else 'Off'}",
            "",
            sav["result"],
            "",
            "Update key",
            sav["key"],
            "",
            "HMAC matches the selected version. SAv2 is HMAC-SHA-1-8 and AES-128. SAv5 is HMAC-SHA-256-16 and AES-256.",
        ])
        _sample(samples, snap)
        _draw_trend(trend, samples)
        selected = points.selection()
        points.delete(*points.get_children())
        for kind, index, name, value, units, held in snap["points"]:
            shown_value = _shown(kind, index, value, units, held)
            address = f"{_group(kind)}:{index}"
            points.insert("", "end", iid=f"{kind}-{index}", values=(kind.upper(), address, index, name, shown_value))
        if selected:
            points.selection_set([item for item in selected if points.exists(item)])
        key = tuple((item[0], item[2], item[3]) for item in snap["log"])
        if key != log_key[0]:
            log_key[0] = key
            shown.clear()
            shown.extend(snap["log"])
            wire.delete(0, "end")
            for _id, stamp, direction, summary, _hx, ok in snap["log"]:
                mark = {"in": "RX", "out": "TX"}.get(direction, "--")
                clock = time.strftime("%H:%M:%S", time.gmtime(stamp / 1000))
                wire.insert("end", f"{clock}  {mark}  {summary}")
                if not ok:
                    wire.itemconfig("end", fg=ALARM)
            if not snap["log"]:
                wire.insert("end", "No frames yet. Connect a master on port 20000.")
            wire.yview_moveto(1)
        root.after(500, refresh)

    host.start()
    refresh()
    root.protocol("WM_DELETE_WINDOW", lambda: (_shutdown(host), root.destroy()))
    root.mainloop()


def _tab(book: ttk.Notebook, title: str) -> tk.Frame:
    frame = tk.Frame(book, bg=BG)
    book.add(frame, text=title)
    return frame


def _text(parent: tk.Frame) -> tk.Text:
    widget = tk.Text(parent, bg=BG, fg=INK, relief="flat", font=("Consolas", 11), padx=12, pady=12, wrap="word")
    widget.pack(fill="both", expand=True)
    widget.configure(state="disabled")
    return widget


def _fill(widget: tk.Text, lines: list[str]) -> None:
    widget.configure(state="normal")
    widget.delete("1.0", "end")
    widget.insert("end", "\n".join(lines))
    widget.configure(state="disabled")


def _lamp(widget: tk.Label, var: tk.StringVar, text: str, on: bool, alarm: bool) -> None:
    var.set(("● " if on else "○ ") + text)
    widget.configure(fg=ALARM if alarm and on else AMBER if on else MUTED)


def _key_name(status: int) -> str:
    return {1: "OK", 2: "NOT_INIT", 3: "COMM_FAIL", 4: "AUTH_FAIL"}.get(status, f"KS_{status}")


def _verdict(snap: dict) -> tuple[str, str]:
    if not snap["running"]:
        return "Stopped", "The outstation is stopped. Start it before a master can connect."
    if snap["error"]:
        return "TCP down", snap["error"]
    if snap["clients"] and snap["link"]:
        word = "master" if snap["clients"] == 1 else "masters"
        return "Master online", f"{snap['clients']} TCP {word} on port {snap['port']}. The link is reset."
    if snap["clients"]:
        return "TCP connected", "A master socket is open, but the link is not reset yet."
    if snap["quiet"] is not None and snap["quiet"] > 15000:
        return "Idle", f"Listening on port {snap['port']}. Nothing has been received for {round(snap['quiet'] / 1000)} seconds."
    return "Waiting", f"Listening on port {snap['port']}, address {snap['outstation']}. No TCP master is connected."


def _sample(rows: list[dict], snap: dict) -> None:
    values = {(kind, index): value for kind, index, _name, value, _units, _held in snap["points"]}
    rows.append(values)
    if len(rows) > 120:
        del rows[:-120]


def _draw_trend(canvas: tk.Canvas, rows: list[dict]) -> None:
    canvas.delete("all")
    width = max(canvas.winfo_width(), 480)
    height = max(canvas.winfo_height(), 360)
    bands = [
        ("Voltage", [("ai", 0, "Bus", AMBER), ("ai", 10, "F1", "#7dcea0"), ("ai", 11, "F2", "#5dade2")], "kV"),
        ("Current", [("ai", 1, "F1", ALARM), ("ai", 2, "F2", "#f0b27a")], "A"),
        ("Frequency", [("ai", 5, "Hz", "#d7bde2")], "Hz"),
        ("Load", [("ai", 7, "F1", "#82e0aa"), ("ai", 8, "F2", "#85c1e9")], "kW"),
    ]
    gap = 10
    band_h = (height - gap * (len(bands) + 1)) / len(bands)
    left, right = 64, 16
    for index, (title, series, unit) in enumerate(bands):
        top = gap + index * (band_h + gap)
        bottom = top + band_h
        canvas.create_rectangle(8, top, width - 8, bottom, outline=LINE, fill=SURFACE)
        canvas.create_text(16, top + 14, text=title, fill=INK, anchor="w", font=("Segoe UI", 10))
        plot_top = top + 28
        plot_bottom = bottom - 18
        plot_left = left
        plot_right = width - right
        present = [row[key] for row in rows for key, _label, _color in series if key in row]
        if len(rows) < 2 or not present:
            canvas.create_text(plot_left, (plot_top + plot_bottom) / 2, text="Waiting for samples", fill=MUTED, anchor="w", font=("Segoe UI", 9))
            continue
        low = min(present)
        high = max(present)
        if high - low < 0.05:
            mid = (high + low) / 2
            low, high = mid - 0.5, mid + 0.5
        span = plot_right - plot_left
        count = len(rows)

        def y_of(value: float, lo: float = low, hi: float = high) -> float:
            return plot_bottom - ((value - lo) / (hi - lo)) * (plot_bottom - plot_top)

        canvas.create_text(plot_left - 8, plot_top, text=f"{high:,.2f}", fill=MUTED, anchor="e", font=("Consolas", 8))
        canvas.create_text(plot_left - 8, plot_bottom, text=f"{low:,.2f}", fill=MUTED, anchor="e", font=("Consolas", 8))
        legend_x = 120
        for key, label, color in series:
            latest = rows[-1].get(key)
            caption = label if latest is None else f"{label} {latest:,.2f} {unit}"
            canvas.create_text(legend_x, top + 14, text=caption, fill=color, anchor="w", font=("Consolas", 9))
            legend_x += 150
            coords = []
            for step, row in enumerate(rows):
                if key not in row:
                    continue
                x = plot_left + (step / max(1, count - 1)) * span
                coords.extend((x, y_of(row[key])))
            if len(coords) >= 4:
                canvas.create_line(*coords, fill=color, width=2, smooth=True)


def _shown(kind: str, index: int, value: float, units: str, held: bool) -> str:
    if kind == "bo":
        text = "Latched" if value >= 0.5 else "Dropped"
    elif kind == "bi":
        if index <= 3:
            text = "Closed" if value >= 0.5 else "Open"
        elif index == 10:
            text = "Remote" if value >= 0.5 else "Local"
        else:
            text = "Alarm" if value >= 0.5 else "Normal"
    else:
        if kind in ("ai", "ao"):
            number = f"{value:,.2f}"
        else:
            number = f"{round(value):,}"
        text = f"{number} {units}".strip()
    if held:
        text += "  held"
    return text


def _group(kind: str) -> int:
    return {"bi": 1, "bo": 10, "ctr": 20, "ai": 30, "ao": 40}.get(kind, 0)


def _selected(points: ttk.Treeview) -> tuple[str, int] | None:
    pick = points.selection()
    if not pick or "-" not in pick[0]:
        return None
    kind, index = pick[0].split("-", 1)
    return kind, int(index)


def _write(host, points: ttk.Treeview, entry: tk.Entry, error: tk.StringVar) -> None:
    chosen = _selected(points)
    if chosen is None:
        error.set("Select a point.")
        return
    message = host.write_manual(chosen[0], chosen[1], entry.get())
    error.set(message or "Held. Simulation will not change it.")


def _release(host, points: ttk.Treeview) -> None:
    chosen = _selected(points)
    if chosen:
        host.release_point(chosen[0], chosen[1])


def _toggle(host) -> None:
    if host.running:
        host.stop()
    else:
        host.start()


def _breaker(host, index: int, closed: int) -> None:
    with host.lock:
        point = find_point(host.station, "bo", index)
        if point:
            write_point(host.station, point, closed, point.flags, int(time.time() * 1000), "control")


def _shutdown(host) -> None:
    host.stop()
