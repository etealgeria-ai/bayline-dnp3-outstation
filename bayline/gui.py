"""Desktop window matching the Bayline console: points, comms, master, wire, SAv5."""

from __future__ import annotations

import time
import tkinter as tk
from tkinter import ttk

from bayline.outstation import write_point
from bayline.station import KEY_AUTH_FAIL, KEY_OK, MAC_ALGORITHMS, ROLE_CODES, find_point

BG = "#121816"
SURFACE = "#1c2621"
INK = "#e7efe9"
MUTED = "#8ea197"
LINE = "#2c3a34"
AMBER = "#e2a53a"
ALARM = "#e15b4a"


def run_gui(host) -> None:
    root = tk.Tk()
    root.title("DNP3 Outstation Simulator - ETE.Algeria@gmail.com")
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

    points = ttk.Treeview(points_tab, columns=("kind", "addr", "idx", "clazz", "name", "value"), show="headings")
    for key, title, width in (("kind", "Type", 60), ("addr", "DNP3 address", 110), ("idx", "Index", 60), ("clazz", "Class", 60), ("name", "Point", 260), ("value", "Value", 160)):
        points.heading(key, text=title)
        points.column(key, width=width, anchor="w")
    points.pack(fill="both", expand=True, padx=8, pady=8)
    point_actions = tk.Frame(points_tab, bg=BG)
    point_actions.pack(fill="x", padx=8, pady=(0, 8))
    for index, title in ((0, "52-T1"), (1, "52-F1"), (2, "52-F2")):
        tk.Button(point_actions, text=f"Trip {title}", command=lambda i=index: _breaker(host, i, 0), bg=SURFACE, fg=INK, relief="flat", padx=10, pady=6).pack(side="left", padx=(0, 6))
        tk.Button(point_actions, text=f"Close {title}", command=lambda i=index: _breaker(host, i, 1), bg=SURFACE, fg=INK, relief="flat", padx=10, pady=6).pack(side="left", padx=(0, 12))
    faults = tk.Frame(points_tab, bg=BG)
    faults.pack(fill="x", padx=8, pady=(0, 8))
    fault_note = tk.StringVar()
    for feeder in (1, 2):
        tk.Button(faults, text=f"Transient fault F{feeder}", command=lambda f=feeder: fault_note.set(host.fault(f, False) or f"Feeder {f}: trip and reclose."), bg=SURFACE, fg=INK, relief="flat", padx=10, pady=6).pack(side="left", padx=(0, 6))
        tk.Button(faults, text=f"Permanent fault F{feeder}", command=lambda f=feeder: fault_note.set(host.fault(f, True) or f"Feeder {f}: three trips, then 79 lockout."), bg=SURFACE, fg=INK, relief="flat", padx=10, pady=6).pack(side="left", padx=(0, 12))
    tk.Label(faults, textvariable=fault_note, bg=BG, fg=AMBER, font=("Segoe UI", 10)).pack(side="left", padx=8)
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
    security_state = _build_security(security_tab, host)
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

    log_key: list[tuple] = [()]

    def refresh() -> None:
        snap = host.snapshot()
        sav = snap["sav"]
        subtitle.set(f"{snap['name']} · address {snap['outstation']} · master {snap['master']} · port {snap['port']}")
        power.configure(text="Stop outstation" if snap["running"] else "Start outstation", bg=ALARM if snap["running"] else AMBER, fg="#1a100e")
        _lamp(lamp_widgets["TCP"], lamp_vars["TCP"], f"TCP {snap['clients']}" if snap["clients"] else f"TCP {snap['port']}", snap["running"] and not snap["error"], bool(snap["error"]))
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
            f"Key wrap         {sav['wrap_name']} (user 1)",
            f"Key status       {_key_name(sav['status'])} (user 1)",
            f"Users            {len(sav['users'])}",
            f"KSQ              {sav['ksq']} (user 1)",
            f"CSQ              {sav['csq']}",
            f"Accepted         {sav['ok']}",
            f"Failed           {sav['fail']}",
            f"Aggressive       {'On' if sav['aggressive'] else 'Off'}",
            "",
            sav["result"],
        ])
        _paint_security(security_state, snap)
        _sample(samples, snap)
        _draw_trend(trend, samples)
        selected = points.selection()
        points.delete(*points.get_children())
        for kind, index, name, value, units, held, clazz, labels in snap["points"]:
            shown_value = _shown(kind, value, units, held, labels)
            address = f"{_group(kind)}:{index}"
            points.insert("", "end", iid=f"{kind}-{index}", values=(kind.upper(), address, index, clazz, name, shown_value))
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
    values = {(point[0], point[1]): point[3] for point in snap["points"]}
    rows.append(values)
    if len(rows) > 120:
        del rows[:-120]


def _draw_trend(canvas: tk.Canvas, rows: list[dict]) -> None:
    canvas.delete("all")
    width = max(canvas.winfo_width(), 480)
    height = max(canvas.winfo_height(), 360)
    bands = [
        ("Voltage", [(("ai", 0), "Bus", AMBER), (("ai", 10), "F1", "#7dcea0"), (("ai", 11), "F2", "#5dade2")], "kV"),
        ("Current", [(("ai", 1), "F1", ALARM), (("ai", 2), "F2", "#f0b27a")], "A"),
        ("Frequency", [(("ai", 5), "Hz", "#d7bde2")], "Hz"),
        ("Load", [(("ai", 7), "F1", "#82e0aa"), (("ai", 8), "F2", "#85c1e9")], "kW"),
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


def _build_security(parent: tk.Frame, host) -> dict:
    outer = tk.Frame(parent, bg=BG)
    outer.pack(fill="both", expand=True)
    canvas = tk.Canvas(outer, bg=BG, highlightthickness=0)
    scroll = ttk.Scrollbar(outer, command=canvas.yview)
    canvas.configure(yscrollcommand=scroll.set)
    scroll.pack(side="right", fill="y")
    canvas.pack(side="left", fill="both", expand=True)
    form = tk.Frame(canvas, bg=BG)
    window = canvas.create_window((0, 0), window=form, anchor="nw")
    form.bind("<Configure>", lambda _event: canvas.configure(scrollregion=canvas.bbox("all")))
    canvas.bind("<Configure>", lambda event: canvas.itemconfigure(window, width=event.width))

    enabled = tk.BooleanVar(value=True)
    aggressive = tk.BooleanVar(value=False)
    version = tk.StringVar(value="SAv5")
    role = tk.StringVar(value="Operator")
    mac = tk.StringVar(value="HMAC-SHA-256-16")
    wrap = tk.StringVar(value="AES-256")
    key = tk.StringVar()
    show_key = tk.BooleanVar(value=False)
    challenge_ms = tk.StringVar(value="5000")
    lifetime = tk.StringVar(value="3600")
    notice = tk.StringVar()
    gate = {"ready": False}
    stats = {name: tk.StringVar(value="—") for name in ("session", "key_status", "ksq", "csq", "sent", "rx", "ok", "fail", "changes", "error", "last_user", "last_time")}
    policy_vars = {}

    def section(title: str) -> tk.Frame:
        tk.Label(form, text=title, bg=BG, fg=AMBER, anchor="w", font=("Segoe UI", 11, "bold")).pack(fill="x", padx=16, pady=(14, 4))
        body = tk.Frame(form, bg=BG)
        body.pack(fill="x", padx=16)
        return body

    def row(body: tk.Frame, label: str, widget: tk.Widget) -> None:
        line = tk.Frame(body, bg=BG)
        line.pack(fill="x", pady=3)
        tk.Label(line, text=label, bg=BG, fg=MUTED, width=28, anchor="w", font=("Segoe UI", 10)).pack(side="left")
        widget.pack(in_=line, side="left", fill="x", expand=True)
        widget.lift(line)

    def check(body: tk.Frame, label: str, variable: tk.BooleanVar, command) -> tk.Checkbutton:
        box = tk.Checkbutton(body, text=label, variable=variable, command=command, bg=BG, fg=INK, selectcolor=SURFACE, activebackground=BG, activeforeground=INK, anchor="w")
        box.pack(fill="x", pady=1)
        return box

    auth = section("1  Secure authentication")
    check(auth, "Enable secure authentication", enabled, lambda: host.set_flag("sav5", enabled.get()))
    row(auth, "SA version", ttk.Combobox(auth, textvariable=version, values=("SAv2", "SAv5"), state="readonly", width=28))

    def on_version(*_args) -> None:
        if not gate["ready"]:
            return
        host.set_auth_version(2 if version.get() == "SAv2" else 5)

    version.trace_add("write", on_version)
    row(auth, "User 1 role", ttk.Combobox(auth, textvariable=role, values=tuple(ROLE_CODES), state="readonly", width=28))

    def on_role(*_args) -> None:
        if gate["ready"] and role.get():
            host.set_role(role.get())

    role.trace_add("write", on_role)
    check(auth, "Aggressive mode (g120v3 + g120v9)", aggressive, lambda: host.set_flag("aggressive", aggressive.get()))

    crypto = section("2  Cryptography")
    mac_names = {name: code for code, (name, _len, _sha1) in MAC_ALGORITHMS.items()}
    mac_box = ttk.Combobox(crypto, textvariable=mac, values=tuple(mac_names), state="readonly", width=28)
    row(crypto, "MAC algorithm", mac_box)
    row(crypto, "User 1 key wrap", tk.Label(crypto, textvariable=wrap, bg=BG, fg=INK, anchor="w", font=("Consolas", 10)))
    tk.Label(crypto, text="SAv5 offers every MAC in the list. The key wrap follows each user's update key: 16 octets is AES-128, 32 is AES-256. SAv2 is always HMAC-SHA-1-8 with AES-128.", bg=BG, fg=MUTED, anchor="w", justify="left", wraplength=820, font=("Segoe UI", 9)).pack(fill="x", pady=(4, 2))

    def on_mac(*_args) -> None:
        if not gate["ready"]:
            return
        if version.get() == "SAv2":
            notice.set("SAv2 always uses HMAC-SHA-1-8. Switch to SAv5 to choose a MAC.")
            return
        code = mac_names.get(mac.get())
        if code:
            host.set_mal(code)
            notice.set(f"MAC algorithm {mac.get()} (code {code}). Session keys were cleared.")

    mac.trace_add("write", on_mac)
    key_entry = ttk.Entry(crypto, textvariable=key, show="*")
    row(crypto, "User 1 update key", key_entry)
    buttons = tk.Frame(crypto, bg=BG)
    buttons.pack(fill="x", pady=4)

    def import_key() -> None:
        notice.set(host.set_update_key(key.get()) or "Update key imported.")

    def generate_key() -> None:
        key.set(host.generate_update_key())
        notice.set("New update key generated. Copy it into the master.")

    def toggle_key() -> None:
        key_entry.configure(show="" if show_key.get() else "*")

    tk.Button(buttons, text="Generate key", command=generate_key, bg=SURFACE, fg=INK, relief="flat", padx=8, pady=4).pack(side="left", padx=(0, 6))
    tk.Button(buttons, text="Import key", command=import_key, bg=SURFACE, fg=INK, relief="flat", padx=8, pady=4).pack(side="left", padx=(0, 6))
    tk.Checkbutton(buttons, text="Show key", variable=show_key, command=toggle_key, bg=BG, fg=INK, selectcolor=SURFACE, activebackground=BG, activeforeground=INK).pack(side="left")

    people = section("3  Users")
    users = ttk.Treeview(people, columns=("number", "name", "role", "wrap", "status", "ksq", "expires"), show="headings", height=5)
    for column, title, width in (("number", "User", 60), ("name", "Name", 140), ("role", "Role", 110), ("wrap", "Key wrap", 90), ("status", "Session", 100), ("ksq", "KSQ", 60), ("expires", "Role expires", 150)):
        users.heading(column, text=title)
        users.column(column, width=width, anchor="w")
    users.pack(fill="x", pady=(0, 6))
    add_number = tk.StringVar(value="2")
    add_name = tk.StringVar()
    add_role = tk.StringVar(value="Operator")
    add_key = tk.StringVar()
    row(people, "User number", ttk.Entry(people, textvariable=add_number, width=30))
    row(people, "Name", ttk.Entry(people, textvariable=add_name, width=30))
    row(people, "Role", ttk.Combobox(people, textvariable=add_role, values=tuple(ROLE_CODES), state="readonly", width=28))
    row(people, "Update key (blank = generate)", ttk.Entry(people, textvariable=add_key, width=30))
    user_buttons = tk.Frame(people, bg=BG)
    user_buttons.pack(fill="x", pady=4)

    def picked_user() -> int | None:
        pick = users.selection()
        return int(pick[0]) if pick else None

    def add_user() -> None:
        try:
            number = int(add_number.get())
        except ValueError:
            notice.set("User number must be a number.")
            return
        message = host.add_user(number, add_name.get(), add_role.get(), add_key.get())
        notice.set(message or f"User {number} added. Its update key is {host.user_key(number)}")

    def delete_user() -> None:
        number = picked_user()
        notice.set("Select a user in the table." if number is None else host.delete_user(number) or f"User {number} deleted.")

    def show_user_key() -> None:
        number = picked_user()
        notice.set("Select a user in the table." if number is None else f"User {number} update key {host.user_key(number)}")

    tk.Button(user_buttons, text="Add or replace user", command=add_user, bg=SURFACE, fg=INK, relief="flat", padx=8, pady=4).pack(side="left", padx=(0, 6))
    tk.Button(user_buttons, text="Delete selected", command=delete_user, bg=SURFACE, fg=INK, relief="flat", padx=8, pady=4).pack(side="left", padx=(0, 6))
    tk.Button(user_buttons, text="Show selected key", command=show_user_key, bg=SURFACE, fg=INK, relief="flat", padx=8, pady=4).pack(side="left")

    authority = section("4  Authority (remote user and update-key change)")
    authority_key = tk.StringVar()
    authority_entry = ttk.Entry(authority, textvariable=authority_key, show="*")
    row(authority, "Authority key", authority_entry)
    pending_users = tk.StringVar(value="None")
    row(authority, "Pending status changes", tk.Label(authority, textvariable=pending_users, bg=BG, fg=INK, anchor="w", font=("Consolas", 10)))
    tk.Label(authority, text="With an authority key the master can add, change, and delete users (g120v10) and send new update keys with symmetric methods 3 (AES-128 / SHA-1) and 4 (AES-256 / SHA-256).", bg=BG, fg=MUTED, anchor="w", justify="left", wraplength=820, font=("Segoe UI", 9)).pack(fill="x", pady=(4, 2))
    authority_buttons = tk.Frame(authority, bg=BG)
    authority_buttons.pack(fill="x", pady=4)
    show_authority = tk.BooleanVar(value=False)
    tk.Button(authority_buttons, text="Generate", command=lambda: (authority_key.set(host.generate_authority_key()), notice.set("New authority key. Load the same key in the authority.")), bg=SURFACE, fg=INK, relief="flat", padx=8, pady=4).pack(side="left", padx=(0, 6))
    tk.Button(authority_buttons, text="Set", command=lambda: notice.set(host.set_authority_key(authority_key.get()) or "Authority key set."), bg=SURFACE, fg=INK, relief="flat", padx=8, pady=4).pack(side="left", padx=(0, 6))
    tk.Button(authority_buttons, text="Clear", command=lambda: (authority_key.set(""), notice.set(host.set_authority_key("") or "Remote user management is off.")), bg=SURFACE, fg=INK, relief="flat", padx=8, pady=4).pack(side="left", padx=(0, 6))
    tk.Checkbutton(authority_buttons, text="Show key", variable=show_authority, command=lambda: authority_entry.configure(show="" if show_authority.get() else "*"), bg=BG, fg=INK, selectcolor=SURFACE, activebackground=BG, activeforeground=INK).pack(side="left")

    session = section("5  Session")
    for label, name in (("Session status", "session"), ("Session key status", "key_status"), ("Key change sequence", "ksq"), ("Challenge sequence", "csq"), ("Session key lifetime", "lifetime_label"), ("Challenge timeout", "timeout_label")):
        if name in ("lifetime_label", "timeout_label"):
            continue
        line = tk.Frame(session, bg=BG)
        line.pack(fill="x", pady=2)
        tk.Label(line, text=label, bg=BG, fg=MUTED, width=28, anchor="w").pack(side="left")
        tk.Label(line, textvariable=stats[name], bg=BG, fg=INK, anchor="w", font=("Consolas", 10)).pack(side="left")
    row(session, "Session key lifetime (s)", ttk.Entry(session, textvariable=lifetime, width=30))
    row(session, "Challenge timeout (ms)", ttk.Entry(session, textvariable=challenge_ms, width=30))

    def apply_limits(*_args) -> None:
        if not gate["ready"]:
            return
        try:
            host.set_auth_limits(int(challenge_ms.get()), int(lifetime.get()))
        except ValueError:
            notice.set("Lifetime and challenge timeout must be numbers.")

    lifetime.trace_add("write", apply_limits)
    challenge_ms.trace_add("write", apply_limits)

    policy = section("6  Authentication policy")
    boxes = (
        ("controls", "Authenticate controls"),
        ("crob", "Binary output / CROB"),
        ("analog", "Analog output"),
        ("direct_operate", "Direct operate"),
        ("direct_operate_nr", "Direct operate no ack"),
        ("select_operate", "Select before operate"),
        ("cold_restart", "Cold restart"),
        ("warm_restart", "Warm restart"),
        ("unsolicited", "Enable / disable unsolicited"),
        ("assign_class", "Assign class"),
        ("initialize", "Initialize data and application"),
        ("time_write", "Time write"),
        ("file_transfer", "File transfer"),
    )
    for name, label in boxes:
        variable = tk.BooleanVar(value=name != "time_write")
        policy_vars[name] = variable
        box = check(policy, label, variable, lambda n=name, v=variable: host.set_policy(n, v.get()))
        if name != "time_write":
            box.configure(state="disabled")

    diag = section("7  Diagnostics")
    for label, name in (
        ("Challenges sent", "sent"),
        ("Challenges received", "rx"),
        ("Authentication accepted", "ok"),
        ("Authentication rejected", "fail"),
        ("Key changes", "changes"),
        ("Last error", "error"),
        ("Last authenticated user", "last_user"),
        ("Last authentication time", "last_time"),
    ):
        line = tk.Frame(diag, bg=BG)
        line.pack(fill="x", pady=2)
        tk.Label(line, text=label, bg=BG, fg=MUTED, width=28, anchor="w").pack(side="left")
        tk.Label(line, textvariable=stats[name], bg=BG, fg=INK, anchor="w", font=("Consolas", 10)).pack(side="left")
    tk.Label(form, textvariable=notice, bg=BG, fg=AMBER, anchor="w", justify="left", wraplength=860, font=("Segoe UI", 10)).pack(fill="x", padx=16, pady=8)
    actions = tk.Frame(form, bg=BG)
    actions.pack(fill="x", padx=16, pady=(0, 16))
    tk.Button(actions, text="Remote / local", command=lambda: host.set_flag("local", not host.snapshot()["local"]), bg=SURFACE, fg=INK, relief="flat", padx=8, pady=4).pack(side="left", padx=(0, 6))
    tk.Button(actions, text="Yard run / hold", command=lambda: host.set_flag("sim", not host.snapshot()["sim_on"]), bg=SURFACE, fg=INK, relief="flat", padx=8, pady=4).pack(side="left")
    return {"enabled": enabled, "aggressive": aggressive, "version": version, "role": role, "mac": mac, "wrap": wrap, "key": key, "lifetime": lifetime, "challenge_ms": challenge_ms, "notice": notice, "stats": stats, "policy": policy_vars, "gate": gate, "users": users, "user_rows": [()], "authority": authority_key, "pending_users": pending_users}


def _paint_security(state: dict, snap: dict) -> None:
    sav = snap["sav"]
    if not state["gate"]["ready"]:
        state["enabled"].set(sav["enabled"])
        state["aggressive"].set(sav["aggressive"])
        state["version"].set(sav["label"] if sav["version"] in (2, 5) else "SAv5")
        state["role"].set(sav["role"])
        state["mac"].set(sav["mac_name"])
        state["key"].set(sav["key"])
        state["authority"].set(sav["authority"])
        state["lifetime"].set(str(sav["session_lifetime_s"]))
        state["challenge_ms"].set(str(sav["challenge_timeout_ms"]))
        for name, variable in state["policy"].items():
            variable.set(sav["policy"][name])
        state["notice"].set(sav["result"])
        state["gate"]["ready"] = True
    state["wrap"].set(sav["wrap_name"])
    state["pending_users"].set(", ".join(sav["pending_users"]) or "None")
    rows = tuple(sav["users"])
    if rows != state["user_rows"][0]:
        state["user_rows"][0] = rows
        table = state["users"]
        picked = table.selection()
        table.delete(*table.get_children())
        for number, name, role_name, key_len, key_status, ksq, expires in rows:
            until = time.strftime("%Y-%m-%d %H:%M", time.localtime(expires / 1000)) if expires else "Never"
            table.insert("", "end", iid=str(number), values=(number, name, role_name, "AES-128" if key_len == 16 else "AES-256", _key_name(key_status), ksq, until))
        table.selection_set([item for item in picked if table.exists(item)])
    status = "OFF" if not sav["enabled"] else "OK" if sav["status"] == KEY_OK else "AUTH_FAIL" if sav["status"] == KEY_AUTH_FAIL else "INVALID"
    key_status = "OFF" if not sav["enabled"] else _key_name(sav["status"]) if sav["status"] == KEY_OK else "INVALID" if sav["status"] != KEY_AUTH_FAIL else "AUTH_FAIL"
    state["stats"]["session"].set(status)
    state["stats"]["key_status"].set(key_status)
    state["stats"]["ksq"].set(str(sav["ksq"]))
    state["stats"]["csq"].set(str(sav["csq"]))
    state["stats"]["sent"].set(str(sav["challenges_sent"]))
    state["stats"]["rx"].set(str(sav["challenges_rx"]))
    state["stats"]["ok"].set(str(sav["ok"]))
    state["stats"]["fail"].set(str(sav["fail"]))
    state["stats"]["changes"].set(str(sav["key_changes"]))
    state["stats"]["error"].set(sav["result"])
    state["stats"]["last_user"].set(str(sav["last_user"] or "—"))
    when = sav["last_auth_time"]
    state["stats"]["last_time"].set(time.strftime("%H:%M:%S", time.localtime(when / 1000)) if when else "—")


def _shown(kind: str, value: float, units: str, held: bool, labels: tuple[str, str] | None) -> str:
    if kind == "bo":
        text = "Latched" if value >= 0.5 else "Dropped"
    elif kind == "bi":
        off, on = labels or ("Normal", "Alarm")
        text = on if value >= 0.5 else off
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
