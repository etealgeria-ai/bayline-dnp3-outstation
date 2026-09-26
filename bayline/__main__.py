"""TCP DNP3 outstation. From the python folder: python outstation.py"""

from __future__ import annotations

import argparse
import json
import os
import socket
import threading
import time

from bayline.codec import frame_size
from bayline.outstation import flush_unsolicited, handle_frame, housekeep, write_point
from bayline.sim import simulate, start_fault
from bayline.crypto import hex_to_bytes
from bayline.station import (
    MAC_ALGORITHMS,
    PROVISIONED_USER,
    ROLE_CODES,
    LogItem,
    SaUser,
    auth_profile,
    create_station,
    find_point,
    reset_session_keys,
    reset_user_session,
    update_key_material,
)

HOST = "0.0.0.0"
DEFAULT_PORT = 20000
DEFAULT_KEY_FILE = "bayline-update-key.hex"
DEFAULT_SA_FILE = "bayline-sav5.json"


def load_update_key(text: str = "", path: str = "") -> tuple[bytes, str]:
    target = path or os.environ.get("BAYLINE_UPDATE_KEY_FILE") or DEFAULT_KEY_FILE
    chosen = text or os.environ.get("BAYLINE_UPDATE_KEY", "")
    parsed = hex_to_bytes(chosen) if chosen else None
    if parsed and len(parsed) in (16, 32):
        try:
            with open(target, "w", encoding="ascii") as handle:
                handle.write(parsed.hex() + "\n")
        except OSError:
            pass
        return parsed, target
    try:
        stored = hex_to_bytes(open(target, encoding="ascii").read())
    except OSError:
        stored = None
    if stored and len(stored) in (16, 32):
        return stored, target
    key = os.urandom(32)
    try:
        with open(target, "w", encoding="ascii") as handle:
            handle.write(key.hex() + "\n")
    except OSError:
        target = ""
    return key, target


def _save_key(path: str, key: bytes) -> None:
    if not path:
        return
    try:
        with open(path, "w", encoding="ascii") as handle:
            handle.write(key.hex() + "\n")
    except OSError:
        pass


def _take(buf: bytearray) -> list[bytes]:
    frames: list[bytes] = []
    while len(buf) >= 3:
        if buf[0] != 0x05 or buf[1] != 0x64:
            try:
                at = buf.index(0x05)
            except ValueError:
                del buf[:-1]
                break
            if at == 0 or buf[1] != 0x64:
                del buf[0]
                continue
            del buf[:at]
            continue
        size = frame_size(buf[2])
        if size < 10:
            del buf[0]
            continue
        if len(buf) < size:
            break
        frames.append(bytes(buf[:size]))
        del buf[:size]
    return frames


def load_sa_config(station, path: str, authority: str = "") -> None:
    """Users 2 and up, the authority key, and the status change sequence live in a JSON file."""
    sav = station.sav5
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        data = {}
    for row in data.get("users", []):
        try:
            number, key = int(row["number"]), bytes.fromhex(row["key"])
        except (KeyError, TypeError, ValueError):
            continue
        if number == PROVISIONED_USER or len(key) not in (16, 32) or not 1 <= number <= 65534:
            continue
        sav.users[number] = SaUser(number, str(row.get("name", f"User {number}")), str(row.get("role", "Viewer")), key, int(row.get("expires", 0)))
    common = data.get("common", {})
    if common.get("role") in ROLE_CODES:
        sav.default().role = common["role"]
    if common.get("name"):
        sav.default().name = str(common["name"])
    if data.get("mal") in MAC_ALGORITHMS:
        sav.mal = data["mal"]
    sav.scs = int(data.get("scs", 0))
    chosen = authority or os.environ.get("BAYLINE_AUTHORITY_KEY", "") or data.get("authority_key", "")
    parsed = hex_to_bytes(chosen) if chosen else None
    sav.authority_key = parsed if parsed and len(parsed) in (16, 32) else b""


def save_sa_config(station, path: str) -> None:
    if not path:
        return
    sav = station.sav5
    data = {
        "authority_key": sav.authority_key.hex(),
        "scs": sav.scs,
        "mal": sav.mal,
        "common": {"name": sav.default().name, "role": sav.default().role},
        "users": [
            {"number": u.number, "name": u.name, "role": u.role, "key": u.update_key.hex(), "expires": u.expires}
            for u in sorted(sav.users.values(), key=lambda u: u.number)
            if u.number != PROVISIONED_USER
        ],
    }
    try:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
            handle.write("\n")
    except OSError:
        pass


class Host:
    """Outstation plus the TCP listener. Safe to start and stop from the window."""

    def __init__(self, port: int = DEFAULT_PORT, host: str = HOST, allow_ips: list[str] | None = None, update_key: str = "", key_file: str = "", sa_file: str = "", authority_key: str = "") -> None:
        self.port = port
        self.host = host or HOST
        self.station = create_station()
        key, path = load_update_key(update_key, key_file)
        self.station.sav5.update_key = key
        self.key_file = path
        self.sa_file = sa_file or os.environ.get("BAYLINE_SA_FILE") or (os.path.join(os.path.dirname(path), DEFAULT_SA_FILE) if path else "")
        if self.sa_file:
            load_sa_config(self.station, self.sa_file, authority_key)
        self.lock = threading.Lock()
        self.clients: list[socket.socket] = []
        self.running = False
        self.error = ""
        self._server: socket.socket | None = None
        self._ticking = False
        self._accept_thread: threading.Thread | None = None
        self.allow_ips: set[str] = set(allow_ips or [])
        self.trace = False
        self._traced = 0

    def start(self) -> None:
        if self.running:
            return
        self.error = ""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind((self.host, self.port))
            server.listen(8)
            server.settimeout(0.4)
        except OSError as exc:
            self.error = f"Port {self.port} is not available. {exc}"
            server.close()
            return
        self._server = server
        self.running = True
        self._note(f"Outstation started on {self.host}:{self.port}")
        where = self.key_file or "not saved"
        print(f"Update key file {where}", flush=True)
        print(f"Update key {self.station.sav5.update_key.hex()}", flush=True)
        sav = self.station.sav5
        if sav.authority_key:
            print(f"Authority key {sav.authority_key.hex()}", flush=True)
        for user in sorted(sav.users.values(), key=lambda u: u.number):
            if user.number != PROVISIONED_USER:
                print(f"SAv5 user {user.number} {user.name} ({user.role}) update key {user.update_key.hex()}", flush=True)
        if not self._ticking:
            self._ticking = True
            threading.Thread(target=self._tick, daemon=True).start()
        self._accept_thread = threading.Thread(target=self._accept, daemon=True)
        self._accept_thread.start()
        print(f"Bayline DNP3 outstation listening on {self.host}:{self.port}  address {self.station.outstation}  SAv5 user 1", flush=True)

    def stop(self) -> None:
        if not self.running and self._server is None:
            return
        self.running = False
        current = self._server
        self._server = None
        if current is not None:
            try:
                current.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            current.close()
        thread = self._accept_thread
        if thread is not None:
            thread.join(timeout=1)
        for sock in list(self.clients):
            try:
                sock.close()
            except OSError:
                pass
        self.clients.clear()
        self._note("Outstation stopped")

    def snapshot(self) -> dict:
        with self.lock:
            station = self.station
            sav = station.sav5
            pending = station.pending_confirm
            armed = station.select
            now = int(time.time() * 1000)
            frames = [item for item in station.log if item.direction in ("in", "out")]
            last = frames[-1].time if frames else None
            profile = auth_profile(sav)
            return {
                "name": station.name,
                "outstation": station.outstation,
                "master": station.master,
                "link": station.link_reset,
                "running": self.running,
                "port": self.port,
                "clients": len(self.clients),
                "error": self.error,
                "restart": station.restart,
                "need_time": station.need_time,
                "local": station.local,
                "sim_on": station.sim_on,
                "unsol": dict(station.unsol),
                "confirm": None if pending is None else {"seq": pending.seq, "left": max(0, int((pending.deadline - now) / 1000))},
                "select": None if armed is None else {"group": armed.group, "index": armed.index, "left": max(0, int((armed.deadline - now) / 1000))},
                "classes": {
                    1: sum(1 for event in station.events if event.clazz == 1),
                    2: sum(1 for event in station.events if event.clazz == 2),
                    3: sum(1 for event in station.events if event.clazz == 3),
                },
                "rx": sum(1 for item in station.log if item.direction == "in"),
                "tx": sum(1 for item in station.log if item.direction == "out"),
                "bad": sum(1 for item in station.log if not item.ok),
                "quiet": None if last is None else max(0, now - last),
                "sav": {
                    "enabled": sav.enabled,
                    "version": profile.version,
                    "label": profile.label,
                    "mac_name": profile.mac_name,
                    "wrap_name": profile.wrap_name,
                    "aggressive": sav.aggressive,
                    "user": sav.user,
                    "role": sav.role,
                    "status": sav.os.status,
                    "ksq": sav.os.ksq,
                    "csq": sav.csq,
                    "mal": sav.mal,
                    "authority": sav.authority_key.hex(),
                    "outstation_name": sav.outstation_name,
                    "users": [
                        (u.number, u.name, u.role, len(u.update_key), u.os.status, u.os.ksq, u.expires)
                        for u in sorted(sav.users.values(), key=lambda u: u.number)
                    ],
                    "pending_users": sorted(sav.status_changes),
                    "ok": sav.ok_count,
                    "fail": sav.fail_count,
                    "challenges_sent": sav.challenges_sent,
                    "challenges_rx": sav.challenges_rx,
                    "key_changes": sav.key_changes,
                    "last_user": sav.last_user,
                    "last_auth_time": sav.last_auth_time,
                    "challenge_timeout_ms": sav.challenge_timeout_ms,
                    "session_lifetime_s": sav.session_lifetime_s,
                    "policy": {
                        "controls": sav.policy.controls,
                        "crob": sav.policy.crob,
                        "analog": sav.policy.analog,
                        "direct_operate": sav.policy.direct_operate,
                        "direct_operate_nr": sav.policy.direct_operate_nr,
                        "select_operate": sav.policy.select_operate,
                        "cold_restart": sav.policy.cold_restart,
                        "warm_restart": sav.policy.warm_restart,
                        "unsolicited": sav.policy.unsolicited,
                        "assign_class": sav.policy.assign_class,
                        "initialize": sav.policy.initialize,
                        "time_write": sav.policy.time_write,
                        "file_transfer": sav.policy.file_transfer,
                    },
                    "result": sav.last_result,
                    "key": update_key_material(sav).hex(),
                },
                "points": [(p.kind, p.index, p.name, p.value, p.units, p.manual, p.clazz, p.labels) for p in station.points],
                "fault": dict(station.sim_state["fault"]) if station.sim_state.get("fault") else None,
                "log": [(item.id, item.time, item.direction, item.summary, item.hex, item.ok) for item in station.log[-80:]],
            }

    def write_manual(self, kind: str, index: int, text: str) -> str | None:
        try:
            value = float(text.strip())
        except ValueError:
            return "Enter a number."
        with self.lock:
            point = find_point(self.station, kind, index)
            if point is None:
                return "Select a point first."
            if point.kind in ("bi", "bo"):
                value = 1 if value >= 0.5 else 0
            if point.kind == "ao" and not 10.5 <= value <= 14.4:
                return "Regulator setpoint must be between 10.5 and 14.4 kV."
            write_point(self.station, point, value, point.flags, int(time.time() * 1000), "control")
            point.manual = point.kind != "ao"
            if point.kind == "ao" and point.index in (0, 1):
                measured = find_point(self.station, "ai", 10 + point.index)
                if measured:
                    measured.manual = False
        return None

    def release_point(self, kind: str, index: int) -> None:
        with self.lock:
            point = find_point(self.station, kind, index)
            if point:
                point.manual = False

    def fault(self, feeder: int, permanent: bool) -> str | None:
        with self.lock:
            message = start_fault(self.station, feeder, permanent, int(time.time() * 1000))
        if message is None:
            self._note(f"{'Permanent' if permanent else 'Transient'} fault on feeder {feeder}")
        return message

    def set_role(self, role: str) -> None:
        if role not in ROLE_CODES:
            return
        with self.lock:
            sav = self.station.sav5
            common = sav.default()
            common.role = role
            reset_user_session(common)
            sav.dirty = True
            sav.last_result = f"User {common.number} is now {role}. Its session keys were cleared."
        self._note(f"User {common.number} role {role}")

    def set_mal(self, code: int) -> None:
        if code not in MAC_ALGORITHMS:
            return
        with self.lock:
            sav = self.station.sav5
            sav.mal = code
            reset_session_keys(sav)
            sav.dirty = True
            sav.last_result = f"MAC algorithm {MAC_ALGORITHMS[code][0]}. Session keys were cleared."

    def add_user(self, number: int, name: str, role: str, key_text: str) -> str | None:
        key = hex_to_bytes(key_text) if key_text.strip() else os.urandom(32)
        if key is None or len(key) not in (16, 32):
            return "Update key must be 16 or 32 octets of hex, or blank to generate one."
        if not 2 <= number <= 65534:
            return "User numbers 2 to 65534 can be added here. User 1 is the default user."
        if role not in ROLE_CODES:
            return "Pick a role."
        name = name.strip() or f"User {number}"
        with self.lock:
            sav = self.station.sav5
            if any(u.name == name and u.number != number for u in sav.users.values()):
                return f'Another user is already named "{name}".'
            sav.users[number] = SaUser(number, name, role, key)
            sav.dirty = True
            sav.last_result = f'User {number} "{name}" ({role}) added. Load the same update key in the master.'
        self._note(f"User {number} added")
        return None

    def delete_user(self, number: int) -> str | None:
        if number == PROVISIONED_USER:
            return "User 1 is the default user and stays."
        with self.lock:
            sav = self.station.sav5
            if sav.users.pop(number, None) is None:
                return f"There is no user {number}."
            sav.dirty = True
            sav.last_result = f"User {number} deleted."
        self._note(f"User {number} deleted")
        return None

    def user_key(self, number: int) -> str:
        with self.lock:
            user = self.station.sav5.users.get(number)
            return user.update_key.hex() if user else ""

    def set_authority_key(self, text: str) -> str | None:
        key = hex_to_bytes(text) if text.strip() else b""
        if key is None or len(key) not in (0, 16, 32):
            return "Authority key must be 16 or 32 octets of hex, or blank to turn remote user management off."
        with self.lock:
            sav = self.station.sav5
            sav.authority_key = key
            sav.status_changes.clear()
            sav.update_pending = None
            sav.dirty = True
            sav.last_result = "Authority key set. Methods 3 and 4 are accepted." if key else "Authority key cleared. Remote user management is off."
        return None

    def generate_authority_key(self) -> str:
        key = os.urandom(32)
        self.set_authority_key(key.hex())
        return key.hex()

    def set_policy(self, name: str, value: bool) -> None:
        with self.lock:
            if hasattr(self.station.sav5.policy, name):
                if name != "time_write":
                    value = True
                setattr(self.station.sav5.policy, name, value)

    def set_auth_limits(self, challenge_ms: int, lifetime_s: int) -> None:
        with self.lock:
            sav = self.station.sav5
            sav.challenge_timeout_ms = max(500, min(60000, challenge_ms))
            sav.session_lifetime_s = max(30, min(86400, lifetime_s))

    def set_update_key(self, text: str) -> str | None:
        key = hex_to_bytes(text)
        if key is None or len(key) not in (16, 32):
            return "Update key must be 16 octets (AES-128) or 32 octets (AES-256) of hex."
        with self.lock:
            self.station.sav5.update_key = key
            reset_session_keys(self.station.sav5)
            self.station.sav5.last_result = "Update key imported. Session keys were cleared."
        _save_key(self.key_file, key)
        return None

    def generate_update_key(self) -> str:
        key = os.urandom(32)
        with self.lock:
            self.station.sav5.update_key = key
            reset_session_keys(self.station.sav5)
            self.station.sav5.last_result = "A new update key was generated. Load the same key in the master."
        _save_key(self.key_file, key)
        return key.hex()

    def set_auth_version(self, version: int) -> None:
        if version not in (2, 5):
            return
        with self.lock:
            sav = self.station.sav5
            sav.version = version
            sav.enabled = True
            reset_session_keys(sav)
            label = auth_profile(sav).label
            sav.last_result = f"{label} selected. Session keys were cleared. The master must wrap a new pair."
        self._note(f"{label} selected")

    def disable_auth(self) -> None:
        with self.lock:
            sav = self.station.sav5
            sav.enabled = False
            sav.pending = None
            sav.last_result = "Secure authentication is off. SAv2 and SAv5 are both disabled. Controls go out in the clear."
        self._note("Authentication disabled")

    def set_flag(self, name: str, value: bool) -> None:
        with self.lock:
            if name == "sav5":
                self.station.sav5.enabled = value
                if not value:
                    self.station.sav5.pending = None
            elif name == "aggressive":
                self.station.sav5.aggressive = value
            elif name == "local":
                self.station.local = value
            elif name == "sim":
                self.station.sim_on = value

    def set_address(self, which: str, value: int) -> None:
        if not 0 <= value <= 65534:
            return
        with self.lock:
            if which == "outstation":
                self.station.outstation = value
            else:
                self.station.master = value

    def _print_trace(self) -> None:
        if not self.trace:
            return
        for item in self.station.log:
            if item.id <= self._traced:
                continue
            self._traced = item.id
            mark = {"in": "RX", "out": "TX"}.get(item.direction, "--")
            print(f"{time.strftime('%H:%M:%S', time.localtime(item.time / 1000))}  {mark}  {item.summary}" + (f"  [{item.detail}]" if item.direction == "note" and item.detail else ""), flush=True)
            if item.direction in ("in", "out") and item.hex:
                print(f"          {item.hex}", flush=True)

    def _note(self, summary: str) -> None:
        with self.lock:
            station = self.station
            station.log.append(LogItem(station.next_log_id, int(time.time() * 1000), "note", summary, "", "", True))
            station.next_log_id += 1

    def _tick(self) -> None:
        last = time.time()
        while True:
            time.sleep(0.8)
            now_s = time.time()
            dt = now_s - last
            last = now_s
            with self.lock:
                if self.station.sav5.dirty:
                    self.station.sav5.dirty = False
                    save_sa_config(self.station, self.sa_file)
            if not self.running:
                continue
            now = int(now_s * 1000)
            with self.lock:
                simulate(self.station, now, dt)
                housekeep(self.station, now)
                frames = flush_unsolicited(self.station, now) if self.clients else []
                self._print_trace()
            for sock in list(self.clients):
                try:
                    if frames:
                        sock.sendall(b"".join(frames))
                except OSError:
                    pass

    def _accept(self) -> None:
        while self.running and self._server is not None:
            try:
                sock, addr = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            if self.allow_ips and addr[0] not in self.allow_ips:
                sock.close()
                self._note(f"Rejected {addr[0]} — not in the allow list")
                continue
            self.clients.append(sock)
            peer = f"{addr[0]}:{addr[1]}"
            self._note(f"Master connected {peer}")
            print(f"master connected {peer}", flush=True)
            threading.Thread(target=self._client, args=(sock, peer), daemon=True).start()

    def _client(self, sock: socket.socket, peer: str) -> None:
        buf = bytearray()
        try:
            while self.running:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf.extend(chunk)
                frames = _take(buf)
                out = bytearray()
                now = int(time.time() * 1000)
                with self.lock:
                    for frame in frames:
                        out.extend(b"".join(handle_frame(self.station, frame, now)))
                        out.extend(b"".join(flush_unsolicited(self.station, now)))
                    self._print_trace()
                if out:
                    sock.sendall(out)
        except OSError:
            pass
        finally:
            if sock in self.clients:
                self.clients.remove(sock)
            sock.close()
            self._note(f"Master disconnected {peer}")
            print(f"master disconnected {peer}", flush=True)


def serve(port: int = DEFAULT_PORT, host: str = HOST, allow_ips: list[str] | None = None, update_key: str = "", key_file: str = "", sa_file: str = "", authority_key: str = "", trace: bool = False, mac: int | None = None, auth: bool = True) -> None:
    listener = Host(port, host, allow_ips, update_key, key_file, sa_file, authority_key)
    listener.trace = trace
    listener.station.sav5.enabled = auth
    if mac:
        listener.station.sav5.mal = mac
    listener.start()
    if listener.error:
        raise SystemExit(listener.error)
    try:
        while listener.running:
            time.sleep(0.4)
    except KeyboardInterrupt:
        listener.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description="Bayline DNP3/TCP outstation")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--host", default=HOST, help="Bind address. Use 0.0.0.0 so a master on the LAN can connect.")
    parser.add_argument("--allow-ip", action="append", default=[], help="Accept this client IP. Repeat for more than one. Omit to accept any IP.")
    parser.add_argument("--update-key", default="", help="User 1 update key as hex: 16 octets for AES-128 key wrap, 32 for AES-256. Also read from BAYLINE_UPDATE_KEY.")
    parser.add_argument("--update-key-file", default="", help="File that stores the update key. Defaults to bayline-update-key.hex.")
    parser.add_argument("--sa-file", default="", help="JSON file with SAv5 users 2 and up, the authority key, and the MAC algorithm. Defaults to bayline-sav5.json.")
    parser.add_argument("--authority-key", default="", help="16- or 32-octet authority key as hex. Turns on remote user and update-key changes. Also read from BAYLINE_AUTHORITY_KEY.")
    parser.add_argument("--mac", type=int, choices=sorted(MAC_ALGORITHMS), help="SAv5 MAC algorithm: 1 SHA-1-4, 2 SHA-1-10, 3 SHA-256-8, 4 SHA-256-16 (default), 5 SHA-1-8")
    parser.add_argument("--no-auth", action="store_true", help="Start with SAv2 and SAv5 disabled")
    parser.add_argument("--headless", action="store_true", help="Listen without opening the window")
    parser.add_argument("--trace", action="store_true", help="With --headless, print every frame and protocol note")
    args = parser.parse_args()
    if args.headless:
        serve(args.port, args.host, args.allow_ip, args.update_key, args.update_key_file, args.sa_file, args.authority_key, args.trace, args.mac, not args.no_auth)
        return
    from bayline.gui import run_gui

    host = Host(args.port, args.host, args.allow_ip, args.update_key, args.update_key_file, args.sa_file, args.authority_key)
    if args.mac:
        host.station.sav5.mal = args.mac
    host.station.sav5.enabled = not args.no_auth
    run_gui(host)


if __name__ == "__main__":
    main()
