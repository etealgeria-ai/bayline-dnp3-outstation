"""TCP DNP3 outstation. From the python folder: python outstation.py"""

from __future__ import annotations

import argparse
import os
import socket
import threading
import time

from bayline.codec import frame_size
from bayline.outstation import flush_unsolicited, handle_frame, housekeep, write_point
from bayline.sim import simulate
from bayline.crypto import hex_to_bytes
from bayline.station import ROLES, LogItem, auth_profile, create_rtu_station, create_station, find_point, reset_session_keys, update_key_material

HOST = "0.0.0.0"
DEFAULT_PORT = 20000
DEFAULT_KEY_FILE = "bayline-update-key.hex"


def load_update_key(text: str = "", path: str = "") -> tuple[bytes, str]:
    target = path or os.environ.get("BAYLINE_UPDATE_KEY_FILE") or DEFAULT_KEY_FILE
    chosen = text or os.environ.get("BAYLINE_UPDATE_KEY", "")
    parsed = hex_to_bytes(chosen, 32) if chosen else None
    if parsed:
        try:
            with open(target, "w", encoding="ascii") as handle:
                handle.write(parsed.hex() + "\n")
        except OSError:
            pass
        return parsed, target
    try:
        stored = hex_to_bytes(open(target, encoding="ascii").read(), 32)
    except OSError:
        stored = None
    if stored:
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


class Host:
    """Outstation plus the TCP listener. Safe to start and stop from the window."""

    def __init__(self, port: int = DEFAULT_PORT, host: str = HOST, allow_ips: list[str] | None = None, update_key: str = "", key_file: str = "", station=None) -> None:
        self.port = port
        self.host = host or HOST
        self.station = station or create_station()
        key, path = load_update_key(update_key, key_file)
        self.station.sav5.update_key = key
        self.key_file = path
        self.lock = threading.Lock()
        self.clients: list[socket.socket] = []
        self.running = False
        self.error = ""
        self._server: socket.socket | None = None
        self._ticking = False
        self._accept_thread: threading.Thread | None = None
        self.allow_ips: set[str] = set(allow_ips or [])

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
        if not self._ticking:
            self._ticking = True
            threading.Thread(target=self._tick, daemon=True).start()
        self._accept_thread = threading.Thread(target=self._accept, daemon=True)
        self._accept_thread.start()
        print(f"{self.station.name} listening on {self.host}:{self.port}  address {self.station.outstation}  SAv5 user 1", flush=True)

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
                "model": station.model,
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
                    "csq": sav.os.csq,
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
                "points": [(p.kind, p.index, p.name, p.value, p.units, p.manual, p.clazz) for p in station.points],
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

    def set_role(self, role: str) -> None:
        spec = ROLES.get(role)
        if spec is None:
            return
        with self.lock:
            sav = self.station.sav5
            sav.role = role
            sav.user = spec[0]
            reset_session_keys(sav)
            sav.last_result = f"Role {role}, user {sav.user}. Session keys were cleared. The master must authenticate as this user."
        self._note(f"Role {role}")

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
        key = hex_to_bytes(text, 32)
        if key is None:
            return "Update key must be 32 octets of hex."
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
            if not self.running:
                continue
            now = int(now_s * 1000)
            with self.lock:
                simulate(self.station, now, dt)
                housekeep(self.station, now)
                frames = flush_unsolicited(self.station, now) if self.clients else []
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


def open_hosts(port: int = DEFAULT_PORT, host: str = HOST, allow_ips: list[str] | None = None, update_key: str = "", key_file: str = "", rtu_port: int = 0, rtu_address: int = 5) -> list[Host]:
    yard = Host(port, host, allow_ips, update_key, key_file or DEFAULT_KEY_FILE, create_station())
    rtu = create_rtu_station()
    rtu.outstation = rtu_address
    second = Host(rtu_port or port + 1, host, allow_ips, update_key, "bayline-rtu-update-key.hex", rtu)
    return [yard, second]


def serve(port: int = DEFAULT_PORT, host: str = HOST, allow_ips: list[str] | None = None, update_key: str = "", key_file: str = "") -> None:
    listener = Host(port, host, allow_ips, update_key, key_file)
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
    parser.add_argument("--rtu-port", type=int, default=0, help="Second outstation port. Defaults to the first port plus 1.")
    parser.add_argument("--rtu-address", type=int, default=5, help="DNP3 address of the second outstation.")
    parser.add_argument("--host", default=HOST, help="Bind address. Use 0.0.0.0 so a master on the LAN can connect.")
    parser.add_argument("--allow-ip", action="append", default=[], help="Accept this client IP. Repeat for more than one. Omit to accept any IP.")
    parser.add_argument("--update-key", default="", help="32-octet update key as hex. Also read from BAYLINE_UPDATE_KEY.")
    parser.add_argument("--update-key-file", default="", help="File that stores the update key. Defaults to bayline-update-key.hex.")
    parser.add_argument("--headless", action="store_true", help="Listen without opening the window")
    args = parser.parse_args()
    hosts = open_hosts(args.port, args.host, args.allow_ip, args.update_key, args.update_key_file, args.rtu_port, args.rtu_address)
    if args.headless:
        for item in hosts:
            item.start()
            if item.error:
                raise SystemExit(item.error)
        try:
            while any(item.running for item in hosts):
                time.sleep(0.4)
        except KeyboardInterrupt:
            for item in hosts:
                item.stop()
        return
    from bayline.gui import run_gui

    run_gui(hosts)


if __name__ == "__main__":
    main()
