"""TCP DNP3 outstation. From the python folder: python outstation.py"""

from __future__ import annotations

import argparse
import socket
import threading
import time

from bayline.codec import frame_size
from bayline.outstation import flush_unsolicited, handle_frame, housekeep, write_point
from bayline.sim import simulate
from bayline.station import LogItem, create_station, find_point

HOST = "0.0.0.0"
DEFAULT_PORT = 20000


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

    def __init__(self, port: int = DEFAULT_PORT) -> None:
        self.port = port
        self.station = create_station()
        self.lock = threading.Lock()
        self.clients: list[socket.socket] = []
        self.running = False
        self.error = ""
        self._server: socket.socket | None = None
        self._ticking = False
        self._accept_thread: threading.Thread | None = None

    def start(self) -> None:
        if self.running:
            return
        self.error = ""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind((HOST, self.port))
            server.listen(8)
            server.settimeout(0.4)
        except OSError as exc:
            self.error = f"Port {self.port} is not available. {exc}"
            server.close()
            return
        self._server = server
        self.running = True
        self._note(f"Outstation started on port {self.port}")
        if not self._ticking:
            self._ticking = True
            threading.Thread(target=self._tick, daemon=True).start()
        self._accept_thread = threading.Thread(target=self._accept, daemon=True)
        self._accept_thread.start()
        print(f"Bayline DNP3 outstation listening on {HOST}:{self.port}  address {self.station.outstation}  SAv5 user 1", flush=True)

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
                    "aggressive": sav.aggressive,
                    "user": sav.user,
                    "status": sav.os.status,
                    "ksq": sav.os.ksq,
                    "csq": sav.os.csq,
                    "ok": sav.ok_count,
                    "fail": sav.fail_count,
                    "result": sav.last_result,
                    "key": sav.update_key.hex(),
                },
                "points": [(p.kind, p.index, p.name, p.value, p.units, p.manual) for p in station.points],
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
            write_point(self.station, point, value, point.flags, int(time.time() * 1000), "control")
            point.manual = True
        return None

    def release_point(self, kind: str, index: int) -> None:
        with self.lock:
            point = find_point(self.station, kind, index)
            if point:
                point.manual = False

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


def serve(port: int = DEFAULT_PORT) -> None:
    host = Host(port)
    host.start()
    if host.error:
        raise SystemExit(host.error)
    try:
        while host.running:
            time.sleep(0.4)
    except KeyboardInterrupt:
        host.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description="Bayline DNP3/TCP outstation")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--headless", action="store_true", help="Listen without opening the window")
    args = parser.parse_args()
    if args.headless:
        serve(args.port)
        return
    from bayline.gui import run_gui

    run_gui(Host(args.port))


if __name__ == "__main__":
    main()
