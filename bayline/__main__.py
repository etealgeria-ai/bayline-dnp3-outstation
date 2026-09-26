"""TCP DNP3 outstation. From the python folder: python -m bayline"""

from __future__ import annotations

import argparse
import socket
import threading
import time

from bayline.codec import frame_size
from bayline.outstation import flush_unsolicited, handle_frame, housekeep
from bayline.sim import simulate
from bayline.station import create_station

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


def serve(port: int = DEFAULT_PORT) -> None:
    station = create_station()
    lock = threading.Lock()
    clients: list[socket.socket] = []

    def tick() -> None:
        last = time.time()
        while True:
            time.sleep(0.8)
            now_s = time.time()
            dt = now_s - last
            last = now_s
            now = int(now_s * 1000)
            with lock:
                simulate(station, now, dt)
                housekeep(station, now)
                frames = flush_unsolicited(station, now) if clients else []
            for sock in list(clients):
                try:
                    if frames:
                        sock.sendall(b"".join(frames))
                except OSError:
                    pass

    threading.Thread(target=tick, daemon=True).start()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, port))
    server.listen(8)
    print(f"Bayline DNP3 outstation listening on {HOST}:{port}  address {station.outstation}  SAv5 user 1", flush=True)
    while True:
        sock, addr = server.accept()
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        clients.append(sock)
        print(f"master connected {addr[0]}:{addr[1]}", flush=True)
        threading.Thread(target=_client, args=(sock, addr, station, lock, clients), daemon=True).start()


def _client(sock: socket.socket, addr, station, lock, clients) -> None:
    buf = bytearray()
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf.extend(chunk)
            frames = _take(buf)
            out = bytearray()
            now = int(time.time() * 1000)
            with lock:
                for frame in frames:
                    out.extend(b"".join(handle_frame(station, frame, now)))
                    out.extend(b"".join(flush_unsolicited(station, now)))
            if out:
                sock.sendall(out)
    except OSError:
        pass
    finally:
        if sock in clients:
            clients.remove(sock)
        sock.close()
        print(f"master disconnected {addr[0]}:{addr[1]}", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Bayline DNP3/TCP outstation")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()
    serve(args.port)


if __name__ == "__main__":
    main()
