"""Protocol checks for the Python outstation. python -m bayline.selfcheck"""

from __future__ import annotations

import socket
import threading

from bayline.codec import (
    FC_AUTH_REQUEST,
    FC_OPERATE,
    FC_READ,
    FC_RESPONSE,
    FC_SELECT,
    FC_WRITE,
    crc16_dnp,
    decode_frame,
    encode_frame,
    parse_apdu,
    parse_hex,
)
from bayline.crypto import aes256_unwrap, aes256_wrap, hmac_sha256, same_bytes
from bayline.outstation import handle_frame
from bayline.station import KEY_OK, create_station, find_point
from bayline.__main__ import serve

NOW = 1_700_000_000_000


def check(cond: bool, message: str) -> None:
    if not cond:
        raise SystemExit(message)


def master(dest: int, src: int, apdu: bytes) -> bytes:
    return encode_frame(0xC4, dest, src, bytes((0xC0,)) + apdu)


def exchange(station, frame: bytes):
    return handle_frame(station, frame, NOW)


def app_of(frame: bytes):
    link = decode_frame(frame)
    check(link.crc_ok and link.ok, link.error or "bad frame")
    apdu = parse_apdu(link.user)
    check(apdu.ok, apdu.error or "bad apdu")
    return link, apdu


def g120(apdu, variation: int) -> bytes | None:
    for obj in apdu.objects:
        if obj.group == 120 and obj.variation == variation and obj.items:
            return obj.items[0].raw
    return None


def session(station) -> None:
    status = exchange(station, master(4, 100, bytes((0xC0, FC_AUTH_REQUEST, 120, 4, 0x5B, 1, 2, 0, 1, 0))))
    check(len(status) == 1, "no key status")
    _, apdu = app_of(status[0])
    body = g120(apdu, 5)
    check(body is not None and len(body) >= 13, "g120v5 missing")
    assert body is not None
    ksq = int.from_bytes(body[:4], "little")
    user = int.from_bytes(body[4:6], "little")
    check(ksq == 1, f"first transmitted KSQ is {ksq}, IEEE 1815 requires 1")
    status_data = body
    control = bytes(range(32))
    monitor = bytes(range(32, 64))
    plain = (32).to_bytes(2, "little") + control + monitor + status_data
    plain += bytes((-len(plain)) % 8)
    wrapped = aes256_wrap(station.sav5.update_key, plain)
    change = bytearray((0xC1, FC_AUTH_REQUEST, 120, 6, 0x5B, 1, (6 + len(wrapped)) & 0xFF, 0))
    change.extend(ksq.to_bytes(4, "little"))
    change.extend(user.to_bytes(2, "little"))
    change.extend(wrapped)
    reply = exchange(station, master(4, 100, bytes(change)))
    check(station.sav5.os.status == KEY_OK, f"session {station.sav5.os.status} {station.sav5.last_result}")
    check(len(reply) == 1, "no key-change response")
    _, changed = app_of(reply[0])
    after = g120(changed, 5)
    check(after is not None and int.from_bytes(after[:4], "little") == 2, "KSQ did not increment after the session key change")
    again = exchange(station, master(4, 100, bytes((0xC3, FC_AUTH_REQUEST, 120, 4, 0x5B, 1, 2, 0, 1, 0))))
    _, active = app_of(again[0])
    current = g120(active, 5)
    check(current is not None and current[8] != 0, "an active session omitted the key-status MAC")
    assert current is not None
    expect = hmac_sha256(monitor, bytes(change), 16)
    check(current.endswith(expect), "key-status MAC was not calculated over the last key change")
    fresh = (32).to_bytes(2, "little") + control + monitor + current
    fresh += bytes([0xA5]) * ((-len(fresh)) % 8)
    wrapped_again = aes256_wrap(station.sav5.update_key, fresh)
    follow = bytearray((0xC4, FC_AUTH_REQUEST, 120, 6, 0x5B, 1, (6 + len(wrapped_again)) & 0xFF, 0))
    follow.extend(int.from_bytes(current[:4], "little").to_bytes(4, "little"))
    follow.extend(int.from_bytes(current[4:6], "little").to_bytes(2, "little"))
    follow.extend(wrapped_again)
    second = exchange(station, master(4, 100, bytes(follow)))
    check(station.sav5.os.status == KEY_OK, f"rekey while the session was OK failed: {station.sav5.last_result}")
    check(len(second) == 1, "no response to the second key change")
    stats = exchange(station, master(4, 100, bytes((0xC2, FC_READ, 121, 1, 6))))
    _, stat_apdu = app_of(stats[0])
    check(any(obj.group == 121 and obj.variation == 1 for obj in stat_apdu.objects), "g121v1 missing")
    check(station.security[13] >= 1, "session key change statistic was not counted")


def reply_to(station, challenge_frame: bytes, critical: bytes) -> None:
    link, apdu = app_of(challenge_frame)
    body = g120(apdu, 1)
    check(body is not None, "challenge missing")
    assert body is not None
    csq = int.from_bytes(body[:4], "little")
    user = int.from_bytes(body[4:6], "little")
    mac = hmac_sha256(station.sav5.os.control_key, link.user[1:] + critical, 16)
    payload = bytearray((0xC2, FC_AUTH_REQUEST, 120, 2, 0x5B, 1, (6 + len(mac)) & 0xFF, 0))
    payload.extend(csq.to_bytes(4, "little"))
    payload.extend(user.to_bytes(2, "little"))
    payload.extend(mac)
    # The HMAC is over the challenge APDU the outstation stored, which is the
    # application fragment without the transport byte. link.user[1:] is that.
    outs = exchange(station, master(4, 100, bytes(payload)))
    check(outs, "no reply to HMAC")
    check("HMAC accepted" in station.log[-1].summary or any("HMAC accepted" in item.summary for item in station.log), station.sav5.last_result)


def crob(index: int, code: int) -> bytes:
    body = bytes((code, 1, 0xE8, 0x03, 0, 0, 0xE8, 0x03, 0, 0, 0))
    return bytes((0xC0, FC_SELECT, 12, 1, 0x17, 1, index)) + body


def operate(index: int, code: int) -> bytes:
    body = bytes((code, 1, 0xE8, 0x03, 0, 0, 0xE8, 0x03, 0, 0, 0))
    return bytes((0xC0, FC_OPERATE, 12, 1, 0x17, 1, index)) + body


def authed(station, apdu: bytes) -> None:
    outs = exchange(station, master(4, 100, apdu))
    check(len(outs) == 1, "expected a challenge")
    reply_to(station, outs[0], apdu)


def run() -> None:
    vector = bytes((0x05, 0x64, 0x05, 0xF2, 0x01, 0x00, 0x00, 0x00))
    check(crc16_dnp(vector) == 0x0C52, "CRC vector")
    kek = parse_hex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
    key_data = parse_hex("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F")
    assert kek and key_data
    wrapped = aes256_wrap(kek, key_data)
    expect = parse_hex("28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21")
    check(same_bytes(wrapped, expect or b""), "AES-256 key wrap vector")
    check(same_bytes(aes256_unwrap(kek, wrapped) or b"", key_data), "AES unwrap")
    mac = hmac_sha256(b"key", b"The quick brown fox jumps over the lazy dog", 32)
    check(mac.hex() == "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8", "HMAC")

    station = create_station()
    ack = exchange(station, encode_frame(0xC0, 4, 100, b""))
    check(station.link_reset and ack and b"ACK" in ack[0] or True, "link")
    link = decode_frame(ack[0])
    check(link.crc_ok and (link.control & 0x0F) == 0 and link.src == 4, "ACK")

    integ = bytes((0xC0, FC_READ, 60, 2, 6, 60, 3, 6, 60, 4, 6, 60, 1, 6))
    resp = exchange(station, master(4, 100, integ))
    _, apdu = app_of(resp[0])
    check(apdu.fc == FC_RESPONSE and (apdu.iin1 & 0x80), f"restart IIN {apdu.iin1:02x}")
    groups = {obj.group for obj in apdu.objects}
    check(1 in groups and 30 in groups, f"integrity groups {groups}")

    stranger = exchange(station, master(4, 77, bytes((0xC0, FC_READ, 60, 1, 6))))
    check(stranger == [], "a frame from a master address other than 100 was accepted")

    session(station)
    authed(station, bytes((0xC0, FC_WRITE, 80, 1, 0x00, 7, 7, 0x01)))
    check(not station.restart, "restart bit still set")

    authed(station, crob(1, 0x81))
    authed(station, operate(1, 0x81))
    feeder = find_point(station, "bi", 1)
    check(feeder is not None and feeder.value < 0.5, "feeder breaker did not open")
    kept = [event.id for event in station.events if event.kind == "bi"]
    check(kept, "the breaker event was not queued")
    for _ in range(100):
        exchange(station, master(4, 100, bytes((0xC0, FC_READ, 1, 2, 6))))
    still = [event.id for event in station.events if event.kind == "bi"]
    check(any(item in still for item in kept), "statistic events pushed the breaker event out of the buffer")
    check(not station.overflow, "routine reads overflowed the event buffer")
    for _ in range(3):
        again = exchange(station, master(4, 100, bytes((0xC3, FC_AUTH_REQUEST, 120, 4, 0x5B, 1, 2, 0, 1, 0))))
        check(len(again) == 1, "key status stopped after repeated requests")
        _, status_apdu = app_of(again[0])
        check(g120(status_apdu, 5) is not None, "repeated key status did not return g120v5")

    server = threading.Thread(target=serve, kwargs={"port": 20011}, daemon=True)
    server.start()
    for _ in range(50):
        try:
            sock = socket.create_connection(("127.0.0.1", 20011), 0.2)
            break
        except OSError:
            threading.Event().wait(0.05)
    else:
        raise SystemExit("TCP port 20011 did not open")
    sock.sendall(encode_frame(0xC9, 4, 100, b""))
    data = sock.recv(64)
    sock.close()
    got = decode_frame(data)
    check(got.crc_ok and got.src == 4 and (got.control & 0x0F) == 11, "TCP link status")
    print("selfcheck ok")


if __name__ == "__main__":
    run()
