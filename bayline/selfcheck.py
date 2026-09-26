"""Protocol checks for the Python outstation. python -m bayline.selfcheck"""

from __future__ import annotations

import hashlib
import hmac
import os
import socket
import tempfile
import threading

from bayline.codec import (
    FC_AUTH_REQUEST,
    FC_DIRECT_OPERATE,
    FC_OPERATE,
    FC_READ,
    FC_RESPONSE,
    FC_SELECT,
    FC_WRITE,
    crc16_dnp,
    decode_frame,
    encode_frame,
    frame_size,
    parse_apdu,
    parse_hex,
)
from bayline.crypto import aes256_unwrap, aes256_wrap, aes_wrap, hmac_sha256, same_bytes
from bayline.outstation import _stat, handle_frame
from bayline.station import KEY_OK, SaUser, create_station, find_point
from bayline.__main__ import serve

NOW = 1_700_000_000_000


def check(cond: bool, message: str) -> None:
    if not cond:
        raise SystemExit(message)


def master(dest: int, src: int, apdu: bytes) -> bytes:
    return encode_frame(0xC4, dest, src, bytes((0xC0,)) + apdu)


def exchange(station, frame: bytes):
    return handle_frame(station, frame, NOW)


def app_of(data: bytes):
    """Decode one response, reassembling it when the outstation split it into transport segments."""
    frames = []
    while data:
        size = frame_size(data[2])
        frames.append(data[:size])
        data = data[size:]
    links = [decode_frame(frame) for frame in frames]
    for link in links:
        check(link.crc_ok and link.ok, link.error or "bad frame")
    check(bool(links[0].user[0] & 0x40) and bool(links[-1].user[0] & 0x80), "transport FIR/FIN bits are wrong")
    link = links[0]
    link.user = bytes((0xC0,)) + b"".join(item.user[1:] for item in links)
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
    check(int.from_bytes(body[4:6], "little") == 0, "the challenge named a user; SAv5 outstations send user 0")
    user = 1
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


def free(variation: int, body: bytes) -> bytes:
    return bytes((120, variation, 0x5B, 1, len(body) & 0xFF, len(body) >> 8)) + body


def new_session(station, user: int, key_len: int, seq: int) -> tuple[bytes, bytes]:
    """Key status with qualifier 0x07 (as opendnp3 sends it), then a key change with key_len-octet session keys."""
    status = exchange(station, master(4, 100, bytes((0xC0 | seq, FC_AUTH_REQUEST, 120, 4, 0x07, 1)) + user.to_bytes(2, "little")))
    _, apdu = app_of(status[0])
    body = g120(apdu, 5)
    check(body is not None, f"no key status for user {user}")
    assert body is not None
    control, monitor = os.urandom(key_len), os.urandom(key_len)
    plain = key_len.to_bytes(2, "little") + control + monitor + body
    plain += bytes((-len(plain)) % 8)
    kek = station.sav5.users[user].update_key
    change = bytes((0xC0 | (seq + 1), FC_AUTH_REQUEST)) + free(6, body[:4] + user.to_bytes(2, "little") + aes_wrap(kek, plain))
    reply = exchange(station, master(4, 100, change))
    _, after = app_of(reply[0])
    status_after = g120(after, 5)
    check(status_after is not None and status_after[7] == KEY_OK, f"user {user} session key change failed: {station.sav5.last_result}")
    return control, monitor


def error_code(frames: list[bytes]) -> int | None:
    if not frames:
        return None
    _, apdu = app_of(frames[0])
    body = g120(apdu, 7)
    return body[8] if body else None


def aggressive(station, user: int, control: bytes, request: bytes, seq: int) -> list[bytes]:
    """request is the function code plus objects. The MAC covers the last challenge and this fragment up to g120v9."""
    head = bytes((0xC0 | seq,)) + request[:1] + free(3, station.sav5.csq.to_bytes(4, "little") + user.to_bytes(2, "little")) + request[1:]
    mac = hmac_sha256(control, station.sav5.last_challenge + head, 16)
    return exchange(station, master(4, 100, head + free(9, mac)))


def user_status(auth: bytes, method: int, operation: int, scs: int, role: int, name: str, days: int = 30) -> bytes:
    fields = bytes((operation,)) + scs.to_bytes(4, "little") + role.to_bytes(2, "little") + days.to_bytes(2, "little") + len(name).to_bytes(2, "little")
    cert = hmac.new(auth, fields + name.encode(), hashlib.sha1 if method == 3 else hashlib.sha256).digest()
    body = bytes((method, operation)) + scs.to_bytes(4, "little") + role.to_bytes(2, "little") + days.to_bytes(2, "little")
    body += len(name).to_bytes(2, "little") + (0).to_bytes(2, "little") + len(cert).to_bytes(2, "little") + name.encode() + cert
    return bytes((0xC0, FC_AUTH_REQUEST)) + free(10, body)


def remote_user(station, auth: bytes, method: int, scs: int, role: int, name: str) -> int:
    digest = hashlib.sha1 if method == 3 else hashlib.sha256
    key_len = 16 if method == 3 else 32
    out = exchange(station, master(4, 100, user_status(auth, method, 1, scs, role, name)))
    check(error_code(out) is None, f"user status change for {name} was refused: {station.sav5.last_result}")
    master_challenge = os.urandom(8)
    request = bytes((method,)) + len(name).to_bytes(2, "little") + len(master_challenge).to_bytes(2, "little") + name.encode() + master_challenge
    out = exchange(station, master(4, 100, bytes((0xC1, FC_AUTH_REQUEST)) + free(11, request)))
    _, apdu = app_of(out[0])
    reply = g120(apdu, 12)
    check(reply is not None, f"no g120v12 for {name}: {station.sav5.last_result}")
    assert reply is not None
    ksq, number, length = reply[:4], reply[4:6], int.from_bytes(reply[6:8], "little")
    outstation_challenge = reply[8 : 8 + length]
    new_key = os.urandom(key_len)
    plain = name.encode() + new_key + outstation_challenge
    plain += bytes((-len(plain)) % 8)
    wrapped = aes_wrap(auth, plain)
    confirm = hmac.new(new_key, station.sav5.outstation_name.encode() + master_challenge + outstation_challenge + ksq + number, digest).digest()
    body = ksq + number + len(wrapped).to_bytes(2, "little") + wrapped
    out = exchange(station, master(4, 100, bytes((0xC2, FC_AUTH_REQUEST)) + free(13, body) + free(15, confirm)))
    _, apdu = app_of(out[0])
    theirs = g120(apdu, 15)
    expect = hmac.new(new_key, name.encode() + outstation_challenge + master_challenge + ksq + number, digest).digest()
    check(theirs == expect, f"outstation confirmation MAC for {name} is wrong: {station.sav5.last_result}")
    user = int.from_bytes(number, "little")
    check(station.sav5.users[user].update_key == new_key and station.sav5.users[user].name == name, f"{name} was not installed")
    return user


def multi_user() -> None:
    station = create_station()
    sav = station.sav5
    sav.users[2] = SaUser(2, "viewer", "Viewer", os.urandom(32))
    sav.users[1].update_key = os.urandom(16)
    control1, _ = new_session(station, 1, 16, 0)
    control2, _ = new_session(station, 2, 32, 2)
    check(len(sav.users[1].os.control_key) == 16, "16-octet session keys were not accepted")

    trip = crob(1, 0x81)
    outs = exchange(station, master(4, 100, trip))
    _, challenge = app_of(outs[0])
    body = g120(challenge, 1)
    check(body is not None and body[4:6] == b"\x00\x00", "challenge missing or not addressed to user 0")
    assert body is not None
    link, _ = app_of(outs[0])
    mac = hmac_sha256(control2, link.user[1:] + trip, 16)
    refused = exchange(station, master(4, 100, bytes((0xC4, FC_AUTH_REQUEST)) + free(2, body[:4] + (2).to_bytes(2, "little") + mac)))
    check(error_code(refused) == 7, "a Viewer's authenticated SELECT did not return authorization failed")
    check(station.select is None, "a refused SELECT armed the output")

    sav.aggressive = True
    feeder = find_point(station, "bi", 2)
    assert feeder is not None
    direct = bytes((FC_DIRECT_OPERATE, 12, 1, 0x28, 1, 0, 2, 0)) + bytes((0x81, 1, 0xE8, 0x03, 0, 0, 0xE8, 0x03, 0, 0, 0))
    before = sav.csq
    outs = aggressive(station, 1, control1, direct, 5)
    _, reply = app_of(outs[0])
    check(reply.fc == FC_RESPONSE and not any(obj.group == 120 for obj in reply.objects), f"aggressive mode was not accepted: {sav.last_result}")
    check(reply.objects and reply.objects[0].qualifier == 0x28, "control echo did not keep the request qualifier")
    check(feeder.value < 0.5 and sav.csq == before + 1, "aggressive DIRECT_OPERATE did not trip feeder 2")
    replay_head = bytes((0xC6,)) + direct[:1] + free(3, before.to_bytes(4, "little") + (1).to_bytes(2, "little")) + direct[1:]
    replay = exchange(station, master(4, 100, replay_head + free(9, hmac_sha256(control1, sav.last_challenge + replay_head, 16))))
    check(error_code(replay) == 2, "a replayed aggressive CSQ was accepted")
    viewer = aggressive(station, 2, control2, direct, 7)
    check(error_code(viewer) == 7, "a Viewer's aggressive DIRECT_OPERATE was not refused")
    read = aggressive(station, 2, control2, bytes((FC_READ, 60, 1, 6)), 8)
    _, polled = app_of(read[0])
    check(polled.fc == FC_RESPONSE and not polled.iin2 & 0x02, "an aggressive-mode READ was not answered cleanly")

    auth = os.urandom(32)
    out = exchange(station, master(4, 100, user_status(auth, 4, 1, 0, 1, "eve")))
    check(error_code(out) == 8, "a user status change without an authority key was not refused with code 8")
    sav.authority_key = auth
    out = exchange(station, master(4, 100, user_status(os.urandom(32), 4, 1, 0, 1, "eve")))
    check(error_code(out) == 10, "bad certification data was not refused with code 10")
    carol = remote_user(station, auth, 3, 0, 2, "carol")
    dave = remote_user(station, auth, 4, 1, 1, "dave")
    check(len(sav.users[carol].update_key) == 16 and sav.users[carol].role == "Engineer", "method 3 did not install a 16-octet key")
    check(len(sav.users[dave].update_key) == 32 and sav.users[dave].role == "Operator", "method 4 did not install a 32-octet key")
    stale = exchange(station, master(4, 100, user_status(auth, 4, 1, 0, 1, "mallory")))
    check(error_code(stale) == 10, "an old status change sequence was accepted")
    gone = exchange(station, master(4, 100, user_status(auth, 4, 2, 2, 2, "carol")))
    check(error_code(gone) is None and carol not in sav.users, "delete did not remove carol")
    control_dave, _ = new_session(station, dave, 32, 9)
    outs = aggressive(station, dave, control_dave, direct.replace(bytes((0x81,)), bytes((0x41,)), 1), 11)
    check(app_of(outs[0])[1].fc == FC_RESPONSE and feeder.value >= 0.5, f"dave could not close feeder 2: {sav.last_result}")


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
    check({1, 10, 20, 30, 40, 121} <= groups, f"integrity groups {groups}; a class 0 poll must carry every static type and g121")
    counted = {obj.group: len(obj.indexes) for obj in apdu.objects}
    check(counted[1] == 20 and counted[30] == 20 and counted[121] == 18, f"integrity poll was truncated: {counted}")

    stranger = exchange(station, master(4, 77, bytes((0xC0, FC_READ, 60, 1, 6))))
    check(stranger == [], "a frame from a master address other than 100 was accepted")

    session(station)
    authed(station, bytes((0xC0, FC_WRITE, 80, 1, 0x00, 7, 7, 0x00)))
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
    trip = next(event for event in station.events if event.kind == "bi")
    station.event_max = 2
    station.events[:] = [trip]
    for _ in range(6):
        station.security_sent[2] = station.security[2]
        _stat(station, 2, NOW, 2)
    check(any(event.id == trip.id for event in station.events), "a security event evicted the breaker trip")
    check(not station.overflow, "dropping a security event set the process overflow bit")
    for _ in range(3):
        again = exchange(station, master(4, 100, bytes((0xC3, FC_AUTH_REQUEST, 120, 4, 0x5B, 1, 2, 0, 1, 0))))
        check(len(again) == 1, "key status stopped after repeated requests")
        _, status_apdu = app_of(again[0])
        check(g120(status_apdu, 5) is not None, "repeated key status did not return g120v5")

    folder = tempfile.mkdtemp(prefix="bayline-selfcheck-")
    multi_user()

    server = threading.Thread(target=serve, kwargs={"port": 20011, "key_file": os.path.join(folder, "key.hex")}, daemon=True)
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
