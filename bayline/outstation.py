"""DNP3 outstation application, including SAv5."""

from __future__ import annotations

import hashlib
import hmac

from bayline.codec import (
    FC_AUTH_REQUEST,
    FC_AUTH_RESPONSE,
    FC_COLD_RESTART,
    FC_CONFIRM,
    FC_DELAY_MEASURE,
    FC_DIRECT_OPERATE,
    FC_DIRECT_OPERATE_NR,
    FC_DISABLE_UNSOL,
    FC_ENABLE_UNSOL,
    FC_FREEZE_CLEAR,
    FC_FREEZE_CLEAR_NR,
    FC_IMMED_FREEZE,
    FC_IMMED_FREEZE_NR,
    FC_NAME,
    FC_OPERATE,
    FC_READ,
    FC_RECORD_TIME,
    FC_RESPONSE,
    FC_SELECT,
    FC_UNSOLICITED,
    FC_WARM_RESTART,
    FC_WRITE,
    ParsedApdu,
    ParsedObject,
    decode_frame,
    describe_frame,
    describe_user,
    encode_frame,
    object_size,
    parse_apdu,
    push_f32,
    push_i16,
    push_i32,
    push_time48,
    push_u16,
    push_u32,
    push_u8,
    read_f32,
    read_i16,
    read_i32,
    read_time48,
    read_uint,
    to_hex,
)
from bayline.crypto import (
    UK_CHALLENGE_LEN,
    aes_unwrap,
    random_bytes,
    same_bytes,
    session_mac,
)
from bayline.station import (
    ERR_AGGRESSIVE,
    ERR_AUTH_FAILED,
    ERR_AUTHORIZATION,
    ERR_CERTIFICATION,
    ERR_SIGNATURE,
    ERR_UK_METHOD,
    ERR_UNEXPECTED,
    ERR_UNKNOWN_USER,
    KEY_CHANGE_METHODS,
    KEY_AUTH_FAIL,
    KEY_OK,
    PROVISIONED_USER,
    RESTART_FLAG,
    ROLE_NAMES,
    DnpEvent,
    PendingAuth,
    PendingConfirm,
    PendingStatusChange,
    PendingUpdateKey,
    Point,
    SaUser,
    SelectArm,
    Station,
    auth_profile,
    find_point,
    find_user_by_name,
    outstation_now,
    points_of,
    reset_session_keys,
    reset_user_session,
    role_permits,
    sync_binary_flag,
    update_key_material,
)

FRAGMENT = 2048
SEGMENT = 249
ERR_NAME = {1: "authentication failed", 2: "unexpected response", 4: "aggressive mode not supported", 5: "MAC algorithm not supported", 7: "authorization failed", 8: "update-key method not permitted", 9: "invalid signature", 10: "invalid certification data", 11: "unknown user", 12: "too many key status requests"}


class Built:
    def __init__(self) -> None:
        self.bytes = bytearray()
        self.event_ids: list[int] = []
        self.truncated = False
        self.extra2 = 0


STAT_THRESHOLD = (2, 2, 2, 2, 2, 100, 100, 100, 100, 10, 2, 10, 100, 2, 2, 2, 2, 2)
# Message totals stay on g121. They must not occupy the event buffer.
NO_EVENT_STATS = {5, 6, 7, 8}


def _trim_events(station: Station) -> None:
    while len(station.events) > station.event_max:
        security = next((i for i, event in enumerate(station.events) if event.kind == "sec"), None)
        if security is not None:
            station.events.pop(security)
            continue
        station.events.pop(0)
        station.overflow = True


def _stat(station: Station, index: int, now: int, step: int = 1) -> None:
    if not 0 <= index < len(station.security) or step <= 0:
        return
    station.security[index] = (station.security[index] + step) & 0xFFFFFFFF
    threshold = STAT_THRESHOLD[index]
    if station.security[index] - station.security_sent[index] < threshold:
        return
    station.security_sent[index] = station.security[index]
    if index in NO_EVENT_STATS:
        return
    station.events.append(
        DnpEvent(station.next_event_id, "sec", index, float(station.security[index]), 0x01, outstation_now(station, now), 3, 2)
    )
    station.next_event_id += 1
    _trim_events(station)


def handle_frame(station: Station, data: bytes, now: int) -> list[bytes]:
    housekeep(station, now)
    summary, detail, ok = describe_frame(data)
    _log(station, "in", summary, detail, to_hex(data), ok, now)
    link = decode_frame(data)
    if not link.ok or not link.crc_ok:
        _stat(station, 9, now)
        _log(station, "note", "CRC failure — frame discarded" if not link.crc_ok else (link.error or "Frame rejected"), link.error, "", False, now)
        return []
    reply_to = link.src
    broadcast = link.dest == 0xFFFF
    if not broadcast and link.dest != station.outstation:
        _stat(station, 9, now)
        _log(station, "note", f"Ignored frame for address {link.dest}", f"This outstation is {station.outstation}.", "", True, now)
        return []
    if link.src != station.master:
        _stat(station, 9, now)
        _log(station, "note", f"Ignored frame from address {link.src}", f"The configured master address is {station.master}.", "", True, now)
        return []
    if (link.control & 0x40) == 0:
        _log(station, "note", "Secondary frame ignored", "Outstations do not accept link responses.", "", True, now)
        return []
    func = link.control & 0x0F
    outs: list[bytes] = []
    if func == 0:
        station.link_reset = True
        station.expect_fcb = True
        if not broadcast:
            outs.append(_secondary(station, reply_to, 0, now))
        return outs
    if func == 2:
        fcv = bool(link.control & 0x10)
        fcb = bool(link.control & 0x20)
        good = station.link_reset and fcv and fcb == station.expect_fcb
        if good:
            station.expect_fcb = not station.expect_fcb
        if not broadcast:
            outs.append(_secondary(station, reply_to, 0 if good else 1, now))
        return outs
    if func == 9:
        if not broadcast:
            outs.append(_secondary(station, reply_to, 11, now))
        return outs
    if func not in (3, 4):
        if not broadcast:
            outs.append(_secondary(station, reply_to, 15, now))
        return outs
    if func == 3:
        fcv = bool(link.control & 0x10)
        fcb = bool(link.control & 0x20)
        if not station.link_reset or not fcv or fcb != station.expect_fcb:
            if not broadcast:
                outs.append(_secondary(station, reply_to, 1, now))
            return outs
        station.expect_fcb = not station.expect_fcb
        if not broadcast:
            outs.append(_secondary(station, reply_to, 0, now))
    _stat(station, 6, now)
    produced = 0
    for apdu in process_app(station, link.user, now):
        if not broadcast:
            outs.append(_primary(station, reply_to, apdu, now))
            produced += 1
    if produced:
        _stat(station, 5, now, produced)
    return outs


def process_app(station: Station, user: bytes, now: int) -> list[bytes]:
    apdu = parse_apdu(user)
    if not apdu.ok:
        i1, i2 = live_iin(station, 0, 0x04)
        return [_apdu(apdu.seq, FC_RESPONSE, i1, i2, b"", False, False)]
    if not apdu.transport_fir or not apdu.transport_fin:
        i1, i2 = live_iin(station, 0, 0x04)
        _log(station, "note", "Multi-fragment request rejected", "This outstation accepts a single transport segment.", "", True, now)
        return [_apdu(apdu.seq, FC_RESPONSE, i1, i2, b"", False, False)]
    extra2 = 0
    objects = b""
    event_ids: list[int] = []
    con = False
    fc = apdu.fc
    if fc == FC_CONFIRM:
        _accept_confirm(station, apdu, now)
        return []
    if fc == FC_AUTH_REQUEST:
        return _auth_request(station, apdu, user, now)
    already = station.sav5.bypass
    station.sav5.bypass = False
    if station.sav5.enabled and not already:
        aggressive = any(obj.group == 120 for obj in apdu.objects)
        if aggressive or _needs_auth(station, apdu):
            held = _gate_critical(station, apdu, user, now, _needs_auth(station, apdu))
            if held is not None:
                return held
    apdu.objects = [obj for obj in apdu.objects if obj.group != 120]
    if fc == FC_READ:
        built = _read_objects(station, apdu, now)
        objects = bytes(built.bytes)
        event_ids = built.event_ids
        extra2 |= built.extra2
    elif fc == FC_WRITE:
        extra2 |= _write_objects(station, apdu, now)
    elif fc in (FC_SELECT, FC_OPERATE, FC_DIRECT_OPERATE, FC_DIRECT_OPERATE_NR):
        mode = {FC_SELECT: "select", FC_OPERATE: "operate", FC_DIRECT_OPERATE: "direct"}.get(fc, "nr")
        objects, bit = _command(station, apdu, user, now, mode)
        extra2 |= bit
        if mode == "nr":
            return []
    elif fc in (FC_IMMED_FREEZE, FC_IMMED_FREEZE_NR, FC_FREEZE_CLEAR, FC_FREEZE_CLEAR_NR):
        objects = _freeze(station, apdu, now, fc in (FC_FREEZE_CLEAR, FC_FREEZE_CLEAR_NR))
        if fc in (FC_IMMED_FREEZE_NR, FC_FREEZE_CLEAR_NR):
            return []
    elif fc == FC_COLD_RESTART:
        _cold_restart(station, now)
        objects = _delay(1000)
    elif fc == FC_WARM_RESTART:
        station.restart = True
        station.need_time = True
        station.select = None
        objects = _delay(200)
    elif fc in (FC_ENABLE_UNSOL, FC_DISABLE_UNSOL):
        extra2 |= _set_unsol(station, apdu, fc == FC_ENABLE_UNSOL)
    elif fc == FC_DELAY_MEASURE:
        objects = _delay(station.proc_delay)
    elif fc == FC_RECORD_TIME:
        station.time_offset = station.time_offset  # recorded at the clock the master last wrote
    else:
        extra2 |= 0x01
    if event_ids:
        _mark_pending(station, apdu.seq, False, event_ids, now)
        con = True
    i1, i2 = live_iin(station, 0, extra2)
    return [_apdu(apdu.seq, FC_RESPONSE, i1, i2, objects, con, False)]


def flush_unsolicited(station: Station, now: int) -> list[bytes]:
    housekeep(station, now)
    if station.pending_confirm:
        return []
    wanted = [e for e in station.events if not e.held and _unsol_class(station, e.clazz)]
    if not wanted:
        return []
    seq = station.unsol_seq & 0x0F
    station.unsol_seq = (station.unsol_seq + 1) & 0x0F
    built = Built()
    _add_events(station, built, wanted, 0, now)
    if not built.event_ids:
        return []
    _mark_pending(station, seq, True, built.event_ids, now)
    i1, i2 = live_iin(station)
    return [_primary(station, station.master, _apdu(seq, FC_UNSOLICITED, i1, i2, bytes(built.bytes), True, True), now)]


def write_point(station: Station, point: Point, value: float, flags: int, now: int, reason: str) -> None:
    prev = point.value
    point.value = value
    point.flags = flags
    sync_binary_flag(point)
    if reason == "silent":
        point.last_event_value = point.value
        point.last_flags = point.flags
        return
    binary = point.kind in ("bi", "bo")
    moved = ((prev >= 0.5) != (point.value >= 0.5) or point.flags != point.last_flags) if binary else (
        abs(point.value - point.last_event_value) >= max(0, point.deadband) or point.flags != point.last_flags
    )
    force = reason != "sim" and (point.value != prev or point.flags != point.last_flags)
    if point.clazz > 0 and (moved if reason == "sim" else force):
        _push_event(station, point, now)
    if point.kind == "bo":
        changed = (prev >= 0.5) != (point.value >= 0.5)
        if point.feedback is not None:
            status = find_point(station, "bi", point.feedback)
            if status:
                write_point(station, status, 1 if point.value >= 0.5 else 0, status.flags, now, "sim" if reason == "sim" else "control")
        if changed and point.op_counter is not None:
            counter = find_point(station, "ctr", point.op_counter)
            if counter:
                write_point(station, counter, counter.value + 1, counter.flags, now, "control")


def housekeep(station: Station, now: int) -> None:
    pending = station.pending_confirm
    if pending and now > pending.deadline:
        keep = set(pending.event_ids)
        for event in station.events:
            if event.id in keep:
                event.held = False
        station.pending_confirm = None
    if station.sav5.pending and now > station.sav5.pending.deadline:
        station.sav5.pending = None
        station.sav5.last_result = "Challenge expired before a reply."
        _stat(station, 3, now)
        _log(station, "note", "SAv5 challenge expired", "The critical request was not executed.", "", True, now)
    _expire_session(station, now)


def live_iin(station: Station, extra1: int = 0, extra2: int = 0) -> tuple[int, int]:
    i1, i2 = extra1, extra2
    for event in station.events:
        if event.clazz == 1:
            i1 |= 0x02
        elif event.clazz == 2:
            i1 |= 0x04
        elif event.clazz == 3:
            i1 |= 0x08
    if station.need_time:
        i1 |= 0x10
    if station.local:
        i1 |= 0x20
    if station.trouble:
        i1 |= 0x40
    if station.restart:
        i1 |= 0x80
    if station.overflow:
        i2 |= 0x08
    return i1 & 0xFF, i2 & 0xFF


def _accept_confirm(station: Station, apdu: ParsedApdu, now: int) -> None:
    pending = station.pending_confirm
    if not pending or pending.seq != apdu.seq or pending.unsol != apdu.uns:
        _log(station, "note", "Confirm ignored", "Sequence or UNS bit does not match the outstanding response.", "", True, now)
        return
    drop = set(pending.event_ids)
    station.events = [e for e in station.events if e.id not in drop]
    station.pending_confirm = None
    if len(station.events) < station.event_max:
        station.overflow = False
    _log(station, "note", f"Confirm accepted · {len(drop)} event{'s' if len(drop) != 1 else ''} removed", "", "", True, now)


def _read_objects(station: Station, apdu: ParsedApdu, now: int) -> Built:
    built = Built()
    unknown = param = False
    if not apdu.objects:
        param = True
    for obj in apdu.objects:
        if obj.group == 60:
            if 2 <= obj.variation <= 4:
                _add_events(station, built, [e for e in station.events if not e.held and e.clazz == obj.variation - 1], 0, now)
            elif obj.variation == 1:
                _add_all_static(station, built, now)
                _add_security(station, built)
            else:
                unknown = True
        elif obj.group == 0:
            chunk = _attributes(obj.variation)
            if chunk is None:
                unknown = True
            elif not _append(built, chunk):
                built.truncated = True
        elif obj.group == 80:
            _append(built, _iin_object(station, obj))
        elif obj.group == 50 and obj.variation == 1:
            body = bytearray()
            push_time48(body, outstation_now(station, now))
            _append(built, bytes((50, 1, 0x07, 1)) + body)
        elif obj.group in (2, 11, 22, 32, 42):
            kind = _kind_for_group(obj.group)
            listed = [e for e in station.events if not e.held and _event_group(e.kind) == obj.group]
            filtered = listed if obj.all else [e for e in listed if e.index in obj.indexes]
            _add_events(station, built, filtered, obj.variation, now)
        elif obj.group == 121:
            _add_security(station, built, None if obj.all else obj.indexes)
        elif obj.group == 122:
            listed = [event for event in station.events if not event.held and event.kind == "sec"]
            if not obj.all:
                listed = [event for event in listed if event.index in obj.indexes]
            _add_events(station, built, listed, obj.variation or 2, now)
        else:
            kind = _kind_for_group(obj.group)
            if not kind or obj.group in (12, 41):
                unknown = True
            else:
                points, bad = _resolve(station, kind, obj)
                param = param or bad
                if obj.group == 21:
                    _add_counters(station, built, points, obj.variation or 1, True)
                elif obj.group == _static_group(kind):
                    _add_static(station, built, points, obj.variation, now)
                else:
                    unknown = True
    if unknown:
        built.extra2 |= 0x02
    if param:
        built.extra2 |= 0x04
    return built


def _write_objects(station: Station, apdu: ParsedApdu, now: int) -> int:
    extra2 = 0
    wrote = False
    for obj in apdu.objects:
        if obj.group == 50 and obj.variation == 1:
            raw = obj.items[0].raw if obj.items else b""
            if len(raw) < 6:
                extra2 |= 0x04
            else:
                station.time_offset = read_time48(raw, 0) - now
                station.need_time = False
                wrote = True
        elif obj.group == 80 and obj.variation == 1:
            if not _apply_iin(station, obj, now):
                extra2 |= 0x04
            else:
                wrote = True
        else:
            extra2 |= 0x02
    if not wrote and not apdu.objects:
        extra2 |= 0x04
    return extra2


def _apply_iin(station: Station, obj: ParsedObject, now: int) -> bool:
    """A master clears IIN1.7 (device restart) by writing 0 to g80v1 index 7. No other bit is writable."""
    if not obj.items or obj.all:
        return False
    raw = obj.items[0].raw
    for i, index in enumerate(obj.indexes):
        on = ((raw[i >> 3] if i >> 3 < len(raw) else 0) >> (i & 7)) & 1
        if index != 7 or on:
            return False
    station.restart = False
    del now
    return True


MAX_CONTROLS = 16


def _command(station: Station, apdu: ParsedApdu, user: bytes, now: int, mode: str) -> tuple[bytes, int]:
    """Run every CROB and analog output in the request and echo the request headers with each status patched in."""
    headers = [obj for obj in apdu.objects if obj.group in (12, 41)]
    if not headers or len(headers) != len(apdu.objects):
        return b"", 0x02 if any(obj.group not in (12, 41) for obj in apdu.objects) else 0x04
    for obj in headers:
        if (obj.group == 12 and obj.variation != 1) or (obj.group == 41 and object_size(41, obj.variation) is None):
            return b"", 0x02
    items: list[tuple[int, int, int, bytes, int]] = []
    for obj in headers:
        prefix, rng = obj.qualifier >> 4, obj.qualifier & 0x0F
        width = {1: 1, 2: 2, 3: 4}.get(prefix, 0) if rng in (7, 8, 9) else 0
        count = len(obj.items)
        for i, item in enumerate(obj.items):
            index = item.index if item.index is not None else (obj.indexes[i] if i < len(obj.indexes) else 0)
            status_at = obj.end - 1 - (count - 1 - i) * (len(item.raw) + width)
            items.append((obj.group, obj.variation, index, item.raw, status_at))
    if not items:
        return b"", 0x04
    wanted = [(g, v, i, raw[:-1]) for g, v, i, raw, _at in items]
    armed = station.select
    extra2 = 0
    statuses: list[int] = []
    if len(items) > MAX_CONTROLS:
        statuses = [8] * len(items)
    elif mode == "select":
        busy = bool(armed and armed.items != wanted and now <= armed.deadline)
        for group, variation, index, raw, _at in items:
            statuses.append(5 if busy else 7 if station.local else _check(station, group, index, raw))
        if busy:
            extra2 = 0x10
        elif all(code == 0 for code in statuses):
            first = wanted[0]
            station.select = SelectArm(first[0], first[1], first[2], first[3], now + station.select_timeout, wanted)
    elif mode == "operate":
        if armed and now > armed.deadline:
            statuses = [1] * len(items)
            station.select = None
        elif not armed or armed.items != wanted:
            statuses = [2] * len(items)
        else:
            statuses = [_execute(station, g, v, i, raw, now) for g, v, i, raw, _at in items]
            station.select = None
    else:
        statuses = [_execute(station, g, v, i, raw, now) for g, v, i, raw, _at in items]
    echo = bytearray(user)
    for (_g, _v, _i, _raw, at), status in zip(items, statuses):
        echo[at] = status
    return b"".join(bytes(echo[obj.offset : obj.end]) for obj in headers), extra2


def _check(station: Station, group: int, index: int, raw: bytes) -> int:
    """Validate a control at select time without acting on it."""
    if group == 12:
        bo = find_point(station, "bo", index)
        if not bo:
            return 4
        return 3 if raw[0] & 0x0F > 4 else 0
    ao = find_point(station, "ao", index)
    return 0 if ao else 4


def _execute(station: Station, group: int, variation: int, index: int, raw: bytes, now: int) -> int:
    if station.local:
        return 7
    if group == 12:
        bo = find_point(station, "bo", index)
        if not bo:
            return 4
        code = raw[0]
        op, tcc = code & 0x0F, (code >> 6) & 0x03
        if op > 4:
            return 3
        if bo.action:
            if tcc == 2 or (tcc == 0 and op in (2, 4)):
                return 4
            return _action(station, bo.action, now)
        nxt = 1 if bo.value >= 0.5 else 0
        if tcc == 2:
            nxt = 0
        elif tcc == 1:
            nxt = 1
        elif op in (1, 3):
            nxt = 1
        elif op in (2, 4):
            nxt = 0
        else:
            return 0
        write_point(station, bo, nxt, bo.flags, now, "control")
        return 0
    ao = find_point(station, "ao", index)
    if not ao:
        return 4
    value = read_i16(raw, 0) if variation == 2 else read_f32(raw, 0) if variation == 3 else read_i32(raw, 0)
    if value != value:
        return 3
    if value < 10.5 or value > 14.4:
        return 12
    write_point(station, ao, value, ao.flags, now, "control")
    measured = find_point(station, "ai", 10 + index) if index in (0, 1) else None
    if measured:
        measured.manual = False
    return 0


TAP_LIMIT = 16


def _action(station: Station, action: str, now: int) -> int:
    """Momentary outputs: the tap changer and the recloser lockout reset."""
    if action in ("tap_up", "tap_down"):
        auto = find_point(station, "bi", 13)
        if auto and auto.value >= 0.5:
            return 10
        tap = find_point(station, "ai", 12)
        if tap is None:
            return 4
        step = 1 if action == "tap_up" else -1
        if not -TAP_LIMIT <= tap.value + step <= TAP_LIMIT:
            return 12
        step_tap(station, step, now)
        return 0
    if action == "reset_79":
        for index in (7, 18):
            lockout = find_point(station, "bi", index)
            if lockout and lockout.value >= 0.5:
                write_point(station, lockout, 0, lockout.flags, now, "control")
        return 0
    return 4


def step_tap(station: Station, step: int, now: int) -> None:
    tap = find_point(station, "ai", 12)
    if tap is None:
        return
    write_point(station, tap, max(-TAP_LIMIT, min(TAP_LIMIT, tap.value + step)), tap.flags, now, "control")
    counter = find_point(station, "ctr", 4)
    if counter:
        write_point(station, counter, counter.value + 1, counter.flags, now, "control")


def _freeze(station: Station, apdu: ParsedApdu, now: int, clear: bool) -> bytes:
    headers = [o for o in apdu.objects if o.group in (20, 21)]
    targets: dict[int, Point] = {}
    source = headers or [ParsedObject(20, 0, 0x06, all=True)]
    for obj in source:
        listed = points_of(station, "ctr") if obj.all else [p for i in obj.indexes if (p := find_point(station, "ctr", i))]
        for point in listed:
            targets[point.index] = point
    for point in targets.values():
        point.frozen = point.value
        if clear:
            write_point(station, point, 0, point.flags, now, "control")
    built = Built()
    _add_counters(station, built, list(targets.values()), 1, True)
    return bytes(built.bytes)


def _cold_restart(station: Station, now: int) -> None:
    station.restart = True
    station.need_time = True
    station.events.clear()
    station.pending_confirm = None
    station.select = None
    station.overflow = False
    station.link_reset = False
    reset_session_keys(station.sav5)
    station.sav5.last_result = "Cold restart cleared the session keys."
    for point in station.points:
        point.flags |= RESTART_FLAG
        point.last_flags = point.flags
    del now


def _set_unsol(station: Station, apdu: ParsedApdu, enable: bool) -> int:
    extra2 = 0
    classes = [o for o in apdu.objects if o.group == 60]
    if any(o.group != 60 for o in apdu.objects):
        extra2 |= 0x02
    if not classes:
        station.unsol = {"c1": enable, "c2": enable, "c3": enable}
        return extra2
    for obj in classes:
        key = {2: "c1", 3: "c2", 4: "c3"}.get(obj.variation)
        if key:
            station.unsol[key] = enable
        else:
            extra2 |= 0x04
    return extra2


def _delay(ms: int) -> bytes:
    out = bytearray((52, 2, 0x07, 1))
    push_u16(out, max(0, min(65535, int(ms))))
    return bytes(out)


def _add_all_static(station: Station, built: Built, now: int) -> None:
    for kind in ("bi", "bo", "ctr", "ai", "ao"):
        if kind == "ctr":
            _add_counters(station, built, points_of(station, "ctr"), 0, False)
        else:
            _add_static(station, built, points_of(station, kind), 0, now)


def _add_static(station: Station, built: Built, points: list[Point], requested: int, now: int) -> None:
    buckets: dict[int, list[Point]] = {}
    for point in points:
        variation = requested or point.static_var
        buckets.setdefault(variation, []).append(point)
    for variation, listed in buckets.items():
        group = _static_group(listed[0].kind)
        offset = 0
        while offset < len(listed):
            remain = listed[offset:]
            taken = _append_fitting(built, lambda n, remain=remain, variation=variation, group=group, now=now: _header_range(group, variation, remain[:n], [_encode_static(p, variation, now) for p in remain[:n]]))
            if taken == 0:
                return
            for point in remain[:taken]:
                point.flags &= ~RESTART_FLAG
                point.last_flags &= ~RESTART_FLAG
            offset += taken
    del station


def _add_counters(station: Station, built: Built, points: list[Point], requested: int, frozen: bool) -> None:
    if not points:
        return
    variation = requested or points[0].static_var or 1
    group = 21 if frozen else 20
    offset = 0
    while offset < len(points):
        remain = points[offset:]
        def make(n: int, remain=remain, variation=variation, group=group, frozen=frozen) -> bytes | None:
            slice_ = remain[:n]
            bodies = []
            for point in slice_:
                body = _encode_counter((point.frozen if frozen and point.frozen is not None else point.value), point.flags, variation)
                if body is None:
                    return None
                bodies.append(body)
            return _header_range(group, variation, slice_, bodies)
        taken = _append_fitting(built, make)
        if taken == 0:
            return
        if not frozen:
            for point in remain[:taken]:
                point.flags &= ~RESTART_FLAG
                point.last_flags &= ~RESTART_FLAG
        offset += taken
    del station


def _add_events(station: Station, built: Built, events: list[DnpEvent], requested: int, now: int) -> None:
    buckets: dict[tuple[int, int], list[DnpEvent]] = {}
    for event in events:
        if event.kind == "sec":
            buckets.setdefault((122, requested or 2), []).append(event)
            continue
        variation = requested or event.variation
        buckets.setdefault((_event_group(event.kind), variation), []).append(event)
    for (group, variation), listed in buckets.items():
        offset = 0
        while offset < len(listed):
            remain = listed[offset:]
            def make(n: int, remain=remain, group=group, variation=variation) -> bytes | None:
                items = []
                for event in remain[:n]:
                    body = _encode_event(event, variation)
                    if body is None:
                        return None
                    items.append((event.index, body))
                return _header_indexed(group, variation, items)
            taken = _append_fitting(built, make)
            if taken == 0:
                return
            built.event_ids.extend(event.id for event in remain[:taken])
            offset += taken
    del station, now


def _encode_static(point: Point, variation: int, now: int) -> bytes | None:
    if point.kind in ("bi", "bo"):
        return bytes((point.flags & 0xFF,)) if variation == 2 else None
    if point.kind == "ctr":
        return _encode_counter(point.value, point.flags, variation)
    return _encode_analog(point.value, point.flags, variation, point.kind == "ao", False, now)


def _encode_event(event: DnpEvent, variation: int) -> bytes | None:
    if event.kind == "sec":
        out = bytearray((0x01,))
        push_u16(out, 0)
        push_u32(out, int(event.value) & 0xFFFFFFFF)
        if variation != 1:
            push_time48(out, event.time)
        return bytes(out)
    if event.kind in ("bi", "bo"):
        if variation == 1:
            return bytes((event.flags & 0xFF,))
        if variation == 2:
            out = bytearray((event.flags & 0xFF,))
            push_time48(out, event.time)
            return bytes(out)
        if variation == 3:
            return bytes((event.flags & 0xFF, 0, 0))
        return None
    if event.kind == "ctr":
        return _encode_counter(event.value, event.flags, variation, event.time if variation in (5, 6) else None)
    return _encode_analog(event.value, event.flags, variation, False, variation in (3, 4, 7), event.time)


def _encode_analog(value: float, flags: int, variation: int, output: bool, timed: bool, time: int) -> bytes | None:
    no_flag = not timed and not output and variation in (3, 4)
    as_float = variation in (5, 7) or (output and variation == 3)
    as16 = variation in (2, 4)
    encoded = flags & 0xFF
    numeric = value
    if not as_float:
        if as16:
            if numeric > 32767 or numeric < -32768:
                encoded |= 0x20
            numeric = max(-32768, min(32767, round(numeric)))
        else:
            numeric = round(numeric)
    out = bytearray()
    if not no_flag:
        push_u8(out, encoded)
    if as_float:
        push_f32(out, value)
    elif as16:
        push_i16(out, int(numeric))
    else:
        push_i32(out, int(numeric))
    if timed:
        push_time48(out, time)
    return bytes(out)


def _encode_counter(value: float, flags: int, variation: int, time: int | None = None) -> bytes | None:
    bare = variation in (5, 6) and time is None
    as16 = variation in (2, 6)
    encoded = flags & 0xFF
    numeric = max(0, round(value))
    if as16 and numeric > 65535:
        encoded |= 0x20
        numeric = 65535
    out = bytearray()
    if not bare:
        push_u8(out, encoded)
    if as16:
        push_u16(out, numeric)
    else:
        push_u32(out, numeric)
    if time is not None:
        push_time48(out, time)
    return bytes(out)


def _header_range(group: int, variation: int, points: list[Point], bodies: list[bytes | None]) -> bytes | None:
    if not points or any(b is None for b in bodies):
        return None
    start, stop = points[0].index, points[-1].index
    flat = b"".join(b for b in bodies if b is not None)
    if all(p.index == start + i for i, p in enumerate(points)) and stop <= 255:
        return bytes((group, variation, 0x00, start, stop)) + flat
    return _header_indexed(group, variation, [(p.index, b) for p, b in zip(points, bodies) if b is not None])


def _header_indexed(group: int, variation: int, items: list[tuple[int, bytes]]) -> bytes:
    out = bytearray((group, variation, 0x17, len(items) & 0xFF))
    for index, body in items:
        out.append(index & 0xFF)
        out.extend(body)
    return bytes(out)


def _attributes(variation: int) -> bytes | None:
    rows: list[tuple[int, str | int]] = [
        (252, "Bayline"),
        (250, "BAY-410 Outstation"),
        (248, "RV-12KV-0041"),
        (247, "Riverside RTU"),
        (246, "OUT-4"),
        (245, "Riverside Substation"),
        (242, "1.4.2"),
        (243, "Rev C"),
        (249, "Level 2"),
        (240, 2048),
        (241, 2048),
    ]
    if variation == 255:
        ids = bytes(v for v, _ in rows)
        return bytes((0, 255, 0x00, 0, 0, 5, len(ids))) + ids
    chosen = rows if variation == 254 else [row for row in rows if row[0] == variation]
    if not chosen:
        return None
    out = bytearray()
    for var, value in chosen:
        if isinstance(value, int):
            payload = bytearray()
            push_u32(payload, value)
            kind = 2
        else:
            payload = bytearray(ord(ch) & 0x7F for ch in value)
            kind = 1
        out.extend((0, var, 0x00, 0, 0, kind, len(payload)))
        out.extend(payload)
    return bytes(out)


def _iin_object(station: Station, obj: ParsedObject) -> bytes:
    i1, i2 = live_iin(station)
    word = i1 | (i2 << 8)
    start = 0 if obj.all else (obj.indexes[0] if obj.indexes else 0)
    stop = 15 if obj.all else (obj.indexes[-1] if obj.indexes else start)
    bits = bytearray()
    for i in range(stop - start + 1):
        if (word >> (start + i)) & 1:
            bi = i >> 3
            while len(bits) <= bi:
                bits.append(0)
            bits[bi] |= 1 << (i & 7)
    if not bits:
        bits.append(0)
    return bytes((80, 1, 0x00, start & 0xFF, stop & 0xFF)) + bytes(bits)


def _append(built: Built, chunk: bytes) -> bool:
    if len(built.bytes) + len(chunk) > FRAGMENT:
        built.truncated = True
        return False
    built.bytes.extend(chunk)
    return True


def _append_fitting(built: Built, make) -> int:
    room = FRAGMENT - len(built.bytes)
    count = 1
    best = None
    while count < 256:
        trial = make(count)
        if trial is None or len(trial) > room:
            break
        best = trial
        count += 1
        if count > 64 and len(trial) > room - 8:
            break
    if best is None:
        built.truncated = True
        return 0
    built.bytes.extend(best)
    return count - 1


def _push_event(station: Station, point: Point, now: int) -> None:
    if point.clazz == 0:
        return
    station.events.append(
        DnpEvent(station.next_event_id, point.kind, point.index, point.value, point.flags, outstation_now(station, now), point.clazz, point.event_var or 2)
    )
    station.next_event_id += 1
    point.last_event_value = point.value
    point.last_flags = point.flags
    _trim_events(station)


def _mark_pending(station: Station, seq: int, unsol: bool, event_ids: list[int], now: int) -> None:
    if station.pending_confirm:
        previous = set(station.pending_confirm.event_ids)
        for event in station.events:
            if event.id in previous:
                event.held = False
    keep = set(event_ids)
    for event in station.events:
        if event.id in keep:
            event.held = True
    station.pending_confirm = PendingConfirm(seq, unsol, event_ids, now + station.confirm_timeout)


def _resolve(station: Station, kind: str, obj: ParsedObject) -> tuple[list[Point], bool]:
    if obj.all:
        return points_of(station, kind), False
    points: list[Point] = []
    param = False
    for index in obj.indexes:
        point = find_point(station, kind, index)
        if point is None:
            param = True
        else:
            points.append(point)
    return points, param


def _kind_for_group(group: int) -> str | None:
    return {1: "bi", 2: "bi", 10: "bo", 11: "bo", 12: "bo", 20: "ctr", 21: "ctr", 22: "ctr", 30: "ai", 32: "ai", 40: "ao", 41: "ao", 42: "ao"}.get(group)


def _static_group(kind: str) -> int:
    return {"bi": 1, "bo": 10, "ctr": 20, "ai": 30, "ao": 40}[kind]


def _event_group(kind: str) -> int:
    if kind == "sec":
        return 122
    return {"bi": 2, "bo": 11, "ctr": 22, "ai": 32, "ao": 42}[kind]


def _add_security(station: Station, built: Built, indexes: list[int] | None = None) -> None:
    chosen = list(range(len(station.security))) if indexes is None else [i for i in indexes if 0 <= i < len(station.security)]
    if not chosen:
        return
    body = bytearray()
    for index in chosen:
        body.append(0x01)
        push_u16(body, 0)
        push_u32(body, station.security[index] & 0xFFFFFFFF)
    if chosen == list(range(chosen[0], chosen[-1] + 1)):
        _append(built, bytes((121, 1, 0x00, chosen[0] & 0xFF, chosen[-1] & 0xFF)) + body)
        return
    items = []
    offset = 0
    for index in chosen:
        items.append((index, bytes(body[offset : offset + 7])))
        offset += 7
    _append(built, _header_indexed(121, 1, items))


def _unsol_class(station: Station, clazz: int) -> bool:
    return bool(station.unsol.get({1: "c1", 2: "c2", 3: "c3"}.get(clazz, ""), False))


def _apdu(seq: int, fc: int, iin1: int, iin2: int, objects: bytes, con: bool, uns: bool) -> bytes:
    ctrl = 0xC0 | (0x20 if con else 0) | (0x10 if uns else 0) | (seq & 0x0F)
    return bytes((ctrl, fc, iin1 & 0xFF, iin2 & 0xFF)) + objects


def _primary(station: Station, dest: int, apdu: bytes, now: int) -> bytes:
    """Split one application fragment into transport segments, one link frame each."""
    frames = bytearray()
    chunks = [apdu[i : i + SEGMENT] for i in range(0, len(apdu), SEGMENT)] or [b""]
    for n, chunk in enumerate(chunks):
        seq = station.tx_transport & 0x3F
        station.tx_transport = (station.tx_transport + 1) & 0x3F
        header = (0x40 if n == 0 else 0) | (0x80 if n == len(chunks) - 1 else 0)
        # FIR is bit 6 and FIN is bit 7 of the transport header.
        frames.extend(encode_frame(0x44, dest, station.outstation, bytes((header | seq,)) + chunk))
    summary, _detail, ok = describe_user(bytes((0xC0,)) + apdu)
    if len(chunks) > 1:
        summary += f"  ({len(chunks)} segments, {len(apdu)} octets)"
    _log(station, "out", summary, "", to_hex(frames), ok, now)
    return bytes(frames)


def _secondary(station: Station, dest: int, func: int, now: int) -> bytes:
    frame = encode_frame(func & 0x0F, dest, station.outstation, b"")
    summary, detail, ok = describe_frame(frame)
    _log(station, "out", summary, detail, to_hex(frame), ok, now)
    return frame


def _log(station: Station, direction: str, summary: str, detail: str, hex_text: str, ok: bool, time: int) -> None:
    from bayline.station import LogItem

    station.log.append(LogItem(station.next_log_id, time, direction, summary, detail, hex_text, ok))
    station.next_log_id += 1
    if len(station.log) > 250:
        del station.log[: len(station.log) - 250]


def _u16(data: bytes, offset: int) -> int:
    return data[offset] | (data[offset + 1] << 8)


def _u32(data: bytes, offset: int) -> int:
    return read_uint(data, offset, 4)


def _sized(group: int, variation: int, body: bytes) -> bytes:
    return bytes((group, variation, 0x5B, 1, len(body) & 0xFF, (len(body) >> 8) & 0xFF)) + body




def _auth_response(station: Station, seq: int, objects: bytes) -> bytes:
    i1, i2 = live_iin(station)
    return _apdu(seq, FC_AUTH_RESPONSE, i1, i2, objects, False, False)


def _auth_fail(station: Station, seq: int, user: int, code: int, text: str, now: int, seq_field: int = 0) -> list[bytes]:
    station.sav5.fail_count += 1
    station.sav5.last_error = code
    station.sav5.last_result = text
    station.sav5.error_burst += 1
    if station.sav5.error_burst > station.sav5.max_error_messages:
        _log(station, "note", "Authentication error suppressed", text, "", False, now)
        return []
    _stat(station, 10, now)
    if code == ERR_AUTHORIZATION:
        _stat(station, 1, now)
    elif code in (ERR_AUTH_FAILED, ERR_CERTIFICATION, ERR_SIGNATURE):
        _stat(station, 2, now)
    elif code == ERR_UNEXPECTED:
        _stat(station, 0, now)
    _log(station, "note", f"{auth_profile(station.sav5).label} {ERR_NAME.get(code, 'error')}", text, "", False, now)
    body = bytearray()
    push_u32(body, seq_field)
    push_u16(body, user)
    push_u16(body, station.master)
    push_u8(body, code)
    push_time48(body, outstation_now(station, now))
    body.extend(ord(ch) & 0x7F for ch in text)
    return [_auth_response(station, seq, _sized(120, 7, bytes(body)))]


def _status_echo_ok(echoed: bytes, status: bytes, mac: bytes) -> bool:
    if status and echoed.startswith(status):
        return True
    full = status + mac
    return bool(full) and echoed.startswith(full)


def _key_status(station: Station, user: SaUser) -> bytes:
    profile = auth_profile(station.sav5, user)
    os = user.os
    data = bytearray()
    push_u32(data, os.ksq)
    push_u16(data, user.number)
    push_u8(data, profile.kwa)
    push_u8(data, os.status)
    push_u8(data, profile.mal if os.status == KEY_OK and len(os.last_status_mac) == profile.mac_len else 0)
    push_u16(data, len(os.key_challenge))
    data.extend(os.key_challenge)
    os.last_key_status = bytes(data)
    mac = os.last_status_mac if data[8] else b""
    return _sized(120, 5, bytes(data) + mac)


def _live_user(station: Station, number: int, now: int) -> SaUser | None:
    user = station.sav5.users.get(number)
    if user is None or user.expired(now):
        return None
    return user


def _clear_keys(user: SaUser) -> None:
    user.os.status = KEY_AUTH_FAIL
    user.os.control_key = b""
    user.os.monitor_key = b""
    user.os.last_status_mac = b""


def _auth_request(station: Station, apdu: ParsedApdu, user: bytes, now: int) -> list[bytes]:
    if apdu.uns:
        _stat(station, 9, now)
        _log(station, "note", "Authentication request with UNS set was discarded", "", "", False, now)
        return []
    first = next((obj for obj in apdu.objects if obj.group == 120), None)
    variation = first.variation if first else 0

    def raw(wanted: int) -> bytes | None:
        for obj in apdu.objects:
            if obj.group == 120 and obj.variation == wanted and obj.items:
                return obj.items[0].raw
        return None

    apdu_in = user[1:]
    body = raw(variation) or b""
    if variation == 4:
        return _on_key_status(station, apdu.seq, body, now)
    if variation == 6:
        return _on_key_change(station, apdu.seq, body, apdu_in, now)
    if variation == 2:
        return _on_reply(station, apdu.seq, body, now)
    if variation == 10:
        return _on_user_status_change(station, apdu.seq, body, now)
    if variation == 11:
        return _on_update_request(station, apdu.seq, body, now)
    if variation == 13:
        return _on_update_change(station, apdu.seq, body, raw(15), now)
    return _auth_fail(station, apdu.seq, 0, ERR_UNEXPECTED, "Authentication request was not a known g120 object.", now)


def _on_key_status(station: Station, seq: int, body: bytes, now: int) -> list[bytes]:
    number = _u16(body, 0) if len(body) >= 2 else 0
    user = _live_user(station, number, now)
    if user is None:
        return _auth_fail(station, seq, number, ERR_UNKNOWN_USER, f"User {number} has no update key on this outstation.", now)
    _expire_session(station, now)
    os = user.os
    if os.status == KEY_OK and os.key_status_count >= station.sav5.max_key_status_requests:
        _clear_keys(user)
        os.key_status_count = 0
        _stat(station, 4, now)
        station.sav5.last_result = f"User {number} session keys cleared after the key-status limit. The next key status lets the master rekey."
        _log(station, "note", "Key-status limit · session keys cleared", station.sav5.last_result, "", False, now)
    os.key_status_count += 1
    os.ksq = (os.ksq + 1) & 0xFFFFFFFF
    profile = auth_profile(station.sav5, user)
    if os.status == KEY_OK and os.last_key_change and os.monitor_key:
        os.last_status_mac = _mac(station, os.monitor_key, os.last_key_change)
    else:
        os.last_status_mac = b""
    os.key_challenge = random_bytes(profile.challenge_len)
    _log(station, "note", f"Key status user {number} KSQ {os.ksq}", "g120v5", "", True, now)
    return [_auth_response(station, seq, _key_status(station, user))]


def _on_key_change(station: Station, seq: int, body: bytes, apdu_in: bytes, now: int) -> list[bytes]:
    number = _u16(body, 4) if len(body) >= 6 else 0
    ksq = _u32(body, 0) if len(body) >= 4 else 0
    wrapped = body[6:] if len(body) >= 6 else b""
    user = _live_user(station, number, now)
    if user is None:
        return _auth_fail(station, seq, number, ERR_UNKNOWN_USER, f"User {number} has no update key on this outstation.", now, ksq)
    os = user.os
    profile = auth_profile(station.sav5, user)
    plain = aes_unwrap(update_key_material(station.sav5, user), wrapped)
    unwrapped = None
    status_ok = False
    if plain and len(plain) >= 2:
        key_len = plain[0] | (plain[1] << 8)
        control = plain[2 : 2 + key_len]
        monitor = plain[2 + key_len : 2 + key_len * 2]
        echoed = plain[2 + key_len * 2 :]
        sized = len(monitor) == key_len and profile.session_key_ok(control)
        status_ok = sized and _status_echo_ok(echoed, os.last_key_status, os.last_status_mac)
        if status_ok:
            unwrapped = (control, monitor)
    seq_ok = len(os.last_key_status) >= 4 and ksq == _u32(os.last_key_status, 0)
    if unwrapped is None or not seq_ok:
        _clear_keys(user)
        os.key_challenge = random_bytes(profile.challenge_len)
        station.sav5.pending = None
        station.sav5.fail_count += 1
        station.sav5.last_error = ERR_AUTH_FAILED
        station.sav5.last_result = (
            f"{profile.wrap_name} unwrap failed for user {number}. The wrapped key status does not match the last g120v5."
            if seq_ok
            else f"Key change sequence {ksq} does not match the last KSQ sent to user {number}."
        )
        _stat(station, 14, now)
        _stat(station, 4, now)
        _stat(station, 2, now)
        os.ksq = (os.ksq + 1) & 0xFFFFFFFF
        _log(station, "note", "Session key change rejected · AUTH_FAIL", station.sav5.last_result, "", False, now)
        return [_auth_response(station, seq, _key_status(station, user))]
    os.control_key, os.monitor_key = unwrapped
    os.last_key_change = apdu_in
    os.ksq = (os.ksq + 1) & 0xFFFFFFFF
    os.status = KEY_OK
    os.last_status_mac = _mac(station, os.monitor_key, apdu_in)
    os.key_challenge = random_bytes(profile.challenge_len)
    station.sav5.pending = None
    station.sav5.key_changes += 1
    _stat(station, 13, now)
    os.keys_at = now
    os.key_status_count = 0
    os.auth_count = 0
    station.sav5.error_burst = 0
    station.sav5.ok_count += 1
    station.sav5.last_error = 0
    station.sav5.last_result = f"Session keys installed for user {number} ({user.name}). KSQ {os.ksq}."
    _log(station, "note", f"Session keys installed · user {number} · KSQ {os.ksq}", f"g120v6 unwrapped with the {profile.wrap_name} update key.", "", True, now)
    return [_auth_response(station, seq, _key_status(station, user))]


def _mac(station: Station, key: bytes, message: bytes) -> bytes:
    profile = auth_profile(station.sav5)
    return session_mac(key, message, profile.mac_len, profile.sha1)


def _authorize(station: Station, user: SaUser, fc: int) -> bool:
    return role_permits(user.role, fc)


def _count_auth(station: Station, user: SaUser, now: int) -> None:
    sav = station.sav5
    sav.ok_count += 1
    sav.last_error = 0
    sav.challenges_rx += 1
    sav.last_user = user.number
    sav.last_auth_time = now
    sav.error_burst = 0
    _stat(station, 12, now)
    user.os.auth_count += 1
    if user.os.auth_count >= sav.max_auth_messages:
        _clear_keys(user)
        sav.last_result = f"User {user.number} reached the authentication count. Wrap a new pair."


def _on_reply(station: Station, seq: int, body: bytes, now: int) -> list[bytes]:
    sav = station.sav5
    if len(body) < 6:
        return _auth_fail(station, seq, 0, ERR_UNEXPECTED, "Reply did not match an open challenge.", now)
    csq, number, mac = _u32(body, 0), _u16(body, 4), body[6:]
    pending = sav.pending
    if pending is None:
        return _auth_fail(station, seq, number, ERR_UNEXPECTED, "Reply did not match an open challenge.", now, csq)
    sav.pending = None
    if csq != pending.csq:
        return _auth_fail(station, seq, number, ERR_UNEXPECTED, f"Reply CSQ {csq} does not match challenge CSQ {pending.csq}.", now, csq)
    user = _live_user(station, number, now)
    profile = auth_profile(sav, user)
    if user is None or user.os.status != KEY_OK or not profile.session_key_ok(user.os.control_key):
        return _auth_fail(station, seq, number, ERR_AUTH_FAILED, f"User {number} has no valid control-direction session key.", now, csq)
    expect = _mac(station, user.os.control_key, pending.challenge_apdu + pending.critical_apdu)
    if len(mac) != len(expect) or not same_bytes(expect, mac):
        return _auth_fail(station, seq, number, ERR_AUTH_FAILED, "HMAC mismatch. The critical request was discarded.", now, csq)
    _count_auth(station, user, now)
    fc = pending.critical_apdu[1] if len(pending.critical_apdu) > 1 else 0
    if not _authorize(station, user, fc):
        return _auth_fail(station, seq, number, ERR_AUTHORIZATION, f"User {number} ({user.name}, {user.role}) is not permitted to use {FC_NAME.get(fc, fc)}.", now, csq)
    sav.last_result = f"{profile.label} HMAC accepted from user {number} for CSQ {csq}. The held request is executing."
    _log(station, "note", f"{profile.label} HMAC accepted · CSQ {csq} · user {number}", "The MAC covers the challenge fragment and the critical fragment.", "", True, now)
    sav.bypass = True
    return process_app(station, bytes((0xC0,)) + pending.critical_apdu, now)


def _kcm_mac(method: int, key: bytes, *parts: bytes) -> bytes:
    sha1 = KEY_CHANGE_METHODS[method][2]
    return hmac.new(key, b"".join(parts), hashlib.sha1 if sha1 else hashlib.sha256).digest()


def _on_user_status_change(station: Station, seq: int, body: bytes, now: int) -> list[bytes]:
    sav = station.sav5
    if len(body) < 16:
        return _auth_fail(station, seq, 0, ERR_UNEXPECTED, "Malformed user status change.", now)
    method, operation, scs = body[0], body[1], _u32(body, 2)
    role_code, expiry = _u16(body, 6), _u16(body, 8)
    name_len, pub_len, cert_len = _u16(body, 10), _u16(body, 12), _u16(body, 14)
    if 16 + name_len + pub_len + cert_len != len(body):
        return _auth_fail(station, seq, 0, ERR_UNEXPECTED, "User status change lengths do not match the object size.", now, scs)
    name_raw = body[16 : 16 + name_len]
    cert = body[16 + name_len + pub_len :]
    if len(sav.authority_key) not in (16, 32):
        return _auth_fail(station, seq, 0, ERR_UK_METHOD, "No authority key is configured, so remote user management is off.", now, scs)
    if method not in KEY_CHANGE_METHODS:
        return _auth_fail(station, seq, 0, ERR_UK_METHOD, f"Key change method {method} is not permitted. This outstation accepts symmetric methods 3 and 4.", now, scs)
    fields = bytearray((operation,))
    push_u32(fields, scs)
    push_u16(fields, role_code)
    push_u16(fields, expiry)
    push_u16(fields, name_len)
    if not same_bytes(_kcm_mac(method, sav.authority_key, bytes(fields), name_raw), cert):
        return _auth_fail(station, seq, 0, ERR_CERTIFICATION, "User status change certification data does not match the authority key.", now, scs)
    if scs < sav.scs:
        return _auth_fail(station, seq, 0, ERR_CERTIFICATION, f"Status change sequence {scs} is older than the expected {sav.scs}.", now, scs)
    sav.scs = (scs + 1) & 0xFFFFFFFF
    sav.dirty = True
    name = name_raw.decode("ascii", "replace")
    role = ROLE_NAMES.get(role_code, f"Role {role_code}")
    existing = find_user_by_name(sav, name)
    if operation == 2:
        if existing is None:
            return _auth_fail(station, seq, 0, ERR_UNKNOWN_USER, f'User "{name}" does not exist.', now, scs)
        if existing.number == PROVISIONED_USER:
            return _auth_fail(station, seq, 0, ERR_UNKNOWN_USER, "User 1 is the default user and cannot be deleted remotely.", now, scs)
        del sav.users[existing.number]
        sav.status_changes.pop(name, None)
        sav.last_result = f'User {existing.number} "{name}" deleted by the authority.'
        _log(station, "note", f"User {existing.number} deleted", name, "", True, now)
        return [_auth_response(station, seq, b"")]
    if operation not in (1, 3):
        return _auth_fail(station, seq, 0, ERR_UNEXPECTED, f"User status operation {operation} is not defined.", now, scs)
    if operation == 3 and existing is None:
        return _auth_fail(station, seq, 0, ERR_UNKNOWN_USER, f'User "{name}" does not exist, so it cannot be changed.', now, scs)
    sav.status_changes[name] = PendingStatusChange(method, role, expiry, now)
    sav.last_result = f'User status change for "{name}" as {role} accepted. Waiting for the update key change.'
    _log(station, "note", f'User status change · "{name}" · {role}', f"SCS {scs}, method {method}.", "", True, now)
    return [_auth_response(station, seq, b"")]


def _on_update_request(station: Station, seq: int, body: bytes, now: int) -> list[bytes]:
    sav = station.sav5
    if len(body) < 5:
        return _auth_fail(station, seq, 0, ERR_UNEXPECTED, "Malformed update key change request.", now)
    method, name_len, cd_len = body[0], _u16(body, 1), _u16(body, 3)
    if 5 + name_len + cd_len != len(body) or cd_len < 4:
        return _auth_fail(station, seq, 0, ERR_UNEXPECTED, "Update key change request lengths do not match the object size.", now)
    if len(sav.authority_key) not in (16, 32):
        return _auth_fail(station, seq, 0, ERR_UK_METHOD, "No authority key is configured, so the update key cannot change on the wire.", now)
    if sav.version == 2:
        return _auth_fail(station, seq, 0, ERR_UK_METHOD, "SAv2 does not change the update key on the wire. Change it out of band.", now)
    if method not in KEY_CHANGE_METHODS:
        return _auth_fail(station, seq, 0, ERR_UK_METHOD, f"Update key change method {method} is not permitted. This outstation accepts symmetric methods 3 and 4.", now)
    name = body[5 : 5 + name_len].decode("ascii", "replace")
    change = sav.status_changes.get(name)
    if change is None:
        return _auth_fail(station, seq, 0, ERR_UNKNOWN_USER, f'No user status change is pending for "{name}".', now)
    if change.method != method:
        return _auth_fail(station, seq, 0, ERR_UK_METHOD, f"The status change for \"{name}\" named method {change.method}, not {method}.", now)
    existing = find_user_by_name(sav, name)
    number = existing.number if existing else next(n for n in range(1, 65535) if n not in sav.users)
    challenge = random_bytes(UK_CHALLENGE_LEN)
    sav.uk_ksq = (sav.uk_ksq + 1) & 0xFFFFFFFF
    sav.update_pending = PendingUpdateKey(sav.uk_ksq, number, name, method, body[5 + name_len :], challenge)
    _log(station, "note", f'Update key change reply · "{name}" · user {number}', "g120v12", "", True, now)
    reply = bytearray()
    push_u32(reply, sav.uk_ksq)
    push_u16(reply, number)
    push_u16(reply, len(challenge))
    reply.extend(challenge)
    return [_auth_response(station, seq, _sized(120, 12, bytes(reply)))]


def _on_update_change(station: Station, seq: int, body: bytes, mac_raw: bytes | None, now: int) -> list[bytes]:
    sav = station.sav5
    pending = sav.update_pending
    sav.update_pending = None
    if len(body) < 8 or pending is None or mac_raw is None:
        return _auth_fail(station, seq, 0, ERR_UNEXPECTED, "Update key change arrived without a pending g120v12 reply or without g120v15.", now)
    ksq, number, length = _u32(body, 0), _u16(body, 4), _u16(body, 6)
    encrypted = body[8 : 8 + length]
    if ksq != pending.ksq or number != pending.user:
        _stat(station, 16, now)
        return _auth_fail(station, seq, number, ERR_AUTH_FAILED, "Update key change sequence or user does not match the g120v12 reply.", now, ksq)
    change = sav.status_changes.get(pending.name)
    key_len = KEY_CHANGE_METHODS[pending.method][1]
    name_raw = pending.name.encode("ascii", "replace")
    plain = aes_unwrap(sav.authority_key, encrypted)
    ok = (
        change is not None
        and plain is not None
        and len(plain) >= len(name_raw) + key_len + len(pending.outstation_challenge)
        and plain[: len(name_raw)] == name_raw
        and same_bytes(plain[len(name_raw) + key_len : len(name_raw) + key_len + len(pending.outstation_challenge)], pending.outstation_challenge)
    )
    if not ok or plain is None or change is None:
        _stat(station, 16, now)
        return _auth_fail(station, seq, number, ERR_AUTH_FAILED, "The encrypted update key did not decrypt with the authority key, or the user name or challenge did not match.", now, ksq)
    new_key = plain[len(name_raw) : len(name_raw) + key_len]
    ids = bytearray()
    push_u32(ids, ksq)
    push_u16(ids, number)
    expect = _kcm_mac(pending.method, new_key, sav.outstation_name.encode("ascii", "replace"), pending.master_challenge, pending.outstation_challenge, bytes(ids))
    if not same_bytes(expect, mac_raw):
        _stat(station, 16, now)
        return _auth_fail(station, seq, number, ERR_SIGNATURE, "The master's update key confirmation MAC did not match.", now, ksq)
    del sav.status_changes[pending.name]
    expires = now + change.expiry_days * 86_400_000 if change.expiry_days else 0
    sav.users[number] = SaUser(number, pending.name, change.role, new_key, expires)
    sav.dirty = True
    sav.ok_count += 1
    sav.last_error = 0
    sav.last_result = f'User {number} "{pending.name}" ({change.role}) has a new update key. Session keys must be wrapped with it.'
    _stat(station, 15, now)
    _log(station, "note", f'Update key installed · user {number} · "{pending.name}"', f"Method {pending.method}, g120v13 and g120v15 accepted.", "", True, now)
    confirm = _kcm_mac(pending.method, new_key, name_raw, pending.outstation_challenge, pending.master_challenge, bytes(ids))
    return [_auth_response(station, seq, _sized(120, 15, confirm))]


def _needs_auth(station: Station, apdu: ParsedApdu) -> bool:
    groups = {obj.group for obj in apdu.objects if obj.group != 120}
    fc = apdu.fc
    if fc in (FC_CONFIRM, FC_READ, FC_AUTH_REQUEST, 23, 24):
        return False
    if fc == FC_WRITE and groups <= {50}:
        return station.sav5.policy.time_write
    return True


def _expire_session(station: Station, now: int) -> None:
    sav = station.sav5
    for user in sav.users.values():
        os = user.os
        if os.status != KEY_OK or not os.keys_at:
            continue
        if now - os.keys_at <= sav.session_lifetime_s * 1000:
            continue
        reset_user_session(user)
        _stat(station, 4, now)
        sav.last_result = f"User {user.number} session key lifetime elapsed. Wrap a new pair."


def _gate_critical(station: Station, apdu: ParsedApdu, user: bytes, now: int, critical: bool) -> list[bytes] | None:
    _expire_session(station, now)
    sav = station.sav5
    aggressive = next((o for o in apdu.objects if o.group == 120 and o.variation == 3), None)
    mac = next((o for o in apdu.objects if o.group == 120 and o.variation == 9), None)
    if aggressive or mac:
        if not sav.aggressive:
            return _auth_fail(station, apdu.seq, 0, ERR_AGGRESSIVE, "Aggressive mode is not enabled on this outstation.", now)
        if not apdu.objects or apdu.objects[0].group != 120 or apdu.objects[0].variation != 3:
            return _auth_fail(station, apdu.seq, 0, ERR_UNEXPECTED, "Aggressive mode requires g120v3 as the first object.", now)
        return _check_aggressive(station, apdu, user, aggressive, mac, now)
    if not critical:
        return None
    profile = auth_profile(sav)
    if not any(u.os.status == KEY_OK and not u.expired(now) for u in sav.users.values()):
        return _auth_fail(station, apdu.seq, 0, ERR_AUTH_FAILED, "No user has valid session keys. Send a key status request and a key change before this request.", now)
    csq = sav.csq & 0xFFFFFFFF
    sav.csq = (csq + 1) & 0xFFFFFFFF
    data = random_bytes(profile.challenge_len)
    body = bytearray()
    push_u32(body, csq)
    push_u16(body, 0)
    push_u8(body, profile.mal)
    push_u8(body, 1)
    body.extend(data)
    challenge = _auth_response(station, apdu.seq, _sized(120, 1, bytes(body)))
    sav.last_challenge = challenge
    sav.pending = PendingAuth(apdu.seq, csq, challenge, user[1:], now + sav.challenge_timeout_ms)
    sav.challenges_sent += 1
    _stat(station, 8, now)
    _log(station, "note", f"Challenged {FC_NAME.get(apdu.fc, apdu.fc)} · CSQ {csq}", "g120v1, reason CRITICAL. Any user with session keys may reply.", "", True, now)
    return [challenge]


def _check_aggressive(station: Station, apdu: ParsedApdu, user: bytes, aggressive: ParsedObject | None, mac_obj: ParsedObject | None, now: int) -> list[bytes] | None:
    _stat(station, 8, now)
    sav = station.sav5
    raw = aggressive.items[0].raw if aggressive and aggressive.items else b""
    mac = mac_obj.items[0].raw if mac_obj and mac_obj.items else b""
    if len(raw) < 6 or not mac:
        return _auth_fail(station, apdu.seq, 0, ERR_UNEXPECTED, "Aggressive mode needs both g120v3 and g120v9.", now)
    csq, number = _u32(raw, 0), _u16(raw, 4)
    who = _live_user(station, number, now)
    if who is None:
        return _auth_fail(station, apdu.seq, number, ERR_UNKNOWN_USER, f"Aggressive mode user {number} has no update key on this outstation.", now, csq)
    if who.os.status != KEY_OK or not auth_profile(sav, who).session_key_ok(who.os.control_key) or not sav.last_challenge:
        return _auth_fail(station, apdu.seq, number, ERR_AUTH_FAILED, "Aggressive mode needs a prior challenge and valid session keys for this user.", now, csq)
    if csq != (sav.csq & 0xFFFFFFFF):
        return _auth_fail(station, apdu.seq, number, ERR_UNEXPECTED, f"Aggressive CSQ {csq} is not {sav.csq}, one more than the last challenge.", now, csq)
    if not apdu.objects or apdu.objects[-1].group != 120 or apdu.objects[-1].variation != 9:
        return _auth_fail(station, apdu.seq, number, ERR_UNEXPECTED, "The MAC object was not at the end of the fragment.", now, csq)
    signed = user[1 : apdu.objects[-1].offset]
    expect = _mac(station, who.os.control_key, sav.last_challenge + signed)
    if len(mac) != len(expect) or not same_bytes(expect, mac):
        return _auth_fail(station, apdu.seq, number, ERR_AUTH_FAILED, "Aggressive-mode HMAC mismatch. The request was not executed.", now, csq)
    sav.csq = (csq + 1) & 0xFFFFFFFF
    _count_auth(station, who, now)
    if _needs_auth(station, apdu) and not _authorize(station, who, apdu.fc):
        return _auth_fail(station, apdu.seq, number, ERR_AUTHORIZATION, f"User {number} ({who.name}, {who.role}) is not permitted to use {FC_NAME.get(apdu.fc, apdu.fc)}.", now, csq)
    sav.last_result = f"Aggressive mode accepted from user {number} at CSQ {csq}."
    _log(station, "note", f"Aggressive mode accepted · CSQ {csq} · user {number}", "g120v3 plus g120v9.", "", True, now)
    return None
