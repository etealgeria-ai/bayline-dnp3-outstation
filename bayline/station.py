"""Riverside 12 kV point database and SAv5 session."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from bayline.crypto import UPDATE_KEY_LEN

BI_ONLINE = 0x01
BI_STATE = 0x80
AI_ONLINE = 0x01
CTR_ONLINE = 0x01
RESTART_FLAG = 0x02
PROVISIONED_USER = 1
KEY_OK = 1
KEY_NOT_INIT = 2
KEY_AUTH_FAIL = 4
ERR_AUTH_FAILED = 1
ERR_UNEXPECTED = 2
ERR_AGGRESSIVE = 4
ERR_MAC_ALGO = 5
ERR_AUTHORIZATION = 7
ERR_UK_METHOD = 8
ERR_SIGNATURE = 9
ERR_CERTIFICATION = 10
ERR_UNKNOWN_USER = 11
ERR_KEY_STATUS_LIMIT = 12
MAX_KEY_STATUS_REQUESTS = 2
CRITICAL = {2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 25, 26, 27, 28, 29, 30, 31}

# IEEE 1815-2012 MAC algorithms: code -> (name, octets, uses SHA-1). Code 6 (AES-GMAC) is not offered.
MAC_ALGORITHMS = {
    1: ("HMAC-SHA-1-4", 4, True),
    2: ("HMAC-SHA-1-10", 10, True),
    3: ("HMAC-SHA-256-8", 8, False),
    4: ("HMAC-SHA-256-16", 16, False),
    5: ("HMAC-SHA-1-8", 8, True),
}
# Symmetric update-key change methods: code -> (name, update key octets, uses SHA-1 for the MACs).
KEY_CHANGE_METHODS = {
    3: ("AES-128 / SHA-1-HMAC", 16, True),
    4: ("AES-256 / SHA-256-HMAC", 32, False),
}

# IEC 62351-8 role codes carried in g120v10.
ROLE_CODES = {
    "Viewer": 0,
    "Operator": 1,
    "Engineer": 2,
    "Installer": 3,
    "SECADM": 4,
    "SECAUD": 5,
    "RBACMNT": 6,
    "Single user": 32768,
}
ROLE_NAMES = {code: name for name, code in ROLE_CODES.items()}

_CONTROLS = {3, 4, 5, 6}
_FREEZES = {7, 8, 9, 10, 11, 12}
_UNSOL = {20, 21}
_CONFIG = {2, 13, 14, 15, 16, 17, 18, 19, 22, 25, 26, 27, 28, 29, 30, 31}
# Critical function codes each role may run once it has authenticated. Reads are never critical.
ROLE_PERMISSIONS = {
    "Viewer": set(),
    "Operator": _CONTROLS | _FREEZES | _UNSOL | {2},
    "Engineer": _CONFIG | _FREEZES | _UNSOL,
    "Installer": _CONFIG | _FREEZES | _UNSOL,
    "SECADM": set(),
    "SECAUD": set(),
    "RBACMNT": set(),
    "Single user": set(CRITICAL),
}


def role_permits(role: str, fc: int) -> bool:
    return fc in ROLE_PERMISSIONS.get(role, set())


@dataclass
class Point:
    kind: str
    index: int
    name: str
    units: str
    value: float
    flags: int
    clazz: int
    deadband: float
    static_var: int
    event_var: int
    last_event_value: float
    last_flags: int
    feedback: int | None = None
    op_counter: int | None = None
    frozen: float | None = None
    manual: bool = False
    labels: tuple[str, str] | None = None
    action: str | None = None


@dataclass
class DnpEvent:
    id: int
    kind: str
    index: int
    value: float
    flags: int
    time: int
    clazz: int
    variation: int
    held: bool = False


@dataclass
class SelectArm:
    group: int
    variation: int
    index: int
    body: bytes
    deadline: int
    items: list[tuple[int, int, int, bytes]] = field(default_factory=list)


@dataclass
class PendingConfirm:
    seq: int
    unsol: bool
    event_ids: list[int]
    deadline: int


@dataclass
class OsSession:
    status: int = KEY_NOT_INIT
    ksq: int = 0
    control_key: bytes = b""
    monitor_key: bytes = b""
    key_challenge: bytes = b""
    last_status_mac: bytes = b""
    keys_at: int = 0
    key_status_count: int = 0
    auth_count: int = 0
    last_key_status: bytes = b""
    last_key_change: bytes = b""


@dataclass
class SaUser:
    number: int
    name: str
    role: str
    update_key: bytes
    expires: int = 0
    os: OsSession = field(default_factory=OsSession)

    def expired(self, now: int) -> bool:
        return bool(self.expires) and now > self.expires


@dataclass
class PendingAuth:
    seq: int
    csq: int
    challenge_apdu: bytes
    critical_apdu: bytes
    deadline: int


@dataclass
class PendingStatusChange:
    method: int
    role: str
    expiry_days: int
    received: int


@dataclass
class PendingUpdateKey:
    ksq: int
    user: int
    name: str
    method: int
    master_challenge: bytes
    outstation_challenge: bytes


@dataclass
class AuthPolicy:
    controls: bool = True
    crob: bool = True
    analog: bool = True
    direct_operate: bool = True
    direct_operate_nr: bool = True
    select_operate: bool = True
    cold_restart: bool = True
    warm_restart: bool = True
    unsolicited: bool = True
    assign_class: bool = True
    initialize: bool = True
    time_write: bool = False
    file_transfer: bool = True


def _default_users() -> dict[int, SaUser]:
    return {PROVISIONED_USER: SaUser(PROVISIONED_USER, "Common", "Single user", os.urandom(UPDATE_KEY_LEN))}


@dataclass
class Sav5:
    enabled: bool = True
    version: int = 5
    aggressive: bool = False
    mal: int = 4
    users: dict[int, SaUser] = field(default_factory=_default_users)
    csq: int = 1
    last_challenge: bytes = b""
    pending: PendingAuth | None = None
    bypass: bool = False
    policy: AuthPolicy = field(default_factory=AuthPolicy)
    challenge_timeout_ms: int = 5000
    session_lifetime_s: int = 3600
    max_key_status_requests: int = MAX_KEY_STATUS_REQUESTS
    max_auth_messages: int = 1000
    max_error_messages: int = 5
    error_burst: int = 0
    outstation_name: str = "Riverside 12 kV"
    authority_key: bytes = b""
    scs: int = 0
    uk_ksq: int = 0
    status_changes: dict[str, PendingStatusChange] = field(default_factory=dict)
    update_pending: PendingUpdateKey | None = None
    dirty: bool = False
    ok_count: int = 0
    fail_count: int = 0
    challenges_sent: int = 0
    challenges_rx: int = 0
    key_changes: int = 0
    last_error: int = 0
    last_user: int = 0
    last_auth_time: int = 0
    last_result: str = "SAv5 selected. Session keys are not initialized."

    def default(self) -> SaUser:
        user = self.users.get(PROVISIONED_USER)
        if user is None:
            user = next(iter(self.users.values()), None) or SaUser(PROVISIONED_USER, "Common", "Single user", os.urandom(UPDATE_KEY_LEN))
        return user

    @property
    def user(self) -> int:
        return self.default().number

    @property
    def role(self) -> str:
        return self.default().role

    @property
    def os(self) -> OsSession:
        return self.default().os

    @property
    def update_key(self) -> bytes:
        return self.default().update_key

    @update_key.setter
    def update_key(self, key: bytes) -> None:
        user = self.users.get(PROVISIONED_USER)
        if user is None:
            self.users[PROVISIONED_USER] = SaUser(PROVISIONED_USER, "Common", "Single user", key)
        else:
            user.update_key = key


@dataclass
class AuthProfile:
    version: int
    mal: int
    mac_len: int
    sha1: bool
    kwa: int
    wrap_len: int
    challenge_len: int
    label: str
    mac_name: str
    wrap_name: str

    def session_key_ok(self, key: bytes) -> bool:
        return len(key) == 16 if self.version == 2 else 16 <= len(key) <= 32


def auth_profile(sav: Sav5, user: SaUser | None = None) -> AuthProfile:
    if sav.version == 2:
        return AuthProfile(2, 5, 8, True, 1, 16, 8, "SAv2", "HMAC-SHA-1-8", "AES-128")
    name, length, sha1 = MAC_ALGORITHMS.get(sav.mal, MAC_ALGORITHMS[4])
    key = (user or sav.default()).update_key
    kwa = 1 if len(key) == 16 else 2
    return AuthProfile(5, sav.mal if sav.mal in MAC_ALGORITHMS else 4, length, sha1, kwa, len(key), 16, "SAv5", name, "AES-128" if kwa == 1 else "AES-256")


def update_key_material(sav: Sav5, user: SaUser | None = None) -> bytes:
    key = (user or sav.default()).update_key
    return key[:16] if sav.version == 2 else key


def find_user_by_name(sav: Sav5, name: str) -> SaUser | None:
    return next((user for user in sav.users.values() if user.name == name), None)


@dataclass
class LogItem:
    id: int
    time: int
    direction: str
    summary: str
    detail: str
    hex: str
    ok: bool


@dataclass
class Station:
    name: str = "Riverside 12 kV"
    location: str = "Riverside Substation"
    outstation: int = 4
    master: int = 100
    link_reset: bool = False
    expect_fcb: bool = True
    unsol_seq: int = 0
    tx_transport: int = 0
    restart: bool = True
    need_time: bool = True
    trouble: bool = False
    local: bool = False
    overflow: bool = False
    time_offset: int = 0
    select: SelectArm | None = None
    pending_confirm: PendingConfirm | None = None
    unsol: dict[str, bool] = field(default_factory=lambda: {"c1": False, "c2": False, "c3": False})
    confirm_timeout: int = 8000
    select_timeout: int = 10000
    event_max: int = 80
    proc_delay: int = 18
    energy_scale: float = 4
    points: list[Point] = field(default_factory=list)
    events: list[DnpEvent] = field(default_factory=list)
    next_event_id: int = 1
    log: list[LogItem] = field(default_factory=list)
    next_log_id: int = 1
    sim_on: bool = True
    scenario: str = "normal"
    scenario_since: int = 0
    fault_stage: int = 0
    sav5: Sav5 = field(default_factory=Sav5)
    sim_state: dict = field(default_factory=dict)
    security: list[int] = field(default_factory=lambda: [0] * 18)
    security_sent: list[int] = field(default_factory=lambda: [0] * 18)


def _flags(kind: str, closed: bool) -> int:
    if kind in ("bi", "bo"):
        return (BI_ONLINE | (BI_STATE if closed else 0)) | RESTART_FLAG
    if kind == "ctr":
        return CTR_ONLINE | RESTART_FLAG
    return AI_ONLINE | RESTART_FLAG


def _point(kind, index, name, value, units, clazz, deadband, static_var, event_var, feedback=None, op_counter=None, labels=None, action=None) -> Point:
    flags = _flags(kind, value >= 0.5)
    return Point(kind, index, name, units, value, flags, clazz, deadband, static_var, event_var, value, flags, feedback, op_counter, labels=labels, action=action)


BREAKER = ("Open", "Closed")
ALARM = ("Normal", "Alarm")


def create_station() -> Station:
    rows = [
        _point("bi", 0, "52-T1 transformer breaker", 1, "", 1, 0, 2, 2, labels=BREAKER),
        _point("bi", 1, "52-F1 feeder breaker", 1, "", 1, 0, 2, 2, labels=BREAKER),
        _point("bi", 2, "52-F2 feeder breaker", 1, "", 1, 0, 2, 2, labels=BREAKER),
        _point("bi", 3, "89-BS bus tie", 1, "", 1, 0, 2, 2, labels=BREAKER),
        _point("bi", 4, "27 bus undervoltage", 0, "", 1, 0, 2, 2, labels=ALARM),
        _point("bi", 5, "50-F1 instantaneous OC", 0, "", 1, 0, 2, 2, labels=("Normal", "Picked up")),
        _point("bi", 6, "50-F2 instantaneous OC", 0, "", 1, 0, 2, 2, labels=("Normal", "Picked up")),
        _point("bi", 7, "79-F1 recloser lockout", 0, "", 1, 0, 2, 2, labels=("Normal", "Lockout")),
        _point("bi", 8, "63-T1 sudden pressure", 0, "", 1, 0, 2, 2, labels=ALARM),
        _point("bi", 9, "Station alarm", 0, "", 1, 0, 2, 2, labels=ALARM),
        _point("bi", 10, "Remote / local", 1, "", 1, 0, 2, 2, labels=("Local", "Remote")),
        _point("bi", 11, "T1 high oil temperature", 0, "", 1, 0, 2, 2, labels=ALARM),
        _point("bi", 12, "52-C1 capacitor bank breaker", 0, "", 1, 0, 2, 2, labels=BREAKER),
        _point("bi", 13, "90 tap changer in auto", 1, "", 1, 0, 2, 2, labels=("Manual", "Auto")),
        _point("bi", 14, "Battery charger fail", 0, "", 1, 0, 2, 2, labels=ALARM),
        _point("bi", 15, "Control house door open", 0, "", 1, 0, 2, 2, labels=("Closed", "Open")),
        _point("bi", 16, "52-F1 SF6 low pressure", 0, "", 1, 0, 2, 2, labels=ALARM),
        _point("bi", 17, "Protection relay healthy", 1, "", 1, 0, 2, 2, labels=("Failed", "Healthy")),
        _point("bi", 18, "79-F2 recloser lockout", 0, "", 1, 0, 2, 2, labels=("Normal", "Lockout")),
        _point("bi", 19, "T1 high winding temperature", 0, "", 1, 0, 2, 2, labels=ALARM),
        _point("bo", 0, "52-T1 control", 1, "", 0, 0, 2, 2, feedback=0),
        _point("bo", 1, "52-F1 control", 1, "", 0, 0, 2, 2, feedback=1, op_counter=2),
        _point("bo", 2, "52-F2 control", 1, "", 0, 0, 2, 2, feedback=2, op_counter=3),
        _point("bo", 3, "89-BS control", 1, "", 0, 0, 2, 2, feedback=3),
        _point("bo", 4, "52-C1 capacitor control", 0, "", 0, 0, 2, 2, feedback=12, op_counter=5),
        _point("bo", 5, "90 tap raise", 0, "", 0, 0, 2, 2, action="tap_up"),
        _point("bo", 6, "90 tap lower", 0, "", 0, 0, 2, 2, action="tap_down"),
        _point("bo", 7, "90 auto / manual", 1, "", 0, 0, 2, 2, feedback=13),
        _point("bo", 8, "79 lockout reset", 0, "", 0, 0, 2, 2, action="reset_79"),
        _point("ai", 0, "Bus voltage", 12.47, "kV", 2, 0.08, 5, 5),
        _point("ai", 1, "Feeder 1 current", 186, "A", 2, 10, 5, 5),
        _point("ai", 2, "Feeder 2 current", 142, "A", 2, 10, 5, 5),
        _point("ai", 3, "Transformer load", 6726, "kW", 2, 250, 5, 5),
        _point("ai", 4, "Transformer reactive", 2210, "kVAr", 2, 120, 5, 5),
        _point("ai", 5, "Frequency", 50.12, "Hz", 2, 0.03, 5, 7),
        _point("ai", 6, "T1 oil temperature", 58, "°C", 2, 1.5, 5, 5),
        _point("ai", 7, "Feeder 1 load", 3816, "kW", 2, 160, 5, 5),
        _point("ai", 8, "Feeder 2 load", 2910, "kW", 2, 160, 5, 5),
        _point("ai", 9, "Battery", 125.4, "VDC", 2, 0.8, 5, 5),
        _point("ai", 10, "Feeder 1 voltage", 12.47, "kV", 2, 0.05, 5, 5),
        _point("ai", 11, "Feeder 2 voltage", 12.47, "kV", 2, 0.05, 5, 5),
        _point("ai", 12, "T1 tap position", 0, "", 2, 0.5, 5, 5),
        _point("ai", 13, "Capacitor bank reactive", 0, "kVAr", 2, 60, 5, 5),
        _point("ai", 14, "Feeder 1 power factor", 0.95, "", 2, 0.01, 5, 5),
        _point("ai", 15, "Feeder 2 power factor", 0.94, "", 2, 0.01, 5, 5),
        _point("ai", 16, "Ambient temperature", 22, "°C", 2, 0.5, 5, 5),
        _point("ai", 17, "T1 winding temperature", 66, "°C", 2, 1.5, 5, 5),
        _point("ai", 18, "Feeder 1 last fault current", 0, "A", 2, 50, 5, 5),
        _point("ai", 19, "Feeder 2 last fault current", 0, "A", 2, 50, 5, 5),
        _point("ctr", 0, "Feeder 1 energy", 184320, "kWh", 3, 50, 1, 1),
        _point("ctr", 1, "Feeder 2 energy", 142110, "kWh", 3, 50, 1, 1),
        _point("ctr", 2, "Feeder 1 operations", 146, "", 3, 1, 1, 5),
        _point("ctr", 3, "Feeder 2 operations", 121, "", 3, 1, 1, 5),
        _point("ctr", 4, "T1 tap operations", 3812, "", 3, 1, 1, 5),
        _point("ctr", 5, "52-C1 operations", 57, "", 3, 1, 1, 5),
        _point("ctr", 6, "T1 reactive energy", 61240, "kVArh", 3, 50, 1, 1),
        _point("ao", 0, "Feeder 1 regulator setpoint", 12.47, "kV", 0, 0.01, 3, 5),
        _point("ao", 1, "Feeder 2 regulator setpoint", 12.47, "kV", 0, 0.01, 3, 5),
    ]
    station = Station(points=rows)
    station.security[17] = 1
    station.security_sent[17] = 1
    return station


def find_point(station: Station, kind: str, index: int) -> Point | None:
    for point in station.points:
        if point.kind == kind and point.index == index:
            return point
    return None


def points_of(station: Station, kind: str) -> list[Point]:
    return sorted((p for p in station.points if p.kind == kind), key=lambda p: p.index)


def sync_binary_flag(point: Point) -> None:
    if point.kind not in ("bi", "bo"):
        return
    if point.value >= 0.5:
        point.flags |= BI_STATE
    else:
        point.flags &= ~BI_STATE


def outstation_now(station: Station, now: int) -> int:
    return now + station.time_offset


def reset_user_session(user: SaUser) -> None:
    user.os = OsSession(ksq=user.os.ksq)


def reset_session_keys(sav: Sav5) -> None:
    for user in sav.users.values():
        reset_user_session(user)
    sav.pending = None
    sav.update_pending = None
    sav.last_challenge = b""
    sav.bypass = False


def is_critical(fc: int) -> bool:
    return fc in CRITICAL
