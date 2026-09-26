"""Riverside 12 kV yard model so a polling master sees plausible, connected values.

Load follows the local time of day. The transformer tap and the capacitor bank set the bus
voltage, the automatic voltage regulator (90) steps the tap, oil and winding temperatures
follow the load, and a feeder fault runs a protection trip and reclose sequence.
"""

from __future__ import annotations

import math
import random
import time

from bayline.outstation import step_tap, write_point
from bayline.station import Point, Station, find_point

SQRT3 = 1.73205080757
NOMINAL_KV = 12.47
FEEDER_AMPS = {1: 210.0, 2: 160.0}
FEEDER_PF = {1: 0.95, 2: 0.94}
FAULT_AMPS = {1: 3150.0, 2: 2780.0}
CAP_KVAR = 1200.0
TAP_STEP = 0.00625
AVR_BAND = 0.01
AVR_DELAY_MS = 10_000
T1_RATED_KVA = 10_000.0
OIL_RISE = 42.0
WINDING_GRADIENT = 18.0
THERMAL_TAU_S = 240.0
OIL_ALARM = (95.0, 90.0)
WINDING_ALARM = (110.0, 105.0)
UNDERVOLTAGE_KV = 0.9 * NOMINAL_KV
RECLOSE_MS = (2_000, 5_000)
TRIP_MS = 150
ALARM_POINTS = (4, 5, 6, 7, 8, 11, 14, 15, 16, 18, 19)
LOCKOUT = {1: 7, 2: 18}
PICKUP = {1: 5, 2: 6}


def simulate(station: Station, now: int, dt_sec: float) -> None:
    if not station.sim_on:
        return
    dt = min(2.0, max(0.05, dt_sec))
    state = station.sim_state
    hour = _hour(now)
    state["wander"] = max(-0.05, min(0.05, state.get("wander", 0.0) + random.gauss(0, 0.004) * math.sqrt(dt)))
    load_pu = max(0.2, load_curve(hour) + state["wander"])

    t1 = _on(station, "bi", 0)
    feeders = {n: _on(station, "bi", n) and t1 for n in (1, 2)}
    cap = _on(station, "bi", 12) and t1
    tap = _value(station, "ai", 12, 0.0)
    fault = state.get("fault")

    amps = {n: FEEDER_AMPS[n] * load_pu if feeders[n] else 0.0 for n in (1, 2)}
    if fault and fault.get("on") and feeders[fault["feeder"]]:
        amps[fault["feeder"]] = FAULT_AMPS[fault["feeder"]] * random.uniform(0.97, 1.03)
    t1_pu = sum(amps.values()) / (T1_RATED_KVA / (SQRT3 * NOMINAL_KV))
    bus = 0.0
    if t1:
        bus = NOMINAL_KV * (1 + TAP_STEP * tap) * (1 - 0.035 * min(t1_pu, 1.5)) * (1.012 if cap else 1.0)
    cap_kvar = CAP_KVAR * (bus / NOMINAL_KV) ** 2 if cap else 0.0

    _ease(station, 0, bus, 0.004, now)
    for n in (1, 2):
        stepped = not feeders[n] or bool(fault and fault.get("feeder") == n)
        _ease(station, n, amps[n], 0.6, now, rate=1.0 if stepped else 0.28)
        _ease(station, 9 + n, _setpoint(station, n - 1) if feeders[n] else 0.0, 0.004, now)
    _ease(station, 5, 50.12, 0.004, now)
    _ease(station, 13, cap_kvar, 2.0, now, rate=0.5)

    kw_total = kvar_total = 0.0
    for n in (1, 2):
        pf = FEEDER_PF[n] + 0.015 * math.sin(2 * math.pi * (hour - 6 + n) / 24)
        volts = _value(station, "ai", 9 + n, 0.0)
        current = max(0.0, _value(station, "ai", n, 0.0))
        kw = SQRT3 * volts * current * pf if feeders[n] else 0.0
        kw_total += kw
        kvar_total += kw * math.tan(math.acos(pf))
        _ease(station, 6 + n, kw, 6, now)
        _ease(station, 13 + n, pf if feeders[n] else 0.0, 0.002, now)
    _ease(station, 3, kw_total, 10, now)
    _ease(station, 4, max(0.0, kvar_total - _value(station, "ai", 13, 0.0)), 6, now)

    _thermal(station, hour, t1_pu, dt, now)
    _battery(station, dt, now)
    _avr(station, bus, t1, now)
    _energy(station, dt, now)
    if fault:
        _fault_step(station, fault, now)
    _alarms(station, now)


def load_curve(hour: float) -> float:
    """Per-unit feeder load for a weekday: a night trough, a morning ramp, and an evening peak."""
    morning = 0.20 * math.exp(-(((hour - 8.5) / 2.2) ** 2))
    evening = 0.30 * math.exp(-(((hour - 19.0) / 2.6) ** 2))
    night = 0.14 * math.exp(-(((hour - 3.5) / 3.0) ** 2))
    return 0.70 + morning + evening - night


def start_fault(station: Station, feeder: int, permanent: bool, now: int) -> str | None:
    if feeder not in (1, 2):
        return "Pick feeder 1 or 2."
    if not (_on(station, "bi", feeder) and _on(station, "bi", 0)):
        return f"Feeder {feeder} is not energised."
    if station.sim_state.get("fault"):
        return "A fault sequence is already running."
    station.sim_state["fault"] = {"feeder": feeder, "permanent": permanent, "stage": "pickup", "at": now, "shots": 0, "on": True}
    return None


def _fault_step(station: Station, fault: dict, now: int) -> None:
    feeder = fault["feeder"]
    breaker = find_point(station, "bi", feeder)
    pickup = find_point(station, "bi", PICKUP[feeder])
    if breaker is None or pickup is None:
        station.sim_state.pop("fault", None)
        return
    if not _on(station, "bi", 0):
        station.sim_state.pop("fault", None)
        return
    stage, since = fault["stage"], now - fault["at"]
    if stage == "pickup":
        _set(station, pickup, 1, now)
        record = find_point(station, "ai", 17 + feeder)
        if record:
            write_point(station, record, FAULT_AMPS[feeder] * random.uniform(0.97, 1.03), record.flags, now, "control")
        fault.update(stage="trip", at=now)
    elif stage == "trip" and since >= TRIP_MS:
        _set(station, breaker, 0, now)
        _set(station, pickup, 0, now)
        counter = find_point(station, "ctr", 1 + feeder)
        if counter:
            write_point(station, counter, counter.value + 1, counter.flags, now, "control")
        fault.update(on=False, at=now)
        if fault["shots"] >= len(RECLOSE_MS):
            lockout = find_point(station, "bi", LOCKOUT[feeder])
            if lockout:
                _set(station, lockout, 1, now)
            station.sim_state.pop("fault", None)
        else:
            fault["stage"] = "open"
    elif stage == "open" and since >= RECLOSE_MS[fault["shots"]]:
        fault["shots"] += 1
        _set(station, breaker, 1, now)
        if fault["permanent"]:
            fault.update(stage="pickup", at=now, on=True)
        else:
            station.sim_state.pop("fault", None)


def _thermal(station: Station, hour: float, t1_pu: float, dt: float, now: int) -> None:
    ambient = 22 + 6 * math.sin(2 * math.pi * (hour - 9) / 24)
    _ease(station, 16, ambient, 0.05, now)
    ambient = _value(station, "ai", 16, ambient)
    ratio = 6.0
    oil_target = ambient + OIL_RISE * ((t1_pu**2 * ratio + 1) / (ratio + 1)) ** 0.9
    oil = find_point(station, "ai", 6)
    if oil and not oil.manual:
        step = (oil_target - oil.value) * (1 - math.exp(-dt / THERMAL_TAU_S))
        write_point(station, oil, oil.value + step + random.gauss(0, 0.02), oil.flags, now, "sim")
    winding = find_point(station, "ai", 17)
    if winding and not winding.manual:
        target = _value(station, "ai", 6, oil_target) + WINDING_GRADIENT * max(0.0, t1_pu) ** 1.6
        write_point(station, winding, winding.value + (target - winding.value) * min(1.0, dt / 30), winding.flags, now, "sim")


def _battery(station: Station, dt: float, now: int) -> None:
    battery = find_point(station, "ai", 9)
    if not battery or battery.manual:
        return
    if _on(station, "bi", 14):
        write_point(station, battery, max(105.0, battery.value - 0.02 * dt), battery.flags, now, "sim")
    else:
        _ease(station, 9, 125.4, 0.04, now)


def _avr(station: Station, bus: float, t1: bool, now: int) -> None:
    state = station.sim_state
    if not t1 or not _on(station, "bi", 13) or bus <= 0:
        state.pop("avr_since", None)
        return
    error = bus / NOMINAL_KV - 1
    if abs(error) <= AVR_BAND:
        state.pop("avr_since", None)
        return
    since = state.setdefault("avr_since", now)
    if now - since < AVR_DELAY_MS:
        return
    step = -1 if error > 0 else 1
    if -16 <= _value(station, "ai", 12, 0.0) + step <= 16:
        step_tap(station, step, now)
    state["avr_since"] = now


def _energy(station: Station, dt: float, now: int) -> None:
    hours = dt * station.energy_scale / 3600
    for load_index, counter_index in ((7, 0), (8, 1), (4, 6)):
        load = find_point(station, "ai", load_index)
        counter = find_point(station, "ctr", counter_index)
        if load and counter and not counter.manual:
            write_point(station, counter, counter.value + max(0.0, load.value) * hours, counter.flags, now, "sim")


def _alarms(station: Station, now: int) -> None:
    _derive(station, 4, _value(station, "ai", 0, NOMINAL_KV) < UNDERVOLTAGE_KV, now)
    _hysteresis(station, 11, _value(station, "ai", 6, 0.0), OIL_ALARM, now)
    _hysteresis(station, 19, _value(station, "ai", 17, 0.0), WINDING_ALARM, now)
    relay = find_point(station, "bi", 17)
    active = any(_on(station, "bi", index) for index in ALARM_POINTS) or bool(relay and relay.value < 0.5)
    _derive(station, 9, active, now)


def _derive(station: Station, index: int, on: bool, now: int) -> None:
    point = find_point(station, "bi", index)
    if point and not point.manual and (point.value >= 0.5) != on:
        write_point(station, point, 1 if on else 0, point.flags, now, "sim")


def _hysteresis(station: Station, index: int, value: float, limits: tuple[float, float], now: int) -> None:
    point = find_point(station, "bi", index)
    if point is None or point.manual:
        return
    if point.value < 0.5 and value >= limits[0]:
        write_point(station, point, 1, point.flags, now, "sim")
    elif point.value >= 0.5 and value <= limits[1]:
        write_point(station, point, 0, point.flags, now, "sim")


def _set(station: Station, point: Point, value: float, now: int) -> None:
    if (point.value >= 0.5) != (value >= 0.5):
        write_point(station, point, value, point.flags, now, "control")


def _ease(station: Station, index: int, target: float, jitter: float, now: int, rate: float = 0.28) -> None:
    point = find_point(station, "ai", index)
    if not point or point.manual:
        return
    nxt = point.value + (target - point.value) * rate + (random.random() - 0.5) * jitter
    if target == 0 and abs(nxt) < jitter:
        nxt = 0.0
    write_point(station, point, nxt, point.flags, now, "sim")


def _setpoint(station: Station, index: int) -> float:
    point = find_point(station, "ao", index)
    if point and 10.5 <= point.value <= 14.4:
        return point.value
    return NOMINAL_KV


def _value(station: Station, kind: str, index: int, default: float) -> float:
    point = find_point(station, kind, index)
    return point.value if point else default


def _on(station: Station, kind: str, index: int) -> bool:
    point = find_point(station, kind, index)
    return bool(point and point.value >= 0.5)


def _hour(now: int) -> float:
    local = time.localtime(now / 1000)
    return local.tm_hour + local.tm_min / 60 + local.tm_sec / 3600
