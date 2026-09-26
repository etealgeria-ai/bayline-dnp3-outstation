# Bayline DNP3 outstation Simulator

Python DNP3 outstation only. No built-in master. Listens on TCP port 20000 for your master.

```powershell
py -3.14 -m pip install -r requirements.txt
py -3.14 outstation.py
```

The window has Points, Trend, Comms, Wire, and Security. A master on this PC uses `127.0.0.1`, port `20000`, outstation address `4`, master address `100`.

`py -3.14 outstation.py --headless` listens without the window. Add `--trace` to print every frame.

## Options

| Option | Meaning |
| --- | --- |
| `--port`, `--host`, `--allow-ip` | Where to listen and who may connect |
| `--update-key HEX` | User 1 update key. 16 octets selects AES-128 key wrap, 32 selects AES-256 |
| `--update-key-file PATH` | Where user 1's key is kept. Default `bayline-update-key.hex` |
| `--sa-file PATH` | Users 2 and up, the authority key, and the MAC choice. Default `bayline-sav5.json` beside the key file |
| `--authority-key HEX` | Turns on remote user management and update-key change |
| `--mac N` | SAv5 MAC: 1 HMAC-SHA-1-4, 2 HMAC-SHA-1-10, 3 HMAC-SHA-256-8, 4 HMAC-SHA-256-16 (default), 5 HMAC-SHA-1-8 |
| `--no-auth` | Start with SAv2 and SAv5 off |
| `--headless`, `--trace` | No window; print the frame log |

## Secure authentication (SAv5, IEEE 1815-2012)

- **Users.** User 1 ("Common", Single user role) always exists. Add more in Security > Users or in the SA file. Each user has its own update key, session keys, and key change sequence number (KSQ). A master may authenticate as any of them.
- **Roles.** Roles are checked after the MAC is verified. A user without the role for a function gets error 7, authorization failed.
  - Viewer, SECAUD, RBACMNT, SECADM: reads only.
  - Operator: controls, freezes, unsolicited enable and disable, and writes.
  - Engineer and Installer: writes, restarts, freezes, and class assignment. No controls.
  - Single user: everything.
- **Challenges.** Challenges carry user 0. The reply's user number selects the session key.
- **Session keys.** Session keys may be 16 to 32 octets.
- **Aggressive mode.** Turn on "Aggressive mode" to accept g120v3 + g120v9. The first aggressive request needs a prior challenge. The CSQ must be one more than the last CSQ used, and the MAC covers that challenge plus the request up to g120v9. It works on reads as well as controls.
- **Remote user and update-key change.** Set an authority key to enable this.
  1. The authority sends a user status change (g120v10) to add, change, or delete a user by name. The certification data is an HMAC with the authority key.
  2. The master sends g120v11 and gets g120v12, which assigns the user number.
  3. The master sends g120v13 and g120v15. The new key arrives AES-key-wrapped under the authority key.
  - Symmetric method 3 (AES-128 / SHA-1) and method 4 (AES-256 / SHA-256) are accepted.
  - Users added this way are saved to the SA file.
- **Not supported.** AES-GMAC is not offered as a MAC (code 6). Update-key change requests for method 5 (AES-GMAC) or the asymmetric methods (67 to 71) get error 8.

## Points

New points were added after the existing indexes, so existing master point maps still line up.

| Type | Indexes | Contents |
| --- | --- | --- |
| BI g1, class 1 | 0-19 | Breakers 52-T1, 52-F1, 52-F2, 89-BS, 52-C1; 27 undervoltage; 50-F1/F2; 79-F1/F2 lockout; 63-T1; station alarm; remote/local; oil and winding temperature alarms; tap changer auto; charger fail; door; SF6; relay healthy |
| BO g10/g12, class 0 | 0-8 | Breaker controls 0-3; capacitor 4; tap raise 5 and lower 6 (pulse); tap auto/manual 7; 79 lockout reset 8 (pulse) |
| Counter g20, class 3 | 0-6 | Feeder energy; breaker operations; tap operations; capacitor operations; reactive energy |
| AI g30, class 2 | 0-19 | Bus and feeder voltages; feeder currents, load, and power factor; transformer kW and kVAr; frequency; oil, winding, and ambient temperature; battery; tap position; capacitor kVAr; last fault currents |
| AO g40/g41, class 0 | 0-1 | Feeder regulator setpoints, 10.5 to 14.4 kV |

The yard model:

- Load follows the local time of day.
- The tap changer holds the bus within 1 % after 10 s in auto. While it is in auto, raise and lower commands return AUTOMATION_INHIBIT.
- The capacitor bank lifts the voltage and cancels reactive power.
- Oil and winding temperatures follow the load and raise their alarms with hysteresis.
- A charger failure drains the battery.
- **Transient fault** trips a feeder and recloses it.
- **Permanent fault** trips three times and locks out the 79. Pulse BO 8 to reset it.

Responses up to 2048 octets are split into transport segments, so a class 0 poll returns every point and all 18 security statistics.

## Tests

```sh
python -m bayline.selfcheck
```

This checks the codec, SAv5 key changes, challenges, multiple users, roles, aggressive mode, remote update-key change (methods 3 and 4), and the TCP listener.

`tools/opendnp3-master` drives the simulator with a real master: opendnp3 2.1.0-RC5, the last opendnp3 release with SAv5. On Linux:

```sh
tools/opendnp3-master/build.sh
tools/opendnp3-master/interop.sh
```

It checks:

- Session keys for AES-128 and AES-256 users.
- Challenge and reply on SBO and direct operate.
- A Viewer being refused.
- A remote user added with method 4 and then operating.
- MAC codes 2 to 5.
- A plain (non-SA) master: integrity poll contents, tap changer, and capacitor.

opendnp3 has no aggressive mode and no MAC code 1, so `selfcheck` covers those alone.
