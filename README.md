# Bayline DNP3 outstation Simulator

Python DNP3 outstation only. No built-in master. Listens on TCP port 20000 for your master.

```powershell
py -3.14 -m pip install -r requirements.txt
py -3.14 outstation.py
```

The window has Points, Comms, Wire, and Security. A master on this PC uses `127.0.0.1`, port `20000`, outstation address `4`.

`py -3.14 outstation.py --headless` listens without the window.
