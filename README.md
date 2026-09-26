# Bayline DNP3 outstation

Python DNP3 outstation with a desktop window and SAv5. Listens on TCP port 20000.

```powershell
py -3.14 -m pip install -r requirements.txt
py -3.14 outstation.py
```

The window has Points, Comms, Master, Wire, and Security. Comms shows the TCP listener, link, frame counts, and the SAv5 session. A master on this PC uses `127.0.0.1`, port `20000`, outstation address `4`.

`py -3.14 outstation.py --headless` listens without the window.
