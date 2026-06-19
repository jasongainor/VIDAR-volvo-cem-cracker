# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Jason Gainor
# Derived from volvo-cem-cracker — Copyright (C) 2020, 2021 Vitaly Mayatskikh,
# Christian Molson, Mark Dapoz — https://github.com/vtl/volvo-cem-cracker (GPL-3.0).
"""Platform-agnostic web UI for the CEM PIN cracker — REAL HARDWARE ONLY.

A tiny stdlib HTTP server (no external deps) that drives the CrackEngine against a real Teensy
and streams live status to a browser — so you watch the crack in a tab on Mac/Windows/Linux
instead of reading serial logs.

    python3 -m cemcrack.webui                                        # open the UI, pick the port
    python3 -m cemcrack.webui --port-serial /dev/tty.usbmodem1234    # preselect the Teensy port

Architecture:  browser  <-- HTTP/JSON -->  this server  -->  CrackEngine  -->  SerialTransport  -->  Teensy  -->  CEM
The browser only renders status and posts start/stop; all timing/stats stay host+MCU side.

INTEGRITY: this operational UI has NO simulator/demo path. Every latency and every unlock comes
from the real CEM over the Teensy — there is no code here that can fabricate a result. Software
is validated separately against the simulator in tests/test_engine.py (clearly a test harness,
never wired to this server).
"""
from __future__ import annotations

import argparse
import json
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import cemproto
from .engine import CrackEngine, CrackConfig, SWEEP_RATE_S

# Bus speeds for the Volvo P2 platform (selectable in the UI; pushed to the Teensy at connect,
# so the firmware never needs editing). HS-CAN speed is model-year dependent: 250 kbps for
# MY<=2004, 500 kbps for MY>=2005 (the MY2005 electrical-architecture change). MS-CAN is 125 kbps.
CAN_SPEEDS = {500_000: "500 kbps (HS-CAN — MY2005+)", 250_000: "250 kbps (HS-CAN — MY<=2004)",
              125_000: "125 kbps (MS-CAN)"}
LOG_CAP = 20000   # ring-buffer cap on retained log lines (since-cursor still resolves via base)
EXPECTED_FW = "cem_probe-4"   # firmware version this UI/engine expects; a mismatch -> reflash gate

# Vehicle catalogue for the header car-picker (served at /cars.json). Sourced from Volvo VIDA
# 2014D vehicle profiles (authoritative model names + model-year ranges). The picker derives the
# HS-CAN bus speed from the selected year via the MY2004/2005 rule above. Data only — ships with
# the tool so the UI is self-contained (no filesystem dependency).
CARS = {
    "platform": "Volvo P2",
    "applies_to": "CEM PIN recovery via the HS-CAN timing side-channel",
    "source": "Volvo VIDA 2014D vehicle profiles",
    "can_hs_rule": "HS-CAN = 250 kbps for MY<=2004, 500 kbps for MY>=2005; LS/MS-CAN = 125 kbps.",
    "cars": [
        {"id": "s60",  "model": "S60",  "body": "sedan",        "year_start": 2001, "year_end": 2009,
         "variants": ["S60 R"], "can_ls_kbps": 125, "can_hs": {"my_le_2004_kbps": 250, "my_ge_2005_kbps": 500}},
        {"id": "s80",  "model": "S80",  "body": "sedan",        "year_start": 1999, "year_end": 2006,
         "variants": [], "can_ls_kbps": 125, "can_hs": {"my_le_2004_kbps": 250, "my_ge_2005_kbps": 500}},
        {"id": "v70",  "model": "V70",  "body": "wagon",        "year_start": 2000, "year_end": 2008,
         "variants": ["V70 R"], "can_ls_kbps": 125, "can_hs": {"my_le_2004_kbps": 250, "my_ge_2005_kbps": 500}},
        {"id": "xc70", "model": "XC70", "body": "wagon (raised)", "year_start": 2001, "year_end": 2007,
         "variants": ["V70 XC"], "can_ls_kbps": 125, "can_hs": {"my_le_2004_kbps": 250, "my_ge_2005_kbps": 500}},
        {"id": "xc90", "model": "XC90", "body": "suv",          "year_start": 2003, "year_end": 2014,
         "variants": [], "note": "first-gen P2 XC90; MY2015+ is SPA gen2 (out of scope)",
         "can_ls_kbps": 125, "can_hs": {"my_le_2004_kbps": 250, "my_ge_2005_kbps": 500}},
    ],
}


class CrackSession:
    """Owns the running engine + its thread; the HTTP handler reads/controls it."""

    def __init__(self):
        self.lock = threading.Lock()
        self.engine: CrackEngine | None = None
        self.thread: threading.Thread | None = None
        self.last_status = {"phase": "idle", "pin": [None] * cemproto.PIN_LEN,
                            "bytes": [], "probes": 0, "elapsed": 0.0, "shuffle": None, "result": None}
        self.running = False
        self.flash_busy = False   # a `pio upload` is in flight — don't open the port from a poll
        self._port_lock = threading.Lock()  # serialize teensy_check/car_check opens (no stacking polls)
        self.error = None
        self.log_buf = []      # list of {elapsed, probes, level, msg}
        self.log_base = 0      # index of log_buf[0] in the absolute stream (for since-cursor)

    def _on_progress(self, status):
        self.last_status = status

    def _on_log(self, rec):
        self.log_buf.append(rec)
        if len(self.log_buf) > LOG_CAP:                  # trim oldest, keep the cursor honest
            drop = len(self.log_buf) - LOG_CAP
            del self.log_buf[:drop]
            self.log_base += drop

    def _on_raw(self, direction, text):
        """Mirror a raw line (serial cmd/response or flash output) into the log, verbatim."""
        self._on_log({"elapsed": 0.0, "probes": 0, "level": "raw", "msg": f"{direction} {text}"})

    def get_log(self, since=0):
        """Return (lines_after `since`, next_cursor). `since` is an absolute stream index."""
        start = max(0, since - self.log_base)
        return self.log_buf[start:], self.log_base + len(self.log_buf)

    def start(self, port_serial=None, shuffle=0, gifts=None, can_speed=500_000, verbose=False,
              resume_index=None):
        """Start a crack against the REAL Teensy on `port_serial`. There is no simulator path:
        if no port is given (or the serial open fails) we refuse to start rather than invent data."""
        with self.lock:
            if self.running:
                return False, "already running"
            if not port_serial:
                return False, "no serial port selected — connect the Teensy and pick its port"
            self.error = None
            self.log_buf = []
            self.log_base = 0
            order = cemproto.SHUFFLE_ORDERS[int(shuffle)]
            gifts = {int(p): int(v) for p, v in (gifts or {}).items()}
            try:
                from .transport import SerialTransport
                tx = SerialTransport(port_serial, can_speed=int(can_speed),
                                     raw_log=self._on_raw, verbose=bool(verbose))
            except Exception as e:                       # noqa: BLE001
                self.error = f"serial open failed: {e}"
                return False, self.error
            # This CEM's reply latency carries a SYSTEMATIC per-value bias (0x00 led the timing on all
            # four unknown bytes in testing — a CAN bit-stuffing / frame-content confound, not PIN
            # signal). A timing "separation" is therefore FALSE and would commit a wrong byte, excluding
            # the truth from the sweep (observed: pin[4]=0x00 committed -> 1M sweep FAILED). So we carry
            # EVERY non-gift byte's full axis: a guaranteed (full 100^k) sweep. Gifts still cut the
            # exponent 100x each; pin[0] is still re-confirmed.
            cfg = CrackConfig(gift_bytes=gifts, gift_confirm=bool(gifts),
                              n_check_unmeasurable=20_000, verify_budget=100_000_000,
                              assume_unmeasurable=True)
            self.engine = CrackEngine(tx, shuffle_order=order, config=cfg,
                                      progress_cb=self._on_progress, log_cb=self._on_log)
            self.running = True

            def run():
                try:
                    self.engine.crack(resume_index=resume_index)
                except Exception as e:                   # noqa: BLE001
                    self.error = f"crack failed: {e}"
                finally:
                    self.running = False
                    try:
                        tx.close()
                    except Exception:                    # noqa: BLE001
                        pass

            self.thread = threading.Thread(target=run, daemon=True)
            self.thread.start()
            return True, "started"

    def check_pin(self, port_serial=None, shuffle=0, pin=None, can_speed=500_000):
        """Single-shot PIN VERIFY on the real Teensy — NOT a crack. Enters programming mode, fires a
        deliberately-wrong unlock (negative control, must be rejected) then the candidate PIN, exits
        prog mode (FF C8), and returns the verdict. Reuses the exact same `U <frame>` unlock the engine
        uses, so it's the minimal change over Start. Synchronous (~3-5 s); raw serial streams to the log."""
        with self.lock:
            if self.running:
                return {"ok": False, "msg": "a crack is running — Stop it first"}
            if self.flash_busy:
                return {"ok": False, "msg": "the Teensy is busy — try again in a moment"}
            if not port_serial:
                return {"ok": False, "msg": "no serial port selected"}
            try:
                pin = [int(b) for b in (pin or [])]
            except (TypeError, ValueError):
                return {"ok": False, "msg": "bad PIN bytes"}
            if len(pin) != cemproto.PIN_LEN or any(not 0 <= b <= 0x99 for b in pin):
                return {"ok": False, "msg": "enter all 6 bytes as two BCD digits (00–99) each"}
            self.flash_busy = True            # stand the pollers down off the port for the check
        self.log_buf = []; self.log_base = 0
        order = cemproto.SHUFFLE_ORDERS[int(shuffle)]
        self._on_raw("##", "CHECK PIN " + " ".join(f"{b:02X}" for b in pin) + " — single unlock test")
        try:
            from .transport import SerialTransport
            tx = SerialTransport(port_serial, can_speed=int(can_speed), raw_log=self._on_raw, verbose=True)
        except Exception as e:                # noqa: BLE001
            self.flash_busy = False
            return {"ok": False, "msg": f"serial open failed: {e}"}
        try:
            tx.prog_on()
            wrong = list(pin); wrong[-1] = (wrong[-1] + 1) & 0xFF     # negative control: must be rejected
            neg = tx.unlock(wrong, order)
            pos = tx.unlock(list(pin), order)
            confirmed = bool(pos and not neg)
            self._on_raw("##", f"negative control (wrong PIN) -> {'UNLOCKED?!' if neg else 'rejected'}; "
                               f"candidate -> {'UNLOCKED' if pos else 'rejected'}")
            if confirmed:      msg = "PIN CONFIRMED — it unlocked, and the wrong-PIN control was rejected"
            elif pos:          msg = "unlocked, but the wrong-PIN control ALSO unlocked — result not trustworthy (re-seat power, retry)"
            else:              msg = "PIN REJECTED — it did not unlock this CEM"
            self._on_raw("##", msg)
            return {"ok": True, "unlocked": bool(pos), "negative_rejected": (not neg),
                    "confirmed": confirmed, "msg": msg}
        except Exception as e:                # noqa: BLE001
            return {"ok": False, "msg": f"check failed: {e}"}
        finally:
            try: tx.prog_off()
            except Exception: pass            # noqa: BLE001
            try: tx.close()
            except Exception: pass            # noqa: BLE001
            self.flash_busy = False

    def stop(self):
        with self.lock:
            if self.engine:
                self.engine.abort = True
            return True, "stopping"

    def shutdown(self, timeout=15.0):
        """Process is exiting (Ctrl-C / SIGTERM / atexit): abort any running crack and WAIT for its
        worker to run its `finally` — which broadcasts FF C8 and returns the car to normal. A bare
        exit (or letting the daemon thread be killed) would strand the car in programming mode. This
        is the host-side guarantee; the firmware watchdog (~10 s of host silence) is the backstop.
        Idempotent and exception-safe so it's always callable from a signal/atexit context."""
        try:
            eng = self.engine
            if eng is not None and self.running:
                eng.abort = True
            t = self.thread
            if t is not None and t.is_alive():
                t.join(timeout)
        except Exception:                                # noqa: BLE001
            pass

    def status(self):
        s = dict(self.last_status)
        s["running"] = self.running
        s["error"] = self.error
        return s

    def _transient(self, port_serial):
        """Open a short-lived transport for a one-off prog-mode op (idle only; verbose raw log)."""
        from .transport import SerialTransport
        return SerialTransport(port_serial, raw_log=self._on_raw, verbose=True)

    def prog(self, on, port_serial):
        """Enter (on=True) or Exit (on=False, FF C8 reset) programming mode, off-crack. Async:
        streams raw serial to the log so the operator sees exactly what's sent."""
        import threading
        if self.running:
            return False, "a crack is running — Stop it first (Stop also exits prog mode)"
        if not port_serial:
            return False, "no serial port selected"
        self.log_buf = []; self.log_base = 0
        self._on_raw("##", f"programming mode {'ON' if on else 'OFF (reset all ECUs, FF C8)'} requested")

        def run():
            try:
                tx = self._transient(port_serial)
            except Exception as e:                       # noqa: BLE001
                self._on_raw("##", f"serial open failed: {e}"); return
            try:
                tx.prog_on() if on else tx.prog_off()
                self._on_raw("##", f"programming mode {'ON' if on else 'OFF — ECUs reset to normal'}")
            except Exception as e:                       # noqa: BLE001
                self._on_raw("##", f"prog command failed: {e}")
            finally:
                try: tx.close()
                except Exception: pass                   # noqa: BLE001
        threading.Thread(target=run, daemon=True).start()
        return True, f"programming mode {'ON' if on else 'OFF'}… watch the log"

    def flash(self):
        """Flash the Teensy firmware (pio run -t upload), streaming the FULL raw output to the log."""
        import subprocess, os, threading, sys, shutil
        if self.running:
            return False, "stop the crack before flashing"
        self.log_buf = []; self.log_base = 0
        fwdir = os.path.join(os.path.dirname(__file__), "..", "firmware")
        # Prefer the 'pio' launcher if it's on PATH; otherwise fall back to running PlatformIO as a
        # module under the SAME interpreter that started this server (`python -m platformio`). On
        # Windows a `pip install --user platformio` puts pio.exe in a Scripts dir that's usually not
        # on PATH — the module form has no such dependency, so the UI flash button always works.
        cmd = (["pio", "run", "-t", "upload"] if shutil.which("pio")
               else [sys.executable, "-m", "platformio", "run", "-t", "upload"])
        self._on_raw("##", "flashing firmware — " + " ".join(cmd))
        self.flash_busy = True     # block teensy_check/car_check (incl. the 4 s poll) from opening the port

        def run():
            try:
                p = subprocess.Popen(cmd, cwd=fwdir,
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                for line in p.stdout:
                    self._on_raw("::", line.rstrip())
                p.wait()
                self._on_raw("##", f"flash finished — exit {p.returncode}"
                                   + (" (re-select the port after re-enumeration)" if p.returncode == 0 else ""))
            except FileNotFoundError:
                self._on_raw("##", "flash error: PlatformIO not found — install it (pip install platformio) or flash from a terminal")
            except Exception as e:                       # noqa: BLE001
                self._on_raw("##", f"flash error: {e}")
            finally:
                self.flash_busy = False
        threading.Thread(target=run, daemon=True).start()
        return True, "flashing… watch the log"

    def teensy_check(self, port=None):
        """Gate 1+2: is a Teensy present, and does its firmware match what this UI expects?
        Fast + quiet (no 2s boot wait, not raw-logged) so the wizard can poll it. Serialized by
        _port_lock and time-bounded (~1.5 s) so overlapping 4 s polls can't stack up and monopolize
        the port — an unrecognized VERSION (older firmware → '? unknown') used to block 8×1 s,
        starving every other opener (incl. the next poll) with 'Access is denied'."""
        if self.running or self.flash_busy:
            return {"found": True, "busy": True, "expected": EXPECTED_FW}
        ports = find_teensy_ports()
        port = port if (port and port in ports) else (ports[0] if ports else None)
        if not port:
            return {"found": False, "expected": EXPECTED_FW, "matches": False}
        if not self._port_lock.acquire(blocking=False):  # another check already holds the port
            return {"found": True, "busy": True, "expected": EXPECTED_FW}
        ver = None
        try:
            import serial, time as _t
            s = serial.Serial(port, 2_000_000, timeout=0.3)
            try:
                s.reset_input_buffer()
                s.write(b"VERSION\n")
                deadline = _t.monotonic() + 1.5          # bounded; boot banner may precede the answer
                while _t.monotonic() < deadline:
                    ln = s.readline().decode(errors="replace").strip()
                    if ln.startswith("VERSION "):
                        ver = ln[8:].strip(); break
            finally:
                s.close()
        except Exception as e:                           # noqa: BLE001
            return {"found": True, "port": port, "version": None, "expected": EXPECTED_FW,
                    "matches": False, "error": str(e)}
        finally:
            self._port_lock.release()
        return {"found": True, "port": port, "version": ver, "expected": EXPECTED_FW,
                "matches": (ver == EXPECTED_FW)}

    def car_check(self, port, speed=500_000):
        """Gate 4: confirm the car is connected + awake by passively sniffing the bus (no prog
        mode, no unlock attempts) — frames seen ⇒ OBD connected + key on + bus alive. Sniffs at
        the SELECTED bus speed (a 250 kbps MY<=2004 car shows no frames if sniffed at 500)."""
        if self.running or self.flash_busy:
            return {"alive": None, "busy": True}
        if not port:
            return {"alive": False, "error": "no Teensy port"}
        try:
            speed = int(speed)
        except (TypeError, ValueError):
            speed = 500_000
        if not self._port_lock.acquire(blocking=False):  # a version poll / another check holds the port
            return {"alive": None, "busy": True}
        try:
            import serial, time as _t
            try:
                s = serial.Serial(port, 2_000_000, timeout=3.0)
            except Exception as e:                       # noqa: BLE001
                return {"alive": False, "error": str(e)}
            try:
                s.reset_input_buffer(); s.write(f"S {speed}\n".encode()); s.readline()
                s.reset_input_buffer(); s.write(b"SNIFF 1500\n")
                frames, uniq, t = 0, 0, _t.monotonic() + 6
                while _t.monotonic() < t:
                    ln = s.readline().decode(errors="replace").strip()
                    if ln.startswith("SNIFFDONE"):
                        p = ln.split(); frames = int(p[1]) if len(p) > 1 else 0
                        uniq = int(p[2]) if len(p) > 2 else 0
                        break
                return {"alive": frames > 0, "frames": frames, "modules": uniq}
            except Exception as e:                       # noqa: BLE001
                return {"alive": False, "error": str(e)}
            finally:
                try: s.close()
                except Exception: pass                   # noqa: BLE001
        finally:
            self._port_lock.release()


SESSION = CrackSession()
PREFERRED_PORT = None     # set by --port-serial; the UI preselects it if present


TEENSY_VIDS = {0x16C0}   # PJRC (Teensy 4.0 USB-Serial vendor id)


def list_serial_ports():
    try:
        from serial.tools import list_ports
        return [p.device for p in list_ports.comports()]
    except Exception:                                    # noqa: BLE001
        return []


def find_teensy_ports():
    """The serial ports that look like a Teensy. Matched FIRST by USB vendor id (PJRC 0x16C0) so it
    works cross-platform — Windows (COM3…), macOS (cu.usbmodem…) and Linux (ttyACM…) — and falls back
    to the name signature. Bluetooth / debug serial are excluded (they're neither PJRC nor usbmodem)."""
    out = []
    try:
        from serial.tools import list_ports
        for p in list_ports.comports():
            dev = p.device or ""
            hay = " ".join(x for x in (dev, p.description or "", p.manufacturer or "") if x).lower()
            if getattr(p, "vid", None) in TEENSY_VIDS or "teensy" in hay \
                    or "usbmodem" in hay or "ttyacm" in hay:
                out.append(dev)
    except Exception:                                    # noqa: BLE001
        pass
    return out


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):       # quiet
        pass

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/index"):
            self._send(200, PAGE, "text/html; charset=utf-8")
        elif self.path.startswith("/cars.json"):
            self._send(200, json.dumps(CARS), "application/json; charset=utf-8")
        elif self.path.startswith("/api/status"):
            self._send(200, json.dumps(SESSION.status()))
        elif self.path.startswith("/api/log"):
            from urllib.parse import urlparse, parse_qs
            q = parse_qs(urlparse(self.path).query)
            since = int(q.get("since", ["0"])[0])
            lines, cursor = SESSION.get_log(since)
            self._send(200, json.dumps({"lines": lines, "cursor": cursor}))
        elif self.path.startswith("/api/ports"):
            ports = list_serial_ports()
            if PREFERRED_PORT and PREFERRED_PORT not in ports:
                ports = [PREFERRED_PORT] + ports
            teensy = find_teensy_ports()
            pref = PREFERRED_PORT or (teensy[0] if teensy else None)   # default to the USB Teensy
            self._send(200, json.dumps({"ports": ports, "preferred": pref, "teensy": teensy}))
        elif self.path.startswith("/api/teensy"):
            from urllib.parse import urlparse, parse_qs
            port = parse_qs(urlparse(self.path).query).get("port", [None])[0]
            self._send(200, json.dumps(SESSION.teensy_check(port)))
        elif self.path.startswith("/api/carcheck"):
            from urllib.parse import urlparse, parse_qs
            q = parse_qs(urlparse(self.path).query)
            port = q.get("port", [None])[0]
            speed = q.get("speed", ["500000"])[0]
            self._send(200, json.dumps(SESSION.car_check(port, speed)))
        elif self.path.startswith("/api/resume_preview"):
            from urllib.parse import urlparse, parse_qs
            q = parse_qs(urlparse(self.path).query)
            runtime = float(q.get("runtime", ["0"])[0] or 0)
            gifts_n = int(q.get("gifts", ["0"])[0] or 0)
            idx_q = q.get("index", [""])[0]
            cur, space = CrackEngine.resume_cursor(
                runtime_s=runtime, swept_bytes=cemproto.PIN_LEN - gifts_n,
                exact_index=(int(idx_q) if idx_q not in ("", None) else None))
            self._send(200, json.dumps({"cursor": cur, "space": space,
                       "swept": cemproto.PIN_LEN - gifts_n,
                       "pct": (100.0 * cur / space if space else 0.0),
                       "remaining_s": (space - cur) * SWEEP_RATE_S}))
        else:
            self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(n) or b"{}") if n else {}
        except (ValueError, json.JSONDecodeError):
            self._send(400, json.dumps({"ok": False, "msg": "malformed JSON body"})); return
        if self.path.startswith("/api/start"):
            gifts = body.get("gifts") or {}
            resume_index = None
            ri, rr = body.get("resume_index"), body.get("resume_runtime_s")
            if ri not in (None, "") or rr not in (None, ""):   # RECOVER MODE requested
                swept = cemproto.PIN_LEN - len(gifts)
                resume_index, _ = CrackEngine.resume_cursor(
                    runtime_s=float(rr or 0), swept_bytes=swept,
                    exact_index=(int(ri) if ri not in (None, "") else None))
            ok, msg = SESSION.start(port_serial=body.get("port"),
                                    shuffle=body.get("shuffle", 0),
                                    gifts=gifts,
                                    can_speed=body.get("speed", 500_000),
                                    verbose=body.get("verbose", False),
                                    resume_index=resume_index)
            self._send(200 if ok else 409, json.dumps({"ok": ok, "msg": msg}))
        elif self.path.startswith("/api/checkpin"):
            res = SESSION.check_pin(port_serial=body.get("port"),
                                    shuffle=body.get("shuffle", 0),
                                    pin=body.get("pin"),
                                    can_speed=body.get("speed", 500_000))
            self._send(200 if res.get("ok") else 409, json.dumps(res))
        elif self.path.startswith("/api/stop"):
            ok, msg = SESSION.stop()
            self._send(200, json.dumps({"ok": ok, "msg": msg}))
        elif self.path.startswith("/api/progon"):
            ok, msg = SESSION.prog(True, body.get("port"))
            self._send(200 if ok else 409, json.dumps({"ok": ok, "msg": msg}))
        elif self.path.startswith("/api/progoff"):
            ok, msg = SESSION.prog(False, body.get("port"))
            self._send(200 if ok else 409, json.dumps({"ok": ok, "msg": msg}))
        elif self.path.startswith("/api/flash"):
            ok, msg = SESSION.flash()
            self._send(200 if ok else 409, json.dumps({"ok": ok, "msg": msg}))
        else:
            self._send(404, json.dumps({"error": "not found"}))


PAGE = r"""<!doctype html>
<html><head><meta charset="utf-8"><title>CEM Probe — PIN Recovery</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  /* Native desktop utility look: system UI font, light flat chrome, titled group boxes,
     one sober blue accent, flat semantic status. Monospace reserved for data + log. WCAG-AA. */
  :root{
    --font:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
    --mono:ui-monospace,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace;
    --win:#e8e8e8;        /* window backdrop */
    --panel:#ffffff;
    --hd:#f3f3f3;         /* panel header fill */
    --hdline:#dcdcdc;
    --line:#cccccc;       /* panel border */
    --line2:#e6e6e6;      /* inner hairline */
    --field:#ffffff;
    --ink:#1d2024;
    --ink2:#3c4248;
    --mut:#6b7077;
    --accent:#2c6db3;
    --accent-d:#245c97;
    --ok:#1f7a36;
    --warn:#8a5a00;
    --bad:#b22f24;
  }
  *{box-sizing:border-box}
  html,body{margin:0;width:100%;max-width:100%;overflow-x:clip}  /* clip (not hidden) so position:sticky still works */
  body{background:var(--win);color:var(--ink);font:13px/1.5 var(--font);
    display:flex;flex-direction:column;height:100vh;overflow:hidden;-webkit-font-smoothing:antialiased}
  .num,.byte .v,.val,#logbox,.logln .ts,.statusbar,.ev{font-family:var(--mono);font-variant-numeric:tabular-nums}

  /* ── minified VIDA header (single charcoal row) ────────────────── */
  .topbar{display:flex;align-items:center;gap:11px;padding:0 16px;height:46px;
    background:#2b2f36;border-bottom:1px solid #1c1f23;position:sticky;top:0;z-index:20}
  svg.emblem{width:30px;height:30px;color:#fff;flex:none;display:block}
  .wm{font:700 15px/1 var(--font);letter-spacing:.18em;color:#fff;cursor:help}
  .brand{display:flex;align-items:baseline;gap:9px;border-left:1px solid rgba(255,255,255,.16);padding-left:13px}
  .brand .name{font:600 14px/1 var(--font);color:#e9ebee}
  .brand .sub{font:400 12px/1 var(--font);color:#9aa1ab}
  .veh{display:flex;align-items:center;gap:6px;border-left:1px solid rgba(255,255,255,.16);padding-left:11px}
  .hdr-sel{height:28px;min-width:0;background:#3a3f47;color:#e9ebee;border:1px solid #4a505a;border-radius:3px;padding:0 8px;font:12.5px var(--font);cursor:pointer}
  .hdr-sel:hover{border-color:#5b626b}
  #car-model{min-width:104px} #car-year{min-width:116px}
  .leds .led:nth-child(n){}
  .leds{margin-left:auto;display:flex;align-items:center;gap:12px}
  .led{display:flex;align-items:center;gap:6px;font:500 12px/1 var(--font);color:#8b929b}
  .led i,.dot{width:8px;height:8px;border-radius:50%;background:#5b626b;display:inline-block}
  .led.on{color:#d3d7dd} .led.on i{background:#7ed957;box-shadow:0 0 0 2px rgba(126,217,87,.16)}
  .led.warn{color:#e8c170} .led.warn i{background:#e0b34d}
  .led.bad{color:#f0a0a0} .led.bad i{background:#e36464}
  .sepv{width:1px;height:16px;background:rgba(255,255,255,.16)}
  #conn{display:inline-flex;align-items:center;gap:6px;font:12px/1 var(--mono);color:var(--ink);text-transform:uppercase}
  .dot.on{background:#7ed957;box-shadow:0 0 0 2px rgba(126,217,87,.16)}

  /* ── work area ─────────────────────────────────────────────────── */
  main{flex:1;min-height:0;width:100%;max-width:1400px;margin:0 auto;padding:16px;min-width:0;
    display:flex;flex-direction:column;overflow:hidden}  /* fixed-height app shell: main fills, never grows the page */
  .cols{display:grid;grid-template-columns:minmax(0,1.1fr) minmax(0,1fr);gap:14px;align-items:stretch;flex:1;min-height:0}
  .left,.right{display:flex;flex-direction:column;gap:14px;min-width:0;min-height:0}
  .left{overflow:auto}                               /* a tall wizard scrolls inside its column, never clips */
  .right>.term{flex:1;display:flex;flex-direction:column;min-height:0}  /* only the log fills height; Status stays natural */
  /* mobile: relax the viewport lock back to natural page scroll, cap the log so it can't dominate */
  @media(max-width:900px){body{height:auto;overflow:visible}main{display:block;overflow:visible}.left{overflow:visible}
    #logbox{max-height:70vh}
    .cols{grid-template-columns:1fr}.metrics{grid-template-columns:repeat(2,minmax(0,1fr))}.pin{grid-template-columns:repeat(3,minmax(0,1fr))}.eqbox{min-height:0}.eqbox .pin{grid-template-rows:none}}
  @media(max-width:520px){.pin{grid-template-columns:repeat(2,minmax(0,1fr))}}

  /* ── panels / group boxes ──────────────────────────────────────── */
  .panel{background:var(--panel);border:1px solid var(--line);border-radius:4px;box-shadow:0 1px 2px rgba(0,0,0,.05);overflow:hidden}
  .panel-hd{display:flex;align-items:center;gap:10px;font:600 12px/1 var(--font);color:#3a3f44;padding:8px 12px;background:var(--hd);border-bottom:1px solid var(--hdline)}
  .panel-hd .hsub{font-weight:400;color:var(--mut);font-size:11px}
  .panel-hd #phase{flex:1;min-width:0;color:var(--ink2)}  /* status line lives in the title bar */
  .panel-bd{padding:8px 14px}
  .eqbox{display:flex;flex-direction:column}
  .eqbox>.panel-bd{flex:1;min-height:0;display:flex;flex-direction:column;padding:7px 12px}
  .eqbox .pin{flex:1;grid-template-rows:1fr}
  .eqbox .metrics{margin-top:auto}
  .panel a{color:var(--accent);text-decoration:none}
  .panel a:hover{text-decoration:underline}
  .sublabel{font:600 11px/1 var(--font);color:#3a3f44;text-transform:uppercase;letter-spacing:.05em;margin:8px 0 4px}

  /* ── PIN register ──────────────────────────────────────────────── */
  .pin{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:6px}
  .byte{position:relative;display:flex;flex-direction:row;align-items:center;gap:8px;padding:5px 9px;min-height:0;
    background:#fafafa;border:1px solid #d2d2d2;border-left:3px solid #cdcdcd;border-radius:4px}
  .byte .pos{font:10px/1 var(--mono);color:#767b81;flex:none}
  .byte .v{font:600 17px/1 var(--mono);color:var(--ink);flex:1;min-height:0}
  .byte .g{flex:1;min-width:0;font:600 17px/1.1 var(--mono);background:#fff;color:var(--ink);border:1px solid #b6b6b6;border-radius:3px;padding:4px 6px;text-transform:uppercase}
  .byte .g::placeholder{color:#c2c2c2;font-weight:500}
  .byte .g:focus{border-color:var(--accent);outline:none}
  .byte .lbl{align-self:center;flex:none;max-width:100%;font:600 8.5px/1.2 var(--font);letter-spacing:.03em;text-transform:uppercase;color:#767b81;
    background:#fff;padding:3px 5px;border:1px solid #d2d2d2;border-radius:2px}
  .byte.gift{border-left-color:var(--accent)} .byte.gift .v{color:var(--accent)} .byte.gift .lbl{color:var(--accent);border-color:#b9d0e6}
  .byte.measured{border-left-color:var(--ok)} .byte.measured .v{color:var(--ok)} .byte.measured .lbl{color:var(--ok);border-color:#bcd9c1}
  .byte.active{border-left-color:var(--accent)} .byte.active .v{color:var(--accent)} .byte.active .lbl{color:var(--accent);border-color:#b9d0e6}
  .byte.unmeas{border-left-color:var(--warn)} .byte.unmeas .v{color:var(--warn);font-size:14px} .byte.unmeas .lbl{color:var(--warn);border-color:#e2d2a6}
  .byte.invalid .g{border-color:var(--bad)}

  /* ── setup wizard ──────────────────────────────────────────────── */
  .wiz{list-style:none;margin:0;padding:0}
  .step{display:grid;grid-template-columns:22px 1fr;gap:11px;align-items:start;padding:6px 2px;border-top:1px solid var(--line2);opacity:.6;transition:opacity .15s}
  .step:first-child{border-top:0;padding-top:0}
  .step.active,.step.done,.step.fail{opacity:1}
  .sn{width:22px;height:22px;border-radius:50%;background:#dadada;color:#666;display:flex;align-items:center;justify-content:center;font:600 12px/1 var(--font);margin-top:3px}
  .step.active .sn{background:var(--accent);color:#fff} .step.done .sn{background:var(--ok);color:#fff} .step.fail .sn{background:var(--bad);color:#fff}
  .sb{display:flex;flex-direction:column;gap:4px;min-width:0}
  .sb b{font:600 13px/1.3 var(--font);color:var(--ink)}
  /* one inline row per step: title + status on the left, action button pushed to the right */
  .srow{display:flex;align-items:center;gap:10px;min-height:29px}
  .srow>b{flex:none} .srow .sv{flex:1;min-width:0} .srow button{margin-left:auto;flex:none} .srow .sm{flex:none}
  .sv{font:400 12px/1.45 var(--mono);color:var(--ink2);overflow-wrap:anywhere}
  .sx{display:flex;gap:10px 12px;align-items:center;flex-wrap:wrap;font-size:13px;color:var(--ink2)}
  .sm{font:400 11px/1.3 var(--mono);color:var(--mut)}
  #pre-list{flex-direction:column;align-items:flex-start;gap:5px}
  label.chk,.chk{display:flex;align-items:center;gap:8px;color:var(--ink2);font-size:13px;cursor:pointer}
  input[type=checkbox]{accent-color:var(--accent);width:15px;height:15px;cursor:pointer}
  .runrow{display:flex;gap:14px 16px;align-items:flex-end;flex-wrap:wrap}
  .field{display:flex;flex-direction:column;gap:5px}
  .field>span{font:500 11px/1 var(--font);color:var(--mut)}
  .runbtns{display:flex;gap:9px;align-items:center;margin-top:6px}
  .hint{color:var(--mut);font-size:12px;line-height:1.5;margin-top:11px;padding-top:10px;border-top:1px solid var(--line2)}

  /* ── controls ──────────────────────────────────────────────────── */
  button{font:500 13px/1 var(--font);padding:0 14px;height:29px;border:1px solid #b3b3b3;border-radius:4px;
    background:linear-gradient(#ffffff,#efefef);color:var(--ink);cursor:pointer}
  button:hover{background:linear-gradient(#ffffff,#e7e7e7);border-color:#9c9c9c}
  button:active{background:#e2e2e2}
  button:disabled{opacity:1;background:#f1f1f1;border-color:#d4d4d4;color:#aaadb0;cursor:default}
  button.go{background:linear-gradient(#3a7cc0,#2c6db3);border-color:var(--accent-d);color:#fff;font-weight:600}
  button.go:not(:disabled):hover{background:linear-gradient(#4185c9,#2f74bd)}
  button.go:disabled{background:#cdd6df;border-color:#bcc6cf;color:#fff}
  button.stop{background:linear-gradient(#cf4a3c,#c0392b);border-color:#a02e22;color:#fff;font-weight:600}
  button.stop:not(:disabled):hover{background:linear-gradient(#d65648,#c5402f)}
  #progoff{background:linear-gradient(#fff,#f3ecdb);border-color:#cdb05a;color:var(--warn);font-weight:600}
  #progoff:hover{background:linear-gradient(#fff,#efe6cf);border-color:#b9982f}
  select,input[type=text]{font:13px var(--font);height:29px;padding:0 8px;border:1px solid #b6b6b6;border-radius:4px;background:var(--field);color:var(--ink)}
  select{cursor:pointer;min-width:170px}
  :focus-visible{outline:2px solid var(--accent);outline-offset:1px}

  /* ── telemetry ─────────────────────────────────────────────────── */
  .phase{font:400 13px/1.5 var(--font);color:var(--ink);min-height:20px}
  .err{color:var(--bad);font:500 12px/1.4 var(--mono);margin-top:8px}
  .err:empty{display:none}
  .bar{height:12px;background:#e6e6e6;border:1px solid #c6c6c6;border-radius:3px;overflow:hidden;margin:5px 0}
  .bar>i{display:block;height:100%;width:0;background:var(--accent);transition:width .3s}
  .metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));border:1px solid #e0e0e0;border-radius:4px;overflow:hidden}
  .metrics>div{padding:4px 8px;border-left:1px solid #ededed;background:#fafafa;min-width:0;display:flex;align-items:baseline;justify-content:space-between;gap:8px}
  .metrics>div:first-child{border-left:0}
  .k{font:500 9px/1.1 var(--font);color:var(--mut);flex:none}
  .val{font:600 13px/1.2 var(--mono);color:var(--ink);overflow-wrap:anywhere;text-align:right}
  /* Status collapsed into a header bar: phase + metrics in the title, thin progress line under it */
  .statbar .panel-hd{flex-wrap:wrap;gap:5px 14px}
  .statbar #phase{flex:1;min-width:90px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:var(--ink2)}
  .statbar .metrics{margin-left:auto;display:flex;border:0;border-radius:0;overflow:visible}
  .statbar .metrics>div{border-left:1px solid #d8d8d8;background:none;padding:0 0 0 12px;margin-left:12px;flex-direction:row;align-items:baseline;gap:6px;justify-content:flex-start}
  .statbar .metrics>div:first-child{border-left:0;padding-left:0;margin-left:0}
  .statbar .err{padding:4px 12px}
  .statbar .bar{margin:0;border:0;border-radius:0;height:3px}
  .info{margin-left:auto;cursor:help;color:var(--mut);font-size:13px;flex:none;user-select:none}

  /* ── tables / events ───────────────────────────────────────────── */
  table{width:100%;border-collapse:collapse;margin-top:0}
  th,td{text-align:left;padding:3px 8px;font-size:13px}
  th{color:var(--mut);font:600 11px/1 var(--font);letter-spacing:.03em;border-bottom:1px solid #d8d8d8;background:#f6f6f6}
  td{border-bottom:1px solid #efefef;color:var(--ink2)}
  #cont td,#bytes td:nth-child(2),#bytes td:nth-child(3){font-family:var(--mono)} #cont td:last-child,#cont th:last-child{text-align:right}
  .st-gift{color:var(--accent)} .st-measured,.st-recovered{color:var(--ok)}
  .st-unmeasurable{color:var(--warn)} .st-rejected{color:var(--bad);font-weight:600}
  .st-scanning{color:var(--ink)} .st-pending{color:var(--mut)}
  .events{display:flex;flex-direction:column;gap:3px;margin-top:4px}
  .ev{display:flex;gap:11px;font:400 12px/1.5 var(--mono)} .ev .et{color:#9aa0a6;flex:0 0 48px;text-align:right}
  .ev .em{min-width:0;overflow-wrap:anywhere;color:var(--ink2)} .ev.good .em{color:var(--ok)} .ev.warn .em{color:var(--warn)} .ev.bad .em{color:var(--bad)}

  /* ── log console ───────────────────────────────────────────────── */
  .term .panel-bd{padding:0;flex:1;display:flex;flex-direction:column;min-height:0}
  .term .panel-bd .sublabel{margin:0;padding:5px 12px 3px;background:#f3f3f3;border-bottom:1px solid #e6e6e6;font-size:10px}
  .term .events{flex:none;max-height:84px;overflow-y:auto;padding:5px 12px;border-bottom:1px solid #ededed;margin:0;gap:2px}
  .term .events .ev{font-size:11px}
  .statbar #aslabel{flex:none;font-size:11px;color:#555}
  .term{display:flex;flex-direction:column}
  .tag{font:600 10px/1 var(--font);letter-spacing:.05em;color:#777;border:1px solid #cfcfcf;border-radius:3px;padding:3px 5px;background:#fff}
  .panel-hd .chk{margin-left:auto;font-size:12px;color:#555}
  #logbox{flex:1;min-height:120px;overflow-y:auto;background:#fcfcfc;padding:9px 0;font:13px/1.55 var(--mono);white-space:pre-wrap;word-break:break-word;color:#23272b}
  .logln{display:flex;gap:13px;padding:1px 13px}
  .logln:nth-child(even){background:#f6f7f9}
  .logln .ts{color:#9aa0a6;flex:0 0 48px;text-align:right}
  .logln .msg{color:#23272b;flex:1;min-width:0;overflow-wrap:anywhere}
  .logln.good .msg{color:#1f7a36} .logln.warn .msg{color:#8a5a00} .logln.bad .msg{color:#b22f24}
  .logln.raw .msg{color:#969ba0}
  #logbox::-webkit-scrollbar{width:13px} #logbox::-webkit-scrollbar-track{background:#f1f1f1}
  #logbox::-webkit-scrollbar-thumb{background:#c4c4c4;border-radius:7px;border:3px solid #fcfcfc}

  /* ── status bar ────────────────────────────────────────────────── */
  .statusbar{display:flex;align-items:center;gap:10px;padding:0 14px;height:26px;
    background:#ededed;border-top:1px solid #cccccc;font:12px/1 var(--mono);color:#5c6066;
    position:sticky;bottom:0;z-index:20}
  .statusbar .sep{color:#bcbcbc}
  .statusbar .spacer{flex:1}
  .statusbar #sb-state{color:var(--ink)}
  /* recover / resume disclosure (Run step) */
  .recover{margin:2px 0 4px;border:1px solid var(--line2);border-radius:4px;background:#fafbfc}
  .recover>summary{cursor:pointer;padding:7px 11px;font:600 12px/1 var(--font);color:var(--ink2);user-select:none}
  .recover[open]>summary{border-bottom:1px solid var(--line2)}
  .recover .runrow{padding:0 11px}
  .recnote{margin:9px 11px 4px;font-size:11.5px;line-height:1.5;color:var(--mut)}
  .recprev{margin:7px 11px 11px;padding:7px 9px;border-radius:3px;background:#eef3ef;border:1px solid #dbe6dd;
    font:12px/1.45 var(--mono);color:var(--ink2);overflow-wrap:anywhere}
  .recprev.warn{background:#fbf3e6;border-color:#ecd9b0;color:#7a5a12}
  /* Check-PIN mode: the primary button turns green when all 6 bytes are entered (verify, not crack) */
  button.go.checkpin{background:linear-gradient(#2f9e57,#268a4b);border-color:#1f7a3f}
  button.go.checkpin:not(:disabled):hover{background:linear-gradient(#34ab5f,#288f4e)}
  button.go.checkpin:disabled{background:#cdd6df;border-color:#bcc6cf}  /* disabled Check-PIN reads as disabled, not green */
  .err.good{color:var(--ok)} .err.warn{color:var(--warn)} .err.bad{color:var(--bad)}
</style></head><body>
<svg width="0" height="0" style="position:absolute" aria-hidden="true">
    <!-- ① ANTLER-TRACE MOOSE -->
    <symbol id="m1" viewBox="0 0 64 64">
      <path fill="currentColor" d="M23,32 C23,25 27,21 32,21 C37,21 41,25 41,32 L39,46 C39,51 36,54 32,54 C28,54 25,51 25,46 Z"/>
      <path fill="currentColor" d="M24,28 C18,24 13,26 16,31 C18,33 23,31 24,28 Z"/>
      <path fill="currentColor" d="M40,28 C46,24 51,26 48,31 C46,33 41,31 40,28 Z"/>
      <g fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round">
        <path d="M30,22 L30,15 L23,15 L23,10"/>
        <path d="M30,15 L26,11"/>
        <path d="M34,22 L34,15 L41,15 L41,10"/>
        <path d="M34,15 L38,11"/>
        <path d="M32,21 L32,7"/>
      </g>
      <g fill="currentColor">
        <circle cx="23" cy="9" r="2.1"/><circle cx="26" cy="10" r="1.7"/>
        <circle cx="41" cy="9" r="2.1"/><circle cx="38" cy="10" r="1.7"/>
        <circle cx="32" cy="6" r="2.3"/>
      </g>
    </symbol>
    <!-- ② OBD-CONNECTOR MOOSE -->
    <symbol id="m2" viewBox="0 0 64 64">
      <!-- palmate moose rack: swoopy windswept palm, fingers raking outward; one side drawn, mirrored -->
      <g fill="currentColor">
        <path d="M25,31 Q32,28.5 39,31 Z"/>
        <path id="antlerL" d="M26,30.5 C23.8,25.5 22.6,20.8 22.2,16.6 C21.9,13.8 21.2,11.6 19.8,9.8 C19.6,11.2 19.2,12.4 18.6,13.4 C18,11 17.4,8.6 16.3,6.7 C16,8.5 15.4,10.4 14.5,11.8 C13.7,9.3 12.7,6.9 11.2,5.2 C11,7.1 10.5,9.2 9.6,10.8 C8.6,8.5 7,6.6 5,5.5 C5.1,7.4 4.8,9.5 4,11.2 C3,9.7 1.7,8.8 0.5,8.7 C1,11.6 2.2,14.7 4.8,17.6 C9,21.9 14.8,24.9 20,27.8 C22.4,29.2 24.4,30 26,30.5 Z"></path>
        <use href="#antlerL" transform="matrix(-1 0 0 1 64 0)"></use>
      </g>
      <!-- OBD-II connector head (the muzzle), 15-pin grid knocked out -->
      <mask id="obdpins">
        <rect x="0" y="0" width="64" height="64" fill="black"/>
        <path d="M10,30 L54,30 L50,52 C50,54 49,55 47,55 L17,55 C15,55 14,54 14,52 Z" fill="white"/>
        <g fill="black">
          <circle cx="18" cy="38" r="1.4"/><circle cx="22" cy="38" r="1.4"/><circle cx="26" cy="38" r="1.4"/><circle cx="30" cy="38" r="1.4"/><circle cx="34" cy="38" r="1.4"/><circle cx="38" cy="38" r="1.4"/><circle cx="42" cy="38" r="1.4"/><circle cx="46" cy="38" r="1.4"/>
          <circle cx="20" cy="46" r="1.4"/><circle cx="24" cy="46" r="1.4"/><circle cx="28" cy="46" r="1.4"/><circle cx="32" cy="46" r="1.4"/><circle cx="36" cy="46" r="1.4"/><circle cx="40" cy="46" r="1.4"/><circle cx="44" cy="46" r="1.4"/>
        </g>
      </mask>
      <rect x="0" y="0" width="64" height="64" fill="currentColor" mask="url(#obdpins)"/>
    </symbol>
    <!-- ③ LETTERFORM A -->
    <symbol id="m3" viewBox="0 0 64 64">
      <path fill="currentColor" fill-rule="evenodd" d="M32,16 L49,53 L40.3,53 L37.1,45.6 L26.9,45.6 L23.7,53 L15,53 Z M32,28 L28.8,39 L35.2,39 Z"/>
      <g fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round">
        <path d="M32,17 L32,8"/>
        <path d="M32,12 L27,9 L23,10"/>
        <path d="M32,12 L37,9 L41,10"/>
      </g>
      <g fill="currentColor"><circle cx="32" cy="7" r="2.1"/><circle cx="22" cy="9.5" r="1.7"/><circle cx="42" cy="9.5" r="1.7"/></g>
    </symbol>
  </svg>

<header class="topbar">
  <svg class="emblem"><use href="#m2"></use></svg><span class="wm" title="VIDAR — Vehicle Immobilizer Disclosure &amp; Access Recovery">VIDAR</span>
  <div class="brand"><span class="name">CEM PIN Recovery</span></div>
  <div class="veh">
    <select id="car-model" class="hdr-sel" aria-label="vehicle model"></select>
    <select id="car-year" class="hdr-sel" aria-label="model year (bus speed)"></select>
  </div>
  <div class="leds">
    <span class="led" id="led-usb"><i></i>Teensy</span>
    <span class="led" id="led-fw"><i></i>Firmware</span>
    <span class="led" id="led-can"><i></i>CAN bus</span>
    <span class="led" id="led-prog"><i></i>Prog mode</span>
  </div>
</header>

<main>
 <div class="cols">
  <div class="left">

   <div class="panel eqbox">
     <div class="panel-hd">PIN Register <span class="hsub">BCD bytes · 00–99 per tile</span><span class="info" title="Enter any known PIN bytes in the tiles (BCD, two digits 00–99) — each removes a 100× factor. The crack auto-enters programming mode and auto-exits (FF C8) when it finishes or you Stop. Wiring: vtl/volvo-cem-cracker — Teensy 4.0 + 2× CF160.">&#9432;</span></div>
     <div class="panel-bd"><div class="pin" id="pin"></div></div>
   </div>

   <div class="panel" id="wizard">
     <div class="panel-hd">Setup <span class="hsub">each step gates the next</span></div>
     <div class="panel-bd">
       <ol class="wiz">
         <li class="step" id="s-teensy"><span class="sn">1</span>
           <div class="sb"><div class="srow"><b>Teensy (USB)</b> <span class="sv" id="v-teensy">checking…</span>
             <button id="b-teensy">Re-check</button></div></div></li>
         <li class="step" id="s-fw"><span class="sn">2</span>
           <div class="sb"><div class="srow"><b>Firmware</b> <span class="sv" id="v-fw">—</span>
             <span class="sm" id="m-fw"></span><button id="b-flash" disabled>Flash firmware</button></div></div></li>
         <li class="step" id="s-car"><span class="sn">3</span>
           <div class="sb"><div class="srow"><b>Connect the car</b> <span class="sv" id="v-car">—</span>
             <button id="b-car" disabled>Check car</button></div>
             <span class="sm">Plug in OBD-II, key to <b style="font-weight:600">position&nbsp;II</b> (engine off), then check.</span></div></li>
         <li class="step" id="s-pre"><span class="sn">4</span>
           <div class="sb"><b>Pre-flight</b>
             <div class="sx" id="pre-list">
               <label class="chk"><input type="checkbox" class="pf"> Laptop on AC, sleep + screensaver off</label>
               <label class="chk"><input type="checkbox" class="pf"> Stable 12&nbsp;V on the car</label>
             </div></div></li>
         <li class="step" id="s-go"><span class="sn">5</span>
           <div class="sb"><b>Run</b>
             <div class="runrow">
               <label class="field"><span>Shuffle order</span>
                 <select id="shuffle">
                   <option value="0">order 0 (0,1,2,3,4,5)</option>
                   <option value="1">order 1 (3,1,5,0,2,4)</option>
                   <option value="2">order 2 (5,2,1,4,0,3)</option>
                   <option value="3">order 3 (2,4,5,0,3,1)</option></select></label>
               <label class="field"><span>Bus speed</span>
                 <select id="speed">
                   <option value="500000">500 kbps · HS-CAN (MY2005+)</option>
                   <option value="250000">250 kbps · HS-CAN (MY≤2004)</option>
                   <option value="125000">125 kbps · MS-CAN</option></select></label>
               <label class="chk" style="align-self:flex-end;margin-bottom:9px"><input type="checkbox" id="verbose"> verbose serial</label>
             </div>
             <details class="recover" id="recwrap">
               <summary>↻ Resume an interrupted run</summary>
               <p class="recnote">If a previous sweep died mid-run (USB drop, power, crash), resume near
                 where it stopped instead of restarting. Enter the <b>same gifts · shuffle · speed</b> as
                 that run, then give its runtime <em>or</em> the last logged sweep index.</p>
               <div class="runrow">
                 <label class="field"><span>Previous run time (hours)</span>
                   <input type="text" id="rec-hours" inputmode="decimal" placeholder="e.g. 7.6"></label>
                 <label class="field"><span>…or exact last sweep index</span>
                   <input type="text" id="rec-index" inputmode="numeric" placeholder="from a 'sweep progress N' line"></label>
               </div>
               <div class="recprev" id="rec-preview">Enter a runtime or index to preview the resume point.</div>
             </details>
             <div class="runbtns">
               <button class="go" id="start" disabled>Start crack</button>
               <button class="stop" id="stop" disabled>Stop</button>
               <button id="progoff" title="reset all ECUs to normal (FF C8) — manual exit">Exit prog mode</button>
             </div></div></li>
       </ol>
     </div>
   </div>

   <div class="panel">
     <div class="panel-hd">Parsed Progress</div>
     <div class="panel-bd">
       <table id="bytes"></table>
       <div class="sublabel" id="conthead" style="display:none">Top contenders · active byte (p_hi)</div>
       <table id="cont"></table>
     </div>
   </div>
  </div>

  <div class="right">
   <div class="panel term statbar">
     <div class="panel-hd">Status <span class="hsub" id="phase">idle</span>
       <div class="metrics">
         <div><div class="k">Probes</div><div class="val" id="probes">0</div></div>
         <div><div class="k">Elapsed</div><div class="val" id="elapsed">0.0s</div></div>
         <div><div class="k">Shuffle</div><div class="val" id="ord">—</div></div>
         <div><div class="k">Result</div><div class="val" id="result">—</div></div>
       </div>
       <label class="chk" id="aslabel"><input type="checkbox" id="autoscroll" checked> auto-scroll</label>
     </div>
     <div class="bar"><i id="barfill"></i></div>
     <div class="err" id="err"></div>
     <div class="panel-bd">
       <div class="sublabel">Key events</div>
       <div class="events" id="events"></div>
       <div class="sublabel">Serial log · raw</div>
       <div id="logbox"></div>
     </div>
   </div>
  </div>
 </div>
</main>

<footer class="statusbar">
  <span id="sb-port">no device</span>
  <span class="sep">│</span><span id="sb-fw">fw —</span>
  <span class="sep">│</span><span id="sb-speed">500 kbps</span>
  <span class="spacer"></span>
  <span id="sb-probes">0 probes</span>
  <span class="sep">│</span><span id="sb-elapsed">0.0s</span>
  <span class="sep">│</span><span id="conn"><span class="dot" id="dot"></span> idle</span>
</footer>


<script>
const PINLEN=6;
let giftMap={};      // {pos:value} known bytes, taken from the per-tile inputs at Start — NOT hardcoded
let logCursor=0;     // absolute index into the server log stream
let lastStatus={};   // most recent /api/status payload
let badGifts=new Set();   // tile indices flagged invalid on the last Start attempt
const $=id=>document.getElementById(id);
function fmt(b){return b==null?'··':b.toString(16).padStart(2,'0').toUpperCase();}
function hx(s){return parseInt(s,16);}
// Read known bytes straight from the per-tile inputs. PIN bytes are BCD, so each is two decimal
// digits 00-99 (e.g. "28" -> 0x28). Returns {gifts:{pos:val}, bad:[positions that failed]}.
function collectGifts(){const gifts={},bad=[];
  for(let i=0;i<PINLEN;i++){const el=$('g'+i); if(!el)continue;
    const t=(el.value||'').trim(); if(t==='')continue;
    if(!/^[0-9]{1,2}$/.test(t)){bad.push(i);continue;}
    gifts[i]=parseInt(t.padStart(2,'0'),16);}
  return {gifts,bad};}

// --- parsed model: per-byte state machine + key-events, derived from the raw log stream ---
const ST={bytes:[],events:[]};
function resetST(){ST.bytes=Array.from({length:PINLEN},()=>({state:'pending',value:null,note:''}));ST.events=[];}
resetST();
const LABEL={gift:'gift',measured:'measured',scanning:'scanning',unmeasurable:'brute-force',
  rejected:'rejected',recovered:'recovered',pending:'pending'};
const TILECLASS={gift:'gift',measured:'measured',recovered:'measured',scanning:'active',
  unmeasurable:'unmeas',rejected:'unmeas',pending:''};
function parseLogLine(r){
  const m=r.msg||'', set=(p,o)=>{ST.bytes[+p]=Object.assign({},ST.bytes[+p],o);};
  let x;
  if(x=m.match(/^gift pos (\d) = 0x([0-9A-F]{2}) \((confirmed|seeded)\)/))      set(x[1],{state:'gift',value:hx(x[2]),note:x[3]});
  else if(x=m.match(/^gift pos (\d) = 0x([0-9A-F]{2}): confirm.*-> REJECTED/))   set(x[1],{state:'rejected',value:hx(x[2]),note:'gift rejected'});
  else if(x=m.match(/^gift pos (\d) = 0x([0-9A-F]{2}) FAILED/))                  set(x[1],{state:'rejected',value:hx(x[2]),note:'failed confirmation'});
  else if(x=m.match(/^position (\d): starting timing scan/))                     set(x[1],{state:'scanning',note:'measuring…'});
  else if(x=m.match(/^pos (\d) round \d+: (\d+) alive,.*lead 0x([0-9A-F]{2}) p_hi=([\d.]+)/)) set(x[1],{state:'scanning',value:hx(x[3]),note:x[2]+' left · p_hi '+x[4]});
  else if(x=m.match(/^pos (\d): MEASURABLE — committed 0x([0-9A-F]{2})/))        set(x[1],{state:'measured',value:hx(x[2]),note:'resolved by timing'});
  else if(x=m.match(/^pos (\d): UNMEASURABLE/))                                  set(x[1],{state:'unmeasurable',value:null,note:'all 100 → sweep'});
  else if(x=m.match(/PIN RECOVERED: ([0-9A-F ]+) ===/)){const v=x[1].trim().split(/\s+/);
    for(let i=0;i<PINLEN&&i<v.length;i++){const cur=ST.bytes[i];
      set(i,{value:hx(v[i]),state:(cur.state==='gift'||cur.state==='measured')?cur.state:'recovered'});}}
  if(r.level&&r.level!=='info'&&r.level!=='raw'){ST.events.push(r); if(ST.events.length>24)ST.events.shift();}
}
function effByte(i){
  let b=Object.assign({},ST.bytes[i]);
  if((i in giftMap)&&b.state==='pending') b={state:'gift',value:giftMap[i],note:'seeded'};
  if(lastStatus.result){b=Object.assign({},b,{value:lastStatus.result[i]});
    if(b.state==='pending'||b.state==='scanning'||b.state==='unmeasurable') b.state='recovered';}
  return b;
}
function tileText(b){
  if(b.state==='gift'||b.state==='measured'||b.state==='recovered') return fmt(b.value);
  if(b.state==='scanning') return b.value!=null?fmt(b.value):'??';
  if(b.state==='unmeasurable') return 'brute';
  if(b.state==='rejected') return '✗';
  return '··';
}
function renderPin(){
  const wrap=$('pin');
  if(wrap.children.length!==PINLEN){wrap.innerHTML='';
    for(let i=0;i<PINLEN;i++){const d=document.createElement('div');d.className='byte';d.id='b'+i;
      d.innerHTML='<div class="pos">pin['+i+']</div>'+
        '<input class="g" id="g'+i+'" maxlength="2" placeholder="··" autocomplete="off" spellcheck="false" aria-label="known byte pin['+i+']">'+
        '<div class="v">··</div><div class="lbl"></div>';
      wrap.appendChild(d);}
    for(let i=0;i<PINLEN;i++){const el=$('g'+i);
      el.addEventListener('input',()=>{el.value=el.value.replace(/[^0-9]/g,'').slice(0,2);
        badGifts.delete(i); $('err').textContent=''; renderPin();});}}
  // editable when idle with no result; show live/recovered state while running OR after a hit
  // (so the recovered PIN stays visible in the tiles on DONE). A failed/aborted run leaves
  // result=null, so the tiles return to editable for a retry.
  const editing=!lastStatus.running && !lastStatus.result;
  for(let i=0;i<PINLEN;i++){const el=$('b'+i),g=$('g'+i),v=el.querySelector('.v'),lbl=el.querySelector('.lbl');
    if(editing){
      g.style.display='';v.style.display='none';lbl.style.display='none';
      const has=/^[0-9]{1,2}$/.test((g.value||'').trim());
      el.className='byte'+(badGifts.has(i)?' invalid':(has?' gift':''));
    }else{
      g.style.display='none';v.style.display='';lbl.style.display='';
      const b=effByte(i);
      el.className='byte'+(TILECLASS[b.state]?' '+TILECLASS[b.state]:'');
      v.textContent=tileText(b);
      lbl.textContent=(b.state==='pending')?'':LABEL[b.state];}}
}
function renderBytes(){
  let h='<tr><th>byte</th><th>state</th><th>value</th><th>detail</th></tr>';
  for(let i=0;i<PINLEN;i++){const b=effByte(i);
    const val=(b.state==='unmeasurable')?'—':(b.value!=null?fmt(b.value):'··');
    h+='<tr><td>pin['+i+']</td><td class="st-'+b.state+'">'+LABEL[b.state]+'</td><td>'+val+'</td><td>'+(b.note||'')+'</td></tr>';}
  $('bytes').innerHTML=h;
}
function renderCont(){
  const bytes=lastStatus.bytes||[]; const act=bytes.find(b=>b.active&&b.top&&b.top.length);
  if(!act){$('conthead').style.display='none';$('cont').innerHTML='';return;}
  $('conthead').style.display='';
  let h='<tr><th>value</th><th>p_hi</th></tr>';
  (act.top||[]).forEach(t=>{h+='<tr><td>0x'+t[0].toString(16).padStart(2,'0').toUpperCase()+'</td><td>'+t[1]+'</td></tr>';});
  $('cont').innerHTML=h;
}
function renderEvents(){
  if(!ST.events.length){$('events').innerHTML='<div class="ev"><span class="em" style="color:var(--mut)">No events yet.</span></div>';return;}
  $('events').innerHTML=ST.events.map(r=>'<div class="ev '+(r.level||'')+'"><span class="et">'+(r.elapsed||0).toFixed(1)+'s</span><span class="em"></span></div>').join('');
  const ems=$('events').querySelectorAll('.em'); ST.events.forEach((r,i)=>{ems[i].textContent=r.msg;});
}
async function poll(){
  try{lastStatus=await (await fetch('/api/status')).json(); const st=lastStatus;
    $('phase').textContent=st.phase||''; $('phase').title=st.phase||'';
    $('err').textContent=st.error||'';
    $('probes').textContent=(st.probes||0).toLocaleString();
    $('elapsed').textContent=(st.elapsed||0)+'s';
    $('ord').textContent=st.shuffle?('('+st.shuffle.join(',')+')'):'—';
    $('result').textContent=st.result?st.result.map(fmt).join(' '):'—';
    const known=(st.pin||[]).filter(x=>x!=null).length;
    $('barfill').style.width=(st.result?100:Math.round(known/PINLEN*100))+'%';
    $('dot').className='dot'+(st.running?' on':'');
    $('conn').lastChild.textContent=' '+(st.running?'running':(st.result?'DONE':'idle'));
    $('stop').disabled=!st.running; if(typeof gateGo==='function')gateGo();
    renderPin(); renderBytes(); renderCont();
  }catch(e){}
}
function appendLog(lines){const box=$('logbox');const stick=$('autoscroll').checked;
  lines.forEach(r=>{parseLogLine(r);
    const d=document.createElement('div');d.className='logln '+(r.level||'info');
    d.innerHTML='<span class="ts">'+(r.elapsed||0).toFixed(1)+'s</span><span class="msg"></span>';
    d.querySelector('.msg').textContent=r.msg;box.appendChild(d);});
  while(box.children.length>4000)box.removeChild(box.firstChild);
  if(stick)box.scrollTop=box.scrollHeight;
  renderPin(); renderBytes(); renderEvents();}
async function pollLog(){try{const r=await(await fetch('/api/log?since='+logCursor)).json();
  if(r.lines&&r.lines.length)appendLog(r.lines); logCursor=r.cursor;}catch(e){}}
// ---- setup wizard: gated steps; Start unlocks only when every gate passes ----
let teensyPort=null; const wiz={teensy:false,fw:false,car:false};
async function postJ(url,body){const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body||{})});
  const j=await r.json().catch(()=>({})); if(j&&j.msg)$('err').textContent=j.msg; return j;}
function setStep(id,cls){const e=$('s-'+id); if(e)e.className='step '+cls;}
function allPinsFilled(){const r=collectGifts();return r.bad.length===0 && Object.keys(r.gifts).length===PINLEN;}
function gateGo(){const pre=[...document.querySelectorAll('.pf')].every(c=>c.checked);
  const base=wiz.teensy&&wiz.fw&&wiz.car;               // Teensy found + firmware ok + car alive
  const crackReady=base&&pre, check=allPinsFilled();
  const btn=$('start');
  // all 6 bytes entered => this is a VERIFY, not a crack: relabel + recolour + lighter gate (no pre-flight)
  btn.textContent=check?'Check PIN':'Start crack';
  btn.classList.toggle('checkpin',check);
  btn.title=check?'All 6 bytes entered — verify this PIN with a single unlock (no crack)':'';
  btn.disabled=!!lastStatus.running||(check?!base:!crackReady);
  return crackReady;}
async function checkTeensy(){
  let r; try{r=await(await fetch('/api/teensy'+(teensyPort?('?port='+encodeURIComponent(teensyPort)):''))).json();}catch(e){return;}
  if(r.busy)return;
  if(!r.found){$('v-teensy').textContent='not found — plug the Teensy into USB';setStep('teensy','fail active');
    wiz.teensy=wiz.fw=false;setStep('fw','');$('v-fw').textContent='—';$('b-flash').disabled=true;$('b-car').disabled=true;gateGo();return;}
  teensyPort=r.port;$('v-teensy').textContent='found on '+r.port;setStep('teensy','done');wiz.teensy=true;
  if(r.matches){$('v-fw').textContent='✓ '+r.version+' (expected '+r.expected+')';setStep('fw','done');wiz.fw=true;
    $('b-flash').disabled=true;$('m-fw').textContent='';$('b-car').disabled=false;if(!wiz.car)setStep('car','active');}
  else{$('v-fw').textContent=(r.version||'unknown')+' ≠ expected '+r.expected+' — flash required';setStep('fw','fail active');
    wiz.fw=false;$('b-flash').disabled=false;$('b-car').disabled=true;}
  gateGo();}
async function checkCar(){$('v-car').textContent='sniffing the bus…';
  const qs=new URLSearchParams(); if(teensyPort)qs.set('port',teensyPort); const sp=$('speed'); if(sp)qs.set('speed',+sp.value);
  let r; try{r=await(await fetch('/api/carcheck?'+qs.toString())).json();}catch(e){return;}
  if(r.busy){$('v-car').textContent='port busy — retrying…';setTimeout(checkCar,800);return;}
  if(r.alive){$('v-car').textContent='✓ car alive — '+r.frames+' frames, '+r.modules+' modules';setStep('car','done');wiz.car=true;setStep('pre','active');}
  else{$('v-car').textContent='no bus traffic — check OBD-II seated + key in position II'+(r.error?(' ('+r.error+')'):'');setStep('car','fail active');wiz.car=false;}
  gateGo();}
$('b-teensy').onclick=checkTeensy;
$('b-flash').onclick=async()=>{if(!confirm('Flash firmware to the Teensy? Disconnect it from the car first if attached.'))return;
  $('m-fw').textContent='flashing… watch the log →';logCursor=0;$('logbox').innerHTML='';await postJ('/api/flash',{});
  setTimeout(()=>{$('m-fw').textContent='verifying…';checkTeensy();},9000);};
$('b-car').onclick=checkCar;
$('progoff').onclick=async()=>{if(confirm('Send reset-all-ECUs (FF C8) to exit programming mode?'))await postJ('/api/progoff',{port:teensyPort});};
document.querySelectorAll('.pf').forEach(c=>c.addEventListener('change',gateGo));
$('start').onclick=async()=>{
  if(allPinsFilled())return doCheckPin();          // all 6 bytes entered => verify this PIN, don't crack
  if(!gateGo()){$('err').textContent='Finish the setup steps first.';return;}
  const {gifts,bad}=collectGifts();
  if(bad.length){badGifts=new Set(bad);renderPin();$('err').textContent='Check pin['+bad.join('], pin[')+']: two digits 00–99 (BCD), or blank.';return;}
  const recH=($('rec-hours').value||'').trim(), recI=($('rec-index').value||'').trim(), recovering=!!(recH||recI);
  let cmsg='Start the crack now? The car enters programming mode for the run and auto-exits (FF C8) when it finishes or you Stop.';
  if(recovering)cmsg='RESUME a previous run — the sweep STARTS PART-WAY IN (see the resume preview). Use the SAME gifts + shuffle as the dead run, or it searches the wrong place.\n\n'+cmsg;
  if(!confirm(cmsg))return;
  badGifts=new Set();giftMap=gifts;logCursor=0;$('logbox').innerHTML='';resetST();renderBytes();renderEvents();
  const body={shuffle:$('shuffle').value,speed:+$('speed').value,gifts:giftMap,port:teensyPort,verbose:$('verbose').checked};
  if(recI)body.resume_index=parseInt(recI,10); else if(recH)body.resume_runtime_s=(parseFloat(recH)||0)*3600;
  const j=await postJ('/api/start',body);
  if(!j.ok)$('err').textContent=j.msg||'failed to start';};
$('stop').onclick=async()=>{await fetch('/api/stop',{method:'POST'});};
// ---- Check PIN: all 6 bytes entered -> one unlock attempt (+negative control), no crack worker ----
async function doCheckPin(){
  const r=collectGifts();
  if(r.bad.length||Object.keys(r.gifts).length!==PINLEN){$('err').className='err';$('err').textContent='Enter all 6 bytes (00–99 each).';return;}
  const pin=[]; for(let i=0;i<PINLEN;i++)pin.push(r.gifts[i]);
  const btn=$('start'), old=btn.textContent; btn.disabled=true; btn.textContent='Checking…';
  $('err').className='err'; $('err').textContent=''; logCursor=0; $('logbox').innerHTML='';
  let j; try{ j=await postJ('/api/checkpin',{pin:pin,shuffle:$('shuffle').value,speed:+$('speed').value,port:teensyPort}); }
  catch(e){ j={ok:false,msg:'request failed'}; }
  btn.textContent=old; gateGo();
  const tag=!j.ok?'bad':(j.confirmed?'good':(j.unlocked?'warn':'bad'));
  $('err').className='err '+tag; $('err').textContent=j.msg||(j.ok?'':'check failed');}
// ---- recover-mode resume preview (server computes the cursor; this only displays it) ----
function recHuman(s){if(s<90)return s.toFixed(0)+'s';if(s<5400)return (s/60).toFixed(1)+' min';return (s/3600).toFixed(1)+' h';}
let recTimer=null;
async function updateRecPreview(){
  const el=$('rec-preview'); if(!el)return;
  const recH=($('rec-hours').value||'').trim(), recI=($('rec-index').value||'').trim();
  if(!recH&&!recI){el.className='recprev';el.textContent='Enter a runtime or index to preview the resume point.';return;}
  let giftN=0; try{giftN=Object.keys(collectGifts().gifts).length;}catch(e){}
  const qs=new URLSearchParams(); qs.set('gifts',giftN);
  if(recI)qs.set('index',recI); else qs.set('runtime',(parseFloat(recH)||0)*3600);
  let r; try{r=await(await fetch('/api/resume_preview?'+qs.toString())).json();}catch(e){return;}
  if(r.cursor>=r.space-1){el.className='recprev warn';
    el.textContent='That runtime covers the WHOLE '+r.space.toLocaleString()+'-combo space — the prior run either finished or the estimate is too high. Lower it, or start fresh.';return;}
  el.className='recprev';
  el.textContent='Resume at index '+r.cursor.toLocaleString()+' / '+r.space.toLocaleString()+
    ' ('+r.pct.toFixed(2)+'% in, '+r.swept+' bytes swept) · ≈ '+recHuman(r.remaining_s)+' left'+
    (recI?' · exact (from log)':' · runtime estimate, rewound 5% for safety');}
['rec-hours','rec-index'].forEach(id=>{const e=$(id); if(e)e.addEventListener('input',()=>{clearTimeout(recTimer);recTimer=setTimeout(updateRecPreview,250);});});

// ---- chassis chrome: status indicators + bottom status bar (additive; reads existing state) ----
function syncChrome(){
  const led=(id,cls)=>{const e=$('led-'+id); if(e)e.className='led'+(cls?' '+cls:'');};
  led('usb', wiz.teensy?'on':'');
  led('fw',  wiz.fw?'on':(wiz.teensy?'warn':''));
  led('can', wiz.car?'on':'');
  led('prog',lastStatus.running?'on':'');
  const set=(id,t)=>{const e=$(id); if(e)e.textContent=t;};
  set('sb-port', teensyPort||'no device');
  set('sb-fw', 'fw '+(wiz.fw?'ok':'—'));
  const sp=$('speed'); set('sb-speed', sp?((+sp.value/1000)+' kbps'):'500 kbps');
  set('sb-probes', (lastStatus.probes||0).toLocaleString()+' probes');
  set('sb-elapsed', (lastStatus.elapsed||0)+'s');
  set('sb-state', lastStatus.running?'RUNNING':(lastStatus.result?'DONE':'IDLE'));
}

renderPin(); renderBytes(); renderEvents(); setStep('teensy','active'); checkTeensy();
setInterval(poll,500); setInterval(pollLog,500); setInterval(()=>{if(!wiz.teensy||!wiz.fw)checkTeensy();},4000);
setInterval(syncChrome,500); poll(); pollLog(); syncChrome();
</script>
<script>
// Header vehicle picker — populated from cars.json (Volvo P2). The crack runs on HS-CAN, and
// HS-CAN speed is fixed by model year: MY<=2004 = 250 kbps, MY>=2005 = 500 kbps. Selecting the
// car/year sets the run bus speed (#speed), so the year option carries the speed in parentheses.
(async function(){
  const $=id=>document.getElementById(id);
  const mSel=$('car-model'),ySel=$('car-year'),spd=$('speed');
  if(!mSel)return;
  let cars=[];
  try{cars=((await (await fetch('cars.json')).json()).cars)||[];}catch(e){}
  if(!cars.length)return;
  const hsFor=y=>(+y<=2004?250000:500000);
  const kb=v=>(v/1000)+' kbps';
  function fillYears(car){let h='';for(let y=car.year_end;y>=car.year_start;y--){h+='<option value="'+y+'">'+y+' ('+kb(hsFor(y))+')</option>';}ySel.innerHTML=h;}
  function applySpeed(){const s=hsFor(ySel.value);
    if(spd){if(![...spd.options].some(o=>+o.value===s)){const o=document.createElement('option');o.value=s;o.textContent=kb(s)+' · HS-CAN';spd.insertBefore(o,spd.firstChild);}
      spd.value=s;}
    if(typeof syncChrome==='function')syncChrome();}
  mSel.innerHTML=cars.map(c=>'<option value="'+c.id+'">'+c.model+'</option>').join('');
  mSel.addEventListener('change',()=>{fillYears(cars.find(c=>c.id===mSel.value));applySpeed();});
  ySel.addEventListener('change',applySpeed);
  mSel.value='xc70'; fillYears(cars.find(c=>c.id==='xc70')||cars[0]); ySel.value='2007'; applySpeed();
})();
</script>

</body></html>"""


def main():
    global PREFERRED_PORT
    ap = argparse.ArgumentParser(description="Web UI for the CEM PIN cracker (real Teensy only)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8731)
    ap.add_argument("--port-serial", default=None,
                    help="serial device for the Teensy; preselected in the UI (optional)")
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()
    PREFERRED_PORT = args.port_serial
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    url = f"http://{args.host}:{args.port}"
    print(f"CEM cracker UI -> {url}   (Ctrl-C to quit; the car is returned to normal on exit)")

    # SAFETY: on ANY exit path, abort a running crack and let its worker broadcast FF C8 before we
    # die — a bare exit would leave the car in programming mode (modules on constant 12 V; a key
    # cycle won't clear it). atexit covers normal return + Ctrl-C; the SIGTERM handler routes a kill
    # through the same path. (The firmware's ~10 s host-silence watchdog is the final backstop.)
    import atexit, signal
    atexit.register(SESSION.shutdown)
    def _on_term(_signo, _frame):
        print("\nsignal received — returning the car to normal (exiting programming mode)…")
        SESSION.shutdown()
        raise SystemExit(0)            # unwinds cleanly; atexit (idempotent) also runs
    try:
        signal.signal(signal.SIGTERM, _on_term)
    except Exception:                  # noqa: BLE001  (not all platforms/threads allow this)
        pass

    if not args.no_browser:
        try:
            webbrowser.open(url)
        except Exception:        # noqa: BLE001
            pass
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping — returning the car to normal (exiting programming mode)…")
        SESSION.shutdown()
        print("bye — car reset (or will auto-reset within ~10 s via the firmware watchdog)")


if __name__ == "__main__":
    main()
