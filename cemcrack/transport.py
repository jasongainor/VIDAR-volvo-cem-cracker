# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Jason Gainor
# Derived from volvo-cem-cracker — Copyright (C) 2020, 2021 Vitaly Mayatskikh,
# Christian Molson, Mark Dapoz — https://github.com/vtl/volvo-cem-cracker (GPL-3.0).
"""Transport: how the engine reaches a CEM. Two backends, same interface, so the smart
search in engine.py is identical whether it's driving the simulator or a real Teensy.

The hard real-time bit (sub-microsecond CAN reply timing) lives on the TEENSY, not here —
USB latency would swamp a host-side measurement. So SerialTransport just asks the Teensy
"probe this PIN N times, give me the latency samples" / "try to unlock this PIN". All the
intelligence (which PINs to probe, the statistics, when to stop) is host-side and shared.
"""
from __future__ import annotations

import time
from abc import ABC, abstractmethod

from . import cemproto


class Transport(ABC):
    @abstractmethod
    def probe(self, pin: list[int], n: int, shuffle_order) -> list[float]:
        """Return n latency samples (microseconds) for unlock attempts with this PIN."""

    @abstractmethod
    def unlock(self, pin: list[int], shuffle_order) -> bool:
        """Deterministic check: try to actually unlock; True iff the PIN is correct."""

    def close(self) -> None:
        pass

    def prog_on(self) -> None:
        """Enter & hold the bus in programming mode (real hardware only; no-op for the sim)."""

    def prog_off(self) -> None:
        """Exit programming mode / reset all ECUs back to normal (no-op for the sim)."""


class SimTransport(Transport):
    """Drives the in-process CemSimulator (offline dev / demo / tests)."""

    def __init__(self, simulator):
        self.sim = simulator

    def probe(self, pin, n, shuffle_order):
        return [self.sim.probe_latency_us(pin) for _ in range(n)]

    def unlock(self, pin, shuffle_order):
        return self.sim.unlock(pin)


class SerialTransport(Transport):
    """Drives the Teensy probe firmware over USB serial (line protocol in firmware/).

    Protocol (ASCII, one line each):
       host -> 'P <n> <16 hex chars = 8 frame bytes>'   teensy -> 'L <us> <us> ... '
       host -> 'U <16 hex chars>'                       teensy -> 'U 1' | 'U 0'
       host -> 'S <500000|250000|125000>'               teensy -> 'S ok'
    """

    def __init__(self, port: str, baud: int = 2_000_000, can_speed: int = 500_000, timeout: float = 5.0,
                 raw_log=None, verbose: bool = False):
        import serial  # lazy: only needed for real hardware
        self.ser = serial.Serial(port, baud, timeout=timeout)
        self.raw_log = raw_log     # callback(direction, text): mirror every serial line, verbatim
        self.verbose = verbose     # if False, the high-volume per-probe P/U traffic is not raw-logged
        time.sleep(2.0)  # let the Teensy reset/boot
        self._cmd(f"S {can_speed}")

    def _raw(self, direction: str, text: str):
        if self.raw_log:
            self.raw_log(direction, text)

    def _cmd(self, line: str, log: bool = True) -> str:
        self.ser.reset_input_buffer()
        self.ser.write((line + "\n").encode())
        resp = self.ser.readline().decode(errors="replace").strip()
        if log:
            self._raw(">>", line)
            self._raw("<<", resp)
        return resp

    def probe(self, pin, n, shuffle_order):
        frame = cemproto.build_unlock_frame(pin, shuffle_order)
        hexf = "".join(f"{b:02x}" for b in frame)
        resp = self._cmd(f"P {n} {hexf}", log=self.verbose)   # gated: thousands of these per crack
        if not resp.startswith("L"):
            raise RuntimeError(f"unexpected probe reply: {resp!r}")
        return [float(x) for x in resp.split()[1:] if float(x) >= 0]   # drop -1 timeouts

    def unlock(self, pin, shuffle_order):
        frame = cemproto.build_unlock_frame(pin, shuffle_order)
        hexf = "".join(f"{b:02x}" for b in frame)
        resp = self._cmd(f"U {hexf}", log=self.verbose)
        return resp.strip().endswith("1")

    def prog_on(self):
        """Enter & hold programming mode (Teensy PROGON: ~1.5s establishment burst, then held)."""
        old, self.ser.timeout = self.ser.timeout, 6.0
        try:
            return self._cmd("PROGON")
        finally:
            self.ser.timeout = old

    def prog_off(self):
        """Exit programming mode: the Teensy broadcasts the reset-all-ECUs frame (FF C8) ~5s."""
        old, self.ser.timeout = self.ser.timeout, 9.0
        try:
            return self._cmd("PROGOFF")
        finally:
            self.ser.timeout = old

    def set_gap(self, gap_us: int):
        """Inter-attempt settle gap (raise if the CEM throttles failed unlocks)."""
        self._cmd(f"G {int(gap_us)}")

    def lockout_probe(self, n: int, abort=None):
        """Fire n deliberately-wrong unlocks on the MCU; returns (responded, n). If responded
        << n the CEM is throttling/locking out and a full sweep is unsafe at speed. BOUNDED so it
        can never hang the crack thread past the prog-mode reset: a finite per-read timeout, an
        overall deadline, and an abort callback (sends 'X' once to break the firmware loop, like
        batch_sweep). On the deadline it raises so the engine's finally still runs prog_off()."""
        self.ser.reset_input_buffer()
        self.ser.write(f"LP {int(n)}\n".encode())
        # worst case ~ n * REPLY_TIMEOUT (8 ms) if the CEM stops answering, plus a generous margin
        deadline = time.monotonic() + max(30.0, n * 0.01 + 15.0)
        sent_abort = False
        old, self.ser.timeout = self.ser.timeout, 1.0
        try:
            while True:
                if abort and abort() and not sent_abort:
                    self.ser.write(b"X"); sent_abort = True     # break the firmware lockout loop
                if time.monotonic() > deadline:
                    raise RuntimeError("lockout pre-flight timed out — no LP reply from the Teensy")
                ln = self.ser.readline().decode(errors="replace").strip()
                if ln.startswith("LP "):
                    parts = ln.split()
                    return int(parts[1]), int(parts[2])
        finally:
            self.ser.timeout = old

    def batch_sweep(self, base_frame, varpos, start=0, order="std", progress_cb=None, abort=None):
        """Hand the exhaustive sweep to the Teensy (CAN-bound, not USB-bound — the big speed
        lever). Iterates the given 8-byte-frame positions over BCD 00..99; returns (frame, idx)
        on the unlock, or (None, tried) when exhausted/aborted. Resumable via start."""
        hexf = "".join(f"{b:02x}" for b in base_frame)
        vp = ",".join(str(p) for p in varpos)
        self.ser.reset_input_buffer()
        self.ser.write(f"BSWEEP {hexf} {vp} {order} {int(start)}\n".encode())
        old, self.ser.timeout = self.ser.timeout, 2.0
        sent_abort = False
        try:
            while True:
                if abort and abort() and not sent_abort:
                    self.ser.write(b"X"); sent_abort = True   # send the abort token ONCE (firmware
                    #   ignores a stray leading 'X' between commands, but don't pile them up anyway)
                ln = self.ser.readline().decode(errors="replace").strip()
                if not ln:
                    continue
                tag = ln.split()
                if tag[0] == "H":
                    frame = [int(tag[1][i:i + 2], 16) for i in range(0, 16, 2)]
                    return frame, int(tag[2])
                if tag[0] == "P" and progress_cb:
                    progress_cb(int(tag[1]))
                if tag[0] == "D":
                    return None, int(tag[1])
        finally:
            self.ser.timeout = old

    def close(self):
        try:
            self.ser.close()
        except Exception:
            pass
