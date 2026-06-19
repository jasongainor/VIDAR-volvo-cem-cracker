# VIDAR-volvo-cem-cracker — Volvo P2 CEM PIN recovery

A timing-attack tool that recovers the 6-byte CEM security PIN on **Volvo P2-platform vehicles**
(S60 / V70 / XC70 / S80 / XC90, ~2000–2009), so the owner can perform authenticated work on their own
car. It is a from-scratch reimplementation **derived from**
[`vtl/volvo-cem-cracker`](https://github.com/vtl/volvo-cem-cracker) (GPL-3.0) — protocol-compatible with
it and built on its reverse-engineering — re-engineered to land reliably and to be driven from a browser
instead of raw serial logs. See [License and credits](#license-and-credits).

> **Use only on a vehicle you own or are authorized to service.**

## Contents

- [Quick start](#quick-start)
- [Tutorial — your first crack](TUTORIAL.md)
- [Why a PIN must be recovered](#why-a-pin-must-be-recovered)
- [How it works](#how-it-works) — deep dive in [HOW-IT-WORKS.md](HOW-IT-WORKS.md)
- [The UI](#the-ui)
- [Hardware](#hardware)
- [Layout](#layout)
- [Notes and limitations](#notes-and-limitations)
- [License and credits](#license-and-credits) — and [findings reused from vtl](#findings-reused-from-vtl)

## Quick start

New here? Walk through [**TUTORIAL.md**](TUTORIAL.md) — it takes you from a bare Teensy to a recovered
PIN. The short version:

```sh
bash setup.sh
```

That one command installs Python (if missing), creates a local virtualenv, installs `pyserial` +
PlatformIO, sets up the Teensy USB driver for your OS, builds the firmware, offers to flash it, and
launches the UI. Works in bash on **macOS, Linux, and Windows (Git Bash / MSYS2)**.

Already set up? Launch directly:

```sh
.venv/bin/python -m cemcrack.webui          # then open http://127.0.0.1:8731
.venv/bin/python tests/test_engine.py        # software self-test (no hardware)
```

## Why a PIN must be recovered

The 6-byte CEM PIN gates authenticated diagnostics on a P2 car. It is **not stored in VIDA** (on-line
security codes are fetched per authorized session) and **cannot be calculated** from the VIN or serial
number. A timing side-channel on the CEM is the practical route — and it needs sub-microsecond reply
timing, which a PC/USB/J2534 interface can't deliver, so the timing runs on a microcontroller.

## How it works

The CEM answers an unlock attempt a hair slower when a PIN byte is correct. The tool measures that on a
Teensy (hardware-timestamped, sub-µs), scores each candidate with an outlier-immune **bucket statistic**,
eliminates losers by **confidence interval** (never culling the truth), and **refuses to commit a byte
it can't measure** — carrying its full range into a final brute **sweep** instead, so the cascade
failure that makes naive attacks fail can't happen. Known bytes you enter as **gifts** each remove a
100× factor. Full detail: **[HOW-IT-WORKS.md](HOW-IT-WORKS.md)**.

## The UI

A single-operator browser console (real-hardware only — no simulator path in the operator UI). A gated
wizard walks you through Teensy → firmware → car → pre-flight, then:

- **Crack** — enter any bytes you already know in the 6 tiles (optional), pick the bus speed, Start.
  A live log streams every probe; the recovered PIN stays shown in the tiles on DONE.
- **Check PIN** — fill in **all 6** tiles and the button turns green and becomes *Check PIN*: it fires
  one unlock attempt (plus a wrong-PIN negative control) and tells you if that PIN is correct — no crack.
- **Resume** — "Resume an interrupted run" estimates where a previous sweep died (from its runtime or a
  logged sweep index) and restarts the sweep there instead of from zero.
- **Exit prog mode** — always reachable; broadcasts the reset (`FF C8`) to return the car to normal.

## Hardware

- **Teensy 4.0 + 2× CAN transceivers** (the standard `vtl/volvo-cem-cracker` rig).
- CAN1 = high-speed bus (500 kbps, where the CEM answers); CAN2 = medium-speed bus (125 kbps).
- Wiring follows the public `vtl/volvo-cem-cracker` pinout (CAN1 TX=22 / RX=23). Tap HS-CAN at OBD-II
  (pin 6 = CAN-H, pin 14 = CAN-L). Keep stable 12 V — voltage sag corrupts the timing.

## Layout

- `cemcrack/cemproto.py` — CAN frame constants, 6-byte BCD encoding, shuffle orders.
- `cemcrack/engine.py` — the smart search (best-arm CI elimination + measurability gate + final sweep).
- `cemcrack/transport.py` — `SimTransport` (tests) and `SerialTransport` (real Teensy).
- `cemcrack/sim.py` — timing simulator (test harness only; configurable channel profiles).
- `cemcrack/webui.py` — the browser UI and its JSON API (real hardware only).
- `firmware/cem_probe/cem_probe.ino` — Teensy firmware (P/U/S/G/LP/BSWEEP protocol, DWT-timestamped).
- `tests/test_engine.py` — engine self-test against the simulator (no hardware).

## Notes and limitations

- Pure-stdlib Python for the engine and UI; `pyserial` only for the real-hardware transport,
  PlatformIO only to build/flash the firmware.
- The operator UI is **real-hardware only** — it refuses to start without a serial port rather than
  fabricate data. The simulator lives only in the test suite.
- Firmware ships with working P2 defaults (500 kbps CAN1, arb-id `0x0FFFFE`, reply byte[2]==0x00); the
  host pushes the bus speed at connect, so the firmware never needs editing.
- The CAN framing follows public `vtl` research and **must be validated on your bench** before trusting
  a result — that is the one thing only real hardware can confirm.

## License and credits

Licensed under the **GNU General Public License v3.0** — see [LICENSE](LICENSE).

This is a derivative of **[vtl/volvo-cem-cracker](https://github.com/vtl/volvo-cem-cracker)** (GPL-3.0),
copyright © 2020, 2021 **Vitaly Mayatskikh**, **Christian Molson**, and **Mark Dapoz**. They did the
foundational reverse-engineering this entire tool stands on; please credit them too.

### Findings reused from vtl

None of their source code is copied verbatim — but the hard-won *discoveries* below are theirs, and this
project depends on every one of them:

| Finding (theirs) | What it is / where it lives here |
|---|---|
| **PIN shuffle orders** | the four per-model byte→frame permutations `{0,1,2,3,4,5}`, `{3,1,5,0,2,4}`, `{5,2,1,4,0,3}`, `{2,4,5,0,3,1}` — reproduced byte-for-byte in `cemproto.SHUFFLE_ORDERS` |
| **Unlock protocol** | arb-id `0x0FFFFE`; request frame `[0x50, 0xBE, m0..m5]`; reply `[0x50, 0xB9, status]` with `status == 0x00` ⇒ unlocked |
| **Programming mode** | broadcast `FF 86` to enter; `FF C8` to reset/exit all ECUs (the safe alternative to a battery pull) |
| **The timing side-channel** | the CEM takes measurably longer to reject a PIN whose *leading* (shuffle-order) bytes are correct — the whole basis of the attack |
| **6-byte BCD PIN** | the PIN is six BCD bytes (100 values each), not arbitrary bytes |
| **The rig** | Teensy 4.0 + 2× CAN transceivers, with DWT-cycle-counter timing on the MCU |

### What's original here

Versus their single-file Teensy sketch:

- a **host/firmware split** over an ASCII line protocol — the Teensy is a dumb-fast probe server; all
  the intelligence runs on a Python host;
- a different, more robust **statistical engine** — the `p_hi` bucket statistic, confidence-interval
  successive elimination with a **measurability gate**, and gift re-confirm (vs. their fixed-stage
  histogram + standard-deviation method);
- a **browser UI** with a gated wizard, **Check PIN** verify, and **resumable** runs;
- a resumable **MCU-delegated brute sweep** with a lockout pre-flight.

Because the protocol facts, shuffle-order tables, and method are theirs, this is released under their
license (GPL-3.0) with attribution.
