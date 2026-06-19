# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Jason Gainor
# Derived from volvo-cem-cracker — Copyright (C) 2020, 2021 Vitaly Mayatskikh,
# Christian Molson, Mark Dapoz — https://github.com/vtl/volvo-cem-cracker (GPL-3.0).
"""Validate the hardened engine against a representative P2 CEM channel (sim.real_p2_generic),
plus a synthetic smoke test. Proves the four things that matter:

  1. the bucket p_hi estimator MEASURES a readable byte (pin[0], ~0.20us) correctly;
  2. an UNREADABLE byte (pin[2], ~0.01us) is DECLARED UNMEASURABLE rather than committed to a
     coin-flip — the cascade failure a naive sweep makes when it commits a guess on a flat byte;
  3. the true value of an unmeasurable byte is carried into the finish;
  4. gifts are re-confirmed (and a wrong gift is caught), then the final sweep recovers the
     full PIN over a tractable space.

Run:  python3 tests/test_engine.py
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from cemcrack import cemproto
from cemcrack.sim import CemSimulator
from cemcrack.transport import SimTransport
from cemcrack.engine import CrackEngine, CrackConfig

failures = []


def check(name, ok, detail=""):
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  — {detail}" if detail else ""))
    if not ok:
        failures.append(name)


def hx(b):
    return "None" if b is None else f"0x{b:02X}"


ORD = cemproto.SHUFFLE_ORDERS[0]
# Arbitrary synthetic test PIN — NOT anyone's real code. Positions 0,1 stand in for any
# known "gift" bytes a user might supply at runtime; the rest exercise the search/sweep path.
SECRET = [0x36, 0x91, 0x42, 0x05, 0x99, 0x13]

print("hardened engine vs representative P2 CEM channel:\n")

# 1. synthetic smoke — basic flow end-to-end on an easy (unquantized, strong-signal) channel
sim = CemSimulator(SECRET, ORD, base_us=100.0, gain_us=4.0, noise_us=3.0)
eng = CrackEngine(SimTransport(sim), shuffle_order=ORD,
                  config=CrackConfig(max_pulls_per_byte=4000, confirm_factor=4,
                                     n_check_unmeasurable=2_000_000))
t = time.monotonic(); got = eng.crack(); dt = time.monotonic() - t
check("synthetic smoke: full PIN recovered", got == SECRET,
      f"{cemproto.fmt_pin(got) if got else None}  probes={eng.probes}  {dt:.1f}s")

# 2. P2 profile: a READABLE byte (pin[0], ~0.20us/sample) is measured correctly by p_hi
sim = CemSimulator.real_p2_generic(SECRET, ORD)
eng = CrackEngine(SimTransport(sim), shuffle_order=ORD,
                  config=CrackConfig(max_pulls_per_byte=500_000, confirm_factor=4,
                                     n_check_unmeasurable=20_000_000))
t = time.monotonic(); r0 = eng._crack_position([None] * 6, ORD[0]); dt = time.monotonic() - t
check("P2: readable pin[0] measured correctly", r0.separated and r0.committed == SECRET[ORD[0]],
      f"committed={hx(r0.committed)} sep={r0.separated} probes={r0.pulls} {dt:.1f}s")

# 3. P2 profile: an UNREADABLE byte (pin[2], ~0.01us) is DECLARED UNMEASURABLE (not guessed)
sim = CemSimulator.real_p2_generic(SECRET, ORD)
eng = CrackEngine(SimTransport(sim), shuffle_order=ORD,
                  config=CrackConfig(n_check_unmeasurable=20_000, max_pulls_per_byte=10_000,
                                     confirm_factor=6))
prefix = [None] * 6
prefix[ORD[0]] = SECRET[ORD[0]]
prefix[ORD[1]] = SECRET[ORD[1]]
t = time.monotonic(); r2 = eng._crack_position(prefix, ORD[2]); dt = time.monotonic() - t
check("P2: unreadable pin[2] declared UNMEASURABLE (no coin-flip commit)",
      (not r2.separated) and r2.committed is None and len(r2.candidates) == 100,
      f"committed={hx(r2.committed)} sep={r2.separated} carried={len(r2.candidates)} probes={r2.pulls} {dt:.1f}s")
check("P2: the TRUE pin[2] is inside the carried full axis (a naive sweep would exclude it)",
      SECRET[ORD[2]] in [v for v, _ in r2.candidates])

# 4. end-to-end: gift the 4 earliest-checked bytes, leave the last 2 unmeasurable, and let the
#    final sweep recover the full PIN over 100^2 (proves carry-100 + verify works on-channel)
sim = CemSimulator.real_p2_generic(SECRET, ORD)
gifts = {ORD[0]: SECRET[ORD[0]], ORD[1]: SECRET[ORD[1]], ORD[2]: SECRET[ORD[2]], ORD[3]: SECRET[ORD[3]]}
eng = CrackEngine(SimTransport(sim), shuffle_order=ORD,
                  config=CrackConfig(gift_bytes=gifts, gift_confirm=False,
                                     n_check_unmeasurable=20_000, max_pulls_per_byte=10_000,
                                     confirm_factor=6, verify_budget=200_000))
t = time.monotonic(); got = eng.crack(); dt = time.monotonic() - t
check("P2 end-to-end: PIN recovered via gifts + carry-100 + final sweep", got == SECRET,
      f"{cemproto.fmt_pin(got) if got else None} probes={eng.probes} {dt:.1f}s")

# 5. gift confirm: a CORRECT gift confirms; a WRONG gift is caught before any brute time
sim = CemSimulator.real_p2_generic(SECRET, ORD)
eng = CrackEngine(SimTransport(sim), shuffle_order=ORD)
ok_correct = eng._confirm_gift([None] * 6, ORD[0], SECRET[ORD[0]])
wrong_val = cemproto.bin_to_bcd((cemproto.bcd_to_bin(SECRET[ORD[0]]) + 1) % 100)
ok_wrong = eng._confirm_gift([None] * 6, ORD[0], wrong_val)
check("gift confirm: correct pin[0] gift confirmed", ok_correct is True)
check("gift confirm: wrong pin[0] gift rejected", ok_wrong is False,
      f"rival={hx(wrong_val)} confirmed={ok_wrong}")

# 6. batch-sweep delegation: on a transport that exposes batch_sweep (the real Teensy path),
#    the engine fixes gifts/measured bytes and hands the swept positions to the firmware. This
#    stub mimics the firmware's BSWEEP locally so the wiring is validated without hardware.
class FakeBatchTransport:
    def __init__(self, sim, order):
        self.sim = sim
        self.order = order
        self.swept_seen = None

    def probe(self, pin, n, order):
        return [self.sim.probe_latency_us(pin) for _ in range(n)]

    def unlock(self, pin, order):
        return self.sim.unlock(pin)

    def lockout_probe(self, n, abort=None):
        return n, n                       # no throttling in the sim

    def batch_sweep(self, base_frame, varpos, start=0, order="std", progress_cb=None, abort=None):
        self.swept_seen = list(varpos)
        total = 100 ** len(varpos)
        for idx in range(start, total):
            f = list(base_frame)
            rem = idx
            for i in range(len(varpos) - 1, -1, -1):
                f[varpos[i]] = cemproto.bin_to_bcd(rem % 100)
                rem //= 100
            pin = [f[self.order[j] + 2] for j in range(cemproto.PIN_LEN)]
            if self.sim.unlock(pin):
                return f, idx
        return None, total


sim = CemSimulator.real_p2_generic(SECRET, ORD)
ft = FakeBatchTransport(sim, ORD)
gifts4 = {ORD[0]: SECRET[ORD[0]], ORD[1]: SECRET[ORD[1]], ORD[2]: SECRET[ORD[2]], ORD[3]: SECRET[ORD[3]]}
eng = CrackEngine(ft, shuffle_order=ORD,
                  config=CrackConfig(gift_bytes=gifts4, gift_confirm=False,
                                     n_check_unmeasurable=20_000, max_pulls_per_byte=10_000,
                                     confirm_factor=6, lockout_probe_count=1000))
t = time.monotonic(); got = eng.crack(); dt = time.monotonic() - t
check("batch-sweep delegation: Teensy-path verify recovers the PIN", got == SECRET,
      f"{cemproto.fmt_pin(got) if got else None} swept_frame_pos={ft.swept_seen} {dt:.1f}s")
check("batch-sweep: swept the unmeasurable message bytes (frame idx = order+2)",
      ft.swept_seen == sorted([ORD[4] + 2, ORD[5] + 2]))

# 7. ATTACK-ORDER regression guard (the real car uses a NON-identity shuffle). Tests 1-6 use
#    SHUFFLE_ORDERS[0] = identity, where order[k]==k, so they cannot distinguish "attack pin[k]"
#    from "attack pin[order[k]]". Here we use SHUFFLE_ORDERS[1] = (3,1,5,0,2,4) — the order this
#    bench's CEM uses — on a channel where ALL six bytes carry strong signal. The CEM checks pin[i]
#    i-th, so each byte is measurable ONLY once its check-order predecessors are pinned; the engine
#    must therefore attack pin[0],pin[1],...,pin[5] in PLAIN INDEX ORDER. If it instead attacked in
#    order[k] sequence it would attack pin[3] (4th-checked) first with pin[0..2] still random, read
#    no signal, and wrongly declare nearly every byte unmeasurable — recovery would need a 100^5
#    sweep and blow the verify budget. So this asserts both "all six measured by timing" and
#    "full PIN recovered with a tiny verify budget".
ORD1 = cemproto.SHUFFLE_ORDERS[1]
assert ORD1 != tuple(range(cemproto.PIN_LEN)), "guard must use a non-identity order"
SECRET1 = [0x12, 0x34, 0x56, 0x78, 0x90, 0x21]
sim = CemSimulator(SECRET1, ORD1, base_us=652.0, per_pos_gain=(3, 3, 3, 3, 3, 3),
                   noise_us=1.0, quantum_us=0.0, outlier_p=0.0)
eng = CrackEngine(SimTransport(sim), shuffle_order=ORD1,
                  config=CrackConfig(max_pulls_per_byte=20_000, confirm_factor=4,
                                     n_check_unmeasurable=2_000_000, verify_budget=200))
results = []
t = time.monotonic(); got = eng._attempt(results); dt = time.monotonic() - t
results.sort(key=lambda r: r.position)
all_measured = all(r.separated and r.committed == SECRET1[r.position] for r in results)
check("non-identity order (3,1,5,0,2,4): every byte measured in CEM check order (plain index)",
      len(results) == cemproto.PIN_LEN and all_measured,
      "states=" + " ".join(f"p{r.position}:{hx(r.committed)}/{'sep' if r.separated else 'UNM'}"
                            for r in results) + f"  {dt:.1f}s")
check("non-identity order: full PIN recovered with a tiny (200) verify budget",
      got == SECRET1, f"{cemproto.fmt_pin(got) if got else None} probes={eng.probes} {dt:.1f}s")

# 8. SE-1 regression: a DEEP gift (not pin[0]) with gift_confirm ON must be SEEDED, not falsely
#    rejected. The side channel only shows a byte's signal once its check-order predecessors are
#    correct; the old code confirmed the lowest-index gift against RANDOM predecessors, saw no
#    signal, and aborted the whole order. Now we confirm only pin[0] (and only if it is gifted).
sim = CemSimulator(SECRET, ORD, base_us=652.0, per_pos_gain=(3, 3, 3, 3, 3, 3),
                   noise_us=1.0, quantum_us=0.0, outlier_p=0.0)
eng = CrackEngine(SimTransport(sim), shuffle_order=ORD,
                  config=CrackConfig(gift_bytes={3: SECRET[3]}, gift_confirm=True,
                                     max_pulls_per_byte=20_000, confirm_factor=4,
                                     n_check_unmeasurable=2_000_000, verify_budget=200))
t = time.monotonic(); got = eng.crack(); dt = time.monotonic() - t
check("SE-1: deep-only gift (pin[3]) with confirm ON is seeded, not falsely rejected",
      got == SECRET, f"{cemproto.fmt_pin(got) if got else None} {dt:.1f}s")

# 9. RECOVER MODE regression: crack(resume_index=N) must START the Teensy sweep at N (not 0), so an
#    interrupted run resumes where it died. Resuming BELOW the true hit still recovers; resuming ABOVE
#    it MISSES — proving the cursor is honored (and why a runtime-based guess must UNDER-shoot). Also
#    pins resume_cursor()'s runtime->index math (rewound) and its exact/clamp behaviour.
_rc, _sp = CrackEngine.resume_cursor(runtime_s=27589.0, swept_bytes=4)   # the real run: 7.66h, 2 gifts
check("recover: runtime->cursor under-shoots the true hit (never skips the PIN)",
      _sp == 100_000_000 and 0 < _rc < 42_209_688, f"cursor={_rc:,} space={_sp:,}")
check("recover: exact index used as-is; oversized runtime clamps to space-1",
      CrackEngine.resume_cursor(exact_index=42_200_000, swept_bytes=4)[0] == 42_200_000
      and CrackEngine.resume_cursor(runtime_s=10**9, swept_bytes=4)[0] == 99_999_999)

class RecordingBatch(FakeBatchTransport):
    def __init__(self, sim, order):
        super().__init__(sim, order); self.start_seen = None
    def batch_sweep(self, base_frame, varpos, start=0, order="std", progress_cb=None, abort=None):
        self.start_seen = start
        return super().batch_sweep(base_frame, varpos, start=start, order=order,
                                   progress_cb=progress_cb, abort=abort)

def _recover_eng(tx):
    return CrackEngine(tx, shuffle_order=ORD,
                       config=CrackConfig(gift_bytes=gifts4, gift_confirm=False,
                                          assume_unmeasurable=True, lockout_probe_count=0))
_bdec = lambda b: (b >> 4) * 10 + (b & 0xF)          # BCD byte -> the decimal digit the sweep iterates
_swept = sorted(p for p in range(cemproto.PIN_LEN) if p not in gifts4)
_hit = 0
for _p in _swept:                                    # the true linear sweep index of SECRET (2-byte space)
    _hit = _hit * 100 + _bdec(SECRET[_p])

_below = RecordingBatch(CemSimulator.real_p2_generic(SECRET, ORD), ORD)
_got_below = _recover_eng(_below).crack(resume_index=max(0, _hit - 100))
check("recover: resume just below the hit recovers, and the sweep started at the cursor",
      _got_below == SECRET and _below.start_seen == max(0, _hit - 100),
      f"hit={_hit} start_seen={_below.start_seen} got={cemproto.fmt_pin(_got_below) if _got_below else None}")

_above = RecordingBatch(CemSimulator.real_p2_generic(SECRET, ORD), ORD)
_got_above = _recover_eng(_above).crack(resume_index=_hit + 1)
check("recover: resume PAST the hit misses it (cursor truly skips earlier combos)",
      _got_above is None and _above.start_seen == _hit + 1,
      f"start_seen={_above.start_seen} got={_got_above}")

print()
if failures:
    print(f"FAILED: {failures}")
    raise SystemExit(1)
print("All cemcrack engine checks passed.")
