# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Jason Gainor
# Derived from volvo-cem-cracker — Copyright (C) 2020, 2021 Vitaly Mayatskikh,
# Christian Molson, Mark Dapoz — https://github.com/vtl/volvo-cem-cracker (GPL-3.0).
"""CEM timing simulator — a software stand-in for a real CEM on the bench.

Lets you develop, test and TUNE the smart engine without a car. It models the documented side
channel: the CEM's reject latency rises with the number of correct LEADING bytes (in shuffle
order), buried in noise.

Two profiles:
  * the default constructor = a deliberately-pessimistic SYNTHETIC channel (strong per-byte
    gain, gaussian noise) used by the engine smoke test; and
  * CemSimulator.real_p2_generic(...) = a representative Volvo P2 CEM channel profile — the hard
    regime the engine must actually win in:
      - latency is QUANTIZED to even microseconds — mass sits in buckets {84,86,88,90} us;
      - it is BIMODAL (most mass split 86<->88); a correct byte nudges mass toward 88/90;
      - the per-byte signal DECAYS with position: pin[0] ~0.20us, pin[1] ~0.12us, pin[2] ~0.01us
        (at/under the noise floor) and deeper bytes ~0 — so timing typically recovers only the
        first ~2 bytes and the rest must be brute-forced by real unlock attempts;
      - rare ~43us low outliers (CAN retransmit/glitch) and occasional odd-microsecond landings.

This is a MODEL, not a real CEM; on-car the exact numbers differ, but the engine reads the
signal statistically so it transfers (thresholds may need a little tuning).
"""
import random

from . import cemproto

# Per-position discriminating signal (us of mean-latency shift a CORRECT byte adds at that
# shuffle position) for a representative P2 CEM. The steep decay after position 1 is the whole
# story: later bytes sit below the noise floor and cannot be read by timing.
P2_GAINS = (0.20, 0.12, 0.012, 0.004, 0.002, 0.001)


class CemSimulator:
    """Simulates unlock-probe latency + the unlock() check for a secret PIN.

    Parameters (defaults reproduce the original synthetic channel; see real_p2_generic for the
    representative P2 profile):
      base_us       baseline reject latency (wrong leading byte)
      gain_us       flat per-correct-byte latency gain (used when per_pos_gain is None)
      per_pos_gain  explicit per-position gain tuple (overrides gain_us) — models signal decay
      noise_us      gaussian measurement noise sigma (continuous, before any quantization)
      quantum_us    if >0, round latency to the nearest multiple (real CEM ~2us grid); 0 = off
      odd_p         P(landing on an odd-microsecond bucket instead of the even grid)
      outlier_p     P(a spurious outlier sample)
      outlier_us    outlier magnitude
      outlier_mode  'add' (additive positive spike, old behavior) or 'low' (replace with a low
                    ~outlier_us spike, as the real CAN retransmit glitch behaves)
    """

    def __init__(self, secret_pin: list[int], shuffle_order=None, *,
                 base_us: float = 100.0, gain_us: float = 4.0, per_pos_gain=None,
                 noise_us: float = 6.0, quantum_us: float = 0.0, odd_p: float = 0.0,
                 outlier_p: float = 0.03, outlier_us: float = 40.0, outlier_mode: str = "add",
                 seed: int | None = 1234):
        assert len(secret_pin) == cemproto.PIN_LEN
        self.secret = list(secret_pin)
        self.order = shuffle_order or cemproto.SHUFFLE_ORDERS[0]
        self.base_us = base_us
        self.per_pos_gain = tuple(per_pos_gain) if per_pos_gain is not None \
            else tuple([gain_us] * cemproto.PIN_LEN)
        self.noise_us = noise_us
        self.quantum_us = quantum_us
        self.odd_p = odd_p
        self.outlier_p = outlier_p
        self.outlier_us = outlier_us
        self.outlier_mode = outlier_mode
        self._rng = random.Random(seed)
        self.probe_count = 0

    # -- representative P2 CEM profile --------------------------------------
    @classmethod
    def real_p2_generic(cls, secret_pin: list[int], shuffle_order=None, *,
                        noise_us: float = 1.6, seed: int | None = 1234):
        """A representative Volvo P2 CEM channel: quantized, bimodal, with a steeply-decaying
        per-position signal so only ~2 bytes are readable by timing. This is the regime the
        engine must actually win in."""
        return cls(secret_pin, shuffle_order,
                   base_us=87.2, per_pos_gain=P2_GAINS, noise_us=noise_us,
                   quantum_us=2.0, odd_p=0.003,
                   outlier_p=0.0008, outlier_us=43.0, outlier_mode="low", seed=seed)

    # -- profile calibrated to the actual car (2026-06-17 bench) -------------
    @classmethod
    def real_p2_observed(cls, secret_pin, shuffle_order=None, *, noise_us: float = 1.5,
                         per_pos_gain=P2_GAINS, seed: int | None = 1234):
        """Calibrated to THIS S60's CEM at the bench: reject latency ~652us baseline with ~1.5us
        CONTINUOUS noise (the DWT cycle-counter samples are continuous — NOT the 2us grid we'd
        assumed). The per-byte SIGNAL magnitude is still an estimate (P2_GAINS); the real values
        await an on-car signal survey on the CORRECT shuffle order. Pass per_pos_gain to sweep
        what-if signal strengths and see how many bytes the engine can resolve (i.e. predict the
        sweep cost) before ever touching the car."""
        return cls(secret_pin, shuffle_order,
                   base_us=652.0, per_pos_gain=per_pos_gain, noise_us=noise_us,
                   quantum_us=0.0, odd_p=0.0,
                   outlier_p=0.0008, outlier_us=43.0, outlier_mode="low", seed=seed)

    def _correct_leading(self, pin: list[int]) -> int:
        """How many PIN bytes match the secret from the front, in PLAIN INDEX ORDER (0,1,2,...).
        That index order IS the CEM's check order: pin[i] is placed at frame byte msg[order[i]]
        (build_unlock_frame) and the CEM validates the frame bytes in shuffle order, so pin[i] is
        by construction the i-th byte checked. The sim therefore works purely in pin-index space —
        the shuffle is a transport/frame concern (modeled by build_unlock_frame on the real path),
        not something the sim needs to re-apply here. Latency grows with this leading-correct count."""
        n = 0
        for pos in range(cemproto.PIN_LEN):
            if pin[pos] == self.secret[pos]:
                n += 1
            else:
                break
        return n

    def _signal_us(self, pin: list[int]) -> float:
        """Noise-free mean latency = base + the gains of each correct leading byte."""
        k = self._correct_leading(pin)
        return self.base_us + sum(self.per_pos_gain[:k])

    def probe_latency_us(self, pin: list[int]) -> float:
        """One noisy latency sample for an unlock attempt (microseconds)."""
        self.probe_count += 1
        if self.outlier_p and self._rng.random() < self.outlier_p:
            if self.outlier_mode == "low":
                return max(0.0, self.outlier_us + self._rng.gauss(0, 1.0))
            # additive positive spike (original synthetic behavior)
            return max(0.0, self._signal_us(pin) + self._rng.gauss(0, self.noise_us)
                       + abs(self._rng.gauss(0, self.outlier_us)))
        raw = self._signal_us(pin) + self._rng.gauss(0, self.noise_us)
        if self.quantum_us > 0:
            if self.odd_p and self._rng.random() < self.odd_p:
                raw = round(raw)                                  # occasional odd-us landing
            else:
                raw = round(raw / self.quantum_us) * self.quantum_us   # even-us grid
        return max(0.0, raw)

    def unlock(self, pin: list[int]) -> bool:
        """The deterministic check: True iff the full PIN is correct (reply[2]==0x00)."""
        self.probe_count += 1
        return list(pin) == self.secret
