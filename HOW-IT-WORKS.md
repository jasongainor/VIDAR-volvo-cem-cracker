# How the cracking works

A technical companion to the README. This explains the timing side-channel, why the design beats a
naive sweep, the host/firmware split, and the wire protocol.

## The side-channel

Authenticated access to a Volvo P2 CEM requires a **6-byte PIN**, each byte a two-digit BCD value
(`00`–`99`), so the space is `100⁶`. You can't brute that blind. But the CEM leaks: when it validates an
unlock attempt it checks the PIN bytes **one at a time, in a fixed order**, and a **correct byte makes
the reply arrive a hair later** (a few hundred CPU cycles). That turns a `100⁶` search into, at worst,
six independent `100`-way searches.

Two structural facts shape everything:

- **Frame placement vs. check order.** Each PIN byte `pin[i]` is placed into the CAN unlock frame at
  message byte `msg[order[i]]`, where `order` is one of four published per-CEM "shuffle" permutations.
  The frame on the wire is `[0x50, 0xBE, msg0..msg5]`. The CEM validates the *message bytes in shuffle
  order*, so `pin[i]` is by construction the **i-th byte checked**. The attack therefore proceeds in
  plain index order `pin[0], pin[1], …` — which is the CEM's check order.
- **The leading-prefix property.** A byte only shows its timing signal once **all of its check-order
  predecessors are already correct**. So you measure `pin[0]` first, fix it, then `pin[1]`, and so on.
  (This is also why a known byte deep in the PIN can't be re-confirmed in isolation — its predecessors
  aren't pinned yet.)

## Why the timing must live on a microcontroller

The signal is sub-microsecond. Host-side USB latency is ~1 ms of jitter — three orders of magnitude
bigger — so a PC/USB/J2534 interface physically cannot see it. The **Teensy 4.0** fires the unlock
frame and timestamps the CEM's reply with the **DWT cycle counter** (≈ CPU-clock resolution). The host
keeps *all* the intelligence (which candidates to probe, the statistics, when to stop); the firmware is
just the dumb-fast-accurate hands.

## The smart search (engine.py)

A naive attack takes the mean latency per candidate, greedily commits the fastest, and brute-forces the
rest. It fails on real CEMs because some bytes don't separate, and committing a coin-flip there excludes
the true PIN from everything downstream. This engine fixes that with four ideas:

1. **Robust bucket statistic, not the mean.** Real CEM latency is quantized (~2 µs buckets) and bimodal;
   a correct byte only shifts probability mass upward. Each candidate is scored by `p_hi` — the
   tie-corrected fraction of its samples **above the field's pooled median**, a Bernoulli rate with an
   exact standard error. This ignores outlier *magnitude* (CAN-retransmit glitches just count as "low"),
   needs no hand-tuned threshold, and is ~2× more sample-efficient than a mean on this distribution.
2. **Never cull the truth.** Candidates are eliminated by **confidence-interval successive elimination**
   with a hard `min_samples` floor and a Bonferroni `z` (≈3.72, FWER 0.01 over the 100 arms). An arm
   whose CI still reaches the current leader is never dropped — noise alone can't lose the correct byte.
3. **Measurability gate (the key fix).** If, within a probe budget, the leader's lower CI never clears
   the runner-up's upper CI, the byte is declared **unmeasurable** rather than guessed. An unmeasurable
   byte carries its **full 100-value axis** into the finish, so the true value is structurally guaranteed
   to be in the search — the greedy-commit cascade failure becomes impossible.
4. **Gifts + re-confirm.** Bytes you already know are seeded as **gifts** (each removes a 100× factor),
   and the first/strongest gift is re-confirmed against the live bus before any brute time is spent —
   catching a wrong shuffle or voltage drift in about a minute.

## The deterministic finish (the "sweep")

Timing fixes the measurable bytes; the rest are resolved by **real unlock attempts** over the cartesian
product of (gifts × measured top-K × full axes for unmeasurable bytes), streamed most-likely-first. The
unlock attempt is the sole arbiter — a hit is a genuine CEM `50 B9 00` reply, not a timing inference.

On real hardware the exhaustive part is delegated to the Teensy (`BSWEEP`): the bottleneck is the CAN
bus (~0.65 ms/attempt), not USB, so running the loop on the MCU is the big speed lever. Before a long
sweep the engine prints a **sweep estimate** (combinations × time) so a multi-hour run never starts
unannounced, and runs a **lockout pre-flight** (a burst of deliberately-wrong unlocks) to confirm the
CEM isn't throttling failed attempts. A resume cursor lets an interrupted sweep restart near where it
died rather than from zero.

Typical outcome: timing cleanly recovers a couple of bytes; the remaining bytes are brute-swept. Each
extra byte you can supply as a gift cuts the sweep time 100×.

## Programming mode & safety

The CEM only answers unlock probes while the whole bus is held in **programming mode** (broadcast
`FF 86`). The firmware enters and maintains it automatically during a crack and **exits it on finish,
stop, or host-silence** by broadcasting the reset-all-ECUs frame **`FF C8`** — returning the car to
normal with no battery pull. A firmware watchdog also auto-exits prog mode if the host goes silent
(crash / closed terminal), so the car can never be stranded. "Exit prog mode" in the UI does this
manually at any time.

## Wire protocol (host ⇄ Teensy, ASCII lines)

| Command | Meaning | Reply |
|---|---|---|
| `S <500000\|250000\|125000>` | set CAN bitrate | `S ok` |
| `G <us>` | inter-attempt settle gap | `G ok` |
| `P <n> <16hex>` | fire `n` timed probes of one 8-byte frame | `L <us> <us> …` (`-1` = timeout) |
| `U <16hex>` | one unlock attempt | `U 1` (unlocked) / `U 0` |
| `LP <n>` | lockout pre-flight: `n` wrong unlocks | `LP <responded> <n>` |
| `BSWEEP <base16hex> <varpos> <order> <start>` | MCU-side brute sweep | `P <idx>` progress, then `H <16hex> <idx>` on unlock or `D <tried>` |
| `PROGON` / `PROGOFF` | enter / exit (`FF C8`) programming mode | `PROGON ok` / `PROGOFF done` |
| `VERSION` | firmware id | `VERSION cem_probe-N` |

Diagnostics for bench bring-up: `SNIFF`, `USNIFF`, `URAW`, `TXSTAT`, `PROGPROBE`.

## Honest limits

The CAN framing and the `50 B9 00 == unlocked` reply semantics come from the public `vtl` method and
**must be validated on your bench** before a result is trusted — that's the one thing only real hardware
confirms. The single most rigorous confirmation is the UI's **Check PIN** (a positive unlock plus a
wrong-PIN negative control). Stable 12 V is essential throughout; voltage sag corrupts the timing.
