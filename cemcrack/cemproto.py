# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Jason Gainor
# Derived from volvo-cem-cracker — Copyright (C) 2020, 2021 Vitaly Mayatskikh,
# Christian Molson, Mark Dapoz — https://github.com/vtl/volvo-cem-cracker (GPL-3.0).
"""Volvo CEM unlock protocol constants & helpers.

Grounded in the public vtl/volvo-cem-cracker research (the method is open). The CEM PIN is
6 BCD bytes (each 0x00-0x99, so 100 values/byte, NOT 256). An unlock probe is an 8-byte
CAN frame on arbitration id 0xffffe:

    [ CEM_HS_ECU_ID(0x50), 0xBE, m0, m1, m2, m3, m4, m5 ]

where the 6 PIN bytes are placed into m[] via a model-dependent SHUFFLE order (one of four
known permutations). The CEM replies on the bus; reply byte[2]==0x00 means UNLOCKED. The
side channel: the CEM takes measurably longer to reject a PIN whose leading (shuffle-order)
bytes are correct — so per-byte latency reveals the PIN. We exploit that far more
efficiently than a uniform sweep (see engine.py)."""

PIN_LEN = 6
BCD_MAX = 100               # BCD byte values 0..99
CEM_HS_ECU_ID = 0x50        # high-speed CAN bus
CEM_LS_ECU_ID = 0x40        # low-speed/medium-speed CAN bus (2004 cars: 125 kbps)
UNLOCK_ARB_ID = 0xffffe
UNLOCK_FUNC = 0xBE

# Four known PIN->message-byte permutations; the right one is CEM-model dependent and is
# auto-detected (the wrong order yields no usable timing signal). pin[i] -> message[order[i]].
SHUFFLE_ORDERS = (
    (0, 1, 2, 3, 4, 5),
    (3, 1, 5, 0, 2, 4),
    (5, 2, 1, 4, 0, 3),
    (2, 4, 5, 0, 3, 1),
)


def bin_to_bcd(value: int) -> int:
    """0..99 -> packed BCD byte (e.g. 42 -> 0x42). The PIN space is BCD."""
    if not 0 <= value <= 99:
        raise ValueError(f"BCD value out of range: {value}")
    return ((value // 10) << 4) | (value % 10)


def bcd_to_bin(b: int) -> int:
    return (b >> 4) * 10 + (b & 0x0F)


def bcd_values() -> list[int]:
    """The 100 valid BCD byte values, in order (0x00,0x01,...,0x09,0x10,...,0x99)."""
    return [bin_to_bcd(v) for v in range(BCD_MAX)]


def is_bcd(b: int) -> bool:
    return (b >> 4) <= 9 and (b & 0x0F) <= 9


def build_unlock_frame(pin: list[int], shuffle_order=SHUFFLE_ORDERS[0]) -> list[int]:
    """The 8-byte CAN payload for an unlock attempt with the given 6-byte PIN."""
    if len(pin) != PIN_LEN:
        raise ValueError("pin must be 6 bytes")
    msg = [0x00] * PIN_LEN
    for i in range(PIN_LEN):
        msg[shuffle_order[i]] = pin[i]
    return [CEM_HS_ECU_ID, UNLOCK_FUNC, *msg]


def fmt_pin(pin) -> str:
    """Human PIN string, '--' for unknown (None) positions."""
    return " ".join("--" if b is None else f"{b:02X}" for b in pin)
