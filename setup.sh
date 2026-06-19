#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Jason Gainor. Derived from volvo-cem-cracker (GPL-3.0),
# Copyright (C) 2020, 2021 Vitaly Mayatskikh, Christian Molson, Mark Dapoz.
# ==============================================================================
# p2-cem-crack — one-command installer.
#
# From a clean machine, this does EVERYTHING needed to run the CEM PIN cracker:
#   1. Python 3.9+             installs it if missing (your OS package manager)
#   2. a project virtualenv    .venv — keeps deps off your system Python
#   3. pyserial                talk to the Teensy over USB
#   4. PlatformIO              build + flash the Teensy firmware
#   5. Teensy USB driver       Linux udev rules / macOS none / Windows guidance
#   6. firmware build          compiles firmware/cem_probe (first run downloads the
#                              Teensy toolchain + uploader), optional flash
#   7. launches the web UI
#
# Works in bash on macOS, Linux, and Windows (Git Bash / MSYS2).
#
#   bash setup.sh                 interactive (asks before any system change)
#   bash setup.sh --yes           assume "yes" to prompts (never auto-flashes, though)
#   bash setup.sh --skip-firmware deps + UI only (no PlatformIO / no firmware build)
#   bash setup.sh --no-launch     set everything up but don't start the UI
# ==============================================================================
set -uo pipefail
cd "$(dirname "$0")"
ROOT="$(pwd)"

# ---------- pretty output ----------
if [[ -t 1 ]]; then B=$'\033[1m'; G=$'\033[32m'; R=$'\033[31m'; Y=$'\033[33m'; D=$'\033[2m'; Z=$'\033[0m'
else B=; G=; R=; Y=; D=; Z=; fi
bold(){ printf '%s\n' "${B}$*${Z}"; }
ok(){   printf '  %s\xe2\x9c\x93%s %s\n' "$G" "$Z" "$*"; }
miss(){ printf '  %s\xe2\x9c\x97%s %s\n' "$R" "$Z" "$*"; }
warn(){ printf '  %s!%s %s\n' "$Y" "$Z" "$*"; }
info(){ printf '    %s%s%s\n' "$D" "$*" "$Z"; }
die(){  printf '\n%sSetup stopped:%s %s\n' "$R" "$Z" "$*" >&2; exit 1; }
run(){  info "\$ $*"; "$@"; }

# ---------- args ----------
ASSUME_YES=0; SKIP_FW=0; DO_LAUNCH=1
for a in "$@"; do case "$a" in
  -y|--yes) ASSUME_YES=1;;
  --skip-firmware) SKIP_FW=1;;
  --no-launch) DO_LAUNCH=0;;
  -h|--help) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
  *) warn "ignoring unknown option: $a";;
esac; done
# ask: returns 0 (yes) on y/Y; --yes auto-accepts. (Flashing has its OWN strict prompt below.)
ask(){ [[ $ASSUME_YES -eq 1 ]] && { info "auto-yes: $1"; return 0; }
  local a; read -r -p "    > $1 [y/N] " a 2>/dev/null || return 1; [[ "${a:-}" =~ ^[Yy] ]]; }

# ---------- detect OS ----------
case "$(uname -s 2>/dev/null)" in
  Darwin) OS=mac;; Linux) OS=linux;; MINGW*|MSYS*|CYGWIN*) OS=windows;; *) OS=unknown;;
esac
bold "p2-cem-crack installer  -  OS: $OS"
[[ "$OS" == unknown ]] && warn "unrecognised OS; trying the POSIX path"
echo

# ---------- 1. Python 3.9+ ----------
find_python(){ PYBIN=""; local c
  for c in python3 python py; do command -v "$c" >/dev/null 2>&1 || continue
    if "$c" -c 'import sys;exit(0 if sys.version_info[:2]>=(3,9) else 1)' 2>/dev/null; then PYBIN="$c"; return 0; fi
  done; return 1; }
bold "[1/7] Python 3.9+"
if find_python; then ok "Python $("$PYBIN" -V 2>&1 | awk '{print $2}')  ($PYBIN)"
else
  miss "Python 3.9+ not found"
  case "$OS" in
    mac)
      if command -v brew >/dev/null 2>&1; then ask "install Python with Homebrew?" && run brew install python
      elif ask "install Homebrew (official script) then Python?"; then
        run /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        command -v brew >/dev/null 2>&1 && run brew install python || info "Then re-run: bash setup.sh"
      else info "Or install from https://www.python.org/downloads/"; fi;;
    linux)
      if   command -v apt-get >/dev/null 2>&1; then ask "install python3 with apt?"   && { run sudo apt-get update; run sudo apt-get install -y python3 python3-venv python3-pip; }
      elif command -v dnf     >/dev/null 2>&1; then ask "install python3 with dnf?"   && run sudo dnf install -y python3 python3-pip
      elif command -v pacman  >/dev/null 2>&1; then ask "install python with pacman?" && run sudo pacman -S --noconfirm python python-pip
      elif command -v zypper  >/dev/null 2>&1; then ask "install python3 with zypper?"&& run sudo zypper install -y python3 python3-pip
      else warn "no known package manager; install Python 3.9+ manually"; fi;;
    windows)
      if command -v winget >/dev/null 2>&1; then ask "install Python with winget?" && run winget install -e --id Python.Python.3.12
      else info "Install from https://www.python.org/downloads/ (CHECK 'Add python.exe to PATH'), then re-run."; fi;;
    *) info "Install Python 3.9+ from https://www.python.org/downloads/";;
  esac
  find_python || die "Python 3.9+ still not found. Install it, open a NEW shell, then re-run: bash setup.sh"
  ok "Python $("$PYBIN" -V 2>&1 | awk '{print $2}')  ($PYBIN)"
fi
if ! "$PYBIN" -c 'import venv' 2>/dev/null; then
  warn "Python 'venv' module missing"
  [[ "$OS" == linux ]] && command -v apt-get >/dev/null 2>&1 && ask "install python3-venv with apt?" && run sudo apt-get install -y python3-venv
  "$PYBIN" -c 'import venv' 2>/dev/null || die "the venv module is unavailable — install python3-venv"
fi
echo

# ---------- 2. virtualenv ----------
bold "[2/7] Project virtualenv (.venv)"
if [[ ! -e .venv ]]; then run "$PYBIN" -m venv .venv || die "could not create .venv"; ok "created .venv"
else ok ".venv already present"; fi
if   [[ -x "$ROOT/.venv/bin/python" ]];         then VPY="$ROOT/.venv/bin/python"
elif [[ -x "$ROOT/.venv/Scripts/python.exe" ]]; then VPY="$ROOT/.venv/Scripts/python.exe"
else die "venv python not found under .venv/bin or .venv/Scripts"; fi
"$VPY" -m pip install --upgrade pip >/dev/null 2>&1 && ok "pip up to date" || warn "could not upgrade pip (continuing)"
echo

# ---------- 3. pyserial ----------
bold "[3/7] pyserial (USB serial to the Teensy)"
if "$VPY" -c 'import serial' 2>/dev/null; then ok "pyserial $("$VPY" -c 'import serial;print(serial.__version__)' 2>/dev/null)"
else run "$VPY" -m pip install pyserial && ok "pyserial installed" || die "pyserial install failed"; fi
echo

# ---------- 4. PlatformIO ----------
if [[ $SKIP_FW -eq 0 ]]; then
  bold "[4/7] PlatformIO (build + flash the firmware)"
  if "$VPY" -m platformio --version >/dev/null 2>&1; then ok "PlatformIO $("$VPY" -m platformio --version 2>&1 | awk '{print $NF}')"
  else run "$VPY" -m pip install platformio && ok "PlatformIO installed" \
       || { warn "PlatformIO install failed — skipping firmware steps"; SKIP_FW=1; }; fi
  echo
else bold "[4/7] PlatformIO  -  skipped (--skip-firmware)"; echo; fi

# ---------- 5. Teensy USB driver ----------
bold "[5/7] Teensy USB driver"
case "$OS" in
  mac) ok "macOS needs no driver (the Teensy enumerates as /dev/cu.usbmodem*)";;
  linux)
    RULES=/etc/udev/rules.d/00-teensy.rules
    if [[ -f "$RULES" ]]; then ok "udev rules present ($RULES)"
    else
      miss "Teensy udev rules missing (without them you'd flash as root and ModemManager may grab the port)"
      if ask "install the official Teensy udev rules (needs sudo)?"; then
        sudo tee "$RULES" >/dev/null <<'RULES'
# Teensy udev rules - https://www.pjrc.com/teensy/00-teensy.rules
ATTRS{idVendor}=="16c0", ATTRS{idProduct}=="04[789B]?", ENV{ID_MM_DEVICE_IGNORE}="1"
ATTRS{idVendor}=="16c0", ATTRS{idProduct}=="04[789A]?", ENV{MTP_NO_PROBE}="1"
SUBSYSTEMS=="usb", ATTRS{idVendor}=="16c0", ATTRS{idProduct}=="04[789ABCD]?", MODE:="0666"
KERNEL=="ttyACM*", ATTRS{idVendor}=="16c0", ATTRS{idProduct}=="04[789B]?", MODE:="0666"
RULES
        sudo udevadm control --reload-rules && sudo udevadm trigger && ok "udev rules installed (replug the Teensy)" \
          || warn "udev reload failed — replug the Teensy and/or reboot"
      fi
    fi;;
  windows)
    info "Windows 10/11 auto-installs the USB-serial driver on first plug-in."
    info "The bootloader (HalfKay) driver + uploader ship with PlatformIO's Teensy tool (fetched in step 6)."
    info "If a flash can't find the Teensy, run the Teensy Loader once: https://www.pjrc.com/teensy/loader.html";;
  *) info "Teensy USB VID is 0x16C0 — install your platform's Teensy/serial driver if a port never appears.";;
esac
echo

# ---------- 6. firmware build (+ optional flash) ----------
if [[ $SKIP_FW -eq 0 ]]; then
  bold "[6/7] Build the Teensy firmware"
  info "first build downloads the Teensy toolchain + uploader (a few hundred MB); later builds are quick."
  if ( cd firmware && "$VPY" -m platformio run ); then ok "firmware compiled"
  else warn "firmware build failed (see above). Retry later:  (cd firmware && $VPY -m platformio run)"; fi
  # Flash is ALWAYS an explicit prompt (never via --yes) — the Teensy must be off the car when flashing.
  printf '    > flash the Teensy now? It must be on USB and NOT connected to the car [y/N] '
  if read -r _f 2>/dev/null && [[ "${_f:-}" =~ ^[Yy] ]]; then
    ( cd firmware && "$VPY" -m platformio run -t upload ) && ok "firmware flashed" \
      || warn "flash failed — check the cable (must be a DATA cable), the port, and that the Teensy is detached from the car"
  else info "skipped flashing — later:  (cd firmware && $VPY -m platformio run -t upload)"; fi
  echo
else bold "[6/7] Firmware build  -  skipped (--skip-firmware)"; echo; fi

# ---------- 7. launch ----------
bold "[7/7] Ready"
ok  "Run the cracker UI:"
echo "      $VPY -m cemcrack.webui            # then open http://127.0.0.1:8731"
info "Self-test (no hardware):  $VPY tests/test_engine.py"
echo
if [[ $DO_LAUNCH -eq 1 && -t 0 ]]; then
  if ask "launch the cracker UI now?"; then echo; exec "$VPY" -m cemcrack.webui; fi
fi
bold "Done."
