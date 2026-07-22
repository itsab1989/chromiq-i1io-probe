#!/usr/bin/env python3
"""
chromiq_io_probe.py — X-Rite i1iO diagnostic collector for ChromIQ issue #129.

WHAT THIS DOES
    Collects information about an i1iO scanning table and the machine it is
    connected to, and writes it into a single file you can send back.

WHAT THIS DOES NOT DO
    It never sends a single byte to the table. It does not move the arm, does
    not open the device, does not touch i1Profiler's settings, and does not
    need the table to be calibrated. It only reads what the operating system
    already knows about the connected hardware.

    You can run it with the arm parked and the table idle. It is safe.

USAGE
    Stage 1 — the important one, takes about 20 seconds:

        python3 chromiq_io_probe.py

    Stage 2 — optional, only if you also want to help with a traffic capture:

        python3 chromiq_io_probe.py --annotate

    Both produce a file named chromiq-io-probe-<timestamp>.txt next to the
    script. Open it, read it (it is plain text, nothing hidden), and attach it
    to the GitHub issue.

PRIVACY
    Serial numbers are replaced with a short stable hash by default, and your
    username and home directory are stripped out. Nothing in the output
    identifies you. If you would rather send the raw values, add --no-redact.
    Serial numbers are not needed for this work.

Requires: Python 3.8+ and nothing else. No pip install.
"""

from __future__ import annotations

import argparse
import datetime
import getpass
import glob
import hashlib
import json
import os
import platform
import re
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
import time

# X-Rite USB vendor ID, and the product IDs we care about.
XRITE_VID = 0x0971
KNOWN_PIDS = {
    0x2000: "i1Pro",
    0x2001: "i1Pro 2 / i1Pro 3 family",
    0x2004: "i1iO table",
    0x2006: "i1iSis",
    0x2007: "ColorMunki",
}

REDACT = True
_SECTIONS: list[tuple[str, str]] = []


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def run(cmd: list[str], timeout: int = 40) -> str:
    """Run a command, return its output, never raise."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except FileNotFoundError:
        return f"[not available on this system: {cmd[0]}]"
    except subprocess.TimeoutExpired:
        return f"[timed out after {timeout}s: {' '.join(cmd)}]"
    except Exception as exc:                              # noqa: BLE001
        return f"[failed: {exc}]"
    out = proc.stdout or ""
    if proc.returncode != 0 and proc.stderr:
        out += f"\n[stderr] {proc.stderr}"
    return out.strip() or "[no output]"


# Each rule is (pattern, description). Group 1 is kept verbatim, group 2 is the
# secret and gets replaced by a stable short hash. One rule per real-world
# format, because a single clever regex missed three of them in testing:
# macOS system_profiler emits "serial_num", lsusb emits "iSerial <index> <val>",
# and Windows hides the serial in the tail of the device instance path.
_SERIAL_RULES = [
    # lsusb -v:   iSerial                 3 IO12345678
    (re.compile(r"(iSerial\s+\d+\s+)(\S{4,})"), "lsusb"),
    # Windows:    USB\VID_0971&PID_2004\IO12345678
    (re.compile(r"(USB\\VID_[0-9A-Fa-f]{4}&PID_[0-9A-Fa-f]{4}\\)([^\s\"',\\]{4,})"),
     "windows-instance-id"),
    # Anything whose key mentions "serial": serial_num, Serial Number,
    # kUSBSerialNumberString, serial:, SerialNumber=. The {3,} tail length keeps
    # IOKit class names like "IOSerialBSDClient"=2 untouched.
    (re.compile(r"([A-Za-z_]*[Ss]erial[A-Za-z_]*(?:\s*[Nn]umber|\s*[Nn]um)?"
                r"\"?\s*[:=]+\s*\"?)([A-Za-z0-9][\w\-]{3,})"), "generic-key"),
    # Bare UUIDs, wherever they turn up.
    (re.compile(r"()\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}"
                r"-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b"), "uuid"),
]


def _hash_secret(match: re.Match) -> str:
    """Replace the secret with a stable short hash, keeping any key prefix.

    Stable so that the same device mentioned in two different sections still
    obviously refers to one device, without revealing the real value.
    """
    prefix = match.group(1) if match.lastindex and match.lastindex >= 1 else ""
    secret = match.group(2) if match.lastindex and match.lastindex >= 2 else match.group(0)
    digest = hashlib.sha256(secret.encode("utf-8", "replace")).hexdigest()[:8]
    return f"{prefix}<redacted:{digest}>"


def scrub(text: str) -> str:
    """Remove things that identify the person rather than the hardware."""
    if not REDACT or not text:
        return text
    try:
        user = getpass.getuser()
    except Exception:                                     # noqa: BLE001
        user = ""
    if user and len(user) >= 3:
        text = re.sub(rf"\b{re.escape(user)}\b", "USER", text)
    home = os.path.expanduser("~")
    if home and home not in ("/", ""):
        text = text.replace(home, "~")
    for pattern, _name in _SERIAL_RULES:
        text = pattern.sub(_hash_secret, text)
    return text


def section(title: str, body: str) -> None:
    _SECTIONS.append((title, scrub(body if body is not None else "")))


def ask(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return ""


# --------------------------------------------------------------------------
# collectors — macOS
# --------------------------------------------------------------------------

def collect_macos() -> None:
    section("macOS — USB device tree (JSON)",
            run(["system_profiler", "-json", "SPUSBDataType"]))
    section("macOS — USB device tree (readable)",
            run(["system_profiler", "SPUSBDataType"]))

    # ioreg carries the descriptor detail system_profiler leaves out:
    # endpoint layout, interface class, bcdDevice, and the parent/child
    # topology that tells us whether the i1Pro hangs off a hub inside the table.
    section("macOS — ioreg USB properties",
            run(["ioreg", "-p", "IOUSB", "-l", "-w", "0"], timeout=60))

    xrite = "/Library/Application Support/X-Rite"
    if os.path.isdir(xrite):
        # The per-device plugin plists carry the USB IDs and device names, and
        # they sit ~8 levels down inside the framework bundle — hence the depth.
        listing = run(["find", xrite, "-maxdepth", "12", "-name", "Info.plist"])
        section("macOS — X-Rite Info.plist files present", listing)
        for path in listing.splitlines():
            path = path.strip()
            if not path or path.startswith("["):
                continue
            if not any(k in path for k in ("i1Pro", "i1iO", "XRiteDevice")):
                continue
            section(f"macOS — plist: {path.replace(xrite, '<X-Rite>')}",
                    run(["plutil", "-p", path]))
    else:
        section("macOS — X-Rite support folder", "[not found — is i1Profiler installed?]")

    app = "/Applications/i1Profiler/i1Profiler.app/Contents/Info.plist"
    section("macOS — i1Profiler version",
            run(["plutil", "-p", app]) if os.path.exists(app) else "[i1Profiler not found]")

    # Worth knowing even if the capture step is skipped: it tells us whether a
    # capture is possible on this Mac at all, and under which names.
    interfaces = macos_usb_capture_interfaces()
    section("macOS — USB capture interfaces available",
            ", ".join(interfaces) if interfaces
            else "[none — USB capture is not possible on this Mac]")


# --------------------------------------------------------------------------
# collectors — Linux
# --------------------------------------------------------------------------

def collect_linux() -> None:
    section("Linux — lsusb (all devices)", run(["lsusb"]))
    # The verbose dump is the single most valuable thing on any platform:
    # full configuration, interface and endpoint descriptors.
    section("Linux — lsusb -v for X-Rite devices",
            run(["lsusb", "-v", "-d", f"{XRITE_VID:04x}:"], timeout=60))
    section("Linux — USB topology", run(["lsusb", "-t"]))

    sysfs = "/sys/bus/usb/devices"
    lines = []
    if os.path.isdir(sysfs):
        for entry in sorted(os.listdir(sysfs)):
            base = os.path.join(sysfs, entry)
            try:
                with open(os.path.join(base, "idVendor")) as fh:
                    vid = fh.read().strip()
            except OSError:
                continue
            if vid.lower() != f"{XRITE_VID:04x}":
                continue
            lines.append(f"--- {entry} ---")
            for attr in ("idProduct", "bcdDevice", "manufacturer", "product",
                         "serial", "speed", "bNumInterfaces",
                         "bDeviceClass", "bmAttributes", "devpath", "version"):
                try:
                    with open(os.path.join(base, attr)) as fh:
                        lines.append(f"{attr}: {fh.read().strip()}")
                except OSError:
                    pass
    section("Linux — sysfs attributes for X-Rite devices",
            "\n".join(lines) or "[no X-Rite devices found in sysfs]")

    section("Linux — kernel messages mentioning USB/FTDI",
            run(["bash", "-c", "dmesg 2>/dev/null | grep -iE 'usb|ftdi' | tail -60"]))


# --------------------------------------------------------------------------
# collectors — Windows
# --------------------------------------------------------------------------

def collect_windows() -> None:
    ps = shutil.which("powershell") or shutil.which("pwsh")
    if not ps:
        section("Windows", "[PowerShell not found — cannot enumerate USB]")
        return

    def psrun(script: str) -> str:
        return run([ps, "-NoProfile", "-NonInteractive", "-Command", script], timeout=60)

    section("Windows — X-Rite USB devices", psrun(
        "Get-PnpDevice | Where-Object { $_.InstanceId -like '*VID_0971*' } | "
        "Format-List FriendlyName,InstanceId,Status,Class,Present"
    ))
    section("Windows — device properties (hardware + driver)", psrun(
        "Get-PnpDevice | Where-Object { $_.InstanceId -like '*VID_0971*' } | "
        "ForEach-Object { '=== ' + $_.InstanceId + ' ==='; "
        "Get-PnpDeviceProperty -InstanceId $_.InstanceId | "
        "Select-Object KeyName,Data | Format-List }"
    ))
    section("Windows — all USB controllers/hubs (topology context)", psrun(
        "Get-PnpDevice -Class USB | Format-List FriendlyName,InstanceId,Status"
    ))
    section("Windows — X-Rite driver files", psrun(
        "Get-ChildItem -Path 'C:\\Program Files*\\X-Rite','C:\\Program Files*\\i1Profiler' "
        "-Recurse -Include *.dll,*.exe -ErrorAction SilentlyContinue | "
        "Select-Object FullName,Length,@{n='Version';e={$_.VersionInfo.FileVersion}} | "
        "Format-List"
    ))
    section("Windows — note",
            "For full endpoint descriptors on Windows the free tool USBTreeView "
            "(uwe-sieber.de) gives much more detail than PowerShell can. If you "
            "are willing, run it, select the i1iO, and paste its report too.")


# --------------------------------------------------------------------------
# collector — i1Profiler iO chart metadata (all platforms)
# --------------------------------------------------------------------------
#
# i1Profiler ships instrument-specific test charts. The iO variants use a much
# denser, robot-oriented layout than the handheld i1Pro, and knowing their
# parameters (patch counts, and any patch-size / gap figures the help files
# state) would help design a matching layout in ChromIQ.
#
# IMPORTANT — we report METADATA ABOUT these files (names, sizes, patch counts,
# and short factual number snippets), never their contents. We do not copy or
# reproduce X-Rite's chart data. That keeps this to plain fact-finding.

# Where i1Profiler keeps its per-colour-space chart folders, per platform.
_I1PROFILER_ROOTS = [
    "/Library/Application Support/X-Rite/i1Profiler",          # macOS
    r"C:\ProgramData\X-Rite\i1Profiler",                       # Windows (usual)
    r"C:\Users\All Users\X-Rite\i1Profiler",                   # Windows (legacy)
    os.path.expanduser("~/Library/Application Support/X-Rite/i1Profiler"),
]

# i1Profiler help files that, in prose, tend to quote the iO chart dimensions.
_I1PROFILER_HELP_ROOTS = [
    "/Applications/i1Profiler/i1Profiler.app/Contents/Resources/Help",
    r"C:\Program Files\X-Rite\i1Profiler\Help",
    r"C:\Program Files (x86)\X-Rite\i1Profiler\Help",
]

# A patch in a CxF/.txf test chart is one <...ObjectType="Target"...> element.
_TARGET_RE = re.compile(r'ObjectType\s*=\s*"Target"')
# Short factual snippets: a number followed by "mm", or a patch/row/column count.
_GEOM_SNIPPET_RE = re.compile(
    r"[^\n<>]{0,40}?\b\d[\d.,]*\s?(?:mm|millimet|patch|patches|row|rows|"
    r"column|columns|gap)s?\b[^\n<>]{0,40}",
    re.IGNORECASE,
)


def _find_i1profiler_root() -> str | None:
    for root in _I1PROFILER_ROOTS:
        if root and os.path.isdir(root):
            return root
    return None


def _count_patches(path: str) -> int:
    """Count target patches in a .txf/CxF chart without holding it all in RAM."""
    count = 0
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for chunk in iter(lambda: fh.read(65536), ""):
                count += len(_TARGET_RE.findall(chunk))
    except OSError:
        return -1
    return count


def collect_i1profiler_charts() -> None:
    """Report iO-specific chart metadata (never the chart contents)."""
    root = _find_i1profiler_root()
    if root is None:
        section("i1Profiler charts",
                "[i1Profiler chart folder not found — this section only has "
                "something to report on a machine with i1Profiler installed.]")
        return

    # 1. Instrument-specific test charts, with patch counts. We look at every
    #    .txf so the iO numbers can be compared against i1Pro / iSis.
    rows: list[str] = []
    io_seen = False
    scan_seen = False
    capped = False
    # .txf is X-Rite's CxF chart (carries the patches); the sidecar .txt is just
    # a short ordering list with no patch objects, so we skip it to avoid noise.
    for dirpath, _dirs, files in os.walk(root):
        for name in sorted(files):
            if not name.lower().endswith(".txf"):
                continue
            low = name.lower()
            is_io = "io" in low  # matches "i1iO", "iO3", …
            # Report the iO charts, plus the i1Pro / iSis ones for comparison.
            if not (is_io or "i1pro" in low or "isis" in low or low.startswith("default")):
                continue
            full = os.path.join(dirpath, name)
            patches = _count_patches(full)
            try:
                size = os.path.getsize(full)
            except OSError:
                size = -1
            space = os.path.basename(os.path.dirname(os.path.dirname(full)))
            is_scan = "scan" in low
            tag = "  <-- iO SCAN mode" if (is_io and is_scan) else ("  <-- iO" if is_io else "")
            rows.append(f"[{space}] {name}: {patches} patches, {size} bytes{tag}")
            io_seen = io_seen or is_io
            scan_seen = scan_seen or (is_io and is_scan)
            if len(rows) >= 300:
                capped = True
                break
        if capped:
            break
    header = ("i1Profiler test charts (patch counts only — no chart data copied)."
              "\nThe iO charts pack far more patches per sheet than the handheld"
              "\ni1Pro, which is the clearest signal of how different the layouts are."
              "\nCharts tagged 'iO SCAN mode' are the strip-scan variant, distinct"
              "\nfrom the spot variant — useful evidence the iO reads two ways.\n")
    if capped:
        rows.append("… (list capped at 300 charts)")
    section("i1Profiler — instrument test charts",
            header + "\n".join(rows) if rows else header + "[no chart files found]")

    if not io_seen:
        section("i1Profiler — iO charts",
                "[no iO-specific charts found — the installation may not include "
                "the iO workflow, which is itself a useful data point.]")

    # 2. Short factual geometry snippets from the iO help files. We extract only
    #    the matching fragments (a number next to mm/patch/row/…), never whole
    #    documents, and cap the total so this can't balloon or leak prose.
    snippets: list[str] = []
    seen: set[str] = set()
    for help_root in _I1PROFILER_HELP_ROOTS:
        if not os.path.isdir(help_root):
            continue
        for dirpath, _dirs, files in os.walk(help_root):
            for name in files:
                if "io" not in name.lower():
                    continue
                if not name.lower().endswith((".htm", ".html", ".txt")):
                    continue
                try:
                    with open(os.path.join(dirpath, name), "r",
                              encoding="utf-8", errors="replace") as fh:
                        text = fh.read(400_000)
                except OSError:
                    continue
                # Strip HTML tags so the snippets read as plain sentences.
                text = re.sub(r"<[^>]+>", " ", text)
                for m in _GEOM_SNIPPET_RE.finditer(text):
                    frag = " ".join(m.group(0).split())
                    if frag and frag not in seen:
                        seen.add(frag)
                        snippets.append(f"[{name}] …{frag}…")
                        if len(snippets) >= 60:
                            break
            if len(snippets) >= 60:
                break
        if len(snippets) >= 60:
            break
    section("i1Profiler — iO geometry hints from help files",
            "\n".join(snippets) if snippets
            else "[no iO help files with dimension text found]")


# --------------------------------------------------------------------------
# summary — the part a human reads first
# --------------------------------------------------------------------------

def quick_summary() -> str:
    """Best-effort 'did we even see the table' answer, per platform."""
    found: list[str] = []
    system = platform.system()
    try:
        if system == "Darwin":
            raw = run(["system_profiler", "-json", "SPUSBDataType"])
            data = json.loads(raw)

            def walk(items):
                for item in items or []:
                    vid = str(item.get("vendor_id", ""))
                    pid = str(item.get("product_id", ""))
                    if "0x0971" in vid:
                        try:
                            num = int(pid, 16)
                        except ValueError:
                            num = -1
                        found.append(
                            f"{item.get('_name', '?')}  VID={vid}  PID={pid}"
                            f"  [{KNOWN_PIDS.get(num, 'unknown X-Rite device')}]"
                            f"  rev={item.get('bcd_device', '?')}"
                        )
                    walk(item.get("_items"))

            walk(data.get("SPUSBDataType"))
        elif system == "Linux":
            for line in run(["lsusb"]).splitlines():
                if f"{XRITE_VID:04x}:" in line.lower():
                    found.append(line.strip())
        elif system == "Windows":
            ps = shutil.which("powershell") or shutil.which("pwsh")
            if ps:
                out = run([ps, "-NoProfile", "-Command",
                           "Get-PnpDevice | Where-Object { $_.InstanceId -like '*VID_0971*' } "
                           "| ForEach-Object { $_.FriendlyName + ' :: ' + $_.InstanceId }"])
                found = [l.strip() for l in out.splitlines() if l.strip()]
    except Exception as exc:                              # noqa: BLE001
        return f"[summary failed: {exc}]"

    if not found:
        return ("NO X-RITE DEVICES SEEN.\n"
                "Please check the table is powered on and plugged in, then run again.")
    return "X-Rite devices detected:\n  " + "\n  ".join(found)


# --------------------------------------------------------------------------
# stage 2a — macOS capture helper
# --------------------------------------------------------------------------
#
# Why this exists, and why nothing is bundled:
#
# Wireshark's ChmodBPF helper is a root LaunchDaemon. Installing it is a
# permanent change to someone else's machine, which is exactly what this tool
# promises never to do — and that promise is the reason people are willing to
# run it. Happily it is also unnecessary: ChmodBPF exists only so Wireshark can
# capture WITHOUT root. Capturing WITH sudo needs no daemon at all, and macOS
# already ships tcpdump + libpcap. So the whole capture can be done with zero
# installs. The user only needs Wireshark to *read* a capture — and they don't
# have to read it, we do.
#
# The interface names are NOT fixed: a 2024 Apple-Silicon Mac exposes
# XHC0/XHC1/XHC2 where older docs all say "XHC20". They must be discovered.

CAPTURE_SCRIPT_NAME = "start-usb-capture.command"

# macOS names its USB capture pseudo-interfaces XHC*/VHC*; some models also
# expose usb*. Matched whole-word so real network interfaces never sneak in.
_USB_IFACE_RE = re.compile(r"^(?:XHC|VHC|usb)\w*$", re.IGNORECASE)


def macos_usb_capture_interfaces() -> list[str]:
    """Discover the BPF pseudo-interfaces macOS exposes for USB capture.

    Read-only — `ifconfig -l` only lists names, it changes nothing.
    """
    out = run(["ifconfig", "-l"], timeout=10)
    if not out or out.startswith("["):
        return []
    return [n for n in out.split() if _USB_IFACE_RE.match(n)]


def macos_capture_script(interfaces: list[str], outdir: str) -> str:
    """Build a self-contained, readable capture script for the user to run.

    Deliberately a separate file rather than something this tool executes
    itself: the privileged part stays visible, opt-in, and under the user's
    control, and this program keeps its "changes nothing" guarantee.
    """
    iface_list = " ".join(shlex.quote(i) for i in interfaces)
    return f"""#!/bin/bash
# ChromIQ — macOS USB capture helper
# Generated by the ChromIQ i1iO information collector.
#
# WHAT THIS DOES
#   Records the USB traffic between this Mac and the i1iO while you drive the
#   table from i1Profiler, so the ChromIQ project can learn how it is
#   controlled. See https://github.com/itsab1989/ChromIQ/issues/129
#
# WHAT IT DOES NOT DO
#   It never sends anything to the table and cannot move the arm — it only
#   listens. It installs NOTHING: `ifconfig` and `tcpdump` are both part of
#   macOS already. No Wireshark, no ChmodBPF, no drivers.
#
# WHY IT ASKS FOR YOUR PASSWORD
#   Listening to raw USB traffic is a privileged operation on macOS. The
#   password goes to macOS's own `sudo`, never to this script or anyone else.
#
# TO UNDO EVERYTHING: nothing to undo. Any capture interface this script
# switches on is switched back off when it finishes (and they all reset on
# reboot anyway).

set -u

OUTDIR={shlex.quote(outdir)}
INTERFACES=({iface_list})

BROUGHT_UP=()
STARTED=()
KEEPALIVE=""
STAMP=""

# macOS ships bash 3.2, where "${{ARR[@]}}" on an EMPTY array aborts the script
# under `set -u`. Every loop over a possibly-empty array is therefore guarded
# by a count check — this is not redundant, it is load-bearing.
restore_interfaces() {{
    if [ "${{#BROUGHT_UP[@]}}" -gt 0 ]; then
        for IF in "${{BROUGHT_UP[@]}}"; do
            sudo ifconfig "$IF" down 2>/dev/null
        done
    fi
}}

# NOTE: SIGTERM, not SIGINT. A command started with `&` from a non-interactive
# shell inherits SIGINT as *ignored*, so `pkill -INT` reports success and does
# nothing at all — verified on macOS. That would leave root tcpdumps running
# and produce an unusable capture. SIGTERM is not ignored, and tcpdump closes
# its output file cleanly on it.
#
# The pattern includes this run's timestamped filename so it can never match a
# tcpdump left over from an earlier run.
stop_capture() {{
    if [ "${{#STARTED[@]}}" -gt 0 ]; then
        for IF in "${{STARTED[@]}}"; do
            sudo pkill -TERM -f "tcpdump -U -i $IF -w io-capture-$STAMP-$IF.pcap" 2>/dev/null
        done
    fi
}}

# Closing the window must not leave root tcpdumps running or interfaces up.
cleanup() {{
    stop_capture
    [ -n "$KEEPALIVE" ] && kill "$KEEPALIVE" 2>/dev/null
    restore_interfaces
}}
trap cleanup EXIT

cd "$OUTDIR" || {{ echo "Cannot enter $OUTDIR"; exit 1; }}

echo "======================================================================"
echo "  ChromIQ — USB capture for the i1iO"
echo "======================================================================"
echo
echo "  Recording to: $OUTDIR"
echo "  Interfaces:   ${{INTERFACES[*]}}"
echo
echo "  This only listens. It cannot move the arm."
echo
echo "  macOS needs your administrator password to listen to USB traffic."
echo

if ! sudo -v; then
    echo
    echo "  Could not get administrator rights, so capturing is not possible."
    echo "  That is fine — the main report on its own is still useful."
    exit 1
fi

# The guided steps take several minutes; sudo's password grace period is 5.
# Refresh it in the background so stopping the capture never re-prompts.
( while true; do sudo -n true 2>/dev/null; sleep 50; done ) &
KEEPALIVE=$!
# Detach it, or bash prints a "Terminated" job message at the end that looks
# alarming to someone who has been told this tool is harmless.
disown "$KEEPALIVE" 2>/dev/null || true

# Bring up only the interfaces that are currently down, and remember which
# ones we touched so we can put them back exactly as we found them.
ACTIVE=()
for IF in "${{INTERFACES[@]}}"; do
    if ! ifconfig "$IF" >/dev/null 2>&1; then
        echo "  - $IF: not present, skipping"
        continue
    fi
    if ifconfig "$IF" 2>/dev/null | head -1 | grep -qE '[<,]UP[,>]'; then
        ACTIVE+=("$IF")
    elif sudo ifconfig "$IF" up 2>/dev/null; then
        BROUGHT_UP+=("$IF")
        ACTIVE+=("$IF")
    else
        echo "  - $IF: could not be switched on, skipping"
    fi
done

if [ "${{#ACTIVE[@]}}" -eq 0 ]; then
    echo
    echo "  No USB capture interfaces could be started on this Mac."
    echo "  This happens on some models. Please skip the capture — or, if you"
    echo "  have a Linux or Windows machine, it is much easier there and the"
    echo "  data is identical."
    exit 1
fi

# One tcpdump per interface: we cannot know in advance which USB bus the iO
# sits on, and capturing them all is cheaper than making the user guess.
STAMP=$(date +%Y%m%d-%H%M%S)
for IF in "${{ACTIVE[@]}}"; do
    OUT="io-capture-$STAMP-$IF.pcap"
    # -U writes each packet straight out, so an abrupt end (closed window,
    # power loss) still leaves a readable file rather than an empty one.
    sudo tcpdump -U -i "$IF" -w "$OUT" >/dev/null 2>"tcpdump-$IF.log" &
    disown $! 2>/dev/null || true
    STARTED+=("$IF")
done

sleep 2

# A tcpdump that died immediately (unsupported interface, no permission) must
# be reported honestly rather than leaving the user recording nothing.
LIVE=0
for IF in "${{STARTED[@]}}"; do
    if pgrep -f "tcpdump -U -i $IF -w io-capture-$STAMP-$IF.pcap" >/dev/null 2>&1; then
        echo "  - $IF: recording"
        LIVE=$((LIVE + 1))
    else
        echo "  - $IF: FAILED to start —"
        sed 's/^/        /' "tcpdump-$IF.log" 2>/dev/null | head -5
    fi
done

if [ "$LIVE" -eq 0 ]; then
    echo
    echo "  Nothing could be recorded on this Mac. Please skip the capture"
    echo "  step — the main report is still genuinely useful on its own."
    exit 1
fi

echo
echo "======================================================================"
echo "  RECORDING. Leave this window open."
echo "======================================================================"
echo
echo "  Now switch to the ChromIQ collector window and work through the"
echo "  steps it gives you (connect, home, move, measure...)."
echo
read -r -p "  When you have finished all the steps, press Enter here... " _

echo
echo "  Stopping..."
stop_capture
sleep 2

# tcpdump wrote these as root; hand them back so they can be attached.
sudo chown "$(id -u):$(id -g)" io-capture-"$STAMP"-*.pcap 2>/dev/null

restore_interfaces

echo
echo "======================================================================"
echo "  DONE — here is what was recorded"
echo "======================================================================"
echo
ls -lh io-capture-"$STAMP"-*.pcap 2>/dev/null | sed 's/^/  /'
echo
echo "  A file of only a few hundred bytes means nothing was captured on"
echo "  that bus — that is normal for the buses the iO is not plugged into."
echo "  If ALL of them are tiny, the capture did not work on this Mac; just"
echo "  send the main report instead."
echo
echo "  Please attach the largest .pcap file AND the probe report to:"
echo "      https://github.com/itsab1989/ChromIQ/issues/129"
echo
read -r -p "  Press Enter to close. " _
"""


def macos_capture_help(interfaces: list[str], script_path: str | None) -> str:
    """Instructions using this Mac's real interface names."""
    if not interfaces:
        return ("""\
  This Mac does not expose any USB capture interfaces, so a capture is not
  possible here. Please skip this step — the main report is still useful.
  (If you happen to have a Linux or Windows machine, capturing there is
  easier anyway, and the data is identical.)""")

    names = ", ".join(interfaces)
    if script_path:
        return (f"""\
  Good news: nothing needs to be installed. macOS already has everything
  required, and I have written a ready-made script for you:

      {script_path}

  1. Open a NEW Terminal window.
  2. Drag that file into it and press Enter (or double-click it in Finder).
  3. It will ask for your admin password — that is macOS asking, because
     listening to USB traffic is privileged. It only listens; it cannot
     move the arm and installs nothing.
  4. When it says RECORDING, come back here and follow the prompts.

  (For the curious: under sudo it runs `ifconfig <if> up` and `tcpdump -w`
  on this Mac's USB interfaces — {names} — and puts everything back as it
  was when it finishes. You can read the whole script first; it is short
  and plain text.)""")

    return (f"""\
  Nothing needs to be installed — macOS already ships tcpdump. In a NEW
  Terminal window, for each of this Mac's USB interfaces ({names}):

      sudo ifconfig {interfaces[0]} up
      sudo tcpdump -i {interfaces[0]} -w io-capture-{interfaces[0]}.pcap

  Then come back here and follow the prompts. Press Ctrl-C in the Terminal
  to stop the capture when this script says you are done.""")


def prepare_macos_capture() -> str:
    """Write the capture script next to the report and return instructions.

    The script must know the folder it lives in, so the directory is chosen
    first and the content built around it — hence the explicit loop instead
    of a generic "write a file somewhere" helper.
    """
    interfaces = macos_usb_capture_interfaces()
    script_path = None
    if interfaces:
        for directory in candidate_dirs():
            if not os.path.isdir(directory):
                continue
            path = os.path.join(directory, CAPTURE_SCRIPT_NAME)
            try:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(macos_capture_script(interfaces, directory))
                os.chmod(path, 0o755)
                script_path = path
                break
            except OSError:
                continue
    return macos_capture_help(interfaces, script_path)


# --------------------------------------------------------------------------
# stage 2 — annotated capture session
# --------------------------------------------------------------------------

CAPTURE_HELP = {
    "Linux": """\
  1. sudo modprobe usbmon
  2. Find the bus number of the i1iO from the 'lsusb' output above.
  3. In a second terminal:  sudo tcpdump -i usbmon<BUS> -w io-capture.pcap
  4. Come back here and follow the prompts.
  5. Stop tcpdump with Ctrl-C when this script says you are done.""",
    "Windows": """\
  1. Install USBPcap (desowin.org/usbpcap) and Wireshark.
  2. Start Wireshark, choose the USBPcap interface the i1iO is on, start capture.
  3. Come back here and follow the prompts.
  4. Stop and save the capture as io-capture.pcapng when this script says so.""",
    # Replaced at runtime by macos_capture_help(), which uses this Mac's real
    # interface names. Kept only as a fallback if that detection fails.
    "Darwin": """\
  macOS already ships everything needed — no Wireshark, no ChmodBPF.
  In a NEW Terminal window, find your USB interfaces with 'ifconfig -l'
  (they are the XHC* ones), then for each:
      sudo ifconfig XHC0 up
      sudo tcpdump -i XHC0 -w io-capture-XHC0.pcap
  Then come back here and follow the prompts.""",
}

# These follow i1Profiler's ACTUAL i1iO workflow, taken from its own on-screen
# instructions: place chart -> press Measure (it calibrates and the arm slides
# out) -> the operator GRABS THE ARM BY HAND and aligns the cross hairs on the
# top-left, bottom-left and bottom-right corners -> it then scans row by row.
#
# Two things an earlier version asked for are deliberately gone, because
# i1Profiler exposes no way to do them: there is no "go home" button (the arm
# parks itself) and no electrostatic-foil toggle (the static mat just holds the
# paper). Asking a helper for impossible steps wastes their time and makes the
# whole tool look uninformed.
#
# The hand-positioning steps are still valuable: while the operator drags the
# arm, the host is polling the table for its position, so that is exactly where
# the position-reporting side of the protocol shows up.
CAPTURE_STEPS = [
    ("Connect",
     "Start i1Profiler and let it find the table. Do nothing else yet."),
    ("Idle",
     "Leave everything completely untouched for about 10 seconds."),
    ("Measure pressed",
     "Place a chart on the table, then press \"Measure\". The device\n"
     "    calibrates itself and the arm slides out to its ready position."),
    ("Align top-left",
     "Grab the arm by hand and line the cross hairs up on the TOP-LEFT\n"
     "    corner patch, then confirm it."),
    ("Align bottom-left",
     "Same again for the BOTTOM-LEFT corner patch."),
    ("Align bottom-right",
     "Same again for the BOTTOM-RIGHT corner patch."),
    ("Scanning",
     "Let it scan at least the first two rows, then stop or cancel it."),
    ("Spot measurement",
     "If your setup offers Spot mode, take ONE single spot reading.\n"
     "    If it does not, just type 'skip'."),
    ("Finished",
     "Let it finish or cancel, and wait until the arm has parked itself."),
]


def annotate_session() -> None:
    system = platform.system()
    print("\n" + "=" * 68)
    print("STAGE 2 — annotated capture session")
    print("=" * 68)
    print("\nThis does NOT capture anything itself. You run the capture tool;")
    print("this script just records precise timestamps for each action so the")
    print("capture can be sliced up afterwards. That alignment is what makes a")
    print("capture useful instead of an unreadable blob.\n")
    print("Set up your capture first:\n")
    if system == "Darwin":
        print(prepare_macos_capture())
    else:
        print(CAPTURE_HELP.get(system, CAPTURE_HELP["Linux"]))

    # Spell out what saying "no" costs. The old wording ("anything else to
    # skip") never said WHAT was being skipped, so people dropped the entire
    # i1Profiler walkthrough — the most valuable part — without realising it
    # existed, and with no hint of how to get back to it.
    print("\n" + "-" * 68)
    print("Next: I would walk you through " + str(len(CAPTURE_STEPS)) + " short operations in i1Profiler")
    print("(connect, align the arm on the chart corners, scan a couple of")
    print("rows) and time each one, so the recording can be split up later.")
    print("It takes about 10 minutes and needs the capture to be running.")
    print("-" * 68)

    if ask("\nIs the capture running — shall I start the walkthrough? (yes / no): ")\
            .lower() not in ("y", "yes"):
        print("\n  Skipping the walkthrough — that is absolutely fine.")
        print("  Your main report is unaffected and still worth sending.")
        print("  To do it another time, run this tool again and choose the")
        print("  advanced step (or start it directly with  --annotate ).\n")
        section("Stage 2 — annotated capture",
                "[walkthrough skipped by operator — no capture running]")
        return

    t0 = time.time()
    log = [f"session start (monotonic zero): {datetime.datetime.now().isoformat()}"]
    print("\nDo each step in i1Profiler, then press Enter here immediately after.")
    print("If a step is not possible on your setup, just type 'skip'.\n")

    for name, instruction in CAPTURE_STEPS:
        print(f"--- {name} ---")
        print(f"    {instruction}")
        start = time.time() - t0
        answer = ask("    press Enter when finished (or 'skip'): ")
        end = time.time() - t0
        if answer.lower().startswith("s"):
            log.append(f"{name}: SKIPPED")
            print("    skipped\n")
            continue
        # Instructions may span lines on screen; the timeline stays one line
        # per step so it can be read against the capture without unpicking it.
        flat = " ".join(instruction.split())
        log.append(f"{name}: t={start:8.3f}s .. {end:8.3f}s   ({flat})")
        print(f"    recorded {start:.3f}s .. {end:.3f}s\n")

    notes = ask("Anything odd happen? (free text, Enter to skip): ")
    if notes:
        log.append(f"operator notes: {notes}")
    section("Stage 2 — annotated capture timeline", "\n".join(log))
    print("\nStop your capture now and save the file.")
    print("Send BOTH the capture file and this probe report.\n")


# --------------------------------------------------------------------------
# capture analysis — turn a raw .pcap into a plain verdict + command timeline
#
# The "analysis half" of the workflow. It NEVER touches a device; it only reads
# a capture file the user already made. It is deliberately DEVICE-AGNOSTIC — it
# assumes no vendor opcodes, because the whole purpose is unknown instruments.
# It reports the raw USB command structure (control setups + bulk volume) so an
# implementer can see what the device's own software said to it, and so the
# person who made the capture can confirm it actually holds traffic before they
# send a multi-megabyte file for nothing.
#
# Only the macOS (Darwin) format is decoded in detail — it is the only one
# validated against real hardware (a ColorMunki via ChromIQ, matched byte-for-
# byte to Argyll's munki driver). Linux (usbmon) and Windows (USBPcap) captures
# are still reported as valid with counts, plus an honest "timeline not decoded
# on this platform yet"; the file itself is complete and worth sending.
# --------------------------------------------------------------------------

LINKTYPE_USB_LINUX = 189
LINKTYPE_USB_LINUX_MMAPPED = 220
LINKTYPE_USBPCAP = 249
LINKTYPE_USB_DARWIN = 266

_LINKTYPE_NAMES = {
    LINKTYPE_USB_LINUX: "Linux usbmon",
    LINKTYPE_USB_LINUX_MMAPPED: "Linux usbmon",
    LINKTYPE_USBPCAP: "Windows USBPcap",
    LINKTYPE_USB_DARWIN: "macOS (Darwin USB)",
}

# Darwin USB header layout (40 bytes), reverse-engineered from real captures and
# confirmed against Argyll's munki driver:
#   [2]       header length (0x28 = 40)
#   [3]       0 = submit (host->device), 1 = complete (device->host)
#   [4:8]     data length, little-endian
#   [0x10:14] URB sequence id (a submit and its completion share it)
#   [0x24:26] idVendor LE   [0x26:28] idProduct LE
#   [40:]     payload; for a control submit this begins with the 8-byte setup
_DARWIN_HDR = 40


def _read_pcap(path):
    """Return (linktype, [(ts, data), ...]). Raise ValueError if not a pcap."""
    with open(path, "rb") as fh:
        blob = fh.read()
    if len(blob) < 24:
        raise ValueError("file too short to be a capture")
    magic = blob[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise ValueError("not a pcap file")
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    linktype = struct.unpack(endian + "I", blob[20:24])[0]
    off, recs = 24, []
    while off + 16 <= len(blob):
        ts_s, ts_u, incl, _orig = struct.unpack(endian + "IIII", blob[off:off + 16])
        off += 16
        if incl > len(blob) - off:                 # truncated final record
            break
        recs.append((ts_s + ts_u / (1e9 if nano else 1e6), blob[off:off + incl]))
        off += incl
    return linktype, recs


def _fmt_ascii(data):
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data)


def _analyze_darwin(recs):
    """Device-agnostic summary: (devices, cmd_counts, timeline, bulk_bytes)."""
    submits = {}                            # seq -> (bRequest, dir_in, wLen, ts)
    cmd_counts = {}                         # bRequest -> count
    devices = {}                            # (vid, pid) -> packet count
    timeline = []
    bulk_bytes = 0
    t0 = recs[0][0] if recs else 0.0
    for ts, data in recs:
        if len(data) < _DARWIN_HDR:
            continue
        direction = data[3]                 # 0 submit, 1 complete
        dlen = struct.unpack("<I", data[4:8])[0]
        seq = struct.unpack("<I", data[0x10:0x14])[0]
        vid = struct.unpack("<H", data[0x24:0x26])[0]
        pid = struct.unpack("<H", data[0x26:0x28])[0]
        if vid or pid:
            devices[(vid, pid)] = devices.get((vid, pid), 0) + 1
        payload = data[_DARWIN_HDR:]
        # A control submit begins with an 8-byte setup packet. Validate both the
        # bmRequestType field (type 0..2 = std/class/vendor, recipient 0..3) AND
        # the USB length invariant — the payload is exactly the 8-byte setup (IN,
        # data returns in the completion) or setup + wLength outbound bytes (OUT).
        # This rejects bulk transfers whose first byte merely looks like a setup.
        # Neither check assumes any specific vendor opcode.
        if (direction == 0 and len(payload) >= 8
                and ((payload[0] >> 5) & 3) <= 2 and (payload[0] & 0x1f) <= 3):
            wlen = struct.unpack("<H", payload[6:8])[0]
            if len(payload) in (8, 8 + wlen):
                breq = payload[1]
                dir_in = bool(payload[0] & 0x80)
                submits[seq] = (breq, dir_in, wlen, ts)
                cmd_counts[breq] = cmd_counts.get(breq, 0) + 1
        elif direction == 1:
            info = submits.get(seq)
            if info:
                if len(timeline) < 30:
                    breq, dir_in, wlen, tsub = info
                    resp = payload[:dlen] if dlen else payload
                    timeline.append((tsub - t0, breq, dir_in, wlen, resp[:16]))
            elif dlen >= 64:                # completion with no control setup
                bulk_bytes += dlen          # = streamed bulk (e.g. sensor data)
    return devices, cmd_counts, timeline, bulk_bytes


def find_captures():
    """Newest io-capture-*.pcap set sitting next to the tool (or Desktop)."""
    for directory in candidate_dirs():
        hits = glob.glob(os.path.join(directory, "io-capture-*.pcap"))
        if hits:
            newest = max(os.path.getmtime(h) for h in hits)
            recent = [h for h in hits if newest - os.path.getmtime(h) < 60]
            return sorted(recent) or sorted(hits)
    return []


def summarize_captures(paths):
    """Plain-language verdict + command timeline for one or more captures."""
    out = ["=" * 68, "  USB capture check", "=" * 68, "",
           "  Reads capture files you already made — it sends NOTHING to any",
           "  device. It confirms a capture really holds instrument traffic",
           "  before you send it, and prints the command timeline.", ""]
    any_real = False
    for path in paths:
        out.append("  " + os.path.basename(path))
        try:
            linktype, recs = _read_pcap(path)
        except (OSError, ValueError) as exc:
            out += [f"     not a readable capture: {exc}", ""]
            continue
        name = _LINKTYPE_NAMES.get(linktype, f"linktype {linktype}")
        total = sum(len(d) for _, d in recs)
        out.append(f"     format: {name}   packets: {len(recs)}   bytes: {total:,}")
        if linktype != LINKTYPE_USB_DARWIN:
            if recs:
                out += ["     Valid capture. A detailed timeline is decoded for macOS",
                        "     captures for now; this file is complete — send it in."]
                any_real = any_real or total > 4096
            else:
                out.append("     Empty — nothing was recorded on this bus.")
            out.append("")
            continue
        devices, cmds, timeline, bulk = _analyze_darwin(recs)
        if devices:
            devstr = ", ".join(f"{v:04x}:{p:04x}" for v, p in
                               sorted(devices, key=lambda k: -devices[k]))
            out.append(f"     device(s) on this bus: {devstr}")
        n_cmd = sum(cmds.values())
        out.append(f"     control commands: {n_cmd}   distinct opcodes: "
                   f"{len(cmds)}   bulk data: {bulk:,} bytes")
        real = bool(devices) and (n_cmd > 0 or bulk > 2048)
        any_real = any_real or real
        if timeline:
            out.append("     timeline (device-agnostic — no opcode is assumed):")
            for tsec, breq, dir_in, wlen, resp in timeline:
                out.append(f"        {tsec:7.3f}s  req=0x{breq:02X} "
                           f"{'IN ' if dir_in else 'OUT'} wLen={wlen:<4} -> "
                           f"{resp.hex(' ')}  |{_fmt_ascii(resp)}|")
        out.append("     VERDICT: " + (
            "OK — real device traffic captured. Good to send."
            if real else
            "little/no device traffic — wrong bus, or no measurement was taken."))
        out.append("")
    out.append("-" * 68)
    out.append("  Overall: " + (
        "at least one file holds real instrument traffic."
        if any_real else
        "no clear instrument traffic found in any file."))
    if not any_real:
        out.append("  Re-run the capture and TAKE A MEASUREMENT while it records.")
    out.append("=" * 68)
    return "\n".join(out)


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main() -> int:
    global REDACT

    parser = argparse.ArgumentParser(
        description="Collect i1iO diagnostics for ChromIQ issue #129. "
                    "Never sends anything to the device."
    )
    parser.add_argument("--annotate", action="store_true",
                        help="go straight into the guided capture session (stage 2)")
    parser.add_argument("--skip-annotate", action="store_true",
                        help="never offer the guided capture session")
    parser.add_argument("--no-redact", action="store_true",
                        help="keep serial numbers and paths as-is")
    parser.add_argument("--capture-setup", action="store_true",
                        help="(macOS) just write the USB capture script and exit")
    parser.add_argument("--analyze", nargs="*", default=None, metavar="PCAP",
                        help="read a USB capture (.pcap) and print a plain "
                             "verdict + command timeline; with no path, finds "
                             "the newest capture next to the tool")
    parser.add_argument("-o", "--output", default=None, help="output file path")
    args = parser.parse_args()
    REDACT = not args.no_redact

    if args.capture_setup:
        if platform.system() != "Darwin":
            print("--capture-setup is macOS-only; see the README for "
                  "Linux (usbmon) and Windows (USBPcap).")
            return 1
        print(prepare_macos_capture())
        return 0

    if args.analyze is not None:
        paths = args.analyze or find_captures()
        if not paths:
            print("No capture file given or found next to the tool.\n"
                  "Make one first with --capture-setup, or pass a path:\n"
                  "    --analyze path/to/capture.pcap")
            return 1
        print(summarize_captures(paths))
        return 0

    print("=" * 68)
    print("  ChromIQ — i1iO information collector")
    print("=" * 68)
    print()
    print("  This only READS information your computer already has about the")
    print("  connected hardware. It never sends anything to the table and it")
    print("  cannot move the arm. It is safe to run at any time.")
    print()
    print("  It takes about a minute. Let's go.")
    print()
    print("-" * 68)
    print("STEP 1 of 3 — looking for your i1iO")
    print("-" * 68)
    print()

    summary = quick_summary()
    print("  " + summary.replace("\n", "\n  ") + "\n")

    if summary.startswith("NO X-RITE DEVICES"):
        print("  This usually means the table is switched off, unplugged, or")
        print("  connected to a different port. You can carry on anyway — the")
        print("  report is still useful — but plugging it in first is better.")
        print()
        if ask("  Press Enter to continue anyway, or type q to quit: ").lower().startswith("q"):
            return 0
        print()

    hardware = {
        "probe_version": "1.3",
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": sys.version.split()[0],
        "redacted": REDACT,
    }
    section("Environment", json.dumps(hardware, indent=2))
    section("Detection summary", summary)

    print("-" * 68)
    print("STEP 2 of 3 — collecting the details")
    print("-" * 68)
    print("\n  Please wait, this takes a few seconds...\n")

    system = platform.system()
    if system == "Darwin":
        collect_macos()
    elif system == "Linux":
        collect_linux()
    elif system == "Windows":
        collect_windows()
    else:
        section("Unsupported platform", f"No collector for {system}")
    # i1Profiler chart metadata is platform-independent (the files live in the
    # same place regardless of which USB backend we used above).
    collect_i1profiler_charts()
    print("  Done.\n")

    # Three things the hardware genuinely cannot tell us itself.
    print("-" * 68)
    print("STEP 3 of 3 — three quick questions")
    print("-" * 68)
    print("\n  Just press Enter to skip any of them.\n")
    answers = {
        "which iO generation (iO / iO2 / iO3)?":
            ask("  1. Which generation is your table — iO, iO2 or iO3?\n     > "),
        "which spectrophotometer is mounted?":
            ask("  2. Which instrument is mounted on it (i1Pro, i1Pro 2, i1Pro 3)?\n     > "),
        "which software normally drives it?":
            ask("  3. Which software do you normally drive it with?\n     > "),
    }
    section("Operator answers",
            "\n".join(f"{q}\n    {a or '[no answer]'}" for q, a in answers.items()))

    # Stage 2 is genuinely advanced, so it is opt-in and clearly labelled.
    if args.annotate:
        annotate_session()
    elif not args.skip_annotate:
        print("\n" + "-" * 68)
        print("OPTIONAL EXTRA — only if you have time and feel adventurous")
        print("-" * 68)
        print()
        print("  There is a second, much more advanced step that records what")
        print("  i1Profiler actually says to the table. It is far more useful to")
        print("  us, but it needs extra software and about 15 minutes.")
        print()
        print("  You do NOT need to do this. The report you already have is a")
        print("  genuinely valuable contribution on its own.")
        print()
        if ask("  Try the advanced step too? (yes / no): ").lower().startswith("y"):
            annotate_session()
        else:
            print("\n  No problem at all — skipping it.\n")

    body = [
        "ChromIQ i1iO probe report",
        "Generated for https://github.com/itsab1989/ChromIQ/issues/129",
        f"Redaction: {'ON (serials hashed, paths stripped)' if REDACT else 'OFF — raw values included'}",
        "",
    ]
    for title, content in _SECTIONS:
        body.append("=" * 72)
        body.append(title)
        body.append("=" * 72)
        body.append(content)
        body.append("")
    report = "\n".join(body)

    out_path = write_report(report, args.output)
    if out_path is None:
        # Never lose the operator's work just because every location was
        # unwritable — show it on screen as an absolute last resort.
        print("\n" + "!" * 68)
        print("Could not save the report anywhere. Please copy everything below")
        print("this line and paste it into the GitHub issue instead.")
        print("!" * 68 + "\n")
        print(report)
        return 1

    size_kb = os.path.getsize(out_path) / 1024
    print("\n" + "=" * 68)
    print("  ALL DONE — thank you!")
    print("=" * 68)
    print()
    print("  Your report was saved here:")
    print()
    print(f"      {out_path}")
    print()
    print(f"  It is a plain text file ({size_kb:.0f} KB). Please open it and have")
    print("  a look first — you can see exactly what is being shared, and you")
    print("  can delete anything you are not comfortable with.")
    print()
    print("  Then attach it to:")
    print("      https://github.com/itsab1989/ChromIQ/issues/129")
    print()
    print("  That's everything. Thank you for helping — this is the single")
    print("  thing standing between the project and i1iO support.")
    print()
    return 0


def candidate_dirs() -> list[str]:
    """Folders to save output in, most preferred first.

    Running from a read-only folder (a mounted disk image, an unzipped bundle
    in a protected location, a network share) must not lose the output, so we
    fall back to the Desktop, then home, then the temp directory.
    """
    dirs: list[str] = []
    # Save next to the tool the user actually launched. When frozen by
    # PyInstaller, __file__ points into a temp bundle that is DELETED on
    # exit — so we must use the real executable's folder (sys.executable),
    # or the output would vanish the moment the program closes.
    base_dir = None
    if getattr(sys, "frozen", False):
        base_dir = os.path.dirname(os.path.abspath(sys.executable))
    else:
        try:
            base_dir = os.path.dirname(os.path.abspath(__file__))
        except Exception:                                 # noqa: BLE001
            base_dir = None
    if base_dir:
        dirs.append(base_dir)
    home = os.path.expanduser("~")
    dirs.append(os.path.join(home, "Desktop"))
    dirs.append(home)
    dirs.append(tempfile.gettempdir())
    return dirs


def write_report(report: str, explicit: str | None) -> str | None:
    """Write the report, trying progressively more reliable locations."""
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    name = f"chromiq-io-probe-{stamp}.txt"

    candidates: list[str] = []
    if explicit:
        candidates.append(explicit)
    else:
        candidates = [os.path.join(d, name) for d in candidate_dirs()]

    for path in candidates:
        try:
            parent = os.path.dirname(path) or "."
            if not os.path.isdir(parent):
                continue
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(report)
            return path
        except OSError:
            continue
    return None


if __name__ == "__main__":
    sys.exit(main())
