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
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
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
    "Darwin": """\
  macOS USB capture is the awkward one. Either:
    a) Install Wireshark plus its ChmodBPF helper, enable USB capture with
       'sudo ifconfig XHC20 up', then capture on the XHC20 interface; or
    b) If you also have a Linux or Windows machine, doing the capture there is
       far easier and the data is identical.
  Then come back here and follow the prompts.""",
}

# Deliberately ordered from safest to most revealing, and each step is one
# single action so it maps to a clean, isolated slice of the capture.
CAPTURE_STEPS = [
    ("Connect", "In i1Profiler, let it detect the i1iO. Do nothing else yet."),
    ("Home", "Send the arm to its home position (and nothing else)."),
    ("Idle", "Leave everything completely untouched for 10 seconds."),
    ("Move A", "Move the arm to the TOP-LEFT corner of a chart. Stop there."),
    ("Move B", "Move the arm to the BOTTOM-LEFT corner. Stop there."),
    ("Move C", "Move the arm to the BOTTOM-RIGHT corner. Stop there."),
    ("Foil on", "Turn the electrostatic foil ON (hold the paper)."),
    ("Foil off", "Turn the electrostatic foil OFF."),
    ("Spot", "Take ONE single spot measurement, anywhere."),
    ("Strip", "Scan ONE single row/strip of a chart."),
    ("Home again", "Send the arm home once more."),
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
    print(CAPTURE_HELP.get(system, CAPTURE_HELP["Linux"]))

    if ask("\nCapture running? Type 'yes' to begin, anything else to skip: ").lower() not in ("y", "yes"):
        section("Stage 2 — annotated capture", "[skipped by operator]")
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
        log.append(f"{name}: t={start:8.3f}s .. {end:8.3f}s   ({instruction})")
        print(f"    recorded {start:.3f}s .. {end:.3f}s\n")

    notes = ask("Anything odd happen? (free text, Enter to skip): ")
    if notes:
        log.append(f"operator notes: {notes}")
    section("Stage 2 — annotated capture timeline", "\n".join(log))
    print("\nStop your capture now and save the file.")
    print("Send BOTH the capture file and this probe report.\n")


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
    parser.add_argument("-o", "--output", default=None, help="output file path")
    args = parser.parse_args()
    REDACT = not args.no_redact

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
        "probe_version": "1.1",
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


def write_report(report: str, explicit: str | None) -> str | None:
    """Write the report, trying progressively more reliable locations.

    Running from a read-only folder (a mounted disk image, an unzipped bundle
    in a protected location, a network share) must not lose the report, so we
    fall back to the Desktop, then home, then the temp directory.
    """
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    name = f"chromiq-io-probe-{stamp}.txt"

    candidates: list[str] = []
    if explicit:
        candidates.append(explicit)
    else:
        # Save next to the tool the user actually launched. When frozen by
        # PyInstaller, __file__ points into a temp bundle that is DELETED on
        # exit — so we must use the real executable's folder (sys.executable),
        # or the report would vanish the moment the program closes.
        base_dir = None
        if getattr(sys, "frozen", False):
            base_dir = os.path.dirname(os.path.abspath(sys.executable))
        else:
            try:
                base_dir = os.path.dirname(os.path.abspath(__file__))
            except Exception:                             # noqa: BLE001
                base_dir = None
        if base_dir:
            candidates.append(os.path.join(base_dir, name))
        home = os.path.expanduser("~")
        candidates.append(os.path.join(home, "Desktop", name))
        candidates.append(os.path.join(home, name))
        import tempfile
        candidates.append(os.path.join(tempfile.gettempdir(), name))

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
