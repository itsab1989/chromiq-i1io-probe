#!/usr/bin/env python3
"""
chromiq_io_probe.py: the ChromIQ X-Rite instrument probe
(the i1iO table, issue #129; since 1.5 also the i1Pro family, the ColorMunki
and the i1Studio; since 1.6 the i1iSis chart readers).

WHAT THIS DOES
    Collects information about an i1iO scanning table and the machine it is
    connected to, and writes it into a single file you can send back.

WHAT THIS DOES NOT DO
    It never sends a single byte to the table. It does not move the arm, does
    not open the device, does not touch i1Profiler's settings, and does not
    need the table to be calibrated. It only reads what the operating system
    already knows about the connected hardware.

    It never changes a system setting. In particular it never switches
    System Integrity Protection (SIP) on or off; it only reads its state.

    You can run it with the arm parked and the table idle. It is safe.

USAGE
    Stage 1, the important one, takes about a minute:

        python3 chromiq_io_probe.py

    Stage 2, optional: record the USB traffic while you use i1Profiler.

        python3 chromiq_io_probe.py --annotate

    To see the i1iO steps first, without recording anything:

        python3 chromiq_io_probe.py --rehearse

    On a Mac a recording is only possible when SIP is switched off. The tool
    checks that for you, says plainly whether a recording is possible, and if
    it is not, explains the other ways to make one.

    Stage 2 for a handheld instrument (i1Pro, i1Pro 2, i1Pro 3, ColorMunki,
    i1Studio), a guided session recorded step by step:

        python3 chromiq_io_probe.py --i1pro

    The same for an i1iSis chart reader (i1iSis, i1iSis XL, i1iSis 2,
    i1iSis 2 XL):

        python3 chromiq_io_probe.py --isis

    Check recordings, or a session folder, before sending them:

        python3 chromiq_io_probe.py --analyze instrument-session-<date>

    All of them produce a file named chromiq-io-probe-<timestamp>.txt next to the
    script. Open it, read it (it is plain text, nothing hidden), and attach it
    to the GitHub issue.

PRIVACY
    Serial numbers are replaced with a short stable hash by default, and your
    username and home directory are stripped out. If you would rather send the
    raw values, add --no-redact. Serial numbers are not needed for this work.

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
import plistlib
import re
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import threading
import time

PROBE_VERSION = "1.6.1"

ISSUE_URL = "https://github.com/itsab1989/ChromIQ/issues/129"   # the i1iO only
NEW_ISSUE_URL = "https://github.com/itsab1989/ChromIQ/issues/new"

# X-Rite USB vendor ID, and the product IDs we have real evidence for.
#
# Only IDs that a real report has shown are named here. 1.3 called 0x2001
# "i1Pro 2 / i1Pro 3 family", but a volunteer's i1Pro 2 reported 0x2000, so
# that guess was wrong and has been removed. Anything not listed is reported
# as "unknown" rather than guessed.
XRITE_VID = 0x0971
# 1.5: newer X-Rite / Calibrite products use this vendor ID (the i1Pro 3 and
# the i1Studio, per ArgyllCMS's device table, insttypes.c:439-450).
XRITE_VIDS = (0x0971, 0x0765)
SESSION_KIND = "chromiq-instrument-session"
KNOWN_PIDS = {
    0x2000: 'i1Pro family, reports itself as "eye-one" (seen from an i1Pro 2)',
    0x2004: 'i1iO table, reports itself as "Eye-One iO" (seen from an i1iO 2)',
    0x2007: "ColorMunki",
    # 1.6: X-Rite's own i1iSis driver plug-in (XRiteDevice 3.0.152, installed
    # with i1Profiler 3.8.8) names 0971:2006, and so does ArgyllCMS's udev
    # rule ("i1 iSis (not tested)"). The plug-in lists only this one ID for
    # the family, so the i1iSis 2 and the XL models most likely share it.
    0x2006: ("i1iSis chart reader (i1iSis, i1iSis XL, i1iSis 2 or 2 XL; "
             "per X-Rite's driver file; its protocol is not known yet)"),
}

# 1.6: the i1iSis family's USB ID, and every X-Rite ID the tool KNOWS to be
# another instrument. An i1iSis session keeps the i1iSis and any X-Rite
# device the tool does not know (in case an i1iSis model reports an ID nobody
# has seen yet), and drops the known others: an i1iSis owner very likely has a
# monitor calibrator plugged in too, and its traffic and serial number do not
# belong in the file. Sources: ArgyllCMS 3.5.0 insttypes.c:439-495 and X-Rite's
# device plug-ins (i1iO 0x2004, i1iO 3 0x30B0, CAPSURE 0x6001), and
# ArgyllCMS's usb/55-Argyll.rules (i1Display 3L 0x600a).
ISIS_IDS = ((0x0971, 0x2006),)
OTHER_INSTRUMENT_IDS = frozenset({
    (0x0971, 0x2000), (0x0971, 0x2001), (0x0971, 0x2003), (0x0971, 0x2004),
    (0x0971, 0x2005), (0x0971, 0x2007),
    (0x0765, 0x5001), (0x0765, 0x5010), (0x0765, 0x5020), (0x0765, 0x6001),
    (0x0765, 0x6003), (0x0765, 0x6008), (0x0765, 0x6009), (0x0765, 0x600A),
    (0x0765, 0x30B0), (0x0765, 0xD020), (0x0765, 0xD092), (0x0765, 0xD094),
})


def instrument_selection(devices: dict, profile: str | None = None,
                         undescribed: bool = False) -> tuple:
    """1.6: which devices of a recording an instrument-only copy keeps.

    devices: key -> {"vid", "pid", "guess_family"} (a device_map(), or the
    IDs of macOS records). Returns (keys, how).

    Every session keeps X-Rite devices only, never a keyboard. The handheld
    sessions keep every X-Rite device, and a device whose identity the
    recording does not show but that uses an instrument family's commands
    (as before 1.6). An i1iSis session (review of 1.6) keeps ONLY the
    i1iSis (0971:2006) when the recording shows one (how = "isis"); when it
    shows none, it keeps X-Rite devices the tool does not know, in case an
    i1iSis model reports an ID nobody has seen yet (how = "unknown"), and
    never a known other instrument or a device it can only guess at: a guess
    comes from i1Pro or ColorMunki commands, which is never the i1iSis.

    profile is the session type: "io" (the i1iO table), a handheld profile
    ("i1pro2", "i1pro", "i1pro3", "munki", "generic"), "isis", or None (a
    caller from before 1.6). Every type except "isis" keeps exactly what
    1.5.5 kept (second review of 1.6: a table recording with an i1iSis on
    the same bus must keep the table). A plain file in --analyze becomes
    "isis" only through plain_file_profile()."""
    if profile != "isis":
        return ([k for k, v in devices.items()
                 if v.get("vid") in XRITE_VIDS or (not v.get("vid") and v.get("guess_family"))],
                "xrite")
    isis = [k for k, v in devices.items() if (v.get("vid"), v.get("pid")) in ISIS_IDS]
    if isis:
        return isis, "isis"
    if undescribed:
        # A device without a USB description may be the i1iSis, so "no
        # i1iSis here" cannot be told: keep nothing (second review).
        return [], "unidentified"
    unknown = [k for k, v in devices.items()
               if v.get("vid") in XRITE_VIDS and (v["vid"], v.get("pid")) not in OTHER_INSTRUMENT_IDS]
    return unknown, ("unknown" if unknown else "")


SESSION_TABLE = "io"           # the session type of the i1iO table recording


def undescribed_present(keys, devices: dict) -> bool:
    """1.6: does a Windows or Linux recording hold traffic of a device whose
    USB description it does not show? (Address 0 is a device being set up.)"""
    described = {k for k, v in devices.items() if v.get("vid")}
    return any(k is not None and k[1] != 0 and k not in described for k in keys)


def decoder_ids() -> set:
    """1.6: the X-Rite devices the tool has a decoder for: the i1Pro family,
    the ColorMunki and i1Studio, and the i1iO table."""
    return {k for k, v in PROFILE_IDS.items() if v != "isis"} | {(XRITE_VID, 0x2004)}


def plain_file_profile(devices: dict):
    """1.6: THE decision for --analyze on plain recordings (no session.json),
    made once over all the files given: "isis" when they show an i1iSis and
    no device the tool has a decoder for (nor one guessed from such a
    device's commands); then the i1iSis rule applies, which drops a monitor
    calibrator or another known instrument without a decoder. Else None:
    the files are read exactly as 1.5.5 read them. session_family() asks
    this same function, so the family and the selection cannot disagree."""
    ids = {(v.get("vid"), v.get("pid")) for v in devices.values()
           if v.get("vid") in XRITE_VIDS}
    guessed = any(not v.get("vid") and v.get("guess_family") for v in devices.values())
    if ids & set(ISIS_IDS) and not ids & decoder_ids() and not guessed:
        return "isis"
    return None


def keeps_device(vid, pid, profile: str | None = None) -> bool:
    """1.6: would a copy keep this one device if it were alone with others of
    the same kind? Only for simple questions; the copies use
    instrument_selection(), which also looks at what else is recorded."""
    keys, _how = instrument_selection({"x": {"vid": vid, "pid": pid}}, profile)
    return bool(keys)


# 1.5: devices under X-Rite's newer vendor ID, named from ArgyllCMS's device
# table (insttypes.c:439-450). Not yet seen in a report; said so.
KNOWN_IDS_0765 = {
    # 1.5.4: from X-Rite's own i1iO 3 driver plug-in (i1Profiler 3.8.8). Its
    # protocol is not known: the analysis of the i1iO 2 is not applied to it.
    0x30B0: "i1iO 3 table (per X-Rite's driver file; its protocol is not known yet)",
    0x6009: "i1Pro 3 or i1Pro 3 Plus (per ArgyllCMS's device table)",
    0x6008: "i1Studio (per ArgyllCMS's device table)",
}


def pid_label(pid, vid=XRITE_VID) -> str:
    if pid is None:
        return "unknown X-Rite device"
    if vid == 0x0765:
        return KNOWN_IDS_0765.get(pid, "unknown X-Rite device (not in this tool's list yet)")
    return KNOWN_PIDS.get(pid, "unknown X-Rite device (not in this tool's list yet)")


REDACT = True
_SECTIONS: list = []
# 1.5.2: why this run could not do its job ("usbpcap_missing", "not_admin",
# "wrong_driver", "no_instrument"), for the WHAT TO DO NOW box printed as the
# last thing before the window closes, and the report that was written.
_CAUSES: list = []
_LAST_REPORT: dict = {}
# 1.5.3: hidden switches for the automated Windows test (tools/vm_test in the
# repository), never needed by a user: --selftest crash,bad-fingerprint,
# offer-on-arm,pretend-usbpcap. See the README, "For testing".
SELFTEST: set = set()
# The options of this run that a copy started as administrator must keep.
_RUN: dict = {}

# How long to wait after starting the recorders before checking they are
# alive. A module constant so the tests can shorten it.
RECORDER_STARTUP_WAIT = 2.0

# 1.6 (third review): every PowerShell command the tool runs, here in one
# place, so the read-only test can pin each one exactly. All of them only
# READ: device lists, device properties, file versions, installed programs.
PS_XRITE_DEVICES = (
    "Get-PnpDevice | Where-Object { ($_.InstanceId -like '*VID_0971*' -or $_.InstanceId -like '*VID_0765*') } | "
    "Format-List FriendlyName,InstanceId,Status,Class,Present")
PS_DEVICE_PROPERTIES = (
    "Get-PnpDevice | Where-Object { ($_.InstanceId -like '*VID_0971*' -or $_.InstanceId -like '*VID_0765*') } | "
    "ForEach-Object { '=== ' + $_.InstanceId + ' ==='; "
    "Get-PnpDeviceProperty -InstanceId $_.InstanceId | "
    "Select-Object KeyName,Data | Format-List }")
PS_USB_HUBS = "Get-PnpDevice -Class USB | Format-List FriendlyName,InstanceId,Status"
PS_DRIVER_FILES = (
    "Get-ChildItem -Path 'C:\\Program Files*\\X-Rite','C:\\Program Files*\\i1Profiler' "
    "-Recurse -Include *.dll,*.exe -ErrorAction SilentlyContinue | "
    "Select-Object FullName,Length,@{n='Version';e={$_.VersionInfo.FileVersion}} | "
    "Format-List")
PS_SUMMARY = (
    "Get-PnpDevice | Where-Object { ($_.InstanceId -like '*VID_0971*' -or $_.InstanceId -like '*VID_0765*') } "
    "| ForEach-Object { $_.FriendlyName + ' :: ' + $_.InstanceId + ' :: ' + $_.Present }")
PS_PROGRAMS = (
    "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
    "'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' "
    "-ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | "
    "ForEach-Object { $_.DisplayName + ' :: ' + $_.DisplayVersion }")
PS_PREFIX = "$ProgressPreference = 'SilentlyContinue'; "


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _quiet_kwargs() -> dict:
    """1.5.3: a helper program must never touch the user's window: no input
    from it (a key the user types belongs to this tool), output and errors
    captured (they go into the report, never onto the screen), and on Windows
    no console of its own (CREATE_NO_WINDOW), so nothing flashes and nothing
    can write into this window."""
    kw = {"stdin": subprocess.DEVNULL, "capture_output": True}
    if os.name == "nt":
        kw["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    return kw


def run(cmd: list, timeout: int = 40) -> str:
    """Run a command, return its output, never raise."""
    try:
        proc = subprocess.run(
            cmd, text=True, timeout=timeout, check=False, errors="replace", **_quiet_kwargs()
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


_RUN_CACHE: dict = {}


def run_cached(cmd: list, timeout: int = 60) -> str:
    """Like run(), but each command runs at most once per session."""
    key = tuple(cmd)
    if key not in _RUN_CACHE:
        _RUN_CACHE[key] = run(cmd, timeout=timeout)
    return _RUN_CACHE[key]


# Each rule is (pattern, description). Group 1 is kept verbatim, group 2 is the
# secret and gets replaced by a stable short hash. One rule per real-world
# format, because a single clever regex missed three of them in testing:
# macOS system_profiler emits "serial_num" or "USBDeviceKeySerialNumber",
# lsusb emits "iSerial <index> <val>", and Windows hides the serial in the tail
# of the device instance path.
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
    # macOS ioreg: "UsbDeviceSignature" = <...> carries the serial number as
    # ASCII after the IDs (1.3 let this through). The IDs it also holds are
    # reported separately, so the whole value is hashed.
    (re.compile(r"(\"UsbDeviceSignature\"\s*=\s*<)([0-9A-Fa-f]+)"), "usb-signature"),
    # Bare UUIDs, wherever they turn up.
    (re.compile(r"()\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}"
                r"-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b"), "uuid"),
]


def _hash_secret(match) -> str:
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
    # 1.5.4 review: run as another administrator, the folder can belong to a
    # different user than the one this process runs as.
    text = re.sub(r"(?i)\b([A-Z]:\\+Users\\+)(?!Public\b)[^\\/\"'\r\n]+", r"\1USER", text)
    text = re.sub(r"(/Users/|/home/)(?!Shared\b)[^/\s\"']+", r"\1USER", text)
    for pattern, _name in _SERIAL_RULES:
        text = pattern.sub(_hash_secret, text)
    return text


def section(title: str, body: str) -> None:
    _SECTIONS.append((title, scrub(body if body is not None else "")))


def set_section(title: str, body: str) -> None:
    """1.5.4: like section(), but replaces a section of the same title, so a
    long session can keep its report section up to date as it goes."""
    for i, (old, _body) in enumerate(_SECTIONS):
        if old == title:
            _SECTIONS[i] = (title, scrub(body if body is not None else ""))
            return
    section(title, body)


# 1.5.4: what the very end of the run must still show (the SIP box after a
# Mac recording), whatever way the run ends.
_END: dict = {}


def _say(text: str = "") -> None:
    """print() that never fails: after the window was closed, printing can
    raise, and that must not stop the recording from being cleaned up."""
    try:
        print(text)
    except (OSError, ValueError):
        pass


# 1.5.4: set once input has ended (stdin closed or piped and used up), so
# loops that wait for a particular answer can stop instead of spinning.
_INPUT_ENDED: list = []


def ask(prompt: str, interruptible: bool = False) -> str:
    try:
        answer = input(prompt).strip()
        _INPUT_ENDED.clear()
        return answer
    except EOFError:
        print()
        # A Ctrl-D typed on a terminal is not the end of the input (typing
        # still works afterwards); only a closed or used-up pipe or file is.
        if not _isatty(sys.stdin):
            _INPUT_ENDED[:] = [True]
        return ""
    except KeyboardInterrupt:
        print()
        if interruptible:
            raise
        return ""


def said_yes(answer: str) -> bool:
    return answer.strip().lower() in ("y", "yes")


# --------------------------------------------------------------------------
# macOS: reading the USB device list (no device is ever opened)
# --------------------------------------------------------------------------
#
# 1.3 asked `system_profiler SPUSBDataType`. On current macOS that returns an
# EMPTY list; the data moved to `SPUSBHostDataType`. 1.3 therefore printed
# "NO X-RITE DEVICES SEEN" while the table was listed in its own ioreg section
# further down. 1.4 asks all three sources and believes any one of them.

def _to_int(value):
    """'0x0971', '0x0971  (X-Rite)', '0x02210000 / 3', 2417 -> int, else None."""
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text = str(value)
    m = re.search(r"0x([0-9A-Fa-f]+)", text)
    if m:
        return int(m.group(1), 16)
    m = re.match(r"\s*(\d+)\s*$", text)
    if m:
        return int(m.group(1))
    return None


def parse_system_profiler_json(text: str):
    """All USB devices in a system_profiler -json dump, or None if unreadable.

    Understands both the current key (SPUSBHostDataType, whose items use
    USBDeviceKey* names) and the old one (SPUSBDataType: vendor_id, ...).
    """
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    devices: list = []

    def walk(items, parents):
        for item in items or []:
            if not isinstance(item, dict):
                continue
            name = str(item.get("_name", "?"))
            vid = _to_int(item.get("USBDeviceKeyVendorID", item.get("vendor_id")))
            pid = _to_int(item.get("USBDeviceKeyProductID", item.get("product_id")))
            loc = _to_int(item.get("USBKeyLocationID", item.get("location_id")))
            if vid is not None:
                devices.append({
                    "name": name, "vid": vid, "pid": pid, "location": loc,
                    "revision": item.get("USBDeviceKeyProductVersion",
                                         item.get("bcd_device")),
                    "speed": item.get("USBDeviceKeyLinkSpeed", item.get("device_speed")),
                    "parents": list(parents),
                })
            here = name if loc is None else f"{name} (Location ID 0x{loc:08x})"
            walk(item.get("_items"), parents + [here])

    found_key = False
    for key in ("SPUSBHostDataType", "SPUSBDataType"):
        if key in data:
            found_key = True
            walk(data.get(key), [])
    return devices if found_key else None


_IOREG_NODE_RE = re.compile(r"^(?P<indent>[ |]*)\+-o (?P<name>.+?)  <class (?P<cls>[^,>]+)")
_IOREG_PROP_RE = re.compile(r'^[ |]*"(?P<key>[^"]+)" = (?P<val>.*)$')


def _ioreg_value(raw: str):
    raw = raw.strip()
    if len(raw) >= 2 and raw.startswith('"') and raw.endswith('"'):
        return raw[1:-1]
    if re.fullmatch(r"-?\d+", raw):
        return int(raw)
    return raw


def parse_ioreg(text: str) -> list:
    """Parse `ioreg -l -w0` text into nodes: name, class, depth, props, parent."""
    nodes: list = []
    stack: list = []                     # indices of open ancestors
    for line in (text or "").splitlines():
        m = _IOREG_NODE_RE.match(line)
        if m:
            depth = len(m.group("indent"))
            full = m.group("name").strip()
            name, _, unit = full.rpartition("@")
            if not name or not re.fullmatch(r"[0-9A-Fa-f,]+", unit):
                name = full
            while stack and nodes[stack[-1]]["depth"] >= depth:
                stack.pop()
            node = {"name": name, "cls": m.group("cls").strip(), "depth": depth,
                    "props": {}, "parent": stack[-1] if stack else None,
                    "line": line}
            nodes.append(node)
            stack.append(len(nodes) - 1)
            continue
        p = _IOREG_PROP_RE.match(line)
        if p and nodes:
            nodes[-1]["props"][p.group("key")] = _ioreg_value(p.group("val"))
    return nodes


def _ancestors(nodes: list, index: int) -> list:
    out = []
    parent = nodes[index]["parent"]
    while parent is not None:
        out.append(parent)
        parent = nodes[parent]["parent"]
    return list(reversed(out))


def _node_label(node: dict) -> str:
    loc = node["props"].get("locationID")
    name = node["props"].get("USB Product Name") or node["name"]
    if isinstance(loc, int):
        return f"{name} (Location ID 0x{loc:08x})"
    return str(name)


_USB_DEVICE_CLASSES = ("IOUSBHostDevice", "IOUSBDevice")


def ioreg_usb_devices(text: str):
    """USB devices from `ioreg -p IOUSB -l -w0`, or None if unreadable."""
    if not text or text.startswith("["):
        return None
    nodes = parse_ioreg(text)
    if not nodes:
        return None
    devices = []
    for i, node in enumerate(nodes):
        if node["cls"] not in _USB_DEVICE_CLASSES:
            continue
        props = node["props"]
        vid = _to_int(props.get("idVendor"))
        if vid is None:
            continue
        bcd = _to_int(props.get("bcdDevice"))
        devices.append({
            "name": str(props.get("USB Product Name") or node["name"]),
            "vid": vid, "pid": _to_int(props.get("idProduct")),
            "location": _to_int(props.get("locationID")),
            "revision": f"{bcd >> 8:x}.{bcd & 0xff:02x}" if bcd is not None else None,
            "speed": props.get("UsbLinkSpeed"),
            "parents": [_node_label(nodes[a]) for a in _ancestors(nodes, i)
                        if nodes[a]["cls"] != "IORegistryEntry"],
        })
    return devices


MACOS_SOURCES = [
    ("system_profiler SPUSBHostDataType (current macOS)",
     ["system_profiler", "-json", "SPUSBHostDataType"], parse_system_profiler_json),
    ("system_profiler SPUSBDataType (older macOS)",
     ["system_profiler", "-json", "SPUSBDataType"], parse_system_profiler_json),
    ("ioreg, USB plane",
     ["ioreg", "-p", "IOUSB", "-l", "-w", "0"], ioreg_usb_devices),
]


def detect_xrite(source_outputs: list) -> dict:
    """Merge X-Rite devices seen by any source.

    source_outputs: [(label, raw_text, parser), ...]. Returns
    {"devices": [...], "sources": [(label, status), ...]}.
    """
    merged: dict = {}
    order: list = []
    statuses = []
    for label, text, parser in source_outputs:
        devices = parser(text)
        if devices is None:
            statuses.append((label, "could not be read"))
            continue
        xrite = [d for d in devices if d["vid"] in XRITE_VIDS]
        if not devices:
            statuses.append((label, "returned an empty list"))
        else:
            listed = "1 USB device" if len(devices) == 1 else f"{len(devices)} USB devices"
            statuses.append((label, f"{listed} listed, {len(xrite)} of them from X-Rite"))
        for dev in xrite:
            key = (dev["pid"], dev["location"])
            if key not in merged:
                merged[key] = dict(dev, seen_by=[label])
                order.append(key)
                continue
            have = merged[key]
            have["seen_by"].append(label)
            for field in ("revision", "speed", "name"):
                if not have.get(field) and dev.get(field):
                    have[field] = dev[field]
            if len(dev.get("parents") or []) > len(have.get("parents") or []):
                have["parents"] = dev["parents"]
    return {"devices": [merged[k] for k in order], "sources": statuses}


def macos_detection() -> dict:
    outputs = [(label, run_cached(cmd, timeout=90), parser)
               for label, cmd, parser in MACOS_SOURCES]
    return detect_xrite(outputs)


def bus_guess(location) -> str | None:
    """XHC<n> from the top byte of a Location ID. An inference, not a fact."""
    if not isinstance(location, int):
        return None
    return f"XHC{(location >> 24) & 0xff}"


def format_detection(result: dict) -> str:
    devices = result["devices"]
    lines = []
    if not devices:
        lines.append("NO X-RITE DEVICES SEEN.")
        lines.append("Is it switched on and plugged in? Step 3 can look again.")
    else:
        lines.append("X-Rite devices detected:")
        for dev in devices:
            pid = dev["pid"]
            pid_txt = f"{pid:04x}" if isinstance(pid, int) else "????"
            loc = dev["location"]
            loc_txt = f"0x{loc:08x}" if isinstance(loc, int) else "unknown"
            vid = dev.get("vid", XRITE_VID)
            lines.append(f"  {dev['name']}   {vid:04x}:{pid_txt}   {pid_label(pid, vid)}")
            lines.append(f"      Location ID {loc_txt}, revision {dev.get('revision') or '?'}")
            parents = [p for p in (dev.get("parents") or []) if p]
            if parents:
                lines.append("      connected through: " + " > ".join(parents))
        # Two X-Rite devices behind the same hub: the hub is almost certainly
        # the one inside the table, with the i1Pro plugged into it.
        hubs: dict = {}
        for dev in devices:
            if dev.get("parents"):
                hubs.setdefault(dev["parents"][-1], []).append(dev["name"])
        for hub, names in hubs.items():
            if len(names) >= 2:
                lines.append(f"  {', '.join(names)} share one hub: {hub}.")
                lines.append("  That hub is most likely the one built into the table, "
                             "with the instrument plugged into it.")
    lines.append("")
    lines.append("Where the tool looked:")
    for label, status in result["sources"]:
        # 1.5.3: on a line of its own, so it fits an 80-column window
        lines.append(f"  {label}:")
        lines.append(f"      {status}")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# macOS: USB description of the X-Rite devices (still without opening them)
# --------------------------------------------------------------------------
#
# Opening the device (the way libusb tools do) can take it away from X-Rite
# Device Services, so this tool never does that. The IOKit registry has the
# device and interface descriptors; macOS does not keep the endpoint details
# there, so those have to come from a recording.

_DEVICE_FIELDS = ["idVendor", "idProduct", "bcdDevice", "bcdUSB", "bDeviceClass",
                  "bDeviceSubClass", "bDeviceProtocol", "bMaxPacketSize0",
                  "bNumConfigurations", "kUSBCurrentConfiguration", "UsbLinkSpeed",
                  "USB Vendor Name", "USB Product Name", "locationID", "USB Address"]
_INTERFACE_FIELDS = ["bInterfaceNumber", "bAlternateSetting", "bInterfaceClass",
                     "bInterfaceSubClass", "bInterfaceProtocol", "bNumEndpoints",
                     "bConfigurationValue", "kUSBString"]
_ENDPOINT_KEY_RE = re.compile(r"endpoint|bEndpointAddress|wMaxPacketSize|bmAttributes|bInterval",
                              re.IGNORECASE)
_CLASS_NAMES = {0: "defined per interface", 2: "communications", 3: "HID",
                8: "mass storage", 9: "hub", 10: "CDC data", 255: "vendor-specific"}


def _fmt_field(key: str, value) -> str:
    if key in ("idVendor", "idProduct") and isinstance(value, int):
        return f"{key} = 0x{value:04x}"
    if key in ("bcdDevice", "bcdUSB") and isinstance(value, int):
        return f"{key} = 0x{value:04x} ({value >> 8:x}.{value & 0xff:02x})"
    if key == "locationID" and isinstance(value, int):
        return f"{key} = 0x{value:08x}"
    if key in ("bDeviceClass", "bInterfaceClass") and isinstance(value, int):
        return f"{key} = {value} ({_CLASS_NAMES.get(value, 'other')})"
    return f"{key} = {value}"


def xrite_subtrees(text: str) -> list:
    """(device node, [subtree nodes]) for each X-Rite USB device in an ioreg dump."""
    nodes = parse_ioreg(text)
    out = []
    seen_lines = set()
    for i, node in enumerate(nodes):
        if node["cls"] not in _USB_DEVICE_CLASSES:
            continue
        if _to_int(node["props"].get("idVendor")) not in XRITE_VIDS:
            continue
        key = (node["name"], node["props"].get("locationID"))
        if key in seen_lines:
            continue
        seen_lines.add(key)
        sub = []
        for j in range(i + 1, len(nodes)):
            if nodes[j]["depth"] <= node["depth"]:
                break
            sub.append(nodes[j])
        out.append((node, sub))
    return out


def describe_xrite_usb(iousb_text: str, service_text: str) -> str:
    """Readable USB description of every X-Rite device, from the registry only."""
    devices = xrite_subtrees(iousb_text)
    service = {(_to_int(n["props"].get("locationID"))): (n, sub)
               for n, sub in xrite_subtrees(service_text)}
    if not devices and service:
        devices = [(n, []) for n, _sub in service.values()]
    if not devices:
        return "[no X-Rite device in the IOKit registry]"
    lines = []
    any_endpoint = False
    for node, _sub in devices:
        props = node["props"]
        loc = _to_int(props.get("locationID"))
        lines.append(f"--- {props.get('USB Product Name') or node['name']} ---")
        lines.append("  device descriptor (as macOS recorded it):")
        for key in _DEVICE_FIELDS:
            if key in props:
                lines.append("    " + _fmt_field(key, props[key]))
        svc_node, svc_sub = service.get(loc, (None, []))
        interfaces = [n for n in svc_sub if n["cls"] == "IOUSBHostInterface"]
        if interfaces:
            for itf in interfaces:
                lines.append(f"  interface {itf['props'].get('bInterfaceNumber', '?')}:")
                for key in _INTERFACE_FIELDS:
                    if key in itf["props"]:
                        lines.append("    " + _fmt_field(key, itf["props"][key]))
        else:
            lines.append("  interfaces: none listed in the registry")
        endpoint_lines = []
        for n in svc_sub:
            for key, value in n["props"].items():
                if _ENDPOINT_KEY_RE.search(key) and key != "bNumEndpoints":
                    endpoint_lines.append(f"    [{n['cls']}] {key} = {value}")
        if endpoint_lines:
            any_endpoint = True
            lines.append("  endpoint details found in the registry:")
            lines.extend(endpoint_lines[:60])
        drivers = sorted({n["cls"] for n in svc_sub if n["cls"] != "IOUSBHostInterface"})
        if drivers:
            lines.append("  software attached to it: " + ", ".join(drivers))
        creators = sorted({str(n["props"]["IOUserClientCreator"]) for n in svc_sub
                           if "IOUserClientCreator" in n["props"]})
        if creators:
            lines.append("  opened by: " + "; ".join(creators))
        lines.append("")
    if not any_endpoint:
        lines.append("Endpoint details (addresses, transfer types, packet sizes) are "
                     "not kept in the macOS registry, and reading them directly would "
                     "mean opening the device, which this tool never does. They "
                     "will be in a USB recording.")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# macOS: can this Mac record USB traffic?
# --------------------------------------------------------------------------

# macOS names its USB capture pseudo-interfaces XHC*/VHC*. Matched whole-word
# so real network interfaces never sneak in.
_USB_IFACE_RE = re.compile(r"^(?:XHC|VHC)\w*$")


def macos_usb_capture_interfaces() -> list:
    """Discover the USB capture interfaces. Read-only: `ifconfig -l` only lists names."""
    out = run(["ifconfig", "-l"], timeout=10)
    if not out or out.startswith("["):
        return []
    return [n for n in out.split() if _USB_IFACE_RE.match(n)]


def parse_csrutil(text: str) -> str:
    """'on', 'off', 'partly' (custom configuration) or 'unknown'."""
    if not text or text.startswith("["):
        return "unknown"
    low = text.lower()
    # Single SIP parts switched off ("csrutil enable --without ...") report
    # "Custom Configuration". That is not enough for USB capture.
    if "custom configuration" in low:
        return "partly"
    m = re.search(r"protection status:\s*(\w+)", low)
    if m:
        if m.group(1) == "enabled":
            return "on"
        if m.group(1) == "disabled":
            return "off"
    return "unknown"


def macos_cpu() -> dict:
    arm = run(["sysctl", "-n", "hw.optional.arm64"], timeout=10).strip() == "1"
    brand = run(["sysctl", "-n", "machdep.cpu.brand_string"], timeout=10).strip()
    if brand.startswith("["):
        brand = ""
    return {"apple_silicon": arm or platform.machine() == "arm64", "brand": brand}


_READINESS: dict = {}


def macos_recording_readiness(devices: list | None = None) -> dict:
    """Everything needed to say honestly whether a recording can work here."""
    if _READINESS and devices is None:
        return _READINESS
    cpu = macos_cpu()
    csr_text = run(["csrutil", "status"], timeout=10)
    sip = parse_csrutil(csr_text)
    interfaces = macos_usb_capture_interfaces()
    tcpdump = shutil.which("tcpdump")
    reasons = []
    if sip == "on":
        reasons.append("System Integrity Protection (SIP) is switched on. macOS only "
                       "lets a program listen to USB traffic when SIP is fully "
                       "switched off.")
    elif sip == "partly":
        reasons.append("System Integrity Protection (SIP) is only partly switched off "
                       "(a custom configuration). Recording needs SIP fully switched "
                       "off; switching off single parts of it does not work.")
    elif sip == "unknown":
        reasons.append("The tool could not read whether System Integrity Protection "
                       "(SIP) is on or off.")
    if not interfaces:
        reasons.append("macOS shows no USB recording interfaces. On Apple Silicon they "
                       "are called XHC0, XHC1 and XHC2, on Intel Macs XHC20. They only "
                       "appear once SIP is fully switched off.")
    if not tcpdump:
        reasons.append("The tcpdump program, which normally comes with macOS, was not "
                       "found.")
    possible = bool(interfaces) and bool(tcpdump) and sip != "on"
    guesses = []
    for dev in devices or []:
        g = bus_guess(dev.get("location"))
        if g and g not in guesses:
            guesses.append(g)
    result = {"cpu": cpu, "sip": sip, "csrutil": csr_text, "interfaces": interfaces,
              "tcpdump": tcpdump, "possible": possible, "reasons": reasons,
              "bus_guesses": guesses}
    _READINESS.clear()
    _READINESS.update(result)
    return result


_SIP_WORDS = {"on": "switched ON", "off": "switched OFF",
              "partly": "partly switched off (custom configuration)",
              "unknown": "unknown"}


def readiness_report(r: dict) -> str:
    cpu = r["cpu"]
    lines = [
        "Processor: " + ("Apple Silicon" if cpu["apple_silicon"] else "Intel")
        + (f" ({cpu['brand']})" if cpu["brand"] else ""),
        f"System Integrity Protection: {_SIP_WORDS[r['sip']]}",
        "  csrutil says: " + " ".join(r["csrutil"].split()),
        "USB recording interfaces: " + (", ".join(r["interfaces"]) or "none"),
        f"tcpdump: {r['tcpdump'] or 'not found'}",
    ]
    if r["bus_guesses"]:
        lines.append("Bus the X-Rite devices are probably on: " + ", ".join(r["bus_guesses"])
                     + " (a guess from the Location ID; the tool records on every "
                       "XHC interface anyway)")
    if r["possible"]:
        lines.append("Verdict: a recording looks possible on this Mac.")
    else:
        lines.append("Verdict: a recording is NOT possible on this Mac right now, because:")
        lines.extend("  - " + _wrap(reason, 70, "    ") for reason in r["reasons"])
    return "\n".join(lines)


# --------------------------------------------------------------------------
# texts the user reads about recording
# --------------------------------------------------------------------------

I1PROFILER_WARNING = """\
  IMPORTANT FOR OWNERS OF AN i1Pro 2 OR AN i1iO 2:
  i1Profiler 3.8.7 (July 2026) removed support for the i1Pro 2 and the
  i1iO 2. Please stay on i1Profiler 3.8.6 or older, and do not let it
  update itself. If it offers an update, decline it."""


def sip_steps_text(apple_silicon: bool) -> str:
    if apple_silicon:
        start = """\
       a. Choose Apple menu > Shut Down, and wait until the Mac is off.
       b. Press and hold the power button until "Loading startup options"
          appears, then let go.
       c. Click "Options", then "Continue". If asked, choose your user and
          type your password."""
    else:
        start = """\
       a. Choose Apple menu > Restart.
       b. Straight away press and hold the Command key and the R key
          together, until the Apple logo appears, then let go.
       c. If asked, choose your user and type your password."""
    return f"""\
     To switch SIP off:
{start}
       d. In the menu bar choose Utilities > Terminal.
       e. Type   csrutil disable   and press Return. If it asks, answer
          y and type your user name and password.
       f. Choose Apple menu > Restart. The Mac starts up normally.
       g. Run this tool again and choose the recording step. It checks
          that SIP is off and guides you through the recording.

     To switch SIP back on afterwards (please do not forget this):
       Do steps a. to d. again, then type   csrutil enable   and press
       Return, answer y if asked, and choose Apple menu > Restart.
       To check it worked: open the Terminal app, type   csrutil status
       and press Return. It should say "enabled"."""


def recording_not_possible_text(r: dict, device: str = "table",
                                profile: str | None = None) -> str:
    """device: "table" (the i1iO, 1.4) or "instrument" (the 1.5 session).
    profile "isis" (1.6 review): the Windows facts for the i1iSis, not the
    i1Pro 2's."""
    reasons = "\n".join("    - " + _wrap(reason, 66, "      ") for reason in r["reasons"])
    if profile == "isis":
        device = "i1iSis"
        which_windows = """\
     Which Windows works: X-Rite says i1Profiler 3.8.8 fixed the i1iSis
     drivers on Windows 11 version 25H2, so please use 3.8.8 or newer
     there. Switch the i1iSis on BEFORE you plug in its USB cable.
     A Windows virtual machine on an Apple Silicon Mac does NOT work for
     a recording: it runs Windows on ARM, where the recorder this tool
     uses (USBPcap) does not exist. Whether X-Rite's i1iSis driver works
     on Windows on ARM is not known."""
        warning = ""
    else:
        which_windows = """\
     Which Windows works: the X-Rite driver for the i1Pro 2 and the i1iO 2
     needs Windows 10 with i1Profiler 3.8.5, or Windows 11 version 24H2 or
     older with i1Profiler 3.8.6. X-Rite says the driver is blocked on
     Windows 11 version 25H2 and newer.
     A Windows virtual machine on an Apple Silicon Mac does NOT work for
     a recording: it runs Windows on ARM, where the recorder this tool
     uses (USBPcap) does not exist. We also know of no X-Rite driver
     there for the i1Pro 2, the i1iO or the ColorMunki."""
        warning = "\n\n" + I1PROFILER_WARNING
    return f"""\
  RECORDING THE USB TRAFFIC IS NOT POSSIBLE ON THIS MAC RIGHT NOW

  Why:
{reasons}

  That is completely normal: SIP is switched on for nearly every Mac, and
  it should be. Your report is useful without a recording.

  If you would like to help with a recording anyway, there are three ways.
  All of them are optional. Pick whichever suits you.

  1. A WINDOWS PC WITH AN INTEL OR AMD PROCESSOR (the easiest way)
     Connect the {device} to that PC, install the free program Wireshark
     (wireshark.org) and tick "USBPcap" when its installer offers it.
     Then run this tool on that PC and choose the recording step; it tells
     you exactly what to do.
{which_windows}

  2. SWITCH SIP OFF ON THIS MAC, ONLY FOR THE RECORDING
     The honest risk: while SIP is off, macOS no longer protects its own
     system files, so harmful software could change them more easily.
     Keep it off only for the recording and switch it back on straight
     after.
     Good to know first: on Apple Silicon Macs this way is only partly
     proven. One person reported in 2026 that it works; another, in 2021,
     got recordings in which every data byte was zero. This tool checks
     for exactly that after recording and tells you plainly.
{sip_steps_text(r["cpu"]["apple_silicon"])}

  3. A HARDWARE USB SNIFFER
     A small box that goes into the cable between the computer and the
     {device} and records what passes through. It changes nothing on the
     Mac. Examples: Cynthion with the free Packetry program (about 210
     EUR), or Taradov's open-hardware USB Sniffer (about 35 USD; its
     software is ready-made only for Windows and Linux). Only worth it if
     you already own one or enjoy this kind of thing.{warning}

  REMINDER: if you switch SIP off for a recording, switch it back on
  afterwards with   csrutil enable   (steps above)."""


SIP_OFF_REMINDER = """\
  ======================================================================
  REMINDER: System Integrity Protection (SIP) is switched OFF on this Mac.
  ======================================================================
  When you have finished recording, please switch it back on:
    1. Start up into the startup options (Apple Silicon: shut down, then
       press and hold the power button; Intel: restart while holding
       Command and R).
    2. Choose Utilities > Terminal, type   csrutil enable   and press
       Return, answer y if asked.
    3. Choose Apple menu > Restart.
  To check: in the Terminal app, type   csrutil status   . It should say
  "enabled"."""


def sip_back_on_box(apple_silicon: bool, thanks: bool = True) -> str:
    """1.5.4: the last thing on the screen after a Mac session with SIP off:
    a friendly box with the exact steps to switch it back on, and the check."""
    if apple_silicon:
        start = ["1. Choose Apple menu > Shut Down and wait until the Mac is off.",
                 "2. Press and hold the power button until \"Loading startup",
                 "   options\" appears, then let go.",
                 "3. Click \"Options\", then \"Continue\". If asked, choose your",
                 "   user and type your password."]
    else:
        start = ["1. Choose Apple menu > Restart.",
                 "2. Straight away press and hold Command and R together, until",
                 "   the Apple logo appears, then let go.",
                 "3. If asked, choose your user and type your password."]
    body = ((["Thank you for recording! Your Mac is still less protected than"] if thanks
             else ["Your Mac is still less protected than"])
            + ["usual, because System Integrity Protection (SIP) is switched off.",
               "Please switch it back on now, it only takes a few minutes:", ""]
            + start
            + ["4. In the menu bar choose Utilities > Terminal.",
               "5. Type   csrutil enable   and press Return. If asked, answer y",
               "   and type your user name and password.",
               "6. Choose Apple menu > Restart. The Mac starts up normally.", "",
               "To check it worked: open the Terminal app, type",
               "   csrutil status",
               "and press Return. It should say \"enabled\"."])
    width = max(len(l) for l in body) + 4
    top = "  +" + "-" * (width - 2) + "+"
    title = "PLEASE SWITCH SIP BACK ON"
    lines = [top, "  | " + title.center(width - 4) + " |", "  |" + " " * (width - 2) + "|"]
    lines += ["  | " + l.ljust(width - 4) + " |" for l in body]
    lines.append(top)
    return "\n".join(lines)


def _wrap(text: str, width: int, indent: str) -> str:
    words, lines, cur = text.split(), [], ""
    for w in words:
        if cur and len(cur) + 1 + len(w) > width:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}" if cur else w
    if cur:
        lines.append(cur)
    return ("\n" + indent).join(lines)


# --------------------------------------------------------------------------
# collectors: macOS
# --------------------------------------------------------------------------

_I1PROFILER_APP_GLOBS = [
    "/Applications/i1Profiler/i1Profiler.app",
    "/Applications/i1Profiler.app",
    "/Applications/X-Rite/i1Profiler/i1Profiler.app",
    "/Applications/*/i1Profiler.app",
    "/Applications/*/*/i1Profiler.app",
]


def i1profiler_version_macos() -> tuple:
    """(version string or None, path or None). Reads only the app's Info.plist."""
    for pattern in _I1PROFILER_APP_GLOBS:
        for app in sorted(glob.glob(pattern)):
            plist = os.path.join(app, "Contents", "Info.plist")
            try:
                with open(plist, "rb") as fh:
                    info = plistlib.load(fh)
            except Exception:                             # noqa: BLE001
                continue
            version = info.get("CFBundleShortVersionString") or info.get("CFBundleVersion")
            return (str(version) if version else None), app
    return None, None


def version_tuple(text) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", str(text or ""))[:3])


def i1profiler_version_note(version) -> str:
    if not version:
        return ""
    if version_tuple(version) >= (3, 8, 7):
        return ("This i1Profiler version is 3.8.7 or newer, which no longer supports "
                "the i1Pro 2 or the i1iO 2. With those, use 3.8.6 or older.")
    return "3.8.6 or older: still supports the i1Pro 2 and the i1iO 2. Do not update it."


def collect_macos() -> None:
    section("macOS: USB device tree (JSON, SPUSBHostDataType)",
            run_cached(["system_profiler", "-json", "SPUSBHostDataType"], timeout=90))
    legacy = run_cached(["system_profiler", "-json", "SPUSBDataType"], timeout=90)
    legacy_devices = parse_system_profiler_json(legacy)
    if legacy_devices:
        section("macOS: USB device tree (JSON, older name SPUSBDataType)", legacy)
    else:
        section("macOS: USB device tree (JSON, older name SPUSBDataType)",
                "[empty on this macOS version; SPUSBHostDataType above has the data]")

    # ioreg carries the descriptor detail system_profiler leaves out, and the
    # parent/child topology that shows the i1Pro hanging off the table's hub.
    iousb = run_cached(["ioreg", "-p", "IOUSB", "-l", "-w", "0"], timeout=90)
    section("macOS: ioreg USB properties", iousb)

    # The service plane holds each device's interfaces and which software has
    # them open. Only the X-Rite devices' branches are kept.
    service = run_cached(["ioreg", "-l", "-w", "0", "-r", "-c", "IOUSBHostDevice"],
                         timeout=90)
    section("macOS: USB description of the X-Rite devices (registry only, device "
            "never opened)", describe_xrite_usb(iousb, service))
    branches = []
    for node, sub in xrite_subtrees(service):
        branches.append(node["line"])
        branches.extend(n["line"] for n in sub)
    if branches:
        raw = []
        keep = False
        for line in service.splitlines():
            if _IOREG_NODE_RE.match(line):
                keep = line in branches
            if keep:
                raw.append(line)
        section("macOS: ioreg service plane, X-Rite devices only", "\n".join(raw[:1500]))

    xrite = "/Library/Application Support/X-Rite"
    if os.path.isdir(xrite):
        # The per-device plugin plists carry the USB IDs and device names, and
        # they sit about 8 levels down inside the framework bundle.
        listing = run(["find", xrite, "-maxdepth", "12", "-name", "Info.plist"])
        section("macOS: X-Rite Info.plist files present", listing)
        for path in listing.splitlines():
            path = path.strip()
            if not path or path.startswith("["):
                continue
            if not any(k in path for k in ("i1Pro", "i1iO", "XRiteDevice")):
                continue
            section(f"macOS: plist: {path.replace(xrite, '<X-Rite>')}",
                    run(["plutil", "-p", path]))
    else:
        section("macOS: X-Rite support folder", "[not found. Is i1Profiler installed?]")

    version, app = i1profiler_version_macos()
    if version:
        section("macOS: i1Profiler version",
                f"{version}   ({app})\n{i1profiler_version_note(version)}")
    else:
        section("macOS: i1Profiler version",
                "[i1Profiler.app not found in /Applications. If you use it, the "
                "operator answers below say which version.]")


# --------------------------------------------------------------------------
# collectors: Linux
# --------------------------------------------------------------------------

def collect_linux() -> None:
    section("Linux: lsusb (all devices)", run(["lsusb"]))
    # The verbose dump is the single most valuable thing on any platform:
    # full configuration, interface and endpoint descriptors.
    section("Linux: lsusb -v for X-Rite devices",
            "\n".join(run(["lsusb", "-v", "-d", f"{v:04x}:"], timeout=60)
                      for v in XRITE_VIDS))
    section("Linux: USB topology", run(["lsusb", "-t"]))

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
            if vid.lower() not in [f"{v:04x}" for v in XRITE_VIDS]:
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
    section("Linux: sysfs attributes for X-Rite devices",
            "\n".join(lines) or "[no X-Rite devices found in sysfs]")

    section("Linux: kernel messages mentioning USB/FTDI",
            run(["bash", "-c", "dmesg 2>/dev/null | grep -iE 'usb|ftdi' | tail -60"]))


# --------------------------------------------------------------------------
# collectors: Windows
# --------------------------------------------------------------------------

def windows_is_arm() -> bool:
    return platform.machine().upper() in ("ARM64", "AARCH64")


# 1.5.4: worded as far as the evidence goes. Nobody has said there is no
# such driver; we know of none, and no X-Rite statement mentions ARM.
WINDOWS_ARM_NOTE = """\
  This Windows runs on an ARM processor (that includes a Windows virtual
  machine on an Apple Silicon Mac). We know of no X-Rite driver for the
  i1iO or the i1Pro 2 on Windows on ARM, so i1Profiler most likely cannot
  talk to the table here. The recorder this tool uses (USBPcap) does not
  exist for ARM processors either. For a recording, please use a Windows
  PC with an Intel or AMD processor."""


def collect_windows() -> None:
    ps = shutil.which("powershell") or shutil.which("pwsh")
    if not ps:
        section("Windows", "[PowerShell not found, cannot list USB devices]")
        return

    def psrun(script: str) -> str:
        return run([ps, "-NoProfile", "-NonInteractive", "-NoLogo", "-Command",
                PS_PREFIX + script], timeout=60)

    section("Windows: X-Rite USB devices", psrun(PS_XRITE_DEVICES))
    section("Windows: device properties (hardware + driver)", psrun(PS_DEVICE_PROPERTIES))
    section("Windows: all USB controllers/hubs (topology context)", psrun(PS_USB_HUBS))
    section("Windows: X-Rite driver files", psrun(PS_DRIVER_FILES))
    if windows_is_arm():
        section("Windows: processor", WINDOWS_ARM_NOTE)
    section("Windows: note",
            "For full endpoint descriptors on Windows the free tool USBTreeView "
            "(uwe-sieber.de) gives much more detail than PowerShell can. If you "
            "are willing, run it, select the X-Rite device (the i1iO or the "
            "instrument), and paste its report too.")


# --------------------------------------------------------------------------
# collector: i1Profiler iO chart metadata (all platforms)
# --------------------------------------------------------------------------
#
# i1Profiler ships instrument-specific test charts. The iO variants use a much
# denser, robot-oriented layout than the handheld i1Pro, and knowing their
# parameters (patch counts, and any patch-size / gap figures the help files
# state) would help design a matching layout in ChromIQ.
#
# IMPORTANT: we report METADATA ABOUT these files (names, sizes, patch counts,
# and short factual number snippets), never their contents. We do not copy or
# reproduce X-Rite's chart data. That keeps this to plain fact-finding.

_I1PROFILER_ROOTS = [
    "/Library/Application Support/X-Rite/i1Profiler",          # macOS
    r"C:\ProgramData\X-Rite\i1Profiler",                       # Windows (usual)
    r"C:\Users\All Users\X-Rite\i1Profiler",                   # Windows (legacy)
    os.path.expanduser("~/Library/Application Support/X-Rite/i1Profiler"),
]

_I1PROFILER_HELP_ROOTS = [
    "/Applications/i1Profiler/i1Profiler.app/Contents/Resources/Help",
    r"C:\Program Files\X-Rite\i1Profiler\Help",
    r"C:\Program Files (x86)\X-Rite\i1Profiler\Help",
]

_TARGET_RE = re.compile(r'ObjectType\s*=\s*"Target"')
_GEOM_SNIPPET_RE = re.compile(
    r"[^\n<>]{0,40}?\b\d[\d.,]*\s?(?:mm|millimet|patch|patches|row|rows|"
    r"column|columns|gap)s?\b[^\n<>]{0,40}",
    re.IGNORECASE,
)


def _find_i1profiler_root():
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


# 1.5.1: "io" as a bare substring also matched "Studio", "option" and
# "iteration" in a user's own chart names and tagged them as iO charts. The
# iO is named "i1iO", "iO2"/"iO3" or "iO" as a word in X-Rite's chart names.
_IO_CHART_RE = re.compile(r"i1io|(?<![a-z])io(?![a-z])|(?<![a-z])io[23](?![a-z0-9])",
                          re.IGNORECASE)


def is_io_chart_name(name: str) -> bool:
    return bool(_IO_CHART_RE.search(name))


def collect_i1profiler_charts() -> None:
    """Report iO-specific chart metadata (never the chart contents)."""
    root = _find_i1profiler_root()
    if root is None:
        section("i1Profiler charts",
                "[i1Profiler chart folder not found. This section only has "
                "something to report on a machine with i1Profiler installed.]")
        return

    rows: list = []
    io_seen = False
    capped = False
    for dirpath, _dirs, files in os.walk(root):
        for name in sorted(files):
            if not name.lower().endswith(".txf"):
                continue
            low = name.lower()
            is_io = is_io_chart_name(name)
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
            if len(rows) >= 300:
                capped = True
                break
        if capped:
            break
    header = ("i1Profiler test charts (patch counts only, no chart data copied)."
              "\nThe iO charts pack far more patches per sheet than the handheld"
              "\ni1Pro, which is the clearest signal of how different the layouts are."
              "\nCharts tagged 'iO SCAN mode' are the strip-scan variant, distinct"
              "\nfrom the spot variant: useful evidence the iO reads two ways.\n")
    if capped:
        rows.append("... (list capped at 300 charts)")
    section("i1Profiler: instrument test charts",
            header + "\n".join(rows) if rows else header + "[no chart files found]")

    if not io_seen:
        section("i1Profiler: iO charts",
                "[no iO-specific charts found. The installation may not include "
                "the iO workflow, which is itself a useful data point.]")

    snippets: list = []
    seen: set = set()
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
                text = re.sub(r"<[^>]+>", " ", text)
                for m in _GEOM_SNIPPET_RE.finditer(text):
                    frag = " ".join(m.group(0).split())
                    if frag and frag not in seen:
                        seen.add(frag)
                        snippets.append(f"[{name}] ...{frag}...")
                        if len(snippets) >= 60:
                            break
            if len(snippets) >= 60:
                break
        if len(snippets) >= 60:
            break
    section("i1Profiler: iO geometry hints from help files",
            "\n".join(snippets) if snippets
            else "[no iO help files with dimension text found]")


# --------------------------------------------------------------------------
# summary: the part a human reads first
# --------------------------------------------------------------------------

_DETECTION: dict = {}


def windows_summary_lines(out: str) -> tuple:
    """1.5.1: 'name :: instance :: True/False' lines -> (display lines, the
    (vid, pid) plugged in now). Windows remembers every instrument it has
    ever seen, once per USB socket; 1.5.0 listed those memories as if they
    were connected, and could pick the session from one of them."""
    lines, present = [], []
    for raw in (out or "").splitlines():
        raw = raw.strip()
        if not raw or raw.startswith("["):
            continue
        parts = [p.strip() for p in raw.split(" :: ")]
        is_here = None
        if len(parts) >= 3 and parts[-1].lower() in ("true", "false"):
            is_here = parts[-1].lower() == "true"
            parts = parts[:-1]
        text = " :: ".join(parts)
        m = _INSTANCE_IDS_RE.search(text)
        # 1.5.3: the note on a line of its own; after the name and the
        # instance path it ran past 80 columns and wrapped mid-word.
        if is_here is False:
            text += "\n    (not plugged in now; Windows remembers it from before)"
        elif is_here and m:
            text += "\n    (plugged in now)"
            key = (int(m.group(1), 16), int(m.group(2), 16))
            if key not in present:
                present.append(key)
        lines.append(text)
    return lines, present


def quick_summary() -> str:
    """Best-effort 'did we even see the table' answer, per platform."""
    found: list = []
    system = platform.system()
    try:
        if system == "Darwin":
            result = macos_detection()
            _DETECTION.clear()
            _DETECTION.update(result)
            return format_detection(result)
        if system == "Linux":
            for line in run(["lsusb"]).splitlines():
                if any(f"{v:04x}:" in line.lower() for v in XRITE_VIDS):
                    found.append(line.strip())
        elif system == "Windows":
            ps = shutil.which("powershell") or shutil.which("pwsh")
            if ps:
                out = run([ps, "-NoProfile", "-NonInteractive", "-NoLogo", "-Command",
                           PS_SUMMARY])
                found, present = windows_summary_lines(out)
                _DETECTION.clear()
                _DETECTION["present_ids"] = present
    except Exception as exc:                              # noqa: BLE001
        return f"[summary failed: {exc}]"

    if not found:
        return ("NO X-RITE DEVICES SEEN.\n"
                "Is it switched on and plugged in? Step 3 can look again.")
    text = "X-Rite devices detected:\n  " + "\n  ".join(found)
    if system == "Windows" and "present_ids" in _DETECTION and not _DETECTION["present_ids"] \
            and any("(not plugged in now" in f for f in found):
        # 1.5.3: short enough for an 80-column window; step 3 can look again.
        text += "\nNone of them is plugged in right now. Step 3 can look again."
    return text


# --------------------------------------------------------------------------
# stage 2: timed walkthrough
# --------------------------------------------------------------------------

CAPTURE_HELP = {
    "Linux": """\
  1. sudo modprobe usbmon
  2. Find the bus number of the i1iO from the 'lsusb' output above.
  3. In a second terminal:  sudo tcpdump -i usbmon<BUS> -w io-capture.pcap
  4. Come back here and follow the prompts.
  5. Stop tcpdump with Ctrl-C when this tool says you are done.""",
    "Windows": """\
  1. Install Wireshark from wireshark.org. When its installer offers
     "USBPcap", tick it. Restart Windows afterwards.
  2. Start Wireshark. Its list shows entries named USBPcap1, USBPcap2 and
     so on. If you do not know which one the table is on, select all of
     them (hold Ctrl and click each one) and start recording.
     If the gear icon next to a USBPcap entry shows "Inject already
     connected devices descriptors into capture data", leave it ticked:
     it adds the table's full USB description to the recording.
  3. Come back here and follow the prompts.
  4. When this tool says you are done, stop Wireshark and save the
     recording (File > Save As; the default pcapng format is fine).

  Which Windows works: the X-Rite driver for the i1Pro 2 and the i1iO 2
  needs Windows 10 with i1Profiler 3.8.5, or Windows 11 version 24H2 or
  older with i1Profiler 3.8.6. X-Rite says the driver is blocked on
  Windows 11 version 25H2 and newer.""",
}

# 1.5.4: the steps for the NEXT i1iO recording.
#
# The first two real recordings (issue #129) already hold the connection,
# the hand alignment of the three corners and the row scans. These steps ask
# for what they lack, ordered by how much each one teaches us, so that a
# tester who stops after the first one or two has still given the most
# useful part. All in ONE round, because on a Mac every round costs the
# tester two restarts with SIP switched off.
# 1.5.4, later the same day: i1Profiler's own help says that a row it cannot
# read is read again more slowly and then patch by patch. So the first
# recordings (three scans and then spots on EVERY row) most likely show that
# fallback: scanning failed on every row of that chart. A NORMAL scan, one
# pass per row, has not been recorded yet; step 1 asks for it, with a chart
# i1Profiler reads in one pass. The earlier chart gets one optional step at
# the end, because it is printed already and costs only a minute.
#   1. One row of a chart i1Profiler reads in one pass, with the
#      calibration, the operator
#      marking when the arm starts along the row (a), when the lamp lights
#      (l) and when the head goes down and up (d, u), then Cancel while the
#      arm moves along the second row. The marks separate the table from the
#      instrument: the recordings showed that the table seems to WAIT for
#      the instrument (when i1Profiler started the i1Pro later after the
#      scan move, the table finished later by the same amount, with nothing
#      sent to the table in between), and that c3 / c4 / d1 are not
#      understood (nothing may lower the head in a test build until they
#      are). The calibration keeps the UV LED's calibration on the table's
#      tile in the recording, and the cancel shows how a job is stopped.
#   2. A few patches in spot mode, if i1Profiler offers it: head marks again,
#      and a spot-only job.
#   3. A small chart measured to the end with the FASTEST setting i1Profiler
#      offers: the normal end where the arm parks by itself, other
#      coordinates, and (with the ruler measurement afterwards) the unit of
#      length. One fast pass per row already held every patch in the first
#      recordings, while i1Profiler took 58 s per row.
#   4. One row with dual scan (M1 or M2), if offered: the recording can show
#      only what crosses the cable (the instrument settings of each pass);
#      the M1 / M2 arithmetic most likely happens inside i1Profiler.
#   5. One row of the earlier chart, optional: the fallback once more.
# Left out on purpose:
#   * Holding the arm back by hand, removing the instrument from the arm, or
#     blocking the calibration, to see an error; and whether the table moves
#     without the instrument measuring. We cannot know that this is harmless
#     for the table's motor and belt, and i1Profiler offers no way to test
#     it; the tester's hardware matters more than the answer.
#   * Switching the table off with the arm out on the chart: the first
#     recordings already show the start-up path from away from home.
#   * Lowering or lifting the head on its own: we know of no way to do that
#     in i1Profiler; the questions at the end ask whether there is one.
# A step is a dict; adding one needs no other change. "optional": a step
# that depends on what i1Profiler offers; skipping it is not "missing".
# The tool still never sends anything to the table: these are things the
# tester does in i1Profiler while the recording runs.
IO_STEPS = [
    {"key": "row",
     "title": "One row of a chart that scans in one pass",
     "prepare": """\
  Use a chart that i1Profiler should read in one pass per row: one of
  the test charts for the i1iO that come with i1Profiler (for example
  "default-i1iO"), freshly printed, or a chart you know scans normally.
  (i1Profiler's help says that when it cannot scan a row, it reads the
  row again more slowly and then patch by patch; that is most likely
  what happened with your earlier chart.) Set up the measurement up to
  the point just before you press Measure.""",
     "do": """\
  Press Measure and let it calibrate as usual, then align the three
  corners. Watch the FIRST row closely and type a letter and Enter here
  the moment you see it:
     a = the arm starts moving along the row
     l = the instrument's lamp lights up (if you can see it)
     d = the head goes down,  u = the head lifts
  When the arm starts along the SECOND row, press Cancel in i1Profiler
  and wait until the arm stands still. If the arm goes along the first
  row more than once, that is fine: carry on and say so afterwards.""",
     "arm": "When the arm started along the row, was the lamp already on? What "
            "did the head do? Was the row read once? What happened after Cancel?",
     "marks": True},
    {"key": "spot",
     "title": "A few patches in spot mode, watching the head",
     "optional": True,
     "prepare": """\
  If i1Profiler offers to measure patch by patch (often called spot
  mode) for the table, choose it and set up the measurement with the
  chart from step 1, up to just before Measure. If it does not, type  s
  to skip this step.""",
     "do": """\
  Press Measure, align the three corners, and let it measure about 5
  patches. Type  d  and Enter each time the head goes DOWN onto the
  paper, and  u  and Enter each time it LIFTS. Then press Cancel and
  wait until the arm stands still.""",
     "arm": "What did the head do on each patch? Which setting did you use?",
     "marks": True},
    {"key": "fast",
     "title": "A small chart to the end, fastest setting",
     "prepare": """\
  Place the SMALL chart (two rows, 10 to 20 patches) somewhere
  other than last time, for example near the right or the bottom edge of
  the area the arm can reach. In i1Profiler choose the FASTEST way it
  offers for the table (for example a single scan, with no extra checking
  or averaging).""",
     "do": """\
  Press Measure, align the three corners, and let it measure the whole
  chart. Please do not cancel: let the arm park by itself at the end,
  and wait until it stands still.""",
     "arm": "What did the arm do at the end, and where did it stop? Which "
            "setting did you choose?"},
    {"key": "dual",
     "title": "One row with dual scan (M1 or M2)",
     "optional": True,
     "prepare": """\
  If i1Profiler offers dual scan, or the measurement condition M1 or M2,
  for the table, choose it, with the chart from step 1. If it does not, type
  s  to skip this step. (Good to know: the recording shows only what
  travels over the cable. i1Profiler most likely does the M1 or M2
  arithmetic itself, so we will see how the instrument is asked to
  measure, not the result. It is still worth this one step.)""",
     "do": """\
  Press Measure (it may calibrate again), align the three corners, and
  let it measure the FIRST row. When the arm starts along the second
  row, press Cancel and wait until the arm stands still.""",
     "arm": "What did the arm do this time? Was anything different from the "
            "first step? Which setting did you choose?",
     "marks": True},
    {"key": "earlier",
     "title": "One row of your earlier chart",
     "optional": True,
     "prepare": """\
  Only if you still have the chart from your first recordings printed:
  place it, with your usual settings. Otherwise type  s  to skip this
  step. It shows us once more what i1Profiler did with this chart.""",
     "do": """\
  Press Measure, align the three corners, and let it work on the FIRST
  row until it moves on to the second row. Then press Cancel and wait
  until the arm stands still.""",
     "arm": "Was the first row again read three times and then patch by patch?"},
]

# Asked after the steps, with no recording running. They prove the unit of
# length (a ruler against the corner positions the table reports) and tell
# which i1Profiler setting gave the "three scans, then patch by patch" rows
# seen in the first recordings.
IO_QUESTIONS = [
    ("chart files",
     "If i1Profiler can save them (a .pxf or .txf file, or the workflow),\n"
     "     please save the chart of step 1, the small chart of step 3 and your\n"
     "     earlier chart, and send them with the recording. Their file names?"),
    ("paper size", "Which paper size was the small chart printed on (for example A4)?"),
    ("ruler",
     "Please measure the first row of the small chart with a ruler: from the\n"
     "     left edge of its first patch to the right edge of its last patch, in\n"
     "     millimetres, and count its patches (for example: 190 mm, 20 patches)."),
    ("settings",
     "The i1Profiler settings you used in steps 1 and 3, and your usual ones\n"
     "     if different: the measuring mode (single scan, dual scan or spot),\n"
     "     the measurement condition (M0, M1 or M2), any accuracy or averaging\n"
     "     option, and the patch size."),
    ("earlier chart",
     "Your earlier chart: was every row always read three times and then\n"
     "     patch by patch, also on other days?"),
    ("sheet hold",
     "Does your table have a way to hold the sheet flat (for example a\n"
     "     button on the base plate)? Do you use it?"),
    ("errors",
     "When something goes wrong, what does the table do or show (a light,\n"
     "     a sound, a message in i1Profiler)?"),
    ("head control",
     "Does i1Profiler have a button or menu that lowers or lifts the head on\n"
     "     its own, without measuring? If yes, where is it?"),
]


# 1.5.4: everything to have ready BEFORE the recording, so a tester on a
# Mac does it all in one round with SIP switched off. Shown once before the
# recording starts, and in --rehearse.
IO_READY_LIST = [
    "i1Profiler is open and has found the table (for an i1iO 2: version "
    "3.8.6 or older).",
    "A chart that i1Profiler reads in one pass per row is printed (for "
    "example one of its own test charts for the i1iO). Steps 1, 2 and 4 use it.",
    "A SMALL chart is printed: two rows (i1Profiler may not allow a single "
    "row on the table), 10 to 20 patches, on any paper size. Step 3 uses it.",
    "If you still have it: the chart of your first recordings (step 5).",
    "You know where i1Profiler offers spot mode, its fastest setting, and "
    "dual scan or M1 / M2 for the table (if it offers them).",
    "You know where i1Profiler lets you save the charts (a chart file or "
    "the workflow), so you can send them.",
    "A ruler is at hand (millimetres).",
    "You know your usual settings: measuring mode (single scan, dual scan "
    "or spot), measurement condition (M0, M1 or M2), any accuracy or "
    "averaging option, and the patch size.",
    "About 30 minutes without interruption.",
]


def io_ready_text() -> str:
    lines = ["  HAVE YOU GOT EVERYTHING READY?"]
    for item in IO_READY_LIST:
        lines.append("    [ ] " + _wrap(item, 60, " " * 8))
    return "\n".join(lines)


def io_summary_table(rows: list) -> list:
    """rows: (step title, recorded: bool or None for skipped, commands, moving).
    The end-of-session table and one plain line on what is missing."""
    out = ["THE STEPS AT A GLANCE",
           f"  {'step':40} {'recorded':9} {'table commands'}"]
    missing = []
    seen_titles = {}
    numbers = {s["title"]: i for i, s in enumerate(IO_STEPS, 1)}
    for title, recorded, n, moving in rows:
        base = io_step_title(title)
        take = re.search(r"\(take (\d+)\)$", title)
        label = (f"{numbers.get(base, '?')}. " + (f"(take {take.group(1)}) " if take else "")
                 + base)
        if len(label) > 40:
            label = label[:39] + "."
        if recorded is None:
            optional = any(s["title"] == base and s.get("optional") for s in IO_STEPS)
            out.append(f"  {label:40} {'skipped':9} -")
            if optional:
                out.append("     (fine if i1Profiler does not offer it)")
            seen_titles.setdefault(base, False)
            continue
        ok = n > 0 and moving > 0
        out.append(f"  {label:40} {'yes':9} {n}")
        if n == 0:
            out.append("     <-- no table command: please repeat")
        elif moving == 0:
            out.append("     <-- none that moves the arm: if the arm moved, please repeat")
        seen_titles[base] = seen_titles.get(base, False) or ok
    for step in IO_STEPS:
        if not seen_titles.get(step["title"]) and not step.get("optional"):
            missing.append(step["title"])
    if missing:
        which = "that step" if len(missing) == 1 else "those steps"
        out.extend(_wrap("Still missing: " + "; ".join(missing) + ". If you can, run the "
                         "tool again now, while SIP is still off (on a Mac), and do only "
                         f"{which} (type  s  to skip the others).", 66, "").split("\n"))
    else:
        out.extend(_wrap("Nothing important is missing: every step recorded commands to "
                         "the table. Thank you!", 66, "").split("\n"))
    return out


IO_MARK_KEYS = {"d": "head down", "down": "head down", "u": "head up", "up": "head up",
                "a": "arm starts moving", "l": "lamp lights up"}


def _io_step_header(number: int, total: int, title: str) -> None:
    print("\n" + "-" * 68)
    print(f"  STEP {number} of {total}: {title}")
    print("-" * 68)


def _ask_choice(prompt: str, allowed: tuple, on_end: str = "") -> str:
    """ask() until the answer is one of the allowed ones ("" = Enter).
    1.5.4 review: a stray letter or a second Enter must never start or end
    a step while the arm is moving."""
    while True:
        answer = ask(prompt, interruptible=True).strip().lower()
        if not answer and _INPUT_ENDED:
            return on_end               # no more input: stop instead of asking for ever
        for choice in allowed:
            if answer == choice or (choice and answer == choice[0]):
                return choice
        print("    (not one of the choices; please type it again)")


IO_END_WORDS = ("e", "end", "done")


def run_io_steps(steps: list, t0: float, log: list, check=None,
                 record: list | None = None, rehearse: bool = False,
                 on_change=None) -> str:
    """Walk the i1iO steps, one at a time.

    Each step: what to prepare, Enter to start, what to do, then  e  and
    Enter to end it (with letter marks on the way: a, l, d, u), one line on
    what the arm did, then the check, and the choice to do it again. The
    recording itself runs for the whole session (the table and i1Profiler
    keep talking between steps, and a line cut in two is unreadable), so a
    step is a pair of time marks in it.

    A step ends only with  e  (a plain Enter does nothing), and a step starts
    only with Enter, so a stray key or a double Enter cannot cut a step short
    or start the next one while the arm still moves.

    log: the report lines, appended to as each step finishes; on_change() is
    called after every change, so the caller can keep the report up to date
    and a Ctrl-C or a closed window keeps every finished step (a step cut
    short by Ctrl-C is logged as interrupted). check(start, end): what the
    recording shows for the step, or None. record: gets one dict per step.
    Returns how the walk ended."""
    record = [] if record is None else record
    changed = on_change or (lambda: None)
    total = len(steps)
    index, take = 0, 1
    while index < total:
        step = steps[index]
        title = step["title"] + (f" (take {take})" if take > 1 else "")
        _io_step_header(index + 1, total, title)
        print("  GET READY:")
        print(step["prepare"])
        print()
        print("  THEN:")
        print(step["do"])
        answer = _ask_choice("\n  (Click into this window first if you were in i1Profiler.)\n"
                             "  Press Enter to START this step, or type  s  to skip it,\n"
                             "  or  q  to stop here: ", ("", "skip", "quit"),
                             on_end="quit")
        if answer == "quit":
            log.append(f"stopped by the operator before: {step['title']}")
            changed()
            return "stopped by the operator"
        if answer == "skip":
            log.append(f"{title}: SKIPPED")
            record.append({"title": title, "skipped": True})
            changed()
            print("  Skipped.")
            index += 1
            take = 1
            continue
        start = time.time()
        print("\n  " + ("REHEARSAL: nothing is recorded. " if rehearse else "")
              + f"STEP {index + 1} STARTED. Do it in i1Profiler now.")
        if step.get("marks"):
            print("  Letters: a = arm starts moving, l = lamp lights up, d = head down,")
            print("  u = head lifts; anything else you type is kept as a note.")
        print("  After clicking in i1Profiler, click once into this window again")
        print("  before you type, so your keys land here and not in i1Profiler.")
        print("  When the step is finished, type  e  and press Enter.")
        marks = []
        try:
            while True:
                typed = ask("  > ", interruptible=True).strip()
                now = time.time()
                if not typed:
                    if _INPUT_ENDED:
                        break
                    print("    (still running: type  e  and Enter when the step is finished)")
                    continue
                low = typed.lower()
                if low in IO_END_WORDS:
                    break
                what = IO_MARK_KEYS.get(low, f"note: {typed}")
                marks.append((what, now))
                print(f"    noted at {now - start:.1f} s: {what}")
        except KeyboardInterrupt:
            now = time.time()
            log.append(f"{title}: t={start - t0:8.3f}s .. {now - t0:8.3f}s   (interrupted)")
            for what, when in marks:
                log.append(f"  mark: {what} at t={when - t0:8.3f}s")
            record.append({"title": title, "start": start, "end": now, "marks": marks,
                           "interrupted": True})
            changed()
            raise
        end = time.time()
        flat = " ".join(step["do"].split())
        log.append(f"{title}: t={start - t0:8.3f}s .. {end - t0:8.3f}s   ({flat})")
        for what, when in marks:
            log.append(f"  mark: {what} at t={when - t0:8.3f}s")
        entry = {"title": title, "start": start, "end": end, "marks": marks}
        record.append(entry)
        changed()
        arm = ask("\n  " + _wrap(f"In one line: {step['arm']}", 66, "  ")
                  + "\n  (Enter to skip)\n  > ",
                  interruptible=True).strip()
        if arm:
            log.append(f"  arm: {arm}")
            entry["arm"] = arm
            changed()
        verdict = None
        if rehearse:
            print("\n  (Rehearsal: nothing was recorded, so there is nothing to check.)")
        elif check is not None:
            try:
                verdict = check(start, end)
            except Exception as exc:                      # noqa: BLE001
                verdict = None
                log.append(f"  check: could not be made ({exc})")
            if verdict:
                print("\n  CHECK: " + _wrap(verdict + ".", 64, "  "))
                log.append(f"  check: {verdict}")
                entry["check"] = verdict
            changed()
        again = _ask_choice("\n  Press Enter to go on, type  r  to do this step again"
                            + ("" if rehearse else " (the recording\n  keeps both tries)")
                            + ", or  q  to stop here: ", ("", "repeat", "quit"))
        if again == "quit":
            log.append("stopped by the operator after: " + title)
            changed()
            return "stopped by the operator"
        if again == "repeat":
            take += 1
            continue
        index += 1
        take = 1
    return "all steps done"


def ask_io_questions(log: list) -> None:
    """The questions that need no recording; the answers go into the report."""
    print("\n" + "-" * 68)
    print("  LAST: A FEW QUESTIONS (nothing is recorded now)")
    print("-" * 68)
    print("  Just press Enter to skip any of them (Ctrl-C is switched off here,")
    print("  so that nothing recorded is lost).\n")
    for n, (key, question) in enumerate(IO_QUESTIONS, 1):
        answer = ask(f"  {n}. {question}\n     > ").strip()
        log.append(f"{key}: {answer or '[no answer]'}")


def io_steps_overview(steps: list) -> list:
    lines = [f"  WHAT YOU WILL DO ({len(steps)} short steps, about 30 minutes, then a few "
             "questions)"]
    for i, s in enumerate(steps, 1):
        lines.append(f"    {i}. {s['title']}")
    lines += ["  The first step is the most useful one. You can skip a step, do it",
              "  again, or stop after any step: the steps you finished are kept.",
              "  Steps 2, 4 and 5 depend on what i1Profiler offers and what you have;",
              "  skip them if not. You need: the table with the i1Pro on it,",
              "  i1Profiler, a chart it reads in one pass, and a small chart of two",
              "  rows."]
    return lines


def rehearse_io() -> int:
    """--rehearse: walk the i1iO steps without recording anything, so a
    tester can see them before switching SIP off, and we can test them."""
    print("=" * 68)
    print("  ChromIQ X-Rite instrument probe " + PROBE_VERSION + ": REHEARSAL")
    print("=" * 68)
    print()
    print("  This walks through the i1iO recording steps WITHOUT recording")
    print("  anything and without saving anything. Nothing is sent to the table.")
    print("  Use it to see the steps before the real recording.")
    print()
    print("\n".join(io_steps_overview(IO_STEPS)))
    print()
    print(io_ready_text())
    run_io_steps(IO_STEPS, time.time(), [], rehearse=True)
    print("\n" + "-" * 68)
    print("  At the end of the real recording, the tool asks these questions:")
    for n, (_key, question) in enumerate(IO_QUESTIONS, 1):
        print(f"  {n}. {question}")
    print()
    print("  That was the rehearsal. For the real recording, run the tool again")
    print("  and choose 1 (the i1iO table); on a Mac, SIP must be switched off")
    print("  first, and the tool says how.")
    return 0


IO3_UNCHECKED = ("the recording holds {n} packets from the i1iO 3. Its protocol is not "
                 "known yet, so this step cannot be checked here: please just carry on")


def is_io3_record(data: bytes) -> bool:
    """A macOS record of the i1iO 3 (0765:30B0, from X-Rite's driver file)."""
    return len(data) >= _DARWIN_HDR and struct.unpack("<HH", data[0x24:0x28]) == (0x0765, 0x30B0)


class IoLiveReader:
    """While the recording runs: what the recording so far shows for one
    step. Reads only what tcpdump appended since the last look (tcpdump
    writes every packet at once with -U), keeps only the X-Rite records, and
    never touches a device. 1.5.4 review: reading every full file again
    after each step could need gigabytes on a busy USB bus; and a recorder
    that has died must be named, not reported as "please repeat"."""

    def __init__(self, files: dict, procs: dict | None = None):
        self.files = dict(files)            # name -> path
        self.procs = dict(procs or {})      # name -> Popen (or anything with poll())
        self.state = {name: {"off": 0, "endian": None, "link": None, "nano": False,
                             "recs": []} for name in self.files}

    def _read_new(self, name: str) -> None:
        st = self.state[name]
        with open(self.files[name], "rb") as fh:
            if st["endian"] is None:
                head = fh.read(24)
                if len(head) < 24:
                    return
                magic = head[:4]
                if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
                    st["endian"] = "<"
                elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
                    st["endian"] = ">"
                else:
                    raise ValueError("not a pcap file")
                st["nano"] = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
                st["link"] = struct.unpack(st["endian"] + "I", head[20:24])[0]
                st["off"] = 24
            fh.seek(st["off"])
            blob = fh.read()
        e, off = st["endian"], 0
        while off + 16 <= len(blob):
            ts_s, ts_u, incl, _orig = struct.unpack(e + "IIII", blob[off:off + 16])
            if off + 16 + incl > len(blob):
                break                                    # still being written
            data = blob[off + 16:off + 16 + incl]
            if st["link"] != LINKTYPE_USB_DARWIN or _darwin_vid(data) in XRITE_VIDS:
                st["recs"].append((ts_s + ts_u / (1e9 if st["nano"] else 1e6), data))
                if st["link"] == LINKTYPE_USB_DARWIN and is_io3_record(data):
                    st["io3"] = st.get("io3", 0) + 1
            off += 16 + incl
        st["off"] += off

    def check(self, start: float, end: float) -> str | None:
        lines, table_on, unreadable, waiting = [], [], [], []
        for name in self.files:
            try:
                if os.path.getsize(self.files[name]) < 24:
                    waiting.append(name)
                    continue
            except OSError:
                pass
            try:
                self._read_new(name)
            except (OSError, ValueError, struct.error):
                unreadable.append(name)
                continue
            st = self.state[name]
            if not st["recs"]:
                continue
            events = capture_events(st["link"], st["recs"])
            keys = io_table_keys(events, device_map(events))
            if keys:
                table_on.append(name)
                lines += io_table_lines(events, keys)
        io3 = sum(self.state[n].get("io3", 0) for n in self.files)
        dead = [n for n, p in self.procs.items() if p is not None and p.poll() is not None]
        watch = [n for n in (table_on or list(self.files)) if n in dead]
        if watch:
            return (f"the recording on {', '.join(watch)} has stopped, so nothing more is "
                    "being recorded. Please type  q  now, and start the tool again for a "
                    "new recording")
        if not table_on and io3:
            return IO3_UNCHECKED.format(n=io3)
        if not table_on and (unreadable or waiting):
            return ("the recording could not be read just now, so this step was not checked "
                    "(the recording itself goes on)")
        if not table_on:
            return "no table command was recorded in this step: please repeat it"
        n, moving = io_count_commands(lines, start, end)
        return io_step_verdict(n, moving)


def io_live_check(paths, start: float, end: float) -> str | None:
    """One look at recording files, without a recorder to watch."""
    return IoLiveReader({p: p for p in paths}).check(start, end)



def annotate_session() -> None:
    """Windows and Linux: the user records; this tool times the steps."""
    system = platform.system()
    print("\n" + "=" * 68)
    print("STAGE 2: timed recording session")
    print("=" * 68)
    print("\nThis tool does not record anything itself here. You run the")
    print("recording program; this tool notes precise timestamps for each")
    print("action, so the recording can be sliced up afterwards. That is what")
    print("makes a recording useful instead of an unreadable blob.\n")
    if system == "Windows" and windows_is_arm():
        print(WINDOWS_ARM_NOTE + "\n")
    print("Set up your recording first:\n")
    print(CAPTURE_HELP.get(system, CAPTURE_HELP["Linux"]))
    print()
    print(I1PROFILER_WARNING)

    print("\n" + "-" * 68)
    print("\n".join(io_steps_overview(IO_STEPS)))
    print()
    print(io_ready_text())
    print("  The recording has to run for the whole time. This tool notes when")
    print("  each step starts and ends, so the recording can be read step by step.")
    print("-" * 68)

    if not said_yes(ask("\nIs the recording running? Shall I start the walkthrough? (yes / no): ")):
        print("\n  Skipping the walkthrough. That is absolutely fine.")
        print("  Your main report is unaffected and still worth sending.")
        print("  To do it another time, run this tool again and choose the")
        print("  recording step (or start it directly with  --annotate ).\n")
        section("Stage 2: timed recording",
                "[walkthrough skipped by operator, no recording running]")
        return
    io_timed_steps()
    _END["no_recording"] = ("The recording was made with another program (for example "
                            "Wireshark); please send that file together with this report.")
    print("\nStop your recording now and save the file.")
    print("Send BOTH the recording and this probe report.\n")


def io_log_header(t0: float) -> list:
    """The first lines of the step log. 1.5.4 adds the exact start as UTC
    epoch seconds (the same clock as the recording), so --analyze places
    every step exactly; 1.5.3 reports had only the local clock time."""
    local = datetime.datetime.fromtimestamp(t0).isoformat()
    return [f"session start (monotonic zero): {local}",
            f"session start (UTC epoch seconds): {t0:.3f}"]


def io_timed_steps(check=None, show_ready: bool = False) -> list:
    """The steps, timed, while someone else's recording runs (Wireshark on
    Windows, a hardware sniffer on a Mac). Returns the step records."""
    if show_ready:
        print()
        print(io_ready_text())
    t0 = time.time()
    log = io_log_header(t0)
    record: list = []
    try:
        log.append("walk: " + run_io_steps(IO_STEPS, t0, log, check=check, record=record))
    except KeyboardInterrupt:
        log.append("walkthrough ended early with Ctrl-C")
    notes = ask("\nAnything odd happen? (free text, Enter to skip): ")
    if notes:
        log.append(f"operator notes: {notes}")
    section("Stage 2: annotated capture timeline", "\n".join(log))
    answers: list = []
    ask_io_questions(answers)
    section("Stage 2: answers about the chart and the settings", "\n".join(answers))
    return record


# --------------------------------------------------------------------------
# stage 2 on macOS: guided recording with the system's own tcpdump
# --------------------------------------------------------------------------
#
# Only ever runs when the user typed "yes", and only when SIP is already off
# and macOS already shows XHC* interfaces. This tool never changes SIP. The
# privileged commands go through macOS's own `sudo`, which asks for the
# password itself; this program never sees or stores it.
#
# What it touches, and how it puts it back:
#   * `sudo ifconfig XHCn up` for each capture interface that was down, and
#     `sudo ifconfig XHCn down` for exactly those afterwards (in a finally
#     block, so also after Ctrl-C).
#   * `sudo tcpdump -U -i XHCn -w <file>` per interface, stopped with SIGTERM.
# We record every XHC interface: which bus the table is on is only a guess.

def _iface_is_up(ifconfig: str, iface: str) -> bool:
    out = run([ifconfig, iface], timeout=10)
    first = out.splitlines()[0] if out else ""
    return bool(re.search(r"[<,]UP[,>]", first))


def _writable_dir() -> str:
    for directory in candidate_dirs():
        if os.path.isdir(directory) and os.access(directory, os.W_OK):
            return directory
    return os.getcwd()


class _Hangup(Exception):
    pass


def _raise_hangup(_signum, _frame):
    raise _Hangup()


def macos_guided_recording(readiness: dict) -> None:
    sudo = shutil.which("sudo")
    ifconfig = shutil.which("ifconfig") or "/sbin/ifconfig"
    tcpdump = readiness["tcpdump"]
    interfaces = list(readiness["interfaces"])
    # The likely bus first, so its line is the first one people read.
    for guess in reversed(readiness.get("bus_guesses") or []):
        if guess in interfaces:
            interfaces.remove(guess)
            interfaces.insert(0, guess)
    outdir = _writable_dir()

    print(f"""
  HOW THE RECORDING WORKS

  1. macOS asks for your password (the one you use to log in to this
     Mac). It goes to macOS's own "sudo" command; this tool never sees or
     stores it. Nothing appears while you type; that is normal.
  2. The tool switches on the USB recording interfaces ({", ".join(interfaces)})
     and starts macOS's own tcpdump program on each of them. It only
     listens. It cannot move the arm.
  3. You do up to five short steps in i1Profiler (about 30 minutes). After
     each one the tool checks that the table's commands were recorded.
  4. The tool stops recording, switches the interfaces off again, checks
     the recording, and makes a copy that holds only the X-Rite traffic.
     Then it asks a few questions about the chart.

  Before you start: open i1Profiler and let it find the table.

  Please do not type anything private on a USB keyboard while it records:
  a recording holds everything on the same USB bus, and the tool records
  every bus because it cannot be sure which one the table is on. The copy
  you send contains only the X-Rite devices' traffic.

  It does not change System Integrity Protection; you switched that off
  yourself, and you switch it back on yourself afterwards.""")
    print()
    print(io_ready_text())
    if not said_yes(ask("\n  Start the recording now? (yes / no): ")):
        print("\n  No recording made. That is fine; your report is still useful.\n")
        section("Stage 2: macOS recording", "[recording possible, but declined by operator]")
        return
    if not sudo or not tcpdump:
        print("\n  sudo or tcpdump is missing, so no recording is possible.\n")
        section("Stage 2: macOS recording", "[sudo or tcpdump missing]")
        return

    print("\n  macOS will now ask for your password.")
    try:
        granted = subprocess.call([sudo, "-v"]) == 0
    except KeyboardInterrupt:
        granted = False
    if not granted:
        print("\n  Could not get administrator rights, so no recording was made.")
        print("  That is fine; the main report on its own is still useful.\n")
        section("Stage 2: macOS recording", "[administrator rights not granted]")
        return

    # sudo forgets the password after 5 minutes; keep it fresh so stopping
    # and switching the interfaces off never asks again halfway through.
    stop_keepalive = threading.Event()

    def keepalive():
        while not stop_keepalive.wait(50):
            subprocess.call([sudo, "-n", "true"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)

    threading.Thread(target=keepalive, daemon=True).start()

    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    brought_up: list = []
    procs: dict = {}
    files: dict = {}
    log: list = []
    record: list = []
    old_handlers = {}
    for sig in (signal.SIGHUP, signal.SIGTERM):
        try:
            old_handlers[sig] = signal.signal(sig, _raise_hangup)
        except (ValueError, OSError):
            pass
    ended_early = None
    try:
        for iface in interfaces:
            if not _iface_is_up(ifconfig, iface):
                rc = subprocess.call([sudo, "-n", ifconfig, iface, "up"],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if rc != 0:
                    print(f"  - {iface}: could not be switched on, skipping it")
                    continue
                brought_up.append(iface)
            path = os.path.join(outdir, f"io-capture-{stamp}-{iface}-full.pcap")
            # Created by us first, so the file stays ours (not root's) when
            # tcpdump writes into it.
            open(path, "wb").close()
            files[iface] = path
            procs[iface] = subprocess.Popen(
                [sudo, "-n", tcpdump, "-U", "-i", iface, "-w", path],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE)
        time.sleep(RECORDER_STARTUP_WAIT)
        live = []
        for iface, proc in procs.items():
            if proc.poll() is None:
                live.append(iface)
                print(f"  - {iface}: recording")
            else:
                err = (proc.stderr.read() if proc.stderr else b"").decode("utf-8", "replace")
                print(f"  - {iface}: could not start recording")
                for line in err.strip().splitlines()[:3]:
                    print(f"        {line}")
        if not live:
            print("\n  Nothing could be recorded on this Mac. Your report is still")
            print("  useful on its own; the other ways to record are in the README.")
            log.append("no interface could be recorded")
        else:
            print("\n" + "=" * 68)
            print("  RECORDING. Now do the steps below.")
            print("=" * 68)
            t0 = time.time()
            log += io_log_header(t0)
            _END["sip_box"] = True          # SIP was switched off for this
            reader = IoLiveReader({i: files[i] for i in live}, {i: procs[i] for i in live})
            keep = lambda: set_section("Stage 2: annotated capture timeline",  # noqa: E731
                                       "\n".join(log))
            keep()
            try:
                log.append("walk: " + run_io_steps(
                    IO_STEPS, t0, log, record=record, check=reader.check, on_change=keep))
            finally:
                _END["steps_done"] = any(not r.get("skipped") for r in record)
    except KeyboardInterrupt:
        ended_early = "Ctrl-C"
    except _Hangup:
        ended_early = "window closed or stop signal"
    finally:
        # A second Ctrl-C must not cut the clean-up short (tcpdump left
        # running, interfaces left on): ignored until the files are safe.
        try:
            old_int = signal.signal(signal.SIGINT, signal.SIG_IGN)
        except (ValueError, OSError):
            old_int = None
        _say("\n  Stopping the recording...")
        for iface, proc in procs.items():
            if proc.poll() is not None:
                continue
            try:
                proc.terminate()            # sudo passes SIGTERM on to tcpdump
                proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                subprocess.call([sudo, "-n", "pkill", "-TERM", "-f",
                                 f"{tcpdump} -U -i {iface} -w {files[iface]}"],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
            except OSError:
                pass
        for proc in procs.values():
            if proc.stderr:
                proc.stderr.close()
        still_up = []
        for iface in brought_up:
            subprocess.call([sudo, "-n", ifconfig, iface, "down"],
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if _iface_is_up(ifconfig, iface):
                still_up.append(iface)
        stop_keepalive.set()
        for sig, handler in old_handlers.items():
            try:
                # 1.5.4 review: a window closed during the questions must not
                # kill the run before the report is written; with SIGHUP
                # ignored, the questions just get no answer.
                signal.signal(sig, signal.SIG_IGN if sig == signal.SIGHUP else handler)
            except (ValueError, OSError):
                pass
        if brought_up:
            if still_up:
                _say(f"  Could not switch {', '.join(still_up)} off again. They switch off")
                _say("  by themselves when you restart the Mac.")
            else:
                _say(f"  Switched {', '.join(brought_up)} off again.")
    if ended_early:
        log.append(f"recording ended early: {ended_early}")
    set_section("Stage 2: annotated capture timeline", "\n".join(log))
    try:
        hung_up = ended_early == "window closed or stop signal"
        if not hung_up:
            notes = ask("\nAnything odd happen? (free text, Enter to skip): ")
            if notes:
                log.append(f"operator notes: {notes}")
                set_section("Stage 2: annotated capture timeline", "\n".join(log))
        result_lines = finish_recordings(files, record, ask_delete=not hung_up)
        set_section("Stage 2: macOS recording result", "\n".join(result_lines))
        _say("\n" + "\n".join("  " + l for l in result_lines))
        if record and not hung_up:
            answers: list = []
            ask_io_questions(answers)
            set_section("Stage 2: answers about the chart and the settings",
                        "\n".join(answers))
        if _IO_SUMMARY:
            set_section("Stage 2: the steps at a glance", "\n".join(_IO_SUMMARY))
            _say("\n" + "\n".join("  " + l for l in _IO_SUMMARY))
        _say()
        _say(SIP_OFF_REMINDER)
        _say()
    finally:
        if old_int is not None:
            try:
                signal.signal(signal.SIGINT, old_int)
            except (ValueError, OSError):
                pass


_IO_SUMMARY: list = []          # 1.5.4: the step table, repeated at the very end


def finish_recordings(files: dict, record: list | None = None, ask_delete: bool = True) -> list:
    """Check each recording, make the X-Rite-only copies, offer to delete the
    rest. 1.5.4: record (the steps) adds the per-step check of the table's
    commands."""
    lines = ["RECORDING CHECK"]
    send = []
    full = []
    for iface, path in files.items():
        if not os.path.exists(path):
            continue
        full.append(path)
        check = check_capture(path, SESSION_TABLE)
        lines.append(f"{iface}: {check['packets']} packets, "
                     f"{check['xrite_packets']} of them from X-Rite devices")
        lines.append("  " + check["verdict"])
        if check["xrite_packets"]:
            dst = path.replace("-full.pcap", "-xrite.pcap")
            kept = filter_xrite_capture(path, dst, SESSION_TABLE)
            if kept:
                send.append(dst)
                lines.append(f"  X-Rite-only copy ({kept} packets): {os.path.basename(dst)}")
    steps = [r for r in record or [] if not r.get("skipped")]
    io3 = 0
    for dst in send:
        try:
            _lt, recs = _read_pcap(dst)
            io3 += sum(1 for _t, d in recs if is_io3_record(d))
        except (OSError, ValueError):
            pass
    if send:
        _END["send"] = {"files": list(send)}
    if steps and io3:
        lines.append("")
        lines.append(_wrap(IO3_UNCHECKED.format(n=io3).replace("this step", "the steps")
                           .replace("please just carry on", "please send the recording "
                                    "anyway") + ".", 66, ""))
        steps = []
    if steps:
        table_lines = []
        for dst in send:
            cap = io_capture(dst)
            if cap:
                table_lines += cap["lines"]
        rows = []
        lines.append("")
        lines.append("THE STEPS, CHECKED IN THE FINISHED RECORDING")
        for r in record:
            if r.get("skipped"):
                lines.append(f"  {r['title']}: skipped")
                rows.append((r["title"], None, 0, 0))
                continue
            n, moving = io_count_commands(table_lines, r["start"], r["end"])
            lines.append(f"  {r['title']}: {io_step_verdict(n, moving)}")
            rows.append((r["title"], True, n, moving))
        _IO_SUMMARY[:] = io_summary_table(rows)
    lines.append("")
    if send:
        lines.append("Please attach these files to the GitHub issue, together with the report:")
        lines.extend("  " + os.path.basename(p) for p in send)
    else:
        lines.append("No X-Rite traffic was found in any recording, so there is nothing "
                     "useful to send. The report on its own still helps.")
    if full and not ask_delete:
        lines.append("The full recordings were kept (the window was closed). Please do not "
                     "send them; delete them when you no longer need them.")
    elif full:
        print("\n  The full recordings (the files ending in -full.pcap) hold everything")
        print("  that happened on those USB buses, possibly including what you typed")
        print("  on a USB keyboard. They are not needed: the X-Rite-only copies have")
        print("  everything we need.")
        if said_yes(ask("  Delete the full recordings now? Recommended. (yes / no): ")):
            for path in full:
                try:
                    os.remove(path)
                except OSError:
                    pass
            lines.append("The full recordings were deleted.")
        else:
            lines.append("The full recordings were kept. Please do not send them; "
                         "delete them when you no longer need them.")
    return lines


# --------------------------------------------------------------------------
# capture analysis: turn a raw .pcap into a plain verdict + command timeline
#
# It NEVER touches a device; it only reads a capture file the user already
# made. It is deliberately DEVICE-AGNOSTIC: it assumes no vendor opcodes.
#
# Only the macOS (Darwin) format is decoded in detail. It was validated
# against real hardware (a ColorMunki via ChromIQ, matched byte for byte to
# Argyll's munki driver). It has NOT yet been tried on a real i1iO recording.
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

# Darwin USB header layout (40 bytes), reverse-engineered from real captures:
#   [2]       header length (0x28 = 40)
#   [3]       0 = submit (host->device), 1 = complete (device->host)
#   [4:8]     data length, little-endian
#   [0x10:14] URB sequence id (a submit and its completion share it)
#   [0x24:26] idVendor LE   [0x26:28] idProduct LE
#   [40:]     payload; for a control submit this begins with the 8-byte setup
_DARWIN_HDR = 40


def _read_pcapng(blob: bytes):
    """Minimal pcapng reader: first interface's link type + packet blocks."""
    off, recs, linktype, endian = 0, [], None, "<"
    tsdiv = 1e6                          # default: microseconds
    while off + 12 <= len(blob):
        btype = struct.unpack(endian + "I", blob[off:off + 4])[0]
        if btype == 0x0A0D0D0A:
            bom = blob[off + 8:off + 12]
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
        blen = struct.unpack(endian + "I", blob[off + 4:off + 8])[0]
        if blen < 12 or off + blen > len(blob):
            break
        body = blob[off + 8:off + blen - 4]
        if btype == 1 and linktype is None and len(body) >= 2:
            linktype = struct.unpack(endian + "H", body[:2])[0]
            # Options: code 9 (if_tsresol) sets the time stamp resolution.
            opt = 8
            while opt + 4 <= len(body):
                code, olen = struct.unpack(endian + "HH", body[opt:opt + 4])
                if code == 0:
                    break
                if code == 9 and olen >= 1:
                    res = body[opt + 4]
                    tsdiv = float(2 ** (res & 0x7f)) if res & 0x80 else float(10 ** res)
                opt += 4 + olen + ((-olen) % 4)
        elif btype == 6 and len(body) >= 20:
            _ifid, ts_hi, ts_lo, cap = struct.unpack(endian + "IIII", body[:16])
            ts = ((ts_hi << 32) | ts_lo) / tsdiv
            recs.append((ts, body[20:20 + cap]))
        elif btype == 3 and len(body) >= 4:
            recs.append((0.0, body[4:]))
        off += blen
    if linktype is None:
        raise ValueError("pcapng file without an interface description")
    return linktype, recs


def _read_pcap(path):
    """Return (linktype, [(ts, data), ...]). Raise ValueError if not a capture."""
    with open(path, "rb") as fh:
        blob = fh.read()
    if len(blob) >= 4 and blob[:4] == b"\x0a\x0d\x0d\x0a":
        return _read_pcapng(blob)
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


def _darwin_hdr_len(data: bytes) -> int:
    n = data[2] if len(data) > 2 else _DARWIN_HDR
    return n if _DARWIN_HDR <= n <= len(data) else _DARWIN_HDR


def _payload(linktype: int, data: bytes) -> bytes:
    """The data bytes of one record, without the capture's own header."""
    if linktype == LINKTYPE_USB_DARWIN:
        return data[_darwin_hdr_len(data):] if len(data) >= _DARWIN_HDR else b""
    if linktype == LINKTYPE_USB_LINUX:
        return data[48:]
    if linktype == LINKTYPE_USB_LINUX_MMAPPED:
        return data[64:]
    if linktype == LINKTYPE_USBPCAP and len(data) >= 2:
        return data[struct.unpack("<H", data[:2])[0]:]
    return data


def _darwin_vid(data: bytes):
    if len(data) < _DARWIN_HDR:
        return None
    return struct.unpack("<H", data[0x24:0x26])[0]


def _darwin_ids(data: bytes):
    """(vendor, product) ID of one macOS record (both are in every record's
    header), or None."""
    if len(data) < _DARWIN_HDR:
        return None
    return struct.unpack("<HH", data[0x24:0x28])


def darwin_selection(records, profile: str | None = None) -> tuple:
    """1.6: instrument_selection() for macOS records: (set of IDs, how)."""
    devices = {}
    for data in records:
        ids = _darwin_ids(data)
        if ids and (ids[0] or ids[1]):
            devices[ids] = {"vid": ids[0], "pid": ids[1]}
    keys, how = instrument_selection(devices, profile)
    return set(keys), how


_EP_TYPES = {0: "control", 1: "isochronous", 2: "bulk", 3: "interrupt"}


def parse_config_descriptor(blob: bytes) -> list:
    """Interfaces and endpoints from a configuration descriptor, as text lines."""
    lines = []
    i = 0
    while i + 2 <= len(blob):
        length, dtype = blob[i], blob[i + 1]
        if length < 2 or i + length > len(blob):
            break
        d = blob[i:i + length]
        if dtype == 4 and length >= 9:
            lines.append(f"interface {d[2]} alt {d[3]}: {d[4]} endpoints, "
                         f"class {d[5]} subclass {d[6]} protocol {d[7]}")
        elif dtype == 5 and length >= 7:
            addr = d[2]
            mps = struct.unpack("<H", d[4:6])[0]
            lines.append(f"  endpoint 0x{addr:02x} ({'IN' if addr & 0x80 else 'OUT'}), "
                         f"{_EP_TYPES[d[3] & 3]}, max packet {mps & 0x7ff} bytes, "
                         f"interval {d[6]}")
        i += length
    return lines


def is_serial_string(resp: bytes, index: int, serial_index) -> bool:
    """1.5.4: is this USB string descriptor the device's serial number?
    Certain when the recording holds the device descriptor (its
    iSerialNumber). Without it, a string of digits and capital letters with
    no space is taken as one: the i1iO's and the i1Pro 2's serial strings
    are digits, their maker and product strings are words."""
    if index == 0 or len(resp) < 4 or resp[1] != 3:
        return False
    if serial_index is not None:
        return index == serial_index
    try:
        text = resp[2:resp[0]].decode("utf-16-le")
    except UnicodeDecodeError:
        return False
    return bool(re.fullmatch(r"[0-9A-Z]{4,}", text)) and any(c.isdigit() for c in text)


def _analyze_darwin(recs):
    """Device-agnostic summary: (devices, cmd_counts, timeline, bulk, descriptors)."""
    submits = {}                    # seq -> (bRequest, dir_in, wLen, ts, wValue, bmReqType)
    cmd_counts = {}
    devices = {}
    timeline = []
    bulk_bytes = 0
    descriptors: list = []
    serial_index: dict = {}         # (vid, pid) -> iSerialNumber, when recorded
    t0 = recs[0][0] if recs else 0.0
    for ts, data in recs:
        if len(data) < _DARWIN_HDR:
            continue
        direction = data[3]
        dlen = struct.unpack("<I", data[4:8])[0]
        seq = struct.unpack("<I", data[0x10:0x14])[0]
        vid = struct.unpack("<H", data[0x24:0x26])[0]
        pid = struct.unpack("<H", data[0x26:0x28])[0]
        if vid or pid:
            devices[(vid, pid)] = devices.get((vid, pid), 0) + 1
        payload = data[_darwin_hdr_len(data):]
        # A control submit begins with an 8-byte setup packet. Validate both the
        # bmRequestType field and the USB length invariant (payload is exactly
        # the setup for IN, or setup + wLength bytes for OUT).
        if (direction == 0 and len(payload) >= 8
                and ((payload[0] >> 5) & 3) <= 2 and (payload[0] & 0x1f) <= 3):
            wlen = struct.unpack("<H", payload[6:8])[0]
            if len(payload) in (8, 8 + wlen):
                breq = payload[1]
                dir_in = bool(payload[0] & 0x80)
                wvalue = struct.unpack("<H", payload[2:4])[0]
                submits[seq] = (breq, dir_in, wlen, ts, wvalue, payload[0])
                cmd_counts[breq] = cmd_counts.get(breq, 0) + 1
        elif direction == 1:
            info = submits.get(seq)
            if info:
                breq, dir_in, wlen, tsub, wvalue, rtype = info
                resp = payload[:dlen] if dlen else payload
                # Standard GET_DESCRIPTOR(CONFIGURATION): the endpoint layout.
                if rtype == 0x80 and breq == 6 and (wvalue >> 8) == 2:
                    for start in (0, 8):
                        part = resp[start:]
                        if len(part) >= 9 and part[0] == 9 and part[1] == 2:
                            lines = parse_config_descriptor(part)
                            tag = f"{vid:04x}:{pid:04x}"
                            if lines and (tag, tuple(lines)) not in descriptors:
                                descriptors.append((tag, tuple(lines)))
                            break
                if rtype == 0x80 and breq == 6 and (wvalue >> 8) == 1 and len(resp) >= 17:
                    serial_index[(vid, pid)] = resp[16]
                shown = resp[:16]
                if (REDACT and rtype == 0x80 and breq == 6 and (wvalue >> 8) == 3
                        and is_serial_string(resp, wvalue & 0xFF,
                                             serial_index.get((vid, pid)))):
                    shown = b"<serial>"
                if len(timeline) < 30:
                    timeline.append((tsub - t0, breq, dir_in, wlen, shown))
            elif dlen >= 64:
                bulk_bytes += dlen
    return devices, cmd_counts, timeline, bulk_bytes, descriptors


def check_capture(path: str, profile: str | None = None) -> dict:
    """Plain facts about one recording, including the all-zero payload check.
    profile (1.6): the session's instrument, for keeps_device()."""
    try:
        linktype, recs = _read_pcap(path)
    except (OSError, ValueError) as exc:
        return {"ok": False, "packets": 0, "xrite_packets": 0, "linktype": None,
                "code": "unreadable", "verdict": f"not a readable recording: {exc}"}
    identified = True
    unidentified_isis = False
    # 1.6.2: the instrument's records are decided in one place
    # (attribute_records): its address at that moment, its endpoints, and
    # nothing that is another device's kind of traffic.
    mine_recs, att = kept_records(linktype, recs, profile)
    how = att["how"]
    left_out = att["left_out"]
    if linktype == LINKTYPE_USB_DARWIN:
        kept_ids = sorted(att["devices"])
        mine = [d for _ts, d in mine_recs]
        xrite = len(mine)
        mine_events = capture_events(linktype, mine_recs)
    else:
        # 1.5: Windows and Linux records carry a bus and device address but no
        # vendor ID, so the X-Rite device is found from its USB description
        # (or its i1Pro commands). If the recording shows no device at all,
        # every record counts for this check (only counts, as in 1.4), and
        # nothing is kept.
        all_events = capture_events(linktype, recs)
        devices = device_map(all_events)
        wanted = att["devices"]
        kept_ids = sorted({(v["vid"], v["pid"]) for v in wanted.values()
                           if v.get("vid") is not None})
        if wanted:
            mine = [d for _ts, d in mine_recs]
            mine_events = capture_events(linktype, mine_recs)
        elif profile == "isis":
            # 1.6 review: no i1iSis identified. If any device in the recording
            # has no USB description, it may be the i1iSis: nothing is kept,
            # and the check says so (with what to do) instead of "OK" over
            # the keyboard's traffic or "no X-Rite traffic". A bus where every
            # device is described and none is the i1iSis is simply not its bus.
            mine = []
            mine_events = []
            unidentified_isis = how == "unidentified"
        elif any(v.get("vid") for v in devices.values()):
            mine = []
            mine_events = []
        else:
            mine = [d for _ts, d in recs]
            mine_events = all_events
            identified = False
        xrite = len(mine)
    # 1.5.5: what the instrument really did: its own (vendor or class)
    # requests and data on its endpoints. A step that was started and stopped
    # at once holds only the descriptor fetch, which is not a recording.
    activity = sum(1 for e in mine_events
                   if (e["kind"] == "control" and (e["rt"] >> 5) & 3 in (1, 2))
                   or (e["kind"] == "data" and e["ep"] & 0x7F))
    # Only the X-Rite packets count: a busy keyboard on the same bus must not
    # hide the fact that the table's own data came out as zeros.
    payload_bytes = 0
    nonzero = 0
    for data in mine:
        payload = _payload(linktype, data)
        payload_bytes += len(payload)
        nonzero += len(payload) - payload.count(0)
    if not recs:
        code, verdict = "empty", "EMPTY: nothing at all was recorded on this bus."
    elif unidentified_isis:
        code, verdict = "unidentified", (
            "NOTHING KEPT: this recording does not say which device is the i1iSis "
            "(it holds no USB description), so the tool kept nothing rather than "
            "risk keeping another device.")
    elif not xrite and (linktype == LINKTYPE_USB_DARWIN or identified):
        code, verdict = "no-xrite", ("No X-Rite traffic on this bus. That is normal for "
                                     "the buses the instrument is not plugged into.")
    elif payload_bytes == 0:
        code, verdict = "no-payload", ("NO DATA: only the outline of the traffic was "
                                       "recorded, without any data bytes.")
    elif nonzero == 0:
        code, verdict = "all-zero", (
            "ALL-ZERO: the recording shows the traffic, but every data byte in it is "
            "zero. macOS recorded the outline of the conversation without its "
            "content. This has been seen before on Apple Silicon Macs; it is not "
            "your mistake, and this recording cannot show us the commands.")
    elif activity == 0 and identified:
        code, verdict = "empty-step", ("EMPTY: only the USB description was recorded, "
                                       "nothing the instrument did.")
    else:
        code, verdict = "ok", (f"OK: real data recorded ({nonzero:,} non-zero data "
                               f"bytes out of {payload_bytes:,}).")
    if code == "ok" and not identified:
        verdict += (" Which device each packet belongs to could not be told from this "
                    "recording (it holds no USB description).")
    note = left_out_text(left_out)
    if note:
        verdict += " " + note
    return {"ok": code == "ok", "packets": len(recs), "xrite_packets": xrite,
            "linktype": linktype, "code": code, "verdict": verdict,
            "payload_bytes": payload_bytes, "nonzero_bytes": nonzero,
            "identified": identified, "activity": activity,
            "kept": how if xrite else "", "kept_ids": kept_ids if xrite else [],
            "left_out": left_out}


def record_device_keys(linktype: int, recs) -> list:
    """(bus, device address) of each record, or None, in the same order."""
    keys = []
    for _ts, d in recs:
        key = None
        if linktype == LINKTYPE_USBPCAP and len(d) >= 27:
            bus, dev = struct.unpack_from("<HH", d, 17)
            key = (bus, dev)
        elif linktype in (LINKTYPE_USB_LINUX, LINKTYPE_USB_LINUX_MMAPPED) and len(d) >= 14:
            dev = d[11]
            bus = struct.unpack_from("<H", d, 12)[0]
            key = (bus, dev)
        keys.append(key)
    return keys


def _write_pcap(dst: str, linktype: int, recs) -> bool:
    out = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, linktype)]
    for ts, data in recs:
        sec = int(ts)
        usec = int(round((ts - sec) * 1e6))
        if usec >= 1000000:
            sec, usec = sec + 1, usec - 1000000
        out.append(struct.pack("<IIII", sec, usec, len(data), len(data)))
        out.append(data)
    try:
        with open(dst, "wb") as fh:
            fh.write(b"".join(out))
    except OSError:
        return False
    return True


def filter_xrite_capture(src: str, dst: str, profile: str | None = None) -> int:
    """Write a copy holding only the X-Rite device's records. Returns count.

    macOS: by the vendor ID in each record (1.4). Windows (USBPcap) and Linux
    (usbmon): by the bus and device address that the recording's own USB
    description shows for the X-Rite device (or, failing that, the device
    that uses the i1Pro's commands). Nothing from any other device address
    is copied: not the keyboard, not the mouse, not the hub. In an i1iSis
    session (profile "isis", 1.6) also not another X-Rite instrument the
    tool knows, such as a monitor calibrator.
    """
    try:
        linktype, recs = _read_pcap(src)
    except (OSError, ValueError):
        return 0
    if linktype in (LINKTYPE_USBPCAP, LINKTYPE_USB_LINUX, LINKTYPE_USB_LINUX_MMAPPED):
        # 1.6.2: attribute_records() decides, record by record.
        kept, _att = kept_records(linktype, recs, profile)
        if not kept or not _write_pcap(dst, linktype, kept):
            return 0
        return len(kept)
    return _filter_darwin_capture(src, dst, profile)


def _filter_darwin_capture(src: str, dst: str, profile: str | None = None) -> int:
    """Write a copy of a macOS pcap holding only X-Rite records. Returns count."""
    try:
        with open(src, "rb") as fh:
            blob = fh.read()
    except OSError:
        return 0
    if len(blob) < 24 or blob[:4] not in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1",
                                          b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        return 0
    endian = "<" if blob[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    if struct.unpack(endian + "I", blob[20:24])[0] != LINKTYPE_USB_DARWIN:
        return 0
    spans = []
    off = 24
    while off + 16 <= len(blob):
        incl = struct.unpack(endian + "I", blob[off + 8:off + 12])[0]
        rec_end = off + 16 + incl
        if rec_end > len(blob):
            break
        spans.append((off, rec_end))
        off = rec_end
    # 1.6.2: attribute_records() decides; the kept records are copied byte
    # for byte, with their own time stamps.
    try:
        _lt, recs = _read_pcap(src)
    except (OSError, ValueError):
        return 0
    if len(recs) != len(spans):
        return 0
    att = attribute_records(LINKTYPE_USB_DARWIN, recs, profile)
    out = [blob[:24]]
    kept = 0
    for (a, b), keep in zip(spans, att["keep"]):
        if keep:
            out.append(blob[a:b])
            kept += 1
    if not kept:
        return 0
    try:
        with open(dst, "wb") as fh:
            fh.write(b"".join(out))
    except OSError:
        return 0
    return kept


def find_captures():
    """Newest recordings sitting next to the tool (or Desktop).

    Prefers the X-Rite-only copies; falls back to any io-capture-*.pcap*.
    """
    for directory in candidate_dirs():
        hits = glob.glob(os.path.join(directory, "io-capture-*-xrite.pcap")) \
            or glob.glob(os.path.join(directory, "io-capture-*.pcap*"))
        if hits:
            newest = max(os.path.getmtime(h) for h in hits)
            recent = [h for h in hits if newest - os.path.getmtime(h) < 60]
            return sorted(recent) or sorted(hits)
    return []


def summarize_captures(paths):
    """Plain-language verdict + command timeline for one or more captures."""
    out = ["=" * 68, "  USB recording check", "=" * 68, "",
           "  Reads recordings you already made. It sends NOTHING to any",
           "  device. It confirms a recording really holds instrument traffic",
           "  before you send it, and prints the command timeline.", ""]
    any_real = False
    any_zero = False
    for path in paths:
        out.append("  " + os.path.basename(path))
        check = check_capture(path)
        if check["code"] == "unreadable":
            out += ["     " + check["verdict"], ""]
            continue
        linktype, recs = _read_pcap(path)
        name = _LINKTYPE_NAMES.get(linktype, f"linktype {linktype}")
        total = sum(len(d) for _, d in recs)
        out.append(f"     format: {name}   packets: {len(recs)}   bytes: {total:,}")
        out.append("     data check: " + check["verdict"])
        any_zero = any_zero or check["code"] == "all-zero"
        if linktype != LINKTYPE_USB_DARWIN:
            if recs:
                out += ["     A detailed timeline is decoded for macOS recordings",
                        "     only, for now; this file is complete, so send it in."]
                any_real = any_real or (total > 4096 and check["code"] == "ok")
            out.append("")
            continue
        devices, cmds, timeline, bulk, descriptors = _analyze_darwin(recs)
        if devices:
            devstr = ", ".join(f"{v:04x}:{p:04x}" for v, p in
                               sorted(devices, key=lambda k: -devices[k]))
            out.append(f"     device(s) on this bus: {devstr}")
        n_cmd = sum(cmds.values())
        out.append(f"     control commands: {n_cmd}   distinct opcodes: "
                   f"{len(cmds)}   bulk data: {bulk:,} bytes")
        for tag, lines in descriptors:
            out.append(f"     USB description of {tag} found in the recording:")
            out.extend("        " + l for l in lines)
        real = bool(devices) and (n_cmd > 0 or bulk > 2048) and check["code"] == "ok"
        any_real = any_real or real
        if timeline:
            out.append("     timeline (device-agnostic, no opcode is assumed):")
            for tsec, breq, dir_in, wlen, resp in timeline:
                out.append(f"        {tsec:7.3f}s  req=0x{breq:02X} "
                           f"{'IN ' if dir_in else 'OUT'} wLen={wlen:<4} -> "
                           + ("<serial number hidden>" if resp == b"<serial>" else
                              f"{resp.hex()}  |{_fmt_ascii(resp)}|"))
        out.append("     VERDICT: " + (
            "OK, real device traffic captured. Good to send."
            if real else
            "data bytes are all zero, see above." if check["code"] == "all-zero" else
            "little or no device traffic: wrong bus, or no measurement was taken."))
        out.append("")
    out.append("-" * 68)
    out.append("  Overall: " + (
        "at least one file holds real instrument traffic."
        if any_real else
        "every data byte was zero, so these recordings cannot show the commands."
        if any_zero else
        "no clear instrument traffic found in any file."))
    if not any_real and not any_zero:
        out.append("  Record again and TAKE A MEASUREMENT while it records.")
    out.append("=" * 68)
    return "\n".join(out)


# --------------------------------------------------------------------------
# 1.5: format-independent view of a recording
#
# Every supported capture format (Windows USBPcap, Linux usbmon, macOS) is
# turned into the same list of events, so the i1Pro decoder below works on
# all of them:
#   {"kind": "control", "t", "bus", "dev", "rt", "req", "wValue", "wIndex",
#    "wLength", "out": bytes, "in": bytes}
#   {"kind": "data", "t", "bus", "dev", "ep", "type", "dir_in", "data": bytes}
#
# USBPcap header (27 bytes, little-endian), from the USBPcap documentation:
#   headerLen u16, irpId u64, status u32, function u16, info u8 (bit 0 set
#   = completion travelling back to the host), bus u16, device u16,
#   endpoint u8 (bit 7 = IN), transfer u8 (0 iso, 1 interrupt, 2 control,
#   3 bulk), dataLength u32; control transfers add one "stage" byte
#   (0 setup, 1 data, 2 status, 3 complete).
# Linux usbmon header (48 or 64 bytes, host byte order), from the kernel's
#   usbmon documentation: id u64, type 'S'/'C'/'E', xfer_type u8 (same
#   numbers as USBPcap), epnum u8, devnum u8, busnum u16, flag_setup,
#   flag_data, ts_sec s64, ts_usec s32, status s32, length u32, len_cap u32,
#   setup[8].
# macOS: the 40-byte header described above; byte 29 is the device address,
#   30 the endpoint address and 31 the endpoint type (USB descriptor order:
#   0 control, 1 isochronous, 2 bulk, 3 interrupt). Only the vendor/product
#   fields were checked against real recordings so far.
# --------------------------------------------------------------------------

_XFER_NAMES = {0: "isochronous", 1: "interrupt", 2: "control", 3: "bulk"}
_DARWIN_EP_TYPES = {0: "control", 1: "isochronous", 2: "bulk", 3: "interrupt"}


def _setup_fields(setup: bytes) -> dict:
    rt, req, wvalue, windex, wlen = struct.unpack("<BBHHH", setup[:8])
    return {"rt": rt, "req": req, "wValue": wvalue, "wIndex": windex, "wLength": wlen}


def _plausible_setup(setup: bytes) -> bool:
    return (len(setup) >= 8 and ((setup[0] >> 5) & 3) <= 2 and (setup[0] & 0x1f) <= 3)


def _events_usbpcap(recs) -> list:
    events = []
    pending = {}                      # (bus, irp) -> control event being built
    for ri, (ts, d) in enumerate(recs):
        if len(d) < 27:
            continue
        (hlen, irp, _status, _func, info, bus, dev, ep, xfer,
         dlen) = struct.unpack_from("<HQIHBHHBBI", d, 0)
        if hlen < 27 or hlen > len(d):
            continue
        data = d[hlen:hlen + dlen]
        completion = bool(info & 1)
        if xfer == 2:
            stage = d[27] if hlen >= 28 else None
            key = (bus, irp)
            if stage == 0 and not completion and _plausible_setup(data):
                ev = {"kind": "control", "t": ts, "bus": bus, "dev": dev,
                      "out": bytes(data[8:]), "in": b"", "_done": False, "_ri": [ri]}
                ev.update(_setup_fields(data))
                pending[key] = ev
                events.append(ev)
                continue
            ev = pending.get(key)
            if ev is None:
                continue
            ev["_ri"].append(ri)
            if not completion and stage == 1 and not (ev["rt"] & 0x80):
                ev["out"] += bytes(data)
            elif completion:
                if (ev["rt"] & 0x80) and data and not ev["in"]:
                    ev["in"] = bytes(data)
                if stage in (2, 3) or stage is None:
                    ev["_done"] = True
                    pending.pop(key, None)
            continue
        dir_in = bool(ep & 0x80)
        if not data:
            continue
        # OUT data travels with the request, IN data with its completion.
        if dir_in != completion:
            continue
        events.append({"kind": "data", "t": ts, "bus": bus, "dev": dev, "ep": ep,
                       "type": _XFER_NAMES.get(xfer, f"type {xfer}"),
                       "dir_in": dir_in, "data": bytes(data), "_ri": [ri]})
    for ev in events:
        ev.pop("_done", None)
    return events


def _events_usbmon(recs, hdr_len: int) -> list:
    events = []
    pending = {}
    for ri, (ts, d) in enumerate(recs):
        if len(d) < hdr_len:
            continue
        (uid, typ, xfer, epnum, devnum, busnum, flag_setup, _flag_data, _sec, _usec,
         _status, _length, len_cap, setup) = struct.unpack_from("<QcBBBHccqiiII8s", d, 0)
        data = d[hdr_len:hdr_len + len_cap]
        key = (busnum, uid)
        if xfer == 2:
            if typ == b"S" and flag_setup == b"\x00" and _plausible_setup(setup):
                ev = {"kind": "control", "t": ts, "bus": busnum, "dev": devnum,
                      "out": bytes(data), "in": b"", "_ri": [ri]}
                ev.update(_setup_fields(setup))
                pending[key] = ev
                events.append(ev)
            elif typ == b"C":
                ev = pending.pop(key, None)
                if ev is not None:
                    ev["_ri"].append(ri)
                if ev is not None and (ev["rt"] & 0x80):
                    ev["in"] = bytes(data)
            continue
        dir_in = bool(epnum & 0x80)
        if not data:
            continue
        if (typ == b"C") != dir_in:
            continue
        events.append({"kind": "data", "t": ts, "bus": busnum, "dev": devnum, "ep": epnum,
                       "type": _XFER_NAMES.get(xfer, f"type {xfer}"),
                       "dir_in": dir_in, "data": bytes(data), "_ri": [ri]})
    return events


def _events_darwin(recs) -> list:
    """macOS records -> events.

    1.5.4: measured on the first real i1iO recordings (macOS 15/26, tcpdump
    on XHCn): data going TO the device travels in the COMPLETION record, not
    in the submit. A bulk OUT submit carries the length but no bytes, and a
    control OUT submit carries only its 8-byte setup; the data stage comes
    with the completion. 1.5.3 read OUT data only from the submit, so every
    command the vendor program sent was missing from --analyze. The submit's
    bytes are still used when a completion arrives empty (other macOS
    versions may differ), and nothing is counted twice."""
    events = []
    pending = {}
    out_submits = {}                  # seq -> the event of a non-control OUT submit
    for ri, (ts, d) in enumerate(recs):
        if len(d) < _DARWIN_HDR:
            continue
        direction = d[3]
        dlen = struct.unpack("<I", d[4:8])[0]
        seq = struct.unpack("<I", d[0x10:0x14])[0]
        dev = d[29]
        ep = d[30]
        etype = _DARWIN_EP_TYPES.get(d[31] & 3, "unknown")
        vid = struct.unpack("<H", d[0x24:0x26])[0]
        pid = struct.unpack("<H", d[0x26:0x28])[0]
        payload = d[_darwin_hdr_len(d):]
        bus = (vid << 16) | pid if not dev else 0
        if direction == 0 and _plausible_setup(payload[:8]) and (ep & 0x7f) == 0:
            wlen = struct.unpack("<H", payload[6:8])[0]
            if len(payload) in (8, 8 + wlen):
                ev = {"kind": "control", "t": ts, "bus": bus, "dev": dev,
                      "out": bytes(payload[8:]), "in": b"", "vid": vid, "pid": pid,
                      "_ri": [ri]}
                ev.update(_setup_fields(payload))
                pending[seq] = ev
                events.append(ev)
                continue
        if direction == 1 and seq in pending:
            ev = pending.pop(seq)
            ev["_ri"].append(ri)
            body = bytes(payload[:dlen] if dlen else payload)
            if ev["rt"] & 0x80:
                ev["in"] = body
            elif body and not ev["out"]:
                ev["out"] = body            # the data stage of a control OUT
            continue
        dir_in = bool(ep & 0x80)
        data = payload[:dlen] if dlen else payload
        if not dir_in and (ep & 0x7f):
            if direction == 0:
                out_submits[seq] = {"kind": "data", "t": ts, "bus": bus, "dev": dev,
                                    "ep": ep, "type": etype, "dir_in": False,
                                    "data": bytes(data), "vid": vid, "pid": pid,
                                    "_ri": [ri]}
                continue
            sub = out_submits.pop(seq, None)
            data = data or (sub["data"] if sub else b"")
            ris = (sub["_ri"] if sub else []) + [ri]
        else:
            ris = [ri]
        if dir_in or not (ep & 0x7f):
            if direction != 1:
                continue
        if not data:
            continue
        events.append({"kind": "data", "t": ts, "bus": bus, "dev": dev, "ep": ep,
                       "type": etype, "dir_in": dir_in, "data": bytes(data),
                       "vid": vid, "pid": pid, "_ri": ris})
    # An OUT whose completion the recording did not catch (it was stopped in
    # between): keep its bytes if the submit had any, at the submit's time.
    leftovers = [ev for ev in out_submits.values() if ev["data"]]
    if leftovers:
        events = sorted(events + leftovers, key=lambda e: e["t"])
    return events


def _capture_events_ri(linktype: int, recs) -> list:
    """capture_events(), each event with "_ri": the indices of the records
    it was built from (1.6.2, for attribute_records())."""
    if linktype == LINKTYPE_USBPCAP:
        return _events_usbpcap(recs)
    if linktype == LINKTYPE_USB_LINUX:
        return _events_usbmon(recs, 48)
    if linktype == LINKTYPE_USB_LINUX_MMAPPED:
        return _events_usbmon(recs, 64)
    if linktype == LINKTYPE_USB_DARWIN:
        return _events_darwin(recs)
    return []


def capture_events(linktype: int, recs) -> list:
    """The recording as a list of control and data events (see above)."""
    events = _capture_events_ri(linktype, recs)
    for ev in events:
        ev.pop("_ri", None)
    return events


def device_map(events) -> dict:
    """(bus, dev) -> {"vid", "pid", "how", "config": [lines]} for every device
    whose identity the recording shows.

    The identity comes from the device descriptor in the recording (USBPcap
    adds it when "inject already connected devices descriptors" is on, and
    any replug or enumeration carries it), from the macOS header, or, as a
    last resort, from the device using one instrument family's own commands.
    """
    devices: dict = {}
    for ev in events:
        key = (ev["bus"], ev["dev"])
        if "vid" in ev and ev["vid"]:
            devices.setdefault(key, {"vid": ev["vid"], "pid": ev["pid"],
                                     "how": "from the recording's own header",
                                     "config": []})
        if ev["kind"] != "control" or ev["rt"] != 0x80 or ev["req"] != 6:
            continue
        dtype = ev["wValue"] >> 8
        blob = ev["in"]
        if dtype == 1 and len(blob) >= 12 and blob[1] == 1:
            vid, pid = struct.unpack("<HH", blob[8:12])
            have = devices.get(key)
            if have is None or have["how"] != "from its USB description":
                devices[key] = {"vid": vid, "pid": pid, "how": "from its USB description",
                                "config": have["config"] if have else []}
        elif dtype == 2 and len(blob) >= 9 and blob[1] == 2:
            lines = parse_config_descriptor(blob)
            entry = devices.setdefault(key, {"vid": None, "pid": None,
                                             "how": "unknown", "config": []})
            if len(lines) > len(entry["config"]):
                entry["config"] = lines
    # Last resort: the families' vendor requests are distinctive enough to
    # point at the instrument when no description was recorded.
    votes: dict = {}
    for ev in events:
        if ev["kind"] != "control" or (ev["rt"] & 0x60) != 0x40 or not ev["dev"]:
            continue
        key = (ev["bus"], ev["dev"])
        if key in devices and devices[key].get("vid"):
            continue
        for fam_key, fam in FAMILIES.items():
            if fam_key != "generic" and ev["req"] in fam["requests"]:
                votes.setdefault(key, {}).setdefault(fam_key, 0)
                votes[key][fam_key] += 1
    for key, fams in votes.items():
        best = max(fams, key=lambda k: fams[k])
        entry = devices.setdefault(key, {"vid": None, "pid": None, "how": "unknown",
                                         "config": []})
        entry["how"] = (f"guessed: it uses the {FAMILIES[best]['short']}'s own commands")
        entry["guess_family"] = best
    return devices


def xrite_devices(devices: dict, profile: str | None = None) -> list:
    """The devices of a device map an instrument-only copy keeps
    (instrument_selection)."""
    return instrument_selection(devices, profile)[0]


# --------------------------------------------------------------------------
# 1.6.2: which records belong to the instrument (attribute_records)
#
# Up to 1.6.1 a Windows or Linux record was kept when its bus and device
# address were the instrument's. That is not enough. In a USBPcap recording
# the address in a packet is a value the kernel driver cached when the device
# was started (USBPcapHelperFunctions.c, USBPcapGetDeviceUSBInfo, called from
# IRP_MN_START_DEVICE) or when its pipes were set up (USBPcapURB.c, the pipe
# table filled at SELECT_CONFIGURATION). When the host controller gives a
# device a new address later (after resume from hibernation or sleep, after a
# port reset), the cached one goes stale, and another device can by then own
# it (desowin/usbpcap issue 105). A real recording held a USB disk's SCSI
# traffic at the instrument's address that way. Linux and macOS cannot share
# an address between two live devices, but an address can come back after a
# replug. So a record is kept only if all of these hold:
#   1. its address was the instrument's at that moment (each device
#      description at an address starts a new owner there; address 0, where
#      every device is set up, is never kept);
#   2. its endpoint is endpoint 0 or one of the instrument's own (from its
#      configuration description in the recording, else the endpoints its
#      family is known to have);
#   3. it is not another kind of device's traffic: mass-storage commands,
#      their data and status, mass-storage, HID or hub class requests,
#      requests aimed at an endpoint or interface the instrument does not
#      have, another device's configuration description;
# and a transfer is kept or dropped whole. What is dropped at the
# instrument's own address is counted by kind and never shown.
# --------------------------------------------------------------------------

# The endpoints of each family when the recording has no configuration
# description: address -> transfer type, or None where the type is not
# known for certain. i1Pro 2: the descriptor of a real one (bulk 0x82
# readings, interrupt 0x84 button, bulk OUT 0x03 lights, bulk 0x85 ruler,
# 0x01 unused). The others: the endpoints ArgyllCMS 3.5.0 uses for them
# (i1pro_imp.c, i1pro3_imp.c, munki_imp.c; see FAMILIES) and the FTDI chip
# of the i1iO table (bulk 0x81 in, 0x02 out).
FAMILY_ENDPOINTS = {
    "i1pro2": {0x01: None, 0x82: "bulk", 0x84: "interrupt", 0x03: "bulk", 0x85: "bulk"},
    "i1pro": {0x01: None, 0x82: None, 0x84: None, 0x03: None},
    "i1pro3": {0x81: None, 0x83: None, 0x84: None, 0x02: None},
    "munki": {0x81: None, 0x83: None},
    "io": {0x81: "bulk", 0x02: "bulk"},
}

_DESC_TYPES = {0: "control", 1: "isochronous", 2: "bulk", 3: "interrupt"}
_EP_LINE_RE = re.compile(r"endpoint 0x([0-9a-f]{2}) \((?:IN|OUT)\), (\w+),")
_IF_LINE_RE = re.compile(r"^interface (\d+) alt \d+: \d+ endpoints, class (\d+)")

# What a dropped transfer looked like, in the words the checks print.
LEFT_OUT_KINDS = {
    "storage": "a USB disk or memory stick",
    "hid": "a keyboard, mouse or other input device",
    "hub": "a USB hub",
    "description": "another device's USB description",
    "endpoint": "an endpoint the instrument does not have",
    "owner": "a time when that address belonged to another device",
    "unattributed": "traffic that could not be attributed with certainty",
}


def config_endpoints(lines) -> dict:
    """{endpoint address: transfer type} from parse_config_descriptor() lines."""
    eps = {}
    for line in lines or ():
        m = _EP_LINE_RE.search(line)
        if m:
            eps[int(m.group(1), 16)] = m.group(2)
    return eps


def config_interfaces(lines) -> dict:
    """{interface number: class} from parse_config_descriptor() lines."""
    out = {}
    for line in lines or ():
        m = _IF_LINE_RE.match(line.strip())
        if m:
            out.setdefault(int(m.group(1)), int(m.group(2)))
    return out


def instrument_endpoints(info: dict):
    """The endpoints a device may use: from its recorded configuration, else
    its family's known set, else None (not known)."""
    eps = config_endpoints(info.get("config"))
    if eps:
        return eps
    vid, pid = info.get("vid"), info.get("pid")
    if (vid, pid) == (XRITE_VID, IO_TABLE_PID):
        return dict(FAMILY_ENDPOINTS["io"])
    fam = info.get("guess_family")
    if vid is not None:
        fam = family_for(vid, pid, info.get("config"))
    if fam in FAMILY_ENDPOINTS:
        return dict(FAMILY_ENDPOINTS[fam])
    return None


def _record_fields(linktype: int, d: bytes):
    """(key, endpoint, transfer type name, carries data, transaction id,
    starts a transaction, ends it) of one record, or None when the record
    cannot be read. The key is (bus, address) on Windows and Linux and
    (vendor, product) on macOS."""
    if linktype == LINKTYPE_USBPCAP:
        if len(d) < 27:
            return None
        hlen, irp, _st, _fn, info, bus, dev, ep, xfer, dlen = struct.unpack_from(
            "<HQIHBHHBBI", d, 0)
        completion = bool(info & 1)
        stage = d[27] if xfer == 2 and hlen >= 28 and len(d) > 27 else None
        kind = {0: "isochronous", 1: "interrupt", 2: "control", 3: "bulk"}.get(
            xfer, "info" if xfer == 0xFE else "unknown")
        starts = not completion and (xfer != 2 or stage in (0, None))
        ends = completion and (xfer != 2 or stage in (2, 3, None))
        return (bus, dev), ep, kind, dlen > 0 and len(d) > hlen, (bus, irp), starts, ends
    if linktype in (LINKTYPE_USB_LINUX, LINKTYPE_USB_LINUX_MMAPPED):
        hdr = 48 if linktype == LINKTYPE_USB_LINUX else 64
        if len(d) < hdr:
            return None
        uid, typ, xfer, ep, dev, bus = struct.unpack_from("<QcBBBH", d, 0)
        kind = {0: "isochronous", 1: "interrupt", 2: "control", 3: "bulk"}.get(xfer, "unknown")
        return ((bus, dev), ep, kind, len(d) > hdr, (bus, uid), typ == b"S",
                typ in (b"C", b"E"))
    if linktype == LINKTYPE_USB_DARWIN:
        if len(d) < _DARWIN_HDR:
            return None
        ids = struct.unpack("<HH", d[0x24:0x28])
        seq = struct.unpack("<I", d[0x10:0x14])[0]
        kind = _DESC_TYPES.get(d[31] & 3, "unknown")
        return (ids, d[30], kind, len(d) > _darwin_hdr_len(d), seq, d[3] == 0, d[3] == 1)
    return None


def _owner_windows(events) -> dict:
    """(bus, address) -> [(time, identity)], where identity is (vid, pid)
    from a device description fetched there, or "new" where SET_ADDRESS gave
    the address to a device being set up. Consecutive equal owners merge."""
    marks: dict = {}
    for ev in events:
        if ev["kind"] != "control":
            continue
        if ev["rt"] == 0x80 and ev["req"] == 6 and ev["wValue"] >> 8 == 1:
            blob = ev["in"]
            if len(blob) >= 12 and blob[1] == 1:
                marks.setdefault((ev["bus"], ev["dev"]), []).append(
                    (ev["t"], struct.unpack("<HH", blob[8:12])))
        elif ev["rt"] == 0x00 and ev["req"] == 5 and 0 < (ev["wValue"] & 0x7F):
            marks.setdefault((ev["bus"], ev["wValue"] & 0x7F), []).append((ev["t"], "new"))
    out = {}
    for key, items in marks.items():
        items.sort(key=lambda x: x[0])
        merged = []
        for t, ident in items:
            if not merged or merged[-1][1] != ident:
                merged.append((t, ident))
        out[key] = merged
    return out


def _owner_index(windows: list, t: float) -> int:
    """Which owner window of an address a moment falls in: 0 before the
    first mark, i for the i-th mark."""
    n = 0
    for i, (start, _ident) in enumerate(windows, 1):
        if t >= start:
            n = i
    return n


def _class_kind(ev) -> str:
    """The kind of device a class request belongs to."""
    rt, req = ev["rt"], ev["req"]
    if rt & 0x1F == 3 or rt in (0x20, 0xA0, 0x23, 0xA3):
        return "hub"
    if rt in (0x21, 0xA1) and req in (0xFE, 0xFF):
        return "storage"
    if rt in (0x21, 0xA1) and req in (0x01, 0x02, 0x03, 0x09, 0x0A, 0x0B):
        return "hid"
    return "unattributed"


def _config_kind(lines) -> str | None:
    """The kind of a configuration description that is clearly not an
    instrument's: mass storage, HID or hub interfaces."""
    classes = set(config_interfaces(lines).values())
    if 8 in classes:
        return "storage"
    if 9 in classes:
        return "hub"
    if 3 in classes:
        return "hid"
    return None


def _bot_drops(events, keys) -> tuple:
    """Mass-storage bulk-only transport at the instrument's address: the
    31-byte "USBC" command, its data phase and the 13-byte "USBS" status.
    Returns (ids of the events to drop, addresses where it was seen)."""
    drop, seen = set(), set()
    by_key: dict = {}
    for ev in events:
        if ev["kind"] == "data" and ev["type"] == "bulk" and (ev["bus"], ev["dev"]) in keys:
            by_key.setdefault((ev["bus"], ev["dev"]), []).append(ev)
    for key, evs in by_key.items():
        windows = []                       # (start, end, endpoints or None = all bulk)
        open_cbw = None
        last_close = None
        for ev in evs:
            data = ev["data"]
            if not ev["dir_in"] and len(data) == 31 and data[:4] == b"USBC":
                if open_cbw is not None:
                    windows.append((open_cbw[0], ev["t"], None))
                open_cbw = (ev["t"], ev["ep"])
            elif ev["dir_in"] and len(data) == 13 and data[:4] == b"USBS":
                if open_cbw is not None:
                    windows.append((open_cbw[0], ev["t"], {open_cbw[1], ev["ep"]}))
                else:
                    start = last_close if last_close is not None else float("-inf")
                    windows.append((start, ev["t"], None))
                open_cbw = None
                last_close = ev["t"]
        if open_cbw is not None:
            windows.append((open_cbw[0], float("inf"), None))
        if not windows:
            continue
        seen.add(key)
        for ev in evs:
            for start, end, eps in windows:
                if start <= ev["t"] <= end and (eps is None or ev["ep"] in eps):
                    drop.add(id(ev))
                    break
    return drop, seen


def attribute_records(linktype: int, recs, profile: str | None = None) -> dict:
    """1.6.2: THE decision which records of a recording are the instrument's.

    Returns {"keep": [bool per record], "devices": {(bus, address) or
    (vid, pid): info} of the instrument, "how": as instrument_selection(),
    "left_out": {kind: transfers}, "undescribed": bool}. "left_out" counts
    only what was dropped at the instrument's own address (or with its IDs),
    never the other devices' own traffic."""
    n = len(recs)
    keep = [False] * n
    result = {"keep": keep, "devices": {}, "how": "", "left_out": {},
              "undescribed": False, "keys": set()}
    if not n:
        return result
    events = _capture_events_ri(linktype, recs)
    fields = [_record_fields(linktype, d) for _ts, d in recs]
    darwin = linktype == LINKTYPE_USB_DARWIN

    # 1. Who owned each address when.
    if darwin:
        devices = {}
        for f in fields:
            if f and (f[0][0] or f[0][1]):
                devices[f[0]] = {"vid": f[0][0], "pid": f[0][1], "config": [],
                                 "how": "from the recording's own header"}
        for ev in events:
            if (ev["kind"] == "control" and ev["rt"] == 0x80 and ev["req"] == 6
                    and ev["wValue"] >> 8 == 2 and len(ev["in"]) >= 9 and ev["in"][1] == 2):
                info = devices.get((ev.get("vid"), ev.get("pid")))
                lines = parse_config_descriptor(ev["in"])
                if info is not None and lines and not info["config"] \
                        and _config_kind(lines) is None:
                    info["config"] = lines
        segs = {k: k for k in devices}
        seg_of = [f[0] if f else None for f in fields]
        wanted_keys, how = instrument_selection(devices, profile)
        result["undescribed"] = False
    else:
        dmap = device_map([{k: v for k, v in ev.items() if k != "_ri"} for ev in events])
        windows = _owner_windows(events)
        rkeys = [f[0] if f else None for f in fields]
        result["undescribed"] = undescribed_present(rkeys, dmap)
        devices = {}
        for key in list(windows):
            idents = {ident for _t, ident in windows[key]}
            if len(idents) == 1 and windows[key][0][1] != "new":
                del windows[key]           # one owner all along: one window
        for key, info in dmap.items():
            marks = windows.get(key, [])
            if not marks:
                devices[key + (0,)] = dict(info, config=[])
                continue
            for i, (_t, ident) in enumerate(marks, 1):
                if ident == "new":
                    continue
                devices[key + (i,)] = {"vid": ident[0], "pid": ident[1],
                                       "how": "from its USB description", "config": []}
        # The configuration descriptions, each to the owner of its time.
        for ev in events:
            if (ev["kind"] == "control" and ev["rt"] == 0x80 and ev["req"] == 6
                    and ev["wValue"] >> 8 == 2 and len(ev["in"]) >= 9 and ev["in"][1] == 2):
                key = (ev["bus"], ev["dev"])
                idx = _owner_index(windows.get(key, []), ev["t"])
                info = devices.get(key + (idx,))
                lines = parse_config_descriptor(ev["in"])
                # The first full description of the owner is its own; a
                # different one later is another device's (step 3).
                if info is not None and lines and not info.get("config") \
                        and _config_kind(lines) is None:
                    info["config"] = lines
        seg_of = []
        for (ts, _d), f in zip(recs, fields):
            if not f:
                seg_of.append(None)
                continue
            key = f[0]
            idx = _owner_index(windows.get(key, []), ts)
            seg_of.append(key + (idx,))
        wanted_keys, how = instrument_selection(
            {k: v for k, v in devices.items() if k[1] != 0}, profile, result["undescribed"])
    wanted = set(wanted_keys)
    result["how"] = how
    addr = (lambda s: s) if darwin else (lambda s: s[:2])
    inst_keys = {addr(s) for s in wanted}
    result["keys"] = inst_keys
    # macOS: only a recorded description narrows the endpoints; the IDs in
    # every record's header already say whose it is.
    allowed = {s: (config_endpoints(devices[s].get("config")) or None) if darwin
               else instrument_endpoints(devices[s]) for s in wanted}
    # The interfaces and classes of the instrument (for requests aimed at an
    # interface, and for class requests).
    ifaces = {s: config_interfaces(devices[s].get("config")) for s in wanted}
    left: dict = {}
    drop_reason = [None] * n

    def mark(ri, kind):
        if drop_reason[ri] is None:
            drop_reason[ri] = kind

    # 2. Per record: owner and endpoint.
    for ri, f in enumerate(fields):
        s = seg_of[ri]
        if f is None or s is None:
            continue
        if s not in wanted:
            if addr(s) in inst_keys and (darwin or s[1] != 0):
                mark(ri, "owner")
            continue
        _key, ep, kind, has_data, _tid, _st, _en = f
        eps = allowed[s]
        if kind == "control" or (kind in ("info", "unknown") and ep & 0x7F == 0):
            if kind == "unknown" and has_data:
                mark(ri, "unattributed")
                continue
            keep[ri] = True
            continue
        if ep == 0xFF or kind == "unknown":
            mark(ri, "unattributed")
            continue
        if eps is None:
            if darwin:
                keep[ri] = True            # the header's IDs are certain
            else:
                mark(ri, "unattributed")
            continue
        if ep not in eps or (kind != "info" and eps[ep] is not None and eps[ep] != kind):
            mark(ri, "endpoint")
            continue
        keep[ri] = True

    # 3. Per transfer: what the content says.
    def seg_for_event(ev):
        if darwin:
            return (ev.get("vid"), ev.get("pid"))
        ri = ev["_ri"][0]
        return seg_of[ri]

    mine = [ev for ev in events if seg_for_event(ev) in wanted]
    bot_ids, bot_keys = _bot_drops(
        mine, {(ev["bus"], ev["dev"]) for ev in mine})
    conflict = set()                    # owners with another device's traffic in them
    decisions = []
    for ev in mine:
        s = seg_for_event(ev)
        kind = None
        if id(ev) in bot_ids:
            kind = "storage"
        elif ev["kind"] == "control":
            rt, req = ev["rt"], ev["req"]
            rtype = (rt >> 5) & 3
            recip = rt & 0x1F
            classes = set(ifaces[s].values())
            if rtype == 1:
                kind = _class_kind(ev)
                if kind == "hid" and 3 in classes:
                    kind = None            # the instrument is itself a HID device
                elif kind == "unattributed" and classes - {0, 0xFF, 8, 9, 3}:
                    kind = None            # it has an interface of a standard class
            elif rtype == 0:
                eps = allowed[s]
                if recip == 2 and (ev["wIndex"] & 0x7F) and eps is not None \
                        and (ev["wIndex"] & 0xFF) not in eps:
                    kind = "endpoint"
                elif recip == 1 and ifaces[s] and (ev["wIndex"] & 0xFF) not in ifaces[s]:
                    kind = "endpoint"
                elif req == 6 and recip == 1 and (ev["wValue"] >> 8) in (0x21, 0x22) \
                        and 3 not in classes:
                    kind = "hid"
                elif req == 6 and ev["wValue"] >> 8 == 2 and len(ev["in"]) >= 9 \
                        and ev["in"][1] == 2:
                    lines = parse_config_descriptor(ev["in"])
                    own = devices[s].get("config")
                    k2 = _config_kind(lines)
                    if k2 or (own and lines and not set(lines) <= set(own)
                              and not set(own) <= set(lines)):
                        kind = k2 or "description"
        if kind:
            conflict.add(s)
        decisions.append((ev, s, kind))
    for s_key in bot_keys:
        for s in wanted:
            if addr(s) == s_key:
                conflict.add(s)
    for ev, s, kind in decisions:
        if kind is None and s in conflict and ev["kind"] == "control" \
                and ev["req"] == 6 and ev["rt"] & 0x80 and ev["wValue"] >> 8 not in (1, 2):
            kind = "unattributed"           # a string or other description: whose?
        if kind:
            for ri in ev["_ri"]:
                keep[ri] = False
                drop_reason[ri] = kind

    # 4. A transfer is kept or dropped whole.
    inst: dict = {}
    groups = []
    for ri, f in enumerate(fields):
        if f is None:
            continue
        tid, starts, ends = f[4], f[5], f[6]
        g = inst.get(tid)
        if g is None or starts:
            g = []
            groups.append(g)
            inst[tid] = g
        g.append(ri)
        if ends:
            inst.pop(tid, None)
    for g in groups:
        reasons = [drop_reason[ri] for ri in g if drop_reason[ri]]
        if not reasons and all(keep[ri] for ri in g):
            continue
        if not any(keep[ri] for ri in g):
            if reasons:
                left[reasons[0]] = left.get(reasons[0], 0) + 1
            continue
        for ri in g:
            keep[ri] = False
        kind = reasons[0] if reasons else "unattributed"
        left[kind] = left.get(kind, 0) + 1
    result["left_out"] = left
    result["devices"] = {addr(s): devices[s] for s in wanted}
    return result


def left_out_text(left: dict) -> str:
    """The plain words for what attribute_records() left out, or ""."""
    total = sum(left.values())
    if not total:
        return ""
    kinds = [LEFT_OUT_KINDS.get(k, k) for k, _v in sorted(left.items(), key=lambda kv: -kv[1])]
    word = "transfer" if total == 1 else "transfers"
    return (f"Some traffic could not be attributed to the instrument and was left out: "
            f"{total} {word} at the instrument's USB address that looked like "
            + "; ".join(kinds) + ". Nothing of it is in any file the tool writes.")


def kept_records(linktype: int, recs, profile: str | None = None) -> tuple:
    """(the instrument's records, attribute_records() result)."""
    att = attribute_records(linktype, recs, profile)
    return [r for r, k in zip(recs, att["keep"]) if k], att


# --------------------------------------------------------------------------
# 1.5: what the open driver knows about each instrument family
#
# LICENCE NOTE. This tool is MIT licensed. ArgyllCMS, where these facts come
# from, is GPL (version 2 or later). No Argyll code or table is copied here:
# the decoders below are written from scratch from the facts (request
# numbers, field order, sizes, byte order), and the comments only point at
# where ArgyllCMS 3.5.0 documents each fact (spectro/i1pro_imp.c, .h;
# i1pro3_imp.c, .h; munki_imp.c, .h; insttypes.c), so anyone can check them.
#
# Byte order differs per family: the i1Pro and i1Pro 2 use BIG-endian fields
# (i1pro_imp.c:6203-6240); the i1Pro 3 (read_ORD32_le, i1pro3_imp.c:5021)
# and the ColorMunki (munki_imp.c:441-446) use LITTLE-endian.
# --------------------------------------------------------------------------

def _be(data: bytes, start: int, size: int):
    if len(data) < start + size:
        return None
    return int.from_bytes(data[start:start + size], "big")


def _le(data: bytes, start: int, size: int):
    if len(data) < start + size:
        return None
    return int.from_bytes(data[start:start + size], "little")


def _short_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:8]


def _raw(out, inn):
    parts = []
    if out:
        parts.append(f"out={out.hex()}")
    if inn:
        parts.append(f"in={inn.hex()}")
    return " ".join(parts)


# ---- i1Pro (Rev A to D) and i1Pro 2 (Rev E) ------------------------------

I1PRO2_FLAG_SCAN = 0x0001          # i1pro_imp.h:1078
I1PRO2_FLAG_RULER_START = 0x0004   # i1pro_imp.h:1079
I1PRO2_FLAG_RULER_END = 0x0008     # i1pro_imp.h:1080
I1PRO2_ILLUMINANT_MASK = 0x0300    # i1pro_imp.h:1073-1075
I1PRO2_KNOWN_FLAGS = 0x030D
_ILLUMINANTS = {0x0000: "no light (dark reading)", 0x0100: "lamp",
                0x0200: "UV LED", 0x0300: "wavelength LED"}


def i1pro2_flag_text(flags: int) -> str:
    parts = ["scan" if flags & I1PRO2_FLAG_SCAN else "spot",
             _ILLUMINANTS[flags & I1PRO2_ILLUMINANT_MASK]]
    if flags & I1PRO2_FLAG_RULER_START:
        parts.append("RULER START")
    if flags & I1PRO2_FLAG_RULER_END:
        parts.append("RULER END")
    other = flags & ~I1PRO2_KNOWN_FLAGS & 0xFFFF
    if other:
        parts.append(f"UNKNOWN BITS 0x{other:04x}")
    return " + ".join(parts)


def _legacy_flag_text(flags: int) -> str:
    # i1pro_imp.h:984-987, the original i1Pro's one-byte flags
    parts = ["scan" if flags & 0x01 else "spot",
             "no lamp" if flags & 0x02 else "lamp",
             "normal gain" if flags & 0x04 else "high gain"]
    if flags & 0x08:
        parts.append("bit 0x08 (meaning unknown)")
    if flags & 0xF0:
        parts.append(f"UNKNOWN BITS 0x{flags & 0xF0:02x}")
    return " + ".join(parts)


def _d_setparams(out, inn):
    blob = out or inn
    if len(blob) < 7:
        return _raw(out, inn)
    return (f"integration {_be(blob, 0, 2)} clocks, lamp {_be(blob, 2, 2)} clocks, "
            f"{_be(blob, 4, 2)} readings, flags 0x{blob[6]:02x} = {_legacy_flag_text(blob[6])}")


def _d_eeprom(out, inn):
    if len(out) < 6:
        return _raw(out, inn)
    return f"address 0x{_be(out, 0, 4):x}, {_be(out, 4, 2)} bytes"


def _d_misc(out, inn):
    if len(inn) < 8:
        return _raw(out, inn)
    power = {0: "high power", 8: "low power"}.get(inn[7], f"power mode {inn[7]}")
    return (f"firmware {_be(inn, 0, 2)}, (unknown 0x{_be(inn, 2, 2):04x}), "
            f"max sensor value {_be(inn, 4, 2)}, (unknown 0x{inn[6]:02x}), {power}")


def _d_reset(out, inn):
    if not out:
        return ""
    return f"mask 0x{out[0]:02x}" + (f", second byte 0x{out[1]:02x}" if len(out) > 1 else "")


def _d_mcmode_get(out, inn):
    if len(inn) < 6:
        return _raw(out, inn)
    return (f"max mode {inn[0]}, mode {inn[1]}, (unknown {inn[2]}), sub-clock divider "
            f"{inn[3]}, integration clock {inn[4]} us, subtract mode 0x{inn[5]:02x}")


def _d_chipid(out, inn):
    return f"chip ID <hashed:{_short_hash(inn)}>" if inn else ""


def _d_trigger2(out, inn):
    if len(out) < 14:
        return _raw(out, inn)
    flags = _be(out, 12, 2)
    return (f"integration {_be(out, 0, 4)} clocks, lamp {_be(out, 4, 4)} clocks, "
            f"{_be(out, 8, 4)} readings, flags 0x{flags:04x} = {i1pro2_flag_text(flags)}")


def _d_measchar(out, inn):
    if len(inn) < 16:
        return _raw(out, inn)
    return (f"clock {_be(inn, 0, 4)} us, {_be(inn, 4, 4)} extra bands, "
            f"{_be(inn, 8, 4)} bands, sub divider {_be(inn, 12, 4)}")


def _d_i1pro_ledseq(out, inn):
    return f"light sequence of {_be(out, 0, 4)} bytes follows on 0x03" if len(out) >= 4 \
        else _raw(out, inn)


def _d_ruler(out, inn):
    return f"parameter 0x{_be(out, 0, 2):04x}" if len(out) >= 2 else _raw(out, inn)


def _d_uvvolts(out, inn):
    if len(inn) < 4:
        return _raw(out, inn)
    return f"before {_be(inn, 0, 2)}, after {_be(inn, 2, 2)}"


def _d_eesize(out, inn):
    return f"{_be(inn, 0, 4)} bytes" if len(inn) >= 4 else _raw(out, inn)


def _i1pro_trigger(req, out):
    """(flags or None, flag text, readings asked for, integration clocks)."""
    if req == 0xD4 and len(out) >= 14:
        flags = _be(out, 12, 2)
        return flags, i1pro2_flag_text(flags), _be(out, 8, 4), _be(out, 0, 4)
    return None, "trigger (parameters set earlier with 0xC1)", None, None


# request -> (name, where Argyll sends it, decoder, does Argyll's live code send it)
I1PRO_REQUESTS = {
    0xC0: ("trigger measurement (original i1Pro)", "i1pro_imp.c:11571", _raw, True),
    0xC1: ("set measurement parameters (original i1Pro)", "i1pro_imp.c:11530",
           _d_setparams, True),
    0xC2: ("get measurement parameters", "i1pro_imp.c:11465", _d_setparams, True),
    # Argyll's EEPROM write is compiled only with ENABLE_WRITE (i1pro_imp.c:11328).
    0xC3: ("write EEPROM", "i1pro_imp.c:11336", _d_eeprom, False),
    0xC4: ("read EEPROM", "i1pro_imp.c:11248", _d_eeprom, True),
    0xC9: ("get status", "i1pro_imp.c:11413", _d_misc, True),
    0xCA: ("reset", "i1pro_imp.c:11200", _d_reset, True),
    0xCF: ("set measurement clock mode", "i1pro_imp.c:11846", _raw, True),
    0xD0: ("end button handling", "i1pro_imp.c:12016", _raw, True),
    0xD1: ("get measurement clock mode", "i1pro_imp.c:11890", _d_mcmode_get, True),
    0xD2: ("get chip ID", "i1pro_imp.c:12082", _d_chipid, True),
    0xD4: ("trigger measurement (i1Pro 2)", "i1pro_imp.c:12178", _d_trigger2, True),
    0xD5: ("get measurement characteristics (i1Pro 2)", "i1pro_imp.c:12115",
           _d_measchar, True),
    # Every call of the light functions is inside #ifdef NEVER (:584, :1448, :12380).
    0xD6: ("indicator lights: sequence", "i1pro_imp.c:12331", _d_i1pro_ledseq, False),
    # i1pro2_stop_ruler is never called (i1pro_imp.c:12264).
    0xD7: ("RULER: stop tracking (?)", "i1pro_imp.c:12277", _d_ruler, False),
    0xD8: ("get UV LED voltages", "i1pro_imp.c:12241", _d_uvvolts, True),
    0xD9: ("get EEPROM size", "i1pro_imp.c:12051", _d_eesize, True),
}

# Indicator lights of the i1Pro 2 (i1pro_imp.c:12291-12317 documents it):
#   BE32 number of blocks, then per block: BE32 block length (the repeat
#   field plus the codes), BE32 repeats (0xFFFFFFFF = forever), then codes of
#   3 bytes: a light mask and a BE16 time in clocks of about 73 us.
#   Mask: 0x01 red right, 0x02 green right, 0x04 blue right,
#         0x08 red left,  0x10 green left,  0x20 blue left.
LED_CLOCK_SECONDS = 73e-6


def _rgb_name(r, g, b) -> str:
    return {(0, 0, 0): "off", (1, 0, 0): "red", (0, 1, 0): "green", (0, 0, 1): "blue",
            (1, 1, 0): "yellow", (0, 1, 1): "cyan", (1, 0, 1): "magenta",
            (1, 1, 1): "white"}[(int(bool(r)), int(bool(g)), int(bool(b)))]


def led_mask_text(mask: int) -> str:
    right = _rgb_name(mask & 0x01, mask & 0x02, mask & 0x04)
    left = _rgb_name(mask & 0x08, mask & 0x10, mask & 0x20)
    text = right if right == left else f"left {left}, right {right}"
    if mask & 0xC0:
        text += f" (unknown bits 0x{mask & 0xC0:02x})"
    return text


def decode_led_sequence(blob: bytes) -> dict:
    """Decode an i1Pro 2 light sequence. Returns {"ok", "blocks", "text", "colours"}."""
    nblocks = _be(blob, 0, 4)
    if nblocks is None or nblocks > 64:
        return {"ok": False, "blocks": [], "colours": [],
                "text": f"undecodable: {blob[:48].hex()}"}
    off = 4
    blocks = []
    for _ in range(nblocks):
        blen = _be(blob, off, 4)
        reps = _be(blob, off + 4, 4)
        if blen is None or reps is None or blen < 4 or off + 4 + blen > len(blob):
            return {"ok": False, "blocks": blocks, "colours": [],
                    "text": f"undecodable after {len(blocks)} block(s): {blob[:48].hex()}"}
        codes = []
        pos = off + 8
        while pos + 3 <= off + 4 + blen:
            codes.append((blob[pos], _be(blob, pos + 1, 2)))
            pos += 3
        blocks.append({"repeats": reps, "codes": codes})
        off += 4 + blen
    parts = []
    for blk in blocks:
        steps = ", ".join(f"{led_mask_text(m)} {c * LED_CLOCK_SECONDS * 1000:.0f} ms"
                          for m, c in blk["codes"])
        reps = "forever" if blk["repeats"] == 0xFFFFFFFF else f"x{blk['repeats']}"
        parts.append(f"[{steps}] {reps}")
    colours = sorted({led_mask_text(m) for blk in blocks for m, _c in blk["codes"]} - {"off"})
    return {"ok": True, "blocks": blocks, "text": " then ".join(parts) or "(empty)",
            "colours": colours}


# ---- i1Pro 3 and 3 Plus -------------------------------------------------

def _i1pro3_meas_flags(flags: int, reflective: bool) -> str:
    # i1pro3_imp.h:1335-1351
    parts = []
    if reflective:
        ill = flags & 0x07
        parts.append({0: "no light", 3: "lamp (all LEDs)", 4: "lamp, polarised mode"}.get(
            ill, f"light code {ill}"))
        known = 0x17
    else:
        parts.append("green wavelength LED" if flags & 0x40 else "no light")
        if flags & 0x80:
            parts.append("bit 0x80 (Argyll: white flash before integration)")
        known = 0xD0
    if flags & 0x10:
        parts.append("RULER (zebra) read")
    if flags & ~known:
        parts.append(f"UNKNOWN BITS 0x{flags & ~known:x}")
    return " + ".join(parts)


def _d3_fw(out, inn):
    if len(inn) < 6:
        return _raw(out, inn)
    n = _le(inn, 2, 4) or 0
    text = inn[6:6 + min(n, 49)].decode("ascii", "replace").strip("\x00")
    return f"firmware {inn[0]}.{inn[1]} '{text}'"


def _d3_params(out, inn):
    if len(inn) < 12:
        return _raw(out, inn)
    clk = struct.unpack("<f", inn[8:12])[0]
    return f"min integration {_le(inn, 0, 4)} clocks, clock {clk * 1e6:.3f} us"


def _d3_eeprom(out, inn):
    if len(out) < 6:
        return _raw(out, inn)
    return f"address 0x{_le(out, 0, 4):x}, {_le(out, 4, 2)} bytes"


def _d3_ledcur(out, inn):
    return "currents " + ", ".join(str(b) for b in out) if out else ""


def _d3_scanind(out, inn):
    if len(out) < 2:
        return _raw(out, inn)
    return (f"green light on after {out[0]} and off after {out[1]} units of two "
            f"minimum integration times (255 = until the end)")


def _d3_meas_refl(out, inn):
    if len(out) < 8:
        return _raw(out, inn)
    n, f = _le(out, 0, 4), _le(out, 4, 4)
    return (f"{n} readings{' (scan: until released)' if n == 0 else ''}, flags 0x{f:x} = "
            f"{_i1pro3_meas_flags(f, True)}")


def _d3_meas_emis(out, inn):
    if len(out) < 12:
        return _raw(out, inn)
    n, c, f = _le(out, 0, 4), _le(out, 4, 4), _le(out, 8, 4)
    return (f"{n} readings, integration {c} clocks, flags 0x{f:x} = "
            f"{_i1pro3_meas_flags(f, False)}")


def _d3_ledseq(out, inn):
    return f"light sequence of {_le(out, 0, 4)} bytes follows on 0x02" if len(out) >= 4 \
        else _raw(out, inn)


def _d3_lasterr(out, inn):
    return f"error code {_le(inn, 0, 4)}" if len(inn) >= 4 else _raw(out, inn)


def _i1pro3_trigger(req, out):
    if req == 0x22 and len(out) >= 8:
        f = _le(out, 4, 4)
        return f, _i1pro3_meas_flags(f, True), _le(out, 0, 4), None
    if req == 0x27 and len(out) >= 12:
        f = _le(out, 8, 4)
        return f, _i1pro3_meas_flags(f, False), _le(out, 0, 4), _le(out, 4, 4)
    return None, "trigger", None, None


I1PRO3_REQUESTS = {          # i1pro3_imp.h:1206-1220
    0x20: ("get firmware version", "i1pro3_imp.c:5007", _d3_fw, True),
    0x21: ("get parameters", "i1pro3_imp.c:5067", _d3_params, True),
    0x22: ("measure (reflective)", "i1pro3_imp.c:5459", _d3_meas_refl, True),
    0x24: ("read EEPROM", "i1pro3_imp.c:5119", _d3_eeprom, True),
    0x25: ("simulate event", "i1pro3_imp.c:5803", _raw, True),
    0x26: ("get chip ID", "i1pro3_imp.c:5170", _d_chipid, True),
    0x27: ("measure (emissive / dark)", "i1pro3_imp.c:5463", _d3_meas_emis, True),
    0x29: ("indicator lights: sequence", "i1pro3_imp.c:6162", _d3_ledseq, True),
    0x2B: ("get last error", "i1pro3_imp.c:6054", _d3_lasterr, True),
    0x2C: ("get board temperature", "i1pro3_imp.c:5292", _raw, True),
    0x2D: ("set LED currents", "i1pro3_imp.c:5217", _d3_ledcur, True),
    0x38: ("get adapter type", "i1pro3_imp.c:5253", _raw, True),
    # 1.5.5: 0x3A IS used, by every reflective measurement
    # (i1pro3_do_measure, i1pro3_imp.c:12773); 1.5.4 listed it as unused.
    0x3A: ("set tint multiplier", "i1pro3_imp.c:5398", _raw, True),
    # Defined in Argyll but never called (i1pro3_imp.c:5317).
    0x3B: ("set scan-start indicator timing", "i1pro3_imp.c:5343", _d3_scanind, False),
    0x66: ("start event reports on 0x83", "i1pro3_imp.c:5881", _raw, True),
}


# 1.5.5: the first byte of each group, as far as the first real i1Pro 3
# recording (with the tester's notes on what the lights did) shows it. Each
# name says how sure we are; Argyll's own bit notes (i1pro3_imp.c ~6080-6138)
# get 0x06 wrong (1.5.4 called it "off"), so they are no longer used to name
# a colour on their own.
I1PRO3_LIGHT_CODES = {
    0x00: "off",
    0x12: "white pulse (likely, from a real recording)",
    0x0A: "green pulse (likely, from a real recording)",
    0x06: "red pulse (likely, from a real recording)",
    0x01: "meaning unknown (guess, from Argyll's note: a white blink)",
}


def decode_i1pro3_led(blob: bytes) -> dict:
    """i1Pro 3 light sequence: groups of 3 bytes (light code, timing, count;
    count 0 = for ever), per Argyll's notes (i1pro3_imp.c:6074-6141)."""
    groups = [blob[i:i + 3] for i in range(0, len(blob) - len(blob) % 3, 3)]
    if not groups:
        return {"ok": True, "text": "off" if len(blob) < 3 else blob.hex(), "colours": []}
    parts = []
    colours = set()
    for g in groups:
        b0, b1, b2 = g[0], g[1], g[2]
        name = I1PRO3_LIGHT_CODES.get(b0, f"code 0x{b0:02x}, meaning unknown")
        for colour in ("white", "green", "red"):
            if name.startswith(colour):
                colours.add(colour)
        times = "for ever" if b2 == 0 else f"{b2} time" + ("" if b2 == 1 else "s")
        parts.append(f"{name}, timing 0x{b1:02x}, {times} [{g.hex()}]")
    return {"ok": True, "text": "; ".join(parts), "colours": sorted(colours)}


# ---- ColorMunki Photo / Design and i1Studio ------------------------------

_MUNKI_SPOS = {0: "between positions / projector", 1: "surface", 2: "calibration",
               3: "ambient"}


def _dm_trigger(out, inn):
    if len(out) < 12:
        return _raw(out, inn)
    return (f"{'lamp' if out[0] else 'no lamp'}, {'scan' if out[1] else 'spot'}, "
            f"{'high' if out[2] else 'normal'} gain, hold temperature duty {out[3]}, "
            f"integration {_le(out, 4, 4)} clocks, {_le(out, 8, 4)} readings")


def _dm_eeprom(out, inn):
    if len(out) < 8:
        return _raw(out, inn)
    return f"address 0x{_le(out, 0, 4):x}, {_le(out, 4, 4)} bytes"


def _dm_version(out, inn):
    if not inn:
        return ""
    text = inn.split(b"\x00")[0].decode("ascii", "replace")
    return f"'{text}'"


def _dm_firmware(out, inn):
    if len(inn) < 24:
        return _raw(out, inn)
    return (f"firmware {_le(inn, 0, 4)}.{_le(inn, 4, 4)}, tick {_le(inn, 8, 4)}, "
            f"min integration {_le(inn, 12, 4)}, EEPROM {_le(inn, 16, 4)} x "
            f"{_le(inn, 20, 4)}")


def _dm_status(out, inn):
    if len(inn) < 2:
        return _raw(out, inn)
    return (f"dial: {_MUNKI_SPOS.get(inn[0], f'unknown 0x{inn[0]:x}')}, button "
            f"{'pressed' if inn[1] == 1 else 'released' if inn[1] == 0 else hex(inn[1])}")


def _dm_measstate(out, inn):
    if len(inn) < 16:
        return _raw(out, inn)
    return (f"LED temperature range {_le(inn, 0, 4)}, LED temperature {_le(inn, 4, 4)}, "
            f"duty cycle {_le(inn, 8, 4)}, A/D feedback {_le(inn, 12, 4)}")


def _dm_led(out, inn):
    if len(out) < 16:
        return _raw(out, inn)
    pulses = struct.unpack("<i", out[12:16])[0]
    return (f"on {_le(out, 0, 4)} ms, off {_le(out, 4, 4)} ms, transition "
            f"{_le(out, 8, 4)} ms, pulses {'as many as possible' if pulses == -1 else pulses}")


def _munki_trigger(req, out):
    if len(out) >= 12:
        flags = (out[0] and 1) | (out[1] and 2) | (out[2] and 4)
        return flags, _dm_trigger(out, b""), _le(out, 8, 4), _le(out, 4, 4)
    return None, "trigger", None, None


MUNKI_REQUESTS = {           # munki_imp.c:8540-9100
    0x80: ("trigger measurement", "munki_imp.c:8883", _dm_trigger, True),
    0x81: ("read EEPROM", "munki_imp.c:8567", _dm_eeprom, True),
    0x85: ("get version string", "munki_imp.c:8696", _dm_version, True),
    0x86: ("get firmware parameters", "munki_imp.c:8631", _dm_firmware, True),
    0x87: ("get status (dial position, button)", "munki_imp.c:8775", _dm_status, True),
    0x8A: ("get chip ID", "munki_imp.c:8670", _d_chipid, True),
    0x8E: ("simulate event", "munki_imp.c:9088", _raw, True),
    0x8F: ("get measurement state", "munki_imp.c:8734", _dm_measstate, True),
    0x92: ("indicator light", "munki_imp.c:8840", _dm_led, True),
}


def decode_munki_event(data: bytes) -> str:
    code = _le(data, 0, 4)
    stamp = _le(data, 4, 4)
    name = {0: "none", 1: "button pressed", 2: "button released",
            0x100: "dial turned"}.get(code, f"unknown 0x{code:x}" if code is not None else "?")
    return f"{name}" + (f" at {stamp} ms" if stamp is not None else "")


_STANDARD_REQUESTS = {0: "GET_STATUS", 1: "CLEAR_FEATURE", 3: "SET_FEATURE",
                      5: "SET_ADDRESS", 6: "GET_DESCRIPTOR", 7: "SET_DESCRIPTOR",
                      8: "GET_CONFIGURATION", 9: "SET_CONFIGURATION",
                      10: "GET_INTERFACE", 11: "SET_INTERFACE", 12: "SYNCH_FRAME"}


# ---- the family table ----------------------------------------------------

FAMILIES = {
    "i1pro2": {
        "name": "i1Pro 2 (Rev E)", "short": "i1Pro 2",
        "requests": I1PRO_REQUESTS, "trigger_reqs": {0xD4, 0xC0}, "parse_trigger": _i1pro_trigger,
        "eeprom_req": 0xC4, "meas_ep": 0x82, "nsen": 134, "nsen_req": 0xD5,
        "led_req": 0xD6, "led_ep": 0x03, "led_decode": decode_led_sequence,
        "event_ep": 0x84, "event_decode": lambda d: f"button 0x{d.hex()}",
        "zebra_ep": None, "scan_flag": I1PRO2_FLAG_SCAN,
        # 0x82 readings and EEPROM, 0x84 button, 0x03 EEPROM write and lights
        # (i1pro_imp.c:11258, 11698, 11931, 11346, 12343). Argyll tells an
        # i1Pro 2 from an original i1Pro by its fifth endpoint 0x85
        # (insttypes.c:482) and never reads that endpoint.
        "argyll_eps": {0x82, 0x84, 0x03},
    },
    "i1pro": {
        "name": "original i1Pro (Rev A to D)", "short": "i1Pro",
        "requests": I1PRO_REQUESTS, "trigger_reqs": {0xC0, 0xD4},
        "parse_trigger": _i1pro_trigger,
        "eeprom_req": 0xC4, "meas_ep": 0x82, "nsen": 128, "nsen_req": None,
        "led_req": None, "led_ep": None, "led_decode": None,
        "event_ep": 0x84, "event_decode": lambda d: f"button 0x{d.hex()}",
        "zebra_ep": None, "scan_flag": None, "argyll_eps": {0x82, 0x84, 0x03},
    },
    "i1pro3": {
        "name": "i1Pro 3 / 3 Plus", "short": "i1Pro 3",
        "requests": I1PRO3_REQUESTS, "trigger_reqs": {0x22, 0x27},
        "parse_trigger": _i1pro3_trigger,
        "eeprom_req": 0x24, "meas_ep": 0x81, "nsen": 282, "nsen_req": None,
        "led_req": 0x29, "led_ep": 0x02, "led_decode": decode_i1pro3_led,
        "event_ep": 0x83,
        "event_decode": lambda d: {1: "button pressed", 2: "button released",
                                   3: "adapter or tile changed"}.get(d[0], d.hex()) if d else "",
        # 0x81 readings and EEPROM, 0x83 events, 0x84 the ruler (zebra) data,
        # 0x02 lights (i1pro3_imp.c:5130, 5609, 5895, 5746, 6175).
        "zebra_ep": 0x84, "scan_flag": None, "argyll_eps": {0x81, 0x83, 0x84, 0x02},
    },
    "munki": {
        "name": "ColorMunki Photo / Design or i1Studio", "short": "ColorMunki",
        "requests": MUNKI_REQUESTS, "trigger_reqs": {0x80}, "parse_trigger": _munki_trigger,
        "eeprom_req": 0x81, "meas_ep": 0x81, "nsen": 137, "nsen_req": None,
        "led_req": 0x92, "led_ep": None, "led_decode": None,
        "event_ep": 0x83, "event_decode": decode_munki_event,
        # 0x81 readings and EEPROM, 0x83 events (munki_imp.c:8575, 8954, 9116).
        "zebra_ep": None, "scan_flag": 2, "argyll_eps": {0x81, 0x83},
    },
    "generic": {
        "name": "X-Rite device the tool has no decoder for", "short": "device",
        "requests": {}, "trigger_reqs": set(), "parse_trigger": None,
        "eeprom_req": None, "meas_ep": None, "nsen": None, "nsen_req": None,
        "led_req": None, "led_ep": None, "led_decode": None, "event_ep": None,
        "event_decode": None, "zebra_ep": None, "scan_flag": None, "argyll_eps": set(),
    },
    # 1.6: the i1iSis chart readers (0971:2006). ArgyllCMS cannot measure with
    # them (insttypes.c has no entry), so there is no open driver to compare
    # with and no decoder: the analysis lists the traffic and asks how the
    # device talks (summarize_isis).
    "isis": {
        "name": "i1iSis chart reader (no decoder: its protocol is not known yet)",
        "short": "i1iSis",
        "requests": {}, "trigger_reqs": set(), "parse_trigger": None,
        "eeprom_req": None, "meas_ep": None, "nsen": None, "nsen_req": None,
        "led_req": None, "led_ep": None, "led_decode": None, "event_ep": None,
        "event_decode": None, "zebra_ep": None, "scan_flag": None, "argyll_eps": set(),
    },
}

# 1.6: families without an open driver to compare with, so nothing is flagged
# as "not used by the open driver".
NO_OPEN_DRIVER = ("generic", "isis")


def family_for(vid, pid, config_lines=(), events=()) -> str:
    """Which decoder fits a device (insttypes.c:440-495 for the IDs)."""
    has_85 = any("endpoint 0x85" in l for l in config_lines or ())
    if vid == 0x0971 and pid == 0x2000:
        if has_85:
            return "i1pro2"
        if config_lines:
            return "i1pro"
        codes = {e["req"] for e in events if e.get("kind") == "control"}
        if codes & {0xD4, 0xD5, 0xD8, 0xD9}:
            return "i1pro2"
        if 0xC1 in codes:
            return "i1pro"
        return "i1pro2"
    if vid == 0x0765 and pid == 0x6009:
        return "i1pro3"
    if (vid == 0x0971 and pid == 0x2007) or (vid == 0x0765 and pid == 0x6008):
        return "munki"
    if (vid, pid) in ISIS_IDS:
        return "isis"
    return "generic"


def ruler_like(data: bytes, packed: bool = False) -> str | None:
    """A plain-words note if a data stream looks like ruler position samples.

    The i1Pro 3 sends its ruler as two sensor bits per clock, four samples
    to a byte, lowest bits first (i1pro3_imp.c:13134-13140); a real movement
    changes one sensor at a time (i1pro3_imp.c:12498-12515). This only
    checks that shape; for the i1Pro 2 it proves nothing by itself.
    """
    if len(data) < 16:
        return None
    if packed:
        samples = [(b >> s) & 3 for b in data for s in (0, 2, 4, 6)]
    else:
        if max(data) > 3:
            return None
        samples = list(data)
    steps = jumps = 0
    for a, b in zip(samples, samples[1:]):
        x = a ^ b
        if x in (1, 2):
            steps += 1
        elif x == 3:
            jumps += 1
    if not packed or (steps > 8 and jumps * 4 < steps):
        how = "2-bit samples packed four to a byte" if packed else "every byte is 0 to 3"
        return (f"{how}, the shape of two-sensor position data: {steps} single steps, "
                f"{jumps} impossible jumps")
    return None


# --------------------------------------------------------------------------
# 1.5: analysing one step
# --------------------------------------------------------------------------

def _ep_key(ev) -> str:
    return f"0x{ev['ep']:02x} {ev['type']} {'IN' if ev['dir_in'] else 'OUT'}"


def analyze_step(events: list, family: str = "i1pro2") -> dict:
    """Everything the report needs about one step's events."""
    fam = FAMILIES.get(family, FAMILIES["generic"])
    table = fam["requests"]
    t0 = events[0]["t"] if events else 0.0
    nsen = fam["nsen"]
    result = {"family": family, "requests": {}, "unknown": [], "endpoints": {},
              "measurements": [], "ruler": [], "leds": [], "eeprom_bytes": 0,
              "timeline": [], "features": set(), "first_t": t0,
              "last_t": events[-1]["t"] if events else 0.0, "nsen": nsen,
              "odd_sizes": [], "ruler_like": [], "events": [], "codes": set()}
    context = None
    pending_led = False
    current = None
    # 1.6 review: for a device without a decoder nobody knows which answers
    # hold its serial number or calibration, so its answers are never shown,
    # only their sizes (the recording itself has them).
    hide_answers = family in NO_OPEN_DRIVER
    for ev in events:
        rel = ev["t"] - t0
        if ev["kind"] == "control":
            rt, req = ev["rt"], ev["req"]
            rtype = (rt >> 5) & 3
            if rtype == 0:
                name = _STANDARD_REQUESTS.get(req, f"standard request {req}")
                if req == 6:
                    name += f" (type {ev['wValue'] >> 8}, index {ev['wValue'] & 0xff})"
                result["requests"][name] = result["requests"].get(name, 0) + 1
                result["timeline"].append((rel, name))
                continue
            result["codes"].add(req)
            result["features"].add(f"request 0x{req:02X}")
            known = table.get(req) if rtype == 2 else None
            if known is None:
                kind = "class" if rtype == 1 else "vendor"
                answer = ev['in'].hex() or '-'
                if hide_answers and ev["in"]:
                    answer = f"<{len(ev['in'])} bytes, not shown>"
                text = (f"UNKNOWN {kind} request 0x{req:02X} "
                        f"{'IN' if rt & 0x80 else 'OUT'} bmRequestType=0x{rt:02x} "
                        f"wValue=0x{ev['wValue']:04x} wIndex=0x{ev['wIndex']:04x} "
                        f"wLength={ev['wLength']} out={ev['out'].hex() or '-'} "
                        f"in={answer}")
                result["unknown"].append((rel, text))
                result["timeline"].append((rel, text))
                label = f"UNKNOWN 0x{req:02X}"
                result["requests"][label] = result["requests"].get(label, 0) + 1
                continue
            name, _where, decoder, _argyll = known
            try:
                args = decoder(ev["out"], ev["in"])
            except Exception as exc:                      # noqa: BLE001
                args = f"(could not decode: {exc}; {_raw(ev['out'], ev['in'])})"
            label = f"0x{req:02X} {name}"
            result["requests"][label] = result["requests"].get(label, 0) + 1
            result["timeline"].append((rel, label + (f": {args}" if args else "")))
            if req == fam["nsen_req"] and len(ev["in"]) >= 12:
                bands = (_be(ev["in"], 4, 4) or 0) + (_be(ev["in"], 8, 4) or 0)
                if 0 < bands < 1024:
                    nsen = bands
                    result["nsen"] = nsen
            if req == fam["eeprom_req"]:
                context = "eeprom"
            elif req in fam["trigger_reqs"]:
                flags, ftext, asked, ints = fam["parse_trigger"](req, ev["out"])
                current = {"t": rel, "req": req, "flags": flags, "flag_text": ftext,
                           "nummeas": asked, "intclocks": ints, "bytes": 0,
                           "transfers": 0, "last": rel, "zebra_bytes": 0}
                if family == "i1pro3":
                    current["nsen"] = 282 if req == 0x22 else 134
                result["measurements"].append(current)
                context = "measure"
                if flags is not None:
                    result["features"].add(f"trigger 0x{req:02X} flags 0x{flags:x}")
                if family in ("i1pro2", "i1pro") and req == 0xD4 and flags is not None \
                        and flags & (I1PRO2_FLAG_RULER_START | I1PRO2_FLAG_RULER_END):
                    result["ruler"].append((rel, f"0xD4 with ruler bits: {ftext}"))
                if family == "i1pro3" and flags is not None and flags & 0x10:
                    result["ruler"].append((rel, f"0x{req:02X} asks for the ruler: {ftext}"))
            if family in ("i1pro2", "i1pro") and req == 0xD7:
                result["ruler"].append((rel, f"0xD7 sent: {args}"))
            if req == fam["led_req"]:
                if fam["led_ep"] is None:          # the request itself is the command
                    result["leds"].append((rel, {"ok": True, "text": args, "colours": []}))
                    result["features"].add("light " + args)
                else:
                    pending_led = True
            continue
        # data
        ep = ev["ep"]
        key = _ep_key(ev)
        size = len(ev["data"])
        info = result["endpoints"].setdefault(key, {"count": 0, "bytes": 0, "sizes": {},
                                                    "first": rel, "last": rel, "ep": ep})
        info["count"] += 1
        info["bytes"] += size
        info["sizes"][size] = info["sizes"].get(size, 0) + 1
        info["last"] = rel
        result["features"].add(f"data on {key}")
        foreign = ep not in fam["argyll_eps"]
        if ep == fam["zebra_ep"] and ev["dir_in"]:
            if current is not None:
                current["zebra_bytes"] += size
            note = ruler_like(ev["data"], packed=True)
            if note:
                result["ruler_like"].append((rel, key, note))
            result["timeline"].append((rel, f"ruler data on {key}: {size} bytes"))
            continue
        if foreign:
            note = ruler_like(ev["data"]) or ruler_like(ev["data"], packed=True)
            if note:
                result["ruler_like"].append((rel, key, note))
        if ep == fam["meas_ep"] and ev["dir_in"]:
            if context == "eeprom":
                result["eeprom_bytes"] += size
                result["timeline"].append((rel, f"EEPROM data on 0x{ep:02x}: {size} bytes "
                                                f"(not shown: calibration and serial)"))
                context = None
                continue
            if current is None:
                current = {"t": rel, "req": None, "flags": None, "flag_text": "no trigger seen",
                           "nummeas": None, "intclocks": None, "bytes": 0, "transfers": 0,
                           "last": rel, "zebra_bytes": 0}
                result["measurements"].append(current)
            current["bytes"] += size
            current["transfers"] += 1
            current["last"] = rel
            unit = 2 * current.get("nsen", nsen or 1)
            if size % unit:
                result["odd_sizes"].append((rel, size))
            result["timeline"].append((rel, f"readings on 0x{ep:02x}: {size} bytes"))
            continue
        if pending_led and ep == fam["led_ep"] and not ev["dir_in"]:
            dec = fam["led_decode"](ev["data"])
            result["leds"].append((rel, dec))
            result["features"].add("light " + dec["text"])
            result["timeline"].append((rel, f"LIGHTS: {dec['text']}"))
            pending_led = False
            continue
        if ep == fam["event_ep"] and ev["dir_in"]:
            text = fam["event_decode"](ev["data"])
            result["events"].append((rel, text))
            result["timeline"].append((rel, f"event on 0x{ep:02x}: {text}"))
            continue
        flag = "  <-- endpoint the open driver never uses" if foreign and \
            family not in NO_OPEN_DRIVER else ""
        if hide_answers and ev["dir_in"]:
            result["timeline"].append((rel, f"data on {key}: {size} bytes "
                                            "(from the device, not shown)"))
            continue
        result["timeline"].append((rel, f"data on {key}: {size} bytes: "
                                        f"{ev['data'][:24].hex()}{flag}"))
    for m in result["measurements"]:
        unit = 2 * m.get("nsen", result["nsen"] or 0)
        m["readings"] = m["bytes"] // unit if unit else 0
        m["duration"] = max(0.0, m["last"] - m["t"])
    return result


# Kept for 1.5's own callers and tests: the i1Pro 2 is the default family.
def analyze_i1pro_step(events: list) -> dict:
    return analyze_step(events, "i1pro2")


def _collapse_timeline(timeline: list, limit: int = 300) -> list:
    """Merge runs of the same line (for example 200 readings transfers)."""
    size_re = re.compile(r"(\d+) bytes")
    rows = []
    for rel, text in timeline:
        sig = size_re.sub("N bytes", text)
        m = size_re.search(text)
        size = int(m.group(1)) if m else 0
        if rows and rows[-1][2] == sig:
            rows[-1][3] += 1
            rows[-1][4] = rel
            rows[-1][5] += size
            continue
        rows.append([rel, text, sig, 1, rel, size])
    lines = []
    for rel, text, sig, count, last, total in rows:
        if count == 1:
            lines.append(f"{rel:9.3f}s  {text}")
        else:
            label = sig.replace("N bytes", f"{total} bytes in total")
            lines.append(f"{rel:9.3f}s  {label}  (x{count}, until {last:.3f}s)")
        if len(lines) >= limit:
            lines.append(f"   ... {len(rows) - limit} more lines not shown")
            break
    return lines


def format_step(name: str, res: dict, notes: dict | None = None) -> list:
    fam = FAMILIES.get(res["family"], FAMILIES["generic"])
    out = [f"--- {name} ---"]
    if res.get("empty"):
        out.append("  EMPTY: nothing was recorded in this step, please repeat it.")
    notes = notes or {}
    if notes.get("did"):
        out.append(f"  operator, what happened: {notes['did']}")
    if notes.get("lights"):
        out.append(f"  operator, the lights: {notes['lights']}")
    if notes.get("setting"):
        out.append(f"  operator, the program's setting: {notes['setting']}")
    if notes.get("page"):
        out.append(f"  operator, how the page moved: {notes['page']}")
    out.append(f"  length: {res['last_t'] - res['first_t']:.1f} s")
    if res["requests"]:
        out.append("  commands:")
        for label, count in sorted(res["requests"].items()):
            out.append(f"    {count:5d} x {label}")
    if res["endpoints"]:
        out.append("  endpoints that carried data:")
        for key, info in sorted(res["endpoints"].items()):
            sizes = ", ".join(f"{s} B x{c}" for s, c in sorted(info["sizes"].items(),
                                                              key=lambda kv: -kv[1])[:5])
            flag = "" if info["ep"] in fam["argyll_eps"] or res["family"] in NO_OPEN_DRIVER \
                else "   <-- NOT USED BY THE OPEN DRIVER"
            out.append(f"    {key}: {info['count']} transfers, {info['bytes']:,} bytes "
                       f"(sizes: {sizes}){flag}")
    if res["measurements"]:
        unit = res["nsen"]
        out.append("  measurements" + (f" (one reading = {2 * unit} bytes):" if unit else ":"))
        for m in res["measurements"]:
            rate = (m["readings"] / m["duration"]) if m["duration"] > 0 else 0.0
            asked = f", asked for {m['nummeas']}" if m["nummeas"] is not None else ""
            ints = f", integration {m['intclocks']} clocks" if m["intclocks"] is not None else ""
            zeb = f", ruler data {m['zebra_bytes']} bytes" if m.get("zebra_bytes") else ""
            out.append(f"    {m['t']:8.3f}s  {m['flag_text']}{asked}{ints}: "
                       f"{m['readings']} readings in {m['transfers']} transfers, "
                       f"{m['bytes']:,} bytes over {m['duration']:.2f} s"
                       + (f" (about {rate:.0f} readings/s)" if rate else "") + zeb)
    if res["odd_sizes"]:
        out.append(f"  NOTE: {len(res['odd_sizes'])} measurement transfer(s) are not a whole "
                   f"number of readings, so something else may travel inside them "
                   f"(first: {res['odd_sizes'][0][1]} bytes at {res['odd_sizes'][0][0]:.3f}s).")
    if res["ruler"]:
        out.append("  RULER COMMANDS:")
        out.extend(f"    {rel:8.3f}s  {text}" for rel, text in res["ruler"])
    if res["ruler_like"]:
        out.append("  POSSIBLE POSITION DATA:")
        for rel, key, note in res["ruler_like"][:10]:
            out.append(f"    {rel:8.3f}s  {key}: {note}")
    if res["leds"]:
        out.append("  INDICATOR LIGHTS (what the program told the light(s) to do):")
        out.extend(f"    {rel:8.3f}s  {dec['text']}" for rel, dec in res["leds"])
    if res["events"]:
        out.append(f"  instrument events: " + "; ".join(
            f"{rel:.3f}s {text}" for rel, text in res["events"][:20]))
    if res["unknown"]:
        out.append("  REQUESTS THE DECODER DOES NOT KNOW, in full:")
        out.extend(f"    {rel:8.3f}s  {text}" for rel, text in res["unknown"])
    out.append("  timeline:")
    out.extend("    " + line for line in _collapse_timeline(res["timeline"]))
    return out


def format_i1pro_step(name: str, res: dict, notes: dict | None = None) -> list:
    return format_step(name, res, notes)


# --------------------------------------------------------------------------
# 1.5: a whole session (several steps), with the comparison and verdict
# --------------------------------------------------------------------------

def load_session(path: str) -> dict | None:
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("kind") != SESSION_KIND:
        return None
    data["_dir"] = os.path.dirname(os.path.abspath(path))
    return data


def _xrite_events(path: str, profile: str | None = None, plain: bool = False):
    """(events of the kept devices, device map, check) for one file.

    profile: the session type. plain (1.6): a recording given to --analyze
    without a session; it is read as an i1iSis recording only when
    plain_file_profile() says so. For an i1iSis the analysis keeps exactly
    what the copy keeps; every other type reads the file as 1.5.5 did."""
    try:
        linktype, recs = _read_pcap(path)
    except (OSError, ValueError):
        return [], {}, check_capture(path, profile)
    events = capture_events(linktype, recs)
    devices = device_map(events)
    if profile is None and plain:
        profile = plain_file_profile(devices)
    check = check_capture(path, profile)
    if check["code"] == "unreadable":
        return [], {}, check
    # 1.6.2: the analysis reads only the records attribute_records() gives
    # the instrument, so it can never print another device's bytes or find
    # "position data" in them. Before 1.6.2 a file in which no device could
    # be identified was analysed whole.
    mine_recs, att = kept_records(linktype, recs, profile)
    events = capture_events(linktype, mine_recs)
    if linktype == LINKTYPE_USB_DARWIN:
        keys = set(att["devices"])
        devices = {k: v for k, v in devices.items()
                   if (v.get("vid"), v.get("pid")) in keys}
    else:
        devices = dict(att["devices"])
    return events, devices, check


def session_steps(paths: list) -> tuple:
    """Turn --analyze arguments into steps.

    Returns (steps, devices, checks, session); each step is
    (title, events, notes, is_control, key). A session file (session.json,
    written by the guided session) names its steps and files; a plain
    recording is one step named after the file, and a file whose name says
    "noruler" or "control" is the control. For plain files (1.6.1) the last
    item is not None but {"plain": the selection made over all files,
    "families": [(file name, its own instrument family), ...]}, and the
    devices are keyed (bus, address, file number).
    """
    steps = []
    devinfo: dict = {}
    checks = []
    session = None
    whole = []
    for path in paths:
        if os.path.isdir(path):
            cand = os.path.join(path, "session.json")
            if os.path.exists(cand):
                path = cand
        if path.endswith(".json"):
            session = load_session(path)
            continue
        whole.append(path)
    family = session.get("family") if session else None
    if session:
        base = session["_dir"]
        if not whole and session.get("whole_recording"):
            cand = os.path.join(base, session["whole_recording"])
            if os.path.exists(cand):
                whole.append(cand)
        cache: dict = {}
        for step in session.get("steps", []):
            if step.get("skipped") or step.get("kept") is False:
                continue          # 1.5.5: a take that a later take replaced
            files = [os.path.join(base, f) for f in step.get("files_xrite") or []]
            files = [f for f in files if os.path.exists(f)]
            events = []
            if files:
                for f in files:
                    evs, devs, check = _xrite_events(f, family)
                    events += evs
                    devinfo.update(devs)
                    checks.append((os.path.basename(f), check))
            elif whole and step.get("start_epoch") is not None:
                # One recording for the whole session (Wireshark by hand):
                # cut it at the times the tool noted.
                for f in whole:
                    if f not in cache:
                        cache[f] = _xrite_events(f, family)
                        devinfo.update(cache[f][1])
                        checks.append((os.path.basename(f), cache[f][2]))
                    lo, hi = step["start_epoch"], step.get("end_epoch") or 1e18
                    events += [e for e in cache[f][0] if lo <= e["t"] <= hi]
            events.sort(key=lambda e: e["t"])
            title = f"step {step.get('number', '?')}: {step.get('title', step.get('key'))}"
            if step.get("take", 1) > 1:
                title += f" (take {step['take']})"
            steps.append((title, events, {"did": step.get("notes", ""),
                                          "lights": step.get("lights", ""),
                                          "setting": step.get("setting", ""),
                                          "page": step.get("page", "")},
                          bool(step.get("control")), step.get("key", "")))
        return steps, devinfo, checks, session
    # 1.6: one decision for all the plain files together (plain_file_profile).
    # 1.6.1: a device is told apart by file, bus and address (two files can
    # hold different devices at the same address), and each file's own
    # instrument family is noted, so that recordings of different
    # instruments are never read as one (mixed_families()).
    union: dict = {}
    families = []
    for i, f in enumerate(whole):
        try:
            lt, recs = _read_pcap(f)
        except (OSError, ValueError):
            families.append((os.path.basename(f), "generic"))
            continue
        evs_all = capture_events(lt, recs)
        devs_all = device_map(evs_all)
        for key, info in devs_all.items():
            union[(i,) + tuple(key)] = info
        families.append((os.path.basename(f), _family_of(
            devs_all, evs_all, plain_file_profile(devs_all))))
    plain = plain_file_profile(union)
    for i, f in enumerate(whole):
        evs, devs, check = _xrite_events(f, plain)
        for key, info in devs.items():
            devinfo[tuple(key) + (i,)] = info
        checks.append((os.path.basename(f), check))
        low = os.path.basename(f).lower()
        control = "noruler" in low or "no-ruler" in low or "control" in low
        steps.append((os.path.basename(f), evs, {}, control, low))
    return steps, devinfo, checks, {"plain": plain, "families": families}


def distinct_devices(devinfo: dict) -> dict:
    """1.6.1: the devices to list, keyed (bus, address, ...). A session keys
    its devices by bus and address, and this returns them unchanged. Plain
    files key them by bus, address and file: the same device seen in
    several files is listed once (its entry from the last file, as before
    1.6.1), and different devices that sat at the same address in
    different files are listed each."""
    merged: dict = {}
    for key, info in devinfo.items():
        merged[(key[0], key[1], info.get("vid"), info.get("pid"))] = (key, info)
    return {key: info for key, info in merged.values()}


def _family_of(devinfo: dict, events: list, plain) -> str:
    """The instrument family of plain recordings (or of a session that does
    not name one), from their devices: "isis" when plain says so, else the
    rule of 1.5.5."""
    if plain == "isis":
        return "isis"
    devs = list(distinct_devices(devinfo).values())
    for info in devs:
        if info.get("vid") in XRITE_VIDS:
            fam = family_for(info["vid"], info["pid"], info.get("config"), events)
            if fam not in ("generic", "isis"):        # 1.5.5 knew no i1iSis
                return fam
    for info in devs:
        if info.get("guess_family"):
            fam = info["guess_family"]
            if fam in ("i1pro2", "i1pro"):
                return family_for(0x0971, 0x2000, (), events)
            return fam
    return "generic"


def session_family(devinfo: dict, steps: list, session: dict | None = None) -> str:
    """The instrument family to analyse with. A session names its own; for
    plain files (session = {"plain": ..., "families": ...} from
    session_steps, 1.6.1) the decision session_steps made for the selection
    is used, never made again from the devices that were kept."""
    if session and session.get("family") in FAMILIES:
        return session["family"]
    plain = session.get("plain") if session and "families" in session \
        else plain_file_profile(devinfo)
    all_events = [e for _n, evs, *_ in steps for e in evs]
    return _family_of(devinfo, all_events, plain)


# 1.6.1: the i1Pro and the i1Pro 2 share one USB ID and are told apart from
# details a recording may lack, so they count as one instrument here.
_SAME_INSTRUMENT = {"i1pro": "i1pro2"}


def mixed_families(session) -> list:
    """1.6.1: for plain files that come from different instruments, each
    file with its instrument family; else []. A file without any instrument
    the tool knows ("generic") does not count as a different instrument."""
    if not session or "families" not in session:
        return []
    kinds = {_SAME_INSTRUMENT.get(fam, fam) for _n, fam in session["families"]
             if fam != "generic"}
    return list(session["families"]) if len(kinds) > 1 else []


def mixed_families_text(mixed: list) -> str:
    """1.6.1: the friendly answer when plain files come from different
    instruments: each is analysed on its own, never mixed into another."""
    out = ["=" * 68, "  Instrument recording analysis", "=" * 68, "",
           "  These recordings come from different instruments:"]
    for name, fam in mixed:
        label = FAMILIES[fam]["name"] if fam != "generic" else "no instrument this tool knows"
        out.append(f"    {name}: {label}")
    out.append("")
    out.append("  " + _wrap(
        "The analysis reads one instrument at a time, so that nothing of one "
        "instrument ends up in the analysis of the other. Please analyse the "
        "recordings of each instrument on their own, for example:", 64, "  "))
    groups: dict = {}
    for name, fam in mixed:
        if fam != "generic":
            groups.setdefault(_SAME_INSTRUMENT.get(fam, fam), []).append(name)
    for names in groups.values():
        out.append("      --analyze " + " ".join(f'"{n}"' if " " in n else n for n in names))
    out.append("")
    out.append("  " + _wrap(
        "The check above still covers every file. Nothing is wrong with the "
        "recordings themselves.", 64, "  "))
    out.append("=" * 68)
    return "\n".join(out)


def is_instrument_traffic(devinfo: dict, steps: list) -> bool:
    """True when the files hold an X-Rite instrument the decoder knows."""
    return session_family(devinfo, steps) != "generic"


def is_i1pro_traffic(devinfo: dict, steps: list) -> bool:
    return is_instrument_traffic(devinfo, steps)


SESSION_PURPOSE_ANALYSIS = {
    "i1pro2": "find where the ruler data travels, how the dual scan and the lights are driven",
    "i1pro": "learn how the vendor program scans strips: rates, timing, retries",
    "i1pro3": "compare the vendor program with what the open driver sends",
    "munki": "learn how the vendor program scans strips: rates, timing, retries, the dial",
    "generic": "list the traffic raw; no decoder for this device",
    "isis": ("list the traffic step by step and find out how the program talks to the "
             "chart reader"),
}


def step_has_data(res: dict) -> bool:
    """The instrument's own requests or data on its endpoints, not only the
    USB description that every start of a recording fetches."""
    return bool(res["codes"] or res["endpoints"])


def summarize_session(paths: list) -> str:
    steps, devinfo, checks, session = session_steps(paths)
    mixed = mixed_families(session)
    if mixed:
        return mixed_families_text(mixed)
    family = session_family(devinfo, steps, session)
    if session and "families" in session:
        session = None                        # plain files: no session file
    fam = FAMILIES[family]
    out = ["=" * 68, "  Instrument recording analysis", "=" * 68, "",
           "  Reads recordings you already made. It sends NOTHING to any device.", "",
           f"  instrument family: {fam['name']}",
           f"  what this analysis looks for: {SESSION_PURPOSE_ANALYSIS[family]}"]
    if session:
        out.append(f"  session: {session.get('created', '?')}, recorded with "
                   f"{session.get('recorder', '?')}, program: "
                   f"{session.get('program') or '?'} {session.get('program_version') or ''}")
    out.append("")
    out.append("  files:")
    for name, check in checks:
        out.append(f"    {name}: {check['verdict']}")
    out.append("")
    xr = {k: v for k, v in distinct_devices(devinfo).items()
          if v.get("vid") in XRITE_VIDS or v.get("guess_family")}
    endpoints_seen = set()
    for key, info in xr.items():
        ident = (f"{info['vid']:04x}:{info['pid']:04x}" if info.get("vid") is not None
                 else "identity not recorded")
        out.append(f"  instrument at bus {key[0]}, address {key[1]}: {ident} ({info['how']})")
        for line in info.get("config") or []:
            out.append("      " + line)
            m = re.search(r"endpoint 0x([0-9a-f]{2})", line)
            if m:
                endpoints_seen.add(int(m.group(1), 16))
    if xr and not any(v.get("config") for v in xr.values()):
        out.append("      (the recording holds no USB description with the endpoint list)")
    if endpoints_seen and family not in NO_OPEN_DRIVER:
        if 0x85 in endpoints_seen and family == "i1pro2":
            out.append("  Endpoint 0x85 is listed: this is an i1Pro 2 (Rev E), the way the "
                       "open driver tells them apart.")
        out.append("  Endpoints the open driver never uses: " +
                   (", ".join(f"0x{e:02x}" for e in sorted(endpoints_seen)
                              if e not in fam["argyll_eps"]) or "none"))
    out.append("")

    results = []
    for name, events, notes, control, key in steps:
        res = analyze_step(events, family)
        # 1.5.5: a step started and stopped at once holds only the USB
        # description; it must not count as "a no-ruler control" and so on.
        if not step_has_data(res):
            res["empty"] = True
        results.append((name, res, notes, control, key))
        out.extend(format_step(name + ("  [CONTROL: no ruler]" if control else ""),
                               res, notes))
        out.append("")
    full = [r for r in results if not r[1].get("empty")]
    if family == "isis":
        # 1.6: the i1Pro parts below (ruler, swipe speed, the light decoder)
        # do not apply to a chart reader.
        out.extend(summarize_isis(results, steps, checks, session, xr))
        return "\n".join(out)

    out.append("-" * 68)
    empties = [r[0] for r in results if r[1].get("empty")]
    if empties:
        out.append("  EMPTY STEPS (nothing recorded, please repeat them): " + "; ".join(empties))
        out.append("")
    out.append("  STEPS SIDE BY SIDE")
    out.append(f"  {'step':32} {'meas':>4} {'readings':>8} {'secs':>6} {'rd/s':>5} "
               f"{'ruler':>5} {'other ep B':>10} {'lights':>6}")
    for name, res, _notes, _control, _key in results:
        ms = res["measurements"]
        reads = sum(m["readings"] for m in ms)
        secs = sum(m["duration"] for m in ms)
        rate = reads / secs if secs > 0 else 0
        other = sum(i["bytes"] for i in res["endpoints"].values()
                    if i["ep"] not in fam["argyll_eps"])
        out.append(f"  {name[:32]:32} {len(ms):>4} {reads:>8} {secs:>6.2f} {rate:>5.0f} "
                   f"{len(res['ruler']):>5} {other:>10} {len(res['leds']):>6}")
    out.append("")

    # The open driver against the recording.
    if fam["requests"]:
        seen = set().union(*(r[1]["codes"] for r in results)) if results else set()
        live = {c for c, v in fam["requests"].items() if v[3]}
        out.append("  THE OPEN DRIVER (ArgyllCMS) AGAINST THIS RECORDING:")
        both = sorted(seen & live)
        never = sorted(c for c in seen if c not in live)
        unused = sorted(live - seen)
        out.append("    requests both use: " + (", ".join(f"0x{c:02X}" for c in both) or "none"))
        out.append("    requests the open driver never sends: " +
                   (", ".join(f"0x{c:02X} ({fam['requests'][c][0]})" if c in fam["requests"]
                              else f"0x{c:02X} (unknown)" for c in never) or "none"))
        out.append("    open-driver requests that do not occur here: " +
                   (", ".join(f"0x{c:02X}" for c in unused) or "none"))
        out.append("")

    controls = [r for r in full if r[3]]
    if controls:
        base = set().union(*(r[1]["features"] for r in controls))
        out.append("  ONLY WITH THE RULER (seen in a ruler step, never in the no-ruler control):")
        anything = False
        for name, res, _n, control, key in results:
            if control or "scan" not in key:
                continue
            extra = sorted(f for f in res["features"] - base if not f.startswith("light "))
            if extra:
                anything = True
                out.append(f"    {name}: " + "; ".join(extra))
        if not anything:
            out.append("    nothing: the scan steps use the same commands and endpoints as "
                       "the control.")
        out.append("")

    fast = [r for r in full if "fast" in r[4]]
    slow = [r for r in full if "slow" in r[4]]
    if fast and slow:
        def stats(r):
            ms = [m for m in r[1]["measurements"] if m["readings"]]
            reads = sum(m["readings"] for m in ms)
            secs = sum(m["duration"] for m in ms)
            ints = sorted({m["intclocks"] for m in ms if m["intclocks"] is not None})
            return reads, secs, ints, sorted(r[1]["features"])
        fr, fs, fi, ff = stats(fast[-1])
        sr, ss, si, sf = stats(slow[-1])
        out.append("  FAST AGAINST SLOW SWIPE:")
        out.append(f"    fast: {fr} readings in {fs:.2f} s, integration clocks {fi or '?'}")
        out.append(f"    slow: {sr} readings in {ss:.2f} s, integration clocks {si or '?'}")
        diff = sorted(set(ff) ^ set(sf))
        out.append("    what differs apart from the length: " +
                   ("; ".join(diff[:12]) if diff else "nothing in the commands"))

        # 1.5.5: in the first real session the "slow" swipes were as quick as
        # the fast ones. Readings per swipe grow with the time a swipe takes.
        def per_swipe(r):
            counts = [m["readings"] for m in r[1]["measurements"] if m["readings"] > 50]
            return sum(counts) / len(counts) if counts else 0
        fpm, spm = per_swipe(fast[-1]), per_swipe(slow[-1])
        if fpm and spm and spm < 1.5 * fpm:
            out.append(f"    NOTE: a slow swipe took about as many readings as a fast one "
                       f"({spm:.0f} against {fpm:.0f} per swipe), so it was most likely not "
                       "slower. Please repeat the slow step, taking 3 to 5 seconds for the "
                       "strip.")
        out.append("")

    out.append("  THE LIGHTS' LANGUAGE (light commands per step, in order):")
    any_led = False
    for name, res, notes, _c, _k in results:
        if res["leds"]:
            any_led = True
            out.append(f"    {name}: " + " | ".join(d["text"] for _r, d in res["leds"]))
            if notes.get("lights"):
                out.append(f"        operator saw: {notes['lights']}")
        elif notes.get("lights"):
            out.append(f"    {name}: no light command recorded; operator saw: {notes['lights']}")
    if not any_led:
        out.append("    No light command in any step. If the operator saw the light(s) "
                   "change, the program drives them some other way: look at the unknown "
                   "requests and at data on endpoints the open driver never uses, at the "
                   "times the operator describes.")
    out.append("")

    all_ms = [m for _n, r, *_ in results for m in r["measurements"]]
    zero = any(c["code"] == "all-zero" for _n, c in checks)
    have_traffic = bool(results) and any(r[1]["requests"] for r in results) and not zero
    scan_ms = [m for m in all_ms if m["readings"] > 1]
    yes = {True: "yes", False: "NO"}
    out.append("=" * 68)
    out.append("  DOES THIS RECORDING HOLD WHAT WE NEED?")
    if session and session.get("only_steps"):
        out.append("    (only steps " + ", ".join(str(n) for n in session["only_steps"])
                   + " were recorded in this session; the others are in the earlier one,")
        out.append("    so a NO below can be fine)")
    out.append(f"    real instrument traffic, not zeros ... {yes[have_traffic]}")
    out.append(f"    USB description (endpoint list) ...... "
               f"{yes[any(v.get('config') for v in xr.values())]}")
    out.append(f"    measurements with readings ........... {yes[bool(scan_ms)]}")
    out.append(f"    a fast and a slow swipe .............. {yes[bool(fast and slow)]}")
    if family in ("i1pro2", "i1pro3"):
        out.append(f"    a dual-scan step ..................... "
                   f"{yes[any('dual' in r[4] for r in full)]}")
        out.append(f"    a no-ruler control ................... {yes[bool(controls)]}")
    if family in ("i1pro2", "i1pro3", "munki"):
        out.append(f"    light commands ....................... {yes[any_led]}")
    out.append("")
    ruler_cmd = any(r[1]["ruler"] for r in results)
    other_ep = any(i["ep"] not in fam["argyll_eps"] for r in results
                   for i in r[1]["endpoints"].values())
    unknown = any(r[1]["unknown"] for r in results)
    if family == "generic":
        out.append("  In plain words: the tool has no decoder for this device; everything is "
                   "listed raw above.")
    elif family == "i1pro2" and (ruler_cmd or other_ep or unknown):
        found = []
        if ruler_cmd:
            found.append("ruler commands (0xD7, or ruler bits in 0xD4)")
        if other_ep:
            found.append("data on endpoints the open driver never uses")
        if unknown:
            found.append("requests the open driver does not know")
        out.append("  In plain words: the recording shows " + ", and ".join(found) +
                   ". These are the places to look for how the program uses the ruler.")
    elif family == "i1pro2" and scan_ms:
        out.append("  In plain words: no sign of ruler traffic. No 0xD7, no ruler bits, no "
                   "data on endpoints the open driver never uses, no unknown requests. "
                   "Either the program did not use the ruler here, or its position data "
                   "travels inside the normal measurement transfers; compare the transfer "
                   "sizes and counts above.")
    elif scan_ms:
        out.append("  In plain words: the recording holds measurements to compare; "
                   + ("it also shows requests or endpoints the open driver does not use, "
                      "listed above." if (unknown or other_ep) else
                      "it uses only requests and endpoints the open driver knows."))
    else:
        out.append("  In plain words: there is no measurement with readings in these files "
                   "yet.")
    if not have_traffic:
        out.append("  The files hold no usable instrument traffic"
                   + (" (every data byte is zero)." if zero else "."))
    out = [line if not line.startswith("  In plain words") and not line.startswith(
        "  The files hold") else "  " + _wrap(line.strip(), 64, "  ") for line in out]
    out.append("=" * 68)
    return "\n".join(out)


_PRINTABLE = set(range(32, 127)) | {9, 10, 13}


def text_share(data: bytes) -> float:
    """How much of a byte string is readable text (0.0 to 1.0)."""
    return sum(1 for b in data if b in _PRINTABLE) / len(data) if data else 0.0


def looks_like_ftdi(events: list) -> dict:
    """1.6: signs of a USB-to-serial chip of the FTDI kind, the way the i1iO
    table talks (section 1.5.4): FTDI's own vendor requests, and IN packets
    that start with two status bytes (the second one 0x60 when idle)."""
    reqs = {}
    for ev in events:
        if ev["kind"] == "control" and ev["rt"] in (0x40, 0xC0) and ev["req"] in _FTDI_REQUESTS:
            name = _FTDI_REQUESTS[ev["req"]]
            reqs[name] = reqs.get(name, 0) + 1
    ins = [ev["data"] for ev in events if ev["kind"] == "data" and ev["dir_in"]]
    status = sum(1 for d in ins if len(d) >= 2 and d[1] & 0xF0 == 0x60)
    return {"requests": reqs, "in_packets": len(ins), "status_packets": status,
            "likely": bool(reqs) and bool(ins) and status >= 0.9 * len(ins)}


def isis_program_lines(events: list, limit: int = 20) -> list:
    """Up to `limit` distinct readable lines the PROGRAM sent to the device.
    Only the computer's side: the device's answers can hold its serial number
    and are never shown as text."""
    lines: list = []
    for ev in events:
        if ev["kind"] != "data" or ev["dir_in"]:
            continue
        for part in re.split(rb"[\r\n]+", ev["data"]):
            part = part.strip()
            if len(part) < 2 or text_share(part) < 1.0:
                continue
            text = part.decode("ascii", "replace")[:60]
            if text not in lines:
                lines.append(text)
            if len(lines) >= limit:
                return lines
    return lines


def summarize_isis(results: list, steps: list, checks: list, session, xr: dict) -> list:
    """1.6: the end of the analysis for an i1iSis chart reader. There is no
    decoder: the report lists what happened in each step, says how the
    program seems to talk to the device, and whether the session holds what
    we need."""
    out = ["-" * 68]
    empties = [r[0] for r in results if r[1].get("empty")]
    if empties:
        out.append("  EMPTY STEPS (nothing recorded, please repeat them): " + "; ".join(empties))
        out.append("")
    out.append("  STEPS SIDE BY SIDE")
    out.append(f"  {'step':34} {'secs':>6} {'requests':>8} {'to iSis B':>10} "
               f"{'from iSis B':>11} {'transfers':>9}")
    for name, res, _notes, _control, _key in results:
        to_dev = sum(i["bytes"] for k, i in res["endpoints"].items() if k.endswith("OUT"))
        from_dev = sum(i["bytes"] for k, i in res["endpoints"].items() if k.endswith(" IN"))
        transfers = sum(i["count"] for i in res["endpoints"].values())
        requests = sum(res["requests"].values())
        secs = res["last_t"] - res["first_t"]
        out.append(f"  {name[:34]:34} {secs:>6.1f} {requests:>8} {to_dev:>10,} "
                   f"{from_dev:>11,} {transfers:>9}")
    out.append("")

    events = [e for _n, evs, *_ in steps for e in evs]
    ftdi = looks_like_ftdi(events)
    out_bytes = b"".join(e["data"] for e in events if e["kind"] == "data" and not e["dir_in"])
    in_bytes = b"".join(e["data"] for e in events if e["kind"] == "data" and e["dir_in"])
    if ftdi["likely"]:
        in_bytes = b"".join(io_ftdi_payload(e["data"]) for e in events
                            if e["kind"] == "data" and e["dir_in"])
    out.append("  HOW DOES THE PROGRAM TALK TO THE iSis?")
    if ftdi["requests"]:
        out.append("    requests of the kind a USB-to-serial chip (FTDI) understands: " +
                   ", ".join(f"{n} x{c}" for n, c in sorted(ftdi["requests"].items())))
    if ftdi["likely"]:
        out.append(f"    {ftdi['status_packets']} of {ftdi['in_packets']} answers start with "
                   "the two status bytes such a chip adds.")
        out.append("    So it LIKELY talks through a USB-to-serial chip, like the i1iO table.")
    else:
        out.append("    no clear sign of a USB-to-serial chip.")
    if out_bytes:
        share = text_share(out_bytes)
        out.append(f"    bytes the program sent: {len(out_bytes):,}, of which {share:.0%} "
                   "readable text")
        if share >= 0.9:
            lines = isis_program_lines(events)
            out.append("    the first different lines the program sent (computer's side only):")
            out.extend(f"      {line}" for line in lines)
    else:
        out.append("    the program sent no data on the iSis's own endpoints (only requests).")
    if in_bytes:
        out.append(f"    bytes the iSis sent back: {len(in_bytes):,}, of which "
                   f"{text_share(in_bytes):.0%} readable text (not shown: they can hold "
                   "its serial number)")
    out.append("")

    out.append("  WHAT THE OPERATOR SAW")
    any_note = False
    for name, _res, notes, _c, _k in results:
        seen = [f"{label}: {notes[k]}" for k, label in
                (("lights", "light"), ("page", "page"), ("setting", "setting"))
                if notes.get(k)]
        if seen:
            any_note = True
            out.append(f"    {name}: " + "; ".join(seen))
    if not any_note:
        out.append("    no notes about the light or the page.")
    out.append("")

    zero = any(c["code"] == "all-zero" for _n, c in checks)
    full = [r for r in results if not r[1].get("empty")]
    have_traffic = bool(full) and not zero
    yes = {True: "yes", False: "NO"}
    keys = {r[4] for r in full}
    out.append("=" * 68)
    out.append("  DOES THIS RECORDING HOLD WHAT WE NEED?")
    if session and session.get("only_steps"):
        out.append("    (only steps " + ", ".join(str(n) for n in session["only_steps"])
                   + " were recorded in this session; the others are in the earlier one,")
        out.append("    so a NO below can be fine)")
    out.append(f"    real traffic of the iSis, not zeros ... {yes[have_traffic]}")
    out.append(f"    USB description (endpoint list) ...... "
               f"{yes[any(v.get('config') for v in xr.values())]}")
    out.append(f"    one page measured, single scan ....... {yes['page-single' in keys]}")
    out.append(f"    the same page, dual scan ............. {yes['page-dual' in keys]}")
    out.append(f"    the same page, fed a little crooked .. {yes['page-skewed' in keys]}")
    out.append(f"    a page that fails on purpose ......... {yes['blank-page' in keys]}")
    out.append(f"    notes on how the page moved .......... "
               f"{yes[any(r[2].get('page') for r in results)]}")
    out.append("")
    if not have_traffic:
        line = ("In plain words: the files hold no usable traffic of the iSis"
                + (" (every data byte is zero)." if zero else "."))
    elif "page-single" in keys:
        line = ("In plain words: the recording shows the program and the iSis at work on a "
                "page. There is no decoder for the iSis yet, so everything is listed raw "
                "above; the steps side by side show where the measuring happens.")
    else:
        line = ("In plain words: there is traffic, but no measured page yet. The step "
                "\"feed one page, single scan\" is the most important one.")
    out.append("  " + _wrap(line, 64, "  "))
    out.append("=" * 68)
    return out


def summarize_i1pro_session(paths: list) -> str:
    return summarize_session(paths)


# --------------------------------------------------------------------------
# 1.5.4: the i1iO table (0971:2004)
#
# Adapted from our own decoder written for the first two real recordings
# (issue #129: i1Profiler 3.8.6 on a Mac, an i1iO 2 with an i1Pro 2 on it).
# What those recordings showed, with the same three words for how sure we
# are that the decode notes use:
#   * The table talks through an FTDI USB-to-serial chip (certain for FTDI:
#     the vendor requests are FTDI's own). Bulk OUT carries text lines to the
#     table; bulk IN brings its answers, and every 64-byte USB packet from
#     the chip starts with 2 status bytes that are not data (certain).
#   * One command per line, ended by CR (certain). Lines to the table start
#     with ';'; the table answers every one with ':!' (accepted) and ':$'
#     (done, with a status digit and any data).
#   * The last two characters of every line are a checksum: the two's
#     complement of the 8-bit sum of all characters before them (certain:
#     it fits all 2,475 lines in both recordings).
# What each command MEANS is mostly not proved. Every description below
# carries its word (certain, likely, guess), a meaning nobody knows says
# "meaning unknown", and a command not seen in the first recordings is
# flagged as new. The raw line is always printed too, so anyone can check.
# --------------------------------------------------------------------------

IO_TABLE_PID = 0x2004
IO_PRO_PID = 0x2000
_HEX2_RE = re.compile(r"[0-9a-fA-F]{2}")

# Commands seen in the first recordings: id -> (what it does, how sure).
IO_COMMANDS = {
    "s0": "status query (always answered 0 so far; meaning: likely)",
    "a1": "identification, sent when the table is opened (guess: hardware and "
          "firmware version)",
    "k2": "information k2 (meaning unknown)",
    "a0": "information a0 (meaning unknown)",
    "u8": "read the table's memory",
    "i1": "home / reference run: the arm goes to its parking place (likely)",
    "p0": "where is the measuring opening? (likely)",
    "p1": "where is the point under the alignment sight? read after a button "
          "press (likely)",
    "m0": "travel move (certain)",
    "m1": "move out to the hand-alignment start (seen so far; how it differs "
          "from m0: meaning unknown)",
    "m2": "scan move along a row while the i1Pro measures (certain)",
    "a3": "ask for the profile of the running move (likely)",
    "c3": "c3, sent as each scan starts (guess: head down)",
    "c4": "c4, sent before every travel to a new row (guess: head up)",
    "d1": "d1, sent before every scan (guess: a start delay in milliseconds)",
    "f0": "leave hand-alignment mode, sent at the very end (likely)",
    "f1": "free the arm, so it can be pushed by hand for alignment (likely)",
    "f3": "f3 (meaning unknown)",
    "f4": "is the arm free? 00 = motors in control, 01 = free (likely)",
}
IO_MOVING = ("m0", "m1", "m2", "i1")


def io_ftdi_payload(transfer: bytes, packet: int = 64) -> bytes:
    """Data from the FTDI chip: drop the 2 status bytes at the start of
    every 64-byte USB packet (a long transfer holds several packets)."""
    return b"".join(transfer[i + 2:i + packet] for i in range(0, len(transfer), packet))


def io_checksum(body: str) -> str:
    """The checksum a line must end with: two's complement of the byte sum."""
    return f"{(-sum(body.encode('latin-1', 'replace'))) & 0xFF:02x}"


def io_checksum_ok(line: str) -> bool:
    """Sum of every character (the start character included) plus the
    checksum byte is 0 modulo 256."""
    if len(line) < 3 or not _HEX2_RE.fullmatch(line[-2:]):
        return False
    return (sum(line[:-2].encode("latin-1", "replace")) + int(line[-2:], 16)) & 0xFF == 0


def _io_s16(text: str) -> int:
    v = int(text, 16)
    return v - 0x10000 if v & 0x8000 else v


def io_table_keys(events: list, devices: dict) -> set:
    """(bus, address) of the table: by its USB IDs (in the macOS header or
    the recorded USB description), or, when the recording holds neither, by
    a line with a correct checksum sent to it. A replug gives a new address;
    every one is kept."""
    keys = set()
    for key, info in devices.items():
        if info.get("vid") == XRITE_VID and info.get("pid") == IO_TABLE_PID:
            keys.add(key)
    for ev in events:
        key = (ev["bus"], ev["dev"])
        if ev.get("vid") == XRITE_VID and ev.get("pid") == IO_TABLE_PID:
            keys.add(key)
        elif (ev["kind"] == "data" and not ev["dir_in"] and ev["data"][:1] == b";"
              and key not in keys):
            text = ev["data"].decode("latin-1")
            if any(io_checksum_ok(part) for part in text.split("\r") if part.startswith(";")):
                keys.add(key)
    return keys


def io_pro_keys(events: list, devices: dict, table: set) -> set:
    """(bus, address) of the i1Pro mounted on the table."""
    keys = set()
    for key, info in devices.items():
        if key in table:
            continue
        if (info.get("vid") == XRITE_VID and info.get("pid") == IO_PRO_PID) \
                or info.get("guess_family") in ("i1pro2", "i1pro"):
            keys.add(key)
    for ev in events:
        if ev.get("vid") == XRITE_VID and ev.get("pid") == IO_PRO_PID:
            keys.add((ev["bus"], ev["dev"]))
    return keys - table


def io_table_lines(events: list, keys: set) -> list:
    """The table's serial conversation as lines, in the order they ended:
    [{"t": time of the first byte, "t_end": time of the CR, "who": "host" or
    "table", "line", "ok": checksum right}]. A line still open when the
    recording ends is kept, marked "unfinished"."""
    bufs = {False: bytearray(), True: bytearray()}
    first = {False: None, True: None}
    lines = []
    for ev in events:
        if ev["kind"] != "data" or (ev["bus"], ev["dev"]) not in keys:
            continue
        inbound = ev["dir_in"]
        payload = io_ftdi_payload(ev["data"]) if inbound else ev["data"]
        for b in payload:
            if first[inbound] is None:
                first[inbound] = ev["t"]
            if b == 0x0D:
                text = bufs[inbound].decode("latin-1")
                if text:
                    lines.append({"t": first[inbound], "t_end": ev["t"],
                                  "who": "table" if inbound else "host", "line": text,
                                  "ok": io_checksum_ok(text)})
                bufs[inbound].clear()
                first[inbound] = None
            elif b != 0x0A:
                bufs[inbound].append(b)
    for inbound in (False, True):
        if bufs[inbound]:
            text = bufs[inbound].decode("latin-1")
            lines.append({"t": first[inbound], "t_end": first[inbound],
                          "who": "table" if inbound else "host", "line": text,
                          "ok": False, "unfinished": True})
    return lines


def io_describe_command(line: str) -> str:
    """Plain words for a line sent to the table (';' id arguments checksum)."""
    cid, args = line[1:3], line[3:-2]
    if cid in ("m0", "m1", "m2") and len(args) == 12:
        try:
            x, y, v = _io_s16(args[0:4]), _io_s16(args[4:8]), int(args[8:12], 16)
        except ValueError:
            return IO_COMMANDS[cid] + f" (arguments {args})"
        return (f"to X={x} Y={y} at speed {v}: {IO_COMMANDS[cid]}; "
                f"{x / 10:.1f}, {y / 10:.1f} mm if the unit is 0.1 mm (likely)")
    if cid == "u8" and len(args) == 12:
        try:
            return (f"read the table's memory at 0x{int(args[:8], 16):X}, "
                    f"{int(args[8:], 16)} bytes (certain)")
        except ValueError:
            pass
    if cid == "d1" and len(args) == 4:
        try:
            return f"{IO_COMMANDS['d1']}: {int(args, 16)}"
        except ValueError:
            pass
    if cid in IO_COMMANDS:
        return IO_COMMANDS[cid] + (f" (arguments {args})" if args else "")
    return f"<-- NEW: command {cid!r} was not in the first recordings" + \
        (f" (arguments {args})" if args else "")


def io_describe_reply(line: str) -> str:
    """Plain words for a ':$' answer (':$' id status data checksum)."""
    cid, status, data = line[2:4], line[4:5], line[5:-2]
    text = "done, status 0" if status == "0" else \
        f"done, status {status}  <-- NOT 0 (meaning unknown; only 0 and, once, 3 seen so far)"
    try:
        if cid in ("p0", "p1") and len(data) == 8:
            return f"{text}: X={_io_s16(data[:4])} Y={_io_s16(data[4:])}"
        if cid == "a3" and len(data) == 20:
            return (f"{text}: {int(data[:8], 16)} (meaning: guess), "
                    f"{int(data[8:16], 16)} ms of travel and speed {int(data[16:], 16)} "
                    "(certain)")
    except ValueError:
        pass
    if cid == "u8":
        return f"{text}: {len(data) // 2} bytes of the table's memory"
    if cid == "f4" and data in ("00", "01"):
        return f"{text}: {data} (" + ("motors in control" if data == "00" else "arm free") \
            + ", likely)"
    return f"{text}" + (f", data {data}" if data else "")


def io_redact(line: str, u8_addr) -> str:
    """Hide the table's serial number. It sits in the table's memory at
    0x604C (4 bytes, certain: it is the same number as the USB serial), and
    i1Profiler reads it with u8. Replaced by <serial> unless --no-redact."""
    if not REDACT or not line.startswith(":$u8") or u8_addr is None:
        return line
    lo, hi = 0x604C, 0x6050
    data_start = 5                       # after ':$u8' and the status digit
    out = line
    nbytes = max(0, (len(line) - 2 - data_start) // 2)
    if u8_addr < hi and u8_addr + nbytes > lo:
        a = data_start + 2 * max(0, lo - u8_addr)
        b = data_start + 2 * min(nbytes, hi - u8_addr)
        out = line[:a] + "<serial>" + line[b:]
    return out


_FTDI_REQUESTS = {0x00: "reset", 0x01: "set modem control", 0x02: "set flow control",
                  0x03: "set baud rate", 0x04: "set data format", 0x09: "set latency timer",
                  0x0A: "get latency timer"}


def io_describe_ftdi(ev: dict) -> str:
    """FTDI's own vendor requests to the table's USB chip."""
    req, val, idx = ev["req"], ev["wValue"], ev["wIndex"]
    if (ev["rt"] >> 5) & 3 == 0:
        name = _STANDARD_REQUESTS.get(req, f"standard request {req}")
        return f"USB {name}"
    name = _FTDI_REQUESTS.get(req)
    if name is None:
        return (f"<-- NEW: vendor request 0x{req:02X} (wValue 0x{val:04X}, "
                f"wIndex 0x{idx:04X})")
    if req == 0x00:
        what = {0: "reset", 1: "empty the receive buffer", 2: "empty the send buffer"}
        return f"FTDI {what.get(val, f'reset 0x{val:04X}')}"
    if req == 0x03:
        div = val & 0x3FFF
        approx = f", about {3000000 // div:,} baud" if div and not (val >> 14) else ""
        return f"FTDI set baud rate (divisor {div}{approx})"
    if req == 0x04:
        parity = {0: "no parity", 1: "odd parity", 2: "even parity", 3: "mark parity",
                  4: "space parity"}.get((val >> 8) & 7, "parity ?")
        stop = {0: "1 stop bit", 1: "1.5 stop bits", 2: "2 stop bits"}.get((val >> 11) & 3, "?")
        return f"FTDI set data format: {val & 0xFF} data bits, {parity}, {stop}"
    return f"FTDI {name} (0x{val:04X})"


def _io_pro_text(ev: dict) -> str | None:
    """One line for an event of the i1Pro on the table."""
    if ev["kind"] == "control":
        if (ev["rt"] >> 5) & 3 == 0:
            return None
        known = I1PRO_REQUESTS.get(ev["req"])
        if known is None:
            return f"i1Pro request 0x{ev['req']:02X} {_raw(ev['out'], ev['in'])}"
        name, _where, decoder, _live = known
        try:
            args = decoder(ev["out"], ev["in"])
        except Exception:                                 # noqa: BLE001
            args = _raw(ev["out"], ev["in"])
        if ev["req"] in (0xC4, 0xC3):                    # EEPROM: address only
            args = _d_eeprom(ev["out"], b"")
        return f"i1Pro {name}" + (f": {args}" if args else "")
    if ev["ep"] == 0x84 and ev["dir_in"]:
        return f"i1Pro BUTTON pressed (interrupt 0x84, value 0x{ev['data'].hex()})"
    direction = "from" if ev["dir_in"] else "to"
    return f"i1Pro data {direction} 0x{ev['ep']:02x}: {len(ev['data'])} bytes"


def io_steps_from_report(text: str, t0_abs: float) -> dict | None:
    """The operator's steps from a probe report, as absolute times.

    1.5.4 reports carry "session start (UTC epoch seconds)", so the times
    are exact. Older reports carry only the local clock time; then the time
    zone is taken as the whole quarter hour that puts the recording's first
    packet 0 to 15 minutes after the session start, which is approximate."""
    m = re.search(r"Stage 2: annotated capture timeline\n=+\n(.*?)(?:\n=====|\Z)", text, re.S)
    if not m:
        return None
    body = m.group(1)
    exact = re.search(r"session start \(UTC epoch seconds\): ([\d.]+)", body)
    if exact:
        start = float(exact.group(1))
    else:
        iso = re.search(r"session start \(monotonic zero\): (\S+)", body)
        if not iso:
            return None
        try:
            naive = datetime.datetime.fromisoformat(iso.group(1)).replace(
                tzinfo=datetime.timezone.utc).timestamp()
        except ValueError:
            return None
        diff = t0_abs - naive
        start = naive + round((diff - 450) / 900) * 900
    steps, marks = [], []
    for line in body.splitlines():
        sm = re.match(r"^(\S[^:\n]*?): t=\s*(-?[\d.]+)s \.\.\s*(-?[\d.]+)s", line)
        if sm:
            steps.append({"name": sm.group(1), "start": start + float(sm.group(2)),
                          "end": start + float(sm.group(3))})
            continue
        sk = re.match(r"^(\S[^:\n]*?): SKIPPED", line)
        if sk:
            steps.append({"name": sk.group(1), "skipped": True})
            continue
        mk = re.match(r"^\s+mark: (.+?) at t=\s*(-?[\d.]+)s", line)
        if mk:
            marks.append({"what": mk.group(1), "t": start + float(mk.group(2))})
    return {"steps": steps, "marks": marks, "exact": bool(exact), "start": start}


def io_step_title(name: str) -> str:
    return re.sub(r"\s*\(take \d+\)$", "", name)


def io_step_verdict(commands: int, moving: int, expect: bool = True) -> str:
    """What the check says about one step. expect: the step is one where
    i1Profiler must talk to the table (all of the 1.5.4 steps)."""
    word = "command" if commands == 1 else "commands"
    if not expect:
        return f"{commands} {word} to the table"
    if commands == 0:
        return "no table command was recorded in this step: please repeat it"
    if moving == 0:
        return (f"this step recorded {commands} {word} to the table, but none that moves "
                "the arm: if the arm moved in this step, please repeat it")
    return f"this step recorded {commands} {word} to the table: good"


def io_count_commands(lines: list, start: float, end: float) -> tuple:
    """(commands, moving commands) sent to the table between two times."""
    sent = [l for l in lines if l["who"] == "host" and start <= l["t"] <= end]
    return len(sent), sum(1 for l in sent if l["line"][1:3] in IO_MOVING)


def io_capture(path: str) -> dict | None:
    """Everything about the table in one recording, or None if there is no
    table in it."""
    try:
        linktype, recs = _read_pcap(path)
    except (OSError, ValueError):
        return None
    if not recs:
        return None
    events = capture_events(linktype, recs)
    devices = device_map(events)
    table = io_table_keys(events, devices)
    if not table:
        return None
    pro = io_pro_keys(events, devices, table)
    by_id = any((info.get("vid"), info.get("pid")) == (XRITE_VID, IO_TABLE_PID)
                for key, info in devices.items() if key in table) or any(
        (ev.get("vid"), ev.get("pid")) == (XRITE_VID, IO_TABLE_PID) for ev in events)
    return {"path": path, "t0": recs[0][0], "events": events, "table": table, "pro": pro,
            "lines": io_table_lines(events, table), "linktype": linktype, "by_id": by_id}


def find_report_for(path: str) -> str | None:
    """The probe report that names this recording, in the same folder."""
    folder = os.path.dirname(os.path.abspath(path))
    name = os.path.basename(path)
    names = {name, name.replace("-xrite.pcap", "-full.pcap")}
    for cand in sorted(glob.glob(os.path.join(folder, "chromiq-io-probe-*.txt")), reverse=True):
        try:
            with open(cand, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        if any(n in text for n in names):
            return cand
    return None


def _report_naming(path: str, reports: list) -> str | None:
    """Of the reports given after --analyze, the one that names this
    recording; a single report is taken as it is."""
    name = os.path.basename(path)
    for rep in reports:
        try:
            with open(rep, encoding="utf-8", errors="replace") as fh:
                if name in fh.read():
                    return rep
        except OSError:
            continue
    return reports[0] if len(reports) == 1 else None


def io_timeline(cap: dict, steps: dict | None = None) -> list:
    """The merged, annotated timeline: table lines in both directions, the
    FTDI requests, the i1Pro's requests and data, and the operator's steps
    and marks. Seconds from the recording's first packet."""
    t0 = cap["t0"]
    items = []
    for ev in cap["events"]:
        key = (ev["bus"], ev["dev"])
        if ev["kind"] == "control" and key in cap["table"]:
            items.append((ev["t"], 1, "TABLE", io_describe_ftdi(ev)))
        elif key in cap["pro"]:
            text = _io_pro_text(ev)
            if text:
                items.append((ev["t"], 2, "i1PRO", text))
    pending = {}
    u8_addr = None
    for l in cap["lines"]:
        # Printable characters only: a damaged recording must not be able to
        # send control characters to the terminal.
        line = "".join(c if 32 <= ord(c) < 127 else "." for c in l["line"])
        flag = "" if l["ok"] else ("  <-- line cut off by the end of the recording"
                                   if l.get("unfinished") else "  <-- CHECKSUM WRONG")
        if l["who"] == "host":
            cid = line[1:3]
            pending[cid] = l["t"]
            if cid == "u8" and len(line) == 17:
                try:
                    u8_addr = int(line[3:11], 16)
                except ValueError:
                    u8_addr = None
            text = ("(cut off, not described)" if l.get("unfinished") else
                    io_describe_command(line) if line.startswith(";") else "not a command line")
            items.append((l["t"], 1, "HOST ", f"{line:<22} {text}{flag}"))
        elif line.startswith(":!"):
            items.append((l["t_end"], 1, "TABLE", f"{line:<22} accepted{flag}"))
        elif line.startswith(":$"):
            cid = line[2:4]
            shown = io_redact(line, u8_addr)
            took = pending.pop(cid, None)
            took = f"  (took {l['t_end'] - took:.3f}s)" if took is not None else ""
            items.append((l["t_end"], 1, "TABLE",
                          f"{shown:<22} {io_describe_reply(line)}{took}{flag}"))
        else:
            items.append((l["t_end"], 1, "TABLE", f"{line:<22} (not a known reply){flag}"))
    if steps:
        for s in steps["steps"]:
            if s.get("skipped"):
                continue
            items.append((s["start"], 0, "", f">>> STEP: {s['name']} "
                                             f"(until {s['end'] - t0:.1f}s)"))
            items.append((s["end"], 3, "", f">>> end of step: {s['name']}"))
        for mk in steps["marks"]:
            items.append((mk["t"], 0, "", f">>> OPERATOR: {mk['what']}"))
    items.sort(key=lambda x: (x[0], x[1]))
    # Runs of i1Pro data on one endpoint become one line.
    out = []
    run = None
    for t, _order, who, text in items:
        m = re.match(r"(i1Pro data (?:from|to) 0x[0-9a-f]{2}): (\d+) bytes$", text)
        if m and run and run[1] == m.group(1):
            run[2] += 1
            run[3] += int(m.group(2))
            run[4] = t
            continue
        if run:
            out.append(_io_run_line(run, t0))
            run = None
        if m:
            run = [t, m.group(1), 1, int(m.group(2)), t]
            continue
        out.append(f"{t - t0:9.3f}  {who:5}  {text}")
    if run:
        out.append(_io_run_line(run, t0))
    return out


def _io_run_line(run: list, t0: float) -> str:
    start, label, count, total, last = run
    if count == 1:
        return f"{start - t0:9.3f}  i1PRO  {label}: {total} bytes"
    return (f"{start - t0:9.3f}  i1PRO  {label}: {total:,} bytes in {count} transfers "
            f"(until {last - t0:.3f}s)")


def summarize_io(paths: list, reports: list | None = None) -> str | None:
    """The i1iO analysis for --analyze, or None when no file holds a table."""
    caps = [c for c in (io_capture(p) for p in paths) if c]
    if not caps:
        return None
    out = ["=" * 68, "  THE i1iO TABLE: WHAT THE PROGRAM AND THE TABLE SAID", "=" * 68, "",
           "  Reads the recording only. It sends nothing to any device.",
           "  How sure we are is said with three words: certain, likely, guess.",
           "  Anything without one of them is a plain count from the recording.",
           "  The table's serial number is hidden" + (" (shown: --no-redact)."
                                                       if not REDACT else ".")
           + " The rest of the table's memory",
           "  is shown as read (it holds the white tile's values and a date).",]
    from collections import Counter                       # noqa: PLC0415
    for cap in caps:
        lines = cap["lines"]
        host = [l for l in lines if l["who"] == "host"]
        good = sum(1 for l in lines if l["ok"])
        out += ["", "  " + os.path.basename(cap["path"]),
                ("    table: 0971:2004 (\"Eye-One iO\") by its USB IDs" if cap["by_id"] else
                 "    table: found by its command lines (the recording holds no USB "
                 "description)"),
                "    a USB-to-serial link through an FTDI chip (certain for the i1iO 2)",
                f"    lines: {len(host)} to the table, {len(lines) - len(host)} from it; "
                f"checksum right on {good} of {len(lines)}"]
        if lines and good == len(lines):
            out.append("      (every line checks out, so the lines were read correctly)")
        elif lines:
            out.append("      (a wrong checksum means a line was cut or misread; "
                       "they are marked in the timeline)")
        counts = Counter(l["line"][1:3] for l in host if l["line"].startswith(";"))
        if counts:
            out.append("    commands to the table: " +
                       ", ".join(f"{k} x{v}" for k, v in sorted(counts.items())))
        new = sorted(k for k in counts if k not in IO_COMMANDS)
        out.append("    commands not seen in the first recordings: " +
                   (", ".join(new) if new else "none"))
        odd = Counter((l["line"][2:4], l["line"][4:5]) for l in lines
                      if l["line"].startswith(":$") and l["line"][4:5] != "0")
        out.append("    answers with a status other than 0: " +
                   (", ".join(f"{c} status {s} x{n}" for (c, s), n in sorted(odd.items()))
                    + " (meaning unknown)" if odd else "none"))
        presses = sum(1 for ev in cap["events"] if (ev["bus"], ev["dev"]) in cap["pro"]
                      and ev["kind"] == "data" and ev["ep"] == 0x84 and ev["dir_in"])
        out.append(f"    i1Pro button presses: {presses}")
        report = _report_naming(cap["path"], reports or []) or find_report_for(cap["path"])
        steps = None
        if report:
            try:
                with open(report, encoding="utf-8", errors="replace") as fh:
                    steps = io_steps_from_report(fh.read(), cap["t0"])
            except OSError:
                steps = None
        if steps and steps["steps"]:
            how = "exact times" if steps["exact"] else (
                "times approximate: worked out from the report's local clock, assuming "
                "the recording started within 15 minutes after the session")
            out.append(f"    steps, from {os.path.basename(report)} ({how}):")
            known = {s["title"] for s in IO_STEPS}
            for s in steps["steps"]:
                if s.get("skipped"):
                    out.append(f"      {s['name']}: skipped")
                    continue
                n, moving = io_count_commands(lines, s["start"], s["end"])
                verdict = io_step_verdict(n, moving, io_step_title(s["name"]) in known)
                out.append(f"      {s['name']}: {verdict}")
        else:
            out.append("    steps: no probe report found for this recording (put the "
                       "chromiq-io-probe report next to it, or name it after --analyze)")
        out += ["", "    TIMELINE (seconds from the first packet in the file)"]
        out += ["    " + line for line in io_timeline(cap, steps)]
    out.append("=" * 68)
    return "\n".join(out)


# --------------------------------------------------------------------------
# the recording step, per platform
# --------------------------------------------------------------------------

def macos_recording_step(direct: bool) -> None:
    readiness = macos_recording_readiness(_DETECTION.get("devices"))
    print("\n" + "-" * 68)
    print("OPTIONAL EXTRA: recording what i1Profiler says to the table")
    print("-" * 68)
    print()
    print("  This is the most useful extra there is, but it is optional. The")
    print("  report you already have is a genuinely valuable contribution.")
    print()
    if readiness["possible"]:
        print("  Good news: a recording looks possible on this Mac.")
        print("  " + readiness_report(readiness).replace("\n", "\n  "))
        print()
        print(I1PROFILER_WARNING)
        macos_guided_recording(readiness)
        return
    print(recording_not_possible_text(readiness))
    print()
    print("  If you are recording some other way right now (for example with a")
    print("  hardware sniffer), this tool can still time the i1Profiler steps")
    print("  for you, which makes that recording much easier to read.")
    if said_yes(ask("  Time the steps for you? (yes / no): ")):
        io_timed_steps(show_ready=True)
    else:
        section("Stage 2: recording",
                "[not possible on this Mac: " + " ".join(readiness["reasons"]) + "]")
        print("\n  No problem at all.\n")


def recording_step(direct: bool) -> None:
    if platform.system() == "Darwin":
        macos_recording_step(direct)
        return
    if direct:
        annotate_session()
        return
    print("\n" + "-" * 68)
    print("OPTIONAL EXTRA: only if you have time and feel adventurous")
    print("-" * 68)
    print()
    print("  There is a second, more advanced step: recording what i1Profiler")
    print("  says to the table. It is far more useful to us, but it needs the")
    print("  free program Wireshark (on Windows) and about 30 minutes.")
    print()
    print("  You do NOT need to do this. The report you already have is a")
    print("  genuinely valuable contribution on its own.")
    print()
    if said_yes(ask("  Try the advanced step too? (yes / no): ")):
        annotate_session()
    else:
        print("\n  No problem at all. Skipping it.\n")


# --------------------------------------------------------------------------
# 1.5: guided recording session for handheld instruments
#
# One session for the whole family (original i1Pro, i1Pro 2, i1Pro 3 / 3
# Plus, ColorMunki Photo / Design and i1Studio, and any other X-Rite
# device), with what we hope to learn layered on per instrument. Each step
# is recorded into its own file, the session file (session.json) is written
# after every step, so nothing finished is lost when the user stops, closes
# the window or the program fails.
#
# The tool never sends anything to the instrument and never changes a
# setting. It starts and stops the recording program (USBPcapCMD on
# Windows, tcpdump on a Mac with SIP off or on Linux) and nothing else.
# --------------------------------------------------------------------------

# Which session fits which device. (vid, pid) -> profile; the i1Pro and the
# i1Pro 2 share 0971:2000 and are told apart in the recording (endpoint
# 0x85), so the session offers the choice.
PROFILE_IDS = {
    (0x0971, 0x2000): "i1pro2",
    (0x0765, 0x6009): "i1pro3",
    (0x0971, 0x2007): "munki",
    (0x0765, 0x6008): "munki",
    (0x0971, 0x2006): "isis",                 # 1.6
}

PROFILE_NAMES = {
    "i1pro2": "i1Pro 2",
    "i1pro": "original i1Pro (the first generation)",
    "i1pro3": "i1Pro 3 or i1Pro 3 Plus",
    "munki": "ColorMunki Photo / Design or i1Studio",
    "isis": "i1iSis, i1iSis XL, i1iSis 2 or i1iSis 2 XL (chart reader)",
    "generic": "another X-Rite instrument",
}

PROFILE_PURPOSE = {
    "i1pro2": """\
  The i1Pro 2 has a small sensor underneath that can read the striped
  ("zebra") edge of its scanning ruler, so it can know where on the strip
  it is. The free ArgyllCMS driver, which ChromIQ uses, never reads that
  sensor: it finds the patches only from how the colour changes over
  time, which is why a fast or uneven swipe can cause misreads. We would
  like to learn three things from i1Profiler: how it switches the ruler
  sensor on and where the position data arrives, how its "dual scan"
  works, and how it drives the coloured lights on the instrument.""",
    "i1pro": """\
  As far as the open driver knows, the original i1Pro has no ruler
  sensor and no coloured indicator lights. We would
  like to learn how the vendor program reads a strip so reliably: how
  many readings it takes per second, with which settings, how it reacts
  to a fast or a slow swipe, and what it does when a scan fails.""",
    "i1pro3": """\
  The free ArgyllCMS driver, which ChromIQ uses, already reads the i1Pro
  3's ruler. So this session is about comparing: what does the vendor
  program do differently from the open driver during a strip scan?
  Commands the open driver never sends, how the dual scan for M0, M1 and
  M2 works, how the coloured lights are driven, how it reacts to a fast
  or uneven swipe, how many readings it takes per patch, and whether it
  reads again by itself.""",
    "munki": """\
  The ColorMunki and the i1Studio have no ruler sensor and no dual scan.
  We would like to learn how the vendor program reads a strip so
  reliably: how many readings it takes per second and per patch, how it
  reacts to a fast or a slow swipe, what it does with a failed strip,
  what the light on the instrument does, and how it asks about the
  dial positions (calibration, measuring).""",
    "isis": """\
  The i1iSis reads a whole printed chart page by itself: you push the
  page in, it pulls it through and measures every patch. The free
  ArgyllCMS driver, which ChromIQ uses, cannot talk to the i1iSis at all,
  and as far as we know, nobody outside X-Rite has described how
  i1Profiler does it. So this
  session is about the basics: what i1Profiler says to the i1iSis when it
  starts, how it gets it ready for a page, what travels while a page is
  measured (once in a single scan and once in a dual scan), and what
  happens when a page cannot be read. Your notes on what the light did
  and how the page moved are just as important as the recording.""",
    "generic": """\
  The tool has no special knowledge of this instrument. It records the
  conversation and lists it as it is, which can still be useful.""",
}

# 1.6: how an i1iSis owner gets a chart page, from i1Profiler's own help
# (devicesetup.htm, testchart.htm, enablebarcode.htm). No chart is shipped
# with this tool.
ISIS_CHART_TEXT = """  THE CHART PAGE YOU NEED
  You need ONE printed chart page made for the i1iSis. Its colours do
  not matter for this recording at all. An old chart page you still have
  is perfect, as long as i1Profiler still has that chart (open the same
  chart file in i1Profiler before step 2). A quick print is fine too.
  If you have none, make one in i1Profiler:
    - in the printer profiling part, go to the test chart page. With the
      i1iSis plugged in, i1Profiler lays the chart out for it by itself
      (in Advanced mode you can also choose the i1iSis by hand, in the
      device setup).
    - i1Profiler also comes with ready-made charts for the i1iSis; their
      names end in "i1iSis" (for an i1iSis XL: "i1iSis XL").
    - if the chart has a barcode, i1Profiler asks you to save the chart
      before printing it. That is normal: save it, then print.
    - a chart with only one page is easiest. Print page 1 on normal
      80 g/m2 printer paper; that is all you need. (X-Rite's guide asks
      for paper 0.08 to 0.45 mm thick; normal printer paper is right,
      please do not use thinner paper.)"""


PROMISE_TEXT = """\
  We cannot promise that anything will come of it. A recording helps us
  understand; whether an open-source measurement engine can ever use what
  we learn is a separate question, and the answer may be no."""

VENDOR_PROGRAMS = [
    "i1Profiler",
    "ccStudio (ColorChecker Studio)",
    "ColorMunki Photo / Design software",
    "i1Studio software",
]


# Steps. "families" lists the profiles a step is offered to. Instructions
# are generic on purpose: page names differ between programs and versions.
SESSION_STEPS = [
    {"key": "idle", "title": "start the program, then leave it idle",
     "families": ("i1pro2", "i1pro", "i1pro3", "munki", "generic"),
     "before": """\
  Before you press Enter: quit the measuring program if it is open. Leave
  the instrument plugged in and resting where it normally rests.""",
     "during": """\
  When the recording runs: start the measuring program and wait until it
  shows that it has found the instrument. Then leave everything alone for
  about 10 seconds and watch the instrument. Do NOT measure or scan
  anything in this step: measuring comes in the later steps.""",
     "lights": "What did the lights do while the program started and while it sat idle?"},
    {"key": "calibrate", "title": "calibrate",
     "families": ("i1pro2", "i1pro", "i1pro3", "munki", "generic"),
     "before": """\
  Before you press Enter: go to the page where you measure a printed test
  chart, the way you normally would, up to the point where the program
  asks you to calibrate. Use any test chart you have printed.
  (In i1Profiler this is usually under Printer, in the profiling
  workflow, on its measurement page. In the ColorMunki and i1Studio
  programs it is the step where you measure the printed chart.)""",
     "during": """\
  When the recording runs: calibrate exactly as the program asks.
  i1Pro family: on the white calibration tile.
  ColorMunki / i1Studio: turn the dial to the calibration position when
  asked, and back to the measuring position afterwards.
  Wait until the program says calibration is done.""",
     "lights": "What did the lights do during and after the calibration?"},
    {"key": "scan-single", "title": "scan one strip (single scan, normal speed)",
     "families": ("i1pro2", "i1pro", "i1pro3", "munki", "generic"),
     "before": """\
  Before you press Enter: choose ONE strip (row) of your chart that you
  will use for all the scan steps, for example the first one. If the
  program offers a choice of measurement mode, choose one that needs a
  single pass per strip (for example M0 or M2 on its own, not "dual
  scan"). Set the chart up as usual (with the ruler and backing board,
  if your instrument has them).""",
     "during": """\
  When the recording runs: scan that one strip at your normal speed, as
  you always do. Wait until the program accepts or refuses it. You do
  not need to finish the chart.""",
     "lights": "What did the lights do before, during and after the scan?"},
    {"key": "scan-dual", "title": "the same strip, dual scan",
     "families": ("i1pro2", "i1pro3"),
     "before": """\
  Before you press Enter: switch the program to its dual scan option, if
  it has one (in i1Profiler it is offered together with the M0, M1 and
  M2 measurement conditions; owners say the instrument's lights flash
  during a dual scan). If you cannot find such an option, type  s  to
  skip this step.""",
     "during": """\
  When the recording runs: scan the same strip, the way the program asks
  for it (it may ask for two passes). Wait until it accepts or refuses
  the strip.""",
     "lights": "What did the lights do during the scan, and between the two passes if there were two?",
     "setting": "Which setting was on in i1Profiler for this scan: single or dual scan,\n"
                "  and M0, M1 or M2? (For example: \"dual, M1\")"},
    {"key": "scan-fast", "title": "the same strip again, clearly faster",
     "families": ("i1pro2", "i1pro", "i1pro3", "munki", "generic"),
     "before": """\
  Before you press Enter: go back to the single-pass mode (if you changed
  it). Get ready to scan the same strip again.""",
     "during": """\
  When the recording runs: scan the same strip about twice as fast as you
  normally would. If the program complains or refuses it, that is a
  useful result too.""",
     "lights": "What did the lights do? Was it different from the normal scan?"},
    {"key": "scan-slow", "title": "the same strip again, slowly",
     "families": ("i1pro2", "i1pro", "i1pro3", "munki", "generic"),
     "before": """\
  Before you press Enter: get ready to scan the same strip once more.""",
     "during": """\
  When the recording runs: scan the same strip slowly and steadily: take
  3 to 5 seconds for the whole strip (count slowly to four while you
  move).""",
     "lights": "What did the lights do this time?"},
    {"key": "scan-fail", "title": "let one scan fail on purpose",
     "families": ("i1pro2", "i1pro", "i1pro3", "munki", "generic"),
     "before": """\
  Before you press Enter: get ready to scan the same strip, but so that
  it fails: for example lift the instrument off the paper halfway along
  the strip, or stop in the middle. Do nothing that could harm the
  instrument. If you would rather not, type  s  to skip this step.""",
     "during": """\
  When the recording runs: start scanning the strip and make it fail as
  described. Wait until the program reports the failure, then do what it
  asks (it may ask you to scan the strip again; you may do that too).""",
     "lights": "What did the lights do when the scan failed, and afterwards?"},
    {"key": "spot", "title": "read one single patch",
     "families": ("i1pro2", "i1pro", "i1pro3", "munki", "generic"),
     "before": """\
  Before you press Enter: find the program's way of reading a single
  patch (often called spot or single patch measurement). If the program
  offers none, or you cannot find it, type  s  to skip this step.""",
     "during": """\
  When the recording runs: read one single patch, then wait until the
  program shows the result.""",
     "lights": "What did the lights do?"},
    {"key": "noruler", "title": "the same strip without the ruler (control)",
     "families": ("i1pro2", "i1pro3"), "control": True,
     "before": """\
  Before you press Enter: go back to the single-pass mode. Take the ruler
  away. This step only makes sense if the program lets you scan without
  the ruler; if it does not, or you are unsure, type  s  to skip it.""",
     "during": """\
  When the recording runs: scan the same strip without the ruler, for
  example by sliding the instrument along a straight edge or freehand.
  If the program refuses or shows a message, that is useful too: note
  what it said. Do not force anything.""",
     "lights": "What did the lights do?"},
    # ---- 1.6: the i1iSis chart readers ---------------------------------
    # Facts behind the wording (see the work notes FACTS.md of 1.6): the
    # status light (off, green, blinking green = "insert chart", blue = busy,
    # red = error) and the way a page is fed (quickly about 5 cm along the
    # left guide, then it is pulled in by itself) are from X-Rite's i1iSis
    # quick start guide; "Measure" and the dual scan modes from i1Profiler
    # 3.8.8's own texts and help; "switch it on BEFORE plugging in the USB
    # cable" from i1Profiler 3.8.8's release notes.
    {"key": "idle", "title": "start i1Profiler, then leave it idle",
     "families": ("isis",), "box": "Then: ",
     "before": """\
  Before you press Enter: quit i1Profiler if it is open. The i1iSis
  should be switched on and connected, with no page in it. (Please
  switch it on BEFORE you plug in its USB cable: X-Rite says that if the
  cable goes in first and the power comes on afterwards, i1Profiler does
  not see the i1iSis.)""",
     "during": """\
  When the recording runs: start i1Profiler and wait until it shows that
  it has found the i1iSis. Then leave everything alone for about 10
  seconds and watch the i1iSis. Do NOT measure anything yet.""",
     "lights": "What did the light on the i1iSis do (colour, blinking, when)?",
     "page": "Did the i1iSis move or make a sound? (Enter if nothing happened)"},
    {"key": "ready", "title": "get the i1iSis ready for a page (do not feed it yet)",
     "families": ("isis",), "box": "Then: ",
     "before": """\
  Before you press Enter: in i1Profiler, go to the page where you measure
  your printed chart, with your chart loaded, as you normally would. If
  it offers a choice between Single scan and Dual scan, choose Single
  scan. Have your printed chart page ready, but keep it in your hand.""",
     "during": """\
  When the recording runs: click Measure (or Start Measurement) in
  i1Profiler, and wait until the i1iSis is ready for the page (its light
  blinks green when it waits for a chart). Then wait about 10 seconds
  more. Do NOT feed the page in this step. If i1Profiler does not wait,
  or asks for the page at once, that is fine: stop the step and say so.""",
     "lights": "What did the light on the i1iSis do?",
     "page": "Did the i1iSis move, whirr or click (for example a calibration)? "
             "(Enter if nothing happened)"},
    {"key": "page-single", "title": "feed one page, single scan",
     "families": ("isis",), "box": "Then: ",
     "before": """\
  Before you press Enter: i1Profiler should now be waiting for the page
  (if you stopped it, get it there again, with Single scan). Hold page 1
  of your chart the way you always feed it.""",
     "during": """\
  When the recording runs: feed the page as usual (push it in quickly,
  about 5 cm, along the left-hand guide; the i1iSis then pulls it in by
  itself). Wait until the page has come out again AND i1Profiler shows
  it as measured. That can take a minute or two. If i1Profiler then asks
  for the next page, do NOT feed it: just stop the step.""",
     "lights": "What did the light do before, during and after the page?",
     "page": "How did the page move? (in, out, back and forth, how many times, "
             "any sounds)"},
    {"key": "page-dual", "title": "the same page again, dual scan",
     "families": ("isis",), "box": "Then: ",
     "before": """\
  Before you press Enter: switch i1Profiler to Dual scan, if it offers
  it (for the i1iSis it reads M0 and M2, for the i1iSis 2 also M1). If
  i1Profiler has to start the measurement again for that, that is fine:
  get it to the point where it waits for the page. If you cannot find a
  Dual scan setting, type  s  to skip this step.""",
     "during": """\
  When the recording runs: feed the same page again, exactly as before.
  Wait until the page has come out again AND i1Profiler shows it as
  measured (a dual scan takes longer).""",
     "lights": "What did the light do this time?",
     "setting": "Which setting was on in i1Profiler for this page? (for example "
                "\"dual scan, M0 M1 M2\")",
     "page": "How did the page move? Did it go through once or twice, or back "
             "and forth?"},
    {"key": "page-skewed", "title": "the same page, fed a little crooked",
     "families": ("isis",), "box": "Then: ",
     "before": """\
  Before you press Enter: go back to Single scan and get i1Profiler to
  wait for the page again. The i1iSis is made to correct a page that
  goes in slightly crooked; this step shows how. If you would rather not,
  type  s  to skip it.""",
     "during": """\
  When the recording runs: feed the same page at a slight angle (a few
  millimetres crooked, not more). Never force it. Wait until the page
  has come out and i1Profiler has accepted or refused it, and do what
  i1Profiler asks.""",
     "lights": "What did the light do?",
     "page": "How did the page move this time? Did i1Profiler accept it?"},
    {"key": "blank-page", "title": "a sheet without a chart (fails on purpose)",
     "families": ("isis",), "box": "Then: ",
     "before": """\
  Before you press Enter: take one plain sheet of normal 80 g/m2
  printer paper, the same size as your chart, with nothing printed on
  it, and get i1Profiler to wait for a page again. The i1iSis will not
  find a chart on it, which is what we want to see. If you would rather
  not, type  s  to skip this step.""",
     "during": """\
  When the recording runs: feed the plain sheet like a chart page. Wait
  until it has come out and i1Profiler shows a message, then do what
  i1Profiler asks (for example cancel, or feed the right page).""",
     "lights": "What did the light do when the sheet could not be read?",
     "page": "How did the sheet move, and what did i1Profiler say?"},
]

# Profiles whose instrument has lights worth asking about. The original
# i1Pro has none (the i1Pro 2's Rev E capability bits are the first to list
# indicator LEDs, i1pro_imp.h:165).
PROFILES_WITH_LIGHTS = ("i1pro2", "i1pro3", "munki", "isis", "generic")


def steps_for(profile: str) -> list:
    return [s for s in SESSION_STEPS if profile in s["families"]]


def step_keys_unique() -> bool:
    """1.6: two families may share a step key ("idle"), one family never."""
    return all(len({s["key"] for s in steps_for(p)}) == len(steps_for(p))
               for p in PROFILE_NAMES)


# ---- what the computer can do: checks ------------------------------------

def windows_build_info() -> dict:
    """Windows build and release name, read only. Empty off Windows."""
    info = {"build": None, "display": None, "product": None}
    if platform.system() != "Windows":
        return info
    try:
        info["build"] = sys.getwindowsversion().build      # type: ignore[attr-defined]
    except Exception:                                     # noqa: BLE001
        pass
    try:
        import winreg                                     # noqa: PLC0415
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
            for name, field in (("DisplayVersion", "display"), ("ProductName", "product"),
                                ("CurrentBuild", "build")):
                try:
                    value = winreg.QueryValueEx(key, name)[0]
                except OSError:
                    continue
                if field == "build":
                    info["build"] = info["build"] or int(value)
                else:
                    info[field] = str(value)
    except Exception:                                     # noqa: BLE001
        pass
    return info


# Windows 11 starts at build 22000; 24H2 is 26100, 25H2 is 26200.
WIN11_FIRST_BUILD = 22000
WIN11_25H2_BUILD = 26200


# 1.5.1: which instruments X-Rite's 25H2 note is about. X-Rite's support page
# "i1Pro 2 Not Working with i1Profiler, Windows 11, MacOS 28 (soon)" (8/2026):
# "The i1Pro 2 / iO2 driver is not compatible with recent Windows 11 updates
# (25H2 or newer)", "The old i1Pro 2 drivers are blocked and there is no
# workaround", and "i1Pro 3 / iO3 is compatible with latest Windows 11
# releases". 1.5.0 showed the warning to everybody, including an i1Pro 3
# owner. The first i1Pro shares the i1Pro 2's USB ID (0971:2000), so the
# computer cannot tell them apart; the note does not mention it.
XRITE_25H2_NOTE_URL = ("https://www.xrite.com/service-support/"
                       "i1pro-2-eol-notes-compatibility-issues-with-windows-11-macos")
PROFILES_BLOCKED_ON_25H2 = ("i1pro2", "i1pro")


def windows_release_check(build, display, arm: bool, profile: str | None = None,
                          vendor_driver_working: bool = False) -> dict:
    """Plain facts about this Windows for the recording. Never blocks.

    profile: the session's instrument (None: not known, said for the i1Pro 2
    and the iO2 as before).
    vendor_driver_working (1.5.2): X-Rite's driver is bound to the plugged-in
    instrument and Windows reports it as working. Then X-Rite's general note
    is not this PC's state, and saying [PLEASE READ] next to "[OK] X-Rite's
    driver" only confused the second user; it is useful evidence instead."""
    if arm:
        # 1.5.4: 1.5.3 said as fact that the vendor program cannot talk to any
        # instrument here. For the i1Pro 3 that is not known: its firmware
        # asks for Microsoft's own WinUSB driver (seen in a user's report),
        # and nobody has tried i1Profiler with it on ARM. "Problem" stays,
        # because there is no recorder for ARM either way.
        if profile == "isis":
            return {"level": "problem", "text": (
                "This Windows runs on an ARM processor. Whether X-Rite's driver for the "
                "i1iSis works here is not known: X-Rite does not say, and we have no "
                "report either way. The recorder this tool uses (USBPcap) does not exist "
                "for ARM processors, so a recording cannot be made on this PC. Please use "
                "a Windows PC with an Intel or AMD processor for the recording (with "
                "i1Profiler 3.8.8 or newer on Windows 11 version 25H2).")}
        if profile == "i1pro3":
            return {"level": "problem", "text": (
                "This Windows runs on an ARM processor. The i1Pro 3 asks Windows for "
                "Microsoft's own USB driver, so Windows may recognise it here without "
                "an X-Rite driver. Whether i1Profiler can measure with it on an ARM "
                "processor is not known: X-Rite does not say, and we have no report "
                "either way. The recorder this tool uses (USBPcap) does not exist for "
                "ARM processors, so a recording cannot be made on this PC. Please use "
                "a Windows PC with an Intel or AMD processor for the recording. If you "
                "try i1Profiler here, please tell us whether it finds the i1Pro 3: "
                "that is useful to know.")}
        return {"level": "problem", "text": (
            "This Windows runs on an ARM processor. We know of no X-Rite driver for "
            "the i1Pro 2, the i1iO or the ColorMunki on Windows on ARM (that includes "
            "a Windows virtual machine on an Apple Silicon Mac), so the vendor program "
            "most likely cannot talk to the instrument here. The recorder this tool "
            "uses (USBPcap) does not exist for ARM processors either. Please use a "
            "Windows PC with an Intel or AMD processor for the recording.")}
    if not build:
        return {"level": "unknown", "text": "The Windows version could not be read."}
    name = "Windows 11" if build >= WIN11_FIRST_BUILD else "Windows 10"
    label = f"{name}{' version ' + display if display else ''} (build {build})"
    if build >= WIN11_25H2_BUILD:
        if profile in PROFILES_BLOCKED_ON_25H2 and vendor_driver_working:
            return {"level": "ok", "text": (
                f"{label}. X-Rite says its driver for the i1Pro 2 and the iO2 does "
                "not work with Windows 11 version 25H2 or newer, but on this PC "
                "X-Rite's driver is installed and Windows reports the instrument as "
                "working, so please carry on. Please tell us whether i1Profiler "
                "measures with it: that is useful to know.")}
        if profile is None or profile in PROFILES_BLOCKED_ON_25H2:
            return {"level": "warning", "text": (
                f"{label}. X-Rite says its driver for the i1Pro 2 and the iO2 does "
                "not work with Windows 11 version 25H2 or newer: Windows blocks it, "
                "and X-Rite will not update it. (The first i1Pro looks the same to "
                "the computer; X-Rite's note does not mention it.) If the vendor "
                "program still finds your instrument, carry on; if it does not, "
                "this is why.")}
        if profile == "isis":
            return {"level": "ok", "text": (
                f"{label}. X-Rite's note about drivers blocked on 25H2 concerns the "
                "i1Pro 2 and the iO2, not the i1iSis. For the i1iSis, X-Rite says "
                "i1Profiler 3.8.8 fixed its drivers on 25H2, so please use 3.8.8 or "
                "newer.")}
        if profile == "i1pro3":
            return {"level": "ok", "text": (
                f"{label}. X-Rite's note about drivers blocked on 25H2 concerns "
                "the i1Pro 2 and the iO2 only. X-Rite says the i1Pro 3 works with "
                "the latest Windows 11 releases.")}
    return {"level": "ok", "text": label}


def parse_sc_query(text: str) -> dict:
    """`sc query USBPcap` -> {"installed", "running"}."""
    low = (text or "").lower()
    installed = "service_name" in low and "usbpcap" in low and "1060" not in low
    return {"installed": installed, "running": installed and "running" in low}


_EXTCAP_IFACE_RE = re.compile(r"^interface \{value=([^}]*)\}\{display=([^}]*)\}", re.M)
_EXTCAP_VALUE_RE = re.compile(r"^value \{arg=(\d+)\}\{value=([^}]*)\}\{display=([^}]*)\}", re.M)
_XRITE_NAME_RE = re.compile(r"x-?rite|eye-?one|i1 ?pro|i1 ?studio|i1 ?isis|colormunki|gretag|"
                            r"calibrite", re.I)


def parse_extcap_interfaces(text: str) -> list:
    """USBPcapCMD --extcap-interfaces -> [(device path, display name)]."""
    return [(m.group(1), m.group(2)) for m in _EXTCAP_IFACE_RE.finditer(text or "")]


def parse_extcap_devices(text: str) -> list:
    """USBPcapCMD --extcap-config -> [(address, name)] of attached devices."""
    out = []
    for m in _EXTCAP_VALUE_RE.finditer(text or ""):
        if not m.group(2).isdigit():
            continue
        out.append((int(m.group(2)), m.group(3)))
    return out


def parse_i1profiler_uninstall(text: str) -> str | None:
    """PowerShell 'DisplayName :: DisplayVersion' lines -> i1Profiler's version."""
    for line in (text or "").splitlines():
        if "i1profiler" in line.lower() and "::" in line:
            version = line.split("::", 1)[1].strip()
            if version:
                return version
    return None


def parse_program_versions(text: str) -> dict:
    """All 'DisplayName :: DisplayVersion' lines for the vendor programs."""
    found = {}
    for line in (text or "").splitlines():
        if "::" not in line:
            continue
        name, version = (part.strip() for part in line.split("::", 1))
        low = name.lower()
        if any(k in low for k in ("i1profiler", "ccstudio", "colorchecker studio",
                                  "colormunki", "i1studio")):
            found[name] = version
    return found


_USBPCAP_CMD_PLACES = [
    r"C:\Program Files\USBPcap\USBPcapCMD.exe",
    r"C:\Program Files\Wireshark\extcap\USBPcapCMD.exe",
    r"C:\Program Files\Wireshark\extcap\wireshark\USBPcapCMD.exe",
]


def find_usbpcapcmd() -> str | None:
    found = shutil.which("USBPcapCMD") or shutil.which("USBPcapCMD.exe")
    if found:
        return found
    for place in _USBPCAP_CMD_PLACES:
        if os.path.exists(place):
            return place
    return None


def windows_is_admin() -> bool | None:
    try:
        import ctypes                                     # noqa: PLC0415
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:                                     # noqa: BLE001
        return None


def _powershell(script: str) -> str:
    ps = shutil.which("powershell") or shutil.which("pwsh")
    if not ps:
        return "[PowerShell not found]"
    return run([ps, "-NoProfile", "-NonInteractive", "-NoLogo", "-Command",
                PS_PREFIX + script], timeout=60)


def windows_program_versions() -> dict:
    return parse_program_versions(_powershell(PS_PROGRAMS))


def i1profiler_check(version, profile: str, build=None) -> dict:
    if not version:
        return {"level": "unknown", "text": "not found (that is fine if you use another program)"}
    # 1.6: i1Profiler 3.8.8's release notes: "Fixes issue where i1iSis
    # drivers would not load on latest Windows 11 operating system (25H2)."
    if profile == "isis" and version_tuple(version) < (3, 8, 8) and build \
            and build >= WIN11_25H2_BUILD:
        return {"level": "warning", "text": (
            f"{version}. X-Rite's notes for i1Profiler 3.8.8 say that older versions "
            "could not load the i1iSis drivers on this Windows version (25H2). If "
            "i1Profiler does not find your i1iSis, please update it to 3.8.8 or newer.")}
    if profile == "i1pro2" and version_tuple(version) >= (3, 8, 7):
        return {"level": "warning", "text": (
            f"{version}. i1Profiler 3.8.7 removed support for the i1Pro 2, so this "
            "version cannot talk to it. Version 3.8.6 or older is needed.")}
    # 1.5.1: X-Rite's note "i1Pro 1 Support Dropped in i1Profiler 3.2.0"
    # (xrite.com/service-support/i1pro1supportdroppedini1profiler320): 3.2.0
    # "has removed the support for revisions A through D of the i1Pro"; keep
    # 3.1.1, which X-Rite lists for Windows 7 to 10 and macOS 10.13 to 10.15.
    if profile == "i1pro" and version_tuple(version) >= (3, 2, 0):
        return {"level": "warning", "text": (
            f"{version}. X-Rite removed the original i1Pro (revisions A to D) "
            "from i1Profiler in version 3.2.0, so this version cannot talk to "
            "it. Version 3.1.1 is needed (X-Rite lists it for Windows 7 to 10).")}
    return {"level": "ok", "text": f"{version}"}


# 1.5.1: rewritten after the first report from a user, who asked "what is
# it?". Facts behind the wording, checked 2026-11-12:
# - Wireshark's installer (packaging/nsis/wireshark.nsi, USBPcapPage.ini) has
#   a page headed "USB Capture" with the checkbox "Install USBPcap 1.5.4.0",
#   NOT ticked by default; it runs USBPcap's own installer (with its licence
#   pages), copies USBPcapCMD.exe into Wireshark's extcap folder and asks for
#   a restart.
# - desowin.org/usbpcap: "After installation you must restart your computer."
# - USBPcap's installer (nsis/USBPcap.nsi) installs a separate driver build on
#   Windows 10 and newer, which its author says is signed by "Microsoft
#   Windows Hardware Compatibility Publisher" (attestation signing, usbpcap
#   issue #39, since 1.2.0.3). So Secure Boot and driver signature
#   enforcement stay on. Whether Windows' memory integrity setting accepts
#   it is not documented anywhere we found, so the text asks the user to
#   tell us rather than switch anything off.
USBPCAP_INSTALL_TEXT = """\
  WHAT USBPcap IS
  USBPcap is a small, free program that lets Windows write down what a
  program and a USB device say to each other, like a voice recorder for
  the USB cable. This tool needs it because Windows has no such recorder
  of its own: without USBPcap there is nothing to record with.

  HOW TO INSTALL IT (free, about 5 minutes)
    1. Open https://www.wireshark.org/download.html and download the
       "Windows x64 Installer". (Wireshark is a free program that brings
       USBPcap with it. You do not need to use Wireshark itself.)
    2. Run it and keep the suggested choices, until you reach the page
       called "USB Capture". There, tick the box "Install USBPcap" (it is
       not ticked unless you tick it). USBPcap's own installer then opens:
       accept its licence and keep its suggested choices.
    3. When everything has finished, restart Windows. USBPcap only starts
       listening to the USB ports after a restart.
    4. Run this tool again (right-click it and choose "Run as
       administrator"), and choose the recording session again.

  You do not need to switch off any security setting for this: not
  Secure Boot, and not "driver signature enforcement". On Windows 10 and 11,
  USBPcap installs a driver that is signed through Microsoft's own signing
  service, so Windows accepts it as it is. If Windows refuses it anyway
  (for example with a message about "memory integrity" or an incompatible
  driver), please do not switch any protection off: tell us what Windows
  said, and we will look at it with you.

  Without Wireshark: USBPcap also has an installer of its own at
  https://desowin.org/usbpcap/ (restart Windows after it, too).
  To remove USBPcap later: Settings, Apps, Installed apps, "USBPcap",
  Uninstall, then restart Windows."""


# 1.5.1: which driver Windows has given the instrument. Only devices that are
# plugged in now count: Windows remembers every instrument it has ever seen,
# once per USB socket, and those memories keep their old driver.
#
# ArgyllCMS (and so ChromIQ) reads an instrument on Windows only through the
# libusb-win32 driver (service "libusb0"): Argyll's usb/ArgyllCMS.inf binds
# it, and its device class is "Argyll LibUSB-win32 devices"; ChromIQ's own
# installer (Preferences, "Instrument drivers...") puts the same driver in
# through libwdi. X-Rite's programs cannot open an instrument bound to it.
# X-Rite's own driver for the i1Pro and i1Pro 2 has the device class
# "XRiteDevices"; the i1Pro 3 asks Windows for the standard WinUSB driver
# itself (compatible ID USB\MS_COMP_WINUSB). One report showed a WinUSB entry
# named "X-Rite i1Pro3" from a libwdi INF; whether that is X-Rite's own name
# is not verified (1.5.4: the help text no longer names it).
_DRIVER_PS = (
    "Get-PnpDevice -PresentOnly | Where-Object { ($_.InstanceId -like '*VID_0971*' "
    "-or $_.InstanceId -like '*VID_0765*') } | ForEach-Object { "
    "$s = (Get-PnpDeviceProperty -InstanceId $_.InstanceId -KeyName DEVPKEY_Device_Service "
    "-ErrorAction SilentlyContinue).Data; "
    "$p = (Get-PnpDeviceProperty -InstanceId $_.InstanceId -KeyName DEVPKEY_Device_DriverProvider "
    "-ErrorAction SilentlyContinue).Data; "
    "'DRV :: ' + $_.FriendlyName + ' :: ' + $_.InstanceId + ' :: ' + $_.Class + ' :: ' + $s + ' :: ' + $p "
    "+ ' :: ' + $_.Status }")

# Every PowerShell command the tool runs (see PS_XRITE_DEVICES above).
POWERSHELL_SCRIPTS = (PS_XRITE_DEVICES, PS_DEVICE_PROPERTIES, PS_USB_HUBS, PS_DRIVER_FILES,
                      PS_SUMMARY, PS_PROGRAMS, _DRIVER_PS)

_INSTANCE_IDS_RE = re.compile(r"VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})")


def parse_driver_lines(text: str) -> list:
    """The 'DRV :: name :: instance :: class :: service :: provider[ :: status]'
    lines (the status, as Get-PnpDevice gives it, since 1.5.2)."""
    out = []
    for line in (text or "").splitlines():
        if not line.startswith("DRV :: "):
            continue
        parts = [p.strip() for p in line[len("DRV :: "):].split(" :: ")]
        parts += [""] * (6 - len(parts))
        name, instance, cls, service, provider, status = parts[:6]
        m = _INSTANCE_IDS_RE.search(instance)
        if not m or "&MI_" in instance.upper():
            continue
        out.append({"vid": int(m.group(1), 16), "pid": int(m.group(2), 16), "name": name,
                    "class": cls, "service": service, "provider": provider,
                    "status": status})
    return out


def driver_state(dev: dict) -> str:
    """'argyll', 'winusb', 'vendor', 'none' or 'unknown' for one present device."""
    service = dev.get("service", "").lower()
    text = " ".join(dev.get(k, "") for k in ("name", "class", "provider")).lower()
    if service in ("libusb0", "libusbk") or "argyll" in text or "libusb" in text:
        return "argyll"
    if service == "winusb":
        return "winusb"
    if not service:
        return "none"
    if "xrite" in text.replace("-", "") or service == "eyeone":
        return "vendor"
    return "unknown"


def instrument_driver_checks(devices: list) -> list:
    """One check per plugged-in instrument: name, level, text, needs_help."""
    checks = []
    for dev in devices:
        if (dev["vid"], dev["pid"]) not in PROFILE_IDS:
            continue
        state = driver_state(dev)
        label = dev["name"] or f"{dev['vid']:04x}:{dev['pid']:04x}"
        drv = dev["service"] or "no driver"
        if state == "argyll":
            checks.append({"name": label, "level": "problem", "help": True, "text": (
                f"{label}: on the ArgyllCMS driver ({drv}), which ChromIQ and "
                "ArgyllCMS use. The vendor program cannot see the instrument "
                "like this (see below what to do).")})
        elif state == "winusb" and dev["vid"] == 0x0765 and \
                "libwdi" in dev.get("provider", "").lower():
            # 1.5.4: a real report: WinUSB, provider "libwdi", an INF named
            # "X-Rite i1Pro3". libwdi is a library that tools such as Zadig
            # use to bind WinUSB; X-Rite's own package would hardly name it as
            # provider. So the name alone says nothing about who installed it.
            checks.append({"name": label, "level": "warning", "help": False, "text": (
                f"{label}: Windows' standard USB driver (WinUSB), installed by a tool "
                "built on libwdi (the driver's provider says \"libwdi\"; Zadig and "
                "ChromIQ's own driver installer are such tools), probably not by "
                "X-Rite's own installer, even if its name sounds like X-Rite. The "
                "i1Pro 3 asks for WinUSB anyway, so this may well work; whether "
                "i1Profiler opens it like this is not known. If i1Profiler does not "
                "find the instrument, give it X-Rite's entry back in Device Manager "
                "(the steps in the report, \"YOUR INSTRUMENT IS ON THE WRONG "
                "DRIVER\") or repair i1Profiler.")})
        elif state == "winusb" and dev["vid"] == 0x0765:
            checks.append({"name": label, "level": "ok", "help": False, "text": (
                f"{label}: Windows' standard USB driver (WinUSB), which the "
                "instrument itself asks for"
                + (f" (provider: {dev['provider']})" if dev.get("provider") else "")
                + ". The vendor program normally finds it like this.")})
        elif state == "winusb":
            checks.append({"name": label, "level": "problem", "help": True, "text": (
                f"{label}: on a general-purpose driver (WinUSB), not on X-Rite's. "
                "The vendor program cannot see the instrument like this (see "
                "below what to do).")})
        elif state == "vendor":
            working = dev.get("status", "").upper() == "OK"
            checks.append({"name": label, "level": "ok", "help": False,
                           "vendor_working": working,
                           "text": f"{label}: X-Rite's driver ({drv})"
                                   + (", and Windows reports it as working" if working else "")})
        elif state == "none":
            checks.append({"name": label, "level": "warning", "help": False, "text": (
                f"{label}: Windows has no driver for it at the moment. Installing "
                "(or repairing) the vendor program normally brings X-Rite's driver.")})
        else:
            checks.append({"name": label, "level": "unknown", "help": False,
                           "text": f"{label}: driver {drv}, not one this tool knows"})
    return checks


DRIVER_HELP_TEXT = """\
  YOUR INSTRUMENT IS ON THE WRONG DRIVER FOR THE VENDOR PROGRAM
  A USB instrument works with one driver at a time. ChromIQ and ArgyllCMS
  need their own driver (called libusb0 or libusb-win32, shown in Device
  Manager with "(Argyll)" in its name or under "Argyll LibUSB-win32
  devices"). X-Rite's programs, such as i1Profiler, need X-Rite's driver,
  and while the instrument is on the ArgyllCMS driver they cannot see it at
  all. So for a recording, please give it X-Rite's driver back first:
    1. Plug the instrument into the USB socket you want to use, then open
       Device Manager (right-click the Start button, "Device Manager").
    2. Find the instrument, under "Argyll LibUSB-win32 devices" or
       "libusb-win32 devices". Right-click it and choose "Update driver".
    3. Choose "Browse my computer for drivers", then "Let me pick from a
       list of available drivers on my computer".
    4. Pick X-Rite's own entry, the one that came with the vendor program
       (for an i1Pro or i1Pro 2 it has been seen as "i1 Pro"). Not an
       entry with "(Argyll)" in its name, and not
       "X-Rite i1 Pro 3 / i1 Pro 3+" or "GretagMacbeth i1 Pro / i1 Pro 2"
       (those are the ArgyllCMS driver as ChromIQ installs it). Click
       Next. If you are not sure which entry is X-Rite's, or it is not in
       the list, reinstall (or repair) the vendor program: its installer
       brings X-Rite's driver. If the list looks different, tell us what
       it shows.
    5. Unplug the instrument, plug it in again, and check that the vendor
       program finds it. Then run this tool again.
  Windows keeps a separate entry for every USB socket, so the instrument
  can have X-Rite's driver in one socket and the ArgyllCMS driver in
  another. If the vendor program does not find it, check the socket it is
  plugged into right now.

  THE WAY BACK, for ChromIQ afterwards: ChromIQ cannot see the instrument
  while it is on X-Rite's driver. Do the same steps and, in step 4, pick
  the ArgyllCMS entry again (the one with "(Argyll)" in its name, or the
  one ChromIQ installed, named as in step 4). Or let ChromIQ do it: in
  ChromIQ's Preferences, open "Instrument drivers..." and click
  "Install Driver". Nothing here needs any security setting switched off."""


def usbpcap_version(cmd) -> str:
    """'1.5.4.0' from USBPcapCMD --extcap-version, or ''."""
    if not cmd:
        return ""
    m = re.search(r"\{version=([^}]*)\}", run([cmd, "--extcap-version"], timeout=20))
    return m.group(1) if m else ""


def usbpcap_diagnosis(c: dict) -> str:
    """1.5.4: everything about the recorder, for the report (a real report
    from 1.5.3 said only "the recording program stopped at once")."""
    admin = c.get("admin")
    cmd = c.get("usbpcapcmd")
    lines = ["THE RECORDER, IN DETAIL",
             "  administrator: " + ("yes" if admin else "no" if admin is False else "not known"),
             f"  USBPcap service: installed {c['service'].get('installed')}, running "
             f"{c['service'].get('running')}",
             f"  USBPcapCMD: {cmd or 'not found'}"
             + (f", version {usbpcap_version(cmd) or 'not reported'}" if cmd else "")]
    hubs = c.get("hubs") or []
    chosen = [h for h in hubs if h["instrument"]]
    if chosen:
        why = "the instrument's name was found among the devices on " + ("this root hub"
                                                                        if len(chosen) == 1
                                                                        else "these root hubs")
    else:
        chosen = hubs
        why = "the instrument was not found by name on any root hub, so all are recorded"
    lines.append(f"  USBPcap root hubs found: {len(hubs)}")
    for h in hubs:
        mark = "  <-- recorded" if h in chosen else ""
        lines.append(f"    {h['path']} ({h['display']}){mark}")
        for addr, name in h.get("devices") or []:
            lines.append(f"      device {addr}: {name}")
        if not h.get("devices"):
            lines.append("      (USBPcapCMD listed no devices here)")
    lines.append(f"  why: {why}" if hubs else "  (none: nothing to record on)")
    return "\n".join(lines)


def windows_driver_devices() -> list:
    return parse_driver_lines(_powershell(_DRIVER_PS))


def windows_capture_checks(profile: str) -> dict:
    """Everything needed to say honestly whether a recording can work here."""
    build = windows_build_info()
    arm = windows_is_arm()
    sc = run(["sc", "query", "USBPcap"], timeout=15)
    service = parse_sc_query(sc)
    if "pretend-usbpcap" in SELFTEST:
        service = {"installed": True, "running": True}
    cmd = find_usbpcapcmd()
    interfaces = parse_extcap_interfaces(run([cmd, "--extcap-interfaces"], timeout=30)) \
        if cmd else []
    hubs = []
    for path, display in interfaces:
        devs = parse_extcap_devices(run([cmd, "--extcap-config", "--extcap-interface", path],
                                        timeout=30))
        hubs.append({"path": path, "display": display, "devices": devs,
                     "instrument": [d for d in devs if _XRITE_NAME_RE.search(d[1])]})
    programs = windows_program_versions()
    i1p = next((v for k, v in programs.items() if "i1profiler" in k.lower()), None)
    drivers = instrument_driver_checks(windows_driver_devices())
    working = any(d.get("vendor_working") for d in drivers)
    return {"windows": windows_release_check(build["build"], build["display"], arm, profile,
                                             vendor_driver_working=working),
            "service": service, "usbpcapcmd": cmd, "hubs": hubs,
            "admin": windows_is_admin(), "programs": programs, "arm": arm,
            "i1profiler": i1profiler_check(i1p, profile, build["build"]), "build": build,
            "drivers": drivers}


def driver_help_needed(c: dict) -> bool:
    return any(d["help"] for d in c.get("drivers") or [])


_LEVEL_WORDS = {"ok": "OK", "warning": "PLEASE READ", "problem": "PROBLEM",
                "unknown": "not known"}


def windows_checks_text(c: dict) -> str:
    lines = ["  WHAT THIS PC OFFERS FOR A RECORDING (read only, nothing changed)", ""]

    def row(label, level, text):
        lines.append(f"  {label:<18} [{_LEVEL_WORDS[level]}] " + _wrap(text, 44, " " * 21 + "     "))

    row("Windows:", c["windows"]["level"], c["windows"]["text"])
    row("i1Profiler:", c["i1profiler"]["level"], c["i1profiler"]["text"])
    others = {k: v for k, v in c["programs"].items() if "i1profiler" not in k.lower()}
    if others:
        row("Other programs:", "ok", ", ".join(f"{k} {v}" for k, v in others.items()))
    svc = c["service"]
    if svc["running"]:
        row("USBPcap:", "ok", "installed and running")
    elif svc["installed"]:
        row("USBPcap:", "warning", "installed, but not running yet. Restart Windows once.")
    else:
        row("USBPcap:", "problem", "not installed (see below how to install it)")
    row("USBPcapCMD:", "ok" if c["usbpcapcmd"] else "problem",
        c["usbpcapcmd"] or "not found (it comes with USBPcap)")
    for d in c.get("drivers") or []:
        row("Driver:", d["level"], d["text"])
    admin = c["admin"]
    row("Administrator:", "ok" if admin else "problem" if admin is False else "unknown",
        "yes, this window runs as administrator" if admin else
        "no. A recording needs it (see below how to start the tool as "
        "administrator)." if admin is False else "not known")
    if c["hubs"]:
        found = [h for h in c["hubs"] if h["instrument"]]
        if found:
            for h in found:
                names = ", ".join(n for _a, n in h["instrument"])
                row("Instrument on:", "ok", f"{h['display']} ({names})")
        else:
            row("Instrument on:", "unknown",
                "could not tell which USB root hub; the tool records on all of them "
                f"({', '.join(h['display'] for h in c['hubs'])}) and keeps only the "
                "instrument's traffic")
    return "\n".join(lines)


def tool_name() -> str:
    """What the user double-clicked, for "right-click ... Run as administrator"."""
    if getattr(sys, "frozen", False):
        return os.path.basename(sys.executable)
    if platform.system() == "Windows":
        return "Start-Windows.bat"
    return os.path.basename(__file__)


# 1.5.2. Facts, checked 2026-11-13 in USBPcap's source (github.com/desowin/
# usbpcap): the capture device is created with the security descriptor
# "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GX;;;WD)(A;;GX;;;RC)"
# (USBPcapDriver/USBPcapRootHubControl.c), so only SYSTEM and administrators
# may open it to read. USBPcapCMD's manifest asks for "asInvoker"; when it is
# not elevated it starts an elevated copy of itself through ShellExecuteEx
# "runas" (USBPcapCMD/cmd.c, create_elevated_worker), that is one Windows
# permission question per recorder start. This tool starts one recorder per
# USB root hub for every step, so without administrator rights the user would
# be asked again and again, and a missed or refused question records nothing.
# 1.5.1 let the session start anyway and said "may refuse".
def admin_help_text() -> str:
    return f"""\
  WHY ADMINISTRATOR RIGHTS ARE NEEDED
  USBPcap only lets programs that run as administrator listen to the USB
  ports. Started without those rights, its recorder would have to ask
  Windows for permission again at every step, and a question that is
  missed or answered "No" means nothing is recorded. So this tool does not
  start the steps until it runs as administrator.

  HOW TO START THIS TOOL AS ADMINISTRATOR
    1. Close this window.
    2. Right-click  {tool_name()}  and choose
       "Run as administrator".
    3. When Windows asks whether to allow it, click "Yes".
    4. Choose the recording session again."""


def windows_can_record(c: dict) -> bool:
    return bool(c["usbpcapcmd"]) and c["service"]["installed"] and bool(c["hubs"])


# ---- recorders -------------------------------------------------------------

class RecorderError(Exception):
    pass


_JOB: list = []


def _kill_with_us(proc) -> None:
    """Windows: put a recorder into a job that ends it when this program
    ends, also when its window is closed (review of 1.5.4: USBPcapCMD run
    as administrator has no job of its own and would go on recording).
    Best effort: any failure leaves things as in 1.5.3."""
    if os.name != "nt":
        return
    try:
        import ctypes                                     # noqa: PLC0415
        from ctypes import wintypes                       # noqa: PLC0415
        k32 = ctypes.windll.kernel32                      # type: ignore[attr-defined]
        k32.CreateJobObjectW.restype = wintypes.HANDLE
        k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        k32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                                ctypes.c_void_p, wintypes.DWORD]
        k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        if not _JOB:
            job = k32.CreateJobObjectW(None, None)
            if not job:
                return

            class _Basic(ctypes.Structure):
                _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64),
                            ("PerJobUserTimeLimit", ctypes.c_int64),
                            ("LimitFlags", wintypes.DWORD),
                            ("MinimumWorkingSetSize", ctypes.c_size_t),
                            ("MaximumWorkingSetSize", ctypes.c_size_t),
                            ("ActiveProcessLimit", wintypes.DWORD),
                            ("Affinity", ctypes.c_size_t),
                            ("PriorityClass", wintypes.DWORD),
                            ("SchedulingClass", wintypes.DWORD)]

            class _Io(ctypes.Structure):
                _fields_ = [(n, ctypes.c_uint64) for n in
                            ("r", "w", "o", "rb", "wb", "ob")]

            class _Ext(ctypes.Structure):
                _fields_ = [("Basic", _Basic), ("Io", _Io),
                            ("ProcessMemoryLimit", ctypes.c_size_t),
                            ("JobMemoryLimit", ctypes.c_size_t),
                            ("PeakProcessMemoryUsed", ctypes.c_size_t),
                            ("PeakJobMemoryUsed", ctypes.c_size_t)]
            info = _Ext()
            info.Basic.LimitFlags = 0x2000                # KILL_ON_JOB_CLOSE
            if not k32.SetInformationJobObject(job, 9, ctypes.byref(info),
                                               ctypes.sizeof(info)):
                k32.CloseHandle(job)
                return
            _JOB.append(job)
        k32.AssignProcessToJobObject(_JOB[0], int(proc._handle))  # noqa: SLF001
    except Exception:                                     # noqa: BLE001
        pass


class _ProcRecorder:
    """Shared start/stop logic: one recording process per interface per step.

    1.5.4: every start is written down in self.diag (command, exit code, the
    program's own output, the file it made), so a failure can be read in the
    report, not only on the screen."""

    label = "recorder"
    # tcpdump: the file is created by us first, so it stays ours (not root's).
    # USBPcapCMD must NOT find it there (see UsbPcapRecorder).
    precreate = True

    def __init__(self, interfaces: list, outdir: str):
        self.interfaces = list(interfaces)
        self.outdir = outdir
        self.procs: dict = {}
        self.files: dict = {}
        self.notes: list = []
        self.diag: list = []
        self.logs: list = []

    def command(self, iface, path) -> list:
        raise NotImplementedError

    def iface_label(self, iface) -> str:
        return re.sub(r"[^A-Za-z0-9]+", "", str(iface)) or "bus"

    def session_start(self) -> bool:
        return True

    def session_end(self) -> None:
        pass

    # USBPcapCMD: stop it directly. With its output in a file it does not
    # attach to our console, so Ctrl-Break cannot reach it; ending it is safe
    # because it flushes the file after every write (thread.c write_data).
    stop_hard = False

    def _popen(self, cmd, log_path=None):
        """stdout and stderr go into a small log file next to the recording,
        read when the program has ended. A disk file: USBPcapCMD then surely
        keeps its messages there (with a console it would write them to that
        console instead, cmd.c attach_parent_console), so the report gets
        them. A job object ends the program with this one (_kill_with_us)."""
        log = open(log_path, "wb") if log_path else subprocess.DEVNULL
        kwargs = {"stdin": subprocess.DEVNULL, "stdout": log,
                  "stderr": subprocess.STDOUT if log_path else subprocess.DEVNULL}
        if os.name == "nt":
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        try:
            proc = subprocess.Popen(cmd, **kwargs)
        finally:
            if log_path:
                log.close()
        _kill_with_us(proc)
        return proc

    @staticmethod
    def _read_log(path) -> str:
        try:
            with open(path, "rb") as fh:
                return fh.read(4000).decode("utf-8", "replace").strip()
        except OSError:
            return ""

    def _prepare(self, path) -> None:
        if os.path.exists(path):
            os.remove(path)           # a leftover from an earlier try
        if self.precreate:
            open(path, "wb").close()

    def _launch(self, iface, cmd, path, attempt: str) -> dict:
        entry = {"interface": str(iface), "attempt": attempt, "command": " ".join(cmd),
                 "file": os.path.basename(path)}
        self.diag.append(entry)
        if os.name == "nt":
            note = ("the folder's path has characters that USBPcapCMD (an ANSI "
                    "program) may not be able to use")
            try:
                if path.encode("mbcs").decode("mbcs") != path:
                    entry["path_note"] = note
            except UnicodeError:
                entry["path_note"] = note
            except LookupError:
                pass
        log_path = path + "." + attempt.split()[0] + ".log"
        try:
            self._prepare(path)
            self.procs[iface] = self._popen(cmd, log_path)
            self.logs.append(log_path)
        except OSError as exc:
            entry["result"] = f"could not be started: {exc}"
            self.notes.append(f"{iface}: could not start ({exc})")
            return entry
        time.sleep(RECORDER_STARTUP_WAIT)
        proc = self.procs[iface]
        size = os.path.getsize(path) if os.path.exists(path) else None
        entry["file_after_start"] = ("not created" if size is None else f"{size} bytes")
        if proc.poll() is None:
            entry["result"] = "running"
            if size is None and not self.precreate:
                entry["warning"] = "running, but it has not created its file yet"
                self.notes.append(f"{iface}: running, but no recording file yet")
            return entry
        out = self._read_log(log_path)
        entry["result"] = f"stopped at once, exit code {proc.returncode}" + (
            " (USBPcapCMD ends with 0 even when it fails)" if proc.returncode == 0 else "")
        entry["output"] = out or "(nothing)"
        self.notes.append(f"{iface}: stopped at once (exit code {proc.returncode})"
                          + (": " + " ".join(out.split())[:200] if out else ""))
        return entry

    def start(self, stem: str) -> list:
        """Start recording; returns the interfaces that really record."""
        self.procs, self.files = {}, {}
        live = []
        for iface in self.interfaces:
            path = os.path.join(self.outdir, f"{stem}-{self.iface_label(iface)}-full.pcap")
            self.files[iface] = path
            entry = self._launch(iface, self.command(iface, path), path, "first try")
            if entry.get("result") == "running":
                live.append(iface)
                continue
            retry = self.retry_command(iface, path, entry.get("output", ""))
            if retry:
                entry = self._launch(iface, retry, path, "retry (simpler options)")
                if entry.get("result") == "running":
                    live.append(iface)
                    self.notes.append(f"{iface}: recording with simpler options")
        for iface in list(self.files):
            if iface not in self.procs:
                self.files.pop(iface)
        return live

    def retry_command(self, iface, path, err):
        return None

    def diag_text(self) -> str:
        lines = []
        for e in self.diag:
            lines.append(f"{e['interface']} ({e['attempt']}): {e.get('result', '?')}")
            lines.append(f"    command: {e['command']}")
            if "file_after_start" in e:
                lines.append(f"    output file {e['file']}: {e['file_after_start']}")
            for key in ("warning", "path_note"):
                if key in e:
                    lines.append(f"    note: {e[key]}")
            if "output" in e:
                lines.append("    what the program said: "
                             + " | ".join(l.strip() for l in e["output"].splitlines() if l.strip()))
        return "\n".join(lines)

    def stop(self) -> list:
        """Stop every recorder; returns the files that exist."""
        for iface, proc in self.procs.items():
            if proc.poll() is not None:
                continue
            try:
                if os.name == "nt" and self.stop_hard:
                    proc.terminate()
                    proc.wait(timeout=6)
                elif os.name == "nt":
                    try:
                        proc.send_signal(signal.CTRL_BREAK_EVENT)   # type: ignore[attr-defined]
                        proc.wait(timeout=4)
                    except (subprocess.TimeoutExpired, OSError, ValueError, AttributeError):
                        proc.terminate()
                        proc.wait(timeout=6)
                else:
                    proc.terminate()
                    proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                try:
                    proc.kill()
                    proc.wait(timeout=5)
                except (OSError, subprocess.TimeoutExpired):
                    pass
            except OSError:
                pass
        for path in self.logs:
            try:
                os.remove(path)
            except OSError:
                pass
        self.logs = []
        files = []
        for path in self.files.values():
            if not os.path.exists(path):
                continue
            if os.path.getsize(path) == 0:       # created by us, never written
                try:
                    os.remove(path)
                except OSError:
                    pass
                continue
            files.append(path)
        self.procs, self.files = {}, {}
        return files


class UsbPcapRecorder(_ProcRecorder):
    """Windows: USBPcapCMD, one per root hub, with the device descriptions.

    1.5.4: run as administrator, USBPcapCMD opens its output file with
    CREATE_NEW (USBPcapCMD/cmd.c, start_capture, in 1.5.4.0 and on master),
    which FAILS when the file already exists; its read thread then says
    "Thread started with invalid write handle!" and the program ends at once
    (thread.c). 1.5.3 created the file first, as for tcpdump on a Mac, so
    every start on a real Windows with USBPcap ended at once, and the retry
    did the same. Here the file is left for USBPcapCMD to create."""

    label = "USBPcap (USBPcapCMD)"
    precreate = False
    stop_hard = True

    def __init__(self, exe: str, interfaces: list, outdir: str):
        super().__init__(interfaces, outdir)
        self.exe = exe

    def _base(self) -> list:
        # A ".py" stand-in (the tests' fake USBPcapCMD) runs with this Python.
        if self.exe.lower().endswith(".py"):
            return [sys.executable, self.exe]
        return [self.exe]

    def command(self, iface, path):
        # -A: every device on this root hub (the X-Rite-only copy is made
        # afterwards); --inject-descriptors: put the description of the
        # devices already connected at the start of the file.
        return self._base() + ["-d", iface, "-o", path, "-A", "--inject-descriptors"]

    def retry_command(self, iface, path, err):
        return self._base() + ["-d", iface, "-o", path, "-A"]

    def iface_label(self, iface):
        return str(iface).replace("\\\\.\\", "").replace("\\", "").replace(".", "") or "USBPcap"


class TcpdumpRecorder(_ProcRecorder):
    """Mac with SIP off (XHC* interfaces) or Linux (usbmon*), through sudo."""

    label = "tcpdump"

    def __init__(self, interfaces: list, outdir: str, mac: bool):
        super().__init__(interfaces, outdir)
        self.mac = mac
        self.sudo = shutil.which("sudo")
        self.tcpdump = shutil.which("tcpdump") or "/usr/sbin/tcpdump"
        self.ifconfig = shutil.which("ifconfig") or "/sbin/ifconfig"
        self.brought_up: list = []
        self.stop_keepalive = threading.Event()

    def session_start(self) -> bool:
        if not self.sudo:
            self.notes.append("sudo not found")
            return False
        print("\n  Your computer will now ask for your password (for its own \"sudo\"")
        print("  command; this tool never sees or stores it).")
        try:
            if subprocess.call([self.sudo, "-v"]) != 0:
                return False
        except KeyboardInterrupt:
            return False

        def keepalive():
            while not self.stop_keepalive.wait(50):
                subprocess.call([self.sudo, "-n", "true"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)

        threading.Thread(target=keepalive, daemon=True).start()
        if self.mac:
            for iface in self.interfaces:
                if not _iface_is_up(self.ifconfig, iface):
                    if subprocess.call([self.sudo, "-n", self.ifconfig, iface, "up"],
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL) == 0:
                        self.brought_up.append(iface)
        return True

    def session_end(self) -> None:
        for iface in self.brought_up:
            subprocess.call([self.sudo, "-n", self.ifconfig, iface, "down"],
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if self.brought_up:
            still = [i for i in self.brought_up if _iface_is_up(self.ifconfig, i)]
            if still:
                print(f"  Could not switch {', '.join(still)} off again. They switch off "
                      "by themselves when you restart.")
            else:
                print(f"  Switched {', '.join(self.brought_up)} off again.")
        self.brought_up = []
        self.stop_keepalive.set()

    def command(self, iface, path):
        return [self.sudo, "-n", self.tcpdump, "-U", "-i", iface, "-w", path]


def linux_usbmon_interfaces() -> list:
    names = sorted({os.path.basename(p) for p in glob.glob("/dev/usbmon*")})
    return [n for n in names if re.fullmatch(r"usbmon\d+", n)]


# ---- the session itself ------------------------------------------------------

def _write_session(session: dict, folder: str) -> None:
    """Write session.json safely: a broken write never destroys the old one."""
    path = os.path.join(folder, "session.json")
    tmp = path + ".tmp"
    clean = {k: v for k, v in session.items() if not k.startswith("_")}
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(clean, fh, indent=2)
        os.replace(tmp, path)
    except OSError:
        pass


class _StopSession(Exception):
    pass


def flush_pending_input() -> int:
    """1.5.5: throw away keys pressed while the tool was busy, so they cannot
    answer the next question. A real tester pressed Enter several times while
    the tool was silently stopping and checking a recording; the extra
    Enters then started and stopped the next steps at once (0.0 s, empty
    files). Returns how many keys were thrown away (when that can be told)."""
    dropped = 0
    try:
        if os.name == "nt":
            import msvcrt                                 # noqa: PLC0415
            while msvcrt.kbhit():                         # type: ignore[attr-defined]
                msvcrt.getwch()                           # type: ignore[attr-defined]
                dropped += 1
        elif _isatty(sys.stdin):
            import termios                                # noqa: PLC0415
            termios.tcflush(sys.stdin.fileno(), termios.TCIFLUSH)
    except Exception:                                     # noqa: BLE001
        pass
    return dropped


def quick_edit_off():
    """1.5.5 review: in the classic Windows console a click into the window
    starts a text selection ("Select" in the title), and the next Enter only
    ends that selection instead of reaching the tool. That fits "keyboard
    not accepting Enter" too. Switch QuickEdit off for the session and give
    back the old mode afterwards. Returns a function that restores it."""
    if os.name != "nt":
        return lambda: None
    try:
        import ctypes                                     # noqa: PLC0415
        from ctypes import wintypes                       # noqa: PLC0415
        k32 = ctypes.windll.kernel32                      # type: ignore[attr-defined]
        k32.GetStdHandle.restype = wintypes.HANDLE
        handle = k32.GetStdHandle(-10)                    # STD_INPUT_HANDLE
        mode = wintypes.DWORD()
        if not k32.GetConsoleMode(handle, ctypes.byref(mode)):
            return lambda: None
        old = mode.value
        new = (old | 0x0080) & ~0x0040                    # EXTENDED_FLAGS on, QUICK_EDIT off
        if new == old or not k32.SetConsoleMode(handle, new):
            return lambda: None
        return lambda: k32.SetConsoleMode(handle, old)
    except Exception:                                     # noqa: BLE001
        return lambda: None


def _session_ask(prompt: str, flush: bool = True) -> str:
    """ask(), but Ctrl-C and a closed window end the session cleanly. Keys
    pressed before the question appeared are thrown away first (1.5.5)."""
    if flush:
        flush_pending_input()
    try:
        return ask(prompt, interruptible=True)
    except KeyboardInterrupt:
        raise _StopSession("Ctrl-C") from None


def choose_profile(pids: list) -> str:
    """Which session fits the instruments seen. pids: [(vid, pid), ...]."""
    for key in pids:
        if key in PROFILE_IDS:
            return PROFILE_IDS[key]
    return "generic"


def _ask_profile(default: str, seen: bool = True) -> str:
    keys = ["i1pro2", "i1pro", "i1pro3", "munki", "isis", "generic"]
    print("\n  Which instrument do you use for this session?")
    for i, key in enumerate(keys, 1):
        # 1.5.3: only when an instrument was really seen (found on a Mac
        # with nothing plugged in: "another X-Rite instrument <- seen")
        mark = "   <- seen on this computer" if key == default and seen else ""
        print(f"    {i}. {PROFILE_NAMES[key]}{mark}")
    if default in ("i1pro2", "i1pro"):
        print("  (The i1Pro and the i1Pro 2 look the same to the computer. If you are")
        print("  not sure which one you have, choose 1: the recording tells them apart.")
        print("  If you have both, plug in only the one you record with, so that the")
        print("  recording holds just that one.)")
    answer = _session_ask(f"  Type a number, or press Enter for {keys.index(default) + 1}: ")
    if answer.isdigit() and 1 <= int(answer) <= len(keys):
        return keys[int(answer) - 1]
    return default


def _ask_program(detected: dict) -> tuple:
    print("\n  Which program do you measure with?")
    for i, name in enumerate(VENDOR_PROGRAMS, 1):
        print(f"    {i}. {name}")
    print(f"    {len(VENDOR_PROGRAMS) + 1}. something else (type its name)")
    if detected:
        print("  Found on this computer: " +
              ", ".join(f"{k} {v}".strip() for k, v in detected.items()))
    answer = _session_ask("  Type a number or the program's name: ")
    if answer.isdigit() and 1 <= int(answer) <= len(VENDOR_PROGRAMS):
        program = VENDOR_PROGRAMS[int(answer) - 1]
    else:
        program = answer
    guess = next((v for k, v in detected.items()
                  if program and program.split()[0].lower() in k.lower()), "")
    version = _session_ask("  Which version of it? (shown in its Help or About window)"
                           + (f" Press Enter for {guess}: " if guess else ": ")) or guess
    return program, version


def privacy_text(profile: str) -> str:
    if profile == "isis":
        # 1.6 review: worded exactly as instrument_selection() and the
        # analysis behave, and "very likely" where nothing is proven yet.
        return """\
  WHAT THE RECORDING CONTAINS, AND WHAT HAPPENS TO IT
  - The USB conversation between i1Profiler and the i1iSis. That very
    likely includes the i1iSis's serial number and its factory
    calibration data, as it does for every X-Rite instrument we know
    (not yet proven for the i1iSis). They identify your i1iSis, not you.
  - The colour values the i1iSis measured from your chart page (your
    printer's and paper's colours; they say nothing about you) and, if
    the chart has a barcode, what the barcode holds, which may include
    the chart's name.
  - While a step records, the recording program also sees the other USB
    devices on the same USB port group, such as a keyboard or a monitor
    calibrator. Please do not type anything private during a step. After
    each step the tool makes a copy that holds ONLY the i1iSis's traffic,
    and that copy is the only thing to send. If a step's recording does
    not show an i1iSis at all, the copy holds an X-Rite device this tool
    does not know instead (in case that is your i1iSis), and the tool
    tells you so right after the step; it never keeps a keyboard or an
    X-Rite instrument it knows to be another one. If the recording does
    not show which device is which, the tool keeps nothing.
  - Your short notes for each step.
  Nothing is uploaded, ever. You decide whether to send the files, and you
  send them yourself. At the end the tool offers to delete the full
  recordings, which you never need to send."""
    return f"""\
  WHAT THE RECORDING CONTAINS, AND WHAT HAPPENS TO IT
  - The USB conversation between the program and the instrument. That
    necessarily includes the instrument's serial number and its factory
    calibration data, because the program reads them from the instrument
    every time it connects. They identify your instrument, not you.
  - While a step records, the recording program also sees the other USB
    devices on the same USB port group, such as a keyboard. Please do not
    type anything private during a step. After each step the tool makes a
    copy that holds ONLY the instrument's traffic (its device address and
    nothing else), and that copy is the only thing to send.
  - Your short notes for each step.
  Nothing is uploaded, ever. You decide whether to send the files, and you
  send them yourself. At the end the tool offers to delete the full
  recordings, which you never need to send."""


def run_instrument_session(recorder, folder: str, profile: str, program: str = "",
                           program_version: str = "", context: dict | None = None,
                           only: list | None = None) -> dict:
    """The guided steps. Returns the session dict (also written to session.json).

    recorder: an object with start(stem) -> live interfaces, stop() -> files,
    session_start(), session_end(), or None for time marks only (the user
    records the whole session himself, for example with Wireshark).
    """
    os.makedirs(folder, exist_ok=True)
    _END["session_folder"] = folder
    full_dir = folder + "-FULL-do-not-send"
    if recorder is not None:
        os.makedirs(full_dir, exist_ok=True)
        recorder.outdir = full_dir
    numbered = [(i, st) for i, st in enumerate(steps_for(profile), 1)
                if not only or i in only]
    steps = [st for _i, st in numbered]
    session = {
        "kind": SESSION_KIND, "probe_version": PROBE_VERSION,
        "created": datetime.datetime.now().isoformat(timespec="seconds"),
        "family": profile, "instrument": PROFILE_NAMES[profile],
        "program": program, "program_version": program_version,
        "recorder": recorder.label if recorder else "time marks only",
        "platform": platform.platform(), "steps": [], "ended": "",
        "context": context or {},
    }
    if only:
        session["only_steps"] = list(only)
    if recorder is None:
        session["whole_recording"] = "whole-session.pcapng"
    _write_session(session, folder)
    old_handlers = {}
    for sig in (getattr(signal, "SIGHUP", None), signal.SIGTERM,
                getattr(signal, "SIGBREAK", None)):
        if sig is None:
            continue
        try:
            old_handlers[sig] = signal.signal(sig, _raise_hangup)
        except (ValueError, OSError):
            pass
    lights = profile in PROFILES_WITH_LIGHTS
    recording = False
    restore_console = quick_edit_off()
    try:
        if recorder is not None and not recorder.session_start():
            session["ended"] = "the recording program could not be started"
            print("\n  The recording could not be started, so no step was recorded.")
            return session
        index = 0
        take = 1
        while index < len(steps):
            step = steps[index]
            number = numbered[index][0]
            total = len(steps_for(profile))
            print("\n" + "-" * 68)
            print(f"  STEP {number} of {total}: {step['title']}"
                  + (f"  (take {take})" if take > 1 else ""))
            print("-" * 68)
            print(step["before"])
            print()
            print(step_box(step["during"], step.get("box", "Then do this in the measuring "
                                                    "program: ")))
            answer = _session_ask("\n  Press Enter to START recording (s = skip this step, "
                                  "q = stop): ").lower()
            if not answer and _INPUT_ENDED:
                session["ended"] = "the input ended (window closed or nothing more typed)"
                break
            if answer.startswith("q"):
                if not any(s.get("files_xrite") or s.get("start_epoch")
                           for s in session["steps"]):
                    # 1.5.4: a real tester measured in the program, never
                    # started a step here, and stopped with nothing recorded.
                    print("\n  Nothing was recorded yet. The tool records only between the")
                    print("  Enter that starts a step and the  e  + Enter that stops it.")
                    if not said_yes(_session_ask("  Stop anyway? (yes / no): ")):
                        continue
                session["ended"] = "stopped by the operator"
                break
            entry = {"number": number, "key": step["key"], "title": step["title"],
                     "take": take, "control": bool(step.get("control"))}
            if answer.startswith("s"):
                entry["skipped"] = True
                session["steps"].append(entry)
                _write_session(session, folder)
                print("  Skipped.")
                index += 1
                take = 1
                continue
            stem = f"step{number}-{step['key']}-take{take}"
            live = ["(your own recording)"]
            if recorder is not None:
                live = recorder.start(stem)
                recording = True
                if not live:
                    recording = False
                    recorder.stop()
                    diag = recorder.diag_text() if hasattr(recorder, "diag_text") else ""
                    session["recorder_failure"] = scrub(diag)
                    print("\n  THE RECORDING DID NOT START")
                    print("  " + _wrap(recorder_failure_words(diag), 66, "  "))
                    print("  What the recording program said:")
                    for note in recorder.notes[-4:]:
                        print("    " + _wrap(note, 64, "      "))
                    session["ended"] = "the recording program stopped at once"
                    _write_session(session, folder)
                    break
            entry["start_epoch"] = time.time()
            where = ", ".join(recorder.iface_label(x) if recorder else str(x) for x in live)
            print(f"\n  RECORDING STEP {number} NOW ({where}).")
            print("  Do the step in the measuring program now. Then come back to THIS")
            print("  window, type  e  and press Enter to stop. (Type  q  and Enter to")
            print("  stop the whole session after this step.)")
            stop_after = False
            interrupted = None
            ticker = LiveLine(recorder, entry["start_epoch"])
            try:
                ticker.start()
                while True:
                    done = _session_ask("  > ").lower()
                    if done.startswith("e") or done.startswith("q"):
                        break
                    if not done and _INPUT_ENDED:
                        break
                    print("    (still recording: type  e  and press Enter to stop)")
                stop_after = done.startswith("q")
                print("  Key received. Stopping the recording and checking it, please")
                print("  wait a few seconds and do not press any key...")
            except _StopSession as exc:
                interrupted = f"ended early ({exc}) during step {number}"
            except _Hangup:
                interrupted = f"ended early (window closed or stop signal) during step {number}"
            finally:
                ticker.stop()
                entry["end_epoch"] = time.time()
                if recorder is not None and recording:
                    entry["files_full"] = [os.path.basename(p) for p in recorder.stop()]
                    recording = False
            entry["files_xrite"] = []
            entry["check"] = []
            activity = 0
            empty = False
            zero = False
            for name in entry.get("files_full", []):
                src = os.path.join(full_dir, name)
                check = check_capture(src, profile)
                entry["check"].append(f"{name}: {check['xrite_packets']} instrument packets; "
                                      f"{check['verdict']}")
                activity += check.get("activity") or 0
                empty = empty or check["code"] == "empty-step"
                zero = zero or check["code"] == "all-zero"
                if check["code"] == "unidentified":
                    entry["unidentified"] = True
                if check["xrite_packets"] and check["code"] in ("ok", "all-zero"):
                    dst_name = name.replace("-full.pcap", "-instrument.pcap")
                    if filter_xrite_capture(src, os.path.join(folder, dst_name), profile):
                        entry["files_xrite"].append(dst_name)
                        if check.get("kept") == "unknown":
                            entry["kept_unknown"] = sorted(
                                {f"{v:04x}:{p:04x}" for v, p in check["kept_ids"]}
                                | set(entry.get("kept_unknown", [])))
            if recorder is not None and (not entry["files_xrite"] or zero):
                entry["empty"] = True
            session["steps"].append(entry)
            _write_session(session, folder)
            if recorder is not None:
                print("  CHECK: " + _wrap(handheld_step_verdict(entry, activity, empty, zero),
                                          64, "  "))
            seconds = entry["end_epoch"] - entry["start_epoch"]
            question = None
            if recorder is not None and entry.get("empty"):
                question = ("\n  Type  r  and press Enter to record this step again, or press "
                            "Enter to go on: ")
            elif seconds < SHORT_STEP_SECONDS and not stop_after:
                question = (f"\n  That was very short ({seconds:.1f} s). Was it on purpose? "
                            "Type  r  to record\n  this step again, or press Enter to keep it: ")
            if not interrupted and question:
                again = _session_ask(question).lower()
                if again.startswith("r"):
                    entry["kept"] = False
                    if not entry.get("empty"):
                        entry["too_short"] = True
                    _write_session(session, folder)
                    take += 1
                    continue
                if recorder is not None and entry.get("empty"):
                    # Nothing to describe: go on without the notes questions.
                    entry["kept"] = True
                    _write_session(session, folder)
                    if stop_after:
                        session["ended"] = "stopped by the operator"
                        break
                    index += 1
                    take = 1
                    continue
            if interrupted:
                # Keep what was recorded, ask nothing more, end the session.
                entry["interrupted"] = True
                _write_session(session, folder)
                session["ended"] = interrupted
                break
            example = ('"page 1, measured", or "refused: barcode not found"'
                       if profile == "isis" else '"strip A, accepted", or "refused: too fast"')
            entry["notes"] = _session_ask(
                "\n  In one line: what did you do, and what did the program show?\n"
                f"  (for example: {example})\n  > ")
            if step.get("setting"):
                entry["setting"] = _session_ask(f"  {step['setting']}\n  > ")
            if step.get("page"):
                entry["page"] = _session_ask(f"  {step['page']}\n  > ")
            if lights:
                entry["lights"] = _session_ask(
                    f"  {step['lights']}\n  (colours, blinking, when; Enter if you did not "
                    "notice)\n  > ")
            _write_session(session, folder)
            if stop_after:
                session["ended"] = "stopped by the operator"
                break
            again = _session_ask("\n  Press Enter to go on to the next step, or type  r  to "
                                 "record this step again: ").lower()
            if again.startswith("r"):
                entry["kept"] = False
                _write_session(session, folder)
                take += 1
                continue
            entry["kept"] = True
            _write_session(session, folder)
            index += 1
            take = 1
        else:
            session["ended"] = "all steps done"
    except _StopSession as exc:
        session["ended"] = f"ended early ({exc})"
    except _Hangup:
        session["ended"] = "ended early (window closed or stop signal)"
    finally:
        if recorder is not None:
            if recording:
                files = recorder.stop()
                session["unfinished_files"] = [os.path.basename(p) for p in files]
            recorder.session_end()
        try:
            restore_console()
        except Exception:                                 # noqa: BLE001
            pass
        for sig, handler in old_handlers.items():
            try:
                signal.signal(sig, handler)
            except (ValueError, OSError):
                pass
        _write_session(session, folder)
    return session


SHORT_STEP_SECONDS = 2.0


def handheld_step_verdict(entry: dict, activity: int, empty: bool, zero: bool = False) -> str:
    """1.5.5: the per-step check of a handheld session, as the Mac table
    session has it."""
    if zero:
        return ("ALL-ZERO: the recording shows the traffic, but every data byte is zero, so "
                "it cannot show the commands. This is a limit of this Mac, not your mistake.")
    if entry.get("files_xrite") and activity and entry.get("kept_unknown"):
        # 1.6 review: an i1iSis session that saw no i1iSis keeps an X-Rite
        # device the tool does not know, and says so.
        word = "request or data transfer" if activity == 1 else "requests and data transfers"
        return (f"this step recorded {activity} {word}, but not of an i1iSis: no i1iSis "
                f"(0971:2006) was seen in it. The tool kept the traffic of an X-Rite device "
                f"it does not know ({', '.join(entry['kept_unknown'])}), in case that is "
                "your i1iSis. If it is not, please tell us; you can also repeat the step.")
    if entry.get("files_xrite") and activity:
        word = "request or data transfer" if activity == 1 else "requests and data transfers"
        return f"this step recorded {activity} {word} of the instrument: good."
    if entry.get("unidentified"):
        return ("NOTHING KEPT: this recording does not show which device is the i1iSis "
                "(it holds no USB description), so the tool kept nothing rather than risk "
                "keeping another device. Please repeat the step. If this happens again: "
                "start the step, then unplug the i1iSis's USB cable and plug it back in "
                "(leave the i1iSis switched on), so that the recording sees it arrive.")
    if empty:
        return "EMPTY: nothing was recorded in this step, please repeat it."
    return ("no instrument traffic was found in this step. Was the measuring program "
            "talking to the instrument? Please repeat it.")


def step_box(during: str, prefix: str = "Then do this in the measuring program: ") -> str:
    """1.5.4: the three things to do in one step, framed, so the order is
    impossible to miss (a real tester measured in the program without ever
    starting a step here)."""
    text = " ".join(during.split())
    for lead in ("When the recording runs:", "When the recording runs"):
        if text.startswith(lead):
            text = text[len(lead):].strip()
    rows = ["1. Press Enter HERE to start recording."]
    rows += _wrap("2. " + prefix + text, 60, "   ").split("\n")
    rows += ["3. Come back to THIS window, type  e  and press Enter to stop."]
    width = max(len(r) for r in rows) + 4
    line = "  +" + "-" * (width - 2) + "+"
    return "\n".join([line] + ["  | " + r.ljust(width - 4) + " |" for r in rows] + [line])


class LiveLine:
    """While a step records, show that it is running: elapsed seconds and the
    bytes recorded so far.

    1.5.5: no longer drawn on the line where the tester types. On a real
    tester's Windows PC, 1.5.4's line (rewritten every second with a carriage
    return) drew over what he typed, so his keys seemed to do nothing, and he
    pressed Enter again and again. Now only the window's title shows the
    running count; nothing is ever drawn over the input."""

    def __init__(self, recorder, start: float, stream=None, interval: float = 1.0,
                 every: float = 20.0):
        self.recorder = recorder
        self.start_t = start
        self.stream = stream or sys.stdout
        self.interval = interval
        self.every = every
        self._stop = threading.Event()
        self._thread = None

    def text(self, now: float | None = None) -> str:
        secs = int((now or time.time()) - self.start_t)
        size = None
        if self.recorder is not None:
            size = 0
            for path in list(getattr(self.recorder, "files", {}).values()):
                try:
                    size += os.path.getsize(path)
                except OSError:
                    pass
        if size is None:
            what = "your own recording runs"
        elif size == 0 and secs >= 5:
            what = "no data yet: instrument plugged in?"
        else:
            what = f"{size:,} bytes on this USB bus"
        return f"  recording {secs} s | {what} | stop: e + Enter"

    def _title(self, text: str) -> None:
        text = text.strip()
        try:
            if os.name == "nt":
                import ctypes                             # noqa: PLC0415
                ctypes.windll.kernel32.SetConsoleTitleW(text)  # type: ignore[attr-defined]
            else:
                self.stream.write(f"\x1b]0;{text}\x07")
                self.stream.flush()
        except Exception:                                 # noqa: BLE001
            pass

    def _run(self):
        while not self._stop.wait(self.interval):
            try:
                self._title(self.text())
            except (OSError, ValueError):
                return

    def start(self) -> None:
        if _isatty(self.stream):
            self._old = None
            try:
                if os.name == "nt":
                    import ctypes                         # noqa: PLC0415
                    buf = ctypes.create_unicode_buffer(512)
                    if ctypes.windll.kernel32.GetConsoleTitleW(buf, 512):  # type: ignore[attr-defined]
                        self._old = buf.value
                else:
                    self.stream.write("\x1b[22;0t")       # remember the title
            except Exception:                             # noqa: BLE001
                pass
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
            try:
                if os.name == "nt":
                    self._title(self._old or "ChromIQ instrument probe")
                else:
                    self.stream.write("\x1b[23;0t")       # give the old title back
                    self.stream.flush()
            except Exception:                             # noqa: BLE001
                pass


def recorder_failure_words(diag: str) -> str:
    """1.5.4: what a failed recorder start means, in plain words, from what
    USBPcapCMD itself prints (it ends with exit code 0 even then)."""
    low = (diag or "").lower()
    if "invalid write handle" in low:
        return ("USBPcap could not create its recording file. Version 1.5.3 of this "
                "tool caused exactly this (it made the file first, and USBPcap refuses "
                "to write into a file that already exists); this version no longer "
                "does that. If it still happens, the folder may not be writable for "
                "USBPcap, its path may hold characters USBPcap cannot handle, or "
                "security software (for example Windows' \"Controlled folder "
                "access\") may block it. Moving this tool into a plain folder such "
                "as C:\\ChromIQ-probe may help.")
    m = re.search(r"couldn't open device - (\d+)", low)
    if m:
        code = int(m.group(1))
        if code == 2:
            return ("USBPcap's recording device does not exist yet. Restart Windows "
                    "once after installing USBPcap, then try again.")
        if code in (5, 32):
            return ("Windows refused access to this USB root hub. Most likely another "
                    "recording of it is already running, for example Wireshark, or a "
                    "USBPcapCMD left over from an earlier try (see Task Manager). "
                    "Close it and try again.")
        return f"USBPcap could not open its recording device (Windows error {code})."
    if "access" in low and "denied" in low:
        return ("Windows refused USBPcap access. Please start this tool as "
                "administrator (right-click it, then \"Run as administrator\").")
    return ("The recording program ended at once, and this tool does not know why. "
            "Everything it said is in the report.")


def finish_session(session: dict, folder: str) -> tuple:
    """After the steps: summary lines, analysis file, offer to delete the full files."""
    full_dir = folder + "-FULL-do-not-send"
    whole = os.path.join(folder, "whole-session.pcapng")
    if session.get("recorder") == "time marks only" and os.path.exists(whole):
        # Recorded by hand with Wireshark: keep only the instrument's traffic
        # in the folder that gets sent, and move the full file out of it.
        copy = os.path.join(folder, "whole-session-instrument.pcap")
        if filter_xrite_capture(whole, copy, session.get("family")):
            os.makedirs(full_dir, exist_ok=True)
            try:
                os.replace(whole, os.path.join(full_dir, "whole-session.pcapng"))
            except OSError:
                pass
            session["whole_recording"] = "whole-session-instrument.pcap"
            for s in session["steps"]:
                if not s.get("skipped"):
                    s["cut_from_whole_recording"] = True
            _write_session(session, folder)
    done = [s for s in session["steps"] if s.get("files_xrite")
            or s.get("cut_from_whole_recording")]
    lines = [f"Session folder: {os.path.basename(folder)}",
             f"Ended: {session.get('ended') or 'unknown'}",
             f"Steps with a saved recording: {len(done)}"]
    for s in session["steps"]:
        state = "skipped" if s.get("skipped") else "replaced by the next take" if \
            s.get("kept") is False else (
            ", ".join(s.get("files_xrite") or [])
            or ("cut from whole-session-instrument.pcap" if s.get("cut_from_whole_recording")
                else "EMPTY: nothing recorded, please repeat this step" if s.get("empty")
                else "no instrument traffic"))
        lines.append(f"  step {s['number']} {s['title']} (take {s.get('take', 1)}): {state}")
    analysis = None
    if done:
        try:
            analysis = summarize_session([os.path.join(folder, "session.json")])
            with open(os.path.join(folder, "analysis.txt"), "w", encoding="utf-8") as fh:
                fh.write(analysis + "\n")
            lines.append("The analysis was saved as analysis.txt in the session folder.")
        except Exception as exc:                          # noqa: BLE001
            lines.append(f"The analysis could not be made ({exc}); the recordings are fine.")
    if os.path.isdir(full_dir) and not os.listdir(full_dir):
        try:
            os.rmdir(full_dir)
        except OSError:
            pass
    if os.path.isdir(full_dir) and os.listdir(full_dir):
        print("\n  The full recordings (in the folder ending in -FULL-do-not-send) hold")
        print("  everything that happened on those USB ports, possibly including what")
        print("  you typed on a USB keyboard. They are not needed: the session folder")
        print("  has the instrument-only copies.")
        flush_pending_input()
        if said_yes(ask("  Delete the full recordings now? Recommended. (yes / no): ")):
            for name in os.listdir(full_dir):
                try:
                    os.remove(os.path.join(full_dir, name))
                except OSError:
                    pass
            try:
                os.rmdir(full_dir)
            except OSError:
                pass
            lines.append("The full recordings were deleted.")
        else:
            lines.append("The full recordings were kept in the -FULL-do-not-send folder. "
                         "Please do not send them; delete them when you no longer need them.")
    return lines, analysis


HANDHELD_SEND_WAYS = f"""\
  To send it, choose whichever suits you:
    - attach it in the forum thread where you heard about this tool, or
    - open a new issue at
        {NEW_ISSUE_URL}
      and attach it there.
  If you would rather not post your instrument's serial number in public,
  send the zip in a private message to itsab1989 on the forum instead."""


def session_send_text(folder: str, profile: str | None = None) -> str:
    serial = ("It very likely contains your i1iSis's serial\n  number and its factory "
              "calibration data." if profile == "isis" else
              "It contains your instrument's serial\n  number and its factory "
              "calibration data.")
    return f"""\
  WHAT TO SEND (only if you want to)
  At the very end the tool puts everything we need into ONE file next to
  it, named  SEND-THIS-<date>.zip : the report, the instrument-only
  recordings, session.json (the steps and your notes) and analysis.txt.
  That one file is all you send. {serial}
{HANDHELD_SEND_WAYS}
  Do NOT send the folder ending in -FULL-do-not-send."""


def is_sendable(name: str) -> bool:
    """1.5.4 review: an allow-list. Only the tool's own files and its
    instrument-only copies; never a full recording (which can hold what was
    typed on a USB keyboard), whatever its name."""
    low = name.lower()
    return (low in ("session.json", "analysis.txt", "whole-session-instrument.pcap")
            or low.endswith("-instrument.pcap") or low.endswith("-xrite.pcap"))


def make_send_zip(report_path: str, send: dict) -> str | None:
    """1.5.4: ONE file to send, next to the report: the report, and the
    session folder's own files (instrument-only recordings, session.json,
    analysis.txt) or the given recordings. Never a full recording, never a
    sub-folder. Returns its path, or None."""
    import zipfile                                        # noqa: PLC0415
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    dst = os.path.join(os.path.dirname(report_path) or ".", f"SEND-THIS-{stamp}.zip")
    items = [report_path]
    folder = send.get("folder")
    if folder and os.path.isdir(folder):
        for name in sorted(os.listdir(folder)):
            full = os.path.join(folder, name)
            if os.path.isfile(full) and is_sendable(name):
                items.append(full)
    items += [f for f in send.get("files") or [] if os.path.isfile(f)
              and is_sendable(os.path.basename(f))]
    try:
        with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zf:
            for item in items:
                arc = os.path.basename(item)
                if folder and os.path.dirname(os.path.abspath(item)) == os.path.abspath(folder):
                    arc = os.path.basename(folder) + "/" + arc
                zf.write(item, arc)
    except (OSError, ValueError):
        return None
    return dst


def manual_recording_text(folder: str, after_failure: bool = False) -> str:
    why = ("  The tool's own start of the recording did not work (twice), so here\n"
           "  is the way by hand. " if after_failure else
           "  This tool could not start the recording itself, but ")
    return f"""\
  RECORDING WITH WIRESHARK BY HAND
{why}you can record the
  whole session with Wireshark while the tool notes the time of every
  step. The analysis can then cut your recording into the steps.
    1. Start Wireshark. Its list shows entries named USBPcap1, USBPcap2
       and so on. If you do not know which one the instrument is on,
       select all of them (hold Ctrl and click each one).
    2. If the gear icon next to a USBPcap entry offers "Inject already
       connected devices descriptors into capture data", tick it.
    3. Start recording, then come back here and do the steps.
    4. At the end, stop Wireshark and save the recording (File, then Save
       As) into the folder  {os.path.basename(folder)}  under the name
         whole-session.pcapng
    5. Then run this tool with   --analyze {os.path.basename(folder)}"""


def earlier_session_here() -> bool:
    """An instrument-session folder from an earlier run next to the tool."""
    try:
        base = _writable_dir()
        return any(n.startswith("instrument-session-") and not n.endswith("-FULL-do-not-send")
                   and os.path.isdir(os.path.join(base, n)) for n in os.listdir(base))
    except OSError:
        return False


def parse_step_numbers(text: str, total: int) -> list:
    """'7,9' or '7 9' -> [7, 9]; numbers outside 1..total are dropped."""
    out = []
    for part in re.split(r"[\s,;]+", text or ""):
        m = re.fullmatch(r"(\d+)-(\d+)", part)
        numbers = range(int(m.group(1)), int(m.group(2)) + 1) if m else (
            [int(part)] if part.isdigit() else [])
        for n in numbers:
            if 1 <= n <= total and n not in out:
                out.append(n)
    return sorted(out)


# 1.6, second review: usbmon records only the traffic, so the USB description
# that tells the i1iSis from other devices is in a recording only when the
# device is plugged in while it records. Without it an i1iSis step keeps
# nothing (instrument_selection). Said BEFORE the steps.
LINUX_ISIS_REPLUG_TEXT = """\
  IMPORTANT ON LINUX: a Linux recording shows which device is the i1iSis
  only when the i1iSis is plugged in while a step records. So in EVERY
  step: press Enter here to start the step, then unplug the i1iSis's USB
  cable and plug it back in (leave the i1iSis switched on), wait until the
  virtual machine and i1Profiler have found it again, and then do the
  step. Without that, the tool keeps nothing from the step and says so."""


def instrument_session_step(pids: list, direct: bool, only: list | None = None,
                            prefer: str | None = None) -> dict:
    """The i1Pro / ColorMunki recording, from start to end, any platform.

    Returns what happened, for the closing words: {"profile", "recorded",
    "help"} (1.5.1). "help" holds the texts to repeat at the very end when
    nothing could be recorded, so they are the last thing on the screen
    instead of being buried above "ALL DONE".
    prefer (1.6): the profile to offer first (--isis), whatever is plugged in."""
    outcome = {"profile": None, "recorded": False, "help": [], "reason": ""}
    system = platform.system()
    default = prefer or choose_profile(pids)
    print("\n" + "=" * 68)
    print("  RECORDING WHAT THE MEASURING PROGRAM SAYS TO YOUR INSTRUMENT")
    print("=" * 68)
    try:
        profile = _ask_profile(default, seen=any(PROFILE_IDS.get(k) == default for k in pids))
    except _StopSession:
        section("Instrument recording session", "[ended before it started]")
        return outcome
    outcome["profile"] = profile
    _RUN["profile"] = profile                  # 1.6 review: for the relaunch and the end box
    print("\n  WHAT THIS IS FOR")
    print(PROFILE_PURPOSE[profile])
    print()
    print(PROMISE_TEXT)
    steps = steps_for(profile)
    if only is None and earlier_session_here():
        # 1.5.5: a tester whose session had two empty steps had to do all
        # nine again; now he can do just those. Asked only when an earlier
        # session folder lies next to the tool.
        try:
            answer = _session_ask("\n  Do you want to repeat only some steps of an earlier "
                                  "session? Type their\n  numbers (for example  7,9 ), or "
                                  "just press Enter for all steps: ")
        except _StopSession:
            section("Instrument recording session", "[ended before it started]")
            return outcome
        only = parse_step_numbers(answer, len(steps))
        while answer.strip() and not only:
            try:
                answer = _session_ask(f"  Please type step numbers from 1 to {len(steps)}, for "
                                      "example  7,9  (or press Enter for all steps): ")
            except _StopSession:
                section("Instrument recording session", "[ended before it started]")
                return outcome
            only = parse_step_numbers(answer, len(steps))
    only = parse_step_numbers(",".join(str(n) for n in only or []), len(steps))
    # 1.6 review: the relaunch as administrator repeats the parsed numbers.
    _RUN["steps"] = ",".join(str(n) for n in only) if only else None
    shown = [(i, st) for i, st in enumerate(steps, 1) if not only or i in only]
    if only:
        print(f"\n  WHAT YOU WILL DO (only step{'s' if len(only) > 1 else ''} "
              f"{', '.join(str(n) for n in only)} of {len(steps)})")
    else:
        print(f"\n  WHAT YOU WILL DO ({len(steps)} short steps, about 15 minutes)")
    for i, s in shown:
        print(f"    {i}. {s['title']}")
    print("  IMPORTANT: use the measuring program for a step only AFTER you have")
    print("  pressed Enter here to start that step. Before that, nothing is recorded.")
    print("  Each step is recorded into its own small file. You can skip or repeat")
    print("  any step and stop at any time; the steps you finished are kept.")
    if profile == "isis":
        print("  You need: the i1iSis, i1Profiler, one printed chart page for the")
        print("  i1iSis and, for step 6, one plain sheet of normal 80 g/m2 printer")
        print("  paper, the same size as your chart.")
        print()
        print(ISIS_CHART_TEXT)
        if not any(PROFILE_IDS.get(k) == "isis" for k in pids):
            print()
            print("  The i1iSis is not plugged in right now. Before the first step, please")
            print("  switch it on FIRST and then plug in its USB cable (X-Rite says that")
            print("  in the other order i1Profiler does not see it). The session goes on")
            print("  from here; nothing is recorded until you start a step.")
    else:
        print("  You need: the instrument, the program you normally measure with, and")
        print("  one printed test chart.")
    print()
    print(privacy_text(profile))
    print()

    context: dict = {}
    recorder = None
    detected_programs: dict = {}
    manual = False
    if system == "Windows":
        checks = windows_capture_checks(profile)
        detected_programs = checks["programs"]
        context = {"windows": checks["windows"]["text"],
                   "usbpcap": checks["service"], "admin": checks["admin"],
                   "hubs": [h["display"] for h in checks["hubs"]]}
        print(windows_checks_text(checks))
        print()
        if not checks["service"]["installed"]:
            outcome["help"].append(USBPCAP_INSTALL_TEXT)
            _note_cause("usbpcap_missing")
        if driver_help_needed(checks):
            outcome["help"].append(DRIVER_HELP_TEXT)
            _note_cause("wrong_driver")
        if checks["admin"] is False:
            outcome["help"].append(admin_help_text())
            _note_cause("not_admin")
        if outcome["help"]:
            print(("\n\n  " + "-" * 66 + "\n\n").join(outcome["help"]))
            print()
        if not checks["service"]["installed"]:
            outcome["reason"] = ("Nothing was recorded, because USBPcap (the recorder "
                                 "this tool needs on Windows) is not installed yet.")
            offer = "not offered (Windows on ARM)"
            if not checks.get("arm") or "offer-on-arm" in SELFTEST:
                offer = offer_usbpcap_install()
            if offer == "installed":
                outcome["reason"] = ("Nothing was recorded yet: USBPcap is now installed, "
                                     "and starts working after Windows has been restarted.")
                _CAUSES[:] = ["usbpcap_restart" if c == "usbpcap_missing" else c
                              for c in _CAUSES]
                # The closing words repeat outcome["help"] as the last thing on
                # screen: "HOW TO INSTALL IT" must not be repeated once it is.
                outcome["help"] = [t for t in outcome["help"] if t != USBPCAP_INSTALL_TEXT]
            section("Instrument recording session",
                    ("[USBPcap was installed during this run; Windows needs a restart]\n"
                     if offer == "installed" else "[USBPcap is not installed]\n")
                    + windows_checks_text(checks)
                    + "\n\n" + usbpcap_diagnosis(checks)
                    + "\n\nThe offer to fetch and start USBPcap's installer: " + offer
                    + "\n\n" + "\n\n".join(outcome["help"]))
            return outcome
        if checks["admin"] is False:
            # 1.5.3: offer to start again as administrator, once, by consent.
            offer_relaunch_as_admin()
            # 1.5.2: say it before the steps, not after the first one failed.
            outcome["reason"] = ("Nothing was recorded, because this window does not run "
                                 "as administrator, and USBPcap records only for "
                                 "administrators.")
            section("Instrument recording session",
                    "[not running as administrator]\n" + windows_checks_text(checks)
                    + "\n\n" + usbpcap_diagnosis(checks)
                    + "\n\n" + "\n\n".join(outcome["help"]))
            return outcome
        win_diag = usbpcap_diagnosis(checks)
        if windows_can_record(checks):
            hubs = [h["path"] for h in checks["hubs"] if h["instrument"]] or \
                [h["path"] for h in checks["hubs"]]
            recorder = UsbPcapRecorder(checks["usbpcapcmd"], hubs, "")
        else:
            manual = True
    elif system == "Darwin":
        readiness = macos_recording_readiness(_DETECTION.get("devices"))
        context = {"sip": readiness["sip"], "interfaces": readiness["interfaces"]}
        if readiness["possible"]:
            print("  Good news: a recording looks possible on this Mac.")
            print("  " + readiness_report(readiness).replace("\n", "\n  "))
            recorder = TcpdumpRecorder(readiness["interfaces"], "", mac=True)
        else:
            print(recording_not_possible_text(readiness, device="instrument",
                                              profile=profile))
            print("\n  The vendor programs (i1Profiler, ccStudio, the ColorMunki and")
            print("  i1Studio programs) run on Windows and on the Mac, so the Windows")
            print("  route above works with the same instrument.")
            section("Instrument recording session",
                    "[not possible on this Mac: " + " ".join(readiness["reasons"]) + "]")
            outcome["reason"] = ("A recording is not possible on this Mac right now: "
                                 + " ".join(readiness["reasons"]))
            return outcome
    else:
        ifaces = linux_usbmon_interfaces()
        context = {"usbmon": ifaces}
        if ifaces and shutil.which("tcpdump"):
            print(f"  usbmon interfaces: {', '.join(ifaces)}. The tool records on all of them.")
            print("  (The vendor programs do not run on Linux itself; this works when they")
            print("  run in a virtual machine that the instrument is passed through to.)")
            if profile == "isis":
                print(LINUX_ISIS_REPLUG_TEXT)
            recorder = TcpdumpRecorder(ifaces, "", mac=False)
        else:
            print("  No usbmon interfaces. Load them first with   sudo modprobe usbmon")
            print("  (and make sure tcpdump is installed), then run the tool again.")
            section("Instrument recording session", "[usbmon not loaded or tcpdump missing]")
            return outcome
    if not said_yes(ask("\n  Start the session now? (yes / no): ")):
        print("\n  No problem at all. Nothing was recorded.\n")
        outcome["reason"] = "You chose not to start the recording session."
        section("Instrument recording session", "[declined by the operator]")
        return outcome
    try:
        program, version = _ask_program(detected_programs)
    except _StopSession:
        section("Instrument recording session", "[ended before the first step]")
        return outcome
    if profile == "i1pro2" and "i1profiler" in (program or "").lower() \
            and version and version_tuple(version) >= (3, 8, 7):
        print("\n  Please note: i1Profiler 3.8.7 and newer no longer talk to the i1Pro 2.")
        print("  If yours still finds the instrument, carry on.")
    if profile == "isis" and "i1profiler" in (program or "").lower() \
            and version and version_tuple(version) < (3, 8, 8) and system == "Windows":
        print("\n  Please note: X-Rite's notes for i1Profiler 3.8.8 say it fixes the i1iSis")
        print("  drivers on Windows 11 version 25H2. If your i1Profiler does not find the")
        print("  i1iSis, updating to 3.8.8 or newer is the first thing to try.")
    if profile == "i1pro" and "i1profiler" in (program or "").lower() \
            and version and version_tuple(version) >= (3, 2, 0):
        print("\n  Please note: i1Profiler 3.2.0 and newer no longer talk to the original")
        print("  i1Pro (revisions A to D); X-Rite says to use 3.1.1. If yours still")
        print("  finds the instrument, carry on.")
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    folder = os.path.join(_writable_dir(), f"instrument-session-{stamp}")
    if manual:
        os.makedirs(folder, exist_ok=True)
        print()
        print(manual_recording_text(folder))
        if not said_yes(ask("\n  Is Wireshark recording now? (yes / no): ")):
            section("Instrument recording session", "[no recording running]")
            return outcome
    session = run_instrument_session(recorder, folder, profile, program, version, context,
                                     only=only)
    failed_start = recorder is not None and session.get("ended") == \
        "the recording program stopped at once"
    if failed_start:
        # 1.5.4: the tool's own start failed (also after the simpler retry):
        # offer the by-hand way at once, with the same steps and notes.
        print()
        print(manual_recording_text(folder, after_failure=True))
        if said_yes(ask("\n  Record by hand with Wireshark now, while this tool walks you "
                        "through\n  the steps? (yes / no): ")) and \
                said_yes(ask("  Is Wireshark recording now? (yes / no): ")):
            first = session
            folder = folder + "-by-hand"
            os.makedirs(folder, exist_ok=True)
            print(f"\n  The new session folder is  {os.path.basename(folder)}")
            print(f"  (save the recording there as  whole-session.pcapng)")
            manual = True
            session = run_instrument_session(None, folder, profile, program, version,
                                             context, only=only)
            session["first_try"] = {"ended": first.get("ended"),
                                    "recorder_failure": first.get("recorder_failure")}
            _write_session(session, folder)
    if manual:
        print("\n  Now stop Wireshark and save the recording into the folder")
        print(f"  {os.path.basename(folder)}  as  whole-session.pcapng  (File, then Save As).")
        flush_pending_input()
        ask("  Press Enter when it is saved (or if you did not save it): ")
    print("\n" + "-" * 68)
    lines, analysis = finish_session(session, folder)
    print("\n" + "\n".join("  " + l for l in lines))
    if analysis:
        verdict = analysis.split("DOES THIS RECORDING HOLD WHAT WE NEED?")[-1]
        print("\n  DOES THIS RECORDING HOLD WHAT WE NEED?" + verdict.replace("\n", "\n  "))
    outcome["recorded"] = bool(any(s.get("files_xrite") for s in session["steps"]) or manual)
    if outcome["recorded"]:
        _END["send"] = {"folder": folder}
    else:
        ended = session.get("ended") or ""
        if "stopped at once" in ended:
            outcome["reason"] = ("The recording program stopped at once, so nothing was "
                                 "recorded. Everything needed to find out why is in the "
                                 "section \"Instrument recording session\" below.")
        elif ended == "stopped by the operator" and not any(
                s.get("start_epoch") for s in session["steps"]):
            outcome["reason"] = ("You stopped the session before the first step was "
                                 "recorded. The tool records only between the Enter "
                                 "that starts a step and the  e  + Enter that stops it.")
    if outcome["recorded"]:
        print()
        print(session_send_text(folder, profile))
    if system == "Darwin":
        print()
        print(SIP_OFF_REMINDER)
    body = "\n".join(lines)
    if system == "Windows":
        body += "\n\n" + windows_checks_text(checks) + "\n\n" + win_diag
    failure = session.get("recorder_failure") or (session.get("first_try") or {}).get(
        "recorder_failure")
    if failure:
        body += ("\n\nTHE RECORDING PROGRAM DID NOT START\n"
                 + recorder_failure_words(failure) + "\n" + failure)
    if analysis:
        body += "\n\n" + analysis
    section("Instrument recording session", body)
    return outcome


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def detected_ids(summary: str) -> list:
    """(vid, pid) of every X-Rite device the detection step saw."""
    ids = []
    for dev in _DETECTION.get("devices") or []:
        if dev.get("vid") is not None and dev.get("pid") is not None:
            ids.append((dev["vid"], dev["pid"]))
    for m in re.finditer(r"VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})", summary or ""):
        ids.append((int(m.group(1), 16), int(m.group(2), 16)))
    for m in re.finditer(r"\b([0-9A-Fa-f]{4}):([0-9A-Fa-f]{4})\b", summary or ""):
        vid = int(m.group(1), 16)
        if vid in XRITE_VIDS:
            ids.append((vid, int(m.group(2), 16)))
    out = []
    for key in ids:
        if key[0] in XRITE_VIDS and key not in out:
            out.append(key)
    # 1.5.1: what is plugged in now comes first, so the session is chosen
    # from the instrument on the desk, not from one Windows remembers.
    present = _DETECTION.get("present_ids") or []
    return [k for k in out if k in present] + [k for k in out if k not in present]


def find_session_folders() -> list:
    for directory in candidate_dirs():
        hits = [h for h in glob.glob(os.path.join(directory, "instrument-session-*"))
                if os.path.isdir(h) and not h.endswith("-FULL-do-not-send")
                and os.path.exists(os.path.join(h, "session.json"))]
        if hits:
            return [max(hits, key=os.path.getmtime)]
    return []


def analyze_paths(paths: list) -> str:
    """--analyze: the instrument analysis when it fits, else 1.4's summary."""
    if any(os.path.isdir(p) or p.endswith(".json") for p in paths):
        return summarize_session(paths)
    # 1.5.4: a probe report named next to the recordings gives the i1iO
    # analysis the operator's steps; it is not a recording itself.
    reports = [p for p in paths if p.lower().endswith(".txt")]
    paths = [p for p in paths if p not in reports]
    if not paths:
        return ("A probe report on its own holds no recording. Name the recording too:\n"
                "    --analyze io-capture-....pcap chromiq-io-probe-....txt")
    text = summarize_captures(paths)
    try:
        table = summarize_io(paths, reports)
    except Exception as exc:                              # noqa: BLE001
        table = f"  The i1iO analysis failed ({exc}); the recording itself is fine."
    if table:
        # The i1Pro on the arm would otherwise get the handheld analysis,
        # which asks about rulers and dual scans that do not apply here.
        return text + "\n\n" + table
    try:
        steps, devinfo, _checks, plain = session_steps(paths)
    except Exception:                                     # noqa: BLE001
        return text
    if mixed_families(plain):
        return text + "\n\n" + mixed_families_text(mixed_families(plain))
    if session_family(devinfo, steps, plain) != "generic":
        return text + "\n\n" + summarize_session(paths)
    return text


def main(argv: list | None = None) -> int:
    global REDACT

    parser = argparse.ArgumentParser(
        description="Collect information about X-Rite instruments (i1iO, i1Pro family, "
                    "ColorMunki / i1Studio, i1iSis) for ChromIQ, and optionally record what the "
                    "vendor program says to them. Never sends anything to the device and "
                    "never changes a system setting."
    )
    parser.add_argument("--annotate", "--record", action="store_true", dest="annotate",
                        help="go straight to the recording step (stage 2)")
    parser.add_argument("--i1pro", "--instrument", action="store_true", dest="instrument",
                        help="the guided recording session for a handheld instrument "
                             "(i1Pro, i1Pro 2, i1Pro 3, ColorMunki, i1Studio)")
    parser.add_argument("--isis", action="store_true",
                        help="the guided recording session for an i1iSis chart reader "
                             "(i1iSis, i1iSis XL, i1iSis 2, i1iSis 2 XL)")
    parser.add_argument("--io", action="store_true",
                        help="the i1iO table: its three questions and the optional "
                             "recording (skips the question what to do)")
    parser.add_argument("--skip-annotate", action="store_true",
                        help="never offer the recording step")
    parser.add_argument("--no-redact", action="store_true",
                        help="keep serial numbers and paths as-is")
    parser.add_argument("--capture-setup", action="store_true",
                        help="(macOS) say whether this Mac can record USB traffic, "
                             "and how, then exit. Changes nothing.")
    parser.add_argument("--analyze", nargs="*", default=None, metavar="PCAP",
                        help="read a USB recording (.pcap/.pcapng) and print a plain "
                             "verdict + command timeline; with no path, finds "
                             "the newest recording next to the tool")
    parser.add_argument("--steps", default=None, metavar="LIST",
                        help="handheld session: record only these steps, for example "
                             "--steps 7,9 (to repeat steps of an earlier session)")
    parser.add_argument("--rehearse", action="store_true",
                        help="walk through the i1iO recording steps without recording "
                             "anything, to see them before the real recording")
    parser.add_argument("-o", "--output", default=None, help="output file path")
    parser.add_argument("--pause", action="store_true",
                        help='always end with "Press Enter to close this window."')
    parser.add_argument("--selftest", default="", help=argparse.SUPPRESS)
    # 1.6: the instrument chosen before a restart as administrator.
    parser.add_argument("--profile", default=None, choices=sorted(PROFILE_NAMES),
                        help=argparse.SUPPRESS)
    parser.add_argument("--relaunched", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--no-pause", action="store_true",
                        help="never wait for Enter at the end (the launchers use this; "
                             "piped or redirected runs never wait anyway)")
    args = parser.parse_args(argv)
    REDACT = not args.no_redact
    _END.clear()
    _IO_SUMMARY.clear()
    _INPUT_ENDED.clear()
    _RUN.clear()
    _RUN.update(output=args.output, no_redact=args.no_redact, relaunched=args.relaunched,
                no_pause=args.no_pause, isis=args.isis, steps=None)
    SELFTEST.clear()
    SELFTEST.update(x.strip() for x in args.selftest.split(",") if x.strip())
    if SELFTEST:
        section("Self-test switches (for the automated test only)", ", ".join(sorted(SELFTEST)))
    if "crash" in SELFTEST:
        raise RuntimeError("self-test: a deliberate error, to test the error ending")

    if args.capture_setup:
        if platform.system() != "Darwin":
            print("--capture-setup is for macOS. On Windows, run the tool and "
                  "choose the recording step; on Linux, see the README (usbmon).")
            return 1
        r = macos_recording_readiness(macos_detection()["devices"])
        print(readiness_report(r))
        print()
        if r["possible"]:
            print("  A recording looks possible. Run the tool with --record to make one.")
            print()
            print(I1PROFILER_WARNING)
        else:
            print(recording_not_possible_text(r))
        if r["sip"] in ("off", "partly"):
            print()
            print(SIP_OFF_REMINDER)
        return 0

    if args.rehearse:
        return rehearse_io()

    if args.analyze is not None:
        paths = args.analyze or find_session_folders() or find_captures()
        if not paths:
            print("No recording given or found next to the tool.\n"
                  "Pass a path:\n"
                  "    --analyze path/to/recording.pcap\n"
                  "    --analyze path/to/instrument-session-folder")
            return 1
        print(analyze_paths(paths))
        return 0

    print("=" * 68)
    print("  ChromIQ X-Rite instrument probe " + PROBE_VERSION)
    print("=" * 68)
    print()
    print("  This only READS information your computer already has about the")
    print("  connected hardware. It never sends anything to the instrument or")
    print("  the table, it cannot move the i1iO's arm, and it changes no")
    print("  settings. It is safe to run at any time.")
    print()
    print("  It takes about a minute. Let's go.")
    print()
    print("-" * 68)
    print("STEP 1 of 3: looking for your X-Rite devices")
    print("-" * 68)
    print()

    summary = quick_summary()
    print("  " + summary.replace("\n", "\n  ") + "\n")
    if summary.startswith("NO X-RITE DEVICES") or "None of them is plugged in right now" in summary:
        _note_cause("no_instrument")

    if summary.startswith("NO X-RITE DEVICES"):
        print("  That is fine for now: in step 3 you can plug the instrument in and")
        print("  let the tool look again.")
        print()

    system = platform.system()
    hardware = {
        "probe_version": PROBE_VERSION,
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "platform": platform.platform(),
        "system": system,
        "release": platform.release(),
        "machine": platform.machine(),
        "python": sys.version.split()[0],
        "redacted": REDACT,
    }
    if system == "Windows":
        # 1.5.4: stated in every report, not only in a recording session.
        admin = windows_is_admin()
        hardware["administrator"] = ("yes" if admin else "no" if admin is False
                                     else "not known")
    if system == "Darwin":
        cpu = macos_cpu()
        hardware["cpu"] = ("Apple Silicon" if cpu["apple_silicon"] else "Intel") + \
            (f" ({cpu['brand']})" if cpu["brand"] else "")
    section("Environment", json.dumps(hardware, indent=2))
    section("Detection summary", summary)

    print("-" * 68)
    print("STEP 2 of 3: collecting the details")
    print("-" * 68)
    print("\n  Please wait, this takes a few seconds...\n")

    if system == "Darwin":
        collect_macos()
        readiness = macos_recording_readiness(_DETECTION.get("devices"))
        section("macOS: USB recording readiness (read only, nothing changed)",
                readiness_report(readiness))
    elif system == "Linux":
        collect_linux()
    elif system == "Windows":
        collect_windows()
    else:
        section("Unsupported platform", f"No collector for {system}")
    collect_i1profiler_charts()
    print("  Done.\n")

    choice, summary = choose_what_to_do(args, summary)
    section("What the user chose", {1: "1: record an i1iO table",
                                    2: "2: record a handheld instrument or an i1iSis",
                                    3: "3: nothing more, just the report"}[choice])
    ids = detected_ids(summary)
    known, here = plugged_in_now(ids)
    if choice == 3:
        return finish_report(args, system, mode="report")
    if choice == 2:
        section("Detected X-Rite IDs", ", ".join(f"{v:04x}:{p:04x}" for v, p in ids) or "none")
        print("-" * 68)
        print("STEP 3 of 3: the recording session")
        print("-" * 68)
        if not any(k in PROFILE_IDS for k in here):
            print()
            print("  No handheld instrument and no i1iSis is plugged in right now. You can")
            print("  still go through the start of the session: it shows what this")
            print("  computer offers for a recording and says what is missing. For the")
            print("  recording itself, the instrument has to be plugged in.")
        only = None
        if args.steps:
            only = parse_step_numbers(args.steps, 99)
            if not only:
                print(f"  --steps {args.steps}: no step numbers in it; please give them like "
                      "--steps 7,9")
                return 2
        outcome = instrument_session_step(ids, direct=True, only=only,
                                          prefer=args.profile or ("isis" if args.isis else None))
        return finish_report(args, system, instrument=True, outcome=outcome)

    print("-" * 68)
    print("STEP 3 of 3: three quick questions about your i1iO table")
    print("-" * 68)
    if not any(k in here for k in IO_IDS):
        print("\n  (No i1iO table is plugged in right now. The answers and the report")
        print("  still help.)")
    print("\n  Just press Enter to skip any of them.\n")
    answers = {
        "which iO generation (iO / iO2 / iO3)?":
            ask("  1. Which generation is your table: iO, iO2 or iO3?\n     > "),
        "which spectrophotometer is mounted?":
            ask("  2. Which instrument is mounted on it (i1Pro, i1Pro 2, i1Pro 3)?\n     > "),
        "which software (and version) normally drives it?":
            ask("  3. Which software, and which version, do you normally drive it with?\n"
                "     (for example: i1Profiler 3.8.6)\n     > "),
    }
    section("Operator answers",
            "\n".join(f"{q}\n    {a or '[no answer]'}" for q, a in answers.items()))

    if args.annotate:
        recording_step(direct=True)
    elif not args.skip_annotate:
        recording_step(direct=False)
    return finish_report(args, system)


IO_ID = (XRITE_VID, 0x2004)
IO3_ID = (0x0765, 0x30B0)               # 1.5.4: the i1iO 3 (X-Rite's driver file)
IO_IDS = (IO_ID, IO3_ID)

REPORT_SEND_WAYS = f"""\
  If you would like to share it with us, choose whichever suits you:
    - for the i1iO table: attach it to
        {ISSUE_URL}
    - for any other instrument: attach it in the forum thread where you
      heard about this tool, or to a new issue at
        {NEW_ISSUE_URL}"""


def plugged_in_now(ids: list) -> tuple:
    """(known, here): the X-Rite devices plugged in right now.

    Windows also lists devices it only remembers, and says for each whether
    it is present (present_ids). macOS and Linux list only what is connected.
    known is False when Windows could not say which are present."""
    present = _DETECTION.get("present_ids")
    if present is None:
        return platform.system() != "Windows", list(ids)
    return True, [k for k in ids if k in present]


def suggest(here: list) -> dict:
    """The suggested answer to "What would you like to do?", from what is
    plugged in now only (1.5.3; before, a remembered i1iO could hide a
    plugged-in handheld instrument)."""
    hand = [k for k in here if k in PROFILE_IDS]
    other = [k for k in here if k not in IO_IDS and k not in PROFILE_IDS]
    table = any(k in here for k in IO_IDS)
    choice = 1 if table else 2 if hand else 3
    return {"choice": choice, "io": table, "hand": hand, "other": other,
            "nothing": not here}


_DRIVER_WORDS = {"argyll": "on the ArgyllCMS driver", "winusb": "on WinUSB",
                 "vendor": "X-Rite's driver", "none": "no driver yet"}


def _windows_driver_words() -> dict:
    """Windows: {(vid, pid): "X-Rite's driver"} for what is plugged in."""
    if platform.system() != "Windows":
        return {}
    try:
        out = {}
        for dev in windows_driver_devices():
            words = _DRIVER_WORDS.get(driver_state(dev))
            if words:
                out[(dev["vid"], dev["pid"])] = words
        return out
    except Exception:                                     # noqa: BLE001
        return {}


def device_name(key) -> str:
    if key == IO_ID:
        return "i1iO table"
    if key == IO3_ID:
        return "i1iO 3 table (its protocol is not known yet)"
    if key in PROFILE_IDS:
        return PROFILE_NAMES[PROFILE_IDS[key]]
    return f"an X-Rite device this tool does not know ({key[0]:04x}:{key[1]:04x})"


def what_to_do_question(sug: dict, known: bool, here: list, drivers: dict) -> list:
    """The lines above the question, and the question itself."""
    lines = []
    if sug["nothing"]:
        lines += ["  Plugged in now: no X-Rite instrument.", "",
                  "  If you want to record an instrument, plug it in now (straight into",
                  "  the computer, not through a USB hub), switch it on, wait a few",
                  "  seconds, and type  a  to let the tool look again."]
    else:
        names = []
        for key in here:
            name = device_name(key)
            if key in drivers:
                name += f" ({drivers[key]})"
            if name not in names:
                names.append(name)
        lines.append("  Plugged in now: " + _wrap(", ".join(names) + ".", 50, " " * 18))
    if not known:
        lines += ["  (Windows did not say which devices are plugged in right now and",
                  "  which it only remembers from before, so all of them are listed.)"]
    if sug["io"] and sug["hand"]:
        hand = ", ".join(dict.fromkeys(device_name(k) for k in sug["hand"]))
        lines += ["", f"  The instrument mounted on the table was seen too ({hand}).",
                  "  Choose 2 instead if you want to record that instrument on its own,",
                  "  off the table."]
    if sug["other"] and not sug["io"] and not sug["hand"]:
        lines += ["", "  This tool does not know that device yet. The report (choice 3)",
                  "  is the most useful thing for it."]
    mark = {n: "   <- suggested" if n == sug["choice"] else "" for n in (1, 2, 3)}
    lines += ["", "  What would you like to do?",
              "    1. record an i1iO table" + mark[1],
              "    2. record a handheld instrument or an i1iSis" + mark[2],
              "       (the i1Pro family, the ColorMunki, the i1Studio, the i1iSis",
              "       chart readers)",
              "    3. nothing more: just make the report" + mark[3],
              "    a. look again (after plugging something in)"]
    return lines


def choose_what_to_do(args, summary: str) -> tuple:
    """(choice, summary). The command line options decide without asking."""
    if args.instrument or getattr(args, "isis", False) is True \
            or isinstance(getattr(args, "profile", None), str) \
            or isinstance(getattr(args, "steps", None), str):
        return 2, summary
    if args.io or args.annotate or args.skip_annotate:
        return 1, summary
    for _ in range(30):                                   # bounded, never endless
        ids = detected_ids(summary)
        known, here = plugged_in_now(ids)
        sug = suggest(here)
        print("-" * 68)
        print("STEP 3 of 3: what would you like to do?")
        print("-" * 68)
        print()
        print("\n".join(what_to_do_question(sug, known, here, _windows_driver_words())))
        print()
        answer = ask(f"  Type 1, 2 or 3 (or  a  to look again), "
                     f"or just press Enter for {sug['choice']}: ",
                     interruptible=True).strip().lower()
        print()
        if answer == "":
            return sug["choice"], summary
        if answer in ("1", "2", "3"):
            return int(answer), summary
        if answer in ("q", "quit"):
            return 3, summary
        if answer in ("a", "again", "look again"):
            print("  Looking again...")
            summary = quick_summary()
            print("  " + summary.replace("\n", "\n  ") + "\n")
            section("Detection summary (looked again)", summary)
            if summary.startswith("NO X-RITE DEVICES") or \
                    "None of them is plugged in right now" in summary:
                _note_cause("no_instrument")
            elif "no_instrument" in _CAUSES:
                _CAUSES.remove("no_instrument")
            continue
        print(f"  \"{answer}\" is not one of the choices. Please type 1, 2 or 3,")
        print("  or  a  to look again.")
        print()
    return 3, summary


def closing_words(outcome: dict | None) -> list:
    """1.5.1: the end of a handheld run, as lines. When nothing was recorded,
    say so plainly and repeat what to do, so it is the last thing on screen
    (1.5.0 put "ALL DONE" and "send it with the session folder" there, with
    the install steps scrolled away above them)."""
    outcome = outcome or {}
    if outcome.get("recorded"):
        if _END.get("zip"):
            first = ["  Please send the one SEND-THIS zip file named above. It holds the",
                     "  report and the recordings."]
        else:
            first = ["  The tool could not make the one file to send. Please make a zip of",
                     "  the session folder yourself and add the report."]
        return first + ["  In the report the serial numbers are scrambled; in the",
                        "  recordings they cannot be, as said above.", "",
                        HANDHELD_SEND_WAYS]
    lines = ["  NOTHING WAS RECORDED THIS TIME",
             "  " + _wrap(outcome.get("reason") or "No step of the session was recorded.",
                          66, "  "),
             "  There is no session folder to send. You do not need to send this",
             "  report either; if you like, send it anyway (it shows what the tool",
             "  found on this computer). A recording is what really helps."]
    for text in outcome.get("help") or []:
        lines += ["", "  " + "-" * 66, "", text]
    if outcome.get("help"):
        lines += ["", "  When that is done, simply run this tool again. Thank you!"]
    return lines


def show_i1profiler_warning(instrument: bool, outcome: dict | None) -> bool:
    """1.5.1: the i1Pro 2 / iO2 warning only where it applies. 1.5.0 showed it
    to every handheld user, including i1Pro 3 owners."""
    if not instrument:
        return True
    return (outcome or {}).get("profile") in PROFILES_BLOCKED_ON_25H2


def report_text(instrument: bool = False) -> str:
    body = [
        "ChromIQ X-Rite instrument probe report, version " + PROBE_VERSION,
        ("Made by the handheld-instrument session" if instrument
         else f"Generated for {ISSUE_URL}"),
        f"Redaction: {'ON (serials hashed, paths stripped)' if REDACT else 'OFF, raw values included'}",
        "",
    ]
    if not _END.get("send"):
        # 1.5.4: said at the top, so nobody reads a report as if it held a
        # recording (a real tester sent only this file).
        if (_END.get("sip_box") or _END.get("session_folder")) and not _END.get("finished"):
            line = ("This report was saved before the end of the run (after an "
                    "interruption or an error). Recordings may be next to it, in the "
                    "folder named in the report.")
        else:
            line = "THIS REPORT CONTAINS NO RECORDING. " + (
                _END.get("no_recording") or "No recording was made in this run.")
        body[3:3] = [line, ""]
    for title, content in _SECTIONS:
        body.append("=" * 72)
        body.append(title)
        body.append("=" * 72)
        body.append(content)
        body.append("")
    return "\n".join(body)


def finish_report(args, system: str, instrument: bool = False,
                  outcome: dict | None = None, mode: str | None = None) -> int:
    """mode "report" (1.5.3): the user chose "nothing more, just the report"."""
    if not _END.get("send"):
        if instrument and (outcome or {}).get("reason"):
            _END["no_recording"] = outcome["reason"]
        elif mode == "report":
            _END.setdefault("no_recording", "You chose to make only the report.")
    _END["finished"] = True
    report = report_text(instrument)
    out_path = write_report(report, args.output)
    if out_path:
        _LAST_REPORT["path"] = out_path
    if out_path is None:
        print("\n" + "!" * 68)
        print("Could not save the report anywhere. Please copy everything below")
        print("this line and paste it into the GitHub issue instead.")
        print("!" * 68 + "\n")
        print(report)
        return 1

    size_kb = os.path.getsize(out_path) / 1024
    zip_path = make_send_zip(out_path, _END["send"]) if _END.get("send") else None
    _END["zip"] = zip_path
    recorded = (not instrument) or bool((outcome or {}).get("recorded"))
    print("\n" + "=" * 68)
    print("  ALL DONE. Thank you!" if recorded else "  FINISHED, BUT NOTHING WAS RECORDED YET")
    print("=" * 68)
    print()
    print("  Your report was saved here:")
    print()
    print(f"      {out_path}")
    print()
    print(f"  It is a plain text file ({size_kb:.0f} KB). Please open it and have")
    print("  a look first: you can see exactly what is being shared, and you")
    print("  can delete anything you are not comfortable with.")
    print()
    if zip_path:
        print("  " + "=" * 66)
        print("  SEND THIS ONE FILE (it holds the report and the recordings):")
        print()
        print(f"      {zip_path}")
        print("  " + "=" * 66)
        print()
    if instrument and recorded:
        print("\n".join(closing_words(outcome)))
    elif mode == "report":
        print(REPORT_SEND_WAYS)
    elif not instrument:
        print("  Then attach it to:")
        print(f"      {ISSUE_URL}")
    if show_i1profiler_warning(instrument, outcome):
        print()
        print(I1PROFILER_WARNING)
    sip_off = system == "Darwin" and _READINESS.get("sip") in ("off", "partly")
    if instrument and recorded and sip_off:
        _END["sip_box"] = True
    if sip_off and not _END.get("sip_box"):
        # Nothing was recorded: keep the short reminder here, and "what to do
        # next" last (1.5.4 review: the big box is for after a recording).
        print()
        print(SIP_OFF_REMINDER)
    print()
    if instrument and not recorded:
        # Last on the screen on purpose: what to do next.
        print("\n".join(closing_words(outcome)))
    elif instrument:
        print("  That's everything. Thank you for helping. Whatever comes of it,")
        print("  a recording like this teaches us more than any amount of guessing.")
    elif mode == "report":
        print("  That's everything. Thank you for helping!")
    else:
        print("  That's everything. Thank you for helping!")
    print()
    return 0


def end_of_run_lines() -> list:
    """1.5.4: after a Mac recording with SIP off, the step table and the box
    with the steps to switch SIP back on are the very last thing on screen,
    after everything else (also after WHAT TO DO NOW, a Ctrl-C or an error)."""
    if not _END.get("sip_box") or _READINESS.get("sip") not in ("off", "partly"):
        return []
    lines = [""]
    if _IO_SUMMARY:
        lines += ["  " + l for l in _IO_SUMMARY] + [""]
    lines += [sip_back_on_box(bool((_READINESS.get("cpu") or {}).get("apple_silicon")),
                              thanks=bool(_END.get("steps_done", True))), ""]
    return lines


def candidate_dirs() -> list:
    """Folders to save output in, most preferred first.

    Running from a read-only folder (a mounted disk image, an unzipped bundle
    in a protected location, a network share) must not lose the output, so we
    fall back to the Desktop, then home, then the temp directory.
    """
    dirs: list = []
    # When frozen by PyInstaller, __file__ points into a temp bundle that is
    # DELETED on exit, so use the real executable's folder.
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


def write_report(report: str, explicit) -> str | None:
    """Write the report, trying progressively more reliable locations."""
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    name = f"chromiq-io-probe-{stamp}.txt"

    candidates: list = []
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


# --------------------------------------------------------------------------
# 1.5.3: help with installing USBPcap, and with starting as administrator.
# Both real users got stuck exactly there. Everything here happens only after
# a yes, in plain view: a normal download over HTTPS, a fingerprint check, a
# normal visible start of USBPcap's own installer (Windows asks its User
# Account Control question itself), and, separately, Windows' own "run as
# administrator" question. No silent switches, no security setting touched,
# no restart done for the user, nothing retried.
# --------------------------------------------------------------------------

# USBPcap's own standalone installer, from its official GitHub release
# (github.com/desowin/usbpcap/releases/tag/1.5.4.0, published 2020-05-22, the
# current release on 2026-11-13). Size and SHA-256 computed here on
# 2026-11-13 from that asset, and identical to the SHA-256 that Wireshark's
# own build pins for the same file (wireshark/wireshark CMakeLists.txt,
# USBPCAP_SHA256). The release page publishes no hash of its own.
USBPCAP_INSTALLER = {
    "name": "USBPcapSetup-1.5.4.0.exe",
    "url": "https://github.com/desowin/usbpcap/releases/download/1.5.4.0/"
           "USBPcapSetup-1.5.4.0.exe",
    "size": 195040,
    "sha256": "87a7edf9bbbcf07b5f4373d9a192a6770d2ff3add7aa1e276e82e38582ccb622",
}

# USBPcap issue #146 "USBPcap Driver BSOD" (opened 2026-03-26, still open on
# 2026-11-13): one user's PC crashed with a blue screen naming USBPcap.sys,
# on Windows 11 25H2 (26200.8037) with USBPcap 1.5.4.0.
USBPCAP_BEFORE_YOU_DECIDE = """\
  ABOUT USBPcap, BEFORE YOU DECIDE
  USBPcap is free, open-source software by its own author (desowin.org),
  not by us. It installs a system driver that sits between Windows and the
  USB ports, which is how it can record them.
  One user has reported that Windows crashed with a blue screen that named
  USBPcap's driver, on Windows 11 25H2 (USBPcap issue #146 on GitHub). We
  know of no other report like it, but you should know before you decide.
  To remove USBPcap again at any time: Settings, Apps, Installed apps,
  "USBPcap", Uninstall, then restart Windows."""


class Relaunched(Exception):
    """This copy has started another one as administrator and closes."""


def _download(url: str, limit: int, timeout: int = 60) -> bytes:
    """A plain HTTPS download, at most limit bytes (urllib, nothing else)."""
    import urllib.request                                 # noqa: PLC0415
    req = urllib.request.Request(url, headers={"User-Agent": "chromiq-i1io-probe"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:   # noqa: S310
        return resp.read(limit + 1)


def fetch_usbpcap_installer(folder: str, fetch=None, info=None) -> dict:
    """Download USBPcap's installer into folder and check its fingerprint.

    Returns {"ok", "path", "message"}. On any mismatch the file is deleted
    and never started."""
    info = info or USBPCAP_INSTALLER
    fetch = fetch or _download
    if "bad-fingerprint" in SELFTEST:
        info = dict(info, sha256="0" * 64)
    try:
        blob = fetch(info["url"], info["size"])
    except Exception as exc:                              # noqa: BLE001
        return {"ok": False, "kind": "download failed", "path": None, "message": (
            "The download did not work (" + (" ".join(str(exc).split())[:120] or
                                            type(exc).__name__) + "). This happens "
            "without internet, behind some company networks, or when GitHub is "
            "blocked. Nothing was saved. The steps above work without this tool.")}
    if len(blob) < info["size"]:
        return {"ok": False, "kind": "download failed", "path": None, "message": (
            f"The download was cut off ({len(blob):,} of {info['size']:,} bytes arrived), "
            "so it was thrown away and NOT started. Please try again later. The steps "
            "above work without this tool.")}
    digest = hashlib.sha256(blob).hexdigest()
    if len(blob) != info["size"] or digest != info["sha256"]:
        return {"ok": False, "kind": "fingerprint mismatch", "path": None, "message": (
            "The downloaded file is not the one this tool expects (its fingerprint "
            "does not match), so it was thrown away and NOT started. That should "
            "not happen; please tell us. The steps above work without this tool.")}
    path = os.path.join(folder, info["name"])
    opened = False
    try:
        with open(path, "wb") as fh:
            opened = True
            fh.write(blob)
    except OSError as exc:
        # A half-written installer (a full disk, say) must not stay behind
        # looking like the real one. Only a file this call opened is removed.
        if opened:
            try:
                os.remove(path)
            except OSError:
                pass
        return {"ok": False, "kind": "download failed", "path": None, "message": (
            f"The file could not be saved in {folder} ({exc}). The steps above "
            "work without this tool.")}
    return {"ok": True, "kind": "downloaded", "path": path, "message": (
        f"Downloaded  {info['name']}  ({info['size']:,} bytes)\n"
        f"    from  {info['url']}\n"
        f"    into  {folder}\n"
        "    Its fingerprint (SHA-256) matches the one written into this tool, so it\n"
        "    is exactly the file USBPcap's author published.")}


def file_matches(path: str, info=None) -> bool:
    """The file on disk, checked again just before it is started (review,
    1.5.3: the first check was on the downloaded bytes in memory)."""
    info = info or USBPCAP_INSTALLER
    if "bad-fingerprint" in SELFTEST:
        info = dict(info, sha256="0" * 64)
    try:
        with open(path, "rb") as fh:
            blob = fh.read(info["size"] + 1)
    except OSError:
        return False
    return len(blob) == info["size"] and hashlib.sha256(blob).hexdigest() == info["sha256"]


def private_download_folder() -> str:
    """A new, empty folder only this user can write to (the user's own temp
    folder). Not next to the tool: Downloads can hold old DLLs that an
    installer running as administrator might load, and a shared folder lets
    another account swap the file between the check and the start."""
    return tempfile.mkdtemp(prefix="chromiq-usbpcap-")


def _shell_execute(path: str, params: str = "", verb: str = "open",
                   wait: bool = True, folder: str | None = None):
    """Windows: start a program the way a double-click does (ShellExecuteEx),
    so Windows asks its own User Account Control question when the program
    needs it. Returns the exit code when waiting, 0 when started without
    waiting, or None when it did not start (for example, "No" at the Windows
    question)."""
    import ctypes                                         # noqa: PLC0415
    from ctypes import wintypes                           # noqa: PLC0415

    class SHELLEXECUTEINFOW(ctypes.Structure):
        _fields_ = [("cbSize", wintypes.DWORD), ("fMask", ctypes.c_ulong),
                    ("hwnd", wintypes.HWND), ("lpVerb", wintypes.LPCWSTR),
                    ("lpFile", wintypes.LPCWSTR), ("lpParameters", wintypes.LPCWSTR),
                    ("lpDirectory", wintypes.LPCWSTR), ("nShow", ctypes.c_int),
                    ("hInstApp", wintypes.HINSTANCE), ("lpIDList", ctypes.c_void_p),
                    ("lpClass", wintypes.LPCWSTR), ("hkeyClass", wintypes.HKEY),
                    ("dwHotKey", wintypes.DWORD), ("hIconOrMonitor", wintypes.HANDLE),
                    ("hProcess", wintypes.HANDLE)]

    info = SHELLEXECUTEINFOW()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = 0x00000040                               # SEE_MASK_NOCLOSEPROCESS
    info.lpVerb = verb
    info.lpFile = path
    info.lpParameters = params or None
    info.lpDirectory = folder
    info.nShow = 1                                        # SW_SHOWNORMAL: visible
    shell32 = ctypes.windll.shell32                       # type: ignore[attr-defined]
    k32 = ctypes.windll.kernel32                          # type: ignore[attr-defined]
    if not shell32.ShellExecuteExW(ctypes.byref(info)):
        return None
    if not info.hProcess:
        return 0
    try:
        if not wait:
            return 0
        k32.WaitForSingleObject(info.hProcess, 0xFFFFFFFF)
        code = wintypes.DWORD()
        k32.GetExitCodeProcess(info.hProcess, ctypes.byref(code))
        return code.value
    finally:
        k32.CloseHandle(info.hProcess)


def usbpcap_installed_now() -> bool:
    if "pretend-usbpcap" in SELFTEST:
        return True
    return parse_sc_query(run(["sc", "query", "USBPcap"], timeout=15))["installed"]


def _remove_empty(folder: str) -> None:
    try:
        os.rmdir(folder)
    except OSError:
        pass


def offer_usbpcap_install(folder: str | None = None, fetch=None, launch=None,
                          installed=None) -> str:
    """Windows, USBPcap missing: fetch and start its installer, by consent.

    Returns what happened, for the report: "declined", "download failed",
    "fingerprint mismatch", "downloaded, not started", "installer did not
    start", "installed", or "still not installed"."""
    launch = launch or (lambda path: _shell_execute(path, wait=True,
                                                    folder=os.path.dirname(path)))
    installed = installed or usbpcap_installed_now
    print("  " + "-" * 66)
    print()
    print(USBPCAP_BEFORE_YOU_DECIDE)
    print()
    if not said_yes(ask("  USBPcap is not installed. Shall this tool fetch its official\n"
                        "  installer for you? (yes / no): ")):
        print("  All right. The steps above are all you need to do it yourself.")
        return "declined"
    print("\n  Downloading USBPcap's installer from its official page on GitHub...")
    made = folder is None
    if made:
        try:
            folder = private_download_folder()
        except OSError as exc:
            print(f"  No folder for the download could be made ({exc}). The steps above")
            print("  work without this tool.")
            return "download failed"
    got = fetch_usbpcap_installer(folder, fetch=fetch)
    if not got["ok"] and made:
        _remove_empty(folder)
    print("  " + got["message"].replace("\n", "\n  "))
    if not got["ok"]:
        return got["kind"]
    print()
    if not said_yes(ask("  Start the USBPcap installer now? Windows will ask for permission\n"
                        "  (the blue or yellow \"User Account Control\" window), and USBPcap's\n"
                        "  installer will show its licence. (yes / no): ")):
        print(f"  All right. The installer is kept here, for when you want it:\n"
              f"      {got['path']}\n"
              "  Double-click it to start it, then restart Windows.")
        return "downloaded, not started"
    if not file_matches(got["path"]):
        print("\n  The saved file no longer matches its fingerprint, so it was NOT started")
        print("  and has been deleted. That should not happen; please tell us.")
        try:
            os.remove(got["path"])
        except OSError:
            pass
        if made:
            _remove_empty(folder)
        return "fingerprint mismatch"
    print("\n  Starting USBPcap's installer. Please answer Windows' question, then")
    print("  follow the installer's own pages. This window waits until it has closed.")
    try:
        code = launch(got["path"])
    except Exception:                                     # noqa: BLE001
        code = None
    if code is None:
        print("\n  The installer did not start. If Windows asked for permission and the")
        print("  answer was \"No\", that is fine: nothing was installed. You can start it")
        print(f"  yourself at any time by double-clicking\n      {got['path']}")
        return "installer did not start"
    now = installed()
    if now:
        print("\n  USBPcap is installed now. Windows must be restarted before USBPcap")
        print("  can record anything. Please restart Windows now, then start this tool")
        print("  again as administrator (right-click it, \"Run as administrator\").")
        print("  This tool does not restart your computer for you.")
        result = "installed"
    else:
        print(f"\n  The installer has closed (its exit code was {code}), but Windows does")
        print("  not list USBPcap as installed. Perhaps the installer was cancelled, or")
        print("  it said it cannot install on this computer. Nothing else was changed.")
        print("  If it showed a message, please tell us what it said.")
        result = "still not installed"
    question = ("\n  Delete the downloaded installer file now? It is not needed any more\n"
                "  now that USBPcap is installed. (yes / no): " if now else
                "\n  Delete the downloaded installer file now? Keep it if you want to try\n"
                "  again later by double-clicking it. (yes / no): ")
    if said_yes(ask(question)):
        try:
            os.remove(got["path"])
            print("  Deleted.")
            if made:
                _remove_empty(folder)
        except OSError as exc:
            print(f"  It could not be deleted ({exc}). You can delete it yourself:")
            print(f"      {got['path']}")
    else:
        print(f"  It stays here:  {got['path']}")
    return result


def relaunch_command() -> tuple:
    """(program, parameters, folder) to start this tool again, straight into
    the handheld session."""
    extra = " --relaunched"
    # 1.6 review: the copy started as administrator keeps the session's
    # instrument (the one CHOSEN at the question; --isis only counts before
    # it) and its step numbers (parsed: digits and commas only).
    steps = ",".join(str(n) for n in parse_step_numbers(str(_RUN.get("steps") or ""), 99))
    if steps:
        extra += f" --steps {steps}"
    if _RUN.get("output"):
        extra += f' -o "{_RUN["output"]}"'
    if _RUN.get("no_redact"):
        extra += " --no-redact"
    if SELFTEST:
        extra += f" --selftest {','.join(sorted(SELFTEST))}"
    chosen = _RUN.get("profile")
    if chosen == "isis" or (chosen is None and _RUN.get("isis")):
        session = "--isis"
    elif chosen in PROFILE_NAMES:
        session = f"--i1pro --profile {chosen}"
    else:
        session = "--i1pro"
    if getattr(sys, "frozen", False):
        return sys.executable, session + extra, os.getcwd()
    script = os.path.abspath(__file__)
    return sys.executable, f'"{script}" {session}' + extra, os.getcwd()


def offer_relaunch_as_admin(launch=None) -> bool:
    """Not administrator: offer, once, to start again as administrator through
    Windows' own question. On success this copy closes (raises Relaunched)."""
    launch = launch or (lambda prog, params, folder: _shell_execute(
        prog, params, verb="runas", wait=False, folder=folder))
    if _RUN.get("relaunched"):
        # Started by this offer already and still not administrator (for
        # example User Account Control is off): never offer again.
        print("\n  This copy was started as administrator by the tool itself, but Windows")
        print("  still does not give it administrator rights. The steps above say how")
        print("  to start it as administrator yourself.")
        return False
    if not said_yes(ask("\n  Start this tool again as administrator now? Windows will ask for\n"
                        "  permission, and a new window opens. (yes / no): ")):
        print("  All right. The steps above say how to do it yourself.")
        return False
    prog, params, folder = relaunch_command()
    try:
        started = launch(prog, params, folder)
    except Exception:                                     # noqa: BLE001
        started = None
    if started is None:
        print("\n  It did not start (perhaps the answer to Windows' question was \"No\").")
        print("  Nothing else happens; the steps above say how to do it yourself.")
        return False
    print("\n  A new window opens, running as administrator; carry on there.")
    print("  You can close this window now." if _RUN.get("no_pause")
          else "  This window closes now.")
    time.sleep(3)
    raise Relaunched()


# --------------------------------------------------------------------------
# 1.5.2: the end of every run. The second user double-clicked the Windows exe,
# the tool printed its install help, and the console window closed the moment
# it finished: he never saw the help and thought it had crashed. So every way
# out (normal end, "nothing recorded", q, an error, Ctrl-C) ends here: what to
# do now, where it is saved, and "Press Enter to close this window."
# --------------------------------------------------------------------------

WIRESHARK_DOWNLOAD_URL = "https://www.wireshark.org/download.html"


def _note_cause(cause: str) -> None:
    if cause not in _CAUSES:
        _CAUSES.append(cause)


def what_to_do_lines(causes: list, report_path: str | None) -> list:
    """The short WHAT TO DO NOW box: the single next action first."""
    if not causes:
        return []
    steps = []
    if "no_instrument" in causes and _RUN.get("profile") == "isis":
        steps.append("Switch the i1iSis on FIRST, then plug its USB cable straight into "
                     "the computer (not through a USB hub). X-Rite says that in the other "
                     "order i1Profiler does not see the i1iSis.")
    elif "no_instrument" in causes:
        steps.append("Plug the instrument in (straight into the computer, not through "
                     "a USB hub), and switch the table on if you have one.")
    if "usbpcap_missing" in causes:
        steps.append("Install USBPcap: open " + WIRESHARK_DOWNLOAD_URL + ", run the "
                     "\"Windows x64 Installer\" and, on its page \"USB Capture\", tick "
                     "\"Install USBPcap\".")
        steps.append("Restart Windows.")
    if "usbpcap_restart" in causes:
        steps.append("Restart Windows: USBPcap is installed now, and starts listening "
                     "to the USB ports only after a restart.")
    if "wrong_driver" in causes:
        steps.append("Give the instrument X-Rite's driver back in Device Manager, and "
                     "check that the measuring program finds it.")
    if "not_admin" in causes:
        steps.append(f"Then right-click  {tool_name()}  and choose \"Run as "
                     "administrator\", and choose the recording session again.")
    else:
        steps.append("Then run this tool again.")
    rule = "  " + "=" * 66
    lines = ["", rule, "    WHAT TO DO NOW", ""]
    for n, text in enumerate(steps, 1):
        lines.append(f"    {n}. " + _wrap(text, 60, " " * 7))
    lines.append("")
    if report_path:
        lines += ["    The same instructions, in full, are in your report. It stays",
                  "    there after this window is closed:",
                  "        " + os.path.basename(report_path),
                  "    in the folder:",
                  "        " + (os.path.dirname(report_path) or ".")]
    else:
        lines.append("    No report was saved this time.")
    lines.append(rule)
    return lines


def _console_process_ids():
    """Windows: the processes attached to this console, or None."""
    try:
        import ctypes                                     # noqa: PLC0415
        arr = (ctypes.c_uint32 * 64)()
        n = ctypes.windll.kernel32.GetConsoleProcessList(arr, 64)  # type: ignore[attr-defined]
        if n <= 0:
            return None
        if n > 64:                                        # crowded: surely not ours alone
            return list(arr) + [-1]
        return list(arr[:n])
    except Exception:                                     # noqa: BLE001
        return None


def _process_image(pid: int) -> str | None:
    """Windows: the full path of a process's program, or None."""
    try:
        import ctypes                                     # noqa: PLC0415
        from ctypes import wintypes                       # noqa: PLC0415
        k32 = ctypes.windll.kernel32                      # type: ignore[attr-defined]
        handle = k32.OpenProcess(0x1000, False, pid)      # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return None
        try:
            buf = ctypes.create_unicode_buffer(1024)
            size = wintypes.DWORD(1024)
            if not k32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
                return None
            return buf.value
        finally:
            k32.CloseHandle(handle)
    except Exception:                                     # noqa: BLE001
        return None


def owns_console(process_ids=None, self_pid=None, parent_pid=None,
                 image_of=None, executable=None):
    """Windows: True when this program has its console window to itself,
    which is what a double-click gives; False when it was started from a
    command window (cmd, PowerShell, a launcher .bat), whose window stays
    open; None when it cannot be told.

    Not "the console's process list holds only this process": a one-file
    PyInstaller exe runs as two processes, the bootloader and its child, both
    on the same console, and a double-clicked .py runs under py.exe. So our
    own parent is not counted when it is that bootloader (the same program
    file) or the py launcher."""
    ids = _console_process_ids() if process_ids is None else process_ids
    if not ids:
        return None
    self_pid = os.getpid() if self_pid is None else self_pid
    parent_pid = os.getppid() if parent_pid is None else parent_pid
    image_of = _process_image if image_of is None else image_of
    executable = sys.executable if executable is None else executable
    others = [p for p in ids if p != self_pid]
    if parent_pid in others:
        image = image_of(parent_pid) or ""
        same = bool(image) and image.lower() == (executable or "").lower()
        launcher = os.path.basename(image.replace("\\", "/")).lower() in ("py.exe", "pyw.exe")
        if same or launcher:
            others.remove(parent_pid)
    return not others


def _isatty(stream) -> bool:
    try:
        return bool(stream) and stream.isatty()
    except (AttributeError, ValueError, OSError):
        return False


def should_pause(argv, env=None, stdin=None, stdout=None, system=None,
                 frozen=None, owns=None) -> bool:
    """Whether to end with "Press Enter to close this window."

    --no-pause never, --pause always. Otherwise never under CI or when input
    or output is piped or redirected; on Windows when this program owns its
    console window (a double-click). When that cannot be told, the frozen
    exe waits (a double-click is how people start it, and one extra Enter in
    a command window costs nothing) and the script does not. macOS keeps a
    Terminal window open after the program ends ("[Process completed]"), and
    the macOS and Linux launchers wait themselves."""
    argv = list(argv or [])
    env = os.environ if env is None else env
    if "--no-pause" in argv or env.get("CHROMIQ_PROBE_NO_PAUSE"):
        return False
    if "--pause" in argv:
        return True
    if env.get("CI") or env.get("GITHUB_ACTIONS"):
        return False
    if not (_isatty(sys.stdin if stdin is None else stdin)
            and _isatty(sys.stdout if stdout is None else stdout)):
        return False
    if (platform.system() if system is None else system) != "Windows":
        return False
    owned = owns_console() if owns is None else owns()
    if owned is None:
        return bool(getattr(sys, "frozen", False) if frozen is None else frozen)
    return owned


def wait_for_enter() -> None:
    flush_pending_input()
    print()
    try:
        input("  Press Enter to close this window.")
    except (EOFError, KeyboardInterrupt):
        pass
    print()


def crash_text(trace: str, saved: str | None) -> list:
    lines = ["", "!" * 68,
             "  SORRY: THE TOOL STOPPED BECAUSE OF A MISTAKE IN IT",
             "!" * 68, "",
             "  This is our mistake, not something you did."]
    if saved:
        lines += ["  What the tool had collected so far, and the technical details of",
                  "  the error, were saved here:", "", "      " + saved, "",
                  "  Please send us that file (or a photo of this window), so we can",
                  "  fix it."]
    else:
        lines += ["  It could not save a report. Please copy the text of this window",
                  "  (or take a photo of it) and send it to us, so we can fix it."]
    lines += ["", "  The technical details, for us:", "", trace.rstrip()]
    return lines


def offer_download_page(interactive: bool, system: str | None = None) -> None:
    """Windows, USBPcap missing: offer to open the download page. Opens
    nothing without a yes."""
    if "usbpcap_missing" not in _CAUSES or not interactive:
        return
    if (platform.system() if system is None else system) != "Windows":
        return
    answer = ask("\n  Open the download page (" + WIRESHARK_SHORT + ") in your web browser\n"
                 "  now? Type  yes  to open it, or just press Enter for no: ")
    if said_yes(answer):
        import webbrowser                                 # noqa: PLC0415
        try:
            webbrowser.open(WIRESHARK_DOWNLOAD_URL)
            print("  Opened. If nothing appeared, type the address into your browser:")
        except Exception:                                 # noqa: BLE001
            print("  The browser could not be opened. Please type this address into it:")
        print("      " + WIRESHARK_DOWNLOAD_URL)


WIRESHARK_SHORT = "wireshark.org/download.html"


def console_main(argv: list | None = None) -> int:
    """main() inside the one way out every run takes."""
    argv = sys.argv[1:] if argv is None else list(argv)
    pause = should_pause(argv)
    try:
        code = main(argv)
    except Relaunched:
        # 1.5.3: the copy running as administrator carries on in its own
        # window; this one closes, as it said it would.
        return 0
    except KeyboardInterrupt:
        print("\n\n  Stopped (Ctrl-C). Nothing more was done; anything already saved"
              "\n  is kept.")
        code = 130
        # 1.5.4 review: a session that ran must not lose its step log.
        if _SECTIONS and not _LAST_REPORT.get("path") and _END.get("sip_box"):
            try:
                saved = write_report(report_text(), _RUN.get("output"))
            except Exception:                             # noqa: BLE001
                saved = None
            if saved:
                _LAST_REPORT["path"] = saved
                print(f"  What was collected so far was saved here:\n      {saved}")
    except SystemExit as exc:                             # argparse: --help, bad option
        code = exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 2)
    except Exception:                                     # noqa: BLE001
        import traceback                                  # noqa: PLC0415
        trace = traceback.format_exc()
        saved = None
        try:
            section("The tool stopped because of an error", trace)
            saved = write_report(report_text(), None)
        except Exception:                                 # noqa: BLE001
            saved = None
        if saved:
            _LAST_REPORT["path"] = saved
        print("\n".join(crash_text(trace, saved)))
        code = 1
    try:
        if _CAUSES:
            print("\n".join(what_to_do_lines(_CAUSES, _LAST_REPORT.get("path"))))
            offer_download_page(_isatty(sys.stdin))
    except Exception:                                     # noqa: BLE001
        pass
    try:
        tail = end_of_run_lines()
        if tail:
            print("\n".join(tail))
    except Exception:                                     # noqa: BLE001
        pass
    if pause:
        wait_for_enter()
    return code


if __name__ == "__main__":
    sys.exit(console_main())
