#!/usr/bin/env python3
"""
chromiq_io_probe.py: the ChromIQ X-Rite instrument probe
(the i1iO table, issue #129; since 1.5 also the i1Pro family, the ColorMunki
and the i1Studio).

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

    On a Mac a recording is only possible when SIP is switched off. The tool
    checks that for you, says plainly whether a recording is possible, and if
    it is not, explains the other ways to make one.

    Stage 2 for a handheld instrument (i1Pro, i1Pro 2, i1Pro 3, ColorMunki,
    i1Studio), a guided session recorded step by step:

        python3 chromiq_io_probe.py --i1pro

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

PROBE_VERSION = "1.5.3"

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
}


# 1.5: devices under X-Rite's newer vendor ID, named from ArgyllCMS's device
# table (insttypes.c:439-450). Not yet seen in a report; said so.
KNOWN_IDS_0765 = {
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
    for pattern, _name in _SERIAL_RULES:
        text = pattern.sub(_hash_secret, text)
    return text


def section(title: str, body: str) -> None:
    _SECTIONS.append((title, scrub(body if body is not None else "")))


def ask(prompt: str, interruptible: bool = False) -> str:
    try:
        return input(prompt).strip()
    except EOFError:
        print()
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
        lines.append("Please check the table is powered on and plugged in, then run again.")
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
        lines.append(f"  {label}: {status}")
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


def recording_not_possible_text(r: dict, device: str = "table") -> str:
    """device: "table" (the i1iO, 1.4) or "instrument" (the 1.5 session)."""
    reasons = "\n".join("    - " + _wrap(reason, 66, "      ") for reason in r["reasons"])
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
     Which Windows works: the X-Rite driver for the i1Pro 2 and the i1iO 2
     needs Windows 10 with i1Profiler 3.8.5, or Windows 11 version 24H2 or
     older with i1Profiler 3.8.6. X-Rite says the driver is blocked on
     Windows 11 version 25H2 and newer.
     A Windows virtual machine on an Apple Silicon Mac does NOT work:
     there is no i1Pro or i1iO driver for Windows on ARM.

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
     you already own one or enjoy this kind of thing.

{I1PROFILER_WARNING}

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


WINDOWS_ARM_NOTE = """\
  This Windows runs on an ARM processor. There is no X-Rite driver for the
  i1Pro or the i1iO on Windows on ARM, so i1Profiler cannot talk to the
  table here. That includes a Windows virtual machine on an Apple Silicon
  Mac. For a recording, please use a Windows PC with an Intel or AMD
  processor."""


def collect_windows() -> None:
    ps = shutil.which("powershell") or shutil.which("pwsh")
    if not ps:
        section("Windows", "[PowerShell not found, cannot list USB devices]")
        return

    def psrun(script: str) -> str:
        return run([ps, "-NoProfile", "-NonInteractive", "-NoLogo", "-Command",
                "$ProgressPreference = 'SilentlyContinue'; " + script], timeout=60)

    section("Windows: X-Rite USB devices", psrun(
        "Get-PnpDevice | Where-Object { ($_.InstanceId -like '*VID_0971*' -or $_.InstanceId -like '*VID_0765*') } | "
        "Format-List FriendlyName,InstanceId,Status,Class,Present"
    ))
    section("Windows: device properties (hardware + driver)", psrun(
        "Get-PnpDevice | Where-Object { ($_.InstanceId -like '*VID_0971*' -or $_.InstanceId -like '*VID_0765*') } | "
        "ForEach-Object { '=== ' + $_.InstanceId + ' ==='; "
        "Get-PnpDeviceProperty -InstanceId $_.InstanceId | "
        "Select-Object KeyName,Data | Format-List }"
    ))
    section("Windows: all USB controllers/hubs (topology context)", psrun(
        "Get-PnpDevice -Class USB | Format-List FriendlyName,InstanceId,Status"
    ))
    section("Windows: X-Rite driver files", psrun(
        "Get-ChildItem -Path 'C:\\Program Files*\\X-Rite','C:\\Program Files*\\i1Profiler' "
        "-Recurse -Include *.dll,*.exe -ErrorAction SilentlyContinue | "
        "Select-Object FullName,Length,@{n='Version';e={$_.VersionInfo.FileVersion}} | "
        "Format-List"
    ))
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
        if is_here is False:
            text += "   (not plugged in now; Windows remembers it from before)"
        elif is_here and m:
            text += "   (plugged in now)"
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
                           "Get-PnpDevice | Where-Object { ($_.InstanceId -like '*VID_0971*' -or $_.InstanceId -like '*VID_0765*') } "
                           "| ForEach-Object { $_.FriendlyName + ' :: ' + $_.InstanceId + ' :: ' + $_.Present }"])
                found, present = windows_summary_lines(out)
                _DETECTION.clear()
                _DETECTION["present_ids"] = present
    except Exception as exc:                              # noqa: BLE001
        return f"[summary failed: {exc}]"

    if not found:
        return ("NO X-RITE DEVICES SEEN.\n"
                "Please check the table is powered on and plugged in, then run again.")
    text = "X-Rite devices detected:\n  " + "\n  ".join(found)
    if system == "Windows" and "present_ids" in _DETECTION and not _DETECTION["present_ids"] \
            and any("(not plugged in now" in f for f in found):
        text += ("\nNone of them is plugged in right now. Please plug in the instrument "
                 "and run the tool again.")
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

# These follow i1Profiler's ACTUAL i1iO workflow, taken from its own on-screen
# instructions: place chart -> press Measure (it calibrates and the arm slides
# out) -> the operator GRABS THE ARM BY HAND and aligns the cross hairs on the
# top-left, bottom-left and bottom-right corners -> it then scans row by row.
# There is no "go home" button (the arm parks itself) and no electrostatic-foil
# toggle (the static mat just holds the paper).
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

# The short version used for a Mac recording: start, one small action, stop.
RECORDING_STEPS = [
    ("Replug",
     "If i1Profiler is open, quit it. Unplug the table's USB cable, wait\n"
     "    5 seconds, and plug it back in. That puts the table's full USB\n"
     "    description into the recording. Type 'skip' if you would rather not."),
    ("Connect",
     "Start i1Profiler and let it find the table. Do nothing else yet."),
    ("Idle",
     "Leave everything untouched for about 10 seconds."),
    ("One small action",
     "Place a chart on the table and press \"Measure\". Let the device\n"
     "    calibrate and the arm slide out, then cancel the measurement."),
    ("Parked",
     "Wait until the arm has parked itself."),
]

# Offered after RECORDING_STEPS, for anyone with ten more minutes.
EXTRA_RECORDING_STEPS = [("Measure pressed again",
                          "Press \"Measure\" again and let the arm slide out.")] \
    + CAPTURE_STEPS[3:]


def run_walkthrough(steps: list, t0: float) -> list:
    """Time each step. Returns timeline lines. Ctrl-C ends it early."""
    log = []
    print("\nDo each step in i1Profiler, then press Enter here immediately after.")
    print("If a step is not possible on your setup, just type 'skip'.\n")
    for name, instruction in steps:
        print(f"--- {name} ---")
        print(f"    {instruction}")
        start = time.time() - t0
        answer = ask("    press Enter when finished (or 'skip'): ", interruptible=True)
        end = time.time() - t0
        if answer.lower().startswith("s"):
            log.append(f"{name}: SKIPPED")
            print("    skipped\n")
            continue
        flat = " ".join(instruction.split())
        log.append(f"{name}: t={start:8.3f}s .. {end:8.3f}s   ({flat})")
        print(f"    recorded {start:.3f}s .. {end:.3f}s\n")
    return log


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
    print("Next: I would walk you through " + str(len(CAPTURE_STEPS)) + " short operations in i1Profiler")
    print("(connect, align the arm on the chart corners, scan a couple of")
    print("rows) and time each one, so the recording can be split up later.")
    print("It takes about 10 minutes and needs the recording to be running.")
    print("-" * 68)

    if not said_yes(ask("\nIs the recording running? Shall I start the walkthrough? (yes / no): ")):
        print("\n  Skipping the walkthrough. That is absolutely fine.")
        print("  Your main report is unaffected and still worth sending.")
        print("  To do it another time, run this tool again and choose the")
        print("  recording step (or start it directly with  --annotate ).\n")
        section("Stage 2: timed recording",
                "[walkthrough skipped by operator, no recording running]")
        return
    t0 = time.time()
    log = [f"session start (monotonic zero): {datetime.datetime.now().isoformat()}"]
    try:
        log += run_walkthrough(CAPTURE_STEPS, t0)
    except KeyboardInterrupt:
        log.append("walkthrough ended early with Ctrl-C")
    notes = ask("Anything odd happen? (free text, Enter to skip): ")
    if notes:
        log.append(f"operator notes: {notes}")
    section("Stage 2: annotated capture timeline", "\n".join(log))
    print("\nStop your recording now and save the file.")
    print("Send BOTH the recording and this probe report.\n")


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
  3. You do a few short steps in i1Profiler (about 3 minutes).
  4. The tool stops recording, switches the interfaces off again, checks
     the recording, and makes a copy that holds only the X-Rite traffic.

  Please do not type anything private on a USB keyboard while it records:
  a recording holds everything on the same USB bus, and the tool records
  every bus because it cannot be sure which one the table is on. The copy
  you send contains only the X-Rite devices' traffic.

  It does not change System Integrity Protection; you switched that off
  yourself, and you switch it back on yourself afterwards.""")
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
    log = [f"session start (monotonic zero): {datetime.datetime.now().isoformat()}"]
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
            log += run_walkthrough(RECORDING_STEPS, t0)
            print("-" * 68)
            print("  That is the short version done. If you have about 10 more")
            print("  minutes, the longer part (aligning the arm on the corners and")
            print("  scanning two rows) shows us much more of how the table works.")
            if said_yes(ask("  Carry on with the longer part? (yes / no): ", interruptible=True)):
                log += run_walkthrough(EXTRA_RECORDING_STEPS, t0)
    except KeyboardInterrupt:
        ended_early = "Ctrl-C"
    except _Hangup:
        ended_early = "window closed or stop signal"
    finally:
        print("\n  Stopping the recording...")
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
                signal.signal(sig, handler)
            except (ValueError, OSError):
                pass
        if brought_up:
            if still_up:
                print(f"  Could not switch {', '.join(still_up)} off again. They switch off")
                print("  by themselves when you restart the Mac.")
            else:
                print(f"  Switched {', '.join(brought_up)} off again.")
    if ended_early:
        log.append(f"recording ended early: {ended_early}")

    notes = ask("\nAnything odd happen? (free text, Enter to skip): ")
    if notes:
        log.append(f"operator notes: {notes}")
    section("Stage 2: annotated capture timeline", "\n".join(log))

    result_lines = finish_recordings(files)
    section("Stage 2: macOS recording result", "\n".join(result_lines))
    print("\n" + "\n".join("  " + l for l in result_lines))
    print()
    print(SIP_OFF_REMINDER)
    print()


def finish_recordings(files: dict) -> list:
    """Check each recording, make the X-Rite-only copies, offer to delete the rest."""
    lines = ["RECORDING CHECK"]
    send = []
    full = []
    for iface, path in files.items():
        if not os.path.exists(path):
            continue
        full.append(path)
        check = check_capture(path)
        lines.append(f"{iface}: {check['packets']} packets, "
                     f"{check['xrite_packets']} of them from X-Rite devices")
        lines.append("  " + check["verdict"])
        if check["xrite_packets"]:
            dst = path.replace("-full.pcap", "-xrite.pcap")
            kept = filter_xrite_capture(path, dst)
            if kept:
                send.append(dst)
                lines.append(f"  X-Rite-only copy ({kept} packets): {os.path.basename(dst)}")
    lines.append("")
    if send:
        lines.append("Please attach these files to the GitHub issue, together with the report:")
        lines.extend("  " + os.path.basename(p) for p in send)
    else:
        lines.append("No X-Rite traffic was found in any recording, so there is nothing "
                     "useful to send. The report on its own still helps.")
    if full:
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


def _analyze_darwin(recs):
    """Device-agnostic summary: (devices, cmd_counts, timeline, bulk, descriptors)."""
    submits = {}                    # seq -> (bRequest, dir_in, wLen, ts, wValue, bmReqType)
    cmd_counts = {}
    devices = {}
    timeline = []
    bulk_bytes = 0
    descriptors: list = []
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
                if len(timeline) < 30:
                    timeline.append((tsub - t0, breq, dir_in, wlen, resp[:16]))
            elif dlen >= 64:
                bulk_bytes += dlen
    return devices, cmd_counts, timeline, bulk_bytes, descriptors


def check_capture(path: str) -> dict:
    """Plain facts about one recording, including the all-zero payload check."""
    try:
        linktype, recs = _read_pcap(path)
    except (OSError, ValueError) as exc:
        return {"ok": False, "packets": 0, "xrite_packets": 0, "linktype": None,
                "code": "unreadable", "verdict": f"not a readable recording: {exc}"}
    identified = True
    if linktype == LINKTYPE_USB_DARWIN:
        mine = [d for _ts, d in recs if _darwin_vid(d) in XRITE_VIDS]
        xrite = len(mine)
    else:
        # 1.5: Windows and Linux records carry a bus and device address but no
        # vendor ID, so the X-Rite device is found from its USB description
        # (or its i1Pro commands). If the recording shows no device at all,
        # every record counts, as in 1.4.
        keys = record_device_keys(linktype, recs)
        devices = device_map(capture_events(linktype, recs))
        wanted = set(xrite_devices(devices))
        if wanted:
            mine = [d for (_ts, d), k in zip(recs, keys) if k in wanted]
        elif any(v.get("vid") for v in devices.values()):
            mine = []
        else:
            mine = [d for _ts, d in recs]
            identified = False
        xrite = len(mine)
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
    else:
        code, verdict = "ok", (f"OK: real data recorded ({nonzero:,} non-zero data "
                               f"bytes out of {payload_bytes:,}).")
    if code == "ok" and not identified:
        verdict += (" Which device each packet belongs to could not be told from this "
                    "recording (it holds no USB description).")
    return {"ok": code == "ok", "packets": len(recs), "xrite_packets": xrite,
            "linktype": linktype, "code": code, "verdict": verdict,
            "payload_bytes": payload_bytes, "nonzero_bytes": nonzero,
            "identified": identified}


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


def filter_xrite_capture(src: str, dst: str) -> int:
    """Write a copy holding only the X-Rite device's records. Returns count.

    macOS: by the vendor ID in each record (1.4). Windows (USBPcap) and Linux
    (usbmon): by the bus and device address that the recording's own USB
    description shows for the X-Rite device (or, failing that, the device
    that uses the i1Pro's commands). Nothing from any other device address
    is copied: not the keyboard, not the mouse, not the hub.
    """
    try:
        linktype, recs = _read_pcap(src)
    except (OSError, ValueError):
        return 0
    if linktype in (LINKTYPE_USBPCAP, LINKTYPE_USB_LINUX, LINKTYPE_USB_LINUX_MMAPPED):
        wanted = set(xrite_devices(device_map(capture_events(linktype, recs))))
        if not wanted:
            return 0
        keys = record_device_keys(linktype, recs)
        kept = [r for r, k in zip(recs, keys) if k in wanted]
        if not kept or not _write_pcap(dst, linktype, kept):
            return 0
        return len(kept)
    return _filter_darwin_capture(src, dst)


def _filter_darwin_capture(src: str, dst: str) -> int:
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
    out = [blob[:24]]
    kept = 0
    off = 24
    while off + 16 <= len(blob):
        incl = struct.unpack(endian + "I", blob[off + 8:off + 12])[0]
        rec_end = off + 16 + incl
        if rec_end > len(blob):
            break
        if _darwin_vid(blob[off + 16:rec_end]) in XRITE_VIDS:
            out.append(blob[off:rec_end])
            kept += 1
        off = rec_end
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
                           f"{resp.hex()}  |{_fmt_ascii(resp)}|")
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
    for ts, d in recs:
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
                      "out": bytes(data[8:]), "in": b"", "_done": False}
                ev.update(_setup_fields(data))
                pending[key] = ev
                events.append(ev)
                continue
            ev = pending.get(key)
            if ev is None:
                continue
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
                       "dir_in": dir_in, "data": bytes(data)})
    for ev in events:
        ev.pop("_done", None)
    return events


def _events_usbmon(recs, hdr_len: int) -> list:
    events = []
    pending = {}
    for ts, d in recs:
        if len(d) < hdr_len:
            continue
        (uid, typ, xfer, epnum, devnum, busnum, flag_setup, _flag_data, _sec, _usec,
         _status, _length, len_cap, setup) = struct.unpack_from("<QcBBBHccqiiII8s", d, 0)
        data = d[hdr_len:hdr_len + len_cap]
        key = (busnum, uid)
        if xfer == 2:
            if typ == b"S" and flag_setup == b"\x00" and _plausible_setup(setup):
                ev = {"kind": "control", "t": ts, "bus": busnum, "dev": devnum,
                      "out": bytes(data), "in": b""}
                ev.update(_setup_fields(setup))
                pending[key] = ev
                events.append(ev)
            elif typ == b"C":
                ev = pending.pop(key, None)
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
                       "dir_in": dir_in, "data": bytes(data)})
    return events


def _events_darwin(recs) -> list:
    events = []
    pending = {}
    for ts, d in recs:
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
                      "out": bytes(payload[8:]), "in": b"", "vid": vid, "pid": pid}
                ev.update(_setup_fields(payload))
                pending[seq] = ev
                events.append(ev)
                continue
        if direction == 1 and seq in pending:
            ev = pending.pop(seq)
            if ev["rt"] & 0x80:
                ev["in"] = bytes(payload[:dlen] if dlen else payload)
            continue
        dir_in = bool(ep & 0x80)
        data = payload[:dlen] if dlen else payload
        if not data or (direction == 1) != dir_in:
            continue
        events.append({"kind": "data", "t": ts, "bus": bus, "dev": dev, "ep": ep,
                       "type": etype, "dir_in": dir_in, "data": bytes(data),
                       "vid": vid, "pid": pid})
    return events


def capture_events(linktype: int, recs) -> list:
    """The recording as a list of control and data events (see above)."""
    if linktype == LINKTYPE_USBPCAP:
        return _events_usbpcap(recs)
    if linktype == LINKTYPE_USB_LINUX:
        return _events_usbmon(recs, 48)
    if linktype == LINKTYPE_USB_LINUX_MMAPPED:
        return _events_usbmon(recs, 64)
    if linktype == LINKTYPE_USB_DARWIN:
        return _events_darwin(recs)
    return []


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


def xrite_devices(devices: dict) -> list:
    return [k for k, v in devices.items()
            if v.get("vid") in XRITE_VIDS or v.get("guess_family")]


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
    # Defined in Argyll but never called (i1pro3_imp.c:5380, :5317).
    0x3A: ("set tint multiplier", "i1pro3_imp.c:5398", _raw, False),
    0x3B: ("set scan-start indicator timing", "i1pro3_imp.c:5343", _d3_scanind, False),
    0x66: ("start event reports on 0x83", "i1pro3_imp.c:5881", _raw, True),
}


def decode_i1pro3_led(blob: bytes) -> dict:
    """i1Pro 3 light sequence: groups of 3 bytes (i1pro3_imp.c:6074-6141).

    Argyll's notes on the first byte are partly guesses; only the colour
    bits and blink/pulse it lists are decoded, the rest is shown raw.
    """
    groups = [blob[i:i + 3] for i in range(0, len(blob) - len(blob) % 3, 3)]
    if not groups:
        return {"ok": True, "text": "off" if len(blob) < 3 else blob.hex(), "colours": []}
    parts = []
    colours = set()
    for g in groups:
        b0, b1, b2 = g[0], g[1], g[2]
        if b0 & 0x80:
            colour = "unknown (top bit set)"
        elif b0 & 0x10 and not b0 & 0x08:
            colour = "white"
        elif b0 & 0x0C == 0x0C:
            colour = "red"
        elif b0 & 0x0C == 0x08:
            colour = "green"
        else:
            colour = "off"
        style = "blink once" if b0 & 0x01 else "pulse"
        if colour != "off":
            colours.add(colour)
        parts.append(f"{colour} {style} (timing 0x{b1:02x}, count {b2}) [{g.hex()}]")
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
}


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
                text = (f"UNKNOWN {kind} request 0x{req:02X} "
                        f"{'IN' if rt & 0x80 else 'OUT'} bmRequestType=0x{rt:02x} "
                        f"wValue=0x{ev['wValue']:04x} wIndex=0x{ev['wIndex']:04x} "
                        f"wLength={ev['wLength']} out={ev['out'].hex() or '-'} "
                        f"in={ev['in'].hex() or '-'}")
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
        flag = "  <-- endpoint the open driver never uses" if foreign and family != "generic" \
            else ""
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
    notes = notes or {}
    if notes.get("did"):
        out.append(f"  operator, what happened: {notes['did']}")
    if notes.get("lights"):
        out.append(f"  operator, the lights: {notes['lights']}")
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
            flag = "" if info["ep"] in fam["argyll_eps"] or res["family"] == "generic" \
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


def _xrite_events(path: str):
    """(events of the X-Rite devices, device map, check) for one file."""
    check = check_capture(path)
    if check["code"] == "unreadable":
        return [], {}, check
    linktype, recs = _read_pcap(path)
    events = capture_events(linktype, recs)
    devices = device_map(events)
    mine = set(xrite_devices(devices))
    if mine:
        events = [e for e in events if (e["bus"], e["dev"]) in mine]
    return events, devices, check


def session_steps(paths: list) -> tuple:
    """Turn --analyze arguments into steps.

    Returns (steps, devices, checks, session); each step is
    (title, events, notes, is_control, key). A session file (session.json,
    written by the guided session) names its steps and files; a plain
    recording is one step named after the file, and a file whose name says
    "noruler" or "control" is the control.
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
    if session:
        base = session["_dir"]
        if not whole and session.get("whole_recording"):
            cand = os.path.join(base, session["whole_recording"])
            if os.path.exists(cand):
                whole.append(cand)
        cache: dict = {}
        for step in session.get("steps", []):
            if step.get("skipped"):
                continue
            files = [os.path.join(base, f) for f in step.get("files_xrite") or []]
            files = [f for f in files if os.path.exists(f)]
            events = []
            if files:
                for f in files:
                    evs, devs, check = _xrite_events(f)
                    events += evs
                    devinfo.update(devs)
                    checks.append((os.path.basename(f), check))
            elif whole and step.get("start_epoch") is not None:
                # One recording for the whole session (Wireshark by hand):
                # cut it at the times the tool noted.
                for f in whole:
                    if f not in cache:
                        cache[f] = _xrite_events(f)
                        devinfo.update(cache[f][1])
                        checks.append((os.path.basename(f), cache[f][2]))
                    lo, hi = step["start_epoch"], step.get("end_epoch") or 1e18
                    events += [e for e in cache[f][0] if lo <= e["t"] <= hi]
            events.sort(key=lambda e: e["t"])
            title = f"step {step.get('number', '?')}: {step.get('title', step.get('key'))}"
            if step.get("take", 1) > 1:
                title += f" (take {step['take']})"
            steps.append((title, events, {"did": step.get("notes", ""),
                                          "lights": step.get("lights", "")},
                          bool(step.get("control")), step.get("key", "")))
        return steps, devinfo, checks, session
    for f in whole:
        evs, devs, check = _xrite_events(f)
        devinfo.update(devs)
        checks.append((os.path.basename(f), check))
        low = os.path.basename(f).lower()
        control = "noruler" in low or "no-ruler" in low or "control" in low
        steps.append((os.path.basename(f), evs, {}, control, low))
    return steps, devinfo, checks, None


def session_family(devinfo: dict, steps: list, session: dict | None = None) -> str:
    if session and session.get("family") in FAMILIES:
        return session["family"]
    all_events = [e for _n, evs, *_ in steps for e in evs]
    for info in devinfo.values():
        if info.get("vid") in XRITE_VIDS:
            fam = family_for(info["vid"], info["pid"], info.get("config"), all_events)
            if fam != "generic":
                return fam
    for info in devinfo.values():
        if info.get("guess_family"):
            fam = info["guess_family"]
            if fam in ("i1pro2", "i1pro"):
                return family_for(0x0971, 0x2000, (), all_events)
            return fam
    return "generic"


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
}


def summarize_session(paths: list) -> str:
    steps, devinfo, checks, session = session_steps(paths)
    family = session_family(devinfo, steps, session)
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
    xr = {k: v for k, v in devinfo.items()
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
    if endpoints_seen and family != "generic":
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
        results.append((name, res, notes, control, key))
        out.extend(format_step(name + ("  [CONTROL: no ruler]" if control else ""),
                               res, notes))
        out.append("")

    out.append("-" * 68)
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

    controls = [r for r in results if r[3]]
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

    fast = [r for r in results if "fast" in r[4]]
    slow = [r for r in results if "slow" in r[4]]
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
    out.append(f"    real instrument traffic, not zeros ... {yes[have_traffic]}")
    out.append(f"    USB description (endpoint list) ...... "
               f"{yes[any(v.get('config') for v in xr.values())]}")
    out.append(f"    measurements with readings ........... {yes[bool(scan_ms)]}")
    out.append(f"    a fast and a slow swipe .............. {yes[bool(fast and slow)]}")
    if family in ("i1pro2", "i1pro3"):
        out.append(f"    a dual-scan step ..................... "
                   f"{yes[any('dual' in r[4] for r in results)]}")
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


def summarize_i1pro_session(paths: list) -> str:
    return summarize_session(paths)


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
        t0 = time.time()
        log = [f"session start (monotonic zero): {datetime.datetime.now().isoformat()}"]
        try:
            log += run_walkthrough(CAPTURE_STEPS, t0)
        except KeyboardInterrupt:
            log.append("walkthrough ended early with Ctrl-C")
        notes = ask("Anything odd happen? (free text, Enter to skip): ")
        if notes:
            log.append(f"operator notes: {notes}")
        section("Stage 2: annotated capture timeline", "\n".join(log))
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
    print("  free program Wireshark (on Windows) and about 15 minutes.")
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
}

PROFILE_NAMES = {
    "i1pro2": "i1Pro 2",
    "i1pro": "original i1Pro (the first generation)",
    "i1pro3": "i1Pro 3 or i1Pro 3 Plus",
    "munki": "ColorMunki Photo / Design or i1Studio",
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
    "generic": """\
  The tool has no special knowledge of this instrument. It records the
  conversation and lists it as it is, which can still be useful.""",
}

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
  about 10 seconds and watch the instrument.""",
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
     "lights": "What did the lights do during the scan, and between the two passes if there were two?"},
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
  When the recording runs: scan the same strip slowly and steadily, so
  that it takes about three times as long as usual.""",
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
]

# Profiles whose instrument has lights worth asking about. The original
# i1Pro has none (the i1Pro 2's Rev E capability bits are the first to list
# indicator LEDs, i1pro_imp.h:165).
PROFILES_WITH_LIGHTS = ("i1pro2", "i1pro3", "munki", "generic")


def steps_for(profile: str) -> list:
    return [s for s in SESSION_STEPS if profile in s["families"]]


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
        return {"level": "problem", "text": (
            "This Windows runs on an ARM processor. X-Rite has no driver for these "
            "instruments on Windows on ARM (that includes a Windows virtual machine on "
            "an Apple Silicon Mac), so the vendor program cannot talk to the "
            "instrument here.")}
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
_XRITE_NAME_RE = re.compile(r"x-?rite|eye-?one|i1 ?pro|i1 ?studio|colormunki|gretag|calibrite",
                            re.I)


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
                "$ProgressPreference = 'SilentlyContinue'; " + script], timeout=60)


def windows_program_versions() -> dict:
    return parse_program_versions(_powershell(
        "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
        "'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' "
        "-ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | "
        "ForEach-Object { $_.DisplayName + ' :: ' + $_.DisplayVersion }"))


def i1profiler_check(version, profile: str) -> dict:
    if not version:
        return {"level": "unknown", "text": "not found (that is fine if you use another program)"}
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
# itself (compatible ID USB\MS_COMP_WINUSB), and X-Rite's i1Pro 3 driver is a
# WinUSB driver named "X-Rite i1Pro3".
_DRIVER_PS = (
    "Get-PnpDevice -PresentOnly | Where-Object { ($_.InstanceId -like '*VID_0971*' "
    "-or $_.InstanceId -like '*VID_0765*') } | ForEach-Object { "
    "$s = (Get-PnpDeviceProperty -InstanceId $_.InstanceId -KeyName DEVPKEY_Device_Service "
    "-ErrorAction SilentlyContinue).Data; "
    "$p = (Get-PnpDeviceProperty -InstanceId $_.InstanceId -KeyName DEVPKEY_Device_DriverProvider "
    "-ErrorAction SilentlyContinue).Data; "
    "'DRV :: ' + $_.FriendlyName + ' :: ' + $_.InstanceId + ' :: ' + $_.Class + ' :: ' + $s + ' :: ' + $p "
    "+ ' :: ' + $_.Status }")

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
        elif state == "winusb" and dev["vid"] == 0x0765:
            checks.append({"name": label, "level": "ok", "help": False, "text": (
                f"{label}: Windows' standard USB driver (WinUSB), which the "
                "instrument itself asks for. The vendor program normally finds "
                "it like this.")})
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
    4. Pick X-Rite's own entry: "X-Rite i1Pro3" for an i1Pro 3, or
       "i1 Pro" for an i1Pro or i1Pro 2. Not an entry with "(Argyll)" in
       its name, and not "X-Rite i1 Pro 3 / i1 Pro 3+" or "GretagMacbeth
       i1 Pro / i1 Pro 2" (those are the ArgyllCMS driver as ChromIQ
       installs it). Click Next. If X-Rite's entry is not in the list,
       reinstall (or repair) the vendor program: its installer brings
       X-Rite's driver.
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
            "i1profiler": i1profiler_check(i1p, profile), "build": build,
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


class _ProcRecorder:
    """Shared start/stop logic: one recording process per interface per step."""

    label = "recorder"

    def __init__(self, interfaces: list, outdir: str):
        self.interfaces = list(interfaces)
        self.outdir = outdir
        self.procs: dict = {}
        self.files: dict = {}
        self.notes: list = []

    def command(self, iface, path) -> list:
        raise NotImplementedError

    def iface_label(self, iface) -> str:
        return re.sub(r"[^A-Za-z0-9]+", "", str(iface)) or "bus"

    def session_start(self) -> bool:
        return True

    def session_end(self) -> None:
        pass

    def _popen(self, cmd):
        kwargs = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL,
                  "stderr": subprocess.PIPE}
        if os.name == "nt":
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        return subprocess.Popen(cmd, **kwargs)

    def start(self, stem: str) -> list:
        """Start recording; returns the interfaces that really record."""
        self.procs, self.files = {}, {}
        for iface in self.interfaces:
            path = os.path.join(self.outdir, f"{stem}-{self.iface_label(iface)}-full.pcap")
            try:
                open(path, "wb").close()
                self.procs[iface] = self._popen(self.command(iface, path))
            except OSError as exc:
                self.notes.append(f"{iface}: could not start ({exc})")
                continue
            self.files[iface] = path
        time.sleep(RECORDER_STARTUP_WAIT)
        live = []
        for iface, proc in list(self.procs.items()):
            if proc.poll() is None:
                live.append(iface)
                continue
            err = (proc.stderr.read() if proc.stderr else b"").decode("utf-8", "replace")
            if proc.stderr:
                proc.stderr.close()
            self.notes.append(f"{iface}: stopped at once: " +
                              (" ".join(err.split())[:200] or f"exit code {proc.returncode}"))
            retry = self.retry_command(iface, self.files[iface], err)
            if retry:
                try:
                    self.procs[iface] = self._popen(retry)
                    time.sleep(RECORDER_STARTUP_WAIT)
                    if self.procs[iface].poll() is None:
                        live.append(iface)
                        self.notes.append(f"{iface}: recording with simpler options")
                except OSError:
                    pass
        return live

    def retry_command(self, iface, path, err):
        return None

    def stop(self) -> list:
        """Stop every recorder; returns the files that exist."""
        for iface, proc in self.procs.items():
            if proc.poll() is not None:
                continue
            try:
                if os.name == "nt":
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
        for proc in self.procs.values():
            if proc.stderr:
                try:
                    proc.stderr.close()
                except OSError:
                    pass
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
    """Windows: USBPcapCMD, one per root hub, with the device descriptions."""

    label = "USBPcap (USBPcapCMD)"

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


def _session_ask(prompt: str) -> str:
    """ask(), but Ctrl-C and a closed window end the session cleanly."""
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


def _ask_profile(default: str) -> str:
    keys = ["i1pro2", "i1pro", "i1pro3", "munki", "generic"]
    print("\n  Which instrument do you use for this session?")
    for i, key in enumerate(keys, 1):
        mark = "   <- seen on this computer" if key == default else ""
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
                           program_version: str = "", context: dict | None = None) -> dict:
    """The guided steps. Returns the session dict (also written to session.json).

    recorder: an object with start(stem) -> live interfaces, stop() -> files,
    session_start(), session_end(), or None for time marks only (the user
    records the whole session himself, for example with Wireshark).
    """
    os.makedirs(folder, exist_ok=True)
    full_dir = folder + "-FULL-do-not-send"
    if recorder is not None:
        os.makedirs(full_dir, exist_ok=True)
        recorder.outdir = full_dir
    steps = steps_for(profile)
    session = {
        "kind": SESSION_KIND, "probe_version": PROBE_VERSION,
        "created": datetime.datetime.now().isoformat(timespec="seconds"),
        "family": profile, "instrument": PROFILE_NAMES[profile],
        "program": program, "program_version": program_version,
        "recorder": recorder.label if recorder else "time marks only",
        "platform": platform.platform(), "steps": [], "ended": "",
        "context": context or {},
    }
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
    try:
        if recorder is not None and not recorder.session_start():
            session["ended"] = "the recording program could not be started"
            print("\n  The recording could not be started, so no step was recorded.")
            return session
        index = 0
        take = 1
        while index < len(steps):
            step = steps[index]
            number = index + 1
            print("\n" + "-" * 68)
            print(f"  STEP {number} of {len(steps)}: {step['title']}"
                  + (f"  (take {take})" if take > 1 else ""))
            print("-" * 68)
            print(step["before"])
            print()
            print(step["during"])
            answer = _session_ask("\n  Press Enter to START recording this step, or type  s  "
                                  "to skip it,\n  or  q  to stop the session here: ").lower()
            if answer.startswith("q"):
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
                    print("\n  The recording did not start:")
                    for note in recorder.notes[-3:]:
                        print("    " + note)
                    print("  If it mentions access or permission, close this window and start")
                    print("  the tool again as administrator (right-click it, then \"Run as")
                    print("  administrator\"). Otherwise you can record with Wireshark by hand")
                    print("  (see the README) while the tool times the steps.")
                    session["ended"] = "the recording program stopped at once"
                    break
            entry["start_epoch"] = time.time()
            where = ", ".join(recorder.iface_label(x) if recorder else str(x) for x in live)
            print(f"\n  RECORDING step {number} ({where}).")
            print("  Do the step in the program now. Press Enter here as soon as you have")
            print("  finished (or type  q  to stop the whole session after this step).")
            stop_after = False
            interrupted = None
            try:
                done = _session_ask("  > ").lower()
                stop_after = done.startswith("q")
            except _StopSession as exc:
                interrupted = f"ended early ({exc}) during step {number}"
            except _Hangup:
                interrupted = f"ended early (window closed or stop signal) during step {number}"
            finally:
                entry["end_epoch"] = time.time()
                if recorder is not None and recording:
                    entry["files_full"] = [os.path.basename(p) for p in recorder.stop()]
                    recording = False
            entry["files_xrite"] = []
            entry["check"] = []
            for name in entry.get("files_full", []):
                src = os.path.join(full_dir, name)
                check = check_capture(src)
                entry["check"].append(f"{name}: {check['xrite_packets']} instrument packets; "
                                      f"{check['verdict']}")
                if check["xrite_packets"] and check["code"] in ("ok", "all-zero"):
                    dst_name = name.replace("-full.pcap", "-instrument.pcap")
                    if filter_xrite_capture(src, os.path.join(folder, dst_name)):
                        entry["files_xrite"].append(dst_name)
            session["steps"].append(entry)
            _write_session(session, folder)
            if recorder is not None:
                if entry["files_xrite"]:
                    print(f"  Recording stopped. Step {number} is saved "
                          f"({', '.join(entry['files_xrite'])}).")
                else:
                    print("  Recording stopped, but no instrument traffic was found in this")
                    print("  step. Was the program talking to the instrument? You can")
                    print("  record the step again.")
            if interrupted:
                # Keep what was recorded, ask nothing more, end the session.
                entry["interrupted"] = True
                _write_session(session, folder)
                session["ended"] = interrupted
                break
            entry["notes"] = _session_ask(
                "\n  In one line: what did you do, and what did the program show?\n"
                "  (for example: \"strip A, accepted\", or \"refused: too fast\")\n  > ")
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
        for sig, handler in old_handlers.items():
            try:
                signal.signal(sig, handler)
            except (ValueError, OSError):
                pass
        _write_session(session, folder)
    return session


def finish_session(session: dict, folder: str) -> tuple:
    """After the steps: summary lines, analysis file, offer to delete the full files."""
    full_dir = folder + "-FULL-do-not-send"
    whole = os.path.join(folder, "whole-session.pcapng")
    if session.get("recorder") == "time marks only" and os.path.exists(whole):
        # Recorded by hand with Wireshark: keep only the instrument's traffic
        # in the folder that gets sent, and move the full file out of it.
        copy = os.path.join(folder, "whole-session-instrument.pcap")
        if filter_xrite_capture(whole, copy):
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
        state = "skipped" if s.get("skipped") else (
            ", ".join(s.get("files_xrite") or [])
            or ("cut from whole-session-instrument.pcap" if s.get("cut_from_whole_recording")
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


def session_send_text(folder: str) -> str:
    return f"""\
  WHAT TO SEND (only if you want to)
  The folder  {os.path.basename(folder)}  next to this tool holds
  everything we need: the instrument-only recordings, session.json (the
  steps and your notes) and analysis.txt (the tool's own reading of it).
  Make a zip file of that folder (Windows: right-click it, then "Send to",
  then "Compressed (zipped) folder"; Mac: right-click, then "Compress").
  Please add the report too (the chromiq-io-probe text file).
  Remember: the zip contains your instrument's serial number and its
  factory calibration data.
{HANDHELD_SEND_WAYS}
  Do NOT send the folder ending in -FULL-do-not-send."""


def manual_recording_text(folder: str) -> str:
    return f"""\
  RECORDING WITH WIRESHARK BY HAND
  This tool could not start the recording itself, but you can record the
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


def instrument_session_step(pids: list, direct: bool) -> dict:
    """The i1Pro / ColorMunki recording, from start to end, any platform.

    Returns what happened, for the closing words: {"profile", "recorded",
    "help"} (1.5.1). "help" holds the texts to repeat at the very end when
    nothing could be recorded, so they are the last thing on the screen
    instead of being buried above "ALL DONE"."""
    outcome = {"profile": None, "recorded": False, "help": [], "reason": ""}
    system = platform.system()
    default = choose_profile(pids)
    print("\n" + "=" * 68)
    print("  RECORDING WHAT THE MEASURING PROGRAM SAYS TO YOUR INSTRUMENT")
    print("=" * 68)
    try:
        profile = _ask_profile(default)
    except _StopSession:
        section("Instrument recording session", "[ended before it started]")
        return outcome
    outcome["profile"] = profile
    print("\n  WHAT THIS IS FOR")
    print(PROFILE_PURPOSE[profile])
    print()
    print(PROMISE_TEXT)
    steps = steps_for(profile)
    print(f"\n  WHAT YOU WILL DO ({len(steps)} short steps, about 15 minutes)")
    for i, s in enumerate(steps, 1):
        print(f"    {i}. {s['title']}")
    print("  Each step is recorded into its own small file. You can skip or repeat")
    print("  any step and stop at any time; the steps you finished are kept.")
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
                    + "\n\n" + "\n\n".join(outcome["help"]))
            return outcome
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
            print(recording_not_possible_text(readiness, device="instrument"))
            print("\n  The vendor programs (i1Profiler, ccStudio, the ColorMunki and")
            print("  i1Studio programs) run on Windows and on the Mac, so the Windows")
            print("  route above works with the same instrument.")
            section("Instrument recording session",
                    "[not possible on this Mac: " + " ".join(readiness["reasons"]) + "]")
            return outcome
    else:
        ifaces = linux_usbmon_interfaces()
        context = {"usbmon": ifaces}
        if ifaces and shutil.which("tcpdump"):
            print(f"  usbmon interfaces: {', '.join(ifaces)}. The tool records on all of them.")
            print("  (The vendor programs do not run on Linux itself; this works when they")
            print("  run in a virtual machine that the instrument is passed through to.)")
            recorder = TcpdumpRecorder(ifaces, "", mac=False)
        else:
            print("  No usbmon interfaces. Load them first with   sudo modprobe usbmon")
            print("  (and make sure tcpdump is installed), then run the tool again.")
            section("Instrument recording session", "[usbmon not loaded or tcpdump missing]")
            return outcome
    if not said_yes(ask("\n  Start the session now? (yes / no): ")):
        print("\n  No problem at all. Nothing was recorded.\n")
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
    session = run_instrument_session(recorder, folder, profile, program, version, context)
    if manual:
        print("\n  Now stop Wireshark and save the recording into the folder")
        print(f"  {os.path.basename(folder)}  as  whole-session.pcapng  (File, then Save As).")
        ask("  Press Enter when it is saved (or if you did not save it): ")
    print("\n" + "-" * 68)
    lines, analysis = finish_session(session, folder)
    print("\n" + "\n".join("  " + l for l in lines))
    if analysis:
        verdict = analysis.split("DOES THIS RECORDING HOLD WHAT WE NEED?")[-1]
        print("\n  DOES THIS RECORDING HOLD WHAT WE NEED?" + verdict.replace("\n", "\n  "))
    outcome["recorded"] = bool(any(s.get("files_xrite") for s in session["steps"]) or manual)
    if outcome["recorded"]:
        print()
        print(session_send_text(folder))
    if system == "Darwin":
        print()
        print(SIP_OFF_REMINDER)
    body = "\n".join(lines)
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
    text = summarize_captures(paths)
    try:
        steps, devinfo, _checks, _s = session_steps(paths)
    except Exception:                                     # noqa: BLE001
        return text
    if is_instrument_traffic(devinfo, steps):
        return text + "\n\n" + summarize_session(paths)
    return text


def main(argv: list | None = None) -> int:
    global REDACT

    parser = argparse.ArgumentParser(
        description="Collect information about X-Rite instruments (i1iO, i1Pro family, "
                    "ColorMunki / i1Studio) for ChromIQ, and optionally record what the "
                    "vendor program says to them. Never sends anything to the device and "
                    "never changes a system setting."
    )
    parser.add_argument("--annotate", "--record", action="store_true", dest="annotate",
                        help="go straight to the recording step (stage 2)")
    parser.add_argument("--i1pro", "--instrument", action="store_true", dest="instrument",
                        help="the guided recording session for a handheld instrument "
                             "(i1Pro, i1Pro 2, i1Pro 3, ColorMunki, i1Studio)")
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
    parser.add_argument("-o", "--output", default=None, help="output file path")
    parser.add_argument("--pause", action="store_true",
                        help='always end with "Press Enter to close this window."')
    parser.add_argument("--selftest", default="", help=argparse.SUPPRESS)
    parser.add_argument("--relaunched", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--no-pause", action="store_true",
                        help="never wait for Enter at the end (the launchers use this; "
                             "piped or redirected runs never wait anyway)")
    args = parser.parse_args(argv)
    REDACT = not args.no_redact
    _RUN.clear()
    _RUN.update(output=args.output, no_redact=args.no_redact, relaunched=args.relaunched,
                no_pause=args.no_pause)
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
                                    2: "2: record a handheld instrument",
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
            print("  No handheld instrument is plugged in right now. You can still go")
            print("  through the start of the session: it shows what this computer offers")
            print("  for a recording and says what is missing. For the recording itself,")
            print("  the instrument has to be plugged in.")
        outcome = instrument_session_step(ids, direct=True)
        return finish_report(args, system, instrument=True, outcome=outcome)

    print("-" * 68)
    print("STEP 3 of 3: three quick questions about your i1iO table")
    print("-" * 68)
    if IO_ID not in here:
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
    other = [k for k in here if k != IO_ID and k not in PROFILE_IDS]
    choice = 1 if IO_ID in here else 2 if hand else 3
    return {"choice": choice, "io": IO_ID in here, "hand": hand, "other": other,
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
              "    2. record a handheld instrument" + mark[2],
              "       (the i1Pro family, the ColorMunki, the i1Studio)",
              "    3. nothing more: just make the report" + mark[3],
              "    a. look again (after plugging something in)"]
    return lines


def choose_what_to_do(args, summary: str) -> tuple:
    """(choice, summary). The command line options decide without asking."""
    if args.instrument:
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
        return ["  Send it together with the session folder, as described above.",
                "  In the report the serial numbers are scrambled; in the zip's",
                "  recordings they cannot be, as said above.", "", HANDHELD_SEND_WAYS]
    lines = ["  NOTHING WAS RECORDED THIS TIME",
             "  " + (outcome.get("reason") or "No step of the session was recorded."),
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
    if system == "Darwin" and _READINESS.get("sip") in ("off", "partly"):
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
        print("  That's everything. Thank you for helping: this is the single")
        print("  thing standing between the project and i1iO support.")
    print()
    return 0


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
    if _RUN.get("output"):
        extra += f' -o "{_RUN["output"]}"'
    if _RUN.get("no_redact"):
        extra += " --no-redact"
    if SELFTEST:
        extra += f" --selftest {','.join(sorted(SELFTEST))}"
    if getattr(sys, "frozen", False):
        return sys.executable, "--i1pro" + extra, os.getcwd()
    script = os.path.abspath(__file__)
    return sys.executable, f'"{script}" --i1pro' + extra, os.getcwd()


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
    if "no_instrument" in causes:
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
    if pause:
        wait_for_enter()
    return code


if __name__ == "__main__":
    sys.exit(console_main())
