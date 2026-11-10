#!/usr/bin/env python3
"""
chromiq_io_probe.py: X-Rite i1iO information collector for ChromIQ issue #129.

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

    Both produce a file named chromiq-io-probe-<timestamp>.txt next to the
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

PROBE_VERSION = "1.4"

ISSUE_URL = "https://github.com/itsab1989/ChromIQ/issues/129"

# X-Rite USB vendor ID, and the product IDs we have real evidence for.
#
# Only IDs that a real report has shown are named here. 1.3 called 0x2001
# "i1Pro 2 / i1Pro 3 family", but a volunteer's i1Pro 2 reported 0x2000, so
# that guess was wrong and has been removed. Anything not listed is reported
# as "unknown" rather than guessed.
XRITE_VID = 0x0971
KNOWN_PIDS = {
    0x2000: 'i1Pro family, reports itself as "eye-one" (seen from an i1Pro 2)',
    0x2004: 'i1iO table, reports itself as "Eye-One iO" (seen from an i1iO 2)',
    0x2007: "ColorMunki",
}


def pid_label(pid) -> str:
    if pid is None:
        return "unknown X-Rite device"
    return KNOWN_PIDS.get(pid, "unknown X-Rite device (not in this tool's list yet)")


REDACT = True
_SECTIONS: list = []

# How long to wait after starting the recorders before checking they are
# alive. A module constant so the tests can shorten it.
RECORDER_STARTUP_WAIT = 2.0


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def run(cmd: list, timeout: int = 40) -> str:
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
        xrite = [d for d in devices if d["vid"] == XRITE_VID]
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
            lines.append(f"  {dev['name']}   {XRITE_VID:04x}:{pid_txt}   {pid_label(pid)}")
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
        if _to_int(node["props"].get("idVendor")) != XRITE_VID:
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


def recording_not_possible_text(r: dict) -> str:
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
     Connect the table to that PC, install the free program Wireshark
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
     table and records what passes through. It changes nothing on the
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
            run(["lsusb", "-v", "-d", f"{XRITE_VID:04x}:"], timeout=60))
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
        return run([ps, "-NoProfile", "-NonInteractive", "-Command", script], timeout=60)

    section("Windows: X-Rite USB devices", psrun(
        "Get-PnpDevice | Where-Object { $_.InstanceId -like '*VID_0971*' } | "
        "Format-List FriendlyName,InstanceId,Status,Class,Present"
    ))
    section("Windows: device properties (hardware + driver)", psrun(
        "Get-PnpDevice | Where-Object { $_.InstanceId -like '*VID_0971*' } | "
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
            "are willing, run it, select the i1iO, and paste its report too.")


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
            is_io = "io" in low
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
                if f"{XRITE_VID:04x}:" in line.lower():
                    found.append(line.strip())
        elif system == "Windows":
            ps = shutil.which("powershell") or shutil.which("pwsh")
            if ps:
                out = run([ps, "-NoProfile", "-Command",
                           "Get-PnpDevice | Where-Object { $_.InstanceId -like '*VID_0971*' } "
                           "| ForEach-Object { $_.FriendlyName + ' :: ' + $_.InstanceId }"])
                found = [l.strip() for l in out.splitlines()
                         if l.strip() and not l.startswith("[")]
    except Exception as exc:                              # noqa: BLE001
        return f"[summary failed: {exc}]"

    if not found:
        return ("NO X-RITE DEVICES SEEN.\n"
                "Please check the table is powered on and plugged in, then run again.")
    return "X-Rite devices detected:\n  " + "\n  ".join(found)


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
            subprocess.call([sudo, "-n", "true"], stdout=subprocess.DEVNULL,
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
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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
        elif btype == 6 and len(body) >= 20:
            _ifid, ts_hi, ts_lo, cap = struct.unpack(endian + "IIII", body[:16])
            ts = ((ts_hi << 32) | ts_lo) / 1e6
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
    if linktype == LINKTYPE_USB_DARWIN:
        mine = [d for _ts, d in recs if _darwin_vid(d) == XRITE_VID]
        xrite = len(mine)
    else:
        mine = [d for _ts, d in recs]
        xrite = len(recs)       # other formats: no per-packet device ID here
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
    elif linktype == LINKTYPE_USB_DARWIN and not xrite:
        code, verdict = "no-xrite", ("No X-Rite traffic on this bus. That is normal for "
                                     "the buses the table is not plugged into.")
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
    return {"ok": code == "ok", "packets": len(recs), "xrite_packets": xrite,
            "linktype": linktype, "code": code, "verdict": verdict,
            "payload_bytes": payload_bytes, "nonzero_bytes": nonzero}


def filter_xrite_capture(src: str, dst: str) -> int:
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
        if _darwin_vid(blob[off + 16:rec_end]) == XRITE_VID:
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
# main
# --------------------------------------------------------------------------

def main() -> int:
    global REDACT

    parser = argparse.ArgumentParser(
        description="Collect i1iO diagnostics for ChromIQ issue #129. "
                    "Never sends anything to the device and never changes a "
                    "system setting."
    )
    parser.add_argument("--annotate", "--record", action="store_true", dest="annotate",
                        help="go straight to the recording step (stage 2)")
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
    args = parser.parse_args()
    REDACT = not args.no_redact

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
        paths = args.analyze or find_captures()
        if not paths:
            print("No recording given or found next to the tool.\n"
                  "Pass a path:\n"
                  "    --analyze path/to/recording.pcap")
            return 1
        print(summarize_captures(paths))
        return 0

    print("=" * 68)
    print("  ChromIQ: i1iO information collector " + PROBE_VERSION)
    print("=" * 68)
    print()
    print("  This only READS information your computer already has about the")
    print("  connected hardware. It never sends anything to the table, it")
    print("  cannot move the arm, and it changes no settings. It is safe to")
    print("  run at any time.")
    print()
    print("  It takes about a minute. Let's go.")
    print()
    print("-" * 68)
    print("STEP 1 of 3: looking for your i1iO")
    print("-" * 68)
    print()

    summary = quick_summary()
    print("  " + summary.replace("\n", "\n  ") + "\n")

    if summary.startswith("NO X-RITE DEVICES"):
        print("  This usually means the table is switched off, unplugged, or")
        print("  connected to a different port. You can carry on anyway (the")
        print("  report is still useful), but plugging it in first is better.")
        print()
        if ask("  Press Enter to continue anyway, or type q to quit: ").lower().startswith("q"):
            return 0
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

    print("-" * 68)
    print("STEP 3 of 3: three quick questions")
    print("-" * 68)
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

    body = [
        "ChromIQ i1iO probe report",
        f"Generated for {ISSUE_URL}",
        f"Redaction: {'ON (serials hashed, paths stripped)' if REDACT else 'OFF, raw values included'}",
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
        print("\n" + "!" * 68)
        print("Could not save the report anywhere. Please copy everything below")
        print("this line and paste it into the GitHub issue instead.")
        print("!" * 68 + "\n")
        print(report)
        return 1

    size_kb = os.path.getsize(out_path) / 1024
    print("\n" + "=" * 68)
    print("  ALL DONE. Thank you!")
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
    print("  Then attach it to:")
    print(f"      {ISSUE_URL}")
    print()
    print(I1PROFILER_WARNING)
    if system == "Darwin" and _READINESS.get("sip") in ("off", "partly"):
        print()
        print(SIP_OFF_REMINDER)
    print()
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


if __name__ == "__main__":
    sys.exit(main())
