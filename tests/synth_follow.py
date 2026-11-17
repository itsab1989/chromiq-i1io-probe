"""1.6.6: synthetic USBPcap recordings in which the instrument's own traffic
travels under ANOTHER device's address. Standard library only; every byte is
INVENTED.

The shape follows the facts of a tester's three i1Pro 2 sessions (Windows 11,
USBPcap attached, i1Profiler): the recording's injected device list puts the
i1Pro 2 at one address and a USB hub at another; the i1Pro 2's own commands
and data are recorded under the hub's address, and a little of the hub's own
traffic (a hub class request, its status endpoint 0x81) under the
instrument's. No real recording was copied: the counts are made up.
"""

import struct

from synth import UsbPcapWriter, XFER_BULK, XFER_INT, be16, be32

I1PRO2_EPS = [(0x82, 2), (0x84, 3), (0x03, 2), (0x85, 2), (0x01, 2)]
HUB_EPS = [(0x81, 3)]
KEYBOARD_EPS = [(0x81, 3)]
DISK_EPS = [(0x81, 2), (0x02, 2)]
BT_EPS = [(0x81, 3), (0x82, 2), (0x02, 2)]

INSTR = 4            # where the injected description puts the instrument
HUB = 9              # where the injected description puts a hub
KEYBOARD = 5
DISK = 6
BLUETOOTH = 7

KEY_MARKER = bytes([0, 0, 0x17, 0x08, 0x16, 0x17, 0, 0])      # "t e s t" as key codes
DISK_MARKER = b"DISK-SECRET-MARKER-" * 4
BT_MARKER = b"BT-SECRET-MARKER-" * 3


def describe(w, dev, vid, pid, dev_class, if_class, endpoints, config=True):
    """GET_DESCRIPTOR device (+ configuration), as USBPcapCMD injects them."""
    dd = struct.pack("<BBHBBBBHHHBBBB", 18, 1, 0x0200, dev_class, 0, 0, 64, vid, pid,
                     0x0100, 1, 2, 3, 1)
    w.control(dev, 0x80, 6, value=0x0100, length=18, reply=dd)
    if not config:
        return
    eps = b"".join(struct.pack("<BBBBHB", 7, 5, addr, kind, 64, 1) for addr, kind in endpoints)
    itf = struct.pack("<BBBBBBBBB", 9, 4, 0, 0, len(endpoints), if_class, 0, 0, 0)
    total = 9 + len(itf) + len(eps)
    cfg = struct.pack("<BBHBBBBB", 9, 2, total, 1, 1, 0, 0x80, 50) + itf + eps
    w.control(dev, 0x80, 6, value=0x0200, length=total, reply=cfg)


def instrument(w, dev=INSTR):
    describe(w, dev, 0x0971, 0x2000, 0xFF, 0xFF, I1PRO2_EPS)


def hub(w, dev=HUB, config=True):
    describe(w, dev, 0x05E3, 0x0610, 9, 9, HUB_EPS, config=config)


def keyboard(w, dev=KEYBOARD, eps=None):
    describe(w, dev, 0x046D, 0xC31C, 0, 3, eps or KEYBOARD_EPS)


def disk(w, dev=DISK, eps=None):
    describe(w, dev, 0x0781, 0x5581, 0, 8, eps or DISK_EPS)


def bluetooth(w, dev=BLUETOOTH, eps=None):
    describe(w, dev, 0x8087, 0x0026, 0xE0, 0xE0, eps or BT_EPS)


def i1pro2_work(w, dev, readings=3, ruler=True):
    """The i1Pro 2's own requests and data: a calibration and a short scan."""
    w.vendor_out(dev, 0xCA, bytes([0x1F, 0]))
    w.vendor_in(dev, 0xD9, be32(8192))
    w.vendor_out(dev, 0xC4, be32(0) + be16(256))
    w.bulk_in(dev, 0x82, bytes(range(256)))
    w.vendor_out(dev, 0xD6, be32(16))
    w.bulk_out(dev, 0x03, bytes(16))
    w.vendor_out(dev, 0xD4, be32(300) + be32(0) + be32(readings) + be16(0x0105))
    w.bulk_in(dev, 0x84, b"\x01", xfer=XFER_INT)
    for i in range(readings):
        w.tick(0.05)
        w.bulk_in(dev, 0x82, bytes([0x40 + i]) * 268)
        if ruler:
            w.bulk_in(dev, 0x85, bytes([0, 1, 3, 2]) * 16)


def hub_work(w, dev):
    """A hub's own traffic: a port status request and its status endpoint."""
    w.control(dev, 0xA3, 0, index=4, reply=b"\x03\x01\x00\x00")
    w.bulk_in(dev, 0x81, b"\x10", xfer=XFER_INT)


def keyboard_work(w, dev, ep=0x81, n=4):
    for _ in range(n):
        w.bulk_in(dev, ep, KEY_MARKER, xfer=XFER_INT)
    w.control(dev, 0x21, 0x09, value=0x0200, out=b"\x02")          # SET_REPORT (LEDs)


def disk_work(w, dev, out_ep=0x02, in_ep=0x81):
    tag = 7
    cbw = b"USBC" + struct.pack("<IIBBB", tag, len(DISK_MARKER), 0x80, 0, 10) + bytes(16)
    w.bulk_out(dev, out_ep, cbw)
    w.bulk_in(dev, in_ep, DISK_MARKER)
    w.bulk_in(dev, in_ep, b"USBS" + struct.pack("<IIB", tag, 0, 0))
    w.control(dev, 0xA1, 0xFE, reply=b"\x00")                       # GET_MAX_LUN


def bluetooth_work(w, dev):
    w.control(dev, 0x20, 0x00, out=b"\x03\x0c\x00")                  # HCI reset (class)
    w.bulk_in(dev, 0x81, b"\x0e\x04\x01\x03\x0c\x00", xfer=XFER_INT)
    w.bulk_in(dev, 0x82, BT_MARKER)
    w.bulk_out(dev, 0x02, BT_MARKER)


def swapped_step(readings=3, others=True, hub_back=True):
    """THE tester's case: description at INSTR, own traffic under HUB's
    address, the hub's own traffic under INSTR's (hub_back; in most of his
    steps there was none of it, in one there was)."""
    w = UsbPcapWriter()
    instrument(w)
    hub(w)
    if others:
        keyboard(w)
        disk(w)
        bluetooth(w)
    i1pro2_work(w, HUB, readings)
    if hub_back:
        hub_work(w, INSTR)
    if others:
        keyboard_work(w, KEYBOARD)
        disk_work(w, DISK)
        bluetooth_work(w, BLUETOOTH)
    return w


def description_only_step():
    """Only the injected descriptions (and the other devices' traffic)."""
    w = UsbPcapWriter()
    instrument(w)
    hub(w)
    keyboard(w)
    keyboard_work(w, KEYBOARD)
    return w


def replugged_step():
    """1.6.6 (f): the instrument is unplugged and plugged in again during a
    step. Windows sets it up afresh (at address 0, then SET_ADDRESS 7) and
    the recording sees that; its old address 3 is then given to a USB disk
    that is plugged in afterwards."""
    w = UsbPcapWriter()
    describe(w, 3, 0x0971, 0x2000, 0xFF, 0xFF, I1PRO2_EPS)
    keyboard(w)
    i1pro2_work(w, 3, readings=2)
    keyboard_work(w, KEYBOARD)
    w.tick(2.0)                                   # unplugged here, plugged in again
    dd = struct.pack("<BBHBBBBHHHBBBB", 18, 1, 0x0200, 0xFF, 0, 0, 64, 0x0971, 0x2000,
                     0x0100, 1, 2, 3, 1)
    w.control(0, 0x80, 6, value=0x0100, length=64, reply=dd)
    w.control(0, 0x00, 5, value=7)                # SET_ADDRESS 7
    describe(w, 7, 0x0971, 0x2000, 0xFF, 0xFF, I1PRO2_EPS)
    i1pro2_work(w, 7, readings=2)
    w.tick(1.0)                                   # a USB stick plugged in: gets address 3
    w.control(0, 0x00, 5, value=3)
    disk(w, 3)
    disk_work(w, 3)
    i1pro2_work(w, 7, readings=1)
    return w
