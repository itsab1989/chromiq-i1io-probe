"""Synthetic USB recordings for the tests. Standard library only.

Everything here is INVENTED from the request formats ArgyllCMS documents
(see the comments in chromiq_io_probe.py). Nothing was recorded from a real
instrument, and the "ruler" traffic on endpoint 0x85 of the i1Pro 2 is pure
invention: it exists to prove that the analyser finds data where the open
driver never looks, not to claim that the real instrument sends it there.

The Windows (USBPcap) layout follows the USBPcap documentation: a 27-byte
header (28 for control transfers, with the stage byte), a setup record for
each control request, data and completion records with the "info" bit set
when travelling back to the host.
"""

import struct

XFER_ISO, XFER_INT, XFER_CTRL, XFER_BULK = 0, 1, 2, 3


class UsbPcapWriter:
    """Builds a USBPcap (link type 249) recording, one record at a time."""

    def __init__(self, t0=1_800_000_000.0, bus=1):
        self.t = t0
        self.bus = bus
        self.irp = 0x1000
        self.records = []           # (ts, bytes)

    def tick(self, seconds=0.001):
        self.t += seconds

    def _rec(self, irp, dev, ep, xfer, info, data, stage=None):
        hlen = 28 if xfer == XFER_CTRL else 27
        hdr = struct.pack("<HQIHBHHBBI", hlen, irp, 0, 0, info, self.bus, dev, ep, xfer,
                          len(data))
        if xfer == XFER_CTRL:
            hdr += bytes([stage])
        self.records.append((self.t, hdr + bytes(data)))

    def control(self, dev, rt, req, value=0, index=0, out=b"", length=None, reply=b""):
        self.irp += 1
        wlen = len(out) if not rt & 0x80 else (length if length is not None else len(reply))
        setup = struct.pack("<BBHHH", rt, req, value, index, wlen)
        ep = 0x80 if rt & 0x80 else 0x00
        self._rec(self.irp, dev, ep, XFER_CTRL, 0, setup, stage=0)
        if out:
            self._rec(self.irp, dev, ep, XFER_CTRL, 0, out, stage=1)
        self.tick(0.0005)
        if rt & 0x80:
            self._rec(self.irp, dev, ep, XFER_CTRL, 1, reply, stage=1)
        self._rec(self.irp, dev, ep, XFER_CTRL, 1, b"", stage=3)
        self.tick(0.0005)

    def vendor_out(self, dev, req, out=b"", value=0):
        self.control(dev, 0x40, req, value=value, out=out)

    def vendor_in(self, dev, req, reply):
        self.control(dev, 0xC0, req, reply=reply)

    def bulk_in(self, dev, ep, data, xfer=XFER_BULK):
        self.irp += 1
        self._rec(self.irp, dev, ep, xfer, 0, b"")
        self.tick(0.0002)
        self._rec(self.irp, dev, ep, xfer, 1, data)
        self.tick(0.0002)

    def bulk_out(self, dev, ep, data):
        self.irp += 1
        self._rec(self.irp, dev, ep, XFER_BULK, 0, data)
        self.tick(0.0002)
        self._rec(self.irp, dev, ep, XFER_BULK, 1, b"")
        self.tick(0.0002)

    def describe(self, dev, vid, pid, endpoints):
        """GET_DESCRIPTOR device + configuration, as USBPcap injects them."""
        dd = struct.pack("<BBHBBBBHHHBBBB", 18, 1, 0x0200, 0xFF, 0, 0, 64, vid, pid,
                         0x0100, 1, 2, 3, 1)
        self.control(dev, 0x80, 6, value=0x0100, length=18, reply=dd)
        eps = b"".join(struct.pack("<BBBBHB", 7, 5, addr, kind, 64, 1)
                       for addr, kind in endpoints)
        itf = struct.pack("<BBBBBBBBB", 9, 4, 0, 0, len(endpoints), 0xFF, 0, 0, 0)
        total = 9 + len(itf) + len(eps)
        cfg = struct.pack("<BBHBBBBB", 9, 2, total, 1, 1, 0, 0x80, 50) + itf + eps
        self.control(dev, 0x80, 6, value=0x0200, length=total, reply=cfg)

    def pcap(self, linktype=249):
        out = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, linktype)]
        for ts, data in self.records:
            sec = int(ts)
            usec = int(round((ts - sec) * 1e6))
            out.append(struct.pack("<IIII", sec, usec, len(data), len(data)))
            out.append(data)
        return b"".join(out)

    def save(self, path):
        with open(path, "wb") as fh:
            fh.write(self.pcap())
        return path


def be32(v):
    return struct.pack(">I", v)


def be16(v):
    return struct.pack(">H", v)


def le32(v):
    return struct.pack("<I", v)


I1PRO = 3          # device address of the instrument in these recordings
KEYBOARD = 5       # another device on the same root hub

# i1Pro 2: 0x82 bulk IN, 0x84 interrupt IN, 0x03 bulk OUT, 0x85 bulk IN
I1PRO2_ENDPOINTS = [(0x82, 2), (0x84, 3), (0x03, 2), (0x85, 2)]
READING = 268      # 134 values of 2 bytes

# An i1Pro 2 light sequence in the documented format: one block, repeated
# 3 times, green both sides for 0x0d00 clocks then off for 0x0d00 clocks.
LED_GREEN_BLINK = (be32(1) + be32(4 + 6) + be32(3) + bytes([0x12]) + be16(0x0d00)
                   + bytes([0x00]) + be16(0x0d00))
LED_OFF = be32(1) + be32(7) + be32(1) + bytes([0x00]) + be16(0x0010)


def keyboard_noise(w, n=3):
    for _ in range(n):
        w.bulk_in(KEYBOARD, 0x81, b"\x00\x00\x04\x00\x00\x00\x00\x00", xfer=XFER_INT)


def i1pro2_trigger(w, flags, nummeas, intclocks=300, lamp=0):
    w.vendor_out(I1PRO, 0xD4, be32(intclocks) + be32(lamp) + be32(nummeas) + be16(flags))


def i1pro2_calibration(w, describe=True):
    if describe:
        w.describe(I1PRO, 0x0971, 0x2000, I1PRO2_ENDPOINTS)
    keyboard_noise(w)
    w.vendor_out(I1PRO, 0xCA, bytes([0x1F, 0]))
    w.vendor_in(I1PRO, 0xD9, be32(8192))
    w.vendor_out(I1PRO, 0xC4, be32(0) + be16(2048))
    w.bulk_in(I1PRO, 0x82, bytes(range(256)) * 8)               # "EEPROM"
    w.vendor_in(I1PRO, 0xD2, b"\x01\x02\x03\x04\x05\x06\x07\x08")
    w.vendor_in(I1PRO, 0xD5, be32(36) + be32(6) + be32(128) + be32(136))
    w.vendor_in(I1PRO, 0xC9, be16(629) + be16(0) + be16(0xFFFF) + bytes([1, 0]))
    w.vendor_out(I1PRO, 0xD6, be32(len(LED_GREEN_BLINK)))
    w.bulk_out(I1PRO, 0x03, LED_GREEN_BLINK)
    w.tick(0.5)
    i1pro2_trigger(w, 0x0000, 4)                                   # dark
    w.bulk_in(I1PRO, 0x82, bytes([7]) * (READING * 4))
    i1pro2_trigger(w, 0x0100, 8, lamp=20)                          # white, lamp
    w.bulk_in(I1PRO, 0x82, bytes([9]) * (READING * 8))
    w.vendor_out(I1PRO, 0xD6, be32(len(LED_OFF)))
    w.bulk_out(I1PRO, 0x03, LED_OFF)


def i1pro2_scan(w, readings=200, flags=0x0101, ruler=False, chunk=64, stop_ruler=False,
                seconds=2.0):
    i1pro2_trigger(w, flags, readings)
    w.bulk_in(I1PRO, 0x84, b"\x01", xfer=XFER_INT)                 # button
    left = readings
    per = seconds / max(1, (readings + chunk - 1) // chunk)
    while left > 0:
        n = min(chunk, left)
        w.tick(per)
        w.bulk_in(I1PRO, 0x82, bytes([0x40 + (left % 50)]) * (READING * n))
        if ruler:
            # INVENTED: two-sensor position samples, one per byte (values
            # 0 to 3, one sensor changing at a time).
            gray = [0, 1, 3, 2]
            w.bulk_in(I1PRO, 0x85, bytes(gray[i % 4] for i in range(64)))
        left -= n
        keyboard_noise(w, 1)
    if stop_ruler:
        w.vendor_out(I1PRO, 0xD7, be16(0))


def i1pro2_session_files(tmpdir, os_mod):
    """One file per step, the way the guided session saves them."""
    files = {}

    def make(key, fn):
        w = UsbPcapWriter()
        w.describe(I1PRO, 0x0971, 0x2000, I1PRO2_ENDPOINTS)
        fn(w)
        files[key] = w.save(os_mod.path.join(tmpdir, f"{key}.pcap"))

    make("calibrate", lambda w: i1pro2_calibration(w, describe=False))
    make("scan-single", lambda w: i1pro2_scan(w, ruler=True, flags=0x0105, stop_ruler=True))
    make("scan-dual", lambda w: (i1pro2_scan(w, ruler=True, flags=0x0105),
                                 i1pro2_scan(w, flags=0x0201, ruler=True, stop_ruler=True)))
    make("scan-fast", lambda w: i1pro2_scan(w, readings=60, ruler=True, flags=0x0105,
                                            seconds=0.5))
    make("scan-slow", lambda w: i1pro2_scan(w, readings=600, ruler=True, flags=0x0105,
                                            seconds=6.0))
    make("noruler", lambda w: i1pro2_scan(w, flags=0x0101))
    make("unknown", lambda w: w.vendor_out(I1PRO, 0xDB, b"\xAA\xBB\xCC\xDD", value=7))
    return files


# ---- i1Pro 3 ---------------------------------------------------------------

I1PRO3_ENDPOINTS = [(0x81, 2), (0x83, 3), (0x84, 2), (0x02, 2)]


def i1pro3_scan(w, readings=100, zebra=True):
    w.describe(I1PRO, 0x0765, 0x6009, I1PRO3_ENDPOINTS)
    w.vendor_in(I1PRO, 0x20, bytes([1, 23]) + le32(5) + b"1.23x" + bytes(10))
    w.vendor_out(I1PRO, 0x3B, bytes([2, 255]))          # never sent by the open driver
    w.vendor_out(I1PRO, 0x29, le32(3))
    w.bulk_out(I1PRO, 0x02, bytes([0x0A, 0x14, 0x02]))  # two green pulses
    w.vendor_out(I1PRO, 0x22, le32(0) + le32(0x13 if zebra else 0x03))
    w.bulk_in(I1PRO, 0x83, b"\x01", xfer=XFER_INT)
    w.bulk_in(I1PRO, 0x81, bytes(564 * readings))
    if zebra:
        # 2-bit samples packed four to a byte, lowest bits first, walking
        # 0,1,3,2 like a quadrature sensor.
        gray = [0, 1, 3, 2]
        samples = [gray[(i // 3) % 4] for i in range(400)]
        packed = bytes(samples[i] | samples[i + 1] << 2 | samples[i + 2] << 4
                       | samples[i + 3] << 6 for i in range(0, 400, 4))
        w.bulk_in(I1PRO, 0x84, packed)
    w.vendor_in(I1PRO, 0x2B, le32(0))


# ---- ColorMunki ------------------------------------------------------------

MUNKI_ENDPOINTS = [(0x81, 2), (0x83, 3)]


def munki_scan(w, readings=50, describe=True):
    if describe:
        w.describe(I1PRO, 0x0971, 0x2007, MUNKI_ENDPOINTS)
    w.vendor_in(I1PRO, 0x87, bytes([1, 0]))             # dial: surface
    w.vendor_out(I1PRO, 0x92, le32(1000) + le32(0) + le32(0) + struct.pack("<i", -1)
                 + le32(0))
    w.vendor_out(I1PRO, 0x80, bytes([1, 1, 0, 0]) + le32(200) + le32(readings))
    w.bulk_in(I1PRO, 0x83, le32(1) + le32(12345), xfer=XFER_INT)
    w.bulk_in(I1PRO, 0x81, bytes(274 * readings))


# ---- 1.6: the i1iSis chart reader (0971:2006) ---------------------------------
#
# PURE INVENTION. Nobody outside X-Rite has described how i1Profiler talks to
# an i1iSis, and no recording of one exists yet. The traffic below only has to
# exercise the tool: a device that looks like a USB-to-serial chip of the FTDI
# kind (the way the i1iO table talks), text lines from the computer, answers
# with two status bytes per 64-byte packet, and a long binary transfer while
# a page is measured. The command words are made up and the "serial number"
# is a placeholder that the tests check never appears in the analysis text.

ISIS = 3                     # device address of the i1iSis in these recordings
DISPLAY = 4                  # an i1Display Pro (0765:5020) on the same hub
ISIS_ENDPOINTS = [(0x81, 2), (0x02, 2)]
ISIS_FAKE_SERIAL = b"SERIAL-INVENTED-4711"


def ftdi_in(data, status=b"\x01\x60"):
    """Data as an FTDI chip returns it: 2 status bytes per 64-byte packet."""
    if not data:
        return status
    return b"".join(status + data[i:i + 62] for i in range(0, len(data), 62))


def isis_open(w, describe=True):
    if describe:
        w.describe(ISIS, 0x0971, 0x2006, ISIS_ENDPOINTS)
    for value in (0, 1, 2):
        w.vendor_out(ISIS, 0x00, value=value)          # "reset"
    w.vendor_out(ISIS, 0x03, value=0x001A)             # "set baud rate"
    w.vendor_out(ISIS, 0x04, value=0x0008)             # "set data format"
    w.bulk_out(ISIS, 0x02, b"INVENTED-HELLO\r")
    w.bulk_in(ISIS, 0x81, ftdi_in(b"OK " + ISIS_FAKE_SERIAL + b"\r"))


def isis_ready(w):
    w.bulk_out(ISIS, 0x02, b"INVENTED-CALIBRATE\r")
    w.tick(1.0)
    w.bulk_in(ISIS, 0x81, ftdi_in(b"OK\r"))
    w.bulk_out(ISIS, 0x02, b"INVENTED-WAIT-FOR-PAGE\r")
    w.bulk_in(ISIS, 0x81, ftdi_in(b""))


def isis_page(w, passes=1):
    w.bulk_out(ISIS, 0x02, b"INVENTED-SCAN-PAGE\r")
    for _ in range(passes):
        for _row in range(10):
            w.tick(0.5)
            w.bulk_in(ISIS, 0x81, ftdi_in(bytes(range(256)) * 2))
    w.bulk_out(ISIS, 0x02, b"INVENTED-EJECT\r")
    w.bulk_in(ISIS, 0x81, ftdi_in(b"DONE\r"))


def isis_blank(w):
    w.bulk_out(ISIS, 0x02, b"INVENTED-SCAN-PAGE\r")
    w.tick(2.0)
    w.bulk_in(ISIS, 0x81, ftdi_in(b"ERR MARKS\r"))


def display_noise(w, describe=True):
    """An i1Display Pro on the same hub, as an i1iSis owner may have it."""
    if describe:
        w.describe(DISPLAY, 0x0765, 0x5020, [(0x81, 3), (0x01, 3)])
    w.bulk_in(DISPLAY, 0x81, b"\x00" * 8 + b"DISPLAYSERIAL99", xfer=XFER_INT)


def isis_session_files(tmpdir, os_mod, with_display=True):
    """One file per i1iSis step key, the way the guided session saves them,
    each with a keyboard (and an i1Display) on the same hub."""
    files = {}

    def make(key, fn):
        w = UsbPcapWriter()
        w.describe(ISIS, 0x0971, 0x2006, ISIS_ENDPOINTS)
        if with_display:
            display_noise(w)
        keyboard_noise(w)
        fn(w)
        keyboard_noise(w)
        files[key] = w.save(os_mod.path.join(tmpdir, f"{key}.pcap"))

    make("idle", lambda w: isis_open(w, describe=False))
    make("ready", isis_ready)
    make("page-single", isis_page)
    make("page-dual", lambda w: isis_page(w, passes=2))
    make("page-skewed", isis_page)
    make("blank-page", isis_blank)
    return files
