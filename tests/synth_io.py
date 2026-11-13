"""Synthetic i1iO table recordings for the tests. Standard library only.

Everything here is INVENTED. It reproduces the STRUCTURE of the first real
i1iO recordings (issue #129), never a byte of them: the serial number, the
table memory and every coordinate below are made up. The structure:

  * macOS (Darwin, link type 266): a 40-byte header per record; data going
    TO the device travels in the COMPLETION record (a bulk OUT submit has
    the length but no bytes; a control OUT submit has only its 8-byte
    setup), data coming FROM the device also in the completion.
  * The table is an FTDI USB-to-serial chip: every 64-byte USB packet it
    sends starts with 2 status bytes; while nothing is waiting it sends just
    those 2 bytes.
  * Lines end with CR. Host: ';' id args checksum; table: ':!' id checksum
    (accepted), then ':$' id status data checksum (done). Checksum: two's
    complement of the byte sum of everything before it, as 2 hex digits
    (lower case from the host, upper case from the table).
"""

import struct

TABLE, PRO = 7, 8                     # device addresses in these recordings
VID, TABLE_PID, PRO_PID = 0x0971, 0x2004, 0x2000
FAKE_SERIAL = 0x00DEC0DE              # invented, little-endian in the memory


def cks(body, upper=False):
    c = f"{(-sum(body.encode('latin-1'))) & 0xFF:02x}"
    return c.upper() if upper else c


def host(body):
    return body + cks(body)


def table(body):
    return body + cks(body, upper=True)


def ftdi_packets(data, status=b"\x11\x60"):
    """Data as the FTDI chip sends it: 62 data bytes per 64-byte packet."""
    if not data:
        return status
    return b"".join(status + data[i:i + 62] for i in range(0, len(data), 62))


def table_memory():
    """An invented 360-byte table memory block starting at 0x6000."""
    mem = bytearray(360)
    struct.pack_into("<I", mem, 0, 360)
    mem[4:8] = b"V1.1"
    struct.pack_into("<I", mem, 0x4C, FAKE_SERIAL)
    for i in range(36):
        struct.pack_into("<f", mem, 0x58 + 4 * i, 0.7 + i / 200)
    return bytes(mem)


class DarwinWriter:
    """Builds a macOS USB recording (link type 266), one record at a time."""

    def __init__(self, t0=1_800_000_000.0):
        self.t = t0
        self.seq = 0x100
        self.records = []

    def tick(self, seconds=0.001):
        self.t += seconds

    def _rec(self, direction, seq, dev, ep, etype, vid, pid, payload, dlen):
        hdr = bytearray(40)
        hdr[2] = 40
        hdr[3] = direction
        struct.pack_into("<I", hdr, 4, dlen)
        struct.pack_into("<I", hdr, 0x10, seq)
        hdr[29], hdr[30], hdr[31] = dev, ep, etype
        struct.pack_into("<HH", hdr, 0x24, vid, pid)
        self.records.append((self.t, bytes(hdr) + bytes(payload)))

    def control(self, dev, pid, rt, req, value=0, index=0, out=b"", reply=b"", length=None):
        self.seq += 1
        wlen = len(out) if not rt & 0x80 else (length if length is not None else len(reply))
        setup = struct.pack("<BBHHH", rt, req, value, index, wlen)
        ep = 0x80 if rt & 0x80 else 0x00
        self._rec(0, self.seq, dev, ep, 0, VID, pid, setup, wlen)
        self.tick(0.0005)
        body = reply if rt & 0x80 else out
        self._rec(1, self.seq, dev, ep, 0, VID, pid, body, len(body))
        self.tick(0.0005)

    def bulk_out(self, dev, pid, ep, data, data_in_submit=False, complete=True):
        self.seq += 1
        self._rec(0, self.seq, dev, ep, 2, VID, pid, data if data_in_submit else b"",
                  len(data))
        self.tick(0.0002)
        if complete:
            self._rec(1, self.seq, dev, ep, 2, VID, pid,
                      b"" if data_in_submit else data, 0 if data_in_submit else len(data))
            self.tick(0.0002)

    def bulk_in(self, dev, pid, ep, data, etype=2):
        self.seq += 1
        self._rec(0, self.seq, dev, ep, etype, VID, pid, b"", 131072)
        self.tick(0.0002)
        self._rec(1, self.seq, dev, ep, etype, VID, pid, data, len(data))
        self.tick(0.0002)

    # ---- the table -------------------------------------------------------

    def send(self, body, *replies, wait=0.016):
        """One command to the table and its two answers in one transfer."""
        self.bulk_out(TABLE, TABLE_PID, 0x02, (host(body) + "\r").encode())
        self.bulk_in(TABLE, TABLE_PID, 0x81, ftdi_packets(b""))      # status only
        self.tick(wait)
        text = "".join(table(r) + "\r" for r in replies)
        self.bulk_in(TABLE, TABLE_PID, 0x81, ftdi_packets(text.encode()))

    def simple(self, cid, args="", data="", status="0"):
        self.send(f";{cid}{args}", f":!{cid}", f":${cid}{status}{data}")

    def open_table(self):
        for val in (0, 1, 2):
            self.control(TABLE, TABLE_PID, 0x40, 0x00, value=val)
        self.control(TABLE, TABLE_PID, 0x40, 0x03, value=0x0034)
        self.control(TABLE, TABLE_PID, 0x40, 0x04, value=0x0008)
        self.simple("a1", data="005D010702")
        mem = table_memory().hex().upper()
        self.simple("u8", "000060000100", mem[:512])
        self.simple("u8", "000061000068", mem[512:])
        self.simple("s0")

    def move(self, cid, x, y, speed, seconds=0.5):
        args = f"{x & 0xFFFF:04x}{y & 0xFFFF:04x}{speed:04x}"
        self.send(f";{cid}{args}", f":!{cid}", f":${cid}0", wait=seconds)

    def position(self, cid, x, y):
        self.simple(cid, data=f"{x & 0xFFFF:04X}{y & 0xFFFF:04X}")

    # ---- the i1Pro on the arm ---------------------------------------------

    def button(self):
        self.bulk_in(PRO, PRO_PID, 0x84, b"\x06", etype=3)

    def trigger(self, readings=5, lamp=0, flags=0x0000):
        out = struct.pack(">IIIH", 139, lamp, readings, flags)
        self.control(PRO, PRO_PID, 0x40, 0xD4, out=out)
        self.bulk_in(PRO, PRO_PID, 0x82, bytes([0x40]) * (268 * readings))

    def pcap(self):
        out = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 266)]
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


def table_session(w):
    """A short invented session: open, align three corners, one scan move,
    two spot moves, home. Returns the (start, end) of the 'measuring' part."""
    w.open_table()
    w.tick(1.0)
    w.move("m1", 2800, 1300, 300)
    w.simple("f3")
    w.simple("f1", data="01")
    for x, y in ((1300, 1500), (1300, 2900), (-1200, 2900)):
        w.tick(2.0)
        w.button()
        w.position("p1", x, y)
    start = w.t
    w.tick(1.0)
    w.simple("c4", data="B8")
    w.move("m0", -1200, 1500, 300)
    w.simple("d1", "016d", "016D")
    w.move("m2", 1300, 1500, 137, seconds=0.01)
    w.simple("a3", data="000002AD00000751" + "0089")
    w.simple("c3")
    w.trigger(readings=20, lamp=41, flags=0x0100)
    w.move("m0", 1300, 1500, 300, seconds=0.1)
    w.trigger(readings=1, lamp=41, flags=0x0100)
    w.move("m0", 1200, 1500, 300, seconds=0.4)
    w.trigger(readings=1, lamp=41, flags=0x0100)
    w.position("p0", 1200, 1500)
    w.send(";i1", ":!i1", ":$i10", wait=2.0)
    w.simple("f0", data="00")
    end = w.t
    return start, end


class UsbmonWriter:
    """A Linux usbmon recording (link type 189, 48-byte header): OUT data in
    the submit ('S'), IN data in the completion ('C'), per the kernel's
    usbmon documentation."""

    def __init__(self, t0=1_800_000_000.0, bus=1):
        self.t = t0
        self.bus = bus
        self.uid = 0x5000
        self.records = []

    def tick(self, seconds=0.001):
        self.t += seconds

    def _rec(self, typ, xfer, ep, dev, data, setup=b"\x00" * 8, flag_setup=b"-"):
        sec = int(self.t)
        hdr = struct.pack("<QcBBBHccqiiII8s", self.uid, typ, xfer, ep, dev, self.bus,
                          flag_setup, b"=", sec, int((self.t - sec) * 1e6), 0, len(data),
                          len(data), setup)
        self.records.append((self.t, hdr + bytes(data)))

    def control_out(self, dev, req, value=0, out=b""):
        self.uid += 1
        setup = struct.pack("<BBHHH", 0x40, req, value, 0, len(out))
        self._rec(b"S", 2, 0x00, dev, out, setup, b"\x00")
        self.tick(0.0005)
        self._rec(b"C", 2, 0x00, dev, b"")
        self.tick(0.0005)

    def bulk_out(self, dev, ep, data):
        self.uid += 1
        self._rec(b"S", 3, ep, dev, data)
        self.tick(0.0002)
        self._rec(b"C", 3, ep, dev, b"")
        self.tick(0.0002)

    def bulk_in(self, dev, ep, data):
        self.uid += 1
        self._rec(b"S", 3, ep, dev, b"")
        self.tick(0.0002)
        self._rec(b"C", 3, ep, dev, data)
        self.tick(0.0002)

    def pcap(self):
        out = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 189)]
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


def same_lines_other_format(writer, dev=TABLE):
    """The table part of a short conversation, written with a USBPcap or a
    usbmon writer (both have bulk_out(dev, ep, data) and bulk_in)."""
    lines = []
    for body, replies in ((";a1", (":!a1", ":$a10005D010702")),
                          (";m0" + f"{(-1200) & 0xFFFF:04x}05dc012c", (":!m0", ":$m00")),
                          (";p0", (":!p0", ":$p00FB5005DC"))):
        writer.bulk_out(dev, 0x02, (host(body) + "\r").encode())
        writer.bulk_in(dev, 0x81, ftdi_packets(b""))
        writer.bulk_in(dev, 0x81, ftdi_packets("".join(table(r) + "\r" for r in replies)
                                               .encode()))
        lines.append(host(body))
        lines.extend(table(r) for r in replies)
    return lines
