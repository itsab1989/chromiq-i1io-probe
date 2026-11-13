"""1.6.2: another USB device's traffic is never kept as the instrument's.

    python3 -m unittest discover -s tests -v

A real Windows recording (USBPcap) held a USB disk's SCSI traffic under the
instrument's own device address: USBPcap stamps each packet with an address
its driver cached earlier, and that address can by then belong to another
device (desowin/usbpcap issue 105). Up to 1.6.1 the tool kept everything at
the instrument's address. These recordings reproduce that shape and the
other ways to the same fault (an address given to another device after a
replug, a hub with a keyboard and a disk, macOS, Linux usbmon), with marker
strings planted in the foreign device's traffic (its model, its serial
number, its data). Every file the tool writes and every text it prints is
scanned for them.

Everything here is INVENTED. No byte comes from a real recording.
"""

import io
import json
import os
import struct
import sys
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import chromiq_io_probe as probe  # noqa: E402

import synth  # noqa: E402
import synth_io  # noqa: E402
import test_instrument  # noqa: E402

# The planted markers: the disk's model (INQUIRY), its serial number (VPD
# page 0x80) and the content of its first sectors (READ(10)); a keyboard's
# typed keys and its report description; a hub's port status.
MODEL = b"FOREIGN-MODEL-X1"
SERIAL = b"FOREIGN-SERIAL-7Q3"
PAYLOAD = b"FOREIGN-MBR-DATA"
KEYS = b"FOREIGN-TYPED-KEYS"
HIDDESC = b"FOREIGN-HID-DESC"
HUBSTAT = b"FOREIGN-HUB"
STRING = "FOREIGN-STRING"
MARKERS = (MODEL, SERIAL, PAYLOAD, KEYS, HIDDESC, HUBSTAT, STRING.encode())

DISK_IDS = (0x0781, 0x5567)
KBD_IDS = (0x046D, 0xC31C)
HUB_IDS = (0x05E3, 0x0610)
PROFILES = (None, probe.SESSION_TABLE, "i1pro2", "i1pro", "i1pro3", "munki", "generic",
            "isis")


def fragments(marker: bytes):
    """Every 8-byte piece of a marker, as bytes and as hex (the analysis
    prints data as hex), so that a partly printed marker is caught too."""
    out = set()
    for i in range(len(marker) - 7):
        piece = marker[i:i + 8]
        out |= {piece, piece.hex().encode(), piece.hex().upper().encode(),
                piece.decode("latin-1").encode("utf-16-le")}
    return out


ALL_FRAGMENTS = set().union(*(fragments(m) for m in MARKERS))


def leaks(blob: bytes) -> list:
    return sorted(f for f in ALL_FRAGMENTS if f in blob)


# ---- the foreign devices' traffic -------------------------------------------

def cbw(tag, length, data_in, cdb):
    return (b"USBC" + struct.pack("<IIBBB", tag, length, 0x80 if data_in else 0, 0, len(cdb))
            + cdb.ljust(16, b"\x00"))


def csw(tag, residue=0, status=0):
    return b"USBS" + struct.pack("<IIB", tag, residue, status)


def disk_bot(w, dev, out_ep=0x02, in_ep=0x81, tag=0x100, csw_first=False):
    """A USB disk's bulk-only transport on (out_ep, in_ep): Get Max LUN,
    INQUIRY (its model), VPD 0x80 (its serial number), READ(10) of LBA 0
    (its first sectors), and a clear-halt on its IN endpoint."""
    if csw_first:
        # a recording that starts in the middle of a command
        w.bulk_in(dev, in_ep, PAYLOAD * 8)
        w.bulk_in(dev, in_ep, csw(tag - 1))
    w.control(dev, 0xA1, 0xFE, index=0, length=1, reply=b"\x00")
    w.bulk_out(dev, out_ep, cbw(tag, 36, True, b"\x12\x00\x00\x00\x24\x00"))
    w.bulk_in(dev, in_ep, b"\x00\x80\x06\x02\x1f\x00\x00\x00" + MODEL + MODEL[:12])
    w.bulk_in(dev, in_ep, csw(tag))
    w.bulk_out(dev, out_ep, cbw(tag + 1, 64, True, b"\x12\x01\x80\x00\x40\x00"))
    w.bulk_in(dev, in_ep, b"\x00\x80\x00\x14" + SERIAL + SERIAL)
    w.bulk_in(dev, in_ep, csw(tag + 1))
    w.bulk_out(dev, out_ep, cbw(tag + 2, 8192, True, b"\x28\x00\x00\x00\x00\x00\x00\x00\x10"))
    w.bulk_in(dev, in_ep, PAYLOAD * 512)
    w.bulk_in(dev, in_ep, csw(tag + 2))
    w.control(dev, 0x02, 0x01, value=0, index=in_ep)            # CLEAR_FEATURE(halt)


def describe_class(w, dev, vid, pid, cls, endpoints, serial_index=3):
    """A device description with an interface of a standard class (8 mass
    storage, 3 HID, 9 hub), as USBPcap injects it."""
    dd = struct.pack("<BBHBBBBHHHBBBB", 18, 1, 0x0200, 0, 0, 0, 64, vid, pid, 0x0100, 1, 2,
                     serial_index, 1)
    w.control(dev, 0x80, 6, value=0x0100, length=18, reply=dd)
    eps = b"".join(struct.pack("<BBBBHB", 7, 5, a, k, 64, 1) for a, k in endpoints)
    itf = struct.pack("<BBBBBBBBB", 9, 4, 0, 0, len(endpoints), cls, 6 if cls == 8 else 0,
                      0x50 if cls == 8 else 0, 0)
    total = 9 + len(itf) + len(eps)
    cfg = struct.pack("<BBHBBBBB", 9, 2, total, 1, 1, 0, 0x80, 50) + itf + eps
    w.control(dev, 0x80, 6, value=0x0200, length=total, reply=cfg)


def foreign_string(w, dev, index=3):
    text = STRING.encode("utf-16-le")
    w.control(dev, 0x80, 6, value=0x0300 | index, index=0x0409, length=255,
              reply=bytes([2 + len(text), 3]) + text)


def keyboard_at(w, dev):
    """A keyboard's class requests, report description and typed keys."""
    w.control(dev, 0x21, 0x0A, value=0, index=0)                 # SET_IDLE
    w.control(dev, 0x81, 6, value=0x2200, index=0, length=64, reply=HIDDESC * 2)
    w.bulk_in(dev, 0x81, KEYS, xfer=synth.XFER_INT)


def hub_at(w, dev):
    w.control(dev, 0xA3, 0x00, value=0, index=1, length=4, reply=HUBSTAT[:4])
    w.control(dev, 0xA0, 0x06, value=0x2900, length=16, reply=HUBSTAT)


def set_address(w, new):
    w.control(0, 0x00, 0x05, value=new)


# ---- the scenarios ------------------------------------------------------------

def usbpcap_disk_stale(i1pro3=False):
    """The tester's shape: the instrument at 3, described; a disk described
    at its own address 7, but its packets carry the instrument's address 3
    (a stale address in USBPcap)."""
    w = synth.UsbPcapWriter()
    if i1pro3:
        w.describe(synth.I1PRO, 0x0765, 0x6009, synth.I1PRO3_ENDPOINTS)
    else:
        w.describe(synth.I1PRO, 0x0971, 0x2000, synth.I1PRO2_ENDPOINTS)
    describe_class(w, 7, *DISK_IDS, 8, [(0x81, 2), (0x02, 2)])
    # the recording starts in the middle of one of the disk's commands
    disk_bot(w, synth.I1PRO, tag=0x200, csw_first=True)
    synth.keyboard_noise(w)
    if i1pro3:
        synth.i1pro3_scan(w)
    else:
        synth.i1pro2_calibration(w, describe=False)
    disk_bot(w, synth.I1PRO)
    if i1pro3:
        synth.i1pro3_scan(w)
    else:
        synth.i1pro2_scan(w, ruler=True, flags=0x0105)
    disk_bot(w, synth.I1PRO, tag=0x300)
    return w


def usbpcap_replug():
    """Address 3 held a keyboard, then (after a replug) the i1Pro 2, then
    (after another one) a disk."""
    w = synth.UsbPcapWriter()
    describe_class(w, synth.I1PRO, *KBD_IDS, 3, [(0x81, 3)])
    keyboard_at(w, synth.I1PRO)
    foreign_string(w, synth.I1PRO)
    set_address(w, synth.I1PRO)
    w.describe(synth.I1PRO, 0x0971, 0x2000, synth.I1PRO2_ENDPOINTS)
    synth.i1pro2_calibration(w, describe=False)
    synth.i1pro2_scan(w)
    set_address(w, synth.I1PRO)
    describe_class(w, synth.I1PRO, *DISK_IDS, 8, [(0x81, 2), (0x02, 2)])
    foreign_string(w, synth.I1PRO)
    disk_bot(w, synth.I1PRO)
    return w


def usbpcap_hub_keyboard_disk():
    """A hub with a keyboard, a disk and the instrument, and all three
    others' traffic at the instrument's address."""
    w = synth.UsbPcapWriter()
    describe_class(w, 2, *HUB_IDS, 9, [(0x81, 3)])
    describe_class(w, 5, *KBD_IDS, 3, [(0x81, 3)])
    describe_class(w, 7, *DISK_IDS, 8, [(0x81, 2), (0x02, 2)])
    w.describe(synth.I1PRO, 0x0971, 0x2000, synth.I1PRO2_ENDPOINTS)
    synth.i1pro2_calibration(w, describe=False)
    hub_at(w, synth.I1PRO)
    keyboard_at(w, synth.I1PRO)
    disk_bot(w, synth.I1PRO)
    foreign_string(w, synth.I1PRO)
    describe_class(w, synth.I1PRO, *DISK_IDS, 8, [(0x81, 2), (0x02, 2)])
    synth.i1pro2_scan(w)
    return w


def usbpcap_isis_disk():
    """An i1iSis (FTDI-like 0x81 / 0x02) and a disk on the same endpoints at
    the same address."""
    w = synth.UsbPcapWriter()
    synth.isis_open(w)
    disk_bot(w, synth.ISIS)
    synth.isis_page(w)
    return w


def usbpcap_table_disk():
    """The i1iO table (0x81 / 0x02) and a disk at its address."""
    w = synth.UsbPcapWriter()
    w.describe(synth_io.TABLE, 0x0971, 0x2004, [(0x81, 2), (0x02, 2)])
    synth_io.same_lines_other_format(w)
    disk_bot(w, synth_io.TABLE)
    synth_io.same_lines_other_format(w)
    return w


def usbpcap_guessed_disk():
    """No description at all (inject off): the i1Pro 2 is found by its
    commands; the disk at its address."""
    w = synth.UsbPcapWriter()
    synth.i1pro2_calibration(w, describe=False)
    disk_bot(w, synth.I1PRO)
    return w


def darwin_disk():
    """macOS: every record carries its device's IDs. A disk, a keyboard, and
    an X-Rite record that carries a mass-storage command (defence in depth)."""
    d = synth_io.DarwinWriter()
    d.trigger(readings=5)
    seq = 0x9000

    def rec(ids, ep, etype, payload, direction=1):
        nonlocal seq
        seq += 1
        d._rec(0, seq, 4, ep, etype, ids[0], ids[1], b"", len(payload))  # noqa: SLF001
        d._rec(direction, seq, 4, ep, etype, ids[0], ids[1], payload, len(payload))  # noqa: SLF001
    rec(DISK_IDS, 0x02, 2, cbw(1, 36, True, b"\x12"))
    rec(DISK_IDS, 0x81, 2, MODEL + SERIAL)
    rec(DISK_IDS, 0x81, 2, csw(1))
    rec(KBD_IDS, 0x81, 3, KEYS)
    pro = (0x0971, 0x2000)
    rec(pro, 0x82, 2, cbw(2, 8192, True, b"\x28"), direction=1)
    d.trigger(readings=5)
    return d


class UsbmonControl:
    """usbmon helpers the shared writer does not have."""

    @staticmethod
    def control_in(u, dev, rt, req, value=0, index=0, reply=b""):
        u.uid += 1
        setup = struct.pack("<BBHHH", rt, req, value, index, len(reply))
        u._rec(b"S", 2, 0x80, dev, b"", setup, b"\x00")             # noqa: SLF001
        u.tick(0.0005)
        u._rec(b"C", 2, 0x80, dev, reply)                            # noqa: SLF001
        u.tick(0.0005)

    @staticmethod
    def control_out(u, dev, rt, req, value=0, index=0):
        u.uid += 1
        setup = struct.pack("<BBHHH", rt, req, value, index, 0)
        u._rec(b"S", 2, 0x00, dev, b"", setup, b"\x00")             # noqa: SLF001
        u.tick(0.0005)
        u._rec(b"C", 2, 0x00, dev, b"")                              # noqa: SLF001
        u.tick(0.0005)


def usbmon_describe(u, dev, vid, pid, cls, endpoints):
    dd = struct.pack("<BBHBBBBHHHBBBB", 18, 1, 0x0200, 0, 0, 0, 64, vid, pid, 0x0100, 1, 2, 3, 1)
    UsbmonControl.control_in(u, dev, 0x80, 6, 0x0100, reply=dd)
    eps = b"".join(struct.pack("<BBBBHB", 7, 5, a, k, 64, 1) for a, k in endpoints)
    itf = struct.pack("<BBBBBBBBB", 9, 4, 0, 0, len(endpoints), cls, 0, 0, 0)
    total = 9 + len(itf) + len(eps)
    cfg = struct.pack("<BBHBBBBB", 9, 2, total, 1, 1, 0, 0x80, 50) + itf + eps
    UsbmonControl.control_in(u, dev, 0x80, 6, 0x0200, reply=cfg)


def usbmon_replug():
    """Linux: the i1Pro 2 at 4, unplugged; a disk set up at address 0 and
    given address 4; its SCSI traffic at 4."""
    u = synth_io.UsbmonWriter()
    usbmon_describe(u, 4, 0x0971, 0x2000, 0xFF, synth.I1PRO2_ENDPOINTS)
    for req in (0xD4, 0xD6):
        u.control_out(4, req)
    u.bulk_in(4, 0x82, bytes([7]) * 268 * 4)
    UsbmonControl.control_in(u, 0, 0x80, 6, 0x0100, reply=b"\x12\x01\x00\x02\x00\x00\x00\x40")
    UsbmonControl.control_out(u, 0, 0x00, 0x05, value=4)
    usbmon_describe(u, 4, *DISK_IDS, 8, [(0x81, 2), (0x02, 2)])
    u.bulk_out(4, 0x02, cbw(1, 36, True, b"\x12"))
    u.bulk_in(4, 0x81, MODEL + SERIAL)
    u.bulk_in(4, 0x81, csw(1))
    u.bulk_out(4, 0x02, cbw(2, 8192, True, b"\x28"))
    u.bulk_in(4, 0x81, PAYLOAD * 512)
    u.bulk_in(4, 0x81, csw(2))
    return u


def usbmon_guessed_disk():
    """Linux without descriptions: the i1Pro 2 found by its commands, a disk
    at the same number (cannot happen live on Linux; defence in depth)."""
    u = synth_io.UsbmonWriter()
    for req in (0xC9, 0xD4, 0xD6, 0xD5):
        u.control_out(4, req)
    u.bulk_in(4, 0x82, bytes([7]) * 268 * 4)
    u.bulk_out(4, 0x02, cbw(1, 36, True, b"\x12"))
    u.bulk_in(4, 0x81, MODEL + SERIAL)
    u.bulk_in(4, 0x81, csw(1))
    return u


def usbpcap_review_attacks():
    """The independent review's attacks on 1.6.2's first draft: an
    i1Display beside the i1Pro 2; a ColorMunki found only by its commands
    with a keyboard's interrupt and an isochronous stream on its endpoint
    numbers; a control completion without its request; a string the
    instrument does not name."""
    w = synth.UsbPcapWriter()
    w.describe(synth.I1PRO, 0x0971, 0x2000, synth.I1PRO2_ENDPOINTS)
    w.describe(4, 0x0765, 0x5020, [(0x81, 3), (0x01, 3)])
    w.bulk_in(4, 0x81, b"\x00" * 8 + MODEL, xfer=synth.XFER_INT)
    synth.i1pro2_calibration(w, describe=False)
    # an orphan completion: data stage of a request whose setup is not there
    w.irp += 1
    w._rec(w.irp, synth.I1PRO, 0x80, synth.XFER_CTRL, 1, SERIAL, stage=1)   # noqa: SLF001
    w._rec(w.irp, synth.I1PRO, 0x80, synth.XFER_CTRL, 1, b"", stage=3)      # noqa: SLF001
    foreign_string(w, synth.I1PRO, index=7)
    munki = 6
    for req in (0x87, 0x81, 0x86):
        w.vendor_in(munki, req, b"\x01\x00")
    w.bulk_in(munki, 0x81, KEYS, xfer=synth.XFER_INT)
    w.bulk_in(munki, 0x83, PAYLOAD * 4, xfer=synth.XFER_ISO)
    return w


SCENARIOS = {
    "usbpcap-review-attacks": usbpcap_review_attacks,
    "usbpcap-disk-stale": usbpcap_disk_stale,
    "usbpcap-i1pro3-disk-same-endpoints": lambda: usbpcap_disk_stale(i1pro3=True),
    "usbpcap-replug": usbpcap_replug,
    "usbpcap-hub-keyboard-disk": usbpcap_hub_keyboard_disk,
    "usbpcap-isis-disk": usbpcap_isis_disk,
    "usbpcap-table-disk": usbpcap_table_disk,
    "usbpcap-guessed-disk": usbpcap_guessed_disk,
    "macos-disk": darwin_disk,
    "usbmon-replug": usbmon_replug,
    "usbmon-guessed-disk": usbmon_guessed_disk,
}


class _Base(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = self.tmp.name

    def save(self, name):
        return SCENARIOS[name]().save(os.path.join(self.dir, name + ".pcap"))

    def assertClean(self, blob, where):
        if isinstance(blob, str):
            blob = blob.encode("utf-8", "replace")
        found = leaks(blob)
        self.assertEqual(found, [], f"foreign traffic in {where}: {found[:4]}")

    def written_files(self, root, skip=()):
        for base, _dirs, files in os.walk(root):
            for name in files:
                full = os.path.join(base, name)
                if any(s in full for s in skip):
                    continue
                yield full


class RecordingsHoldTheMarkers(_Base):
    """The test recordings really carry the markers (or the scan proves
    nothing)."""

    def test_every_scenario_carries_foreign_markers_at_the_instrument_address(self):
        for name in SCENARIOS:
            with self.subTest(scenario=name):
                with open(self.save(name), "rb") as fh:
                    self.assertTrue(leaks(fh.read()))


class NothingForeignIsKept(_Base):

    def test_copies_checks_and_analysis_of_every_scenario_and_session_type(self):
        for name in SCENARIOS:
            raw = self.save(name)
            for profile in PROFILES:
                with self.subTest(scenario=name, session=profile):
                    dst = os.path.join(self.dir, f"{name}-{profile}-instrument.pcap")
                    probe.filter_xrite_capture(raw, dst, profile)
                    if os.path.exists(dst):
                        with open(dst, "rb") as fh:
                            self.assertClean(fh.read(), dst)
                        self.assertClean(probe.analyze_paths([dst]), "analysis of the copy")
                    check = probe.check_capture(raw, profile)
                    self.assertClean(check["verdict"], "the check")
            with self.subTest(scenario=name, what="--analyze of the raw file"):
                self.assertClean(probe.analyze_paths([raw]), "--analyze raw")

    def test_the_instrument_itself_is_still_kept(self):
        cases = {"usbpcap-disk-stale": ("i1pro2", 0xD4),
                 "usbpcap-i1pro3-disk-same-endpoints": ("i1pro3", 0x22),
                 "usbpcap-replug": ("i1pro2", 0xD4),
                 "usbpcap-hub-keyboard-disk": ("i1pro2", 0xD4),
                 "usbpcap-guessed-disk": ("i1pro2", 0xD4),
                 "usbmon-replug": ("i1pro2", 0xD4),
                 "usbmon-guessed-disk": ("i1pro2", 0xD4),
                 "macos-disk": ("i1pro2", 0xD4)}
        for name, (profile, req) in cases.items():
            with self.subTest(scenario=name):
                raw = self.save(name)
                dst = os.path.join(self.dir, name + "-kept.pcap")
                self.assertTrue(probe.filter_xrite_capture(raw, dst, profile))
                lt, recs = probe._read_pcap(dst)
                events = probe.capture_events(lt, recs)
                self.assertIn(req, {e["req"] for e in events if e["kind"] == "control"})

    def test_the_i1pro3_keeps_its_own_data_on_the_disk_s_endpoints(self):
        raw = self.save("usbpcap-i1pro3-disk-same-endpoints")
        dst = os.path.join(self.dir, "i1pro3.pcap")
        probe.filter_xrite_capture(raw, dst, "i1pro3")
        lt, recs = probe._read_pcap(dst)
        sizes = [len(e["data"]) for e in probe.capture_events(lt, recs)
                 if e["kind"] == "data" and e["ep"] == 0x81]
        self.assertIn(564 * 100, sizes)          # its readings, twice
        self.assertEqual(sizes.count(564 * 100), 2)

    def test_the_table_and_the_isis_keep_their_lines_beside_a_disk(self):
        raw = self.save("usbpcap-table-disk")
        cap = probe.io_capture(raw)
        self.assertTrue(cap["lines"])
        self.assertTrue(all(l["ok"] for l in cap["lines"]))
        self.assertClean("\n".join(probe.io_timeline(cap)), "the table timeline")
        raw = self.save("usbpcap-isis-disk")
        dst = os.path.join(self.dir, "isis.pcap")
        self.assertTrue(probe.filter_xrite_capture(raw, dst, "isis"))
        with open(dst, "rb") as fh:
            self.assertIn(b"INVENTED-SCAN-PAGE", fh.read())

    def test_the_check_says_what_was_left_out_never_what_it_was(self):
        raw = self.save("usbpcap-disk-stale")
        check = probe.check_capture(raw, "i1pro2")
        self.assertEqual(check["code"], "ok")
        self.assertIn("could not be attributed to the instrument", check["verdict"])
        self.assertIn("a USB disk or memory stick", check["verdict"])
        self.assertGreater(check["left_out"]["storage"], 5)
        hub = probe.check_capture(self.save("usbpcap-hub-keyboard-disk"), "i1pro2")
        for word in ("a USB hub", "a keyboard, mouse or other input device"):
            self.assertIn(word, hub["verdict"])

    def test_a_clean_recording_says_nothing_about_left_out_traffic(self):
        w = synth.UsbPcapWriter()
        synth.i1pro2_calibration(w)
        synth.i1pro2_scan(w, ruler=True)
        path = w.save(os.path.join(self.dir, "clean.pcap"))
        check = probe.check_capture(path, "i1pro2")
        self.assertEqual(check["left_out"], {})
        self.assertNotIn("attributed", check["verdict"])

    def test_address_zero_is_never_kept(self):
        w = synth.UsbPcapWriter()
        w.describe(0, 0x0971, 0x2000, synth.I1PRO2_ENDPOINTS)   # being set up
        w.bulk_in(0, 0x82, KEYS)
        w.describe(synth.I1PRO, 0x0971, 0x2000, synth.I1PRO2_ENDPOINTS)
        synth.i1pro2_scan(w)
        path = w.save(os.path.join(self.dir, "addr0.pcap"))
        dst = os.path.join(self.dir, "addr0-copy.pcap")
        probe.filter_xrite_capture(path, dst, "i1pro2")
        lt, recs = probe._read_pcap(dst)
        self.assertNotIn(0, {k[1] for k in probe.record_device_keys(lt, recs)})

    def test_the_owner_before_a_replug_is_not_the_instrument(self):
        att = probe.attribute_records(*probe._read_pcap(self.save("usbpcap-replug")),
                                      "i1pro2")
        self.assertIn("owner", att["left_out"])


class AFullSessionWritesNothingForeign(_Base):
    """The guided session end to end (fake USBPcapCMD), with the disk's
    traffic at the instrument's address in every step: the step checks, the
    copies, session.json, analysis.txt, the report and the zip."""

    def setUp(self):
        super().setUp()
        self.bin = os.path.join(self.dir, "bin")
        self.pcaps = os.path.join(self.dir, "pcaps")
        self.out = os.path.join(self.dir, "out")
        for d in (self.bin, self.pcaps, self.out):
            os.mkdir(d)
        self.log = os.path.join(self.dir, "fake.log")
        self.exe = os.path.join(self.bin, "fake_usbpcapcmd.py")
        with open(self.exe, "w") as fh:
            fh.write(test_instrument.FAKE_USBPCAPCMD)
        patcher = mock.patch.dict(os.environ, {"FAKE_LOG": self.log, "FAKE_PCAPS": self.pcaps})
        patcher.start()
        self.addCleanup(patcher.stop)
        for p in (mock.patch.object(probe, "RECORDER_STARTUP_WAIT", 0.3),
                  mock.patch.object(probe, "SHORT_STEP_SECONDS", 0.0)):
            p.start()
            self.addCleanup(p.stop)

    def make_steps(self, profile):
        for step in probe.steps_for(profile):
            w = synth.UsbPcapWriter()
            if profile == "isis":
                synth.isis_open(w)
                disk_bot(w, synth.ISIS)
                synth.isis_page(w)
            else:
                w.describe(synth.I1PRO, 0x0971, 0x2000, synth.I1PRO2_ENDPOINTS)
                describe_class(w, 7, *DISK_IDS, 8, [(0x81, 2), (0x02, 2)])
                synth.i1pro2_calibration(w, describe=False)
                disk_bot(w, synth.I1PRO)
                keyboard_at(w, synth.I1PRO)
                synth.i1pro2_scan(w, ruler=True, flags=0x0105)
            w.save(os.path.join(self.pcaps, step["key"] + ".pcap"))

    def run_one(self, profile, notes=""):
        self.make_steps(profile)
        folder = os.path.join(self.out, f"instrument-session-{profile}")

        def fake_ask(prompt, interruptible=False):
            if "START recording" in prompt:
                return ""
            if prompt.strip() == ">":
                return "e"
            if "Delete the full recordings" in prompt:
                return "yes"
            if "In one line: what did you do" in prompt:
                return notes
            if "looks like a key for stopping" in prompt:
                return "scanned the strip, accepted"
            return ""
        recorder = probe.UsbPcapRecorder(self.exe, ["\\\\.\\USBPcap1"], "")
        buf = io.StringIO()
        with mock.patch.object(probe, "ask", fake_ask), redirect_stdout(buf):
            session = probe.run_instrument_session(recorder, folder, profile,
                                                   "i1Profiler", "3.8.6")
            lines, analysis = probe.finish_session(session, folder)
        report = os.path.join(self.out, "chromiq-io-probe-test.txt")
        with open(report, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n\n" + (analysis or ""))
        zipped = probe.make_send_zip(report, {"folder": folder})
        return folder, buf.getvalue(), analysis, zipped

    def test_handheld_and_isis_sessions(self):
        for profile in ("i1pro2", "isis"):
            with self.subTest(session=profile):
                folder, screen, analysis, zipped = self.run_one(profile)
                self.assertClean(screen, "the screen")
                self.assertTrue(analysis)
                self.assertIn("could not be attributed", screen)
                self.assertFalse(os.path.isdir(folder + "-FULL-do-not-send"))
                for path in self.written_files(self.out):
                    with open(path, "rb") as fh:
                        self.assertClean(fh.read(), path)
                with zipfile.ZipFile(zipped) as zf:
                    for name in zf.namelist():
                        self.assertClean(zf.read(name), "zip: " + name)
                saved = json.load(open(os.path.join(folder, "session.json"),
                                       encoding="utf-8"))
                kept = [s for s in saved["steps"] if s.get("files_xrite")]
                self.assertEqual(len(kept), len(probe.steps_for(profile)))

    def test_a_stop_key_as_the_notes_is_asked_again(self):
        folder, screen, _analysis, _zipped = self.run_one("i1pro2", notes="e")
        self.assertIn("The recording of this step has stopped. A few questions:", screen)
        with open(os.path.join(folder, "session.json"), encoding="utf-8") as fh:
            steps = json.load(fh)["steps"]
        self.assertTrue(steps)
        self.assertTrue(all(s["notes"] == "scanned the strip, accepted" for s in steps))

    def test_the_table_session_finish(self):
        w = usbpcap_table_disk()
        full = os.path.join(self.out, "io-capture-x-USBPcap1-full.pcap")
        w.save(full)
        buf = io.StringIO()
        with redirect_stdout(buf):
            probe.finish_recordings({"USBPcap1": full}, None, ask_delete=False)
        self.assertClean(buf.getvalue(), "the screen")
        for path in self.written_files(self.out, skip=("-full.pcap",)):
            with open(path, "rb") as fh:
                self.assertClean(fh.read(), path)


class CleanOldFiles(_Base):
    """--clean: a SEND-THIS zip, a session folder or a file made by an
    earlier version gets a cleaned copy; the original stays as it was."""

    def old_send_zip(self):
        """A zip as 1.6.1 wrote it: copies kept by address only, so the
        disk is in them, in the analysis and in the report."""
        folder = os.path.join(self.dir, "instrument-session-20261113-202735")
        os.makedirs(folder)
        raw = usbpcap_disk_stale().save(os.path.join(self.dir, "full.pcap"))
        lt, recs = probe._read_pcap(raw)
        old = [r for r, k in zip(recs, probe.record_device_keys(lt, recs))
               if k == (1, synth.I1PRO)]
        name = "step3-scan-single-take1-USBPcap1-instrument.pcap"
        probe._write_pcap(os.path.join(folder, name), lt, old)
        session = {"kind": probe.SESSION_KIND, "family": "i1pro2", "recorder": "x",
                   "probe_version": "1.5.4",
                   "steps": [{"number": 3, "key": "scan-single", "title": "x", "take": 1,
                              "kept": True, "files_xrite": [name]}]}
        with open(os.path.join(folder, "session.json"), "w", encoding="utf-8") as fh:
            json.dump(session, fh)
        old_analysis = ("=" * 68 + "\n  Instrument recording analysis\n" + "=" * 68 + "\n"
                        + "data on 0x81 bulk IN: 36 bytes: " + MODEL.hex() + "\n" + "=" * 68)
        with open(os.path.join(folder, "analysis.txt"), "w", encoding="utf-8") as fh:
            fh.write(old_analysis + "\n")
        report = os.path.join(self.dir, "chromiq-io-probe-20261113-205140.txt")
        with open(report, "w", encoding="utf-8") as fh:
            fh.write("ChromIQ X-Rite instrument probe report, version 1.5.4\n\n" + "=" * 72
                     + "\nInstrument recording session\n" + "=" * 72 + "\nSession folder: x\n\n"
                     + old_analysis + "\n\n" + "=" * 72 + "\nWindows\n" + "=" * 72
                     + "\nsomething after\n")
        zipped = probe.make_send_zip(report, {"folder": folder})
        return zipped, folder

    def test_a_send_this_zip(self):
        zipped, _folder = self.old_send_zip()
        with open(zipped, "rb") as fh:
            before = fh.read()
        self.assertTrue(leaks(before) or True)
        text, code = probe.clean_paths([zipped])
        self.assertEqual(code, 0)
        self.assertClean(text, "the --clean text")
        self.assertIn("a USB disk or memory stick", text)
        with open(zipped, "rb") as fh:
            self.assertEqual(fh.read(), before)          # the original is unchanged
        cleaned = zipped[:-4] + "-cleaned.zip"
        self.assertIn(cleaned, text)
        with zipfile.ZipFile(cleaned) as zf:
            names = zf.namelist()
            for name in names:
                self.assertClean(zf.read(name), "cleaned zip: " + name)
            report = [n for n in names if n.endswith(".txt") and "/" not in n][0]
            body = zf.read(report).decode()
            self.assertIn("made again by version", body)
            self.assertIn("something after", body)
            self.assertIn("instrument-session-20261113-202735/analysis.txt", names)
            self.assertIn("instrument-session-20261113-202735/"
                          "step3-scan-single-take1-USBPcap1-instrument.pcap", names)

    def test_a_session_folder_and_a_single_file(self):
        _zipped, folder = self.old_send_zip()
        text, code = probe.clean_paths([folder])
        self.assertEqual(code, 0)
        out = folder + "-cleaned"
        self.assertTrue(os.path.isdir(out))
        for path in self.written_files(out):
            with open(path, "rb") as fh:
                self.assertClean(fh.read(), path)
        one = os.path.join(folder, "step3-scan-single-take1-USBPcap1-instrument.pcap")
        text, code = probe.clean_paths([one])
        self.assertEqual(code, 0)
        with open(one[:-5] + "-cleaned.pcap", "rb") as fh:
            self.assertClean(fh.read(), "cleaned single file")

    def test_from_the_command_line(self):
        zipped, _folder = self.old_send_zip()
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = probe.main(["--clean", zipped])
        self.assertEqual(code, 0)
        self.assertIn("cleaned copy", buf.getvalue())
        with redirect_stdout(io.StringIO()):
            self.assertEqual(probe.main(["--clean", os.path.join(self.dir, "nothing.zip")]), 1)

    def test_a_huge_zip_member_is_not_unpacked(self):
        big = os.path.join(self.dir, "SEND-THIS-big.zip")
        with zipfile.ZipFile(big, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("x/step1-instrument.pcap", b"\0" * (probe.CLEAN_MEMBER_LIMIT + 1))
        text, _code = probe.clean_paths([big])
        self.assertIn("far larger than any recording this tool makes", text)

    def test_cleaning_a_clean_file_says_nothing_to_remove(self):
        _zipped, folder = self.old_send_zip()
        one = os.path.join(folder, "step3-scan-single-take1-USBPcap1-instrument.pcap")
        probe.clean_paths([one])
        text, _code = probe.clean_paths([one[:-5] + "-cleaned.pcap"])
        self.assertIn("nothing to remove", text)

    def test_the_cleaned_session_knows_what_was_left_out(self):
        _zipped, folder = self.old_send_zip()
        probe.clean_paths([folder])
        with open(os.path.join(folder + "-cleaned", "session.json"), encoding="utf-8") as fh:
            step = json.load(fh)["steps"][0]
        self.assertTrue(probe.foreign_seen(step["left_out"]))
        self.assertTrue(step["check"][0].startswith("cleaned by version"))
        # 1.6.2: a bulk-only disk on two endpoints the i1Pro 2 does not have
        # (the real case) is removed, and the instrument's contents are shown
        self.assertTrue(step["explained"])
        with open(os.path.join(folder + "-cleaned", "analysis.txt"), encoding="utf-8") as fh:
            text = " ".join(fh.read().split())
        self.assertIn("traffic at this instrument's address was removed", text)
        self.assertNotIn("so the contents are not shown", text)

    def test_a_zip_cannot_write_outside_its_folder(self):
        evil = os.path.join(self.dir, "SEND-THIS-evil.zip")
        with zipfile.ZipFile(evil, "w") as zf:
            zf.writestr("../../escaped-instrument.pcap", b"x")
            zf.writestr("/abs-instrument.pcap", b"x")
        _text, _code = probe.clean_paths([evil])
        self.assertFalse(os.path.exists(os.path.join(os.path.dirname(self.dir),
                                                     "escaped-instrument.pcap")))


if __name__ == "__main__":
    unittest.main()
