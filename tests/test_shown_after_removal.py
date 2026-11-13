"""1.6.2: a step that is shown because the other device's traffic was
explained as one bulk-only disk on endpoints the instrument does not have
prints decoded values only, never raw bytes; and the ColorMunki's event rule.

    python3 -m unittest discover -s tests -v

From the coordinator's review (attackb2.py, adv4.py). Every byte is INVENTED.
"""

import contextlib
import io
import json
import os
import shutil
import struct
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import chromiq_io_probe as probe  # noqa: E402

import synth  # noqa: E402
import test_recording_one as rec1  # noqa: E402
from synth import XFER_BULK, XFER_INT  # noqa: E402

A = 3
INSTR = {"i1pro2": (0x0971, 0x2000, [(0x01, 2), (0x82, 2), (0x03, 2), (0x84, 3), (0x85, 2)]),
         "i1pro3": (0x0765, 0x6009, [(0x81, 2), (0x83, 3), (0x84, 2), (0x02, 2)]),
         "munki": (0x0971, 0x2007, [(0x81, 2), (0x83, 3)]),
         "io": (0x0971, 0x2004, [(0x81, 2), (0x02, 2)]),
         "isis": (0x0971, 0x2006, [(0x81, 2), (0x02, 2)]),
         "generic": (0x0971, 0x2099, [(0x81, 2), (0x02, 2)])}
KEYS = bytes([0, 0, 0x0B, 0x08, 0x0F, 0x0F, 0x12, 0])


def rec(w, ep, xfer, data, out=False):
    w.irp += 1
    if out:
        w._rec(w.irp, A, ep, xfer, 0, data)                     # noqa: SLF001
        w.tick(0.0002)
        w._rec(w.irp, A, ep, xfer, 1, b"")                      # noqa: SLF001
    else:
        w._rec(w.irp, A, ep, xfer, 0, b"")                      # noqa: SLF001
        w.tick(0.0002)
        w._rec(w.irp, A, ep, xfer, 1, data)                     # noqa: SLF001
    w.tick(0.0002)


def absent_pair(prof):
    eps = {e for e, _k in INSTR[prof][2]}
    for o, i in ((0x02, 0x81), (0x06, 0x85), (0x0A, 0x89)):
        if o not in eps and i not in eps:
            return o, i
    raise AssertionError(prof)


def bot(w, o, i, mark, complete=True, n=3):
    for k in range(n):
        if complete or k:
            rec(w, o, XFER_BULK, b"USBC" + bytes([k + 1, 0, 0, 0]) + b"\x00\x02\x00\x00\x80\x00"
                b"\x0a\x28" + bytes(15), True)
        rec(w, i, XFER_BULK, mark + b" sector data " * 8)
        if complete or k != n - 1:
            rec(w, i, XFER_BULK, b"USBS" + bytes([k + 1, 0, 0, 0]) + bytes(5))


def own(w, prof):
    vid, pid, eps = INSTR[prof]
    w.describe(A, vid, pid, eps)
    w.vendor_out(A, 0x01, b"\x00\x01")
    ins = [e for e, k in eps if e & 0x80 and k == 2]
    rec(w, ins[0], XFER_BULK, b"\x10\x20" * 64)


def out_ep(prof):
    return [e for e, k in INSTR[prof][2] if not e & 0x80 and k == 2][:1]


def in_ep(prof):
    return [e for e, k in INSTR[prof][2] if e & 0x80 and k == 2][:1]


ATTACKS = {
    "disk alone": lambda w, p: bot(w, *absent_pair(p), b"DISKA-MARK"),
    "disk + OUT data on an instrument endpoint": lambda w, p: (
        bot(w, *absent_pair(p), b"DISKA-MARK"),
        [rec(w, e, XFER_BULK, b"SECOND-OUT-MARK printer job text", True) for e in out_ep(p)]),
    "disk + IN data on an instrument endpoint": lambda w, p: (
        bot(w, *absent_pair(p), b"DISKA-MARK"),
        [rec(w, e, XFER_BULK, b"SECOND-IN-MARK serial typed text") for e in in_ep(p)]),
    "disk + vendor request on endpoint 0": lambda w, p: (
        bot(w, *absent_pair(p), b"DISKA-MARK"), w.vendor_in(A, 0x42, b"VENDOR2-MARK serial")),
    "disk + keyboard on an interrupt endpoint": lambda w, p: (
        bot(w, *absent_pair(p), b"DISKA-MARK"),
        [rec(w, e, XFER_INT, KEYS) for e, k in INSTR[p][2] if k == 3]),
    "disk with an incomplete command": lambda w, p: bot(w, *absent_pair(p), b"DISKI-MARK",
                                                        complete=False, n=1),
    "fake USBC/USBS + text on an instrument endpoint": lambda w, p: (
        rec(w, absent_pair(p)[0], XFER_BULK, b"USBC" + b"FAKE-MARK".ljust(27, b"."), True),
        rec(w, absent_pair(p)[1], XFER_BULK, b"USBS" + b"FAKE2xxxx"),
        [rec(w, e, XFER_BULK, b"FAKEDATA-MARK on instrument ep", True) for e in out_ep(p)]),
    "composite disk + HID": lambda w, p: (bot(w, *absent_pair(p), b"DISKC-MARK"),
                                          rec(w, 0x8F, XFER_INT, b"HIDC-MARK" + bytes(3))),
    "two disks": lambda w, p: (bot(w, 0x0A, 0x89, b"DISK1-MARK"),
                               bot(w, 0x0C, 0x8D, b"DISK2-MARK")),
}
MARKS = [b"DISKA-MARK", b"SECOND-OUT-MARK", b"SECOND-IN-MARK", b"VENDOR2-MARK", KEYS[2:7],
         b"DISKI-MARK", b"FAKE-MARK", b"FAKEDATA-MARK", b"DISKC-MARK", b"HIDC-MARK",
         b"DISK1-MARK", b"DISK2-MARK"]


def printed(text):
    low = text.lower()
    return [m for m in MARKS if m.decode("latin-1") in text or m[:9].hex() in low]


def quiet(fn):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        r = fn()
    return (r or "") + buf.getvalue()


class ShownAfterRemoval(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = self.tmp.name

    def test_no_marker_printed_in_any_attack(self):
        for prof in INSTR:
            for name, fn in ATTACKS.items():
                with self.subTest(session=prof, attack=name):
                    w = synth.UsbPcapWriter()
                    own(w, prof)
                    fn(w, prof)
                    synth.keyboard_noise(w)
                    d = os.path.join(self.dir, f"{prof}-{abs(hash(name))}")
                    os.makedirs(d)
                    raw = w.save(os.path.join(d, "full.pcap"))
                    chk = probe.check_capture(raw, prof)
                    dst = os.path.join(d, "s", "c.pcap")
                    os.makedirs(os.path.dirname(dst))
                    probe.filter_xrite_capture(raw, dst, prof)
                    files = ["c.pcap"] if os.path.exists(dst) else []
                    with open(os.path.join(d, "s", "session.json"), "w") as fh:
                        json.dump({"kind": probe.SESSION_KIND, "family": prof, "recorder": "x",
                                   "steps": [{"number": 1, "key": "scan-single", "title": "x",
                                              "take": 1, "kept": True, "files_xrite": files,
                                              "left_out": chk["left_out"],
                                              "explained": chk["explained"]}]}, fh)
                    texts = (chk["verdict"]
                             + quiet(lambda: probe.summarize_session([os.path.join(d, "s")]))
                             + quiet(lambda: probe.analyze_paths([raw]))
                             + quiet(lambda: probe.clean_paths([raw])[0]))
                    self.assertEqual(printed(texts), [])

    def test_decoded_figures_are_the_same_with_and_without_raw_bytes(self):
        """On the structure of the real recording: what the analysis decodes
        (readings, ruler, lights, requests, sizes) is the same whether raw
        bytes are shown or not; only the raw bytes go."""
        for n in range(1, 10):
            with self.subTest(step=n):
                w = rec1.step_recording(n, disk=n in rec1.WITH_DISK)
                w.vendor_out(rec1.DEV, 0xD6, synth.be32(len(synth.LED_GREEN_BLINK)))
                w.bulk(0x03, synth.LED_GREEN_BLINK)
                kept, att = probe.kept_records(249, w.records, "i1pro2")
                self.assertEqual(att["explained"], n in rec1.WITH_DISK)
                events = probe.capture_events(249, kept)
                a = probe.analyze_step(events, "i1pro2", show_raw=True)
                b = probe.analyze_step(events, "i1pro2", show_raw=False)
                for key in ("measurements", "motion", "requests", "endpoints", "codes",
                            "odd_sizes", "ruler", "events"):
                    self.assertEqual(a[key], b[key], key)
                self.assertEqual([d["text"] for _t, d in a["leds"]],
                                 [d["text"] for _t, d in b["leds"]])
                self.assertTrue(a["measurements"] and a["motion"] and a["leds"])
                raw_lines = [t for _r, t in b["timeline"] if "data on" in t]
                self.assertTrue(all("raw bytes not shown" in t for t in raw_lines))


class ColorMunkiEvents(unittest.TestCase):

    def keep(self, data):
        w = synth.UsbPcapWriter()
        w.describe(A, 0x0971, 0x2007, [(0x81, 2), (0x83, 3)])
        w.vendor_in(A, 0x87, b"\x01\x00")
        rec(w, 0x83, XFER_INT, data)
        att = probe.attribute_records(249, w.records, "munki")
        lt_events = probe.capture_events(249, [r for r, k in zip(w.records, att["keep"]) if k])
        return any(e["kind"] == "data" and e["ep"] == 0x83 for e in lt_events), att["left_out"]

    def test_known_and_small_unknown_codes_are_kept(self):
        for code in (0, 1, 2, 0x100, 0x200):
            with self.subTest(code=code):
                kept, _left = self.keep(struct.pack("<II", code, 1234))
                self.assertTrue(kept)

    def test_keyboard_reports_with_a_key_are_left_out(self):
        for pos in range(2, 8):
            report = bytearray(8)
            report[pos] = 0x0B
            with self.subTest(key_in_byte=pos):
                kept, left = self.keep(bytes(report))
                if pos in (2, 3):
                    self.assertFalse(kept)
                    self.assertIn("button", left)
        # PINNED (the limit): keys in bytes 4 to 7 only happen with a key in
        # byte 2 too (a keyboard fills its key slots from byte 2 on), so
        # bytes 4..7 alone are a ColorMunki time stamp and kept.
        kept, _left = self.keep(KEYS)
        self.assertFalse(kept)

    def test_a_modifier_only_report_is_kept_and_carries_no_key(self):
        # PINNED: shift held, no key: looks like event code 0x02 (released)
        kept, _left = self.keep(bytes([0x02, 0, 0, 0, 0, 0, 0, 0]))
        self.assertTrue(kept)


if __name__ == "__main__":
    unittest.main()
