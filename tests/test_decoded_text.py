"""1.6.3: decoded strings in steps shown after another device's traffic was
removed, and control characters in every decoded string.

From the reviewer's decoded.py (2026-11-13): a step whose recording had a
USB disk's traffic removed (on endpoints the instrument does not have) is
shown with decoded values only. Two string decoders still printed text
there: the i1Pro 3's "get firmware version" (0x20) and the ColorMunki's
"get version string" (0x85). Any device answering at that address could put
its own text into them. Now they print the length only in such steps, and no
decoder ever prints a control character."""

import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import chromiq_io_probe as probe  # noqa: E402
import synth  # noqa: E402
from synth import XFER_BULK  # noqa: E402

A = 3
INSTR = {"i1pro2": (0x0971, 0x2000, [(0x01, 2), (0x82, 2), (0x03, 2), (0x84, 3), (0x85, 2)]),
         "i1pro3": (0x0765, 0x6009, [(0x81, 2), (0x83, 3), (0x84, 2), (0x02, 2)]),
         "munki": (0x0971, 0x2007, [(0x81, 2), (0x83, 3)])}
MARK = b"PLANTEDTXT-4711-MARK"


def rec(w, ep, xfer, data, out=False):
    w.irp += 1
    if out:
        w._rec(w.irp, A, ep, xfer, 0, data)
        w.tick(0.0002)
        w._rec(w.irp, A, ep, xfer, 1, b"")
    else:
        w._rec(w.irp, A, ep, xfer, 0, b"")
        w.tick(0.0002)
        w._rec(w.irp, A, ep, xfer, 1, data)
    w.tick(0.0002)


def disk(w):
    """A bulk-only disk at the instrument's address, on two endpoints the
    instrument does not have: removed, and the step shown (decoded only)."""
    for k in range(2):
        rec(w, 0x0A, XFER_BULK, b"USBC" + bytes([k + 1, 0, 0, 0]) + b"\0" * 23, True)
        rec(w, 0x89, XFER_BULK, b"DISK-MARK" * 8)
        rec(w, 0x89, XFER_BULK, b"USBS" + bytes([k + 1, 0, 0, 0]) + b"\0" * 5)


class ShownAfterRemoval(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)

    # the marker right after the i1Pro 3 firmware answer's 6-byte head, so
    # both string decoders would show it
    def analysis(self, prof, with_disk=True, reply=None):
        if reply is None:
            reply = (MARK + b"\x00\x12\x34" if prof == "munki" else
                     b"\x01\x02" + len(MARK).to_bytes(4, "little") + MARK + b"\x00\x12")
        vid, pid, eps = INSTR[prof]
        w = synth.UsbPcapWriter()
        w.describe(A, vid, pid, eps)
        if with_disk:
            disk(w)
        for r in sorted(probe.FAMILIES[prof]["requests"]):
            w.control(A, 0xC0, r, value=0x4711, reply=reply)
            w.control(A, 0x40, r, value=0x4711, out=MARK)
        for e, k in eps:
            if k == 2:
                rec(w, e, XFER_BULK, MARK + bytes(range(40)), not e & 0x80)
        raw = w.save(os.path.join(self.tmp, prof + "-full.pcap"))
        chk = probe.check_capture(raw, prof)
        folder = os.path.join(self.tmp, prof + ("-disk" if with_disk else "-clean"))
        os.makedirs(folder)
        dst = os.path.join(folder, prof + "-instrument.pcap")
        probe.filter_xrite_capture(raw, dst, prof)
        with open(os.path.join(folder, "session.json"), "w") as fh:
            json.dump({"kind": probe.SESSION_KIND, "family": prof, "recorder": "x",
                       "steps": [{"number": 1, "key": "scan-single", "title": "x", "take": 1,
                                  "kept": True, "left_out": chk.get("left_out") or {},
                                  "explained": chk.get("explained", False),
                                  "files_xrite": [os.path.basename(dst)]}]}, fh)
        return chk, probe.summarize_session([folder])

    def test_no_planted_text_in_a_step_shown_after_removal(self):
        for prof in INSTR:
            with self.subTest(family=prof):
                chk, text = self.analysis(prof)
                self.assertTrue(chk.get("explained"))
                self.assertFalse(probe.hide_contents(chk["left_out"], chk["explained"]))
                self.assertIn("raw contents are not shown", " ".join(text.split()))
                self.assertNotIn("PLANTEDTXT", text)
                self.assertNotIn("TXT-4711", text)
                self.assertNotIn(MARK[:8].hex(), text.lower())
                self.assertNotIn("DISK-MARK", text)

    def test_the_string_decoders_give_the_length(self):
        _chk, text = self.analysis("i1pro3")
        self.assertRegex(text, r"0x20 get firmware version: firmware \d+\.\d+ "
                               r"<\d+ characters, not shown>")
        _chk, text = self.analysis("munki")
        self.assertRegex(text, r"0x85 get version string: <\d+ characters, not shown>")

    def test_without_a_removal_the_text_is_shown(self):
        _chk, text = self.analysis("i1pro3", with_disk=False,
                                   reply=bytes([1, 23]) + (5).to_bytes(4, "little") + b"1.23x")
        self.assertIn("firmware 1.23 '1.23x'", text)


class ControlCharacters(unittest.TestCase):

    def test_every_string_decoder_drops_control_characters(self):
        nasty = b"\x1b[31mRED\x07\x00\x08\x7f\x9bX\r\n"
        fw = bytes([1, 2]) + len(nasty).to_bytes(4, "little") + nasty
        for text in (probe._d3_fw(b"", fw), probe._dm_version(b"", nasty)):
            with self.subTest(text=text):
                self.assertFalse(any(ord(c) < 32 or 127 <= ord(c) < 160 for c in text), text)
                self.assertIn("[31mRED", text)

    def test_safe_text(self):
        self.assertEqual(probe.safe_text("a\x1bb\x00\tc\u0085"), "abc")
        self.assertEqual(probe.safe_text("ok�"), "ok?")


if __name__ == "__main__":
    unittest.main()
