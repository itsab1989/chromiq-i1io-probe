"""1.6.2: clean recordings never say "another device shared this address".

    python3 -m unittest discover -s tests -v

From the coordinator's review (fp.py): things a real instrument recording
can hold that are NOT proof of another device: Windows' Microsoft OS string
request (index 0xEE, the first time a device is plugged into a PC), a string
the instrument's description does not name, a control answer whose request
came before the recording started, cancelled or empty button reads, pipe
resets, a re-configuration, a ColorMunki event code ArgyllCMS does not know.
Also: a damaged zip given to --clean. Every byte is INVENTED.
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
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import chromiq_io_probe as probe  # noqa: E402

import synth  # noqa: E402
from synth import XFER_BULK, XFER_INT  # noqa: E402

A = 10
EPS = {"i1pro2": (0x0971, 0x2000, [(0x01, 2), (0x82, 2), (0x03, 2), (0x84, 3), (0x85, 2)], 0x84),
       "i1pro3": (0x0765, 0x6009, [(0x81, 2), (0x83, 3), (0x84, 2), (0x02, 2)], 0x83),
       "munki": (0x0971, 0x2007, [(0x81, 2), (0x83, 3)], 0x83)}


def rec(w, ep, xfer, data, status=0):
    w.irp += 1
    w._rec(w.irp, A, ep, xfer, 0, b"")                              # noqa: SLF001
    w.tick(0.0002)
    w.records.append((w.t, struct.pack("<HQIHBHHBBI", 27, w.irp, status, 9, 1, w.bus, A, ep,
                                       xfer, len(data)) + data))
    w.tick(0.0002)


def info(w, ep, status):
    w.irp += 1
    w.records.append((w.t, struct.pack("<HQIHBHHBBI", 27, w.irp, status, 0x1E, 0, w.bus, A,
                                       ep, 0xFE, 0)))
    w.tick(0.0002)


def base(prof):
    vid, pid, eps, btn = EPS[prof]
    w = synth.UsbPcapWriter()
    w.describe(A, vid, pid, eps)
    w.vendor_out(A, 0x01, b"\x00")
    rec(w, [e for e, k in eps if e & 0x80 and k == 2][0], XFER_BULK, b"\x11" * 64)
    return w, btn


def press(prof):
    return b"\x01" if prof != "munki" else struct.pack("<II", 1, 1234)


def cases():
    out = {}
    for prof in EPS:
        w, btn = base(prof)
        rec(w, btn, XFER_INT, press(prof))
        out[(prof, "normal press")] = w
        w, btn = base(prof)
        rec(w, btn, XFER_INT, b"", status=0xC0000120)
        out[(prof, "cancelled button read")] = w
        w, btn = base(prof)
        rec(w, btn, XFER_INT, b"")
        out[(prof, "zero-length button completion")] = w
        w, btn = base(prof)
        info(w, btn, 0xC0010000)
        info(w, btn, 0)
        out[(prof, "pipe reset on the button endpoint")] = w
        w, btn = base(prof)
        w.control(A, 0x80, 6, value=0x03EE, length=18, reply=b"\x12\x03MSFT100\x01\x00")
        out[(prof, "Microsoft OS string 0xEE")] = w
        w, btn = base(prof)
        w.control(A, 0x80, 6, value=0x0304, length=10, reply=b"\x0a\x03I\x00F\x00x\x00y\x00")
        out[(prof, "string index 4")] = w
        w, btn = base(prof)
        w.irp += 1
        w.records.insert(0, (w.t - 5, struct.pack("<HQIHBHHBBI", 28, w.irp, 0, 8, 1, w.bus, A,
                                                  0x80, 2, 2) + b"\x01" + b"\x00\x00"))
        out[(prof, "control answer whose request came before the recording")] = w
        w, btn = base(prof)
        w.control(A, 0x00, 9, value=0)
        w.control(A, 0x00, 9, value=1)
        w.describe(A, *EPS[prof][:3])
        rec(w, btn, XFER_INT, press(prof))
        out[(prof, "re-configuration")] = w
    w, btn = base("munki")
    rec(w, btn, XFER_INT, struct.pack("<II", 0x0200, 5))
    out[("munki", "unknown event code")] = w
    return out


class NoFalseAlarm(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = self.tmp.name

    def test_nothing_claims_another_device_or_hides_contents(self):
        for (prof, name), w in cases().items():
            with self.subTest(session=prof, case=name):
                path = w.save(os.path.join(self.dir, f"{prof}-{abs(hash(name))}.pcap"))
                check = probe.check_capture(path, prof)
                self.assertFalse(probe.foreign_seen(check["left_out"]), check["left_out"])
                self.assertFalse(probe.hide_contents(check["left_out"],
                                                     check.get("explained", False)))
                self.assertNotIn("Another USB device", check["verdict"])
                text = probe.analyze_paths([path])
                self.assertNotIn("contents are not shown", " ".join(text.split()))
                self.assertNotIn("Another USB device", text)

    def test_an_unknown_colormunki_event_is_kept_and_named(self):
        w = cases()[("munki", "unknown event code")]
        path = w.save(os.path.join(self.dir, "munki.pcap"))
        dst = os.path.join(self.dir, "munki-copy.pcap")
        probe.filter_xrite_capture(path, dst, "munki")
        lt, recs = probe._read_pcap(dst)
        events = [e for e in probe.capture_events(lt, recs) if e["kind"] == "data"
                  and e["ep"] == 0x83]
        self.assertEqual(len(events), 1)
        text = probe.analyze_paths([path])
        self.assertIn("unknown event code (8 bytes, not shown)", text)
        self.assertNotIn("0x200", text)

    def test_left_out_records_without_proof_are_said_plainly(self):
        w = cases()[("i1pro2", "Microsoft OS string 0xEE")]
        path = w.save(os.path.join(self.dir, "ee.pcap"))
        verdict = probe.check_capture(path, "i1pro2")["verdict"]
        self.assertIn("A few records could not be matched to the instrument and were left out",
                      verdict)

    def test_a_damaged_zip_is_said_plainly(self):
        good = os.path.join(self.dir, "SEND-THIS-x.zip")
        w, _btn = base("i1pro2")
        payload = w.pcap() * 20
        with zipfile.ZipFile(good, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("instrument-session-x/step1-a-instrument.pcap", payload)
            zf.writestr("instrument-session-x/session.json", json.dumps({"kind": "x"}))
        blob = bytearray(open(good, "rb").read())
        mid = blob.find(b"step1-a-instrument.pcap") + 200
        for i in range(mid, mid + 40):
            blob[i] ^= 0x5A                      # damage the compressed data
        bad = os.path.join(self.dir, "SEND-THIS-bad.zip")
        open(bad, "wb").write(bytes(blob))
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = probe.main(["--clean", bad])
        out = buf.getvalue()
        self.assertNotIn("Traceback", out)
        self.assertIn("could not be read from the zip, left out", out)
        self.assertIn(code, (0, 1))

    def test_the_whole_zip_cap_has_its_own_words(self):
        big = os.path.join(self.dir, "SEND-THIS-many.zip")
        with zipfile.ZipFile(big, "w", zipfile.ZIP_DEFLATED) as zf:
            for i in range(6):
                zf.writestr(f"x/step{i}-instrument.pcap", b"\0" * (190 * 1024))
        # the same rule with small limits, so the test writes little to disk
        with mock.patch.object(probe, "CLEAN_MEMBER_LIMIT", 200 * 1024), \
                mock.patch.object(probe, "CLEAN_TOTAL_LIMIT", 1024 * 1024):
            text, _code = probe.clean_paths([big])
        self.assertIn("the zip as a whole would unpack to far more than a session ever holds",
                      text)


if __name__ == "__main__":
    unittest.main()
