"""1.6.2: the coordinator's review cases. One foreign device at a time
carries the instrument's USB address (a stale USBPcap address), for six
session types and seventeen kinds of device.

    python3 -m unittest discover -s tests -v

What is tested:
  * whenever the tool SAW another device at the address (it left something
    out for that reason), no planted marker appears in any text it prints
    or writes: the check, --analyze of the raw file and of the copy, the
    session analysis, --clean's text (the "contents not shown" rule, G2);
  * a keyboard on the instrument's own button endpoint is recognised (G1);
  * the cases in which nothing tells the device apart are exactly the
    known limit named in the README (same endpoint numbers and types, or
    vendor requests on endpoint 0): listed here, so that a change shows.
Every byte is INVENTED.
"""

import contextlib
import io
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
from synth import XFER_BULK, XFER_INT, XFER_ISO  # noqa: E402

A = 3
INSTR = {
    "i1pro2": (0x0971, 0x2000, [(0x82, 2), (0x84, 3), (0x03, 2), (0x85, 2), (0x01, 2)]),
    "i1pro3": (0x0765, 0x6009, [(0x81, 2), (0x83, 3), (0x84, 2), (0x02, 2)]),
    "munki": (0x0971, 0x2007, [(0x81, 2), (0x83, 3)]),
    "io": (0x0971, 0x2004, [(0x81, 2), (0x02, 2)]),
    "isis": (0x0971, 0x2006, [(0x81, 2), (0x02, 2)]),
    "generic": (0x0971, 0x2099, [(0x81, 2), (0x02, 2)]),
}
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


FOREIGN = {
    "disk-BOT": lambda w: (rec(w, 0x02, XFER_BULK, b"USBC\x01\x00\x00\x00\x00\x02\x00\x00\x80"
                                                   b"\x00\x0a\x28" + b"BOTCMD-MARK".ljust(15, b"\0"),
                               True),
                           rec(w, 0x81, XFER_BULK, b"BOTFILE-MARK tax-return.pdf " * 4),
                           rec(w, 0x81, XFER_BULK, b"USBS\x01" + bytes(8))),
    "disk-BOT-midway": lambda w: rec(w, 0x81, XFER_BULK, b"BOTMID-MARK photo.jpg " * 4),
    "disk-UAS": lambda w: (rec(w, 0x04, XFER_BULK, b"\x01\x00\x00\x01" + bytes(12) + b"\x28"
                               + bytes(15), True),
                           rec(w, 0x81, XFER_BULK, b"UASFILE-MARK letter.docx " * 4),
                           rec(w, 0x02, XFER_BULK, b"UASWRITE-MARK diary.txt " * 4, True),
                           rec(w, 0x83, XFER_BULK, b"\x03\x00\x00\x01" + bytes(12))),
    "disk-UAS-on-82": lambda w: rec(w, 0x82, XFER_BULK, b"UAS82-MARK letter.docx " * 4),
    "keyboard-81": lambda w: [rec(w, 0x81, XFER_INT, KEYS) for _ in range(3)],
    "keyboard-83": lambda w: [rec(w, 0x83, XFER_INT, KEYS) for _ in range(3)],
    "keyboard-84": lambda w: [rec(w, 0x84, XFER_INT, KEYS) for _ in range(3)],
    "mouse-81": lambda w: [rec(w, 0x81, XFER_INT, b"\x01\x05\xfb\x00") for _ in range(3)],
    "webcam-iso": lambda w: rec(w, 0x81, XFER_ISO, b"WEBCAM-MARK face " * 8),
    "usb-serial": lambda w: (rec(w, 0x81, XFER_BULK, b"\x01\x60SERIAL-MARK password=x"),
                             rec(w, 0x02, XFER_BULK, b"SERIALOUT-MARK AT+PIN=1234", True)),
    "hub-int": lambda w: rec(w, 0x81, XFER_INT, b"\x02"),
    "phone-MTP": lambda w: (rec(w, 0x81, XFER_BULK, b"\x20\x00\x00\x00\x02\x00\x09\x10"
                                                    b"MTPPHOTO-MARK selfie.jpg"),
                            rec(w, 0x01, XFER_BULK, b"\x10\x00\x00\x00\x01\x00\x09\x10MTPOUT-MARK",
                                True),
                            rec(w, 0x82, XFER_INT, b"MTPEVENT-MARK")),
    "audio-iso": lambda w: rec(w, 0x01, XFER_ISO, b"AUDIO-MARK " * 8, True),
    "i1display": lambda w: (rec(w, 0x81, XFER_INT, b"DISPLAYSER-MARK" + bytes(49)),
                            rec(w, 0x01, XFER_INT, b"DISPLAYCMD-MARK" + bytes(49), True)),
    "printer-01-82": lambda w: (rec(w, 0x01, XFER_BULK, b"\x1b%-12345X@PJL JOB NAME=PRINTJOB-MARK",
                                    True),
                                rec(w, 0x82, XFER_BULK, b"PRINTERSTAT-MARK ready")),
    "printer-02-81": lambda w: (rec(w, 0x02, XFER_BULK, b"@PJL JOB NAME=PRINTJOB2-MARK", True),
                                rec(w, 0x81, XFER_BULK, b"PRINTERSTAT2-MARK ready")),
    "vendor-ep0": lambda w: w.vendor_in(A, 0x42, b"VENDOREP0-MARK other-device-serial"),
}
MARKS = [b"BOTFILE-MARK", b"BOTCMD-MARK", b"BOTMID-MARK", b"UASFILE-MARK", b"UASWRITE-MARK",
         b"UAS82-MARK", b"WEBCAM-MARK", b"SERIAL-MARK", b"SERIALOUT-MARK", b"MTPPHOTO-MARK",
         b"MTPOUT-MARK", b"MTPEVENT-MARK", b"AUDIO-MARK", b"DISPLAYSER-MARK", b"DISPLAYCMD-MARK",
         b"PRINTJOB-MARK", b"PRINTERSTAT-MARK", b"PRINTJOB2-MARK", b"PRINTERSTAT2-MARK",
         b"VENDOREP0-MARK", KEYS]


def in_text(text: str) -> list:
    b, low = text.encode("utf-8", "replace"), text.lower()
    return [m for m in MARKS if m in b or m[:8].hex() in low or m[:8].hex().upper() in text]


def own_traffic(w, prof):
    vid, pid, eps = INSTR[prof]
    w.describe(A, vid, pid, eps)
    w.vendor_out(A, 0x01, b"\x00\x01")
    ins = [e for e, k in eps if e & 0x80 and k == 2]
    if ins:
        rec(w, ins[0], XFER_BULK, b"\x10\x20" * 64)


def quiet(fn):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        r = fn()
    return r, buf.getvalue()


# The known limit: nothing tells these apart from the instrument (the same
# endpoint number and transfer type, or vendor requests on endpoint 0), and
# the tool saw nothing else of the device, so their bytes reach the printed
# analysis (vendor answers, data on an endpoint the open driver does not
# use, the i1iSis and generic devices' "lines the program sent", the table's
# lines). More of these devices' bytes can be in the binary copies (for
# example a printer's job on an i1Pro 2's 0x01, a phone's data): the README
# and the CHANGELOG say so. Listed exactly, so that any change shows.
KNOWN_LIMIT = {
    ("generic", "printer-02-81"), ("generic", "usb-serial"),
    ("i1pro2", "vendor-ep0"), ("i1pro3", "printer-02-81"), ("i1pro3", "usb-serial"),
    ("i1pro3", "vendor-ep0"), ("io", "disk-BOT-midway"), ("io", "printer-02-81"),
    ("io", "usb-serial"), ("isis", "printer-02-81"), ("isis", "usb-serial"),
    ("munki", "vendor-ep0"),
}


class SharedAddress(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.results = {}
        for prof in INSTR:
            for name, fn in FOREIGN.items():
                cls.results[(prof, name)] = cls.run_case(prof, name, fn)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    @classmethod
    def run_case(cls, prof, name, fn):
        d = os.path.join(cls.tmp.name, f"{prof}--{name}")
        os.makedirs(d)
        w = synth.UsbPcapWriter()
        own_traffic(w, prof)
        fn(w)
        synth.keyboard_noise(w)
        raw = w.save(os.path.join(d, "step1-full.pcap"))
        att = probe.attribute_records(*probe._read_pcap(raw), prof)
        dst = os.path.join(d, "step1-instrument.pcap")
        probe.filter_xrite_capture(raw, dst, prof)
        texts = [json.dumps(probe.check_capture(raw, prof), default=str)]
        sess = os.path.join(d, "sess")
        os.makedirs(sess)
        files = []
        if os.path.exists(dst):
            shutil.copy(dst, sess)
            files = [os.path.basename(dst)]
        with open(os.path.join(sess, "session.json"), "w") as fh:
            json.dump({"kind": probe.SESSION_KIND, "family": prof, "recorder": "x", "steps": [
                {"number": 1, "key": "scan-single", "title": "x", "take": 1, "kept": True,
                 "files_xrite": files,
                 # what the session's own step check writes (check_capture)
                 "left_out": probe.check_capture(raw, prof)["left_out"]}]}, fh)
        for fn2 in (lambda: probe.summarize_session([sess]),
                    lambda: probe.analyze_paths([raw]),
                    lambda: probe.clean_paths([raw])[0]):
            r, so = quiet(fn2)
            texts += [r or "", so]
        return {"seen": probe.foreign_seen(att["left_out"]),
                "hidden": probe.hide_contents(att["left_out"]), "left_out": att["left_out"],
                "text": in_text("\n".join(texts))}

    def test_no_marker_in_any_text_once_another_device_was_seen(self):
        for case, r in self.results.items():
            if r["seen"]:
                with self.subTest(case=case):
                    self.assertEqual(r["text"], [])

    def test_the_cases_not_seen_are_exactly_the_known_limit(self):
        leaked = {case for case, r in self.results.items() if r["text"]}
        self.assertEqual(leaked, KNOWN_LIMIT)
        self.assertTrue(all(not self.results[c]["seen"] for c in leaked))

    def test_a_keyboard_on_the_button_endpoint_is_recognised(self):
        # (the ColorMunki's 8-byte events are checked by size only, since an
        # event code ArgyllCMS does not know must be kept: a keyboard there is
        # kept in the copy, its bytes are never shown)
        for prof, name in (("i1pro2", "keyboard-84"), ("i1pro3", "keyboard-83")):
            with self.subTest(session=prof):
                r = self.results[(prof, name)]
                self.assertIn("button", r["left_out"])
                self.assertEqual(r["text"], [])


if __name__ == "__main__":
    unittest.main()
