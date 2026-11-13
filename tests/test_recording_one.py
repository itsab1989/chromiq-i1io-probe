"""1.6.2: the STRUCTURE of the real recording that led to 1.6.2 (the
recording analyst's notes, sections 6 to 8), rebuilt with invented data.

    python3 -m unittest discover -s tests -v

An i1Pro 2 at bus 1, address 10 (descriptor endpoints 0x01, 0x82, 0x03,
0x84, 0x85), a bulk-only USB disk whose packets carry the same address, on
0x02 OUT and 0x81 IN only: 31-byte commands, 13-byte status, 8192-byte
sector reads ending in 55AA, stalls (status 0xC0000004) each followed by a
pipe reset (transfer 0xFE, function 0x001E); the instrument's own cancelled
read-aheads (status 0xC0010000) and pipe resets on 0x82 and 0x85 after each
scan; 2624-byte reads; the button on 0x84 as one byte 06; the disk's bursts
in the middle of the instrument's measurements; nine steps, the disk in
steps 1, 2, 4, 5, 6, 7 and 9.
"""

import json
import os
import struct
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import chromiq_io_probe as probe  # noqa: E402

import synth  # noqa: E402

DEV = 10
EPS = [(0x01, 2), (0x82, 2), (0x03, 2), (0x84, 3), (0x85, 2)]
SECRET = b"RECORDING-ONE-DISK-SECRET"
STEP_KEYS = [s["key"] for s in probe.steps_for("i1pro2")]
WITH_DISK = {1, 2, 4, 5, 6, 7, 9}


class Writer(synth.UsbPcapWriter):
    """USBPcap records with a status and a URB function, as on Windows."""

    def raw(self, irp, ep, xfer, info, data, status=0, function=0x0009):
        hdr = struct.pack("<HQIHBHHBBI", 27, irp, status, function, info, self.bus, DEV,
                          ep, xfer, len(data))
        self.records.append((self.t, hdr + bytes(data)))
        self.tick(0.0002)

    def bulk(self, ep, data, status=0, xfer=3):
        self.irp += 1
        if ep & 0x80:
            self.raw(self.irp, ep, xfer, 0, b"", status=0xFFFFFFFF)
            self.raw(self.irp, ep, xfer, 1, data, status=status)
        else:
            self.raw(self.irp, ep, xfer, 0, data, status=0xFFFFFFFF)
            self.raw(self.irp, ep, xfer, 1, b"", status=status)

    def pipe_reset(self, ep):
        self.irp += 1
        self.raw(self.irp, ep, 0xFE, 0, b"", function=0x001E)
        self.raw(self.irp, ep, 0xFE, 1, b"", function=0x001E)

    def disk_burst(self, tag, stall=False, out_ep=0x02, in_ep=0x81):
        self.bulk(out_ep, b"USBC" + struct.pack("<IIBBB", tag, 8192, 0x80, 0, 10)
                  + b"\x28".ljust(16, b"\0"))
        self.bulk(in_ep, (SECRET * 400)[:8190] + b"\x55\xaa")
        if stall:
            self.bulk(in_ep, b"", status=0xC0000004)
            self.pipe_reset(in_ep)
        self.bulk(in_ep, b"USBS" + struct.pack("<IIB", tag, 0, 0))


def step_recording(n, disk=True, shared=False):
    w = Writer()
    w.describe(DEV, 0x0971, 0x2000, EPS)
    w.control(DEV, 0x40, 0xD4, out=struct.pack(">IIIH", 139, 41, 10, 0x010D))
    w.bulk(0x84, b"\x06", xfer=1)                                # the button
    data = bytes([0x40]) * (268 * 200)
    for i in range(0, len(data), 2624):
        w.bulk(0x82, data[i:i + 2624])
        if disk and i == 2624 * 10:
            w.disk_burst(100 + n, stall=(n % 2 == 1))          # in the middle of it
    gray = [0, 1, 3, 2]
    ruler = bytes(gray[(k // 40) % 4] for k in range(200 * 139 - 5))
    for i in range(0, len(ruler), 4096):
        w.bulk(0x85, ruler[i:i + 4096])
    w.bulk(0x82, b"", status=0xC0010000)                        # cancelled read-ahead
    w.pipe_reset(0x82)
    w.bulk(0x85, b"", status=0xC0010000)
    w.pipe_reset(0x85)
    if shared:
        # what 1.6.2 cannot see through: the disk ALSO on the instrument's 0x01
        w.bulk(0x01, b"USBC" + struct.pack("<IIBBB", 7, 0, 0, 0, 6) + bytes(16))
    return w


class RecordingOne(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = self.tmp.name

    def session(self, shared_steps=()):
        folder = os.path.join(self.dir, "instrument-session-x")
        os.makedirs(folder, exist_ok=True)
        steps = []
        for n, key in enumerate(STEP_KEYS, 1):
            raw = step_recording(n, disk=n in WITH_DISK, shared=n in shared_steps).save(
                os.path.join(self.dir, f"step{n}-full.pcap"))
            name = f"step{n}-{key}-take1-USBPcap1-instrument.pcap"
            probe.filter_xrite_capture(raw, os.path.join(folder, name), "i1pro2")
            check = probe.check_capture(raw, "i1pro2")
            steps.append({"number": n, "key": key, "title": key, "take": 1, "kept": True,
                          "files_xrite": [name], "control": key == "noruler",
                          "lights": "green", "left_out": check["left_out"],
                          "explained": check["explained"]})
        with open(os.path.join(folder, "session.json"), "w", encoding="utf-8") as fh:
            json.dump({"kind": probe.SESSION_KIND, "family": "i1pro2", "recorder": "x",
                       "steps": steps}, fh)
        return folder, steps

    def test_every_instrument_record_kept_every_disk_record_dropped(self):
        for n in range(1, 10):
            with self.subTest(step=n):
                full = step_recording(n, disk=n in WITH_DISK)
                clean = step_recording(n, disk=False)
                lt, recs = 249, full.records
                kept = [d for (_t, d), k in zip(recs, probe.attribute_records(
                    lt, recs, "i1pro2")["keep"]) if k]
                # the same records as the recording without the disk (irp ids differ)
                strip = lambda d: d[:2] + d[10:]            # noqa: E731
                self.assertEqual([strip(d) for d in kept],
                                 [strip(d) for _t, d in clean.records])

    def test_the_disk_is_explained_and_the_analysis_shows_the_instrument(self):
        folder, steps = self.session()
        for st in steps:
            if st["number"] in WITH_DISK:
                self.assertTrue(st["explained"], st["number"])
                self.assertEqual(set(st["left_out"]) - {"storage", "endpoint"}, set())
        text = " ".join(probe.summarize_session([folder]).split())
        self.assertNotIn("contents not shown", text)
        self.assertNotIn(SECRET[:12].decode(), text)
        self.assertEqual(text.count("traffic at this instrument's address was removed"),
                         len(WITH_DISK))
        self.assertIn("THE RULER'S POSITION, STEP BY STEP:", text)
        self.assertIn("by the ruler, the instrument moved for:", text)

    def test_a_disk_on_an_instrument_endpoint_hides_that_step_and_says_so(self):
        folder, steps = self.session(shared_steps={5, 9})
        self.assertFalse(steps[4]["explained"])
        text = probe.summarize_session([folder])
        flat = " ".join(text.split())
        side = text.split("STEPS SIDE BY SIDE")[1].split("THE OPEN DRIVER")[0]
        self.assertIn("contents not shown (another device shared this address)", side)
        self.assertNotRegex(side, r"step 5: scan-fast\s+0\s+0")
        self.assertIn("FAST AGAINST SLOW SWIPE: not compared, because the step 5: scan-fast "
                      "step's contents are not shown.", flat)
        self.assertIn("ONLY WITH THE RULER: not compared, because the no-ruler control step "
                      "is not shown.", flat)
        self.assertNotIn("Without the ruler the position never changed", flat)
        lights = text.split("THE LIGHTS' LANGUAGE")[1].split("DOES THIS RECORDING")[0]
        self.assertIn("step 5: scan-fast: contents not shown", lights)
        self.assertNotIn("step 5: scan-fast: no light command", lights)
        ruler = text.split("THE RULER'S POSITION, STEP BY STEP:")[1].split("FAST AGAINST")[0]
        self.assertIn("step 9: noruler [CONTROL]: contents not shown", ruler)
        self.assertIn("2 steps below are not shown", flat)


if __name__ == "__main__":
    unittest.main()
