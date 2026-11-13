"""1.6.2: the analyser bugs a real i1Pro 2 recording showed.

    python3 -m unittest discover -s tests -v

The shapes follow what a real i1Pro 2 with i1Profiler showed (a tester's
recording, 2026-11-13): readings read in 2624-byte pieces, the ruler on
0x85 as one sample (0 to 3) per byte, light sequences as long PWM ramps.
Every byte here is INVENTED.
"""

import os
import struct
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import chromiq_io_probe as probe  # noqa: E402

import synth  # noqa: E402

GRAY = [0, 1, 3, 2]


def ruler_bytes(n, start_moving, steps):
    """n samples; still until start_moving, then `steps` quadrature steps
    spread evenly to the end."""
    out, pos = [], 0
    moving = max(1, n - start_moving)
    for i in range(n):
        if i >= start_moving:
            pos = min(steps, (i - start_moving) * steps // moving)
        out.append(GRAY[pos % 4])
    return bytes(out)


def scan_step(path, readings, start_moving, steps, flags=0x010D):
    w = synth.UsbPcapWriter()
    w.describe(synth.I1PRO, 0x0971, 0x2000, synth.I1PRO2_ENDPOINTS)
    synth.i1pro2_trigger(w, flags, 10, intclocks=139, lamp=41)
    data = bytes([0x40]) * (268 * readings)
    for i in range(0, len(data), 2624):                 # i1Profiler's buffer size
        w.bulk_in(synth.I1PRO, 0x82, data[i:i + 2624])
    ruler = ruler_bytes(readings * 139 - 5, start_moving, steps)
    for i in range(0, len(ruler), 4096):
        w.bulk_in(synth.I1PRO, 0x85, ruler[i:i + 4096])
    return w.save(path)


def blk(steps, reps):
    body = b"".join(bytes([m]) + struct.pack(">H", c) for m, c in steps)
    return struct.pack(">II", 4 + len(body), reps) + body


def pulse(mask, width=2):
    steps = []
    for k in list(range(2, 67, width)) + list(range(66, 1, -width)):
        steps += [(mask, k), (0, 69 - k)]
    return steps


class Analysis162(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = self.tmp.name
        p = lambda n: os.path.join(self.dir, n)          # noqa: E731
        self.files = [
            scan_step(p("scan-single.pcap"), 570, 3000, 318),
            scan_step(p("scan-fast.pcap"), 140, 10, 143),
            scan_step(p("scan-slow.pcap"), 740, 50000, 345),
            scan_step(p("noruler.pcap"), 460, 10 ** 9, 0),
        ]
        self.report = probe.summarize_session(self.files)

    def test_readings_read_in_odd_pieces_are_not_flagged(self):
        self.assertNotIn("not a whole number of readings", self.report)

    def test_a_measurement_whose_total_is_odd_is_flagged(self):
        w = synth.UsbPcapWriter()
        w.describe(synth.I1PRO, 0x0971, 0x2000, synth.I1PRO2_ENDPOINTS)
        synth.i1pro2_trigger(w, 0x0101, 10)
        w.bulk_in(synth.I1PRO, 0x82, bytes(268 * 3 + 7))
        report = probe.summarize_session([w.save(os.path.join(self.dir, "odd.pcap"))])
        self.assertIn("1 measurement holds a total that is not a whole number of readings",
                      report)

    def test_ruler_motion_per_step_and_the_control(self):
        r = self.report
        self.assertIn("THE RULER'S POSITION, STEP BY STEP:", r)
        self.assertRegex(r, r"scan-single\.pcap: 31\d position steps \(net \+31\d\), moving for")
        self.assertIn("noruler.pcap  [CONTROL]: ", r)
        self.assertIn("the position never changed: no motion was seen", r)
        self.assertIn("Without the ruler the position never changed", r)

    def test_fast_and_slow_judged_by_the_ruler(self):
        r = " ".join(self.report.split())
        self.assertIn("by the ruler, the instrument moved for: normal", r)
        self.assertIn("the slow swipe", r)
        self.assertIn("was not clearly slower than the normal one", r)
        self.assertIn("in the fast step the instrument was already moving when the scan began",
                      r)

    def test_lights_in_words(self):
        seq = (struct.pack(">I", 3) + blk([(0, 0x3640), (0, 1)], 1) + blk(pulse(0x12), 2)
               + blk(pulse(0x3F, 1), 0xFFFFFFFF))
        text = probe.decode_led_sequence(seq)["text"]
        self.assertTrue(text.startswith("off for 1.0 s, then green, one smooth pulse of"), text)
        self.assertIn("s, twice, then white, one smooth pulse of", text)
        self.assertIn("over and over until the next light command", text)
        self.assertNotIn("[", text)                     # no step list for a long ramp
        blue = probe.decode_led_sequence(struct.pack(">I", 1) + blk(pulse(0x20), 0xFFFFFFFF))
        self.assertIn("blue on the left side only", blue["text"])
        red = probe.decode_led_sequence(struct.pack(">I", 1) + blk(pulse(0x09, 4), 4))
        self.assertIn("red, one smooth pulse of", red["text"])
        self.assertIn("4 times", red["text"])

    def test_both_know_not_both_use(self):
        self.assertIn("requests both know:", self.report)
        self.assertNotIn("requests both use:", self.report)


if __name__ == "__main__":
    unittest.main()
