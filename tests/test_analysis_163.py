"""1.6.3: what a real i1Pro 3 recording showed the analysis was missing
(structural facts from a tester's repeat, FOR_PROBE_BUILDER.md; the data
here is invented, as everything in synth.py):

- the ruler's travel per scan (a no-ruler control still carries zebra data,
  but its position hardly changes);
- a genuinely slow rescan in the fail-on-purpose step was never counted,
  because only the step names were looked at;
- the lights answer "no" could not be read."""

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
from synth import XFER_INT  # noqa: E402
from test_enter_key import Base, FakeConsole  # noqa: E402

A = synth.I1PRO
GRAY = [0, 1, 3, 2]


def zebra(moves, total=400):
    """Packed 2-bit samples: `moves` single steps forward, then standing."""
    samples = [GRAY[min(i, moves) % 4] for i in range(total)]
    return bytes(samples[i] | samples[i + 1] << 2 | samples[i + 2] << 4 | samples[i + 3] << 6
                 for i in range(0, total, 4))


def swipe(w, seconds, readings=120, moves=200, chunks=6):
    w.vendor_out(A, 0x22, (0).to_bytes(4, "little") + (0x13).to_bytes(4, "little"))
    w.bulk_in(A, 0x83, b"\x01", xfer=XFER_INT)
    for _ in range(chunks):
        w.tick(seconds / chunks)
        w.bulk_in(A, 0x81, bytes(564 * (readings // chunks)))
    w.bulk_in(A, 0x84, zebra(moves))


def step_file(tmp, key, *seconds, moves=200):
    w = synth.UsbPcapWriter()
    w.describe(A, 0x0765, 0x6009, synth.I1PRO3_ENDPOINTS)
    for sec in seconds:
        swipe(w, sec, moves=moves)
        w.tick(1.0)
    return w.save(os.path.join(tmp, key + ".pcap"))


class RulerTravelAndSwipes(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_the_i1pro3_ruler_travel_per_scan(self):
        text = probe.summarize_session([step_file(self.tmp, "scan-single", 2.0),
                                        step_file(self.tmp, "noruler", 2.0, moves=0)])
        self.assertIn("ruler travel 200 position changes (net +200)", text)
        self.assertIn("ruler (0x84, by the i1Pro 3's zebra samples): 200 position changes",
                      text)
        self.assertIn("THE RULER'S POSITION, STEP BY STEP:", text)
        self.assertRegex(text, r"noruler\.pcap \[CONTROL\]: none \([\d,]+ samples, the "
                               r"position never changed\)")

    def test_a_slow_rescan_in_the_fail_step_is_listed(self):
        text = probe.summarize_session([step_file(self.tmp, "scan-fail", 1.0, 7.3)])
        self.assertIn("EVERY SWIPE, BY HOW LONG ITS READINGS TOOK:", text)
        self.assertIn("    scan-fail.pcap:\n"
                      "      1.00 s (120 readings, ruler 200 changes, net +200)\n"
                      "      7.30 s (120 readings, ruler 200 changes, net +200)\n", text)
        self.assertIn("There is no fast and slow step pair here, but these swipes took from "
                      "1.00 s to 7.30 s (the longest in scan-fail.pcap).", " ".join(text.split()))
        part = text.split("EVERY SWIPE")[1].split("THE LIGHTS")[0]
        for line in part.splitlines():
            self.assertLessEqual(len(line), 80, line)

    def test_no_note_with_a_fast_and_slow_pair(self):
        text = probe.summarize_session([step_file(self.tmp, "scan-fast", 1.0),
                                        step_file(self.tmp, "scan-slow", 5.0)])
        self.assertIn("EVERY SWIPE", text)
        self.assertNotIn("There is no fast and slow step pair", text)


class TheLightsAnswer(Base):

    def test_a_bare_no_is_asked_once_more(self):
        console = FakeConsole(["", "e", "started", "no", "no change", "", "q"])
        session, _screen = self.run_session(console)
        self.assertEqual(session["steps"][0]["lights"], "no change")
        self.assertTrue(any("Does that mean the lights did not change?" in p
                            for p in console.prompts))

    def test_enter_after_no_means_did_not_look(self):
        console = FakeConsole(["", "e", "started", "no", "", "", "q"])
        session, _screen = self.run_session(console)
        self.assertEqual(session["steps"][0]["lights"], "did not look")

    def test_the_prompts_fit_80_columns(self):
        console = FakeConsole(["", "e", "started", "no", "", "", "q"])
        self.run_session(console)
        for prompt in console.prompts:
            for line in prompt.splitlines():
                self.assertLessEqual(len(line), 80, line)


if __name__ == "__main__":
    unittest.main()
