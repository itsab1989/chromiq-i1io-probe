"""1.6.3: a session in which every step kept nothing.

A tester's public screenshot showed tool 1.5.5 on Windows ending a nine-step
i1Pro 3 session with every step "EMPTY: nothing recorded", although the same
PC recorded fine before and after. No file of that run reached us, so the
cause is NOT known. These tests pin what the tool does now when it happens:
it still keeps nothing it cannot attribute, says what the recording DID
hold (counts, device classes and USB ids only, never contents), says what to
try one action per line, and writes one small SEND-THIS ...-report-only.zip
with only the report and session.json.

The four simulated recordings (invented, as everything in synth.py):
  - the instrument's own records under an address that is not the one its
    USB description sits at (a stale address), once at an address described
    as a USB disk and once at an address the recording does not describe;
  - the instrument absent (only a keyboard and a hub);
  - the wrong root hub recorded (a disk and a keyboard, no X-Rite device);
  - a zero-length capture (an empty file, and a recording with no records).
Every simulated payload carries a planted marker that must never appear in
anything the tool prints or writes."""

import io
import json
import os
import struct
import sys
import tempfile
import types
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
from test_instrument import FAKE_USBPCAPCMD  # noqa: E402
from test_usbpcap_start import INTERFACES, _answers  # noqa: E402

MARK = b"PLANTED-STALE-4711"
DISK_MARK = b"PLANTED-DISK-0815"
KEY_MARK = b"PLANTED-KEYS-2342"
MARKS = (MARK, DISK_MARK, KEY_MARK)

INSTR = 15          # where the i1Pro 3's USB description sits
STALE = 7           # where its traffic is stamped (a USB disk is described here)
UNDESCRIBED = 20    # an address the recording holds no description for
KEYBOARD = 5


def describe_class(w, dev, vid, pid, iface_class, endpoints, dev_class=0):
    dd = struct.pack("<BBHBBBBHHHBBBB", 18, 1, 0x0200, dev_class, 0, 0, 64, vid, pid,
                     0x0100, 1, 2, 3, 1)
    w.control(dev, 0x80, 6, value=0x0100, length=18, reply=dd)
    eps = b"".join(struct.pack("<BBBBHB", 7, 5, a, k, 64, 1) for a, k in endpoints)
    itf = struct.pack("<BBBBBBBBB", 9, 4, 0, 0, len(endpoints), iface_class, 0, 0, 0)
    total = 9 + len(itf) + len(eps)
    cfg = struct.pack("<BBHBBBBB", 9, 2, total, 1, 1, 0, 0x80, 50) + itf + eps
    w.control(dev, 0x80, 6, value=0x0200, length=total, reply=cfg)


def keyboard(w, n=3):
    for _ in range(n):
        w.bulk_in(KEYBOARD, 0x81, b"\x00\x00\x04" + KEY_MARK[:5], xfer=XFER_INT)


def i1pro3_traffic(w, dev, control=True):
    """The i1Pro 3's work, with a planted marker in every payload."""
    if control:
        w.vendor_in(dev, 0x20, bytes([1, 23]) + MARK)
        w.vendor_out(dev, 0x22, struct.pack("<II", 0, 0x13))
    w.bulk_out(dev, 0x02, bytes([0x0A, 0x14, 0x02]) + MARK)
    w.bulk_in(dev, 0x83, b"\x01", xfer=XFER_INT)
    w.bulk_in(dev, 0x81, MARK * 40)
    w.bulk_in(dev, 0x84, MARK * 4)


def stale_at_disk():
    """The description at INSTR; the instrument's work stamped with the
    address of a USB disk described at STALE."""
    w = synth.UsbPcapWriter()
    w.describe(INSTR, 0x0765, 0x6009, synth.I1PRO3_ENDPOINTS)
    describe_class(w, STALE, 0x0781, 0x5581, 8, [(0x81, 2), (0x02, 2)])
    describe_class(w, KEYBOARD, 0x046D, 0xC31C, 3, [(0x81, 3)], dev_class=0)
    keyboard(w)
    i1pro3_traffic(w, STALE)
    keyboard(w)
    return w


def stale_undescribed():
    """The description at INSTR; the instrument's bulk work at an address
    the recording does not describe (no control request there, so no
    family guess either)."""
    w = synth.UsbPcapWriter()
    w.describe(INSTR, 0x0765, 0x6009, synth.I1PRO3_ENDPOINTS)
    describe_class(w, KEYBOARD, 0x046D, 0xC31C, 3, [(0x81, 3)])
    keyboard(w)
    i1pro3_traffic(w, UNDESCRIBED, control=False)
    return w


def absent():
    w = synth.UsbPcapWriter()
    describe_class(w, 2, 0x05E3, 0x0610, 9, [(0x81, 3)], dev_class=9)
    describe_class(w, KEYBOARD, 0x046D, 0xC31C, 3, [(0x81, 3)])
    keyboard(w, 5)
    return w


def wrong_hub():
    w = synth.UsbPcapWriter()
    describe_class(w, 4, 0x0781, 0x5581, 8, [(0x81, 2), (0x02, 2)])
    describe_class(w, KEYBOARD, 0x046D, 0xC31C, 3, [(0x81, 3)])
    w.bulk_out(4, 0x02, b"USBC" + b"\x01\x00\x00\x00" + DISK_MARK + b"\x00" * 6)
    w.bulk_in(4, 0x81, DISK_MARK * 32)
    w.bulk_in(4, 0x81, b"USBS" + b"\x01\x00\x00\x00" + b"\x00" * 5)
    keyboard(w)
    return w


def header_only():
    return synth.UsbPcapWriter()


class Facts(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def save(self, w, name):
        return w.save(os.path.join(self.tmp.name, name))

    def facts(self, path, profile="i1pro3"):
        return probe.merge_facts([probe.recording_facts(path, profile)])

    def text(self, facts, profile="i1pro3"):
        return "\n".join(probe.facts_lines(facts, profile))

    def assertNoMarks(self, blob, what):
        if isinstance(blob, str):
            blob = blob.encode("utf-8", "replace")
        for m in MARKS:
            self.assertNotIn(m, blob, what)
            self.assertNotIn(m.hex().encode(), blob.lower(), what)
            self.assertNotIn(m[:8], blob, what)

    def test_nothing_is_kept_in_any_of_the_cases(self):
        for name, build in (("stale-disk", stale_at_disk), ("stale-undescribed",
                            stale_undescribed), ("absent", absent), ("wrong-hub", wrong_hub),
                            ("header-only", header_only)):
            with self.subTest(case=name):
                path = self.save(build(), name + ".pcap")
                check = probe.check_capture(path, "i1pro3")
                # the session keeps a copy only for these two codes
                self.assertNotIn(check["code"], ("ok", "all-zero"))
                self.assertFalse(check["ok"])
                # and what the copy rules would keep holds no planted byte
                dst = os.path.join(self.tmp.name, name + "-instrument.pcap")
                if probe.filter_xrite_capture(path, dst, "i1pro3"):
                    with open(dst, "rb") as fh:
                        self.assertNoMarks(fh.read(), dst)

    def test_a_stale_address_at_a_disk(self):
        facts = self.facts(self.save(stale_at_disk(), "a.pcap"))
        self.assertEqual(facts["family_ids"], {"0765:6009": [1, 6, 0]})
        self.assertEqual(facts["family_eps"], {"USB disk or memory stick": 8})
        self.assertEqual(facts["classes"]["USB disk or memory stick"][0], 1)
        text = self.text(facts)
        self.assertIn("The i1Pro 3's USB id (0765:6009) was seen at 1 address: 6 records "
                      "there, none of them its own requests or data.", " ".join(text.split()))
        self.assertIn("On the i1Pro 3's endpoint numbers (0x02, 0x81, 0x83, 0x84) at other "
                      "addresses: 8 records", " ".join(text.split()))
        self.assertNoMarks(text, "facts")
        self.assertNoMarks(json.dumps(facts), "facts json")

    def test_a_stale_address_without_a_description(self):
        facts = self.facts(self.save(stale_undescribed(), "b.pcap"))
        self.assertEqual(facts["family_eps"],
                         {"device whose USB description the recording does not hold": 8})
        self.assertNoMarks(self.text(facts), "facts")

    def test_the_instrument_absent_and_the_wrong_hub(self):
        for build in (absent, wrong_hub):
            with self.subTest(case=build.__name__):
                facts = self.facts(self.save(build(), build.__name__ + ".pcap"))
                self.assertEqual(facts["family_ids"], {})
                text = " ".join(self.text(facts).split())
                self.assertIn("The i1Pro 3's USB id (0765:6009) was not seen", text)
                self.assertIn("keyboard, mouse or other input device: 1 device", text)
                self.assertNoMarks(text, "facts")
        facts = self.facts(self.save(absent(), "hub.pcap"))
        self.assertIn("USB hub", facts["classes"])
        facts = self.facts(self.save(wrong_hub(), "disk.pcap"))
        self.assertIn("USB disk or memory stick", facts["classes"])

    def test_a_zero_length_capture(self):
        empty = os.path.join(self.tmp.name, "zero.pcap")
        open(empty, "wb").close()
        for path in (empty, self.save(header_only(), "h.pcap")):
            with self.subTest(path=os.path.basename(path)):
                facts = self.facts(path)
                self.assertEqual(facts["records"], 0)
                self.assertIn("nothing at all: 0 records on 1 recorded USB bus.",
                              self.text(facts))
        none = probe.merge_facts([])
        self.assertIn("wrote no file", self.text(none))

    def test_counts_and_ids_only_and_80_columns(self):
        for build in (stale_at_disk, stale_undescribed, absent, wrong_hub):
            facts = self.facts(self.save(build(), "w.pcap"))
            for profile in ("i1pro3", "i1pro2", "munki", "isis", "generic"):
                for line in probe.facts_lines(facts, profile):
                    self.assertLessEqual(len("    " + line), 80, line)
                    self.assertNotIn("—", line)
        for system in ("Windows", "Darwin", "Linux"):
            for line in probe.empty_help_lines(system):
                self.assertLessEqual(len("  " + line), 80, line)
                self.assertNotIn("—", line)

    def test_the_help_is_one_action_per_line(self):
        lines = probe.empty_help_lines("Windows")
        text = "\n".join(lines)
        for want in ("  1. Unplug the instrument's USB cable.", "  2. Wait five seconds.",
                     "  3. Plug it back in.", "  4. Start this tool again.",
                     "If the steps are still empty:",
                     '  1. Restart Windows with "Restart" (not "Shut down" and then',
                     "  2. Plug the instrument in after Windows has started.",
                     "  3. Start this tool again."):
            self.assertIn(want, lines, want)
        self.assertIn("the cause is not known yet", text)
        self.assertIn("The small text report and session.json hold no recording.", text)
        self.assertNotIn("will", text.lower().replace("willing", ""))


class TheWholeSession(unittest.TestCase):
    """The Windows session from start to end, every step stale (the case of
    the screenshot), up to the report and the one file to send."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = self.tmp.name
        self.exe = os.path.join(self.dir, "fake_usbpcapcmd.py")
        with open(self.exe, "w") as fh:
            fh.write(FAKE_USBPCAPCMD)
        self.pcaps = os.path.join(self.dir, "pcaps")
        os.mkdir(self.pcaps)
        for p in (mock.patch.dict(os.environ, {"FAKE_LOG": os.path.join(self.dir, "fake.log"),
                                               "FAKE_PCAPS": self.pcaps}),
                  mock.patch.object(probe, "RECORDER_STARTUP_WAIT", 0.3),
                  mock.patch.object(probe, "SHORT_STEP_SECONDS", 0.0)):
            p.start()
            self.addCleanup(p.stop)
        for clear in (probe._SECTIONS, probe._INPUT_ENDED, probe._END, probe._CAUSES):
            clear.clear()
            self.addCleanup(clear.clear)

    def run_all(self, build, answers):
        for step in probe.steps_for("i1pro3"):
            build().save(os.path.join(self.pcaps, step["key"] + ".pcap"))

        def fake_run(cmd, timeout=40):
            joined = " ".join(cmd)
            if cmd[0] == "sc":
                return "SERVICE_NAME: USBPcap\n        STATE              : 4  RUNNING\n"
            if "--extcap-version" in joined:
                return "extcap {version=1.5.4.0}{help=http://desowin.org/usbpcap/}\n"
            if "--extcap-interfaces" in joined:
                return INTERFACES.split("\n")[0] + "\n"
            return "value {arg=99}{value=15}{display=[15] X-Rite i1Pro3}{enabled=true}\n"
        it = iter(answers)
        patches = [
            mock.patch.object(probe, "run", fake_run),
            mock.patch.object(probe, "find_usbpcapcmd", lambda: self.exe),
            mock.patch.object(probe, "windows_program_versions",
                              lambda: {"i1Profiler": "3.8.6.16077"}),
            mock.patch.object(probe, "windows_build_info",
                              lambda: {"build": 26200, "display": "25H2", "product": ""}),
            mock.patch.object(probe, "windows_is_arm", lambda: False),
            mock.patch.object(probe, "windows_is_admin", lambda: True),
            mock.patch.object(probe, "windows_driver_devices", lambda: [
                {"vid": 0x0765, "pid": 0x6009, "name": "i1Pro3", "class": "USBDevice",
                 "service": "WinUSB", "provider": "X-Rite", "status": "OK"}]),
            mock.patch.object(probe.platform, "system", lambda: "Windows"),
            mock.patch.object(probe, "_writable_dir", lambda: self.dir),
            mock.patch.object(probe, "ask", _answers(it)),
        ]
        for p in patches:
            p.start()
        try:
            out = io.StringIO()
            with redirect_stdout(out):
                outcome = probe.instrument_session_step([(0x0765, 0x6009)], direct=True)
                code = probe.finish_report(types.SimpleNamespace(output=None), "Windows",
                                           instrument=True, outcome=outcome)
        finally:
            for p in patches:
                p.stop()
        return outcome, code, out.getvalue()

    START = ["", "yes", "1", ""]       # profile, start, program, version

    def every_step(self):
        steps = []
        for _ in probe.steps_for("i1pro3"):
            steps += ["", "e", ""]     # start, stop, go on (empty step: no notes)
        return self.START + steps + ["yes"]          # delete the full recordings

    def written(self):
        for root, _dirs, files in os.walk(self.dir):
            if os.path.abspath(root) == os.path.abspath(self.pcaps):
                continue
            for name in files:
                if name.endswith(".py") or name == "fake.log":
                    continue
                yield os.path.join(root, name)

    def assertNoMarks(self, blob, what):
        if isinstance(blob, str):
            blob = blob.encode("utf-8", "replace")
        for m in MARKS:
            self.assertNotIn(m, blob, what)
            self.assertNotIn(m[:8], blob, what)
            self.assertNotIn(m.hex().encode(), blob.lower(), what)

    def test_every_step_stale(self):
        with mock.patch.object(probe, "candidate_dirs", lambda: [self.dir]):
            outcome, code, screen = self.run_all(stale_at_disk, self.every_step())
        self.assertEqual(code, 0)
        self.assertTrue(outcome["all_empty"])
        self.assertFalse(outcome["recorded"])
        flat = " ".join(screen.split())
        self.assertIn("CHECK: EMPTY: only the instrument's USB description was recorded "
                      "in this step, none of its requests or data. Please repeat it.", flat)
        self.assertIn("WHAT YOU CAN TRY (the cause is not known yet):", screen)
        self.assertEqual(screen.count("WHAT YOU CAN TRY"), 2)    # first empty step, the end
        self.assertIn("(What you can try is listed above, after step 1.)", screen)
        self.assertIn("FINISHED, BUT NOTHING WAS KEPT", screen)
        self.assertIn("SEND THIS ONE FILE (the report and session.json, no recording):",
                      screen)
        self.assertIn("NOTHING WAS KEPT THIS TIME", screen)
        self.assertIn("Why this happens is not known yet.", flat)
        # the last thing on screen is what to try
        tail = screen.rstrip().splitlines()[-12:]
        self.assertIn("    3. Start this tool again.", tail)
        zips = [p for p in self.written() if p.endswith(".zip")]
        self.assertEqual(len(zips), 1)
        self.assertTrue(os.path.basename(zips[0]).startswith("SEND-THIS-"))
        self.assertTrue(zips[0].endswith("-report-only.zip"))
        with zipfile.ZipFile(zips[0]) as zf:
            names = zf.namelist()
            self.assertEqual(len(names), 2, names)
            self.assertTrue(any(n.endswith("/session.json") for n in names))
            self.assertTrue(any(n.startswith("chromiq-io-probe-") for n in names))
            for n in names:
                self.assertNoMarks(zf.read(n), "zip " + n)
            report = zf.read([n for n in names if n.endswith(".txt")][0]).decode()
            saved = json.loads(zf.read([n for n in names if n.endswith(".json")][0]))
        self.assertIn("THIS REPORT CONTAINS NO RECORDING. Every step was recorded", report)
        self.assertIn("WHAT THE STEPS THAT KEPT NOTHING HELD", report)
        self.assertIn("On the i1Pro 3's endpoint numbers", report)
        self.assertTrue(all(s.get("seen") for s in saved["steps"]))
        self.assertTrue(all(not s["files_xrite"] for s in saved["steps"]))
        # no recording anywhere but the deleted full ones, and no planted byte
        for path in self.written():
            self.assertFalse(path.endswith(".pcap"), path)
            with open(path, "rb") as fh:
                self.assertNoMarks(fh.read(), path)
        self.assertNoMarks(screen, "the screen")
        for line in screen.splitlines():
            if "fake_usbpcapcmd" not in line and self.dir not in line:   # test paths
                self.assertLessEqual(len(line), 80, line)
        self.screen = screen

    def one_step_then_stop(self, build):
        with mock.patch.object(probe, "candidate_dirs", lambda: [self.dir]):
            outcome, _code, screen = self.run_all(build, self.START + ["", "e", "q", "yes"])
        self.assertTrue(outcome.get("all_empty"))
        self.assertIn("-report-only.zip", screen)
        self.assertNoMarks(screen, "screen")
        for path in self.written():
            with open(path, "rb") as fh:
                self.assertNoMarks(fh.read(), path)
        return screen

    def test_instrument_absent(self):
        screen = self.one_step_then_stop(absent)
        self.assertIn("The i1Pro 3's USB id (0765:6009) was not seen", " ".join(screen.split()))

    def test_wrong_root_hub(self):
        screen = self.one_step_then_stop(wrong_hub)
        self.assertIn("- USB disk or memory stick: 1 device", screen)

    def test_zero_length_capture(self):
        screen = self.one_step_then_stop(header_only)
        self.assertIn("CHECK: EMPTY: nothing at all was recorded in this step (0 records).",
                      screen)

    def test_a_session_that_kept_something_is_not_report_only(self):
        def good():
            w = synth.UsbPcapWriter()
            synth.i1pro3_scan(w)
            return w
        answers = self.START + ["", "e", "notes", "", "", "q"]
        with mock.patch.object(probe, "candidate_dirs", lambda: [self.dir]):
            outcome, _code, screen = self.run_all(good, answers)
        self.assertTrue(outcome["recorded"])
        self.assertFalse(outcome.get("all_empty"))
        self.assertNotIn("report-only", screen)
        self.assertNotIn("WHAT YOU CAN TRY", screen)


if __name__ == "__main__":
    unittest.main()


class TheWrongInstrumentChosen(unittest.TestCase):
    """1.6.3: a handheld session keeps only its own family, so a session
    started for the wrong instrument keeps nothing, and the facts say so."""

    def test_an_i1pro3_recorded_in_an_i1pro2_session(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, tmp, True)
        w = synth.UsbPcapWriter()
        synth.i1pro3_scan(w)
        path = w.save(os.path.join(tmp, "a.pcap"))
        self.assertEqual(probe.filter_xrite_capture(path, os.path.join(tmp, "b.pcap"),
                                                    "i1pro2"), 0)
        facts = probe.merge_facts([probe.recording_facts(path, "i1pro2")])
        text = " ".join(" ".join(probe.facts_lines(facts, "i1pro2")).split())
        self.assertIn("Another X-Rite instrument was at work in this recording: 0765:6009 "
                      "(i1Pro 3 or i1Pro 3 Plus)", text)
        self.assertIn("choose it when it asks which instrument you use", text)
        self.assertIn("another X-Rite instrument (0765:6009): 1 device", text)
        self.assertIn("The i1Pro 2's USB id (0971:2000) was not seen", text)
        # and the right session keeps it
        self.assertTrue(probe.filter_xrite_capture(path, os.path.join(tmp, "c.pcap"),
                                                   "i1pro3"))


class TheCheckNamesTheOtherInstrument(unittest.TestCase):

    def test_check_code_other_instrument(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, tmp, True)
        w = synth.UsbPcapWriter()
        synth.i1pro3_scan(w)
        path = w.save(os.path.join(tmp, "a.pcap"))
        check = probe.check_capture(path, "munki")
        self.assertEqual(check["code"], "other-instrument")
        self.assertIn("another instrument's (an i1Pro 3 or 3 Plus (0765:6009))",
                      check["verdict"])
        self.assertEqual(check["other_ids"], ["0765:6009"])
        self.assertEqual(probe.check_capture(path, "i1pro3")["code"], "ok")
        # the table session and a caller without a type: as before
        self.assertEqual(probe.check_capture(path, "io")["code"], "ok")
        self.assertEqual(probe.check_capture(path)["code"], "ok")


class OnAMac(unittest.TestCase):

    def test_facts_name_each_device_and_skip_other_addresses(self):
        import synth_io
        tmp = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, tmp, True)
        w = synth_io.DarwinWriter()
        for n in range(3):
            w._rec(1, 10 + n, 7, 0x81, 3, 0x046D, 0xC31C, b"\x00\x00\x04" + KEY_MARK, 18)
        path = w.save(os.path.join(tmp, "m.pcap"))
        facts = probe.merge_facts([probe.recording_facts(path, "i1pro3")])
        text = "\n".join(probe.facts_lines(facts, "i1pro3"))
        self.assertIn("- other USB device (046d:c31c): 1 device, 3 records", text)
        self.assertIn("The i1Pro 3's USB id (0765:6009) was not seen", " ".join(text.split()))
        self.assertNotIn("other addresses", text)
        self.assertNotIn(KEY_MARK.decode(), text)


class TheFinishLinesFit(unittest.TestCase):
    """1.6.3 (review nit): every line of the session's finish fits 79 columns
    as printed (two spaces in front), also when the full recordings are kept."""

    def test_finish_lines(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, tmp, True)
        folder = os.path.join(tmp, "instrument-session-20261114-120000")
        os.makedirs(folder)
        os.makedirs(folder + "-FULL-do-not-send")
        open(os.path.join(folder + "-FULL-do-not-send", "x-full.pcap"), "wb").close()
        session = {"steps": [{"number": n, "title": t, "take": 1, "empty": True}
                             for n, t in enumerate((s["title"] for s in
                                                    probe.steps_for("i1pro3")), 1)],
                   "ended": "all steps done", "family": "i1pro3"}
        with mock.patch.object(probe, "ask", lambda *_a, **_k: "no"), \
                redirect_stdout(io.StringIO()):
            lines, _analysis = probe.finish_session(session, folder)
        printed = "\n".join("  " + l for l in lines).splitlines()
        self.assertIn("were kept in the -FULL-do-not-send", " ".join(printed))
        for line in printed:
            self.assertLessEqual(len(line), 79, line)


def i1pro3_rec():
    w = synth.UsbPcapWriter()
    synth.i1pro3_scan(w)
    synth.keyboard_noise(w)
    return w


class TheWrongInstrument(TheWholeSession):
    """1.6.3 (review, famB.py): an i1Pro 3 recorded in an i1Pro 2 session. The
    first thing said is which instrument the recording shows and what to
    choose; no replug advice; stopping is the default; the end and the
    report say it again."""

    START_I1PRO2 = ["1", "yes", "1", ""]

    def test_stop_at_once(self):
        with mock.patch.object(probe, "candidate_dirs", lambda: [self.dir]):
            outcome, code, screen = self.run_all(i1pro3_rec,
                                                 self.START_I1PRO2 + ["", "e", "", "yes"])
        self.assertEqual(code, 0)
        self.assertTrue(outcome["wrong_instrument"])
        after = screen.split("Key received.")[1]
        first = [l for l in after.splitlines() if l.strip()][2]   # after the "wait" line
        self.assertTrue(first.startswith("  CHECK: This recording shows an i1Pro 3 or 3 Plus"),
                        first)
        flat = " ".join(screen.split())
        self.assertIn("CHECK: This recording shows an i1Pro 3 or 3 Plus (0765:6009), not the "
                      "instrument you chose (i1Pro 2). Nothing was kept from this step.", flat)
        self.assertIn("To record it: stop here, start the tool again and choose 3 (i1Pro 3 "
                      "or 3 Plus) when it asks which instrument you use.", flat)
        prompt = probe.WRONG_INSTRUMENT_PROMPT
        self.assertIn("Press Enter to stop the session now (recommended)", prompt)
        self.assertTrue(all(len(l) <= 80 for l in prompt.splitlines()))
        self.assertNotIn("WHAT YOU CAN TRY", screen)
        self.assertNotIn("Unplug", screen)
        self.assertNotIn("STEP 2 of 9", screen)
        self.assertIn("NOTHING WAS KEPT THIS TIME", screen)
        self.assertIn("The recording showed an i1Pro 3 or 3 Plus (0765:6009), not the "
                      "instrument you chose (i1Pro 2). Nothing was kept.", flat)
        tail = " ".join(screen.split("NOTHING WAS KEPT THIS TIME")[1].split())
        self.assertIn("start the tool again and choose 3 (i1Pro 3 or 3 Plus)", tail)
        self.assertEqual([p for p in self.written() if p.endswith(".zip")], [])
        report = [p for p in self.written() if os.path.basename(p).startswith(
            "chromiq-io-probe-")]
        with open(report[0], encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("THIS REPORT CONTAINS NO RECORDING. The recording showed an i1Pro 3", text)
        self.assertIn("THE INSTRUMENT CHOSEN IS NOT THE ONE RECORDED", text)
        for line in screen.splitlines():
            if self.dir not in line and "fake_usbpcapcmd" not in line:
                self.assertLessEqual(len(line), 80, line)

    def test_go_on_is_possible(self):
        answers = self.START_I1PRO2 + ["", "e", "go on", "", "e", "q"]
        with mock.patch.object(probe, "candidate_dirs", lambda: [self.dir]):
            _outcome, _code, screen = self.run_all(i1pro3_rec, answers)
        self.assertIn("STEP 2 of 9", screen)
        self.assertIn("(You chose to go on; this step kept nothing either.)", screen)
        self.assertNotIn("WHAT YOU CAN TRY", screen)


class EveryFamilyPair(unittest.TestCase):
    """1.6.3 (review): each handheld session against each instrument."""

    def recordings(self, tmp):
        def i1pro2(w):
            synth.i1pro2_calibration(w)
        def munki(w):
            synth.munki_scan(w)
        def isis(w):
            synth.isis_open(w)
        def io_table(w):
            w.describe(synth.I1PRO, 0x0971, 0x2004, [(0x81, 2), (0x02, 2)])
            w.bulk_out(synth.I1PRO, 0x02, b";TABLE\r")
            w.bulk_in(synth.I1PRO, 0x81, b"\x01\x60OK\r")
        def i1pro3(w):
            synth.i1pro3_scan(w)
        out = {}
        for name, fn in (("i1pro2", i1pro2), ("i1pro3", i1pro3), ("munki", munki),
                         ("isis", isis), ("io", io_table)):
            w = synth.UsbPcapWriter()
            fn(w)
            out[name] = w.save(os.path.join(tmp, name + ".pcap"))
        return out

    def test_pairs(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, tmp, True)
        recs = self.recordings(tmp)
        own = {"i1pro2": {"i1pro2"}, "i1pro": {"i1pro2"}, "i1pro3": {"i1pro3"},
               "munki": {"munki"}, "generic": set()}
        choice = {"i1pro2": "choose 1 (i1Pro 2) or 2 (original i1Pro)",
                  "i1pro3": "choose 3 (i1Pro 3 or 3 Plus)",
                  "munki": "choose 4 (ColorMunki or i1Studio)", "isis": "choose 5 (i1iSis)",
                  "io": "choose 1 (record an i1iO table) at its first question"}
        for session in ("i1pro2", "i1pro", "i1pro3", "munki", "generic"):
            for rec, path in recs.items():
                with self.subTest(session=session, recording=rec):
                    check = probe.check_capture(path, session)
                    if rec in own[session]:
                        self.assertEqual(check["code"], "ok")
                        continue
                    self.assertEqual(check["code"], "other-instrument")
                    first, todo = probe.wrong_instrument_lines(check["other_ids"], session)
                    self.assertTrue(first.startswith("This recording shows "), first)
                    self.assertIn(f"not the instrument you chose "
                                  f"({probe.SHORT_NAMES[session]})", first)
                    self.assertIn(choice[rec], " ".join(todo))

    def test_several_instruments_are_each_named(self):
        first, todo = probe.wrong_instrument_lines(["0971:2000", "0971:2006"], "i1pro3")
        self.assertIn("an i1Pro or i1Pro 2 (0971:2000) and an i1iSis (0971:2006)", first)
        self.assertEqual(len(todo), 2)
        self.assertTrue(todo[0].startswith("To record an i1Pro or i1Pro 2 (0971:2000):"))
