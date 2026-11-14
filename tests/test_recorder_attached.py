"""1.6.5: is USBPcap attached to the instrument? From a tester's Windows
session (structural facts only): nine steps over 42 minutes kept nothing,
because the instrument's driver stack was {EyeOne, ACPI, USBHUB3}, without
USBPcap, after the instrument had been set up again. The stacks below are
invented in the forms Windows gives (DEVPKEY_Device_Stack)."""

import io
import json
import os
import sys
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
import test_all_empty as tae  # noqa: E402

ATTACHED = "\\Driver\\EyeOne,\\Driver\\USBPcap,\\Driver\\ACPI,\\Driver\\USBHUB3"
MISSING = "\\Driver\\EyeOne,\\Driver\\ACPI,\\Driver\\USBHUB3"


def dev(vid, pid, stack, status="OK", name="i1 Pro"):
    return {"vid": vid, "pid": pid, "name": name, "class": "USBDevice", "service": "EyeOne",
            "provider": "X-Rite", "status": status, "stack": stack}


class Verdict(unittest.TestCase):

    def test_parse_driver_lines(self):
        line = ("DRV :: i1 Pro :: USB\\VID_0971&PID_2000\\<redacted:1a2b3c4d> :: USBDevice :: "
                "EyeOne :: X-Rite :: OK :: " + MISSING)
        d = probe.parse_driver_lines(line)[0]
        self.assertEqual(d["stack"], MISSING)
        old = probe.parse_driver_lines("DRV :: i1 Pro :: USB\\VID_0971&PID_2000\\x :: USBDevice "
                                       ":: EyeOne :: X-Rite :: OK")[0]
        self.assertEqual(old["stack"], "")
        self.assertIn("DEVPKEY_Device_Stack", probe._DRIVER_PS)

    def test_attached_missing_and_unknown(self):
        cases = {ATTACHED: "yes", MISSING: "no", "{EyeOne, ACPI, USBHUB3}": "no",
                 "{EyeOne, USBPcap, ACPI, USBHUB3}": "yes", "": "unknown",
                 "something else": "unknown", "\\Driver\\EyeOne": "unknown",
                 "\\Driver\\EyeOne,\\Driver\\ACPI": "unknown"}
        for stack, want in cases.items():
            with self.subTest(stack=stack):
                self.assertEqual(probe.recorder_attached(dev(0x0971, 0x2000, stack)), want)
        self.assertEqual(probe.recorder_attached(dev(0x0971, 0x2000, MISSING, status="Error")),
                         "unknown")

    def test_several_devices(self):
        devices = [dev(0x0971, 0x2000, ATTACHED), dev(0x0971, 0x2000, MISSING, name="second"),
                   dev(0x0765, 0x5020, MISSING, name="i1Display"),
                   dev(0x0765, 0x6009, MISSING, name="i1Pro3")]
        v = probe.recorder_verdict(devices, "i1pro2")
        self.assertEqual(v["verdict"], "no")
        self.assertEqual([d["name"] for d in v["devices"]], ["i1 Pro", "second"])
        self.assertEqual(probe.recorder_verdict(devices[:1], "i1pro2")["verdict"], "yes")
        self.assertEqual(probe.recorder_verdict(devices[2:3], "i1pro2")["verdict"], "unknown")
        self.assertEqual(probe.recorder_verdict([], "i1pro2")["verdict"], "unknown")
        # another X-Rite instrument: every X-Rite device but a monitor calibrator
        self.assertEqual([d["name"] for d in probe.recorder_verdict(devices, "generic")
                          ["devices"]], ["i1 Pro", "second", "i1Pro3"])

    def test_the_table(self):
        table = dev(0x0971, 0x2004, MISSING, name="Eye-One iO")
        self.assertEqual(probe.recorder_verdict([table, dev(0x0971, 0x2000, ATTACHED)],
                                                "io")["verdict"], "no")
        io3 = dev(0x0765, 0x30B0, ATTACHED, name="i1iO 3")
        self.assertEqual(probe.recorder_verdict([io3], "io")["verdict"], "yes")

    def test_lines_fit(self):
        v = probe.recorder_verdict([dev(0x0971, 0x2000, MISSING)], "i1pro2")
        texts = (probe.recorder_not_attached_lines(v) + probe.descriptor_only_lines("Windows")
                 + probe.descriptor_only_lines("Darwin"))
        for line in texts:
            self.assertLessEqual(len("  " + line), 79, line)
            self.assertNotIn("—", line)
        for prompt in (probe.RECORDER_STOP_PROMPT, probe.DESCRIPTOR_STOP_PROMPT):
            for line in prompt.splitlines():
                self.assertLessEqual(len(line), 79, line)
        for word in ("yes", "no", "unknown"):
            self.assertLessEqual(len("  " + probe.recorder_line({"verdict": word})), 79)
        self.assertEqual(probe.recorder_line({"verdict": "unknown"}),
                         "USB recorder attached to your instrument: could not tell")


def descriptor_only():
    w = synth.UsbPcapWriter()
    w.describe(synth.I1PRO, 0x0765, 0x6009, synth.I1PRO3_ENDPOINTS)
    synth.keyboard_noise(w)
    return w


def good():
    w = synth.UsbPcapWriter()
    synth.i1pro3_scan(w)
    return w


class TheSession(tae.TheWholeSession):
    """The Windows session from start to end (the harness of test_all_empty)."""

    def test_every_step_stale(self):             # (the parent's own test, not here)
        pass

    def setUp(self):
        super().setUp()
        self.addCleanup(lambda: self.__dict__.pop("drivers", None))

    def run(self_, *a, **k):                       # noqa: N805
        return super().run(*a, **k)

    def go(self, build, answers):
        with mock.patch.object(probe, "candidate_dirs", lambda: [self.dir]):
            return self.run_all(build, answers)

    def report(self):
        path = [p for p in self.written() if os.path.basename(p).startswith(
            "chromiq-io-probe-")][0]
        with open(path, encoding="utf-8") as fh:
            return fh.read()

    def test_not_attached_stops_before_step_1(self):
        self.drivers = [dev(0x0765, 0x6009, MISSING, name="i1Pro3")]
        outcome, code, screen = self.go(good, ["", ""])     # profile Enter, then Enter = stop
        self.assertEqual(code, 0)
        self.assertIn("USB recorder attached to your instrument: no", screen)
        self.assertIn("THE USB RECORDER IS NOT ATTACHED TO YOUR INSTRUMENT YET", screen)
        self.assertIn('3. Restart Windows with "Restart" (not "Shut down": with Fast',
                      screen)
        self.assertNotIn("STEP 1 of 9", screen)
        self.assertIn("USB recorder (USBPcap) is not attached", " ".join(screen.split()))
        report = self.report()
        self.assertIn("USB recorder attached to your instrument: no", report)
        self.assertFalse(outcome["recorded"])

    def test_not_attached_go_on(self):
        self.drivers = [dev(0x0765, 0x6009, MISSING, name="i1Pro3")]
        _o, _c, screen = self.go(good, ["", "go on", "yes", "1", "", "", "e", "notes", "",
                                        "", "q"])
        self.assertIn("STEP 1 of 9", screen)
        self.assertIn("instrument: good", screen)

    def test_attached_and_could_not_tell_do_not_block(self):
        for stack, word in ((ATTACHED, "yes"), ("", "could not tell")):
            with self.subTest(word=word):
                self.drivers = [dev(0x0765, 0x6009, stack, name="i1Pro3")]
                for clear in (probe._SECTIONS, probe._INPUT_ENDED, probe._END):
                    clear.clear()
                for p in list(self.written()):
                    os.remove(p)
                for d in os.listdir(self.dir):
                    full = os.path.join(self.dir, d)
                    if d.startswith("instrument-session") and os.path.isdir(full):
                        import shutil
                        shutil.rmtree(full)
                _o, _c, screen = self.go(good, self.START + ["", "e", "n", "", "", "q"])
                self.assertIn(f"USB recorder attached to your instrument: {word}", screen)
                self.assertNotIn("NOT ATTACHED", screen)
                self.assertIn("STEP 1 of 9", screen)

    def test_first_step_only_the_description(self):
        self.drivers = [dev(0x0765, 0x6009, ATTACHED, name="i1Pro3")]
        outcome, _c, screen = self.go(descriptor_only, self.START + ["", "e", "", "yes"])
        flat = " ".join(screen.split())
        self.assertIn("CHECK: EMPTY: only the instrument's USB description was recorded", flat)
        self.assertIn("Two things look exactly like this", flat)
        self.assertIn("the measuring program did not talk to the instrument", flat)
        self.assertIn("1. Does the measuring program show the instrument as connected?", flat)
        self.assertNotIn("STEP 2 of 9", screen)
        self.assertNotIn("WHAT YOU CAN TRY", screen)
        self.assertTrue(outcome["all_empty"])
        self.assertIn("The first step recorded only the instrument's USB description",
                      " ".join(screen.split("NOTHING WAS KEPT THIS TIME")[1].split()))
        zips = [p for p in self.written() if p.endswith("-report-only.zip")]
        self.assertEqual(len(zips), 1)
        with zipfile.ZipFile(zips[0]) as zf:
            report = zf.read([n for n in zf.namelist() if n.endswith(".txt")][0]).decode()
            saved = json.loads(zf.read([n for n in zf.namelist()
                                        if n.endswith("session.json")][0]))
        self.assertIn("WHAT WAS SEEN ABOUT THE RECORDING", report)
        self.assertIn("USB recorder attached to your instrument: yes", report)
        self.assertIn("The first recorded step held only the instrument's USB",
                      " ".join(report.split()))
        self.assertTrue(saved["first_step_descriptor_only"])
        self.assertEqual(saved["context"]["recorder_attached"]["verdict"], "yes")
        for line in screen.splitlines():
            if self.dir not in line and "fake_usbpcapcmd" not in line:
                self.assertLessEqual(len(line), 80, line)

    def test_first_step_go_on_and_record_again(self):
        _o, _c, screen = self.go(descriptor_only, self.START + ["", "e", "go on", "", "e",
                                                                "q"])
        self.assertIn("STEP 2 of 9", screen)
        self.assertEqual(screen.count("Two things look exactly like this"), 1)

    def test_a_good_first_step_says_nothing_new(self):
        _o, _c, screen = self.go(good, self.START + ["", "e", "n", "", "", "q"])
        self.assertNotIn("Two things look exactly like this", screen)


class NotOnOtherSystems(unittest.TestCase):

    def test_mac_and_linux_never_ask_windows(self):
        with mock.patch.object(probe, "windows_driver_devices",
                               side_effect=AssertionError("asked on another system")):
            for system in ("Darwin", "Linux"):
                with mock.patch.object(probe.platform, "system", lambda s=system: s):
                    lines = probe.descriptor_only_lines()
                text = " ".join(lines)
                self.assertNotIn("USBPcap", text)
                self.assertIn("Unplug the instrument and plug it in again", text)


class TheTableSession(unittest.TestCase):

    def test_windows_table_not_attached(self):
        probe._SECTIONS.clear()
        self.addCleanup(probe._SECTIONS.clear)
        answers = iter([""])
        with mock.patch.object(probe.platform, "system", lambda: "Windows"), \
                mock.patch.object(probe, "windows_is_arm", lambda: False), \
                mock.patch.object(probe, "windows_driver_devices",
                                  lambda: [dev(0x0971, 0x2004, MISSING, name="Eye-One iO")]), \
                mock.patch.object(probe, "ask", lambda *_a, **_k: next(answers)), \
                mock.patch.object(probe, "io_timed_steps",
                                  side_effect=AssertionError("walkthrough started")), \
                redirect_stdout(io.StringIO()) as out:
            probe.annotate_session()
        screen = out.getvalue()
        self.assertIn("USB recorder attached to your instrument: no", screen)
        self.assertIn("THE USB RECORDER IS NOT ATTACHED", screen)
        sections = dict(probe._SECTIONS)
        self.assertIn("Stage 2: USB recorder", sections)
        self.assertIn("Eye-One iO (0971:2004): no", sections["Stage 2: USB recorder"])


if __name__ == "__main__":
    unittest.main()


class AnotherXriteInstrument(unittest.TestCase):
    """1.6.5 (review): in an "another X-Rite instrument" session the device
    recorded is not known; an unrelated X-Rite device without the recorder
    must not stop a session whose instrument has it."""

    def test_mixed_is_yes_with_a_note(self):
        devices = [dev(0x0765, 0xD020, ATTACHED, name="DTP20"),
                   dev(0x0971, 0x2000, MISSING, name="i1 Pro")]
        v = probe.recorder_verdict(devices, "generic")
        self.assertEqual(v["verdict"], "yes")
        lines = probe.recorder_detail_lines(v)
        self.assertIn("  DTP20 (0765:d020): yes", lines)
        self.assertIn("  i1 Pro (0971:2000): no", lines)
        self.assertIn("The recorder does not see i1 Pro (0971:2000). That is fine if it is "
                      "not the instrument you record.", " ".join(lines))
        for line in lines:
            self.assertLessEqual(len("    " + line), 79, line)

    def test_no_yes_at_all_still_stops(self):
        devices = [dev(0x0765, 0xD020, MISSING, name="DTP20"),
                   dev(0x0971, 0x2000, "", name="i1 Pro")]
        self.assertEqual(probe.recorder_verdict(devices, "generic")["verdict"], "no")
        self.assertEqual(probe.recorder_verdict(devices[1:], "generic")["verdict"], "unknown")

    def test_the_checks_text_names_each_device(self):
        v = probe.recorder_verdict([dev(0x0765, 0xD020, ATTACHED, name="DTP20"),
                                    dev(0x0971, 0x2000, MISSING, name="i1 Pro")], "generic")
        c = {"windows": {"level": "ok", "text": "x"}, "i1profiler": {"level": "ok", "text": "x"},
             "programs": {}, "service": {"installed": True, "running": True},
             "usbpcapcmd": "u", "drivers": [], "admin": True, "hubs": [], "recorder": v}
        text = probe.windows_checks_text(c)
        self.assertIn("USB recorder attached to your instrument: yes", text)
        self.assertIn("i1 Pro (0971:2000): no", text)
        self.assertIn("The recorder does not see i1 Pro", text)


class TheTableAndItsInstrument(unittest.TestCase):
    """1.6.5 (review): the i1iO table session checks the table AND the
    instrument riding on it, so a yes for the table cannot hide a no for the
    instrument; one line per device."""

    def test_instrument_without_recorder(self):
        devices = [dev(0x0971, 0x2004, ATTACHED, name="Eye-One iO"),
                   dev(0x0971, 0x2000, MISSING, name="i1 Pro")]
        v = probe.recorder_verdict(devices, "io")
        self.assertEqual(v["verdict"], "no")
        self.assertEqual([d["name"] for d in v["devices"]], ["Eye-One iO", "i1 Pro"])
        lines = probe.recorder_detail_lines(v)
        self.assertIn("  Eye-One iO (0971:2004): yes", lines)
        self.assertIn("  i1 Pro (0971:2000): no", lines)

    def test_i1io3_with_i1pro3(self):
        devices = [dev(0x0765, 0x30B0, ATTACHED, name="i1iO 3"),
                   dev(0x0765, 0x6009, ATTACHED, name="i1Pro3")]
        self.assertEqual(probe.recorder_verdict(devices, "io")["verdict"], "yes")

    def test_the_session_section_lists_both(self):
        probe._SECTIONS.clear()
        self.addCleanup(probe._SECTIONS.clear)
        answers = iter([""])
        with mock.patch.object(probe.platform, "system", lambda: "Windows"), \
                mock.patch.object(probe, "windows_is_arm", lambda: False), \
                mock.patch.object(probe, "windows_driver_devices", lambda: [
                    dev(0x0971, 0x2004, ATTACHED, name="Eye-One iO"),
                    dev(0x0971, 0x2000, MISSING, name="i1 Pro")]), \
                mock.patch.object(probe, "ask", lambda *_a, **_k: next(answers)), \
                mock.patch.object(probe, "io_timed_steps",
                                  side_effect=AssertionError("walkthrough started")), \
                redirect_stdout(io.StringIO()) as out:
            probe.annotate_session()
        self.assertIn("THE USB RECORDER IS NOT ATTACHED", out.getvalue())
        section = dict(probe._SECTIONS)["Stage 2: USB recorder"]
        self.assertIn("Eye-One iO (0971:2004): yes", section)
        self.assertIn("i1 Pro (0971:2000): no", section)
